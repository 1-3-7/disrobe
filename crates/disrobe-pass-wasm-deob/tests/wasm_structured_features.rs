#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_wasm_deob::{
    AtomicMemoryRefusal, CalleeNames, Error, FunctionSig, LiftResult, LiftTarget, ModuleSignatures,
    extract_signatures, lift_function_body, rust_module_decls, rust_runtime_prelude,
    try_lift_function_from_module, try_lift_functions_from_module,
};
use wasmparser::{FunctionBody, Parser, Payload};

fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}

fn callees_with_module(bytes: &[u8], sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::from_module(
        bytes,
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

fn lift_index(wat: &str, function_index: usize, target: LiftTarget) -> LiftResult {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("wat assembles to real wasm bytes");
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let defined: &[FunctionSig] = sigs.defined();
    let callees: CalleeNames = callees_with_module(&bytes, &sigs);
    let bodies: Vec<FunctionBody<'_>> = defined_bodies(&bytes);
    let body: &FunctionBody<'_> = bodies.get(function_index).expect("body present");
    let sig: &FunctionSig = defined.get(function_index).expect("sig present");
    lift_function_body(body, sig, &callees, target)
}

fn lift_index_without_module(wat: &str, function_index: usize, target: LiftTarget) -> LiftResult {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("wat assembles to real wasm bytes");
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let defined: &[FunctionSig] = sigs.defined();
    let callees: CalleeNames = CalleeNames::with_signatures(
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    );
    let bodies: Vec<FunctionBody<'_>> = defined_bodies(&bytes);
    let body: &FunctionBody<'_> = bodies.get(function_index).expect("body present");
    let sig: &FunctionSig = defined.get(function_index).expect("sig present");
    lift_function_body(body, sig, &callees, target)
}

const MEM64_WAT: &str = r#"
    (module
      (memory i64 1)
      (func (export "load64") (param i64) (result i32)
        local.get 0
        i32.load offset=8)
      (func (export "store64") (param i64) (param i32)
        local.get 0
        local.get 1
        i32.store offset=8))
"#;

#[test]
fn memory64_load_routes_to_64bit_addressed_helper() {
    let out: LiftResult = lift_index(MEM64_WAT, 0, LiftTarget::Rust);
    assert!(
        out.pseudo_source.contains("wasm_load_i32_a64("),
        "memory64 load must use the 64-bit-addressed helper:\n{}",
        out.pseudo_source
    );
    assert!(out.coverage.fully_recovered(), "no untranslated ops");
}

#[test]
fn memory64_store_routes_to_64bit_addressed_helper() {
    let out: LiftResult = lift_index(MEM64_WAT, 1, LiftTarget::Rust);
    assert!(
        out.pseudo_source.contains("wasm_store_i32_a64("),
        "memory64 store must use the 64-bit-addressed helper:\n{}",
        out.pseudo_source
    );
}

#[test]
fn memory32_load_stays_on_32bit_helper() {
    const WAT: &str = r#"
        (module
          (memory 1)
          (func (export "ld") (param i32) (result i32)
            local.get 0
            i32.load offset=4))
    "#;
    let out: LiftResult = lift_index(WAT, 0, LiftTarget::Rust);
    assert!(out.pseudo_source.contains("wasm_load_i32(p0, 4)"));
    assert!(!out.pseudo_source.contains("wasm_load_i32_a64"));
}

const DEFINED_MEM64_ATOMIC_WAT: &str = r#"
    (module
      (memory i64 1 1 shared)
      (func (export "load") (param i64) (result i32)
        local.get 0
        i32.atomic.load offset=12))
"#;

#[test]
fn defined_memory64_atomic_load_preserves_trapping_guards_for_each_target() {
    let cases: [(LiftTarget, &str); 3] = [
        (
            LiftTarget::Rust,
            "wasm_i32_atomic_load_a64(wasm_atomic_addr_a64(p0, 12, 4), 12)",
        ),
        (
            LiftTarget::TypeScript,
            "wasmI32AtomicLoadA64(wasmAtomicAddrA64(p0, 12n, 4), 12)",
        ),
        (
            LiftTarget::C,
            "wasm_i32_atomic_load_a64(wasm_atomic_addr_a64(p0, UINT64_C(12), 4), UINT64_C(12))",
        ),
    ];
    for (target, expected) in cases {
        let out: LiftResult = lift_index(DEFINED_MEM64_ATOMIC_WAT, 0, target);
        assert!(
            out.pseudo_source.contains(expected),
            "{target:?} memory64 atomic lift must retain the offset, width, and 64-bit trapping guard in `{expected}`:\n{}",
            out.pseudo_source
        );
        assert!(out.coverage.fully_recovered(), "no untranslated ops");
    }
}

const ATOMIC_TRAP_GUARDS_WAT: &str = r#"
    (module
      (memory 1 1 shared)
      (func (export "guarded") (param i32 i32 i64)
        local.get 0
        i32.atomic.load offset=12
        drop
        local.get 0
        local.get 1
        i32.atomic.store offset=12
        local.get 0
        local.get 1
        i32.atomic.rmw16.add_u offset=12
        drop
        local.get 0
        local.get 1
        local.get 1
        i32.atomic.rmw16.cmpxchg_u offset=12
        drop
        local.get 0
        local.get 1
        memory.atomic.notify offset=12
        drop
        local.get 0
        local.get 1
        local.get 2
        memory.atomic.wait32 offset=12
        drop))
"#;

#[test]
fn every_atomic_shape_lifts_through_trapping_address_guards() {
    let cases: [(LiftTarget, [&str; 6]); 3] = [
        (
            LiftTarget::Rust,
            [
                "wasm_i32_atomic_load(wasm_atomic_addr(p0, 12, 4), 12)",
                "wasm_i32_atomic_store(wasm_atomic_addr(p0, 12, 4), 12, p1)",
                "wasm_i32_atomic_rmw16_add_u(wasm_atomic_addr(p0, 12, 2), 12, p1)",
                "wasm_i32_atomic_rmw16_cmpxchg_u(wasm_atomic_addr(p0, 12, 2), 12, p1, p1)",
                "wasm_memory_atomic_notify(wasm_atomic_addr(p0, 12, 4), 12, p1)",
                "wasm_memory_atomic_wait32(wasm_atomic_addr(p0, 12, 4), 12, p1, p2)",
            ],
        ),
        (
            LiftTarget::TypeScript,
            [
                "wasmI32AtomicLoad(wasmAtomicAddr(p0, 12n, 4), 12)",
                "wasmI32AtomicStore(wasmAtomicAddr(p0, 12n, 4), 12, p1)",
                "wasmI32AtomicRmw16AddU(wasmAtomicAddr(p0, 12n, 2), 12, p1)",
                "wasmI32AtomicRmw16CmpxchgU(wasmAtomicAddr(p0, 12n, 2), 12, p1, p1)",
                "wasmMemoryAtomicNotify(wasmAtomicAddr(p0, 12n, 4), 12, p1)",
                "wasmMemoryAtomicWait32(wasmAtomicAddr(p0, 12n, 4), 12, p1, p2)",
            ],
        ),
        (
            LiftTarget::C,
            [
                "wasm_i32_atomic_load(wasm_atomic_addr(p0, UINT64_C(12), 4), UINT64_C(12))",
                "wasm_i32_atomic_store(wasm_atomic_addr(p0, UINT64_C(12), 4), UINT64_C(12), p1)",
                "wasm_i32_atomic_rmw16_add_u(wasm_atomic_addr(p0, UINT64_C(12), 2), UINT64_C(12), p1)",
                "wasm_i32_atomic_rmw16_cmpxchg_u(wasm_atomic_addr(p0, UINT64_C(12), 2), UINT64_C(12), p1, p1)",
                "wasm_memory_atomic_notify(wasm_atomic_addr(p0, UINT64_C(12), 4), UINT64_C(12), p1)",
                "wasm_memory_atomic_wait32(wasm_atomic_addr(p0, UINT64_C(12), 4), UINT64_C(12), p1, p2)",
            ],
        ),
    ];
    for (target, expected_calls) in cases {
        let out: LiftResult = lift_index(ATOMIC_TRAP_GUARDS_WAT, 0, target);
        for expected in expected_calls {
            assert!(
                out.pseudo_source.contains(expected),
                "{target:?} atomic lift omitted the offset, bounds, overflow, or natural-alignment guard in `{expected}`:\n{}",
                out.pseudo_source
            );
        }
        assert!(out.coverage.fully_recovered(), "no untranslated ops");
    }
}

const SAFE_ATOMIC_WAT: &str = r#"
    (module
      (memory 1 1 shared)
      (func (export "load") (param i32) (result i32)
        local.get 0
        i32.atomic.load))
"#;

const UNSAFE_ATOMIC_MEMORY_MODELS: [(&str, usize, &str); 16] = [
    (
        "missing memory",
        0,
        r#"(module
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "multiple memories",
        0,
        r#"(module
          (memory 1 1 shared)
          (memory 1 1 shared)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "zero initial pages",
        0,
        r#"(module
          (memory 0 1 shared)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "non-fixed maximum",
        0,
        r#"(module
          (memory 1 2 shared)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "unshared memory",
        0,
        r#"(module
          (memory 1 1)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "custom page size",
        0,
        r#"(module
          (memory 1 1 shared (pagesize 1))
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "module memory growth",
        1,
        r#"(module
          (memory 1 1 shared)
          (func (export "grow") (param i32) (result i32)
            local.get 0
            memory.grow)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "imported memory",
        0,
        r#"(module
          (import "env" "memory" (memory 1 1 shared))
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "data segment",
        0,
        r#"(module
          (memory 1 1 shared)
          (data (i32.const 0) "\01\00\00\00")
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "start function",
        1,
        r#"(module
          (memory 1 1 shared)
          (func $start)
          (start $start)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "imported global",
        0,
        r#"(module
          (import "env" "value" (global i32))
          (memory 1 1 shared)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "defined global",
        0,
        r#"(module
          (memory 1 1 shared)
          (global i32 (i32.const 0))
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "defined tag",
        0,
        r#"(module
          (tag $value (param i32))
          (memory 1 1 shared)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "function import",
        0,
        r#"(module
          (import "env" "value" (func (result i32)))
          (memory 1 1 shared)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "defined table",
        0,
        r#"(module
          (memory 1 1 shared)
          (table 1 funcref)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
    (
        "element segment",
        1,
        r#"(module
          (memory 1 1 shared)
          (table 1 funcref)
          (func $target)
          (elem (i32.const 0) func $target)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    ),
];

fn assert_trapping_atomic_refusal(out: &LiftResult, target: LiftTarget, label: &str) {
    assert!(
        out.pseudo_source.contains("DR-WASMDEOB-0003"),
        "{target:?} must expose the stable refusal for {label}:\n{}",
        out.pseudo_source
    );
    assert!(
        out.coverage
            .untranslated
            .iter()
            .any(|op: &String| op == "<unsupported-atomic-memory-model>"),
        "{target:?} must report refused atomic coverage for {label}"
    );
    assert!(!out.coverage.fully_recovered());
    assert!(!out.pseudo_source.contains("atomic_load("));
    assert!(!out.pseudo_source.contains("AtomicLoad("));
    match target {
        LiftTarget::Rust => assert!(out.pseudo_source.contains("panic!(")),
        LiftTarget::TypeScript => assert!(out.pseudo_source.contains("throw new Error(")),
        LiftTarget::C => assert!(out.pseudo_source.contains("abort();")),
        LiftTarget::Wat => panic!("high-level refusal target required"),
    }
    assert!(!out.pseudo_source.contains("return 0"));
}

#[test]
fn unsafe_atomic_memory_models_emit_trapping_refusals() {
    for (label, function_index, wat) in UNSAFE_ATOMIC_MEMORY_MODELS {
        for target in [LiftTarget::Rust, LiftTarget::TypeScript, LiftTarget::C] {
            let out: LiftResult = lift_index(wat, function_index, target);
            assert_trapping_atomic_refusal(&out, target, label);
        }
    }
}

#[test]
fn atomic_memory_lift_without_module_context_emits_trapping_refusal() {
    for target in [LiftTarget::Rust, LiftTarget::TypeScript, LiftTarget::C] {
        let out: LiftResult = lift_index_without_module(SAFE_ATOMIC_WAT, 0, target);
        assert_trapping_atomic_refusal(&out, target, "missing module context");
    }
}

#[test]
fn atomic_fence_does_not_require_memory_context() {
    const WAT: &str = r#"(module (func (export "fence") atomic.fence))"#;
    let cases: [(LiftTarget, &str); 3] = [
        (LiftTarget::Rust, "wasm_atomic_fence();"),
        (LiftTarget::C, "wasm_atomic_fence();"),
        (LiftTarget::TypeScript, "wasmAtomicFence();"),
    ];
    for (target, expected) in cases {
        let out: LiftResult = lift_index_without_module(WAT, 0, target);
        assert!(out.pseudo_source.contains(expected), "{target:?}");
        assert!(out.coverage.fully_recovered(), "{target:?}");
    }

    let bytes: Vec<u8> = wat::parse_str(WAT).expect("wat");
    for (target, expected) in cases {
        let out: LiftResult = try_lift_function_from_module(&bytes, 0, target)
            .unwrap_or_else(|error| panic!("{target:?} must express atomic.fence: {error}"));
        assert!(out.pseudo_source.contains(expected), "{target:?}");
    }
}

#[test]
fn strict_module_lift_propagates_typed_atomic_memory_refusal() {
    const WAT: &str = r#"(module
      (memory 1 2 shared)
      (func (export "load") (param i32) (result i32)
        local.get 0
        i32.atomic.load))"#;
    let bytes: Vec<u8> = wat::parse_str(WAT).expect("wat");
    let error: Error = try_lift_functions_from_module(&bytes, LiftTarget::Rust)
        .expect_err("unsafe atomic memory must be a typed refusal");
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::MaximumPages {
            memory_index: 0,
            actual: Some(2),
        })
    ));
}

#[test]
fn strict_module_lift_preserves_legacy_stub_for_invalid_non_atomic_opcode() {
    let mut bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (func (export "broken") (result i32)
            i32.const 0)
          (func (export "intact") (result i32)
            i32.const 7))"#,
    )
    .expect("wat");
    let body_range: std::ops::Range<usize> = defined_bodies(&bytes)
        .first()
        .expect("one function body")
        .range();
    let opcode_index: usize = body_range.start.checked_add(1).expect("opcode index");
    assert_eq!(bytes.get(opcode_index), Some(&0x41));
    bytes[opcode_index] = 0xff;

    for target in [LiftTarget::Rust, LiftTarget::TypeScript, LiftTarget::C] {
        let results: Vec<LiftResult> = try_lift_functions_from_module(&bytes, target)
            .expect("non-atomic lift errors retain legacy stubs");
        assert_eq!(results.len(), 2);
        assert!(
            results[0]
                .pseudo_source
                .contains("not lifted: DR-WASMDEOB-0001")
        );
        assert_eq!(
            results[0].coverage.untranslated,
            vec!["<parse-failure>".to_owned()]
        );
        assert!(results[1].pseudo_source.contains("intact"));
        assert!(results[1].coverage.fully_recovered());
    }
}

#[test]
fn strict_module_lift_rejects_atomic_state_after_invalid_operator_scan() {
    let mut bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "broken") (result i32)
            i32.const 0)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    )
    .expect("wat");
    let body_range: std::ops::Range<usize> = defined_bodies(&bytes)
        .first()
        .expect("one function body")
        .range();
    let opcode_index: usize = body_range.start.checked_add(1).expect("opcode index");
    assert_eq!(bytes.get(opcode_index), Some(&0x41));
    bytes[opcode_index] = 0xff;

    let error: Error = try_lift_functions_from_module(&bytes, LiftTarget::Rust)
        .expect_err("an incomplete grow scan must refuse atomic lifting");
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::MemoryScanFailed)
    ));
}

#[test]
fn strict_module_call_indirect_uses_type_index_signatures() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (type $unused (func (param i64 i64) (result i64)))
          (type $callee (func (param f64) (result f32)))
          (type $dispatch (func (param f64 i32) (result f32)))
          (table 1 funcref)
          (func $callee_impl (type $callee) (param f64) (result f32)
            local.get 0
            f32.demote_f64)
          (elem (i32.const 0) func $callee_impl)
          (func (export "dispatch") (type $dispatch) (param f64 i32) (result f32)
            local.get 0
            local.get 1
            call_indirect (type $callee)))"#,
    )
    .expect("wat");
    let result: LiftResult = try_lift_function_from_module(&bytes, 1, LiftTarget::Rust)
        .expect("strict call_indirect lift");
    assert!(
        result
            .pseudo_source
            .contains("pub fn dispatch(p0: f64, p1: i32) -> f32")
    );
    assert!(
        result
            .pseudo_source
            .contains("let t0: f32 = call_indirect_type1(p1, p0);")
    );
    assert!(!result.pseudo_source.contains("not lifted"));
}

fn strict_module_error(wat: &str, function_index: usize) -> Error {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("wat");
    try_lift_function_from_module(&bytes, function_index, LiftTarget::Rust)
        .expect_err("unsafe atomic module must be a typed refusal")
}

#[test]
fn strict_module_lift_rejects_imported_atomic_memory() {
    const WAT: &str = r#"(module
      (import "env" "memory" (memory 1 1 shared))
      (func (export "load") (param i32) (result i32)
        local.get 0
        i32.atomic.load))"#;
    let error: Error = strict_module_error(WAT, 0);
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::ImportedMemory { memory_index: 0 })
    ));
}

#[test]
fn strict_module_lift_rejects_atomic_memory_custom_page_size() {
    const WAT: &str = r#"(module
      (memory 1 1 shared (pagesize 1))
      (func (export "load") (param i32) (result i32)
        local.get 0
        i32.atomic.load))"#;
    let error: Error = strict_module_error(WAT, 0);
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::PageSize {
            memory_index: 0,
            actual: 0,
        })
    ));
}

#[test]
fn strict_module_lift_rejects_atomic_module_data_segments() {
    const WAT: &str = r#"(module
      (memory 1 1 shared)
      (data (i32.const 0) "\01\00\00\00")
      (func (export "load") (param i32) (result i32)
        local.get 0
        i32.atomic.load))"#;
    let error: Error = strict_module_error(WAT, 0);
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::DataSegments { actual: 1 })
    ));
}

#[test]
fn strict_module_lift_rejects_atomic_module_start_function() {
    const WAT: &str = r#"(module
      (memory 1 1 shared)
      (func $start)
      (start $start)
      (func (export "load") (param i32) (result i32)
        local.get 0
        i32.atomic.load))"#;
    let error: Error = strict_module_error(WAT, 1);
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::StartFunction { function_index: 0 })
    ));
}

#[test]
fn strict_module_lift_rejects_atomic_module_imported_globals() {
    const WAT: &str = r#"(module
      (import "env" "value" (global i32))
      (memory 1 1 shared)
      (func (export "load") (param i32) (result i32)
        local.get 0
        i32.atomic.load))"#;
    let error: Error = strict_module_error(WAT, 0);
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::Imports { actual: 1 })
    ));
}

#[test]
fn strict_module_lift_rejects_atomic_module_defined_globals() {
    const WAT: &str = r#"(module
      (memory 1 1 shared)
      (global i32 (i32.const 0))
      (func (export "load") (param i32) (result i32)
        local.get 0
        i32.atomic.load))"#;
    let error: Error = strict_module_error(WAT, 0);
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::Globals { actual: 1 })
    ));
}

#[test]
fn strict_module_lift_rejects_atomic_module_defined_tags() {
    const WAT: &str = r#"(module
      (tag $value (param i32))
      (memory 1 1 shared)
      (func (export "load") (param i32) (result i32)
        local.get 0
        i32.atomic.load))"#;
    let error: Error = strict_module_error(WAT, 0);
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::Tags { actual: 1 })
    ));
}

#[test]
fn strict_module_lift_rejects_atomic_module_function_imports() {
    const WAT: &str = r#"(module
      (import "env" "value" (func (result i32)))
      (memory 1 1 shared)
      (func (export "load") (param i32) (result i32)
        local.get 0
        i32.atomic.load))"#;
    let error: Error = strict_module_error(WAT, 0);
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::Imports { actual: 1 })
    ));
}

#[test]
fn strict_module_lift_rejects_atomic_module_tables() {
    const WAT: &str = r#"(module
      (memory 1 1 shared)
      (table 1 funcref)
      (func (export "load") (param i32) (result i32)
        local.get 0
        i32.atomic.load))"#;
    let error: Error = strict_module_error(WAT, 0);
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::Tables { actual: 1 })
    ));
}

#[test]
fn strict_module_lift_rejects_atomic_module_element_segments() {
    const WAT: &str = r#"(module
      (memory 1 1 shared)
      (table 1 funcref)
      (func $target)
      (elem (i32.const 0) func $target)
      (func (export "load") (param i32) (result i32)
        local.get 0
        i32.atomic.load))"#;
    let error: Error = strict_module_error(WAT, 1);
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::ElementSegments { actual: 1 })
    ));
}

#[test]
fn strict_module_lift_derives_selection_signature_and_callees_from_module_bytes() {
    const WAT: &str = r#"(module
      (func (export "callee64") (param i64) (result i64)
        local.get 0)
      (func (export "distractor") (param f64) (result f64)
        local.get 0)
      (func (export "selected") (param i64) (result i64)
        local.get 0
        call 0))"#;
    let bytes: Vec<u8> = wat::parse_str(WAT).expect("wat");
    let out: LiftResult = try_lift_function_from_module(&bytes, 2, LiftTarget::Rust)
        .expect("module-derived lift inputs");
    assert!(
        out.pseudo_source
            .contains("pub fn selected(p0: i64) -> i64")
    );
    assert!(out.pseudo_source.contains("let t0: i64 = callee64(p0);"));
    assert!(out.coverage.fully_recovered());
}

#[test]
fn strict_module_lift_accepts_matching_safe_atomic_context() {
    let bytes: Vec<u8> = wat::parse_str(SAFE_ATOMIC_WAT).expect("wat");
    let out: LiftResult =
        try_lift_function_from_module(&bytes, 0, LiftTarget::Rust).expect("safe atomic module");
    assert!(out.coverage.fully_recovered());
    assert!(out.pseudo_source.contains("wasm_i32_atomic_load("));
}

const FUNCREF_WAT: &str = r#"
    (module
      (type $ft (func (param i32) (result i32)))
      (func $square (param i32) (result i32)
        local.get 0
        local.get 0
        i32.mul)
      (func (export "call_through") (param i32) (result i32)
        local.get 0
        ref.func $square
        call_ref $ft))
"#;

#[test]
fn ref_func_lifts_to_named_function_reference() {
    let out: LiftResult = lift_index(FUNCREF_WAT, 1, LiftTarget::Rust);
    assert!(
        out.pseudo_source.contains("square"),
        "ref.func must name the referenced function:\n{}",
        out.pseudo_source
    );
}

#[test]
fn call_ref_emits_indirect_call_through_reference() {
    let out: LiftResult = lift_index(FUNCREF_WAT, 1, LiftTarget::Rust);
    assert!(
        out.pseudo_source.contains("(square)(p0)"),
        "call_ref must call through the named function reference:\n{}",
        out.pseudo_source
    );
    assert!(
        !out.pseudo_source.contains("untranslated op"),
        "no untranslated ops in funcref lift:\n{}",
        out.pseudo_source
    );
}

const GC_WAT: &str = r#"
    (module
      (type $point (struct (field (mut i32)) (field (mut i32))))
      (type $vec (array (mut i32)))
      (func (export "make_x") (param i32) (param i32) (result i32)
        local.get 0
        local.get 1
        struct.new $point
        struct.get $point 0)
      (func (export "arr_first") (result i32)
        i32.const 7
        i32.const 3
        array.new_fixed $vec 2
        i32.const 0
        array.get $vec)
      (func (export "boxed31") (param i32) (result i32)
        local.get 0
        ref.i31
        i31.get_s))
"#;

#[test]
fn struct_new_and_get_lift_to_named_typed_access() {
    let out: LiftResult = lift_index(GC_WAT, 0, LiftTarget::Rust);
    assert!(
        out.pseudo_source.contains("Struct0"),
        "struct.new must build a named struct:\n{}",
        out.pseudo_source
    );
    assert!(
        out.pseudo_source.contains(".f0_0"),
        "struct.get must read a named field:\n{}",
        out.pseudo_source
    );
    assert!(out.coverage.fully_recovered());
}

#[test]
fn array_new_fixed_and_get_lift_to_indexed_access() {
    let out: LiftResult = lift_index(GC_WAT, 1, LiftTarget::Rust);
    assert!(
        out.pseudo_source.contains("vec![") && out.pseudo_source.contains("[("),
        "array.new_fixed + array.get must lift to a vec and an indexed read:\n{}",
        out.pseudo_source
    );
    assert!(out.coverage.fully_recovered());
}

#[test]
fn i31_ref_round_trips_through_tagged_int() {
    let out: LiftResult = lift_index(GC_WAT, 2, LiftTarget::Rust);
    assert!(
        out.pseudo_source.contains("0x7fff_ffff") || out.pseudo_source.contains("<< 1"),
        "ref.i31 / i31.get must lift to tagged-int arithmetic:\n{}",
        out.pseudo_source
    );
    assert!(out.coverage.fully_recovered());
}

const SIMD_WAT: &str = r#"
    (module
      (func (export "splat_add") (param i32) (result v128)
        local.get 0
        i32x4.splat
        local.get 0
        i32x4.splat
        i32x4.add)
      (func (export "vload") (param i32) (result v128)
        local.get 0
        v128.load offset=0))
"#;

#[test]
fn simd_lane_ops_lift_to_real_helpers_not_dropped() {
    let out: LiftResult = lift_index(SIMD_WAT, 0, LiftTarget::Rust);
    assert!(
        out.pseudo_source.contains("wasm_i32x4_splat(")
            && out.pseudo_source.contains("wasm_i32x4_add("),
        "SIMD splat + add must lift to lane helpers:\n{}",
        out.pseudo_source
    );
    assert!(
        !out.pseudo_source.contains("untranslated op"),
        "no untranslated SIMD ops:\n{}",
        out.pseudo_source
    );
    assert!(out.coverage.fully_recovered());
}

#[test]
fn v128_load_lifts_to_v128_memory_helper() {
    let out: LiftResult = lift_index(SIMD_WAT, 1, LiftTarget::Rust);
    assert!(
        out.pseudo_source.contains("wasm_load_v128("),
        "v128.load must lift to the v128 memory helper:\n{}",
        out.pseudo_source
    );
}

const BULK_WAT: &str = r#"
    (module
      (memory 1)
      (data "abcd")
      (func (export "copy") (param i32) (param i32) (param i32)
        local.get 0
        local.get 1
        local.get 2
        memory.copy)
      (func (export "fill") (param i32) (param i32) (param i32)
        local.get 0
        local.get 1
        local.get 2
        memory.fill)
      (func (export "seed") (param i32) (param i32) (param i32)
        local.get 0
        local.get 1
        local.get 2
        memory.init 0
        data.drop 0))
"#;

#[test]
fn bulk_memory_copy_and_fill_lift_to_helpers() {
    let copy: LiftResult = lift_index(BULK_WAT, 0, LiftTarget::Rust);
    assert!(
        copy.pseudo_source.contains("wasm_memory_copy("),
        "memory.copy must lift to a helper:\n{}",
        copy.pseudo_source
    );
    let fill: LiftResult = lift_index(BULK_WAT, 1, LiftTarget::Rust);
    assert!(
        fill.pseudo_source.contains("wasm_memory_fill("),
        "memory.fill must lift to a helper:\n{}",
        fill.pseudo_source
    );
}

#[test]
fn memory_init_and_data_drop_lift_to_helpers() {
    let out: LiftResult = lift_index(BULK_WAT, 2, LiftTarget::Rust);
    assert!(out.pseudo_source.contains("wasm_memory_init("));
    assert!(out.pseudo_source.contains("wasm_data_drop(0)"));
    assert!(out.coverage.fully_recovered());
}

const EH_WAT: &str = r#"
    (module
      (tag $oops (param i32))
      (func (export "guarded") (param i32) (result i32)
        block $handler (result i32)
          block $body
            try_table (catch $oops $handler)
              local.get 0
              i32.eqz
              if
                i32.const 5
                throw $oops
              end
            end
            i32.const 1
            return
          end
          i32.const 0
          return
        end)
      (func (export "always") (result i32)
        i32.const 9
        throw $oops
        i32.const 0))
"#;

#[test]
fn try_table_structures_into_labeled_block_with_catch_routing() {
    let out: LiftResult = lift_index(EH_WAT, 0, LiftTarget::Rust);
    assert!(
        out.pseudo_source.contains("wasm_exception_pending("),
        "try_table catch must route on a pending exception:\n{}",
        out.pseudo_source
    );
    assert!(
        out.pseudo_source.contains("wasm_throw("),
        "throw must raise an exception:\n{}",
        out.pseudo_source
    );
    assert!(
        !out.pseudo_source.contains("untranslated op"),
        "no untranslated EH ops:\n{}",
        out.pseudo_source
    );
}

#[test]
fn throw_unwinds_with_typed_default_return() {
    let out: LiftResult = lift_index(EH_WAT, 1, LiftTarget::Rust);
    assert!(
        out.pseudo_source.contains("wasm_throw(0)"),
        "throw $oops must raise tag index 0 (its payload value is consumed, not the tag):\n{}",
        out.pseudo_source
    );
    assert!(
        out.pseudo_source.contains("return 0i32;"),
        "throw must unwind via a typed default return:\n{}",
        out.pseudo_source
    );
}

fn tool_on_path(tool: &str) -> Option<PathBuf> {
    let probe: &str = if cfg!(windows) { "where" } else { "which" };
    let output: std::process::Output = Command::new(probe).arg(tool).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout: String = String::from_utf8_lossy(&output.stdout).to_string();
    let first: &str = stdout.lines().next()?.trim();
    if first.is_empty() {
        None
    } else {
        Some(PathBuf::from(first))
    }
}

fn lift_all_rust(wat: &str) -> String {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("wat assembles");
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
    let defined: &[FunctionSig] = sigs.defined();
    let callees: CalleeNames = callees_with_module(&bytes, &sigs);
    let mut out: String = rust_runtime_prelude().to_owned();
    out.push('\n');
    out.push_str(&rust_module_decls(&bytes));
    for (i, body) in defined_bodies(&bytes).iter().enumerate() {
        out.push('\n');
        out.push_str(
            &lift_function_body(body, &defined[i], &callees, LiftTarget::Rust).pseudo_source,
        );
    }
    out
}

const FEATURE_RICH_WAT: &str = r#"
    (module
      (type $point (struct (field (mut i32)) (field (mut f64))))
      (type $vec (array (mut i32)))
      (type $unary (func (param i32) (result i32)))
      (tag $oops (param i32))
      (memory i64 1)
      (func $dbl (param i32) (result i32)
        local.get 0
        i32.const 2
        i32.mul)
      (func (export "wide_mem") (param i64) (result i32)
        local.get 0
        i64.const 9
        i64.store offset=16
        local.get 0
        i64.load offset=16
        i32.wrap_i64)
      (func (export "ref_call") (param i32) (result i32)
        local.get 0
        ref.func $dbl
        call_ref $unary)
      (func (export "gc") (param i32) (result i32)
        local.get 0
        f64.const 1.5
        struct.new $point
        struct.get $point 0)
      (func (export "simd") (param i32) (result v128)
        local.get 0
        i32x4.splat
        local.get 0
        i32x4.splat
        i32x4.add)
      (func (export "bulk") (param i32)
        local.get 0
        i32.const 0
        i32.const 4
        memory.fill)
      (func (export "eh") (param i32) (result i32)
        block $h (result i32)
          block $b
            try_table (catch $oops $h)
              local.get 0
              throw $oops
            end
            i32.const 1
            return
          end
          i32.const 0
          return
        end))
"#;

#[test]
fn feature_rich_lift_compiles_with_rustc() {
    let src: String = lift_all_rust(FEATURE_RICH_WAT);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_wasm_feat").expect("mkdir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let rs: PathBuf = dir.join("feat.rs");
    std::fs::write(&rs, &src).expect("write rs");
    let Some(rustc): Option<PathBuf> = tool_on_path("rustc") else {
        eprintln!("SKIP: rustc not on PATH for the compile-the-feature-output gate");
        return;
    };
    let out: std::process::Output = Command::new(rustc)
        .args([
            "--edition",
            "2021",
            "--crate-type",
            "lib",
            "--emit=metadata",
            "-o",
        ])
        .arg(dir.join("feat.rmeta"))
        .arg(&rs)
        .output()
        .expect("spawn rustc");
    assert!(
        out.status.success(),
        "rustc rejected the lifted SIMD/GC/EH/memory64/funcref output (exit {:?})\n--- stderr ---\n{}\n--- source ---\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
        src
    );
}
