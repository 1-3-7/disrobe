#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, ModuleSignatures, extract_signatures,
    lift_function_body, rust_module_decls, rust_runtime_prelude,
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
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_wasm_feat_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
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
