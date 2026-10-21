#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[cfg(feature = "sandbox")]
use std::collections::BTreeMap;

#[cfg(feature = "sandbox")]
use crate::bounded_wasmtime::{Bounded, fuel_engine};
#[cfg(feature = "sandbox")]
use crate::build_records::{RecordSet, recorded_bytes, recorded_wat};
#[cfg(feature = "sandbox")]
use disrobe_pass_wasm_deob::{
    MAX_DECRYPT_OUTPUT, MAX_DECRYPT_SPAN, MAX_STUBS_PER_MODULE, RecoveredModule, StubInfo,
    UnresolvedReason, UnwrapReport, recover_module, recover_module_with_host_script,
    unwrap_decryption,
};
#[cfg(feature = "sandbox")]
use wasmparser::{Operator, Parser, Payload};
#[cfg(feature = "sandbox")]
use wasmtime::{Engine, Val};

#[cfg(feature = "sandbox")]
const FUEL_BUDGET: u64 = 20_000_000;

#[cfg(feature = "sandbox")]
const ONDEMAND_PLAINTEXT: &str = "disrobe/wasm/on-demand-decrypt";

#[cfg(feature = "sandbox")]
fn call(inst: &mut Bounded, export: &str, args: &[i32]) -> Option<i32> {
    let argv: Vec<Val> = args.iter().map(|arg: &i32| Val::I32(*arg)).collect();
    match inst.call(export, &argv, Val::I32(0)) {
        Some(Val::I32(value)) => Some(value),
        _ => None,
    }
}

#[cfg(feature = "sandbox")]
fn divergences(
    engine: &Engine,
    reference: &[u8],
    candidate: &[u8],
    exports: &[(&str, usize)],
) -> Vec<String> {
    let samples: [i32; 14] = [-7, -1, 0, 1, 2, 3, 7, 27, 63, 64, 97, 99, 100, 1000];
    let mut want: Bounded = Bounded::instantiate(engine, reference, FUEL_BUDGET);
    let mut got: Bounded = Bounded::instantiate(engine, candidate, FUEL_BUDGET);
    let mut out: Vec<String> = Vec::new();
    for (export, arity) in exports {
        for a in samples {
            for b in samples
                .iter()
                .take(if *arity == 2 { samples.len() } else { 1 })
            {
                let args: Vec<i32> = if *arity == 2 { vec![a, *b] } else { vec![a] };
                let expected: Option<i32> = call(&mut want, export, &args);
                let actual: Option<i32> = call(&mut got, export, &args);
                assert!(
                    expected.is_some(),
                    "the reference traps on {export}{args:?}"
                );
                if expected != actual {
                    out.push(format!(
                        "{export}{args:?}: want {expected:?} got {actual:?}"
                    ));
                }
            }
        }
    }
    out
}

#[cfg(feature = "sandbox")]
fn br_table_count(wasm: &[u8]) -> usize {
    let mut count: usize = 0;
    for payload in Parser::new(0).parse_all(wasm) {
        if let Payload::CodeSectionEntry(body) = payload.expect("valid module") {
            for op in body.get_operators_reader().expect("operators") {
                if matches!(op.expect("operator"), Operator::BrTable { .. }) {
                    count += 1;
                }
            }
        }
    }
    count
}

#[cfg(feature = "sandbox")]
fn import_count(wasm: &[u8]) -> usize {
    let mut count: usize = 0;
    for payload in Parser::new(0).parse_all(wasm) {
        if let Payload::ImportSection(reader) = payload.expect("valid module") {
            count += reader.count() as usize;
        }
    }
    count
}

#[cfg(feature = "sandbox")]
const TIGRESS_EXPORTS: [(&str, usize); 3] =
    [("sum_squares", 1), ("collatz_steps", 1), ("classify", 1)];

#[cfg(feature = "sandbox")]
#[test]
fn tigress_style_switch_dispatchers_fold_on_the_deob_route() {
    let engine: Engine = fuel_engine();
    let clean: Vec<u8> = recorded_bytes(RecordSet::Corpus, "authored/tigress_flatten.clean.wasm");
    let obf: Vec<u8> = recorded_bytes(RecordSet::Corpus, "authored/tigress_flatten.obf.wasm");
    assert!(
        divergences(&engine, &clean, &obf, &TIGRESS_EXPORTS).is_empty(),
        "the flattened build must already behave like the clean build"
    );
    assert_eq!(
        br_table_count(&obf),
        3,
        "one dispatcher per flattened function"
    );

    let recovered: RecoveredModule = recover_module(&obf).expect("recover");
    assert_eq!(
        recovered.report.flattened_functions_restructured, 3,
        "{:?}",
        recovered.report
    );
    assert_eq!(recovered.report.flattened_dispatchers_walled, 0);
    assert_eq!(
        br_table_count(&recovered.bytes),
        0,
        "every dispatcher is gone"
    );
    let diverged: Vec<String> = divergences(&engine, &clean, &recovered.bytes, &TIGRESS_EXPORTS);
    assert!(diverged.is_empty(), "{diverged:#?}");

    let mutant: Vec<u8> = recorded_bytes(RecordSet::Corpus, "authored/tigress_flatten.mutant.wasm");
    let mutant_recovered: RecoveredModule = recover_module(&mutant).expect("recover mutant");
    assert!(
        !divergences(&engine, &clean, &mutant_recovered.bytes, &TIGRESS_EXPORTS).is_empty(),
        "the mutant's changed case body must turn the differential red"
    );
}

#[cfg(feature = "sandbox")]
#[test]
fn a_dispatcher_switch_above_the_case_cap_is_walled_without_panicking() {
    let targets: String = "0 ".repeat(5000);
    let source: String = format!(
        r#"(module
          (func (export "f") (param i32) (result i32) (local i32)
            i32.const 0
            local.set 1
            loop
              block
                block
                  local.get 1
                  br_table {targets}1
                end
                local.get 0
                return
              end
              br 0
            end
            i32.const 0))"#
    );
    let bytes: Vec<u8> = wat::parse_str(&source).expect("assemble");
    wasmparser::Validator::new()
        .validate_all(&bytes)
        .expect("the oversized dispatcher validates");
    let recovered: RecoveredModule = recover_module(&bytes).expect("recover");
    assert_eq!(recovered.report.flattened_functions_restructured, 0);
    assert_eq!(
        recovered.report.flattened_dispatchers_walled, 1,
        "{:?}",
        recovered.report
    );
    assert_eq!(br_table_count(&recovered.bytes), 1);
}

#[cfg(feature = "sandbox")]
fn host_script(swap: bool) -> String {
    let path: std::path::PathBuf = crate::build_records::RecordSet::Corpus
        .root()
        .join("src/wobfuscator_hosttable.js");
    let text: String = std::fs::read_to_string(&path).expect("host script");
    if swap {
        text.replace("k0: (a, b) => a ^ b", "k0: (a, b) => a & b")
    } else {
        text
    }
}

#[cfg(feature = "sandbox")]
#[test]
fn wobfuscator_static_host_table_reinlines_every_imported_operator() {
    let engine: Engine = fuel_engine();
    let clean: Vec<u8> = recorded_bytes(
        RecordSet::Corpus,
        "authored/wobfuscator_hosttable.clean.wasm",
    );
    let obf: Vec<u8> = recorded_bytes(RecordSet::Corpus, "authored/wobfuscator_hosttable.obf.wasm");
    let exports: [(&str, usize); 2] = [("mix", 2), ("hash", 2)];
    assert_eq!(import_count(&obf), 7);

    let nameless: RecoveredModule = recover_module(&obf).expect("recover without the table");
    assert_eq!(
        import_count(&nameless.bytes),
        7,
        "opaque import names alone must not be guessed"
    );

    let recovered: RecoveredModule =
        recover_module_with_host_script(&obf, &host_script(false)).expect("recover");
    assert_eq!(
        recovered.report.wobfuscator_ops_reinlined, 7,
        "{:?}",
        recovered.report
    );
    assert_eq!(recovered.report.wobfuscator_imports_dropped, 7);
    assert_eq!(import_count(&recovered.bytes), 0);
    let refused: BTreeMap<&str, &str> = recovered
        .report
        .wobfuscator_host_bindings_refused
        .iter()
        .map(|r| (r.import.as_str(), r.reason.as_str()))
        .collect();
    assert_eq!(refused.keys().copied().collect::<Vec<&str>>(), vec!["k7"]);
    assert!(refused["k7"].contains("Math.imul"));
    let diverged: Vec<String> = divergences(&engine, &clean, &recovered.bytes, &exports);
    assert!(diverged.is_empty(), "{diverged:#?}");

    let swapped: RecoveredModule =
        recover_module_with_host_script(&obf, &host_script(true)).expect("recover swapped");
    assert!(
        !divergences(&engine, &clean, &swapped.bytes, &exports).is_empty(),
        "a wrong table entry must turn the differential red"
    );
}

#[cfg(feature = "sandbox")]
fn data_offset(module: &[u8], needle: &[u8]) -> usize {
    module
        .windows(needle.len())
        .position(|window: &[u8]| window == needle)
        .expect("ciphertext present in the module")
}

#[cfg(feature = "sandbox")]
#[test]
fn wasmixer_decrypt_stub_plaintext_reaches_the_deob_report() {
    let engine: Engine = fuel_engine();
    let obf: Vec<u8> = recorded_wat(RecordSet::Corpus, "real/wasmixer_ondemand.obf.wat");
    let recovered: RecoveredModule = recover_module(&obf).expect("recover");
    let literals = &recovered.report.wasmixer_decrypted_literals;
    assert_eq!(literals.len(), 1, "{:?}", recovered.report);
    assert_eq!(literals[0].text.as_deref(), Some(ONDEMAND_PLAINTEXT));
    assert_eq!(literals[0].address, 1_048_576);
    assert_eq!(literals[0].length, ONDEMAND_PLAINTEXT.len());
    assert!(recovered.report.wasmixer_stubs_unresolved.is_empty());

    let read_back = |bytes: &[u8]| -> Vec<u8> {
        let mut inst: Bounded = Bounded::instantiate(&engine, bytes, FUEL_BUDGET);
        let pointer: i32 =
            call(&mut inst, "dec_load", &[0, ONDEMAND_PLAINTEXT.len() as i32]).expect("dec_load");
        let memory: wasmtime::Memory = inst
            .instance
            .get_memory(&mut inst.store, "memory")
            .expect("memory export");
        let start: usize = usize::try_from(pointer).expect("pointer");
        memory.data(&inst.store)[start..start + ONDEMAND_PLAINTEXT.len()].to_vec()
    };
    assert_eq!(read_back(&obf), ONDEMAND_PLAINTEXT.as_bytes());
    assert_eq!(
        read_back(&recovered.bytes),
        read_back(&obf),
        "surfacing the plaintext leaves the stub's run-time behaviour alone"
    );

    let cipher: Vec<u8> = ONDEMAND_PLAINTEXT.bytes().map(|b: u8| b ^ 0x4b).collect();
    let mut mutated: Vec<u8> = obf;
    let at: usize = data_offset(&mutated, &cipher);
    mutated[at] ^= 0x01;
    let wrong: RecoveredModule = recover_module(&mutated).expect("recover mutated");
    assert_ne!(
        wrong.report.wasmixer_decrypted_literals[0].text.as_deref(),
        Some(ONDEMAND_PLAINTEXT),
        "a flipped ciphertext byte must change the surfaced plaintext"
    );
}

#[cfg(feature = "sandbox")]
fn relative_thunk(data_len: usize) -> Vec<u8> {
    let data: String = "k".repeat(data_len);
    wat::parse_str(format!(
        r#"(module
          (memory (export "memory") 32)
          (data (i32.const 256) "{data}")
          (func (export "dec") (param i32 i32) (result i32)
            local.get 0
            i32.const 256
            i32.add))"#
    ))
    .expect("assemble thunk")
}

#[cfg(feature = "sandbox")]
const fn stub(fn_index: u32) -> StubInfo {
    StubInfo {
        fn_index,
        key: Some(0x4b),
        op_histogram: BTreeMap::new(),
        confidence: 1.0,
    }
}

#[cfg(feature = "sandbox")]
#[test]
fn decrypt_stub_spans_and_counts_are_bounded() {
    let oversized: Vec<u8> = relative_thunk(usize::try_from(MAX_DECRYPT_SPAN).unwrap() + 1);
    let report: UnwrapReport = unwrap_decryption(&oversized, &[stub(0)]).expect("unwrap");
    assert!(report.segments.is_empty());
    assert_eq!(report.unresolved[0].reason, UnresolvedReason::SpanTooLarge);

    let span: usize = usize::try_from(MAX_DECRYPT_SPAN).unwrap();
    let fits: usize = MAX_DECRYPT_OUTPUT / span;
    let full_span: Vec<u8> = relative_thunk(span);
    let over_budget: Vec<StubInfo> = (0..=fits).map(|_| stub(0)).collect();
    let report: UnwrapReport = unwrap_decryption(&full_span, &over_budget).expect("unwrap");
    assert_eq!(
        report.segments.len(),
        fits,
        "full spans fill the module budget"
    );
    assert_eq!(
        report
            .unresolved
            .iter()
            .filter(|u| u.reason == UnresolvedReason::OutputBudgetExhausted)
            .count(),
        1
    );

    let small: Vec<u8> = relative_thunk(8);
    let many: Vec<StubInfo> = (0..=MAX_STUBS_PER_MODULE).map(|_| stub(0)).collect();
    let report: UnwrapReport = unwrap_decryption(&small, &many).expect("unwrap");
    assert_eq!(
        report
            .unresolved
            .iter()
            .filter(|u| u.reason == UnresolvedReason::StubLimitExceeded)
            .count(),
        1
    );

    let unexported: Vec<u8> = wat::parse_str(
        r#"(module
          (memory (export "memory") 1)
          (data (i32.const 256) "abcd")
          (func (param i32 i32) (result i32)
            local.get 0
            i32.const 256
            i32.add))"#,
    )
    .expect("assemble");
    let report: UnwrapReport = unwrap_decryption(&unexported, &[stub(0)]).expect("unwrap");
    assert!(report.segments.is_empty());
    assert_eq!(report.unresolved[0].reason, UnresolvedReason::NotExported);
}

#[cfg(not(feature = "sandbox"))]
#[test]
fn wasm_family_recovery_refuses_to_report_success_without_the_sandbox_feature() {
    panic!(concat!(
        "DR-WASMDEOB-SANDBOX: this target grades recovered modules by wasmtime execution. ",
        "Re-run it as `cargo test -p disrobe-pass-wasm-deob --features sandbox --test it ",
        "wasm_family_recovery::`."
    ));
}
