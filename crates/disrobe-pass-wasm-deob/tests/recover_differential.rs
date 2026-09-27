#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[cfg(feature = "sandbox")]
#[path = "common/bounded_wasmtime.rs"]
mod bounded_wasmtime;
#[path = "common/build_records.rs"]
mod build_records;

#[cfg(feature = "sandbox")]
use bounded_wasmtime::{Bounded, fuel_engine};
#[cfg(feature = "sandbox")]
use build_records::recorded_wat;
use build_records::{RecordSet, assert_recorded};
#[cfg(feature = "sandbox")]
use disrobe_pass_wasm_deob::{
    RecoveredModule, RecoveryReport, WasmFamilySupport, WasmObfuscator, WasmPipelineSupport,
    recover_module,
};
#[cfg(feature = "sandbox")]
use wasmtime::{Engine, Val};

#[cfg(feature = "sandbox")]
const FUEL_BUDGET: u64 = 5_000_000;

#[cfg(feature = "sandbox")]
fn assemble(name: &str) -> Vec<u8> {
    recorded_wat(RecordSet::Corpus, &format!("real/{name}"))
}

#[cfg(feature = "sandbox")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ret(i32),
    Trap,
}

#[cfg(feature = "sandbox")]
fn call_i32(inst: &mut Bounded, export: &str, args: &[i32]) -> Outcome {
    let argv: Vec<Val> = args.iter().map(|arg: &i32| Val::I32(*arg)).collect();
    match inst.call(export, &argv, Val::I32(0)) {
        Some(Val::I32(value)) => Outcome::Ret(value),
        _ => Outcome::Trap,
    }
}

#[cfg(feature = "sandbox")]
fn battery() -> Vec<[i32; 2]> {
    let mut out: Vec<[i32; 2]> = Vec::new();
    let samples: [i32; 9] = [0, 1, 2, 3, 7, -1, -5, 1000, i32::MIN / 2];
    for a in samples {
        for b in samples {
            out.push([a, b]);
        }
    }
    out
}

#[cfg(feature = "sandbox")]
fn assert_export_equivalent(
    clean: &mut Bounded,
    recovered: &mut Bounded,
    export: &str,
    arity: usize,
) {
    for inputs in battery() {
        let args: &[i32] = &inputs[..arity];
        let want: Outcome = call_i32(clean, export, args);
        let got: Outcome = call_i32(recovered, export, args);
        assert_eq!(
            got, want,
            "export `{export}` diverged on {args:?}: clean={want:?} recovered={got:?}"
        );
    }
}

#[cfg(feature = "sandbox")]
struct Case {
    clean: &'static str,
    obf: &'static str,
    exports: &'static [(&'static str, usize)],
    expect: fn(&RecoveryReport) -> bool,
}

#[cfg(feature = "sandbox")]
fn cases() -> Vec<Case> {
    vec![
        Case {
            clean: "mba_checksum.clean.wat",
            obf: "mba_checksum.obf.wat",
            exports: &[("mix", 2), ("checksum", 2)],
            expect: |r: &RecoveryReport| r.mba_expressions_folded >= 2,
        },
        Case {
            clean: "callind_dispatch.clean.wat",
            obf: "callind_dispatch.obf.wat",
            exports: &[("run", 2)],
            expect: |r: &RecoveryReport| r.call_indirect_resolved >= 3,
        },
        Case {
            clean: "cff_pipeline.clean.wat",
            obf: "cff_pipeline.obf.wat",
            exports: &[("pipeline", 1)],
            expect: |r: &RecoveryReport| r.flattened_functions_restructured >= 1,
        },
        Case {
            clean: "cff_loop.clean.wat",
            obf: "cff_loop.obf.wat",
            exports: &[("loop_sum", 1)],
            expect: |r: &RecoveryReport| r.flattened_functions_restructured >= 1,
        },
    ]
}

#[cfg(feature = "sandbox")]
#[test]
fn obfuscated_recovers_to_clean_behavior_under_wasmtime() {
    let eng: Engine = fuel_engine();
    for case in cases() {
        let clean_bytes: Vec<u8> = assemble(case.clean);
        let obf_bytes: Vec<u8> = assemble(case.obf);

        let pre_clean: Outcome = call_i32(
            &mut Bounded::instantiate(&eng, &clean_bytes, FUEL_BUDGET),
            case.exports[0].0,
            &[3, 5],
        );
        let pre_obf: Outcome = call_i32(
            &mut Bounded::instantiate(&eng, &obf_bytes, FUEL_BUDGET),
            case.exports[0].0,
            &[3, 5],
        );
        assert_eq!(
            pre_obf, pre_clean,
            "real toolchain obfuscation must already match clean before recovery ({})",
            case.obf
        );

        let recovered: RecoveredModule =
            recover_module(&obf_bytes).unwrap_or_else(|e| panic!("recover {}: {e}", case.obf));
        assert!(
            (case.expect)(&recovered.report),
            "recovery report did not show the expected transform for {}: {:?}",
            case.obf,
            recovered.report
        );

        let mut clean_inst: Bounded = Bounded::instantiate(&eng, &clean_bytes, FUEL_BUDGET);
        let mut recovered_inst: Bounded = Bounded::instantiate(&eng, &recovered.bytes, FUEL_BUDGET);
        for (export, arity) in case.exports {
            assert_export_equivalent(&mut clean_inst, &mut recovered_inst, export, *arity);
        }
    }
}

#[cfg(feature = "sandbox")]
#[test]
fn recovery_is_byte_stable_and_valid() {
    for case in cases() {
        let obf_bytes: Vec<u8> = assemble(case.obf);
        let recovered: RecoveredModule = recover_module(&obf_bytes).expect("recover");
        assert!(
            wasmparser::validate(&recovered.bytes).is_ok(),
            "recovered {} must validate",
            case.obf
        );
        assert_ne!(
            recovered.bytes, obf_bytes,
            "recovery must change {}, otherwise the stability check below compares nothing",
            case.obf
        );
        let again: RecoveredModule = recover_module(&recovered.bytes).expect("re-recover");
        assert_eq!(
            again.bytes,
            recovered.bytes,
            "recovering {} a second time must re-encode to the identical module ({} bytes then {} \
             bytes)",
            case.obf,
            recovered.bytes.len(),
            again.bytes.len()
        );
    }
}

#[cfg(feature = "sandbox")]
#[test]
fn decrypt_stub_static_extraction_reveals_plaintext() {
    let obf_bytes: Vec<u8> = assemble("decrypt_stub.obf.wat");
    let recovered: RecoveredModule = recover_module(&obf_bytes).expect("recover");
    assert!(
        recovered.report.decrypt_stub_bytes_recovered >= 10,
        "report={:?}",
        recovered.report
    );
    let module: walrus::Module = walrus::Module::from_buffer(&recovered.bytes).expect("round-trip");
    let plaintext: Vec<u8> = module
        .data
        .iter()
        .find(|d| !d.value.is_empty())
        .map(|d| d.value.clone())
        .expect("a data segment");
    assert_eq!(
        plaintext, b"helloworld",
        "static decrypt of the real constant-key stub must reveal the embedded plaintext"
    );
}

#[cfg(feature = "sandbox")]
#[test]
fn opaque_predicate_o0_folds_interprocedurally_and_stays_intact() {
    let eng: Engine = fuel_engine();
    let obf_bytes: Vec<u8> = assemble("opaque_select.obf.wat");
    let recovered: RecoveredModule = recover_module(&obf_bytes).expect("recover");
    assert_eq!(
        recovered.report.opaque_predicates_removed, 2,
        "real clang -O0 emits two block-based br_if predicates each guarded by a call to the pure \
         collatz_steps helper over a constant; the interprocedural interpreter folds both: {:?}",
        recovered.report
    );
    assert!(
        wasmparser::validate(&recovered.bytes).is_ok(),
        "folded module must validate"
    );

    let clean_bytes: Vec<u8> = assemble("opaque_select.clean.wat");
    let mut clean_inst: Bounded = Bounded::instantiate(&eng, &clean_bytes, FUEL_BUDGET);
    let mut recovered_inst: Bounded = Bounded::instantiate(&eng, &recovered.bytes, FUEL_BUDGET);
    assert_export_equivalent(&mut clean_inst, &mut recovered_inst, "pick", 2);
    assert_export_equivalent(&mut clean_inst, &mut recovered_inst, "scale", 1);
}

#[cfg(feature = "sandbox")]
struct FamilyCase {
    family: WasmObfuscator,
    clean: &'static str,
    obf: &'static str,
    exports: &'static [(&'static str, usize)],
    expect: fn(&RecoveryReport) -> bool,
}

#[cfg(feature = "sandbox")]
fn family_cases() -> Vec<FamilyCase> {
    vec![
        FamilyCase {
            family: WasmObfuscator::WasmMixer,
            clean: "wasmixer_inflate.clean.wat",
            obf: "wasmixer_inflate.obf.wat",
            exports: &[("run", 2)],
            expect: |r: &RecoveryReport| {
                r.wasmixer_fragments_inlined >= 3 && r.wasmixer_elements_pruned >= 1
            },
        },
        FamilyCase {
            family: WasmObfuscator::Wobfuscator,
            clean: "wobfuscator_import.clean.wat",
            obf: "wobfuscator_import.obf.wat",
            exports: &[("mix", 2)],
            expect: |r: &RecoveryReport| {
                r.wobfuscator_ops_reinlined >= 2 && r.wobfuscator_imports_dropped >= 2
            },
        },
        FamilyCase {
            family: WasmObfuscator::JscramblerWasm,
            clean: "jscrambler_guard.clean.wat",
            obf: "jscrambler_guard.obf.wat",
            exports: &[("f", 2)],
            expect: |r: &RecoveryReport| r.jscrambler_imports_stripped >= 1,
        },
    ]
}

#[cfg(feature = "sandbox")]
#[test]
fn named_obfuscator_families_recover_to_clean_behavior_under_wasmtime() {
    let eng: Engine = fuel_engine();
    let cases: Vec<FamilyCase> = family_cases();
    let pipeline_delivered: Vec<WasmObfuscator> = WasmObfuscator::NAMED_FAMILIES
        .into_iter()
        .filter(|family: &WasmObfuscator| {
            family.support().is_some_and(|support: WasmFamilySupport| {
                support.pipeline == WasmPipelineSupport::Delivered
            })
        })
        .collect();
    let fixture_families: Vec<WasmObfuscator> =
        cases.iter().map(|case: &FamilyCase| case.family).collect();
    assert_eq!(pipeline_delivered.len(), 3);
    assert_eq!(fixture_families.len(), pipeline_delivered.len());
    for family in &pipeline_delivered {
        assert!(
            fixture_families.contains(family),
            "the catalog calls {family:?} pipeline delivered, but no fixture drives its recovery path"
        );
    }
    for family in &fixture_families {
        assert!(
            pipeline_delivered.contains(family),
            "the recovery fixture for {family:?} must be represented in the pipeline-delivery catalog"
        );
    }

    for case in cases {
        let clean_bytes: Vec<u8> = assemble(case.clean);
        let obf_bytes: Vec<u8> = assemble(case.obf);

        let recovered: RecoveredModule =
            recover_module(&obf_bytes).unwrap_or_else(|e| panic!("recover {}: {e}", case.obf));
        assert!(
            (case.expect)(&recovered.report),
            "recovery report did not show the expected transform for {}: {:?}",
            case.obf,
            recovered.report
        );
        assert!(
            wasmparser::validate(&recovered.bytes).is_ok(),
            "recovered {} must re-validate",
            case.obf
        );

        let mut clean_inst: Bounded = Bounded::instantiate(&eng, &clean_bytes, FUEL_BUDGET);
        let mut recovered_inst: Bounded = Bounded::instantiate(&eng, &recovered.bytes, FUEL_BUDGET);
        for (export, arity) in case.exports {
            assert_export_equivalent(&mut clean_inst, &mut recovered_inst, export, *arity);
        }
    }
}

#[cfg(feature = "sandbox")]
#[test]
fn named_family_recovery_is_idempotent_and_import_free() {
    for case in family_cases() {
        let obf_bytes: Vec<u8> = assemble(case.obf);
        let recovered: RecoveredModule = recover_module(&obf_bytes).expect("recover");
        let module: walrus::Module =
            walrus::Module::from_buffer(&recovered.bytes).expect("recovered round-trips");
        assert_eq!(
            module.imports.iter().count(),
            0,
            "recovered {} must have no residual obfuscator imports",
            case.obf
        );
        let again: RecoveredModule =
            recover_module(&recovered.bytes).expect("re-recover the recovered module");
        assert!(
            wasmparser::validate(&again.bytes).is_ok(),
            "second-pass recovery of {} must still validate",
            case.obf
        );
        assert_eq!(
            again.bytes,
            recovered.bytes,
            "recovering {} a second time must re-encode to the identical module ({} bytes then {} \
             bytes)",
            case.obf,
            recovered.bytes.len(),
            again.bytes.len()
        );
    }
}

#[cfg(feature = "sandbox")]
#[test]
fn tabulated_expected_outputs_match_clean_originals() {
    let eng: Engine = fuel_engine();
    let checks: &[(&str, &str, &[i32], i32)] = &[
        ("callind_dispatch.clean.wat", "run", &[3, 5], 37),
        ("callind_dispatch.clean.wat", "run", &[2, 4], 22),
        ("callind_dispatch.clean.wat", "run", &[0, 0], 0),
        ("callind_dispatch.clean.wat", "run", &[7, 1], 1),
        ("cff_pipeline.clean.wat", "pipeline", &[0], 30),
        ("cff_pipeline.clean.wat", "pipeline", &[1], 5),
        ("cff_pipeline.clean.wat", "pipeline", &[10], 80),
        ("cff_loop.clean.wat", "loop_sum", &[0], 0),
        ("cff_loop.clean.wat", "loop_sum", &[1], 2),
        ("cff_loop.clean.wat", "loop_sum", &[5], 10),
        ("opaque_select.clean.wat", "pick", &[3, 5], 56),
        ("opaque_select.clean.wat", "pick", &[2, 4], 42),
        ("opaque_select.clean.wat", "scale", &[5], 26),
        ("opaque_select.clean.wat", "scale", &[0], 11),
    ];
    for (file, export, args, want) in checks {
        let bytes: Vec<u8> = assemble(file);
        let mut inst: Bounded = Bounded::instantiate(&eng, &bytes, FUEL_BUDGET);
        let got: Outcome = call_i32(&mut inst, export, args);
        assert_eq!(
            got,
            Outcome::Ret(*want),
            "{file}::{export}{args:?} expected {want}, got {got:?}"
        );
    }
}

#[cfg(not(feature = "sandbox"))]
#[test]
fn recover_differential_refuses_to_report_success_without_the_sandbox_feature() {
    panic!(concat!(
        "DR-WASMDEOB-SANDBOX: this target grades recovered output against a real ",
        "runtime. The missing prerequisite is the crate feature `sandbox`. Re-run ",
        "it as `cargo test -p disrobe-pass-wasm-deob --features sandbox --test ",
        "recover_differential`. Without that feature every graded test in this target is ",
        "compiled out and its `ok` result line grades nothing."
    ));
}

#[test]
#[should_panic(expected = "real/cff_loop.obf.wat no longer matches its build record")]
fn a_committed_module_whose_bytes_drift_from_its_record_is_refused() {
    assert_recorded(RecordSet::Corpus, "real/cff_loop.obf.wat", b"(module)");
}

#[test]
#[should_panic(expected = "real/unrecorded.obf.wat has no build record")]
fn a_committed_module_without_a_record_is_refused() {
    assert_recorded(RecordSet::Corpus, "real/unrecorded.obf.wat", b"(module)");
}

#[cfg(feature = "sandbox")]
#[test]
#[should_panic(expected = "module instantiates within the store limits")]
fn the_grading_store_refuses_a_module_past_its_memory_cap() {
    let bytes: Vec<u8> = wat::parse_str("(module (memory 257))").expect("assemble");
    let _instance: Bounded = Bounded::instantiate(&fuel_engine(), &bytes, FUEL_BUDGET);
}
