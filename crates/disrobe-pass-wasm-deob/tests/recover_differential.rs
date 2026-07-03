#![cfg(feature = "sandbox")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};

use disrobe_pass_wasm_deob::{RecoveredModule, RecoveryReport, recover_module};
use wasmtime::{Config, Engine, Linker, Module, Store, Val};

const FUEL_BUDGET: u64 = 5_000_000;

fn real_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/wasm/obf/real")
}

fn assemble(name: &str) -> Vec<u8> {
    let path: PathBuf = real_dir().join(name);
    let text: String = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}\nrun corpus/wasm/obf/build.sh to produce the real toolchain wat",
            path.display()
        )
    });
    wat::parse_str(&text).unwrap_or_else(|e| panic!("assemble {}: {e}", path.display()))
}

fn engine() -> Engine {
    let mut config: Config = Config::new();
    config.consume_fuel(true);
    Engine::new(&config).expect("engine")
}

struct Inst {
    store: Store<()>,
    instance: wasmtime::Instance,
}

fn instantiate(eng: &Engine, bytes: &[u8]) -> Inst {
    let module: Module = Module::new(eng, bytes).expect("module compiles");
    let mut store: Store<()> = Store::new(eng, ());
    store.set_fuel(FUEL_BUDGET).expect("fuel");
    let mut linker: Linker<()> = Linker::new(eng);
    linker
        .define_unknown_imports_as_traps(&module)
        .expect("trap imports");
    let instance: wasmtime::Instance = linker.instantiate(&mut store, &module).expect("instance");
    Inst { store, instance }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ret(i32),
    Trap,
}

fn call_i32(inst: &mut Inst, export: &str, args: &[i32]) -> Outcome {
    let func: wasmtime::Func = match inst.instance.get_func(&mut inst.store, export) {
        Some(f) => f,
        None => return Outcome::Trap,
    };
    let argv: Vec<Val> = args.iter().map(|a| Val::I32(*a)).collect();
    let mut results: [Val; 1] = [Val::I32(0)];
    inst.store.set_fuel(FUEL_BUDGET).ok();
    if func.call(&mut inst.store, &argv, &mut results).is_err() {
        return Outcome::Trap;
    }
    match results[0] {
        Val::I32(v) => Outcome::Ret(v),
        _ => Outcome::Trap,
    }
}

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

fn assert_export_equivalent(clean: &mut Inst, recovered: &mut Inst, export: &str, arity: usize) {
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

struct Case {
    clean: &'static str,
    obf: &'static str,
    exports: &'static [(&'static str, usize)],
    expect: fn(&RecoveryReport) -> bool,
}

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

#[test]
fn obfuscated_recovers_to_clean_behavior_under_wasmtime() {
    let eng: Engine = engine();
    for case in cases() {
        let clean_bytes: Vec<u8> = assemble(case.clean);
        let obf_bytes: Vec<u8> = assemble(case.obf);

        let pre_clean: Outcome = call_i32(
            &mut instantiate(&eng, &clean_bytes),
            case.exports[0].0,
            &[3, 5],
        );
        let pre_obf: Outcome = call_i32(
            &mut instantiate(&eng, &obf_bytes),
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

        let mut clean_inst: Inst = instantiate(&eng, &clean_bytes);
        let mut recovered_inst: Inst = instantiate(&eng, &recovered.bytes);
        for (export, arity) in case.exports {
            assert_export_equivalent(&mut clean_inst, &mut recovered_inst, export, *arity);
        }
    }
}

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
        let again: RecoveredModule = recover_module(&recovered.bytes).expect("re-recover");
        let _ = again;
    }
}

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

#[test]
fn opaque_predicate_o0_folds_interprocedurally_and_stays_intact() {
    let eng: Engine = engine();
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
    let mut clean_inst: Inst = instantiate(&eng, &clean_bytes);
    let mut recovered_inst: Inst = instantiate(&eng, &recovered.bytes);
    assert_export_equivalent(&mut clean_inst, &mut recovered_inst, "pick", 2);
    assert_export_equivalent(&mut clean_inst, &mut recovered_inst, "scale", 1);
}

struct FamilyCase {
    clean: &'static str,
    obf: &'static str,
    exports: &'static [(&'static str, usize)],
    expect: fn(&RecoveryReport) -> bool,
}

fn family_cases() -> Vec<FamilyCase> {
    vec![
        FamilyCase {
            clean: "wasmixer_inflate.clean.wat",
            obf: "wasmixer_inflate.obf.wat",
            exports: &[("run", 2)],
            expect: |r: &RecoveryReport| {
                r.wasmixer_fragments_inlined >= 3 && r.wasmixer_elements_pruned >= 1
            },
        },
        FamilyCase {
            clean: "wobfuscator_import.clean.wat",
            obf: "wobfuscator_import.obf.wat",
            exports: &[("mix", 2)],
            expect: |r: &RecoveryReport| {
                r.wobfuscator_ops_reinlined >= 2 && r.wobfuscator_imports_dropped >= 2
            },
        },
        FamilyCase {
            clean: "jscrambler_guard.clean.wat",
            obf: "jscrambler_guard.obf.wat",
            exports: &[("f", 2)],
            expect: |r: &RecoveryReport| r.jscrambler_imports_stripped >= 1,
        },
    ]
}

#[test]
fn named_obfuscator_families_recover_to_clean_behavior_under_wasmtime() {
    let eng: Engine = engine();
    for case in family_cases() {
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

        let mut clean_inst: Inst = instantiate(&eng, &clean_bytes);
        let mut recovered_inst: Inst = instantiate(&eng, &recovered.bytes);
        for (export, arity) in case.exports {
            assert_export_equivalent(&mut clean_inst, &mut recovered_inst, export, *arity);
        }
    }
}

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
    }
}

#[test]
fn tabulated_expected_outputs_match_clean_originals() {
    let eng: Engine = engine();
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
        let mut inst: Inst = instantiate(&eng, &bytes);
        let got: Outcome = call_i32(&mut inst, export, args);
        assert_eq!(
            got,
            Outcome::Ret(*want),
            "{file}::{export}{args:?} expected {want}, got {got:?}"
        );
    }
}
