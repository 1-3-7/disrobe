#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::Path;

use disrobe_pass_wasm_deob::{EhModuleSummary, lift_module_faithful_wat, scan_module_eh};
use wasmparser::{Validator, WasmFeatures};

#[path = "common/wat_corpus.rs"]
mod wat_corpus;

fn validate(bytes: &[u8]) -> Result<(), String> {
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(bytes)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn corpus(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../corpus/wasm/wat/{name}"))
}

fn lift(name: &str) -> (Vec<u8>, Vec<u8>, String) {
    let text: String = wat_corpus::verified_wat_text(&corpus(name));
    let original: Vec<u8> = wat::parse_str(&text).expect("source wat must assemble");
    let lifted_wat: String =
        lift_module_faithful_wat(&original).expect("faithful lift must produce output");
    let lifted: Vec<u8> = wat::parse_str(&lifted_wat)
        .unwrap_or_else(|e| panic!("lifted wat must re-assemble: {e}\n{lifted_wat}"));
    (original, lifted, lifted_wat)
}

fn throw_catch_totals(summary: &EhModuleSummary) -> (u64, u64, u64) {
    let mut throws: u64 = 0;
    let mut catches: u64 = 0;
    let mut catches_ref: u64 = 0;
    for tag in summary.per_tag.values() {
        throws += u64::from(tag.throws);
        catches += u64::from(tag.catches);
        catches_ref += u64::from(tag.catches_ref);
    }
    (throws, catches, catches_ref)
}

fn assert_faithful(name: &str) {
    let (original, lifted, lifted_wat): (Vec<u8>, Vec<u8>, String) = lift(name);
    validate(&original).unwrap_or_else(|e| panic!("{name}: original EH corpus must validate: {e}"));
    validate(&lifted).unwrap_or_else(|e| {
        panic!(
            "{name}: recovered EH module must validate under the spec validator: {e}\n{lifted_wat}"
        )
    });

    let orig: EhModuleSummary = scan_module_eh(&original).expect("scan original");
    let lift_sum: EhModuleSummary = scan_module_eh(&lifted).expect("scan lifted");

    assert!(
        orig.uses_modern_eh(),
        "{name}: corpus must actually exercise modern try_table EH"
    );
    assert_eq!(
        orig.constructs, lift_sum.constructs,
        "{name}: every EH construct must survive into the recovered output\n{lifted_wat}"
    );
    assert_eq!(
        orig.tag_section_count, lift_sum.tag_section_count,
        "{name}: every exception tag must be re-declared"
    );
    assert_eq!(
        throw_catch_totals(&orig),
        throw_catch_totals(&lift_sum),
        "{name}: throw / catch / catch_ref totals must match the original\n{lifted_wat}"
    );

    let orig_per_fn: BTreeMap<u32, (u32, u32, u32, u32, u32)> = orig
        .functions
        .iter()
        .map(|(idx, f)| {
            (
                *idx,
                (
                    f.legacy_try_blocks,
                    f.try_table_blocks,
                    f.catch_all_ref_arms,
                    f.throw_refs,
                    f.catch_all_arms,
                ),
            )
        })
        .collect();
    let lift_per_fn: BTreeMap<u32, (u32, u32, u32, u32, u32)> = lift_sum
        .functions
        .iter()
        .map(|(idx, f)| {
            (
                *idx,
                (
                    f.legacy_try_blocks,
                    f.try_table_blocks,
                    f.catch_all_ref_arms,
                    f.throw_refs,
                    f.catch_all_arms,
                ),
            )
        })
        .collect();
    assert_eq!(
        orig_per_fn, lift_per_fn,
        "{name}: per-function modern-EH block profile must be preserved\n{lifted_wat}"
    );
}

#[test]
fn modern_try_table_corpus_round_trips_faithfully() {
    assert_faithful("eh_try_table_modern.wat");
}

#[test]
fn legacy_and_modern_corpus_round_trips_through_the_faithful_lifter() {
    assert_faithful("eh_numeric_roundtrip.wat");
}

#[test]
fn faithful_lift_preserves_modern_eh_syntax() {
    let (_, _, wat): (Vec<u8>, Vec<u8>, String) = lift("eh_try_table_modern.wat");
    assert!(
        wat.contains("catch_ref $tag0"),
        "catch_ref must survive:\n{wat}"
    );
    assert!(
        wat.contains("catch_all_ref"),
        "catch_all_ref must survive:\n{wat}"
    );
    assert!(wat.contains("throw_ref"), "throw_ref must survive:\n{wat}");
    assert!(
        wat.contains("(catch $tag0 0) (catch $tag1 1)"),
        "a multi-catch try_table must keep every catch clause:\n{wat}"
    );
}

#[cfg(feature = "sandbox")]
#[path = "common/eh_exec.rs"]
mod eh_exec;

#[cfg(feature = "sandbox")]
mod execution {
    use super::eh_exec::{
        Differential, Outcome, differential, drop_first_catch_clause, eh_engine, modern_projection,
        run,
    };
    use super::lift;
    use wasmtime::Engine;

    #[test]
    fn execution_store_rejects_modules_above_the_memory_limit() {
        let engine: Engine = eh_engine();
        let oversized: Vec<u8> = wat::parse_str(
            "(module (memory 257) (func (export \"value\") (result i32) i32.const 7))",
        )
        .expect("oversized test module");
        let module: wasmtime::Module =
            wasmtime::Module::new(&engine, &oversized).expect("oversized module compiles");
        assert!(
            super::eh_exec::run_module(&engine, &module, "value", &[], 1).is_err(),
            "the Wasmtime store memory limit must reject oversized modules"
        );
    }

    #[test]
    fn execution_store_reports_fuel_exhaustion_for_an_infinite_loop() {
        let engine: Engine = eh_engine();
        let loop_forever: Vec<u8> = wat::parse_str(
            "(module (func (export \"spin\") (result i32) (loop $spin br $spin) unreachable))",
        )
        .expect("infinite-loop mutation-control module");
        assert_eq!(
            run(&engine, &loop_forever, "spin", &[], 1),
            Outcome::Trapped("OutOfFuel".to_owned()),
            "the fuel budget must stop an infinite Wasmtime execution"
        );
    }

    fn check(name: &str) -> Differential {
        let (original, lifted, lifted_wat): (Vec<u8>, Vec<u8>, String) = lift(name);
        let result: Differential = differential(&original, &lifted).unwrap_or_else(|e| {
            panic!(
                "{name}: {e}
{lifted_wat}"
            )
        });
        eprintln!(
            "[{name}] EH execution checks: {} ({} returned, {} thrown, {} trapped); legacy-EH exports Wasmtime cannot compile: {:?}",
            result.tally.checked(),
            result.tally.returned,
            result.tally.thrown,
            result.tally.trapped,
            result.stubbed_exports
        );
        result
    }

    #[test]
    fn modern_eh_module_executes_equivalently_including_uncaught_throws() {
        let result: Differential = check("eh_try_table_modern.wat");
        assert!(
            result.stubbed_exports.is_empty(),
            "the modern corpus has no legacy-EH functions: {:?}",
            result.stubbed_exports
        );
        assert!(
            result.tally.returned > 0 && result.tally.thrown > 0,
            "the modern corpus must compare returning and uncaught-throw paths: {:?}",
            result.tally
        );
    }

    #[test]
    fn mixed_eh_module_executes_equivalently_on_its_modern_exports() {
        let result: Differential = check("eh_numeric_roundtrip.wat");
        assert!(
            result.tally.returned > 0,
            "the mixed corpus must compare modern-EH exports: {:?}",
            result.tally
        );
    }

    #[test]
    fn wasmtime_still_rejects_the_legacy_eh_functions_the_probe_stubs() {
        let (original, _, _): (Vec<u8>, Vec<u8>, String) = lift("eh_numeric_roundtrip.wat");
        let engine: Engine = eh_engine();
        assert!(
            wasmtime::Module::new(&engine, &original).is_err(),
            "Wasmtime now compiles legacy EH: grade the stubbed legacy exports instead"
        );
        assert!(
            wasmtime::Module::new(&engine, modern_projection(&original).bytes).is_ok(),
            "the modern-EH projection must compile under the EH engine"
        );
    }

    #[test]
    fn dropping_a_catch_clause_from_the_lifted_module_fails_the_probe() {
        for name in ["eh_try_table_modern.wat", "eh_numeric_roundtrip.wat"] {
            let (original, _, lifted_wat): (Vec<u8>, Vec<u8>, String) = lift(name);
            let mutated_wat: String = drop_first_catch_clause(&lifted_wat);
            let mutated: Vec<u8> = wat::parse_str(&mutated_wat)
                .unwrap_or_else(|e| panic!("{name}: mutated wat must assemble: {e}"));
            let verdict: Result<Differential, String> = differential(&original, &mutated);
            assert!(
                verdict.is_err(),
                "{name}: a lifted module missing a catch clause must diverge"
            );
            eprintln!(
                "[{name}] catch-clause mutation: {}",
                verdict.err().unwrap_or_default()
            );
        }
    }
}
