#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::Path;

use disrobe_pass_wasm_deob::{
    EhModuleSummary, FunctionSig, ModuleSignatures, extract_signatures, lift_module_to_wat,
    scan_module_eh,
};
use wasmparser::{FunctionBody, Parser, Payload, Validator, WasmFeatures};

#[path = "common/wat_corpus.rs"]
mod wat_corpus;

fn bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for p in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(b)) = p {
            out.push(b);
        }
    }
    out
}

fn lift(path: &Path) -> (Vec<u8>, Vec<u8>, String) {
    let text: String = wat_corpus::verified_wat_text(path);
    let original: Vec<u8> = wat::parse_str(&text).expect("source wat must assemble");
    let sigs: ModuleSignatures = extract_signatures(&original).expect("sigs");
    let defined: &[FunctionSig] = sigs.defined();
    let mut pairs: Vec<(FunctionBody<'_>, FunctionSig)> = Vec::new();
    for (i, b) in bodies(&original).into_iter().enumerate() {
        if let Some(s) = defined.get(i) {
            pairs.push((b, s.clone()));
        }
    }
    let off: u32 = sigs.imported_function_count() as u32;
    let lifted_wat: String = lift_module_to_wat(&pairs, off);
    let lifted: Vec<u8> = wat::parse_str(&lifted_wat)
        .unwrap_or_else(|e| panic!("lifted wat must re-assemble: {e}\n{lifted_wat}"));
    (original, lifted, lifted_wat)
}

fn validate(bytes: &[u8]) -> Result<(), String> {
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(bytes)
        .map(|_| ())
        .map_err(|e| e.to_string())
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

#[test]
fn lifted_eh_module_validates_under_the_spec_validator() {
    let root: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (original, lifted, lifted_wat): (Vec<u8>, Vec<u8>, String) =
        lift(&root.join("../../corpus/wasm/wat/eh_numeric_roundtrip.wat"));
    validate(&original).expect("original EH corpus must validate");
    validate(&lifted)
        .unwrap_or_else(|e| panic!("recovered EH module must validate: {e}\n{lifted_wat}"));
}

#[test]
fn recovered_eh_constructs_match_the_original_structure() {
    let root: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (original, lifted, lifted_wat): (Vec<u8>, Vec<u8>, String) =
        lift(&root.join("../../corpus/wasm/wat/eh_numeric_roundtrip.wat"));
    let orig_sum: EhModuleSummary = scan_module_eh(&original).expect("scan original");
    let lift_sum: EhModuleSummary = scan_module_eh(&lifted).expect("scan lifted");

    assert!(
        orig_sum.uses_exception_handling(),
        "the corpus must actually exercise EH"
    );
    assert_eq!(
        orig_sum.constructs, lift_sum.constructs,
        "every EH construct in the source must survive into the recovered output\nlifted:\n{lifted_wat}"
    );
    assert_eq!(
        orig_sum.tag_section_count, lift_sum.tag_section_count,
        "the recovered module must re-declare every exception tag"
    );

    let (ot, oc, ocr): (u64, u64, u64) = throw_catch_totals(&orig_sum);
    let (lt, lc, lcr): (u64, u64, u64) = throw_catch_totals(&lift_sum);
    assert_eq!(ot, lt, "throw count must match the original");
    assert_eq!(oc, lc, "catch count must match the original");
    assert_eq!(ocr, lcr, "catch_ref count must match the original");

    let orig_per_fn: BTreeMap<u32, (u32, u32)> = orig_sum
        .functions
        .iter()
        .map(|(idx, f)| (*idx, (f.legacy_try_blocks, f.try_table_blocks)))
        .collect();
    let lift_per_fn: BTreeMap<u32, (u32, u32)> = lift_sum
        .functions
        .iter()
        .map(|(idx, f)| (*idx, (f.legacy_try_blocks, f.try_table_blocks)))
        .collect();
    assert_eq!(
        orig_per_fn, lift_per_fn,
        "per-function legacy-try and try_table block counts must be preserved"
    );
}

#[cfg(feature = "sandbox")]
#[path = "common/eh_exec.rs"]
mod eh_exec;

#[cfg(feature = "sandbox")]
mod execution {
    use super::eh_exec::{Differential, differential, drop_first_catch_clause};
    use super::lift;
    use std::path::{Path, PathBuf};

    fn corpus() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/wasm/wat/eh_numeric_roundtrip.wat")
    }

    #[test]
    fn modern_eh_exports_execute_equivalently_on_returning_and_throwing_paths() {
        let (original, lifted, lifted_wat): (Vec<u8>, Vec<u8>, String) = lift(&corpus());
        let result: Differential = differential(&original, &lifted).unwrap_or_else(|e| {
            panic!(
                "{e}
{lifted_wat}"
            )
        });
        eprintln!(
            "whole-module EH execution checks: {} ({} returned, {} thrown, {} trapped); legacy-EH exports Wasmtime cannot compile: {:?}",
            result.tally.checked(),
            result.tally.returned,
            result.tally.thrown,
            result.tally.trapped,
            result.stubbed_exports
        );
        assert!(
            result.tally.returned > 0,
            "the whole-module lift must compare modern-EH exports: {:?}",
            result.tally
        );
    }

    #[test]
    fn dropping_a_catch_clause_from_the_whole_module_lift_fails_the_probe() {
        let (original, _, lifted_wat): (Vec<u8>, Vec<u8>, String) = lift(&corpus());
        let mutated: Vec<u8> = wat::parse_str(drop_first_catch_clause(&lifted_wat))
            .expect("mutated whole-module wat must assemble");
        let verdict: Result<Differential, String> = differential(&original, &mutated);
        assert!(
            verdict.is_err(),
            "a whole-module lift missing a catch clause must diverge"
        );
    }
}
