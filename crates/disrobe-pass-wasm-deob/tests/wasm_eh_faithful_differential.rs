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
