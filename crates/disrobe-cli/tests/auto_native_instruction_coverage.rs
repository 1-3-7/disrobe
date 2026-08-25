#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::path::{Path, PathBuf};

use serde_json::Value;

const MIXED: &str = "tests/fixtures/native_aarch64_mixed_coverage.elf";

fn find_file_named(root: &Path, target: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(root).ok()?.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            if let Some(found) = find_file_named(&path, target) {
                return Some(found);
            }
        } else if entry.file_name().to_string_lossy() == target {
            return Some(path);
        }
    }
    None
}

fn run_auto(output: &Path) -> String {
    let fixture: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MIXED);
    let run: common::Run = common::run_disrobe(&[
        "auto",
        &fixture.display().to_string(),
        "--out",
        &output.display().to_string(),
    ]);
    assert_eq!(run.code, 0, "auto must succeed: {}", run.stderr);
    let report_path: PathBuf =
        find_file_named(output, "pseudo-source.json").expect("pseudo-source output");
    std::fs::read_to_string(report_path).expect("pseudo-source text")
}

fn named<'a>(entries: &'a Value, name: &str) -> &'a Value {
    entries
        .as_array()
        .expect("function entries must be an array")
        .iter()
        .find(|entry: &&Value| entry["name"] == name)
        .unwrap_or_else(|| panic!("{name} must be present: {entries}"))
}

#[test]
fn auto_native_report_records_lifter_instruction_coverage_from_the_authored_fixture() {
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("create output directory");
    let first: String = run_auto(&scratch.path().join("first"));
    let report: Value = serde_json::from_str(&first).expect("pseudo-source JSON");

    let clean: &Value = named(&report["recovered"], "clean_arith");
    assert_eq!(clean["instruction_coverage"]["span_instructions"], 11);
    assert_eq!(clean["instruction_coverage"]["modelled_instructions"], 11);
    assert_eq!(
        clean["instruction_coverage"]["unmodelled_mnemonics"],
        serde_json::json!([])
    );

    let probe: &Value = named(&report["unrecovered"], "system_probe");
    assert!(
        probe["reason"].as_str().is_some_and(|reason: &str| reason
            .contains("a callee-saved register is not provably restored at the return")),
        "the traced report must preserve the normal lifter refusal: {probe}"
    );
    assert_eq!(probe["instruction_coverage"]["span_instructions"], 3);
    assert_eq!(probe["instruction_coverage"]["modelled_instructions"], 1);
    assert_eq!(
        probe["instruction_coverage"]["unmodelled_mnemonics"],
        serde_json::json!(["mrs", "svc"])
    );

    assert_eq!(report["instruction_coverage"]["span_instructions"], 14);
    assert_eq!(report["instruction_coverage"]["modelled_instructions"], 12);
    assert_eq!(
        report["instruction_coverage"]["unmodelled_mnemonics"],
        serde_json::json!(["mrs", "svc"])
    );

    let second: String = run_auto(&scratch.path().join("second"));
    assert_eq!(
        first, second,
        "coverage serialization must be deterministic"
    );
}
