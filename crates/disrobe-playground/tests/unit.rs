#![cfg(feature = "chain")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write as _;
use std::path::PathBuf;

use disrobe_playground::circular::{CircularityKind, CircularityReport};
use disrobe_playground::oracle::{OracleKind, OracleResult, OracleVerdict};
use disrobe_playground::report::PlaygroundReport;
use disrobe_playground::scan_circularity;

fn write(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
    let path: PathBuf = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut f: std::fs::File = std::fs::File::create(&path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    path
}

#[test]
fn circular_detector_flags_explicit_marker() {
    let tmp: tempfile::TempDir = tempfile::tempdir().unwrap();
    let goldens: PathBuf = tmp.path().join("goldens");
    write(
        &goldens,
        "evil.golden.json",
        "{\"_p\":\"disrobe-playground:circular-oracle py.deob\"}",
    );
    let report: CircularityReport = scan_circularity(&[tmp.path().to_path_buf()]);
    assert!(!report.is_clean());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == CircularityKind::PassOutputEqualsOwnGolden)
    );
}

#[test]
fn circular_detector_flags_self_emit_provenance() {
    let tmp: tempfile::TempDir = tempfile::tempdir().unwrap();
    let goldens: PathBuf = tmp.path().join("goldens");
    write(
        &goldens,
        "x.golden.json",
        "{\"prov\":\"golden-emitted-by-pass-under-test jvm.classify\"}",
    );
    let report: CircularityReport = scan_circularity(&[tmp.path().to_path_buf()]);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == CircularityKind::SelfEmittedGolden
                && f.pass_id.as_deref() == Some("jvm.classify"))
    );
}

#[test]
fn circular_detector_clean_on_honest_golden() {
    let tmp: tempfile::TempDir = tempfile::tempdir().unwrap();
    let goldens: PathBuf = tmp.path().join("goldens");
    write(
        &goldens,
        "honest.golden.json",
        "{\"input\":\"corpus://x.pyc\",\"expected_source_from\":\"cpython interpreter recompile\"}",
    );
    let report: CircularityReport = scan_circularity(&[tmp.path().to_path_buf()]);
    assert!(
        report.is_clean(),
        "honest golden must not trip: {:#?}",
        report.findings
    );
}

#[test]
fn circular_detector_flags_synthetic_oracle_path() {
    let tmp: tempfile::TempDir = tempfile::tempdir().unwrap();
    let dir: PathBuf = tmp.path().join("goldens").join("synth_oracle");
    write(&dir, "data.json", "{}");
    let report: CircularityReport = scan_circularity(&[tmp.path().to_path_buf()]);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == CircularityKind::SyntheticSelfReference)
    );
}

fn result(oracle: OracleKind, id: &str, verdict: OracleVerdict) -> OracleResult {
    OracleResult {
        oracle,
        pass_under_test: "test.pass".to_owned(),
        fixture_id: id.to_owned(),
        input_rel: format!("corpus://{id}"),
        baseline_rel: None,
        verdict,
    }
}

#[test]
fn reporter_excludes_skips_from_denominator() {
    let results: Vec<OracleResult> = vec![
        result(
            OracleKind::ByteIdenticalUnpack,
            "a",
            OracleVerdict::ByteIdentical,
        ),
        result(
            OracleKind::ByteIdenticalUnpack,
            "b",
            OracleVerdict::ToolMissing {
                tool: "upx".to_owned(),
            },
        ),
        result(
            OracleKind::ByteIdenticalUnpack,
            "c",
            OracleVerdict::FixtureAbsent {
                rel: "x".to_owned(),
            },
        ),
    ];
    let report: PlaygroundReport = PlaygroundReport::from_results(results, 0, 1);
    let row = report.row(OracleKind::ByteIdenticalUnpack).unwrap();
    assert_eq!(row.evaluated, 1, "tool-missing + fixture-absent excluded");
    assert_eq!(row.recovered, 1);
    assert_eq!(row.byte_identical, 1);
    assert_eq!(row.recovery_bp(), 10_000);
}

#[test]
fn reporter_never_rounds_lossy_to_100() {
    let results: Vec<OracleResult> = vec![
        result(
            OracleKind::ByteIdenticalUnpack,
            "a",
            OracleVerdict::ByteIdentical,
        ),
        result(
            OracleKind::ByteIdenticalUnpack,
            "b",
            OracleVerdict::Lossy {
                residual_bp: 1,
                note: "near".to_owned(),
            },
        ),
    ];
    let report: PlaygroundReport = PlaygroundReport::from_results(results, 0, 1);
    let row = report.row(OracleKind::ByteIdenticalUnpack).unwrap();
    assert_eq!(row.evaluated, 2);
    assert_eq!(row.recovered, 1);
    assert!(row.lossy >= 1);
    assert!(
        row.recovery_bp() < 10_000,
        "a lossy fixture must keep the recovery below 100.00%",
    );
}

#[test]
fn reporter_emits_four_kind_vector() {
    let report: PlaygroundReport = PlaygroundReport::from_results(vec![], 0, 1);
    assert_eq!(report.rows.len(), 4);
    assert_eq!(report.headline_vector().len(), 4);
}
