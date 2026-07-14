#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::{run_disrobe, temp_dir};

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn fixture_pdb() -> Option<PathBuf> {
    let path: PathBuf =
        workspace_root().join("crates/disrobe-pass-native/tests/fixtures/pdb_cxx_recovery.pdb");
    path.exists().then_some(path)
}

#[test]
fn native_pdb_cxx_reconstructs_headers_from_the_real_fixture() {
    let Some(pdb): Option<PathBuf> = fixture_pdb() else {
        eprintln!("SKIP: real pdb fixture missing (pdb_cxx_recovery.pdb)");
        return;
    };
    let out: PathBuf = temp_dir("pdb-cxx-headers");

    let run: common::Run = run_disrobe(&[
        "native",
        "pdb-cxx",
        pdb.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(run.code, 0, "native pdb-cxx failed: {}", run.stderr);
    assert!(
        run.stdout.contains("native pdb-cxx: OK"),
        "text summary must report success; stdout:\n{}",
        run.stdout
    );

    let header_path: PathBuf = out.join("pdb_cxx_recovery.h");
    let header: String =
        std::fs::read_to_string(&header_path).unwrap_or_else(|e: std::io::Error| {
            panic!(
                "read reconstructed header at {}: {e}",
                header_path.display()
            )
        });
    assert!(
        header.contains("Vector3") && header.contains("struct"),
        "header must reconstruct struct Vector3; got:\n{header}"
    );
    assert!(
        header.contains("Node"),
        "header must reconstruct the self-referential Node struct; got:\n{header}"
    );
    assert!(
        header.contains("ColorTag"),
        "header must reconstruct enum ColorTag; got:\n{header}"
    );

    let report_path: PathBuf = out.join("pdb_cxx_recovery.pdb-cxx.json");
    let report_text: String =
        std::fs::read_to_string(&report_path).unwrap_or_else(|e: std::io::Error| {
            panic!("read report at {}: {e}", report_path.display())
        });
    let report: serde_json::Value =
        serde_json::from_str(&report_text).expect("report must be valid JSON");
    assert_eq!(report["schema"], "disrobe.native.pdb-cxx/v1");
    let udts_recovered: u64 = report["udts_recovered"].as_u64().expect("udts_recovered");
    assert!(
        udts_recovered >= 4,
        "must recover at least the 4 hand-authored UDTs (Vector3, Payload, Flags, Node); got {udts_recovered}"
    );
    let enums_recovered: u64 = report["enums_recovered"].as_u64().expect("enums_recovered");
    assert_eq!(
        enums_recovered, 2,
        "must recover both ColorTag and Priority enums"
    );
    assert_eq!(
        report["deferred_count"].as_u64(),
        Some(0),
        "the hand-authored fixture must not trip any reject path: {report}"
    );
}

#[test]
fn native_pdb_cxx_json_summary_reports_deferred_reasons_shape() {
    let Some(pdb): Option<PathBuf> = fixture_pdb() else {
        eprintln!("SKIP: real pdb fixture missing (pdb_cxx_recovery.pdb)");
        return;
    };
    let out: PathBuf = temp_dir("pdb-cxx-json");

    let run: common::Run = run_disrobe(&[
        "--json",
        "native",
        "pdb-cxx",
        pdb.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(run.code, 0, "native pdb-cxx failed: {}", run.stderr);

    let summary: serde_json::Value =
        serde_json::from_str(&run.stdout).expect("stdout must be valid JSON");
    assert_eq!(summary["schema"], "disrobe.native.pdb-cxx/v1");
    assert!(summary["udts_recovered"].as_u64().unwrap_or(0) > 0);
    assert!(summary["deferred"].is_array());
    assert_eq!(
        summary["deferred"].as_array().map(Vec::len),
        summary["deferred_count"].as_u64().map(|n: u64| n as usize)
    );
}
