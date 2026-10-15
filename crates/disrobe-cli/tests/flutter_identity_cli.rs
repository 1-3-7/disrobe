#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{run_disrobe, temp_dir};

fn flutter_corpus(relative: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/mobile/flutter")
        .join(relative)
        .to_str()
        .expect("utf8 path")
        .to_owned()
}

fn oracle() -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(flutter_corpus("pinned_graph_fixture/oracle.json")).expect("oracle"),
    )
    .expect("oracle json")
}

#[test]
fn disrobe_flutter_identity_names_the_sdk_of_a_real_build() {
    let oracle: serde_json::Value = oracle();
    let library: String = flutter_corpus("pinned_graph_fixture/receipt_validator_arm64.so");
    let run: common::Run = run_disrobe(&["--json", "flutter", "identity", &library]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).expect("JSON report");
    assert_eq!(report["container"], "library");
    assert_eq!(
        report["snapshot_hash"],
        oracle["snapshot_compatibility_hash"]
    );
    assert!(
        report["dart_sdk_releases"]
            .as_array()
            .expect("releases")
            .iter()
            .any(|release| release["dart_version"] == oracle["dart_version"]
                && release["dart_revision"] == oracle["dart_sdk_revision"]),
        "{}",
        run.stdout
    );
    assert!(
        report["flutter_releases_with_dart"]
            .as_array()
            .expect("releases")
            .contains(&oracle["flutter_version"])
    );

    let text: common::Run = run_disrobe(&[
        "flutter",
        "identity",
        &flutter_corpus("identity/App_ios_universal"),
    ]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    assert!(
        text.stdout
            .contains("snapshot hash     ace654289f5abc240509fc941453ebc5"),
        "{}",
        text.stdout
    );
    assert!(text.stdout.contains("[x86_64]"), "{}", text.stdout);
}

#[test]
fn disrobe_flutter_identity_refuses_a_non_library_by_name() {
    let run: common::Run = run_disrobe(&[
        "flutter",
        "identity",
        &flutter_corpus("pinned_graph_fixture/oracle.json"),
    ]);
    assert_ne!(run.code, 0);
    let flat: String = run
        .stderr
        .chars()
        .filter(|c: &char| !c.is_whitespace() && *c != '\u{2502}')
        .collect();
    assert!(flat.contains("DR-CLI-0779"), "{}", run.stderr);
    assert!(flat.contains("DR-MOB-0065"), "{}", run.stderr);
}

#[test]
fn mobile_extract_records_the_flutter_identity_in_its_manifest() {
    let oracle: serde_json::Value = oracle();
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("mobile-extract-flutter");
    let out: PathBuf = scratch.path().join("out");
    let run: common::Run = run_disrobe(&[
        "mobile",
        "extract",
        &flutter_corpus("pinned_graph_fixture/receipt_validator_arm64.so"),
        "--out",
        out.to_str().expect("utf8 path"),
    ]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.json")).expect("manifest"))
            .expect("manifest json");
    assert_eq!(
        manifest["identity"]["snapshot_hash"],
        oracle["snapshot_compatibility_hash"]
    );
    assert!(manifest["identity_error"].is_null(), "{manifest}");
    assert!(
        run.stdout.contains(&format!(
            "dart sdk:     3.12.1, {}",
            oracle["dart_version"].as_str().expect("version")
        )),
        "{}",
        run.stdout
    );
}
