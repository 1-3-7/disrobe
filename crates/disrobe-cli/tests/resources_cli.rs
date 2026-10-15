#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{run_disrobe, temp_dir};

#[test]
fn disrobe_resources_decodes_version_info_and_extracts_the_embedded_payload() {
    let sample: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/native/resources/resources.exe");
    let sample: &str = sample.to_str().expect("utf8 path");
    let run: common::Run = run_disrobe(&["--json", "resources", sample]);
    assert_eq!(run.code, 0, "disrobe resources failed: {}", run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).expect("JSON report");
    assert_eq!(report["version"]["file_version"], "1.2.3.4");
    assert_eq!(
        report["version"]["strings"]["040704b0"]["ProductName"],
        "Disrobe Beispiel"
    );
    assert_eq!(
        report["manifests"][0]["execution_level"],
        "requireAdministrator"
    );

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("resources-cli");
    let out: PathBuf = scratch.path().join("extracted");
    let text: common::Run = run_disrobe(&[
        "resources",
        sample,
        "--extract",
        out.to_str().expect("utf8 path"),
    ]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    assert!(
        text.stdout.contains("RCDATA/PAYLOAD/1033"),
        "{}",
        text.stdout
    );
    let payload: Vec<u8> = std::fs::read(out.join("RCDATA-PAYLOAD-1033.pe")).expect("payload");
    let source: Vec<u8> = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/native/resources/src/payload.bin"),
    )
    .expect("source payload");
    assert_eq!(payload, source);
}
