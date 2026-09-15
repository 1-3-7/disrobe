#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::process::{Command, Output, Stdio};

const FIXTURE: &[u8] =
    include_bytes!("../../disrobe-binfmt/tests/fixtures/enigma/x86_evb_10_70_20240522.exe");
const ORIGINAL_MEMBER: &[u8] =
    include_bytes!("../../disrobe-binfmt/tests/fixtures/enigma/README_packed.txt");

#[test]
fn auto_extracts_the_real_enigma_virtual_box_member() {
    let input_dir: tempfile::TempDir = tempfile::tempdir().expect("input tempdir");
    let input: std::path::PathBuf = input_dir.path().join("enigma-virtual-box.exe");
    std::fs::write(&input, FIXTURE).expect("stage Enigma Virtual Box fixture");
    let output_dir: tempfile::TempDir = tempfile::tempdir().expect("output tempdir");

    let output: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(&input)
        .arg("--out")
        .arg(output_dir.path())
        .arg("--max-depth")
        .arg("3")
        .stdin(Stdio::null())
        .output()
        .expect("run disrobe auto");
    assert!(
        output.status.success(),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let member: std::path::PathBuf = output_dir.path().join("extracted").join("README.txt");
    assert_eq!(
        std::fs::read(member).expect("read recovered Enigma Virtual Box member"),
        ORIGINAL_MEMBER
    );

    let chain_bytes: Vec<u8> =
        std::fs::read(output_dir.path().join("chain.json")).expect("read Enigma Virtual Box chain");
    let chain: serde_json::Value =
        serde_json::from_slice(&chain_bytes).expect("parse Enigma Virtual Box chain");
    let passes: Vec<&str> = chain["nodes"]
        .as_array()
        .expect("chain nodes")
        .iter()
        .filter_map(|node: &serde_json::Value| node["pass"].as_str())
        .collect();
    assert!(
        passes.contains(&"binfmt.container"),
        "Enigma Virtual Box must enter the container pass: {passes:?}"
    );
}
