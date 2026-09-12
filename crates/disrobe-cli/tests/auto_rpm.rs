#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::process::{Command, Output, Stdio};

const FIXTURE: &[u8] = include_bytes!("../../disrobe-binfmt/tests/fixtures/rpm/hello-v4-gzip.rpm");
const SCRIPT_BYTES: &[u8] = b"#!/bin/bash\necho aWQ= | base64 -d | bash\n";
const V6_FIXTURE: &[u8] =
    include_bytes!("../../disrobe-binfmt/tests/fixtures/rpm/rpm-v6-bzip2.rpm");

#[test]
fn auto_extracts_and_refeeds_an_rpm_script_member() {
    let input_dir: tempfile::TempDir = tempfile::tempdir().expect("input tempdir");
    let input: std::path::PathBuf = input_dir.path().join("hello.rpm");
    std::fs::write(&input, FIXTURE).expect("write RPM fixture");
    let out: tempfile::TempDir = tempfile::tempdir().expect("output tempdir");

    let output: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(&input)
        .arg("--out")
        .arg(out.path())
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

    let extracted: std::path::PathBuf = out
        .path()
        .join("extracted")
        .join("usr")
        .join("bin")
        .join("disrobe-rpm-fixture");
    assert_eq!(
        std::fs::read(&extracted).expect("read extracted RPM script"),
        SCRIPT_BYTES
    );

    let chain_bytes: Vec<u8> =
        std::fs::read(out.path().join("chain.json")).expect("read chain.json");
    let chain: serde_json::Value = serde_json::from_slice(&chain_bytes).expect("parse chain.json");
    let passes: Vec<&str> = chain["nodes"]
        .as_array()
        .expect("chain nodes")
        .iter()
        .filter_map(|node: &serde_json::Value| node["pass"].as_str())
        .collect();
    assert!(
        passes.contains(&"binfmt.container"),
        "RPM must enter the container pass: {passes:?}"
    );
    assert!(
        passes.contains(&"shell.deob"),
        "the extracted shell member must be re-fed to script recovery: {passes:?}"
    );
}

#[test]
fn auto_extracts_and_refeeds_a_stripped_v6_bzip2_rpm_member() {
    let input_dir: tempfile::TempDir = tempfile::tempdir().expect("input tempdir");
    let input: std::path::PathBuf = input_dir.path().join("basic-v6.rpm");
    std::fs::write(&input, V6_FIXTURE).expect("write RPM fixture");
    let out: tempfile::TempDir = tempfile::tempdir().expect("output tempdir");

    let output: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(&input)
        .arg("--out")
        .arg(out.path())
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

    let extracted: std::path::PathBuf = out
        .path()
        .join("extracted")
        .join("usr")
        .join("bin")
        .join("disrobe-rpm-v6-fixture");
    assert_eq!(
        std::fs::read(&extracted).expect("read extracted RPM script"),
        SCRIPT_BYTES
    );

    let chain_bytes: Vec<u8> =
        std::fs::read(out.path().join("chain.json")).expect("read chain.json");
    let chain: serde_json::Value = serde_json::from_slice(&chain_bytes).expect("parse chain.json");
    let passes: Vec<&str> = chain["nodes"]
        .as_array()
        .expect("chain nodes")
        .iter()
        .filter_map(|node: &serde_json::Value| node["pass"].as_str())
        .collect();
    assert!(
        passes.contains(&"binfmt.container"),
        "RPM must enter the container pass: {passes:?}"
    );
    assert!(
        passes.contains(&"shell.deob"),
        "the extracted shell member must be re-fed to script recovery: {passes:?}"
    );
}
