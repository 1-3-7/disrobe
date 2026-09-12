#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::process::{Command, Output, Stdio};

const FIRMWARE: &[u8] =
    include_bytes!("../../disrobe-binfmt/tests/fixtures/uefi_fv/edk2_brotli_guided.fv");
const DRIVER: &[u8] = include_bytes!("../../disrobe-binfmt/tests/fixtures/uefi_fv/hello_a.efi");
const TIANO_FIRMWARE: &[u8] =
    include_bytes!("../../disrobe-binfmt/tests/fixtures/uefi_fv/edk2_tiano_guided.fv");
const TIANO_DRIVER: &[u8] =
    include_bytes!("../../disrobe-binfmt/tests/fixtures/uefi_fv/hello_b.efi");

fn run_auto(firmware: &[u8], stem: &str, member: &str, expected: &[u8]) -> serde_json::Value {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&format!("auto-uefi-{stem}-input"))
            .expect("create firmware input directory");
    let firmware_path: std::path::PathBuf = input.path().join(format!("{stem}.fv"));
    std::fs::write(&firmware_path, firmware).expect("stage firmware");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&format!("auto-uefi-{stem}-output"))
            .expect("create firmware output directory");

    let process: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(&firmware_path)
        .arg("--out")
        .arg(output.path())
        .arg("--max-depth")
        .arg("3")
        .stdin(Stdio::null())
        .output()
        .expect("run disrobe auto on firmware");
    assert!(
        process.status.success(),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );

    let recovered: Vec<u8> = std::fs::read(output.path().join(format!("extracted/{member}")))
        .expect("read persisted driver");
    assert_eq!(recovered, expected);
    let chain_bytes: Vec<u8> =
        std::fs::read(output.path().join("chain.json")).expect("read chain report");
    serde_json::from_slice(&chain_bytes).expect("parse chain report")
}

#[test]
fn auto_persists_the_exact_brotli_guided_driver_and_routes_it_to_native_analysis() {
    let chain: serde_json::Value = run_auto(FIRMWARE, "brotli-guided", "BrotliDriver", DRIVER);
    let passes: Vec<&str> = chain["nodes"]
        .as_array()
        .expect("chain nodes")
        .iter()
        .filter_map(|node: &serde_json::Value| node["pass"].as_str())
        .collect();
    assert!(
        passes.contains(&"binfmt.container"),
        "firmware must enter the container pass: {passes:?}"
    );
    assert!(
        passes.contains(&"native.image-classify"),
        "the recovered EFI image must reach native analysis: {passes:?}"
    );
}

#[test]
fn auto_persists_the_exact_tiano_guided_driver_and_routes_it_to_native_analysis() {
    let chain: serde_json::Value =
        run_auto(TIANO_FIRMWARE, "tiano-guided", "TianoDriver", TIANO_DRIVER);
    let passes: Vec<&str> = chain["nodes"]
        .as_array()
        .expect("chain nodes")
        .iter()
        .filter_map(|node: &serde_json::Value| node["pass"].as_str())
        .collect();
    assert!(passes.contains(&"binfmt.container"), "{passes:?}");
    assert!(passes.contains(&"native.image-classify"), "{passes:?}");
}
