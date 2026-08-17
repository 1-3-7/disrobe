#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::process::{Command, Output, Stdio};

const FIRMWARE: &[u8] =
    include_bytes!("../../disrobe-binfmt/tests/fixtures/uefi_fv/edk2_brotli_guided.fv");
const DRIVER: &[u8] = include_bytes!("../../disrobe-binfmt/tests/fixtures/uefi_fv/hello_a.efi");

#[test]
fn auto_persists_the_exact_brotli_guided_driver_and_routes_it_to_native_analysis() {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-uefi-brotli-input")
            .expect("create firmware input directory");
    let firmware_path: std::path::PathBuf = input.path().join("brotli-guided.fv");
    std::fs::write(&firmware_path, FIRMWARE).expect("stage Brotli-guided firmware");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-uefi-brotli-output")
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
        .expect("run disrobe auto on Brotli-guided firmware");
    assert!(
        process.status.success(),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );

    let recovered: Vec<u8> = std::fs::read(output.path().join("extracted/BrotliDriver"))
        .expect("read persisted Brotli-guided driver");
    assert_eq!(recovered, DRIVER);

    let chain_bytes: Vec<u8> =
        std::fs::read(output.path().join("chain.json")).expect("read chain report");
    let chain: serde_json::Value =
        serde_json::from_slice(&chain_bytes).expect("parse chain report");
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
