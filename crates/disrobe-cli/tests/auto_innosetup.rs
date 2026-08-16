#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Output, Stdio};

const FIXTURE: &[u8] =
    include_bytes!("../../disrobe-binfmt/tests/fixtures/innosetup/innosetup-6.3.3.exe");

fn recovered_compilers(root: &Path, compilers: &mut Vec<Vec<u8>>) {
    let entries: std::fs::ReadDir = std::fs::read_dir(root).expect("read batch output");
    for entry in entries {
        let path: std::path::PathBuf = entry.expect("read batch entry").path();
        if path.is_dir() {
            recovered_compilers(&path, compilers);
        } else if path.file_name().and_then(std::ffi::OsStr::to_str) == Some("Compil32.exe") {
            compilers.push(std::fs::read(path).expect("read recovered compiler"));
        }
    }
}

fn batch_compilers(jobs: u32) -> Vec<Vec<u8>> {
    let input: tempfile::TempDir = tempfile::tempdir().expect("batch input tempdir");
    for name in ["inno-a.exe", "inno-b.exe"] {
        std::fs::write(input.path().join(name), FIXTURE).expect("stage Inno Setup fixture");
    }
    let output: tempfile::TempDir = tempfile::tempdir().expect("batch output tempdir");
    let process: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(input.path())
        .arg("--out")
        .arg(output.path())
        .arg("--jobs")
        .arg(jobs.to_string())
        .arg("--max-depth")
        .arg("3")
        .stdin(Stdio::null())
        .output()
        .expect("run batch auto");
    assert!(
        process.status.success(),
        "disrobe auto batch failed for jobs={jobs}: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let mut compilers: Vec<Vec<u8>> = Vec::new();
    recovered_compilers(output.path(), &mut compilers);
    compilers.sort();
    assert_eq!(compilers.len(), 2);
    compilers
}

#[test]
fn auto_extracts_and_refeeds_a_real_inno_setup_member() {
    let input_dir: tempfile::TempDir = tempfile::tempdir().expect("input tempdir");
    let input: std::path::PathBuf = input_dir.path().join("innosetup-6.3.3.exe");
    std::fs::write(&input, FIXTURE).expect("write Inno Setup fixture");
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

    let compiler: std::path::PathBuf = out
        .path()
        .join("extracted")
        .join("app")
        .join("Compil32.exe");
    let compiler_bytes: Vec<u8> =
        std::fs::read(&compiler).expect("read extracted Inno Setup compiler");
    assert_eq!(compiler_bytes.len(), 3_940_272);
    assert!(compiler_bytes.starts_with(b"MZ"));

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
        "Inno Setup must enter the container pass: {passes:?}"
    );
    assert!(
        passes.contains(&"native.image-classify"),
        "the extracted compiler must be re-fed to native recovery: {passes:?}"
    );
}

#[test]
fn batch_auto_is_byte_identical_at_one_and_four_jobs() {
    assert_eq!(batch_compilers(1), batch_compilers(4));
}
