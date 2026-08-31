#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_wasm_deob::{BoundaryLinks, extract_signatures};

const BOUNDARY_WAT: &str = r#"(module
    (import "host" "call" (func (param i32)))
    (import "host" "memory" (memory 1))
    (import "host" "table" (table 1 funcref))
    (import "host" "global" (global i32))
    (export "call_out" (func 0))
    (export "memory_out" (memory 0))
    (export "table_out" (table 0))
    (export "global_out" (global 0)))"#;

fn cli_binary() -> PathBuf {
    let executable: PathBuf = std::env::current_exe().expect("current test executable");
    let mut target_dir: PathBuf = executable
        .parent()
        .expect("test executable parent")
        .to_path_buf();
    while target_dir.file_name().and_then(|name| name.to_str()) != Some("debug") {
        assert!(target_dir.pop(), "test executable has a debug ancestor");
    }
    target_dir.join(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    })
}

#[test]
fn wasm_deob_writes_a_canonical_boundary_links_sidecar() {
    let module: Vec<u8> = wat::parse_str(BOUNDARY_WAT).expect("boundary module assembles");
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("scratch directory");
    let input: PathBuf = scratch.path().join("boundary.wasm");
    let output: PathBuf = scratch.path().join("boundary.deob.wat");
    std::fs::write(&input, &module).expect("write module");

    let run = |output: &PathBuf| {
        Command::new(cli_binary())
            .args(["wasm", "deob", input.to_str().expect("input path"), "--out"])
            .arg(output)
            .output()
            .expect("run disrobe")
    };
    let first = run(&output);
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let sidecar: PathBuf = output.with_extension("boundary-links.json");
    let written: Vec<u8> = std::fs::read(&sidecar).expect("boundary-links sidecar");
    let expected: Vec<u8> = extract_signatures(&module)
        .expect("extract boundary links")
        .boundary_links()
        .to_json()
        .expect("serialize boundary links");
    let validated: BoundaryLinks = BoundaryLinks::from_json(&written).expect("validated sidecar");

    assert_eq!(written, expected);
    assert_eq!(validated.schema_version(), 1);
    assert_eq!(validated.links().len(), 8);

    let second = run(&output);
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        std::fs::read(&sidecar).expect("repeat boundary-links sidecar"),
        written
    );
}

#[test]
fn wasm_deob_writes_an_empty_boundary_links_sidecar() {
    let module: &[u8] = b"\0asm\x01\x00\x00\x00";
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("scratch directory");
    let input: PathBuf = scratch.path().join("empty.wasm");
    let output: PathBuf = scratch.path().join("empty.deob.wat");
    std::fs::write(&input, module).expect("write module");

    let output_result = Command::new(cli_binary())
        .args(["wasm", "deob", input.to_str().expect("input path"), "--out"])
        .arg(&output)
        .output()
        .expect("run disrobe");
    assert!(
        output_result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output_result.stderr)
    );

    let sidecar: PathBuf = output.with_extension("boundary-links.json");
    let bytes: Vec<u8> = std::fs::read(sidecar).expect("boundary-links sidecar");
    let links: BoundaryLinks = BoundaryLinks::from_json(&bytes).expect("validated empty sidecar");
    assert_eq!(links.schema_version(), 1);
    assert!(links.links().is_empty());
}

#[test]
fn wasm_deob_reports_a_boundary_links_write_failure_without_success_output() {
    let module: Vec<u8> = wat::parse_str(BOUNDARY_WAT).expect("boundary module assembles");
    let scratch: tempfile::TempDir = tempfile::tempdir().expect("scratch directory");
    let input: PathBuf = scratch.path().join("write-failure.wasm");
    let output: PathBuf = scratch.path().join("write-failure.deob.wat");
    let sidecar: PathBuf = output.with_extension("boundary-links.json");
    std::fs::write(&input, module).expect("write module");
    std::fs::create_dir(&sidecar).expect("block boundary-links sidecar");

    let result = Command::new(cli_binary())
        .args(["wasm", "deob", input.to_str().expect("input path"), "--out"])
        .arg(&output)
        .output()
        .expect("run disrobe");
    let stdout: String = String::from_utf8_lossy(&result.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&result.stderr).into_owned();

    assert!(
        !result.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("DR-CLI-0042: cannot write boundary links"),
        "stderr: {stderr}"
    );
    assert!(
        !stdout.contains("boundary links:"),
        "success output must not name the failed sidecar: {stdout}"
    );
}
