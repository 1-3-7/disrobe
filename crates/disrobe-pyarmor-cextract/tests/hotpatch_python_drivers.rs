#![cfg(not(target_os = "windows"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_python() -> Option<PathBuf> {
    if let Some(env_value) = std::env::var_os("PYO3_PYTHON") {
        let p: PathBuf = PathBuf::from(env_value);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(out) = std::process::Command::new("uv")
        .args(["python", "find", "3.14"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        && out.status.success()
    {
        let raw: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let p: PathBuf = PathBuf::from(raw);
        if p.is_file() {
            return Some(p);
        }
    }
    let candidates: [&str; 4] = [
        "/usr/bin/python3.14",
        "/usr/local/bin/python3.14",
        "/opt/homebrew/bin/python3.14",
        "/usr/bin/python3",
    ];
    for cand in candidates {
        let p: PathBuf = PathBuf::from(cand);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn cextract_importable(python: &Path) -> bool {
    let out: std::io::Result<Output> = Command::new(python)
        .arg("-c")
        .arg("import disrobe_cextract; print(disrobe_cextract.__version__)")
        .output();
    matches!(out, Ok(o) if o.status.success())
}

fn run_script(script_name: &str, expect_marker: &str) {
    let Some(python): Option<PathBuf> = workspace_python() else {
        eprintln!("SKIP: no python interpreter found");
        return;
    };
    if !cextract_importable(&python) {
        eprintln!(
            "SKIP: disrobe_cextract not importable from {} (run `maturin develop` first)",
            python.display()
        );
        return;
    }
    let script: PathBuf =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/{script_name}"));
    assert!(script.exists(), "missing {}", script.display());
    let output: Output = Command::new(&python).arg(&script).output().expect("spawn");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "{script_name} failed (exit {:?})\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains(expect_marker),
        "{script_name} missing marker '{expect_marker}'\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn hotpatch_selftest_round_trip() {
    run_script(
        "hotpatch_selftest_round_trip.py",
        "OK: hotpatch selftest round-trip succeeded",
    );
}

#[test]
fn backend_selection_respects_env_var() {
    run_script(
        "backend_selection_respects_env_var.py",
        "OK: env var override respected",
    );
}
