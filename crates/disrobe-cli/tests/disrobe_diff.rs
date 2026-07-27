#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unwrap_in_result
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::{Capability, scratch::ScratchDir};
use disrobe_ir::{Envelope, RawPayload, Rung, Sidecar, encode_raw};

fn cli_binary() -> PathBuf {
    let mut p: PathBuf = env_target_dir();
    p.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    p
}

fn env_target_dir() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s: &std::ffi::OsStr| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s: &std::ffi::OsStr| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir
}

fn scratch_dir() -> ScratchDir {
    ScratchDir::create("disrobe-envelope-diff").expect("create scratch directory")
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_disrobe(args: &[&str]) -> Run {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} -- run `cargo build -p disrobe-cli` first",
        bin.display()
    );
    let output: std::process::Output = Command::new(&bin)
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn build_envelope(rung: Rung, caps: Vec<Capability>) -> Envelope {
    let hot: Vec<u8> = encode_raw(&RawPayload {
        source_path: "fixture.bin".to_owned(),
        source_bytes: vec![0xde, 0xad, 0xbe, 0xef],
        source_hash: [0u8; 32],
        detected_format: None,
    })
    .expect("encode raw");
    let side: Sidecar = Sidecar {
        produced_by: "disrobe-test".to_owned(),
        produced_by_version: "0.1.0".to_owned(),
        capabilities: caps,
        provenance: std::collections::BTreeMap::new(),
    };
    let cold: Vec<u8> = side.encode().expect("encode sidecar");
    Envelope::new(rung, hot, cold)
}

fn write_envelope(path: &Path, env: &Envelope) {
    let bytes: Vec<u8> = env.encode().expect("encode envelope");
    std::fs::write(path, bytes).expect("write .dr fixture");
}

#[test]
fn diff_identical_envelopes_reports_identical() {
    let dir: ScratchDir = scratch_dir();
    let a: PathBuf = dir.path().join("a.dr");
    write_envelope(
        &a,
        &build_envelope(Rung::Raw, vec![Capability::produces("raw", 1)]),
    );
    let run: Run = run_disrobe(&["envelope", "diff", a.to_str().unwrap(), a.to_str().unwrap()]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("structurally identical"),
        "stdout: {}",
        run.stdout
    );
}

#[test]
fn diff_capability_bump_reports_difference() {
    let dir: ScratchDir = scratch_dir();
    let a: PathBuf = dir.path().join("a.dr");
    let b: PathBuf = dir.path().join("b.dr");
    write_envelope(
        &a,
        &build_envelope(Rung::Raw, vec![Capability::produces("mir.core", 1)]),
    );
    write_envelope(
        &b,
        &build_envelope(Rung::Raw, vec![Capability::produces("mir.core", 2)]),
    );
    let run: Run = run_disrobe(&["envelope", "diff", a.to_str().unwrap(), b.to_str().unwrap()]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("major-changed"),
        "stdout: {}",
        run.stdout
    );
}

#[test]
fn diff_json_emits_machine_report() {
    let dir: ScratchDir = scratch_dir();
    let a: PathBuf = dir.path().join("a.dr");
    let b: PathBuf = dir.path().join("b.dr");
    write_envelope(
        &a,
        &build_envelope(Rung::Raw, vec![Capability::produces("mir.core", 1)]),
    );
    write_envelope(
        &b,
        &build_envelope(Rung::Raw, vec![Capability::produces("mir.core", 2)]),
    );
    let run: Run = run_disrobe(&[
        "envelope",
        "diff",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let parsed: serde_json::Value = serde_json::from_str(&run.stdout).expect("stdout must be json");
    assert_eq!(parsed["identical"], serde_json::Value::Bool(false));
    let diffs: &Vec<serde_json::Value> =
        parsed["differences"].as_array().expect("differences array");
    assert!(!diffs.is_empty(), "expected non-empty differences");
}

#[test]
fn migrate_check_sound_for_identical() {
    let dir: ScratchDir = scratch_dir();
    let a: PathBuf = dir.path().join("a.dr");
    write_envelope(
        &a,
        &build_envelope(Rung::Raw, vec![Capability::produces("raw", 1)]),
    );
    let run: Run = run_disrobe(&[
        "envelope",
        "migrate-check",
        a.to_str().unwrap(),
        a.to_str().unwrap(),
    ]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(run.stdout.contains("SOUND"), "stdout: {}", run.stdout);
}

#[test]
fn migrate_check_unsound_on_major_bump() {
    let dir: ScratchDir = scratch_dir();
    let from: PathBuf = dir.path().join("from.dr");
    let to: PathBuf = dir.path().join("to.dr");
    write_envelope(
        &from,
        &build_envelope(Rung::Raw, vec![Capability::produces("mir.core", 1)]),
    );
    write_envelope(
        &to,
        &build_envelope(Rung::Raw, vec![Capability::requires("mir.core", 2)]),
    );
    let run: Run = run_disrobe(&[
        "envelope",
        "migrate-check",
        from.to_str().unwrap(),
        to.to_str().unwrap(),
    ]);
    assert_ne!(
        run.code, 0,
        "expected non-zero exit; stdout: {}",
        run.stdout
    );
    assert!(run.stderr.contains("DR-CLI-0089"), "stderr: {}", run.stderr);
}

#[test]
fn migrate_check_unsound_on_rung_gap() {
    let dir: ScratchDir = scratch_dir();
    let raw: PathBuf = dir.path().join("raw.dr");
    let surface: PathBuf = dir.path().join("surface.dr");
    write_envelope(
        &raw,
        &build_envelope(Rung::Raw, vec![Capability::produces("raw", 1)]),
    );
    write_envelope(
        &surface,
        &build_envelope(Rung::Surface, vec![Capability::produces("raw", 1)]),
    );
    let run: Run = run_disrobe(&[
        "envelope",
        "migrate-check",
        raw.to_str().unwrap(),
        surface.to_str().unwrap(),
    ]);
    assert_ne!(
        run.code, 0,
        "expected non-zero exit; stdout: {}",
        run.stdout
    );
    assert!(run.stderr.contains("DR-CLI-0089"), "stderr: {}", run.stderr);
}
