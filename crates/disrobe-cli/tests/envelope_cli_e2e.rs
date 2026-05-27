#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation
)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static ENVELOPE_FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    while dir.file_name().and_then(|s| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir
}

fn temp_path(stem: &str, ext: &str) -> PathBuf {
    let pid: u32 = std::process::id();
    let seq: u64 = ENVELOPE_FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("disrobe-cli-e2e-{stem}-{pid}-{seq}.{ext}"))
}

fn write_bytes(path: &PathBuf, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write fixture");
}

fn run_disrobe(args: &[&str]) -> (i32, String, String) {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {}. Run `cargo build -p disrobe-cli` first.",
        bin.display()
    );
    let output: std::process::Output = Command::new(&bin).args(args).output().expect("spawn");
    let code: i32 = output.status.code().unwrap_or(-1);
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    (code, stdout, stderr)
}

#[test]
fn envelope_create_then_inspect_roundtrip_empty_file() {
    let src: PathBuf = temp_path("empty", "bin");
    let dr: PathBuf = temp_path("empty", "dr");
    write_bytes(&src, &[]);
    let _ = std::fs::remove_file(&dr);
    let (code, out, err): (i32, String, String) = run_disrobe(&[
        "envelope",
        "create",
        src.to_str().unwrap(),
        "--out",
        dr.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "create stderr: {err}\nstdout: {out}");
    assert!(out.contains("envelope create: OK"));
    let (code2, out2, _): (i32, String, String) =
        run_disrobe(&["envelope", "inspect", dr.to_str().unwrap()]);
    assert_eq!(code2, 0);
    assert!(out2.contains("rung:               Raw"));
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dr);
}

#[test]
fn envelope_create_then_inspect_roundtrip_large_random_bytes() {
    let src: PathBuf = temp_path("large-rand", "bin");
    let dr: PathBuf = temp_path("large-rand", "dr");
    let mut data: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut seed: u32 = 0x9E3779B1;
    for _ in 0..(64 * 1024) {
        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        data.push((seed >> 16) as u8);
    }
    write_bytes(&src, &data);
    let _ = std::fs::remove_file(&dr);
    let (code, out, err): (i32, String, String) = run_disrobe(&[
        "envelope",
        "create",
        src.to_str().unwrap(),
        "--out",
        dr.to_str().unwrap(),
        "--format",
        "bin",
    ]);
    assert_eq!(code, 0, "stderr: {err}\nout: {out}");
    let dr_bytes: Vec<u8> = std::fs::read(&dr).expect("read dr");
    assert!(dr_bytes.len() > 64 * 1024);
    let (code2, _, _): (i32, String, String) =
        run_disrobe(&["envelope", "verify", dr.to_str().unwrap()]);
    assert_eq!(code2, 0);
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dr);
}

#[test]
fn envelope_verify_detects_tamper_on_hot_payload() {
    let src: PathBuf = temp_path("tamper", "bin");
    let dr: PathBuf = temp_path("tamper", "dr");
    write_bytes(&src, b"hello disrobe envelope tamper detection test");
    let _ = std::fs::remove_file(&dr);
    let (code, _, _): (i32, String, String) = run_disrobe(&[
        "envelope",
        "create",
        src.to_str().unwrap(),
        "--out",
        dr.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let mut dr_bytes: Vec<u8> = std::fs::read(&dr).expect("read");
    let last: usize = dr_bytes.len() - 1;
    dr_bytes[last] ^= 0xFF;
    std::fs::write(&dr, &dr_bytes).expect("write tampered");
    let (code2, _, err): (i32, String, String) =
        run_disrobe(&["envelope", "verify", dr.to_str().unwrap()]);
    assert_ne!(code2, 0);
    assert!(err.contains("hash mismatch") || err.contains("DR-CLI-0087"));
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dr);
}

#[test]
fn envelope_inspect_rejects_non_envelope_file() {
    let bogus: PathBuf = temp_path("bogus", "bin");
    write_bytes(&bogus, b"this is not an envelope");
    let (code, _, err): (i32, String, String) =
        run_disrobe(&["envelope", "inspect", bogus.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(err.contains("DR-CLI-0080") || err.contains("envelope"));
    let _ = std::fs::remove_file(&bogus);
}

#[test]
fn envelope_create_refuses_to_overwrite_existing() {
    let src: PathBuf = temp_path("noclobber", "bin");
    let dr: PathBuf = temp_path("noclobber", "dr");
    write_bytes(&src, b"first");
    let _ = std::fs::remove_file(&dr);
    let (code, _, _): (i32, String, String) = run_disrobe(&[
        "envelope",
        "create",
        src.to_str().unwrap(),
        "--out",
        dr.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let (code2, _, err): (i32, String, String) = run_disrobe(&[
        "envelope",
        "create",
        src.to_str().unwrap(),
        "--out",
        dr.to_str().unwrap(),
    ]);
    assert_ne!(code2, 0);
    assert!(err.contains("DR-CLI-0086") || err.to_lowercase().contains("exists"));
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dr);
}

#[test]
fn envelope_create_rejects_unsupported_rung_value() {
    let src: PathBuf = temp_path("badrung", "bin");
    let dr: PathBuf = temp_path("badrung", "dr");
    write_bytes(&src, b"x");
    let _ = std::fs::remove_file(&dr);
    let (code, _, err): (i32, String, String) = run_disrobe(&[
        "envelope",
        "create",
        src.to_str().unwrap(),
        "--out",
        dr.to_str().unwrap(),
        "--rung",
        "mir",
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("DR-CLI-0082"));
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dr);
}

#[test]
fn envelope_create_rejects_missing_source_file() {
    let missing: PathBuf = temp_path("missing-source-nonexistent", "bin");
    let dr: PathBuf = temp_path("missing-source-nonexistent", "dr");
    let _ = std::fs::remove_file(&missing);
    let _ = std::fs::remove_file(&dr);
    let (code, _, err): (i32, String, String) = run_disrobe(&[
        "envelope",
        "create",
        missing.to_str().unwrap(),
        "--out",
        dr.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("DR-CLI-0083") || err.contains("cannot read"));
}

#[test]
fn envelope_verify_handles_truncated_file() {
    let src: PathBuf = temp_path("trunc", "bin");
    let dr: PathBuf = temp_path("trunc", "dr");
    write_bytes(&src, b"truncate me to expose the header guard");
    let _ = std::fs::remove_file(&dr);
    let (code, _, _): (i32, String, String) = run_disrobe(&[
        "envelope",
        "create",
        src.to_str().unwrap(),
        "--out",
        dr.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let dr_bytes: Vec<u8> = std::fs::read(&dr).expect("read");
    std::fs::write(&dr, &dr_bytes[..10]).expect("truncate");
    let (code2, _, err): (i32, String, String) =
        run_disrobe(&["envelope", "verify", dr.to_str().unwrap()]);
    assert_ne!(code2, 0);
    assert!(err.contains("DR-CLI-0087") || err.contains("envelope"));
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dr);
}
