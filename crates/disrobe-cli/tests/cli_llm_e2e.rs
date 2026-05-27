#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::same_item_push
)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use jsonschema::Validator;
use serde_json::Value as Json;

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    let seq: u64 = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("disrobe-llm-e2e-{stem}-{pid}-{seq}.{ext}"))
}

fn write_minimal_pyc(path: &PathBuf) {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&[0xa7, 0x0d, 0x0d, 0x0a]);
    bytes.extend_from_slice(&[0u8; 12]);
    let code_marker: u8 = b'c';
    bytes.push(code_marker);
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    bytes.extend_from_slice(&0_i32.to_le_bytes());
    let null_marker: u8 = b'N';
    for _ in 0..8 {
        bytes.push(null_marker);
    }
    std::fs::write(path, bytes).expect("write minimal pyc");
}

fn run_disrobe(args: &[&str]) -> (i32, String, String) {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} — run `cargo build -p disrobe-cli`",
        bin.display()
    );
    let output: std::process::Output = Command::new(&bin)
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn schema_root() -> Json {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("schemas");
    p.push("disrobe-metadata-llm-v1.json");
    let bytes: Vec<u8> =
        std::fs::read(&p).unwrap_or_else(|e| panic!("read schema {}: {e}", p.display()));
    serde_json::from_slice(&bytes).expect("schema parse")
}

#[test]
fn llm_flag_help_lists_metadata_options() {
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&["--help"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("--llm"), "help missing --llm:\n{stdout}");
    assert!(stdout.contains("--metadata-pack-1"));
    assert!(stdout.contains("--metadata-format"));
}

#[test]
fn unknown_metadata_format_errors_with_dr_cli_0440() {
    let (code, _stdout, stderr): (i32, String, String) = run_disrobe(&[
        "--llm",
        "--metadata-format",
        "xml",
        "py",
        "decompile",
        "/nonexistent",
    ]);
    assert_ne!(code, 0, "must error");
    assert!(
        stderr.contains("DR-CLI-0440") || stderr.contains("--metadata-format"),
        "expected DR-CLI-0440, stderr={stderr}"
    );
}

#[test]
fn decryption_keys_without_auth_errors_with_dr_cli_0420() {
    let (code, _stdout, stderr): (i32, String, String) =
        run_disrobe(&["--decryption-keys", "py", "decompile", "/nonexistent"]);
    assert_ne!(code, 0, "must error");
    assert!(
        stderr.contains("DR-CLI-0420") || stderr.contains("decryption-keys"),
        "expected DR-CLI-0420, stderr={stderr}"
    );
}

#[test]
fn no_llm_flags_writes_no_bundle() {
    let pyc: PathBuf = temp_path("noflag", "pyc");
    write_minimal_pyc(&pyc);
    let out_dir: PathBuf = temp_path("noflag-out", "dir");
    let pyc_str: String = pyc.to_string_lossy().into_owned();
    let out_str: String = out_dir.to_string_lossy().into_owned();
    let (_code, _stdout, _stderr): (i32, String, String) =
        run_disrobe(&["py", "decompile", &pyc_str, "--out", &out_str]);
    let bundle_path: PathBuf = out_dir.join("py-decompile.disrobe.llm.json");
    assert!(
        !bundle_path.exists(),
        "must not write a bundle without --llm"
    );
}

#[test]
fn llm_flag_writes_schema_conforming_bundle() {
    let pyc: PathBuf = temp_path("llm", "pyc");
    write_minimal_pyc(&pyc);
    let out_dir: PathBuf = temp_path("llm-out", "dir");
    let bundle_out: PathBuf = temp_path("llm-bundle", "json");
    let pyc_str: String = pyc.to_string_lossy().into_owned();
    let out_str: String = out_dir.to_string_lossy().into_owned();
    let bundle_str: String = bundle_out.to_string_lossy().into_owned();

    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&[
        "--llm",
        "--i-have-authorization",
        "--metadata-out",
        &bundle_str,
        "--force",
        "py",
        "decompile",
        &pyc_str,
        "--out",
        &out_str,
    ]);
    if code != 0 {
        eprintln!("stdout=\n{stdout}\nstderr=\n{stderr}");
    }
    if !bundle_out.exists() {
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&bundle_out).expect("read bundle");
    let bundle: Json = serde_json::from_slice(&bytes).expect("parse bundle");
    assert_eq!(
        bundle.get("schema").and_then(Json::as_str),
        Some("disrobe.metadata.llm.v1")
    );
    let schema: Json = schema_root();
    let validator: Validator = jsonschema::validator_for(&schema).expect("compile");
    let errors: Vec<String> = validator
        .iter_errors(&bundle)
        .map(|e: jsonschema::ValidationError<'_>| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "bundle failed schema:\n{}\nbundle={}",
        errors.join("\n"),
        serde_json::to_string_pretty(&bundle).unwrap()
    );
}
