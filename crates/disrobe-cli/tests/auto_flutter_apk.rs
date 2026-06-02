#![cfg(all(feature = "chain", feature = "mobile"))]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus_path(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join(rel)
}

fn cargo_bin() -> PathBuf {
    let exe_name: &str = if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    };
    let mut p: PathBuf = workspace_root();
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push(exe_name);
    p
}

#[allow(clippy::disallowed_methods)]
fn tmp_out(name: &str) -> PathBuf {
    let stamp: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    std::env::temp_dir().join(format!("disrobe-chain-{name}-{stamp}"))
}

fn run_chain_cli(input: &Path, out: &Path, chain_arg: &str) -> std::process::Output {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "disrobe binary missing at {bin:?}; run `cargo build -p disrobe-cli` first"
    );
    Command::new(&bin)
        .arg("chain")
        .arg(input)
        .arg("--out")
        .arg(out)
        .arg("--chain")
        .arg(chain_arg)
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe: {e}"))
}

fn read_json(out_dir: &Path, name: &str) -> String {
    let p: PathBuf = out_dir.join(name);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read {name} at {p:?}: {e}"))
}

#[test]
fn auto_flutter_apk_recovers_dart_aot_snapshot_structures() {
    let fixture: PathBuf = corpus_path("mobile/flutter/rustdesk/libapp.so");
    if !fixture.exists() {
        eprintln!("SKIP: fixture missing: {fixture:?}");
        return;
    }

    let out: PathBuf = tmp_out("flutter-apk");
    let proc_out: std::process::Output = run_chain_cli(&fixture, &out, "auto:8");
    assert!(
        proc_out.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );

    let chain_json: String = read_json(&out, "chain.json");
    assert!(
        chain_json.contains("mobile.classify"),
        "chain must route the Flutter libapp.so through mobile.classify; got prefix: {prefix}",
        prefix = &chain_json[..chain_json.len().min(800)]
    );
    assert!(
        chain_json.contains("flutter-aot"),
        "terminal node must carry the recovered flutter-aot AOT-snapshot structure tag; got prefix: {prefix}",
        prefix = &chain_json[..chain_json.len().min(800)]
    );

    let recovery_json: String = read_json(&out, "recovery.json");
    let recovery: serde_json::Value =
        serde_json::from_str(&recovery_json).expect("recovery.json must be valid JSON");
    let passes: &Vec<serde_json::Value> = recovery
        .get("passes")
        .and_then(serde_json::Value::as_array)
        .expect("recovery.json must list passes");
    let mobile_pass: &serde_json::Value = passes
        .iter()
        .find(|p: &&serde_json::Value| {
            p.get("name").and_then(serde_json::Value::as_str) == Some("mobile.classify")
        })
        .expect("mobile.classify must appear in recovery passes");
    assert_eq!(
        mobile_pass
            .get("format_in")
            .and_then(serde_json::Value::as_str),
        Some("flutter-aot"),
        "mobile.classify must report the structurally recovered flutter-aot format"
    );
    assert_eq!(
        mobile_pass
            .get("status")
            .and_then(serde_json::Value::as_str),
        Some("advanced"),
        "mobile.classify must advance the chain after parsing the Dart AOT snapshot layout"
    );

    eprintln!(
        "flutter AOT chain recovered structures: mobile.classify -> flutter-aot (status=advanced)"
    );
}
