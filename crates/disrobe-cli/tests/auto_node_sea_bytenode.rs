#![cfg(feature = "chain")]
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
        "disrobe binary missing at {bin:?}; run `cargo build -p disrobe-cli --features chain` first"
    );
    Command::new(&bin)
        .arg("chain")
        .arg(input)
        .arg("--out")
        .arg(out)
        .arg("--chain")
        .arg(chain_arg)
        .arg("--capture-stages")
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe: {e}"))
}

fn read_chain_json(out_dir: &Path) -> String {
    let p: PathBuf = out_dir.join("chain.json");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read chain.json at {p:?}: {e}"))
}

fn read_terminal_stage(out_dir: &Path) -> String {
    let stage_dir: PathBuf = out_dir.join("01-js-deob");
    let p: PathBuf = stage_dir.join("output.bin");
    std::fs::read_to_string(&p).unwrap_or_else(|e: std::io::Error| {
        panic!("cannot read terminal stage output at {p:?}: {e}")
    })
}

#[test]
fn test_chain_node_sea_blob_dispatches_js_deob_and_recovers_flags() {
    let fixture: PathBuf = corpus_path("js/sea/sea-prep.blob");
    if !fixture.exists() {
        eprintln!("SKIP: fixture missing: {fixture:?}");
        return;
    }
    let out: PathBuf = tmp_out("node-sea");
    let proc_out: std::process::Output = run_chain_cli(&fixture, &out, "auto:8");
    assert!(
        proc_out.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );

    let json: String = read_chain_json(&out);
    assert!(
        json.contains("js.deob"),
        "expected js.deob pass dispatched in chain.json; got prefix: {prefix}",
        prefix = &json[..json.len().min(600)]
    );
    assert!(
        json.contains("js-node-sea"),
        "expected node-sea carve tag in chain.json; got prefix: {prefix}",
        prefix = &json[..json.len().min(600)]
    );

    let terminal: String = read_terminal_stage(&out);
    assert!(
        terminal.contains("\"flags\": 5"),
        "expected SEA flags=5 (disable-warning|use-code-cache, matching sea-config.json) \
         at terminal node; got: {terminal}"
    );
}

#[test]
fn test_chain_bytenode_jsc_dispatches_js_deob_and_recovers_v8_header() {
    let fixture: PathBuf = corpus_path("v8/node-22/hello-22.jsc");
    if !fixture.exists() {
        eprintln!("SKIP: fixture missing: {fixture:?}");
        return;
    }
    let out: PathBuf = tmp_out("bytenode-jsc");
    let proc_out: std::process::Output = run_chain_cli(&fixture, &out, "auto:8");
    assert!(
        proc_out.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );

    let json: String = read_chain_json(&out);
    assert!(
        json.contains("js.deob"),
        "expected js.deob pass dispatched in chain.json; got prefix: {prefix}",
        prefix = &json[..json.len().min(600)]
    );
    assert!(
        json.contains("js-bytenode-jsc"),
        "expected bytenode jsc lift tag in chain.json; got prefix: {prefix}",
        prefix = &json[..json.len().min(600)]
    );

    let terminal: String = read_terminal_stage(&out);
    assert!(
        terminal.contains("\"node\": \"node22\""),
        "expected V8 version demangled to node22 from the real cached-data magic \
         at terminal node; got: {terminal}"
    );
    assert!(
        terminal.contains("\"magic_number\": 3235776040"),
        "expected V8_MAGIC_NODE_22 (0xC0DE0628) recovered at terminal node; got: {terminal}"
    );
}
