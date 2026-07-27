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
fn tmp_out(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-chain-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
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

fn run_hermes_decompile(input: &Path, out: &Path) -> std::process::Output {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "disrobe binary missing at {bin:?}; run `cargo build -p disrobe-cli` first"
    );
    Command::new(&bin)
        .arg("hermes")
        .arg("decompile")
        .arg(input)
        .arg("--out")
        .arg(out)
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe hermes: {e}"))
}

fn read_chain_json(out_dir: &Path) -> String {
    let p: PathBuf = out_dir.join("chain.json");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read chain.json at {p:?}: {e}"))
}

const HERMES_MAGIC_LE_BYTES: [u8; 8] = [0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f];
const RECOVERED_TOKEN: &str = "disrobe-hermes-token";

#[test]
fn test_chain_rn_hermes_to_js() {
    let fixture: PathBuf = corpus_path("mobile/hermes/hello/index.android.bundle");
    if !fixture.exists() {
        eprintln!("SKIP: fixture missing: {fixture:?}");
        return;
    }

    let raw: Vec<u8> = std::fs::read(&fixture)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read hermes fixture {fixture:?}: {e}"));
    assert!(
        raw.len() >= 8 && raw[..8] == HERMES_MAGIC_LE_BYTES,
        "fixture must begin with the Hermes bytecode magic, got {:?}",
        &raw[..raw.len().min(8)]
    );

    let chain_out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("rn-hermes-chain");

    let chain_out: PathBuf = chain_out_scratch.path().to_path_buf();
    let chain_proc: std::process::Output = run_chain_cli(&fixture, &chain_out, "auto:8");
    assert!(
        chain_proc.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&chain_proc.stderr)
    );
    let chain_json: String = read_chain_json(&chain_out);
    assert!(
        chain_json.contains("mobile.classify"),
        "expected mobile.classify pass in chain.json; got prefix: {prefix}",
        prefix = &chain_json[..chain_json.len().min(800)]
    );
    assert!(
        chain_json.contains("react-native-hermes") || chain_json.contains("hermes-magic"),
        "expected Hermes classification tag in chain.json; got prefix: {prefix}",
        prefix = &chain_json[..chain_json.len().min(800)]
    );

    let herm_out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("rn-hermes-decompile");

    let herm_out: PathBuf = herm_out_scratch.path().to_path_buf();
    let herm_proc: std::process::Output = run_hermes_decompile(&fixture, &herm_out);
    assert!(
        herm_proc.status.success(),
        "hermes decompile failed: {}",
        String::from_utf8_lossy(&herm_proc.stderr)
    );
    let js_path: PathBuf = herm_out.join("index.android.js");
    let js: String = std::fs::read_to_string(&js_path)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read lifted JS at {js_path:?}: {e}"));
    assert!(
        js.contains("hermes_version=96"),
        "lifted source must carry the recovered Hermes version banner; got prefix: {prefix}",
        prefix = &js[..js.len().min(400)]
    );
    assert!(
        js.contains(RECOVERED_TOKEN),
        "lifted source must surface the recovered string-table token {RECOVERED_TOKEN:?}; got: {js}"
    );
}
