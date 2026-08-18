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

mod common;

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
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir
        .file_name()
        .and_then(|part: &std::ffi::OsStr| part.to_str())
        != Some("debug")
        && dir
            .file_name()
            .and_then(|part: &std::ffi::OsStr| part.to_str())
            != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
}

#[allow(clippy::disallowed_methods)]
fn tmp_out(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-chain-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn upx_available() -> bool {
    let r: std::io::Result<std::process::Output> = Command::new("upx").arg("--version").output();
    r.is_ok_and(|o: std::process::Output| o.status.success())
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

fn read_chain_json(out_dir: &Path) -> String {
    let p: PathBuf = out_dir.join("chain.json");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read chain.json at {p:?}: {e}"))
}

#[test]
fn test_chain_upx_to_pe() {
    let fixture: PathBuf = corpus_path("native/packers/upx/rg.packed.upx.exe");
    if common::uncommitted_corpus_is_absent(&fixture, "the upx-packed PE chain") {
        return;
    }
    if !upx_available() {
        common::unmeasured(
            "the upx-packed PE chain",
            "no upx CLI is on PATH and no workflow installs one",
            common::REQUIRE_UPX,
        );
        return;
    }
    let out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("upx");
    let out: PathBuf = out_scratch.path().to_path_buf();
    let proc_out: std::process::Output = run_chain_cli(&fixture, &out, "auto:8");
    assert!(
        proc_out.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );
    let json: String = read_chain_json(&out);
    assert!(
        json.contains("native.packer-unpack"),
        "expected packer pass in chain.json; got: {json}"
    );
    assert!(
        json.contains("upx") || json.contains("UPX"),
        "expected upx tag in chain.json"
    );
}

#[test]
fn test_chain_pyarmor_to_pyc() {
    let fixture: PathBuf = corpus_path(
        "python/pyarmor/v8/basic/chunk_00_try_except_basic_try_except_else/chunk_00_try_except_basic_try_except_else.py",
    );
    assert!(
        fixture.exists(),
        "{} is tracked in git and this case grades nothing without it, so its absence is a \
         damaged checkout rather than an optional dependency",
        fixture.display()
    );
    let out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("pyarmor");
    let out: PathBuf = out_scratch.path().to_path_buf();
    let proc_out: std::process::Output = run_chain_cli(&fixture, &out, "auto:8");
    assert!(
        proc_out.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );
    let json: String = read_chain_json(&out);
    assert!(
        json.contains("pyarmor.unpack") || json.contains("pyarmor"),
        "expected pyarmor pass referenced in chain.json; got: {json}"
    );
}

#[test]
fn test_chain_js_obfuscator_to_source() {
    let fixture: PathBuf = corpus_path("js/javascript-obfuscator/obfuscated.js");
    assert!(
        fixture.exists(),
        "{} is tracked in git and this case grades nothing without it, so its absence is a \
         damaged checkout rather than an optional dependency",
        fixture.display()
    );
    let out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("jsobf");
    let out: PathBuf = out_scratch.path().to_path_buf();
    let proc_out: std::process::Output = run_chain_cli(&fixture, &out, "auto:8");
    assert!(
        proc_out.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );
    let json: String = read_chain_json(&out);
    assert!(
        json.contains("js.deob") || json.contains("javascript-obfuscator") || json.contains("js-"),
        "expected js.deob pass referenced in chain.json; got prefix: {prefix}",
        prefix = &json[..json.len().min(500)]
    );
}

#[test]
fn test_chain_squashfs_to_files() {
    let fixture: PathBuf = corpus_path("binfmt/squashfs/hello.squashfs");
    if common::uncommitted_corpus_is_absent(&fixture, "the squashfs container chain") {
        return;
    }
    let out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("squashfs");
    let out: PathBuf = out_scratch.path().to_path_buf();
    let proc_out: std::process::Output = run_chain_cli(&fixture, &out, "auto:8");
    assert!(
        proc_out.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );
    let json: String = read_chain_json(&out);
    assert!(
        json.contains("container.unpack") || json.contains("squashfs"),
        "expected container.unpack referenced in chain.json; got prefix: {prefix}",
        prefix = &json[..json.len().min(500)]
    );
}

#[test]
fn test_chain_stacked_upx_then_js() {
    let fixture: PathBuf = corpus_path("js/sea/sea-prep.blob");
    assert!(
        fixture.exists(),
        "{} is tracked in git and this case grades nothing without it, so its absence is a \
         damaged checkout rather than an optional dependency",
        fixture.display()
    );
    let out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("upx-js-sea");
    let out: PathBuf = out_scratch.path().to_path_buf();
    let proc_out: std::process::Output = run_chain_cli(&fixture, &out, "auto:8");
    assert!(
        proc_out.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );
    let json: String = read_chain_json(&out);
    assert!(
        json.contains("schema") && json.contains("disrobe.chain"),
        "chain.json must be schema-compliant; got prefix: {prefix}",
        prefix = &json[..json.len().min(500)]
    );
}

#[test]
fn test_chain_emits_v1_schema() {
    let fixture: PathBuf = corpus_path("native/packers/upx/hello.exe");
    if common::uncommitted_corpus_is_absent(&fixture, "the plan-only chain schema") {
        return;
    }
    let out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("schema");
    let out: PathBuf = out_scratch.path().to_path_buf();
    let proc_out: std::process::Output = run_chain_cli(&fixture, &out, "?:4");
    assert!(
        proc_out.status.success(),
        "chain plan-only failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );
    let json: String = read_chain_json(&out);
    assert!(
        json.contains("disrobe.chain/v1"),
        "expected schema v1 in chain.json"
    );
}
