#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

const BENIGN: [&str; 6] = [
    "native/compilers/go/hello.go.exe",
    "native/zig/hello.zig.elf",
    "native/formats/hello.pe64.exe",
    "native/formats/hello.auditable.exe",
    "mobile/flutter/disrobe_sample/libapp_arm64.so",
    "python/freezers/pyinstaller/gauntlet/hello.exe",
];

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn cli_binary() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s: &std::ffi::OsStr| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s: &std::ffi::OsStr| s.to_str()) != Some("release")
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

fn fixture(relative: &str) -> PathBuf {
    let path: PathBuf = workspace_root().join("corpus").join(relative);
    assert!(
        path.is_file(),
        "the benign gate needs the tracked fixture {}",
        path.display()
    );
    path
}

fn run_json(args: &[&str], relative: &str) -> Value {
    let bin: PathBuf = cli_binary();
    let output: Output = Command::new(&bin)
        .args(args)
        .arg(fixture(relative))
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", bin.display()));
    assert!(
        output.status.success(),
        "{args:?} {relative} exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{args:?} {relative} must emit json: {error}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn benign_binaries_carry_no_technique_or_anti_analysis_claim() {
    for relative in BENIGN {
        let report: Value = run_json(&["behavior", "--json"], relative);
        let techniques: &Vec<Value> = report["attack_ids"]
            .as_array()
            .unwrap_or_else(|| panic!("{relative}: attack_ids array: {report:#}"));
        assert!(
            techniques.is_empty(),
            "{relative} is an ordinary program, yet reports ATT&CK techniques {techniques:?}"
        );
        let anti: &Vec<Value> = report["anti_analysis"]["findings"]
            .as_array()
            .unwrap_or_else(|| panic!("{relative}: anti_analysis.findings array: {report:#}"));
        assert!(
            anti.is_empty(),
            "{relative} is an ordinary program, yet reports anti-analysis findings {anti:#?}"
        );
    }
}

#[test]
fn benign_binaries_carry_no_malware_family() {
    for relative in BENIGN {
        let report: Value = run_json(&["frisk", "--format", "json"], relative);
        let findings: &Vec<Value> = report["findings"]
            .as_array()
            .unwrap_or_else(|| panic!("{relative}: findings array: {report:#}"));
        let families: Vec<&Value> = findings
            .iter()
            .filter(|finding: &&Value| finding["category"] == "malware_config")
            .collect();
        assert!(
            families.is_empty(),
            "{relative} is an ordinary program, yet reports malware configuration {families:#?}"
        );
    }
}
