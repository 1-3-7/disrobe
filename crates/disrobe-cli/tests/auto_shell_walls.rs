#![cfg(all(feature = "auto", feature = "shell"))]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn committed(rel: &str) -> PathBuf {
    let path: PathBuf = workspace_root().join(rel);
    assert!(
        path.is_file(),
        "the committed fixture {} is missing; restore it from git",
        path.display()
    );
    path
}

fn auto_chain(rel: &str) -> serde_json::Value {
    let input: PathBuf = committed(rel);
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-shell-walls").expect("output dir");
    let process: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(&input)
        .arg("--out")
        .arg(output.path())
        .output()
        .expect("run disrobe auto");
    assert!(
        process.status.success(),
        "disrobe auto {rel} failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let bytes: Vec<u8> = std::fs::read(output.path().join("chain.json")).expect("read chain.json");
    serde_json::from_slice(&bytes).expect("parse chain.json")
}

fn shell_nodes(chain: &serde_json::Value) -> Vec<serde_json::Value> {
    chain["nodes"]
        .as_array()
        .expect("chain nodes")
        .iter()
        .filter(|node: &&serde_json::Value| node["pass"] == "shell.deob")
        .cloned()
        .collect()
}

#[test]
fn office_files_without_macros_end_in_a_typed_shell_wall() {
    let cases: [&str; 3] = [
        "crates/disrobe-pass-shell/tests/fixtures/office_walls/memo.doc",
        "crates/disrobe-pass-shell/tests/fixtures/office_walls/memo_encrypted.docx",
        "crates/disrobe-pass-shell/tests/fixtures/office_walls/memo.msg",
    ];
    let mut failures: Vec<String> = Vec::new();
    for rel in cases {
        let chain: serde_json::Value = auto_chain(rel);
        let nodes: Vec<serde_json::Value> = shell_nodes(&chain);
        let walled: bool = nodes.len() == 1
            && nodes[0]["verdict"] == "error"
            && nodes[0]["output_kind"].is_null()
            && nodes[0]["error"]
                .as_str()
                .is_some_and(|error: &str| error.contains("DR-SHELL-09"));
        if !walled {
            failures.push(format!(
                "{rel}: expected one shell.deob node refused with a DR-SHELL code, got {nodes:#?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_vba_input_is_claimed_once_and_its_rendered_output_is_not_reclaimed() {
    let cases: [(&str, &str); 3] = [
        ("corpus/shell/vba/megafile/EdgeCases.bas", "not-applicable"),
        ("corpus/shell/vba/vbaProject.bin", "complete"),
        ("corpus/shell/vba/hello.docm", "complete"),
    ];
    let mut failures: Vec<String> = Vec::new();
    for (rel, verdict) in cases {
        let chain: serde_json::Value = auto_chain(rel);
        let nodes: Vec<serde_json::Value> = shell_nodes(&chain);
        let expected: bool = matches!(
            nodes.as_slice(),
            [only] if only["parent_id"] == 0 && only["verdict"] == verdict && only["error"].is_null()
        );
        if !expected {
            failures.push(format!(
                "{rel}: expected shell.deob to claim the input once, ending {verdict}, got {nodes:#?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn chain_json_records_the_recovered_language_or_report_of_each_dialect() {
    let cases: [(&str, &str, &str); 5] = [
        (
            "corpus/shell/powershell/invoke-obfuscation/encoding/hello.ps1",
            "source",
            "PowerShell",
        ),
        ("corpus/shell/batch/seta/hello.bat", "source", "Batch"),
        ("corpus/shell/vba/vbaProject.bin", "source", "VBA"),
        ("corpus/shell/vba/hello.docm", "source", "VBA"),
        ("corpus/shell/pdf/launch_action.pdf", "report", "pdf"),
    ];
    let mut failures: Vec<String> = Vec::new();
    for (rel, kind, name) in cases {
        let chain: serde_json::Value = auto_chain(rel);
        let nodes: Vec<serde_json::Value> = shell_nodes(&chain);
        let recorded: Option<&serde_json::Value> = nodes
            .first()
            .map(|node: &serde_json::Value| &node["output_kind"]);
        let matches: bool = recorded.is_some_and(|output_kind: &serde_json::Value| {
            let field: &str = if kind == "report" {
                "format_tag"
            } else {
                "language"
            };
            output_kind["kind"] == kind && output_kind[field] == name
        });
        if !matches {
            failures.push(format!(
                "{rel}: expected shell.deob output kind {kind} {name}, got {recorded:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
