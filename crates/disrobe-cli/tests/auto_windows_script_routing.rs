#![cfg(all(feature = "auto", feature = "shell"))]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn corpus(rel: &str) -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join("corpus").join(rel)
}

fn read_fixture(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus(rel);
    assert!(
        path.is_file(),
        "the committed fixture {} is missing; restore it from git",
        path.display()
    );
    std::fs::read(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("reading {}: {error}", path.display()))
}

fn run_auto_cli(bytes: &[u8], file_name: &str, purpose: &str) -> disrobe_core::scratch::ScratchDir {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&format!("auto-{purpose}-input"))
            .expect("create auto input directory");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&format!("auto-{purpose}-output"))
            .expect("create auto output directory");
    let input_path: PathBuf = input.path().join(file_name);
    std::fs::write(&input_path, bytes).expect("write auto input");
    let process: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(&input_path)
        .arg("--out")
        .arg(output.path())
        .output()
        .expect("run disrobe auto");
    assert!(
        process.status.success(),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    drop(input);
    output
}

fn read_chain_json(output: &Path) -> serde_json::Value {
    let bytes: Vec<u8> =
        std::fs::read(output.join("chain.json")).expect("read disrobe auto chain.json");
    serde_json::from_slice(&bytes).expect("parse disrobe auto chain.json")
}

fn first_pass_node(rel: &str) -> serde_json::Value {
    let bytes: Vec<u8> = read_fixture(rel);
    let file_name: &str = rel.rsplit('/').next().expect("fixture file name");
    let output: disrobe_core::scratch::ScratchDir =
        run_auto_cli(&bytes, file_name, "windows-script");
    let chain: serde_json::Value = read_chain_json(output.path());
    chain["nodes"]
        .as_array()
        .expect("chain nodes")
        .iter()
        .find(|node: &&serde_json::Value| !node["pass"].is_null())
        .cloned()
        .unwrap_or_else(|| panic!("auto claimed nothing for {rel}: {chain}"))
}

#[test]
fn obfuscated_windows_scripts_reach_shell_deob_with_their_own_language() {
    let cases: [(&str, &str); 14] = [
        ("shell/powershell/chameleon/hello.ps1", "PowerShell"),
        ("shell/powershell/chameleon/rename_real.ps1", "PowerShell"),
        (
            "shell/powershell/invoke-obfuscation/ast/hello.ps1",
            "PowerShell",
        ),
        (
            "shell/powershell/invoke-obfuscation/compress/hello.ps1",
            "PowerShell",
        ),
        (
            "shell/powershell/invoke-obfuscation/compress/edge_cases.ps1",
            "PowerShell",
        ),
        (
            "shell/powershell/invoke-obfuscation/encoding/hello.ps1",
            "PowerShell",
        ),
        (
            "shell/powershell/invoke-obfuscation/string/hello.ps1",
            "PowerShell",
        ),
        (
            "shell/powershell/invoke-obfuscation/token/hello.ps1",
            "PowerShell",
        ),
        ("shell/powershell/invoke-stealth/hello.ps1", "PowerShell"),
        ("shell/powershell/psobf/hello.ps1", "PowerShell"),
        ("shell/batch/caret/hello.bat", "Batch"),
        ("shell/batch/seta/hello.bat", "Batch"),
        ("shell/batch/forsubstr/hello.bat", "Batch"),
        ("shell/vbs/chr_chain/hello.vbs", "VBA"),
    ];
    let mut failures: Vec<String> = Vec::new();
    for (rel, language) in cases {
        let node: serde_json::Value = first_pass_node(rel);
        let kind: &serde_json::Value = &node["output_kind"];
        if node["pass"] != "shell.deob"
            || node["verdict"] == "error"
            || kind["kind"] != "source"
            || kind["language"] != language
        {
            failures.push(format!(
                "{rel}: expected shell.deob {language} source, got pass {} verdict {} kind {kind} error {}",
                node["pass"], node["verdict"], node["error"]
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn plain_windows_scripts_keep_the_scriptlang_report() {
    let cases: [&str; 3] = [
        "shell/powershell/megafile/edge_cases.ps1",
        "shell/powershell/chameleon/rename_original.ps1",
        "shell/batch/baseline/hello.bat",
    ];
    let mut failures: Vec<String> = Vec::new();
    for rel in cases {
        let node: serde_json::Value = first_pass_node(rel);
        let kind: &serde_json::Value = &node["output_kind"];
        if node["pass"] != "scriptlang.classify"
            || node["verdict"] == "error"
            || kind["kind"] != "report"
            || kind["format_tag"] != "scriptlang-report"
        {
            failures.push(format!(
                "{rel}: expected the scriptlang.classify report for an unobfuscated script, got pass {} verdict {} kind {kind} error {}",
                node["pass"], node["verdict"], node["error"]
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
