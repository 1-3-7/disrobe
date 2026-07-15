#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_ruby::{RubyAnalysis, analyze_bytes};

fn ruby_available() -> bool {
    Command::new("ruby")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn compile_regexp(literal: &str) -> Option<(Vec<u8>, String)> {
    let mut bin_path: PathBuf = std::env::temp_dir();
    bin_path.push(format!(
        "disrobe_regexp_{}.yarvc",
        literal.replace(['/', '\\', '?', '*', '.', ' '], "_")
    ));
    let script: String = format!(
        "File.binwrite({path:?}, RubyVM::InstructionSequence.compile({literal:?}).to_binary); print(({literal}).inspect)",
        path = bin_path.to_string_lossy(),
        literal = literal,
    );
    let output = Command::new("ruby").arg("-e").arg(&script).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let expected: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let bytes: Vec<u8> = std::fs::read(&bin_path).ok()?;
    let _ = std::fs::remove_file(&bin_path);
    Some((bytes, expected))
}

fn recovered_regexp(literal: &str) -> Option<(String, String)> {
    let (bytes, expected): (Vec<u8>, String) = compile_regexp(literal)?;
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "regexp.yarvc").ok()?;
    let yarv = analysis.yarv?;
    let recovered: String = yarv
        .decompiled
        .recovered_strings
        .into_iter()
        .find(|s| s.starts_with('/'))?;
    Some((recovered, expected))
}

#[test]
fn regexp_literals_preserve_flags_against_real_ruby() {
    if !ruby_available() {
        eprintln!("skip: ruby not on PATH; install ruby 3.4.x to grade regexp flag recovery");
        return;
    }
    for literal in ["/abc/", "/abc/i", "/abc/m", "/abc/x", "/abc/imx", "/abc/n"] {
        let (recovered, expected): (String, String) = recovered_regexp(literal)
            .unwrap_or_else(|| panic!("failed to recover regexp for {literal}"));
        assert_eq!(
            recovered, expected,
            "recovered regexp for source {literal} must equal Ruby's own inspect form"
        );
    }
}
