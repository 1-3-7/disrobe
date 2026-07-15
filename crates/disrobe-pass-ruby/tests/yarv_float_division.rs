#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_ruby::{RubyAnalysis, YarvAnalysis, analyze_bytes};

fn fixture_path(rel: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(rel);
    p
}

fn recovered_source(rel: &str) -> String {
    let bytes: Vec<u8> = std::fs::read(fixture_path(rel))
        .unwrap_or_else(|e: std::io::Error| panic!("read {rel}: {e}"));
    let analysis: RubyAnalysis =
        analyze_bytes(&bytes, rel).unwrap_or_else(|e| panic!("analyze {rel}: {e}"));
    let yarv: YarvAnalysis = analysis
        .yarv
        .unwrap_or_else(|| panic!("{rel} produced no YARV analysis"));
    yarv.decompiled.source
}

#[test]
fn float_division_operands_recover_their_real_values() {
    let recovered: String = recovered_source("float_division.rb.yarvc");
    for literal in ["7.0 / 2", "-7.0 / 2", "10.0 / 4", "1.5 + 2.5", "100.25 % 7"] {
        assert!(
            recovered.contains(literal),
            "recovered float source must carry `{literal}`, not a zeroed operand; got:\n{recovered}"
        );
    }
    assert!(
        !recovered.contains("0.0 / 2"),
        "float operand must not collapse to 0.0; got:\n{recovered}"
    );
}

fn ruby_available() -> bool {
    Command::new("ruby")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn ruby_eval_stdout(source: &str) -> String {
    let mut path: PathBuf = std::env::temp_dir();
    path.push("disrobe_ruby_float_division_eval.rb");
    std::fs::write(&path, source).expect("write temp ruby source");
    let output = Command::new("ruby")
        .arg(&path)
        .output()
        .expect("run ruby on the source");
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "ruby failed to evaluate the source:\n{source}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
}

#[test]
fn recovered_float_division_evaluates_to_the_same_values() {
    if !ruby_available() {
        eprintln!(
            "skip: ruby not on PATH; install ruby 3.4.x to run the float-division value oracle"
        );
        return;
    }
    let original: String = std::fs::read_to_string(fixture_path("float_division.rb"))
        .expect("read original float_division.rb");
    let recovered: String = recovered_source("float_division.rb.yarvc");

    let want: String = ruby_eval_stdout(&original);
    let got: String = ruby_eval_stdout(&recovered);
    assert_eq!(
        got, want,
        "recompiling the recovered source must reproduce the original float-division values"
    );
    assert_eq!(
        want.lines().next(),
        Some("3.5"),
        "7.0 / 2 must evaluate to 3.5 under real ruby, guarding the true-division value"
    );
}
