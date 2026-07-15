#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_ruby::{RubyAnalysis, analyze_bytes};

const FIXTURE: &[u8] = include_bytes!("fixtures/precedence.yarvc");

fn recover(bytes: &[u8], name: &str) -> String {
    let analysis: RubyAnalysis = analyze_bytes(bytes, name).expect("analyze precedence fixture");
    analysis.yarv.expect("yarv analysis").decompiled.source
}

fn code_only(source: &str) -> String {
    source
        .lines()
        .take_while(|l: &&str| !l.starts_with("# string literals"))
        .collect::<Vec<&str>>()
        .join("\n")
}

#[test]
fn recovers_operand_grouping_that_survives_reassociation() {
    let src: String = recover(FIXTURE, "precedence.yarvc");
    let code: String = code_only(&src);
    for expected in [
        "20 - (8 - 3)",
        "64 / (8 / 2)",
        "100 % (7 % 4)",
        "(2 + 3) * 4",
        "(1 | 2) + 4",
        "1 - (2 - 3) - 4",
    ] {
        assert!(
            code.contains(expected),
            "the reconstructed source must keep `{expected}` grouped so it re-parses to the same tree; got:\n{code}"
        );
    }
    assert!(
        code.contains("100 - 20 - 5") && !code.contains("100 - (20 - 5)"),
        "a left-associative chain must not gain grouping that changes its value; got:\n{code}"
    );
    assert!(
        code.contains("8 - 2 * 3") && !code.contains("(2 * 3)"),
        "a tighter-binding right operand needs no grouping; got:\n{code}"
    );
}

fn ruby_available() -> bool {
    Command::new("ruby")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn eval_ruby(source: &str) -> Option<String> {
    let mut path: PathBuf = std::env::temp_dir();
    path.push("disrobe_yarv_precedence_recovered.rb");
    std::fs::write(&path, source).ok()?;
    let output = Command::new("ruby").arg(&path).output().ok()?;
    let _ = std::fs::remove_file(&path);
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n"))
}

#[test]
fn recovered_source_evaluates_to_the_intended_values() {
    if !ruby_available() {
        eprintln!("skip: ruby not on PATH; install ruby 3.4.x to run the recompile-and-eval check");
        return;
    }
    let src: String = recover(FIXTURE, "precedence.yarvc");
    let recovered: String = eval_ruby(&src).expect("recovered source must run under ruby");
    let intended: &str = "15\n16\n1\n20\n7\n-2\n75\n2\n";
    assert_eq!(
        recovered.trim_end(),
        intended.trim_end(),
        "evaluating the reconstructed source under the real interpreter must reproduce the \
         original program's output; a dropped or wrong grouping would diverge here"
    );
}
