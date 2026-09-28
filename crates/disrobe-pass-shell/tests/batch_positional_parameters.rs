#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_shell::batch::engine::{BatchDeobReport, deobfuscate_batch};

const SELF_COPYING: &str =
    "@echo off\r\nif \"%1\"==\"\" (\r\n  echo usage\r\n) else (\r\n  copy \"%~f0\" \"%1\"\r\n)\r\n";

#[test]
fn an_unknown_positional_parameter_stays_symbolic_in_the_output() {
    let report: BatchDeobReport = deobfuscate_batch(SELF_COPYING, &[]);
    assert!(
        report.output.contains("%~f0"),
        "`%~f0` must stay symbolic when the script path is unknown, got:\n{}",
        report.output
    );
    assert!(
        !report.output.contains("copy \"\""),
        "an unknown parameter must not expand to an empty string, got:\n{}",
        report.output
    );
}

#[test]
fn a_branch_on_an_unknown_parameter_keeps_both_arms() {
    let report: BatchDeobReport = deobfuscate_batch(SELF_COPYING, &[]);
    assert!(
        report.output.contains("echo usage") && report.output.contains("copy"),
        "neither arm of a test on an unknown `%1` may be deleted, got:\n{}",
        report.output
    );
    assert_eq!(
        report.if_branches_folded, 0,
        "a comparison against an unknown parameter is not decidable"
    );
}

#[test]
fn a_known_parameter_still_folds() {
    let args: Vec<String> = vec!["C:\\s.bat".to_owned(), "target.bat".to_owned()];
    let report: BatchDeobReport = deobfuscate_batch(SELF_COPYING, &args);
    assert!(
        report.output.contains("copy \"C:\\s.bat\" \"target.bat\"")
            && !report.output.contains("usage"),
        "with the arguments known the branch folds to the copy, got:\n{}",
        report.output
    );
}
