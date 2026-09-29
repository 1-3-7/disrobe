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

#[cfg(windows)]
#[test]
fn known_parameters_fold_to_the_values_cmd_expands() {
    const ECHOING: &str = "@echo off\r\nif \"%1\"==\"\" (\r\n  echo usage\r\n) else (\r\n  echo copy \"%~f0\" \"%1\" %2\r\n)\r\n";
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_batch_positional_cmd")
            .expect("scratch directory");
    let script: std::path::PathBuf = scratch.path().join("positional.bat");
    std::fs::write(&script, ECHOING).expect("write the authored script");
    let script_path: String = script.to_string_lossy().into_owned();
    let output: std::process::Output = std::process::Command::new("cmd")
        .args(["/d", "/c", &script_path, "target.bat", "second"])
        .output()
        .expect("cmd runs the authored script");
    assert!(output.status.success(), "cmd failed: {output:?}");
    let expected: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert!(
        expected.starts_with("copy \"") && expected.ends_with("\"target.bat\" second"),
        "cmd must print the expanded copy line, got {expected:?}"
    );

    let args: Vec<String> = vec![script_path, "target.bat".to_owned(), "second".to_owned()];
    let report: BatchDeobReport = deobfuscate_batch(ECHOING, &args);
    let normalized: Vec<String> = report
        .output
        .lines()
        .map(|line: &str| line.split_whitespace().collect::<Vec<&str>>().join(" "))
        .collect();
    assert!(
        normalized
            .iter()
            .any(|line: &String| line == &format!("echo {expected}")),
        "the folded branch must print what cmd printed ({expected:?}), got:\n{}",
        report.output
    );
    assert!(
        !report.output.contains("usage"),
        "the empty-argument arm is dead once %1 is known, got:\n{}",
        report.output
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
