#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

const CLEAN: &str = "corpus/native/obfuscators/guardian-rs/sample.clean.exe";
const VARIANT: &str = "corpus/native/obfuscators/guardian-rs/sample.virtualized.exe";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn fixture(relative: &str) -> PathBuf {
    let path: PathBuf = workspace_root().join(relative);
    assert!(
        path.is_file(),
        "committed fixture is missing: {}",
        path.display()
    );
    path
}

fn run_diff(args: &[&str]) -> Run {
    let output: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("native")
        .arg("diff")
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe native diff");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn rows(report: &Value) -> usize {
    ["added", "removed", "changed"]
        .into_iter()
        .map(|name: &str| report[name].as_array().expect("listing is an array").len())
        .sum()
}

#[test]
fn limit_bounds_native_diff_text_and_reports_exact_withheld_count() {
    let clean: PathBuf = fixture(CLEAN);
    let variant: PathBuf = fixture(VARIANT);
    let run: Run = run_diff(&[
        clean.to_str().expect("utf-8 fixture path"),
        variant.to_str().expect("utf-8 fixture path"),
        "--limit",
        "1",
    ]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let printed: usize = run
        .stdout
        .lines()
        .filter(|line: &&str| {
            line.starts_with("    + ") || line.starts_with("    - ") || line.starts_with("    ~ ")
        })
        .count();
    assert_eq!(printed, 1, "{}", run.stdout);
    assert!(
        run.stdout.contains("withheld listing rows: 1"),
        "{}",
        run.stdout
    );
}

#[test]
fn limit_bounds_native_diff_json_without_changing_totals_or_schema() {
    let clean: PathBuf = fixture(CLEAN);
    let variant: PathBuf = fixture(VARIANT);
    let clean_text: &str = clean.to_str().expect("utf-8 fixture path");
    let variant_text: &str = variant.to_str().expect("utf-8 fixture path");
    let full_run: Run = run_diff(&["--json", clean_text, variant_text]);
    assert_eq!(full_run.code, 0, "stderr: {}", full_run.stderr);
    let full: Value = serde_json::from_str(&full_run.stdout).expect("full JSON report");
    let total_rows: usize = rows(&full);
    assert_eq!(total_rows, 2, "fixture drifted: {full}");
    assert!(full["listing"]["limit"].is_null(), "{full}");
    assert_eq!(full["listing"]["shown"], total_rows, "{full}");
    assert_eq!(full["listing"]["withheld"], 0, "{full}");

    for (limit, shown) in [("0", 0_usize), ("1", 1_usize), ("100", total_rows)] {
        let first: Run = run_diff(&["--json", "--limit", limit, clean_text, variant_text]);
        let second: Run = run_diff(&["--json", "--limit", limit, clean_text, variant_text]);
        assert_eq!(first.code, 0, "stderr: {}", first.stderr);
        assert_eq!(second.code, 0, "stderr: {}", second.stderr);
        assert_eq!(
            first.stdout, second.stdout,
            "JSON bytes changed for --limit {limit}"
        );
        let report: Value = serde_json::from_str(&first.stdout).expect("bounded JSON report");
        assert_eq!(report["schema"], full["schema"]);
        assert_eq!(report["total_a"], full["total_a"]);
        assert_eq!(report["total_b"], full["total_b"]);
        assert_eq!(report["identical"], full["identical"]);
        assert_eq!(report["similarity"], full["similarity"]);
        assert_eq!(rows(&report), shown, "{report}");
        assert_eq!(
            report["listing"]["limit"],
            limit.parse::<usize>().expect("limit")
        );
        assert_eq!(report["listing"]["shown"], shown);
        assert_eq!(report["listing"]["withheld"], total_rows - shown);
    }
}
