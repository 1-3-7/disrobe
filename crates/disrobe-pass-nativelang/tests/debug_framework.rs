#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_NATIVELANG_DEBUG_HARNESS";

fn nim_fixture() -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push("nim");
    p.push("hello.nim.elf");
    std::fs::read(&p).unwrap_or_else(|e| {
        panic!(
            "missing committed fixture corpus/native/nim/hello.nim.elf (a tracked corpus file): {e}"
        )
    })
}

fn run_harness(debug: Option<&str>, json: bool) -> Output {
    let exe: PathBuf = std::env::current_exe().expect("test executable path");
    let mut cmd: Command = Command::new(exe);
    cmd.env(HARNESS_ENV, "1");
    cmd.env_remove("DISROBE_DEBUG");
    cmd.env_remove("DISROBE_DEBUG_FORMAT");
    cmd.env("NO_COLOR", "1");
    if let Some(spec) = debug {
        cmd.env("DISROBE_DEBUG", spec);
    }
    if json {
        cmd.env("DISROBE_DEBUG_FORMAT", "json");
    }
    cmd.arg("--ignored");
    cmd.arg("--exact");
    cmd.arg("--nocapture");
    cmd.arg("--test-threads=1");
    cmd.arg("harness_entrypoint");
    let out: Output = cmd.output().expect("spawn harness child");
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        stdout.contains("1 passed"),
        "the child has to report one test executed, otherwise the filter matched nothing and \
         every assertion below would be grading an empty run; child stdout was:\n{stdout}"
    );
    out
}

#[test]
#[ignore = "the subprocess body of the contract tests below, which spawn it on every run"]
fn harness_entrypoint() {
    assert!(
        std::env::var_os(HARNESS_ENV).is_some(),
        "this is the child half of the debug-framework contract tests in this file, not a test to \
         run on its own. They spawn it with {HARNESS_ENV} set. Reaching this line without the \
         variable means the spawn stopped propagating it and every parent was grading a child that \
         did nothing"
    );
    let bytes: Vec<u8> = nim_fixture();
    let analysis: disrobe_pass_nativelang::NativeLangAnalysis =
        disrobe_pass_nativelang::analyze(&bytes).expect("nim fixture analyzes");
    assert_eq!(
        analysis.fingerprint.lang,
        disrobe_pass_nativelang::NativeLang::Nim
    );
}

fn require_fixture() {
    let _present: Vec<u8> = nim_fixture();
}

#[test]
fn unset_is_zero_overhead() {
    require_fixture();
    let out: Output = run_harness(None, false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:nativelang]"),
        "DISROBE_DEBUG unset must emit no nativelang debug output, got:\n{stderr}"
    );
}

#[test]
fn set_emits_decision_points() {
    require_fixture();
    let out: Output = run_harness(Some("nativelang"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:nativelang] === nativelang analyze ==="),
        "expected the analyze section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:nativelang] === fingerprint ==="),
        "expected the fingerprint section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:nativelang] winner = nim"),
        "expected the language fingerprint winner, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:nativelang] recover-lang = nim"),
        "expected the recovery language decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:nativelang] nim-demangled ="),
        "expected the nim demangle count, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:nativelang] === recover-functions ==="),
        "expected the function-recovery section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:nativelang] source-grade ="),
        "expected the graded source decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:nativelang] source partial:")
            || stderr.contains("[debug:nativelang] source wall:"),
        "expected an honest graded source line (partial when DWARF carries types+lines, wall \
         otherwise), got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:nativelang] === dwarf-types ==="),
        "expected the dwarf-types section header, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_nativelang() {
    require_fixture();
    let out: Output = run_harness(Some("jvm,go"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:nativelang]"),
        "a sibling scope must not enable nativelang output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    require_fixture();
    let out: Output = run_harness(Some("nativelang"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"nativelang\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several nativelang json events, got {}:\n{stderr}",
        events.len()
    );
    for line in &events {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid json line {line:?}: {e}"));
        assert!(
            value.is_object(),
            "each debug line must be a json object: {line}"
        );
        assert_eq!(
            value.get("scope").and_then(serde_json::Value::as_str),
            Some("nativelang"),
            "every nativelang event carries scope=nativelang: {line}"
        );
    }
}
