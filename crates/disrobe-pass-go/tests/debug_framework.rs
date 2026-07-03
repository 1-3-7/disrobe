#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_GO_DEBUG_HARNESS";
const FIXTURE_ABSENT_SENTINEL: &str = "GO_DEBUG_HARNESS_FIXTURE_ABSENT";

fn fixture_path() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("hello_normal.exe");
    p
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
    cmd.output().expect("spawn harness child")
}

fn harness_skipped(out: &Output) -> bool {
    String::from_utf8_lossy(&out.stdout).contains(FIXTURE_ABSENT_SENTINEL)
        || String::from_utf8_lossy(&out.stderr).contains(FIXTURE_ABSENT_SENTINEL)
}

#[test]
#[ignore = "spawned as a subprocess by the debug-framework contract tests"]
fn harness_entrypoint() {
    if std::env::var_os(HARNESS_ENV).is_none() {
        return;
    }
    let path: PathBuf = fixture_path();
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
        println!("{FIXTURE_ABSENT_SENTINEL} {}", path.display());
        return;
    };
    let analysis: disrobe_pass_go::GoAnalysis =
        disrobe_pass_go::analyze(&bytes).expect("hello_normal.exe analyzes");
    assert!(
        analysis.symbols.funcs.len() > 100,
        "the reference go binary must yield a real function table"
    );
}

#[test]
fn unset_is_zero_overhead() {
    let out: Output = run_harness(None, false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:go]"),
        "DISROBE_DEBUG unset must emit no go debug output, got:\n{stderr}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("go"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    if harness_skipped(&out) {
        eprintln!(
            "SKIPPED set_emits_decision_points: hello_normal.exe fixture absent; \
             regenerate via crates/disrobe-pass-go/tests/fixtures/regen.ps1"
        );
        return;
    }
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:go] === go.analyze ==="),
        "expected the analyze section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:go] image_kind ="),
        "expected the image-kind classification decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:go] pclntab_version ="),
        "expected the pclntab version decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:go] func_count ="),
        "expected the function-boundary count decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:go] moduledata_via ="),
        "expected the moduledata source decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:go] === go.garble ==="),
        "expected the garble analysis section, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:go] classify ="),
        "expected the garble classification decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:go] === go.dwarf ==="),
        "expected the dwarf recovery section, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_go() {
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:go]"),
        "a sibling scope must not enable go output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("go"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    if harness_skipped(&out) {
        eprintln!(
            "SKIPPED json_mode_is_one_object_per_line: hello_normal.exe fixture absent; \
             regenerate via crates/disrobe-pass-go/tests/fixtures/regen.ps1"
        );
        return;
    }
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"go\""))
        .collect();
    assert!(
        events.len() >= 8,
        "expected several go json events, got {}:\n{stderr}",
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
            Some("go"),
            "every go event carries scope=go: {line}"
        );
    }
}
