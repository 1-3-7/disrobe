#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_SCRIPTLANG_DEBUG_HARNESS";
const HELLO_CONCISE: &[u8] = include_bytes!("fixtures/hello.concise.txt");

fn run_harness(debug: Option<&str>, json: bool) -> Output {
    let exe: std::path::PathBuf = std::env::current_exe().expect("test executable path");
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

#[test]
#[ignore = "spawned as a subprocess by the debug-framework contract tests"]
fn harness_entrypoint() {
    if std::env::var_os(HARNESS_ENV).is_none() {
        return;
    }
    let artifact: disrobe_pass_scriptlang::lang::ScriptArtifact =
        disrobe_pass_scriptlang::lang::analyze(HELLO_CONCISE).expect("real perl concise analyzes");
    assert_eq!(
        artifact.lang(),
        disrobe_pass_scriptlang::lang::ScriptLang::Perl
    );
}

#[test]
fn unset_is_zero_overhead() {
    let out: Output = run_harness(None, false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let noise: String = stderr
        .lines()
        .filter(|line: &&str| !line.trim_start().starts_with("Compiling"))
        .filter(|line: &&str| !line.trim_start().starts_with("Finished"))
        .filter(|line: &&str| !line.trim_start().starts_with("Running"))
        .filter(|line: &&str| !line.trim().is_empty())
        .filter(|line: &&str| !line.contains("test result"))
        .filter(|line: &&str| !line.contains("running 1 test"))
        .filter(|line: &&str| !line.contains("harness_entrypoint"))
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        !noise.contains("[debug:scriptlang]"),
        "DISROBE_DEBUG unset must emit no scriptlang debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("scriptlang"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:scriptlang] === scriptlang analyze ==="),
        "expected the analyze section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:scriptlang] classify = perl-concise"),
        "expected the perl-concise classify decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:scriptlang] perl.optree ="),
        "expected the perl op-tree structural facts, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:scriptlang] perl.recovery ="),
        "expected the perl source-recovery decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:scriptlang] perl.lexical_pads ="),
        "expected the lexical-pad recovery decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_scriptlang() {
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:scriptlang]"),
        "a sibling scope must not enable scriptlang output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("scriptlang"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"scriptlang\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several scriptlang json events, got {}:\n{stderr}",
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
            Some("scriptlang"),
            "every scriptlang event carries scope=scriptlang: {line}"
        );
    }
}
