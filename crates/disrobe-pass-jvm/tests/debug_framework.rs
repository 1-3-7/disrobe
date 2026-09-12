#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_JVM_DEBUG_HARNESS";

fn minimal_classfile(major: u16) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&0xCAFE_BABE_u32.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&major.to_be_bytes());
    for _ in 0..8 {
        buf.extend_from_slice(&0u16.to_be_bytes());
    }
    buf
}

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
    let bytes: Vec<u8> = minimal_classfile(52);
    let summary: disrobe_pass_jvm::pass::JvmSummary =
        disrobe_pass_jvm::pass::analyze(&bytes).expect("minimal classfile analyzes");
    assert_eq!(summary.kind, "classfile");
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
        !noise.contains("[debug:jvm]"),
        "DISROBE_DEBUG unset must emit no jvm debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("jvm"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:jvm] === jvm analyze ==="),
        "expected the analyze section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:jvm] classify = classfile"),
        "expected the classify decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:jvm] classfile ="),
        "expected the classfile structural facts, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:jvm] protector-peel ="),
        "expected the protector-peel decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_jvm() {
    let out: Output = run_harness(Some("nuitka,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:jvm]"),
        "a sibling scope must not enable jvm output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("jvm"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"jvm\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several jvm json events, got {}:\n{stderr}",
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
            Some("jvm"),
            "every jvm event carries scope=jvm: {line}"
        );
    }
}
