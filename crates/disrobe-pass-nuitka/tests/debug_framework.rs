#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_NUITKA_DEBUG_HARNESS";
const SECRET_TOKEN: &str = "aB3dEf7hIj9kLm2nOp5qRs8t";

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
    let mut secret_image: Vec<u8> = b"KAX".to_vec();
    secret_image.extend_from_slice(SECRET_TOKEN.as_bytes());
    let _ = disrobe_pass_nuitka::extract_onefile(&secret_image, 0);

    let mut plain_image: Vec<u8> = b"KAX".to_vec();
    plain_image.extend_from_slice(b"plain text body, not token shaped, has spaces 1234");
    let _ = disrobe_pass_nuitka::extract_onefile(&plain_image, 0);
}

fn child_stderr(out: &Output) -> String {
    assert!(out.status.success(), "child failed: {out:?}");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn unset_is_zero_overhead() {
    let out: Output = run_harness(None, false);
    let stderr: String = child_stderr(&out);
    assert!(
        !stderr.contains("[debug:nuitka]"),
        "DISROBE_DEBUG unset must emit no nuitka debug output, got:\n{stderr}"
    );
}

#[test]
fn set_emits_decision_points_in_text_mode() {
    let out: Output = run_harness(Some("nuitka"), false);
    let stderr: String = child_stderr(&out);
    assert!(
        stderr.contains("[debug:nuitka] extract_onefile: offset=0 magic="),
        "expected the extract_onefile offset/magic line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:nuitka] extract_onefile: stream_len="),
        "expected the stream_len line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:nuitka]   hex "),
        "expected a plain hex dump for the non-secret-shaped body, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:nuitka]   asc "),
        "expected an ascii line alongside the plain hex dump, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_nuitka() {
    let out: Output = run_harness(Some("jvm,native"), false);
    let stderr: String = child_stderr(&out);
    assert!(
        !stderr.contains("[debug:nuitka]"),
        "a sibling scope must not enable nuitka output, got:\n{stderr}"
    );
}

#[test]
fn secret_shaped_hex_body_is_redacted_not_dumped() {
    let out: Output = run_harness(Some("nuitka"), false);
    let stderr: String = child_stderr(&out);
    assert!(
        !stderr.contains(SECRET_TOKEN),
        "the secret-shaped body must never appear verbatim, got:\n{stderr}"
    );
    assert!(
        stderr.contains("extract_onefile: stream head: <redacted,"),
        "expected a redacted marker for the secret-shaped stream head, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("nuitka"), true);
    let stderr: String = child_stderr(&out);
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"nuitka\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several nuitka json events, got {}:\n{stderr}",
        events.len()
    );
    let mut saw_hex_kind: bool = false;
    for line in &events {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid json line {line:?}: {e}"));
        assert!(
            value.is_object(),
            "each debug line must be a json object: {line}"
        );
        assert_eq!(
            value.get("scope").and_then(serde_json::Value::as_str),
            Some("nuitka"),
            "every nuitka event carries scope=nuitka: {line}"
        );
        if value.get("kind").and_then(serde_json::Value::as_str) == Some("hex") {
            saw_hex_kind = true;
            assert!(
                value.get("len").is_some() && value.get("shown").is_some(),
                "a hex event carries len and shown: {line}"
            );
            assert!(
                value
                    .get("hex")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|h: &str| !h.is_empty()),
                "a hex event carries packed hex: {line}"
            );
        }
    }
    assert!(
        saw_hex_kind,
        "expected at least one kind=hex event for the plain body, got:\n{stderr}"
    );
    assert!(
        !stderr.contains(SECRET_TOKEN),
        "the secret-shaped body must never appear verbatim in json mode either, got:\n{stderr}"
    );
}
