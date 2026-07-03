#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Output};

use disrobe_pass_sourcedefender::{LayeredRecovery, recover_layered};

const HARNESS_ENV: &str = "DISROBE_SOURCEDEFENDER_DEBUG_HARNESS";
const REAL_HELLO_PYE: &str = "../../corpus/python/sourcedefender/hello.pye";

fn fixture_present() -> bool {
    Path::new(REAL_HELLO_PYE).exists()
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
    let bytes: Vec<u8> = std::fs::read(REAL_HELLO_PYE).expect("read real hello.pye fixture");
    let recovery: LayeredRecovery =
        recover_layered(&bytes, "hello.pye").expect("recover real legacy .pye");
    assert_eq!(
        recovery.recovered_source.as_deref().map(str::trim_end),
        Some("print(\"Hello World!\")")
    );
}

#[test]
fn unset_is_zero_overhead() {
    if !fixture_present() {
        return;
    }
    let out: Output = run_harness(None, false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:sourcedefender]"),
        "DISROBE_DEBUG unset must emit no sourcedefender debug output, got:\n{stderr}"
    );
}

#[test]
fn set_emits_decision_points() {
    if !fixture_present() {
        return;
    }
    let out: Output = run_harness(Some("sourcedefender"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:sourcedefender] legacy-basename-password = hello"),
        "expected the basename-derived password decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:sourcedefender] legacy-key ="),
        "expected the aes key derivation decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:sourcedefender] zlib-inflate ="),
        "expected the zlib inflate decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:sourcedefender] source-recovered ="),
        "expected the source recovery decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_sourcedefender() {
    if !fixture_present() {
        return;
    }
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:sourcedefender]"),
        "a sibling scope must not enable sourcedefender output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    if !fixture_present() {
        return;
    }
    let out: Output = run_harness(Some("sourcedefender"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| {
            line.trim_start()
                .starts_with("{\"scope\":\"sourcedefender\"")
        })
        .collect();
    assert!(
        events.len() >= 4,
        "expected several sourcedefender json events, got {}:\n{stderr}",
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
            Some("sourcedefender"),
            "every sourcedefender event carries scope=sourcedefender: {line}"
        );
    }
}
