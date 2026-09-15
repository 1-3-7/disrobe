#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_as3::abc::{self, MethodInfo};
use disrobe_pass_as3::lifter::lift_body;
use disrobe_pass_as3::swf::{self, Swf};
use disrobe_pass_as3::{AbcFile, DoAbc};

const HARNESS_ENV: &str = "DISROBE_AS3_DEBUG_HARNESS";

fn abc_bearing_swf() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path: PathBuf = manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("flash")
        .join("avm2_disasm_oracle")
        .join("control_shapes.swf");
    assert!(
        path.is_file(),
        "the debug-framework contract runs against a tracked ABC-bearing SWF so it grades in \
         every checkout rather than only where the untracked corpus happens to exist, and {} \
         is missing, which means a damaged checkout rather than an absent corpus",
        path.display()
    );
    path
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
    let path: PathBuf = abc_bearing_swf();
    let bytes: Vec<u8> = std::fs::read(&path).expect("read the tracked swf");
    let parsed: Swf = swf::parse(&bytes).expect("parse the tracked swf");
    let blobs: Vec<DoAbc> = parsed.collect_do_abc();
    for blob in &blobs {
        let Ok(abc): Result<AbcFile, _> = abc::parse(&blob.abc_bytes) else {
            continue;
        };
        for body in &abc.method_bodies {
            let info: Option<&MethodInfo> = abc.methods.get(body.method as usize);
            let _ = lift_body(&abc, body, info);
        }
    }
}

fn harness_skipped(stderr: &str) -> bool {
    !stderr.contains("[debug:as3]") && !stderr.contains("\"scope\":\"as3\"")
}

#[test]
fn unset_is_zero_overhead() {
    let out: Output = run_harness(None, false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:as3]"),
        "DISROBE_DEBUG unset must emit no as3 debug output, got:\n{stderr}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("as3"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:as3] === swf.parse ==="),
        "expected the swf.parse section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:as3] compression ="),
        "expected the compression decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:as3] === abc.parse ==="),
        "expected the abc.parse section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:as3] cpool ="),
        "expected the constant-pool facts, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:as3] body_count ="),
        "expected the method-body count decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:as3] classify ="),
        "expected the lift_body classification decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_as3() {
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:as3]"),
        "a sibling scope must not enable as3 output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("as3"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !harness_skipped(&stderr),
        "json harness must produce as3 events, got:\n{stderr}"
    );
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"as3\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several as3 json events, got {}:\n{stderr}",
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
            Some("as3"),
            "every as3 event carries scope=as3: {line}"
        );
    }
}
