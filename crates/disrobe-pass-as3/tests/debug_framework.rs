#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_as3::abc::{self, MethodInfo};
use disrobe_pass_as3::lifter::lift_body;
use disrobe_pass_as3::swf::{self, Swf};
use disrobe_pass_as3::{AbcFile, DoAbc};

const HARNESS_ENV: &str = "DISROBE_AS3_DEBUG_HARNESS";

fn corpus_root() -> PathBuf {
    if let Ok(over) = std::env::var("DR_AS3_CORPUS") {
        return PathBuf::from(over);
    }
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("flash")
        .join("swf")
}

fn first_abc_bearing_swf() -> Option<PathBuf> {
    let dir: PathBuf = corpus_root();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .ok()?
        .filter_map(|e| e.ok().map(|d| d.path()))
        .filter(|p: &PathBuf| p.extension().and_then(|e| e.to_str()) == Some("swf"))
        .collect();
    paths.sort();
    for path in paths {
        let Ok(bytes): Result<Vec<u8>, _> = std::fs::read(&path) else {
            continue;
        };
        let Ok(parsed): Result<Swf, _> = swf::parse(&bytes) else {
            continue;
        };
        for blob in parsed.collect_do_abc() {
            if let Ok(parsed_abc) = abc::parse(&blob.abc_bytes)
                && !parsed_abc.method_bodies.is_empty()
            {
                return Some(path);
            }
        }
    }
    None
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
    let Some(path): Option<PathBuf> = first_abc_bearing_swf() else {
        return;
    };
    let bytes: Vec<u8> = std::fs::read(&path).expect("read corpus swf");
    let parsed: Swf = swf::parse(&bytes).expect("parse corpus swf");
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
    if first_abc_bearing_swf().is_none() {
        eprintln!("skip: as3 corpus absent");
        return;
    }
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
    if first_abc_bearing_swf().is_none() {
        eprintln!("skip: as3 corpus absent");
        return;
    }
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
    if first_abc_bearing_swf().is_none() {
        eprintln!("skip: as3 corpus absent");
        return;
    }
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
    if first_abc_bearing_swf().is_none() {
        eprintln!("skip: as3 corpus absent");
        return;
    }
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
