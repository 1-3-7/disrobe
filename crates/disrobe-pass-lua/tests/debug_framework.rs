#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_LUA_DEBUG_HARNESS";

fn fixture_path() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("lua");
    p.push("luac");
    p.push("hello.5_3.luac");
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
    let bytes: Vec<u8> = std::fs::read(fixture_path())
        .unwrap_or_else(|e| panic!("fixture must be tracked: corpus/lua/luac/hello.5_3.luac: {e}"));
    let chunk: disrobe_pass_lua::DecompiledChunk =
        disrobe_pass_lua::decompile_auto(&bytes).expect("real 5.3 luac decompiles");
    assert!(!chunk.source.is_empty());
}

fn meaningful_stderr(out: &Output) -> String {
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    stderr
        .lines()
        .filter(|line: &&str| !line.trim_start().starts_with("Compiling"))
        .filter(|line: &&str| !line.trim_start().starts_with("Finished"))
        .filter(|line: &&str| !line.trim_start().starts_with("Running"))
        .filter(|line: &&str| !line.trim().is_empty())
        .filter(|line: &&str| !line.contains("test result"))
        .filter(|line: &&str| !line.contains("running 1 test"))
        .filter(|line: &&str| !line.contains("harness_entrypoint"))
        .collect::<Vec<&str>>()
        .join("\n")
}

#[test]
fn unset_is_zero_overhead() {
    let out: Output = run_harness(None, false);
    assert!(out.status.success(), "child failed: {out:?}");
    let noise: String = meaningful_stderr(&out);
    assert!(
        !noise.contains("[debug:lua]"),
        "DISROBE_DEBUG unset must emit no lua debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("lua"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:lua] === lua.detect ==="),
        "expected the detect section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:lua] classify = Lua53"),
        "expected the format classify decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:lua] standard_version_byte = 0x53"),
        "expected the standard version-byte decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:lua] === lua.decompile_chunk ==="),
        "expected the decompile section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:lua] lifter = register"),
        "expected the lifter decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:lua] fidelity ="),
        "expected the fidelity classification, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_lua() {
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:lua]"),
        "a sibling scope must not enable lua output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("lua"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"lua\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several lua json events, got {}:\n{stderr}",
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
            Some("lua"),
            "every lua event carries scope=lua: {line}"
        );
    }
}
