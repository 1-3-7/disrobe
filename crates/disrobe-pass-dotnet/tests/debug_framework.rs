#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;
use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_DOTNET_DEBUG_HARNESS";

const OBFUSCATED_REL: &str =
    "../../corpus/dotnet/confuserex/gauntlet/GauntletSample.confuserex2.exe";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("fixture missing at {} ({}): {e}", rel, path.display())
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
        "this is the child half of the debug-framework contract tests, not a test to run on its \
         own. It is spawned with {HARNESS_ENV} set by unset_is_zero_overhead, \
         set_emits_decision_points, other_scope_does_not_enable_dotnet and \
         json_mode_is_one_object_per_line, all of which run unignored. Reaching this line without \
         the variable means the spawn stopped propagating it and the parents were grading a child \
         that did nothing"
    );
    let image: Vec<u8> = load(OBFUSCATED_REL);
    let summary: disrobe_pass_dotnet::pass::PassSummary =
        disrobe_pass_dotnet::pass::analyze(&image).expect("real confuserex2 sample analyzes");
    assert!(summary.primary_protector.is_some());
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
        !noise.contains("[debug:dotnet]"),
        "DISROBE_DEBUG unset must emit no dotnet debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("dotnet"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:dotnet] === dotnet.analyze ==="),
        "expected the analyze section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:dotnet] pe ="),
        "expected the pe structural decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:dotnet] runtime ="),
        "expected the runtime classification decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:dotnet] primary_protector ="),
        "expected the primary-protector decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:dotnet] protector-match ="),
        "expected per-protector classification + evidence, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:dotnet] cil-body ="),
        "expected the CIL method-body parse decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:dotnet] confuserex-constants ="),
        "expected the ConfuserEx2 constants-decryptor decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_dotnet() {
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:dotnet]"),
        "a sibling scope must not enable dotnet output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("dotnet"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"dotnet\""))
        .collect();
    assert!(
        events.len() >= 5,
        "expected several dotnet json events, got {}:\n{stderr}",
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
            Some("dotnet"),
            "every dotnet event carries scope=dotnet: {line}"
        );
    }
}
