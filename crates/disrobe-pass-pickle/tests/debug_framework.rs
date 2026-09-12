#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_PICKLE_DEBUG_HARNESS";

fn fixture() -> Vec<u8> {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("pickle")
        .join("malicious")
        .join("p2")
        .join("reduce_os_system.pkl");
    std::fs::read(&path).expect("malicious reduce_os_system fixture must be committed")
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
    let bytes: Vec<u8> = fixture();
    let dis: disrobe_pass_pickle::Disassembly =
        disrobe_pass_pickle::disassemble(&bytes).expect("disasm fixture");
    let trace: disrobe_pass_pickle::VmTrace =
        disrobe_pass_pickle::execute(&dis).expect("vm fixture");
    let report: disrobe_pass_pickle::SafetyReport = disrobe_pass_pickle::analyze_deep(&trace);
    assert_eq!(
        report.severity,
        disrobe_pass_pickle::Severity::OvertlyMalicious
    );
    let poly: disrobe_pass_pickle::PolyglotReport = disrobe_pass_pickle::analyze_polyglot(&bytes);
    assert!(poly.is_pickle);
    #[cfg(feature = "ml")]
    {
        let format: disrobe_pass_pickle::ModelFormat = disrobe_pass_pickle::detect_model(&bytes);
        assert_eq!(format, disrobe_pass_pickle::ModelFormat::BarePickle);
    }
}

fn filtered_noise(stderr: &str) -> String {
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
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let noise: String = filtered_noise(&stderr);
    assert!(
        !noise.contains("[debug:pickle]"),
        "DISROBE_DEBUG unset must emit no pickle debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("pickle"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:pickle] === pickle disassemble ==="),
        "expected the disassemble section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pickle] protocol-header ="),
        "expected the protocol-detection decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pickle] disassembled ="),
        "expected the opcode-stream summary, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pickle] reduce ="),
        "expected the REDUCE trace decision, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pickle] global-import ="),
        "expected the global-import resolution, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pickle] gadget-chain ="),
        "expected the gadget-chain classification, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pickle] verdict ="),
        "expected the severity verdict, got:\n{stderr}"
    );
    #[cfg(feature = "ml")]
    assert!(
        stderr.contains("[debug:pickle] model-format ="),
        "expected the model-file detection, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_pickle() {
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:pickle]"),
        "a sibling scope must not enable pickle output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("pickle"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"pickle\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several pickle json events, got {}:\n{stderr}",
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
            Some("pickle"),
            "every pickle event carries scope=pickle: {line}"
        );
    }
}
