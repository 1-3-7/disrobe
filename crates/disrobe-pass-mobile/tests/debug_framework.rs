#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::process::{Command, Output};

use disrobe_pass_mobile::{
    HermesModule, RecoveredRegExp, parse_hermes_module, recover_hermes_regexps,
};

const HARNESS_ENV: &str = "DISROBE_MOBILE_DEBUG_HARNESS";

const REGEX_HBC: &[u8] = include_bytes!("../../../corpus/mobile/hermes/regex/regexes.hbc.v96");

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
    let module: HermesModule = parse_hermes_module(REGEX_HBC).expect("parse regex bundle");
    assert_eq!(module.header.version, 96);
    let regexps: Vec<RecoveredRegExp> =
        recover_hermes_regexps(&module.reg_exp_table, &module.reg_exp_storage);
    assert!(!regexps.is_empty(), "fixture carries compiled regexps");
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
        !noise.contains("[debug:mobile]"),
        "DISROBE_DEBUG unset must emit no mobile debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("mobile"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:mobile] === hermes.parse ==="),
        "expected the hermes parse section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:mobile] hbc.version = 96"),
        "expected the hbc version decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:mobile] hbc.reg_exp_count ="),
        "expected the hbc regexp-count structural fact, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:mobile] === hermes.regex ==="),
        "expected the regex disassembly section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:mobile] re[0] /"),
        "expected a recovered regex decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_mobile() {
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:mobile]"),
        "a sibling scope must not enable mobile output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("mobile"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"mobile\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several mobile json events, got {}:\n{stderr}",
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
            Some("mobile"),
            "every mobile event carries scope=mobile: {line}"
        );
    }
}
