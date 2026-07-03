#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_PHP_DEBUG_HARNESS";
const FUNCS_DZOA: &[u8] = include_bytes!("fixtures/protector_oparray/funcs.dzoa");

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
    let report: disrobe_pass_php::RecoveryReport =
        disrobe_pass_php::recover_php(FUNCS_DZOA, None).expect("recover funcs.dzoa op_array");
    assert_eq!(report.php_kind, "OpArray");
    assert!(report.output.contains("function greet"), "{report:?}");
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
        !noise.contains("[debug:php]"),
        "DISROBE_DEBUG unset must emit no php debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("php"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:php] === php recover ==="),
        "expected the recover section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:php] classify ="),
        "expected the classify decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:php] oparray-root-kind = Main"),
        "expected the oparray root-kind decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:php] === php oparray ==="),
        "expected the oparray section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:php] route = oparray-container"),
        "expected the route decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:php] skeleton-functions ="),
        "expected the skeleton-functions decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:php] skeleton-named-params ="),
        "expected the skeleton-named-params decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_php() {
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:php]"),
        "a sibling scope must not enable php output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("php"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"php\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several php json events, got {}:\n{stderr}",
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
            Some("php"),
            "every php event carries scope=php: {line}"
        );
    }
}
