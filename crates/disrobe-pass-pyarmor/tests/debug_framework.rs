#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_pyarmor::{
    Detection, StaticUnpackConfig, detect_from_wrapper, unpack_static_with_config,
};

const HARNESS_ENV: &str = "DISROBE_PYARMOR_DEBUG_HARNESS";
const SKIP_MARKER: &str = "DEBUG-HARNESS-SKIP: corpus fixture absent";

fn corpus_wrapper() -> PathBuf {
    let here: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .expect("crates")
        .parent()
        .expect("repo root")
        .join("corpus")
        .join("python")
        .join("pyarmor")
        .join("v8")
        .join("basic")
        .join("chunk_00_try_except_basic_try_except_else")
        .join("chunk_00_try_except_basic_try_except_else.py")
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
    let wrapper: PathBuf = corpus_wrapper();
    let Ok(text): Result<String, _> = std::fs::read_to_string(&wrapper) else {
        eprintln!("{SKIP_MARKER}: {}", wrapper.display());
        return;
    };
    let (det, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&text).expect("real committed v8 wrapper detects");
    assert_eq!(&payload[..2], b"PY");
    let cfg: StaticUnpackConfig = StaticUnpackConfig::default();
    let output: disrobe_pass_pyarmor::StaticUnpackOutput =
        unpack_static_with_config(&payload, &cfg).expect("detect-only static unpack succeeds");
    assert_eq!(
        output.status,
        disrobe_pass_pyarmor::StaticDecryptStatus::DetectOnly
    );
    let _ = det;
}

fn skipped(stderr: &str) -> bool {
    stderr.contains(SKIP_MARKER)
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
        !noise.contains("[debug:pyarmor]"),
        "DISROBE_DEBUG unset must emit no pyarmor debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("pyarmor"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    if skipped(&stderr) {
        return;
    }
    assert!(
        stderr.contains("[debug:pyarmor] === pyarmor detect ==="),
        "expected the detect section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pyarmor] marker ="),
        "expected the marker decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pyarmor] layout ="),
        "expected the layout decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pyarmor] === pyarmor static-unpack ==="),
        "expected the static-unpack section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pyarmor] decrypt-route ="),
        "expected the per-version decrypt-route decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pyarmor] decrypt-status = DetectOnly"),
        "expected the DetectOnly status (no runtime supplied), got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pyarmor] serial-class ="),
        "expected the serial/license classification decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_pyarmor() {
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:pyarmor]"),
        "a sibling scope must not enable pyarmor output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("pyarmor"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    if skipped(&stderr) {
        return;
    }
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"pyarmor\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several pyarmor json events, got {}:\n{stderr}",
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
            Some("pyarmor"),
            "every pyarmor event carries scope=pyarmor: {line}"
        );
    }
}
