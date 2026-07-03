#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_PYFREEZE_DEBUG_HARNESS";

fn fixture_binary() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("python");
    p.push("freezers");
    p.push("cxfreeze");
    p.push("extracted");
    p.push("hello.exe");
    p
}

fn out_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0x51ED_2A7C);
    let nonce: u64 = N.fetch_add(0x9E37_79B9, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "disrobe-pyfreeze-debug-{}-{nonce}",
        std::process::id()
    ))
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
    cmd.output().expect("spawn harness child")
}

#[test]
#[ignore = "spawned as a subprocess by the debug-framework contract tests"]
fn harness_entrypoint() {
    if std::env::var_os(HARNESS_ENV).is_none() {
        return;
    }
    let binary: PathBuf = fixture_binary();
    let dest: PathBuf = out_dir();
    let out: disrobe_pass_pyfreeze::PyfreezeOutput =
        disrobe_pass_pyfreeze::extract(&binary, &dest).expect("cxfreeze fixture extracts");
    assert_eq!(
        out.detection.kind,
        disrobe_pass_pyfreeze::FreezerKind::CxFreeze
    );
    let _ = std::fs::remove_dir_all(&dest);
}

fn fixture_present() -> bool {
    let present: bool = fixture_binary().is_file();
    if !present {
        eprintln!(
            "[debug_framework] skipped: cxfreeze fixture missing at {}",
            fixture_binary().display()
        );
    }
    present
}

#[test]
fn unset_is_zero_overhead() {
    if !fixture_present() {
        return;
    }
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
        !noise.contains("[debug:pyfreeze]"),
        "DISROBE_DEBUG unset must emit no pyfreeze debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    if !fixture_present() {
        return;
    }
    let out: Output = run_harness(Some("pyfreeze"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:pyfreeze] === pyfreeze extract ==="),
        "expected the extract section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pyfreeze] === pyfreeze detect ==="),
        "expected the detect section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pyfreeze] classify = CxFreeze"),
        "expected the freezer classification decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pyfreeze] dispatch = CxFreeze"),
        "expected the per-family dispatch decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pyfreeze] decompile = "),
        "expected the bytecode-to-source handoff decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pyfreeze] roundtrip = "),
        "expected the roundtrip grade decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:pyfreeze] recovered-modules = "),
        "expected the recovered-modules summary decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_pyfreeze() {
    if !fixture_present() {
        return;
    }
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:pyfreeze]"),
        "a sibling scope must not enable pyfreeze output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    if !fixture_present() {
        return;
    }
    let out: Output = run_harness(Some("pyfreeze"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"pyfreeze\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several pyfreeze json events, got {}:\n{stderr}",
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
            Some("pyfreeze"),
            "every pyfreeze event carries scope=pyfreeze: {line}"
        );
    }
}
