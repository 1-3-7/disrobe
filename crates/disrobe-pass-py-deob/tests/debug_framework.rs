#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_PYDEOB_DEBUG_HARNESS";

fn corpus_fixture() -> Option<Vec<u8>> {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut root: PathBuf = PathBuf::from(manifest_dir);
    root.pop();
    root.pop();
    root.push("corpus");
    root.push("python");
    root.push("obfuscators");
    root.push("blankobf");
    for stem in ["real_edge_cases_3_8_r1", "real_edge_cases_3_8_r1_imports"] {
        let path: PathBuf = root.join(format!("{stem}.py"));
        if let Ok(bytes) = std::fs::read(&path) {
            return Some(bytes);
        }
    }
    None
}

fn obfuscated_input() -> Vec<u8> {
    if let Some(fixture) = corpus_fixture() {
        return fixture;
    }
    let original: &str = "def add(a, b):\n    return a + b\nprint(add(40, 2))\n";
    disrobe_pass_py_deob::obfuscators::blankobf::bake(original).into_bytes()
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
    let bytes: Vec<u8> = obfuscated_input();
    let outcome: disrobe_pass_py_deob::AutoDeobOutcome =
        disrobe_pass_py_deob::auto_deobfuscate(&bytes, None);
    assert_eq!(outcome.kind, disrobe_pass_py_deob::RouteKind::Deobfuscated);
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
        !noise.contains("[debug:py-deob]"),
        "DISROBE_DEBUG unset must emit no py-deob debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("py-deob"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:py-deob] === auto-route ==="),
        "expected the auto-route section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:py-deob] detect_family ="),
        "expected the family detection decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:py-deob] obfuscator-selected ="),
        "expected the obfuscator-selection decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:py-deob] obfuscator-quality ="),
        "expected the recovery-quality classification, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:py-deob] route = deobfuscated"),
        "expected the route classification, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_py_deob() {
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:py-deob]"),
        "a sibling scope must not enable py-deob output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("py-deob"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"py-deob\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several py-deob json events, got {}:\n{stderr}",
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
            Some("py-deob"),
            "every py-deob event carries scope=py-deob: {line}"
        );
    }
}

#[test]
fn deterministic_input_routes_to_deobfuscated() {
    let bytes: Vec<u8> = obfuscated_input();
    let outcome: disrobe_pass_py_deob::AutoDeobOutcome =
        disrobe_pass_py_deob::auto_deobfuscate(&bytes, None);
    assert_eq!(outcome.kind, disrobe_pass_py_deob::RouteKind::Deobfuscated);
}
