#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_WASM_DEOB_DEBUG_HARNESS";

const ARITH4: &[u8] = include_bytes!("fixtures/arith4.wasm");

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
    let analysis: disrobe_pass_wasm_deob::pass::WasmAnalysis =
        disrobe_pass_wasm_deob::pass::analyze(ARITH4).expect("arith4 wasm analyzes");
    assert!(
        analysis.summary.func_count > 0,
        "arith4 must lift defined functions"
    );
    assert!(
        analysis.recovered_bytes > 0,
        "recover_module must re-emit a module"
    );
    assert!(
        analysis.faithful_wat_lifted,
        "faithful lifter must render arith4"
    );
}

fn nonblank_noise(stderr: &str) -> String {
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
    let noise: String = nonblank_noise(&stderr);
    assert!(
        !noise.contains("[debug:wasm-deob]"),
        "DISROBE_DEBUG unset must emit no wasm-deob debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("wasm-deob"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:wasm-deob] === wasm-deob analyze ==="),
        "expected the analyze section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:wasm-deob] detect ="),
        "expected the obfuscator detect decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:wasm-deob] === module-parse ==="),
        "expected the module-parse section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:wasm-deob] module-shape ="),
        "expected the module-shape decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:wasm-deob] === recover ==="),
        "expected the recover section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:wasm-deob] unflatten ="),
        "expected the unflatten decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:wasm-deob] wasmixer-defrag ="),
        "expected the wasmixer defrag decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:wasm-deob] === faithful-lift ==="),
        "expected the faithful-lift section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:wasm-deob] bodies ="),
        "expected the faithful lifter bodies decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_wasm_deob() {
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:wasm-deob]"),
        "a sibling scope must not enable wasm-deob output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("wasm-deob"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"wasm-deob\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several wasm-deob json events, got {}:\n{stderr}",
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
            Some("wasm-deob"),
            "every wasm-deob event carries scope=wasm-deob: {line}"
        );
    }
}
