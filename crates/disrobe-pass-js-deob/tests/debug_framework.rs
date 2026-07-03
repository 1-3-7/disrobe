#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_js_deob::{
    DeobOptions, DeobOutput, Detection, JsObfuscator, deobfuscate_all, detect,
};

const HARNESS_ENV: &str = "DISROBE_JS_DEOB_DEBUG_HARNESS";

fn corpus_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join("jsconfuser")
        .join("obfuscated.megafile.high.js")
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
    let fixture: PathBuf = corpus_fixture();
    let source: String = std::fs::read_to_string(&fixture)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", fixture.display()));
    let detection: Detection = detect(source.as_bytes());
    assert_eq!(detection.family, JsObfuscator::JsConfuser);
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(&source, &opts);
    assert!(!out.source.is_empty());
}

fn run_ok(debug: Option<&str>, json: bool) -> String {
    let out: Output = run_harness(debug, json);
    assert!(out.status.success(), "child failed: {out:?}");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn unset_is_zero_overhead() {
    let stderr: String = run_ok(None, false);
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
        !noise.contains("[debug:js-deob]"),
        "DISROBE_DEBUG unset must emit no js-deob debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let stderr: String = run_ok(Some("js-deob"), false);
    assert!(
        stderr.contains("[debug:js-deob] === js-deob detect ==="),
        "expected the detect section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:js-deob] family = JsConfuser"),
        "expected the family classification decision, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:js-deob] === jsconfuser deobfuscate_all ==="),
        "expected the deobfuscate_all section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:js-deob] string-compression-blocks-reversed ="),
        "expected the lzstring string-compression recovery decision, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:js-deob] output-bytes ="),
        "expected the deobfuscate_all output summary, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_js_deob() {
    let stderr: String = run_ok(Some("jvm,native"), false);
    assert!(
        !stderr.contains("[debug:js-deob]"),
        "a sibling scope must not enable js-deob output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let stderr: String = run_ok(Some("js-deob"), true);
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"js-deob\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several js-deob json events, got {}:\n{stderr}",
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
            Some("js-deob"),
            "every js-deob event carries scope=js-deob: {line}"
        );
    }
}
