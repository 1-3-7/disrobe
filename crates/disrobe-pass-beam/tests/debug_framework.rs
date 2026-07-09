#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::Rung;
use disrobe_core::chain::Pass;
use disrobe_core::{Artifact, CoreError};
use disrobe_pass_beam::chain_detector::BEAM_PASS;

const HARNESS_ENV: &str = "DISROBE_BEAM_DEBUG_HARNESS";

fn fixture_bytes() -> Vec<u8> {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path: PathBuf = manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("beam")
        .join("elixir")
        .join("Elixir.Hello.beam");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn run_chain(body: &[u8]) -> String {
    let input: Artifact = Artifact::new(Rung::Raw, body.to_vec(), [7u8; 32]);
    let out: Artifact = BEAM_PASS
        .run(&input)
        .unwrap_or_else(|e: CoreError| panic!("run beam pass on real fixture: {e}"));
    String::from_utf8(out.envelope).expect("recovered source is utf8")
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
    let source: String = run_chain(&fixture_bytes());
    assert!(!source.is_empty());
}

fn child_stderr(out: &Output) -> String {
    assert!(out.status.success(), "child failed: {out:?}");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn unset_is_zero_overhead() {
    let out: Output = run_harness(None, false);
    let stderr: String = child_stderr(&out);
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
        !noise.contains("[debug:beam]"),
        "DISROBE_DEBUG unset must emit no beam debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("beam"), false);
    let stderr: String = child_stderr(&out);
    assert!(
        stderr.contains("[debug:beam] === beam analyze ==="),
        "expected the analyze section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:beam] classify = beam (FOR1/BEAM IFF container)"),
        "expected the classify decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:beam] === iff chunk parse ==="),
        "expected the iff chunk parse section, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:beam] === opcode stream ==="),
        "expected the opcode stream section, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:beam] === dbgi recovery ==="),
        "expected the dbgi recovery section, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:beam] dbgi_class = elixir quoted-AST"),
        "expected the elixir quoted-AST classification, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:beam] elixir_emit ="),
        "expected the elixir source-emit counts, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_beam() {
    let out: Output = run_harness(Some("jvm,native"), false);
    let stderr: String = child_stderr(&out);
    assert!(
        !stderr.contains("[debug:beam]"),
        "a sibling scope must not enable beam output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("beam"), true);
    let stderr: String = child_stderr(&out);
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"beam\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several beam json events, got {}:\n{stderr}",
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
            Some("beam"),
            "every beam event carries scope=beam: {line}"
        );
    }
}
