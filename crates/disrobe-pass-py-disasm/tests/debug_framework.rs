#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::process::{Command, Output};

use disrobe_core::{Artifact, Capability, LegacyPass, Rung};
use disrobe_ir::{Envelope, RawPayload, encode_raw};
use disrobe_pass_py_disasm::pass::{PASS_INPUT_PATH_CAP, PyDisasmPass, PyDisasmPassReport};

const HARNESS_ENV: &str = "DISROBE_PYDIS_DEBUG_HARNESS";

const CPYTHON_311_PYC: &[u8] =
    include_bytes!("../../../corpus/python/decompile/legacy/compiled/binary_ops.3.11.pyc");
const MPY_BYTECODE: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_bytecode.mpy");

fn synth_envelope(source_path: &str, body: &[u8]) -> Vec<u8> {
    let raw: RawPayload = RawPayload {
        source_path: source_path.to_owned(),
        source_bytes: body.to_vec(),
        source_hash: [0u8; 32],
        detected_format: None,
    };
    let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
    Envelope::new(Rung::Raw, hot, vec![])
        .encode()
        .expect("encode envelope")
}

fn run_pass(source_path: &str, body: &[u8]) -> PyDisasmPassReport {
    let bytes: Vec<u8> = synth_envelope(source_path, body);
    let input: Artifact = Artifact::with_capabilities(
        Rung::Raw,
        bytes,
        [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
        [7u8; 32],
    );
    let out: Artifact = PyDisasmPass.run(&input).expect("pass run");
    serde_json::from_slice(&out.envelope).expect("decode report")
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
    cmd.output().expect("spawn harness child")
}

#[test]
#[ignore = "spawned as a subprocess by the debug-framework contract tests"]
fn harness_entrypoint() {
    if std::env::var_os(HARNESS_ENV).is_none() {
        return;
    }
    let cpython: PyDisasmPassReport = run_pass("binary_ops.pyc", CPYTHON_311_PYC);
    assert_eq!(cpython.runtime, "cpython");
    assert!(cpython.instruction_count > 0);
    let mpy: PyDisasmPassReport = run_pass("hello.mpy", MPY_BYTECODE);
    assert_eq!(mpy.runtime, "micropython");
    assert!(mpy.instruction_count > 0);
}

fn harness_stderr(debug: Option<&str>, json: bool) -> String {
    let out: Output = run_harness(debug, json);
    assert!(out.status.success(), "child failed: {out:?}");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn unset_is_zero_overhead() {
    let stderr: String = harness_stderr(None, false);
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
        !noise.contains("[debug:py-disasm]"),
        "DISROBE_DEBUG unset must emit no py-disasm debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let stderr: String = harness_stderr(Some("py-disasm"), false);
    assert!(
        stderr.contains("[debug:py-disasm] === py.disasm ==="),
        "expected the analyze section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:py-disasm] classify = cpython pyc"),
        "expected the cpython classify decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:py-disasm] pyc-magic ="),
        "expected the magic-to-version decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:py-disasm] marshal-parse ="),
        "expected the marshal-parse decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:py-disasm] line-table ="),
        "expected the line-table decode decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:py-disasm] code-object ="),
        "expected the code-object walk decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:py-disasm] classify = alt-runtime micropython"),
        "expected the alt-runtime classify decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:py-disasm] mpy-bytecode ="),
        "expected the micropython bytecode decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:py-disasm] mpy-opcodes ="),
        "expected the micropython opcode-decode decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_py_disasm() {
    let stderr: String = harness_stderr(Some("jvm,native"), false);
    assert!(
        !stderr.contains("[debug:py-disasm]"),
        "a sibling scope must not enable py-disasm output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let stderr: String = harness_stderr(Some("py-disasm"), true);
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"py-disasm\""))
        .collect();
    assert!(
        events.len() >= 6,
        "expected several py-disasm json events, got {}:\n{stderr}",
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
            Some("py-disasm"),
            "every py-disasm event carries scope=py-disasm: {line}"
        );
    }
}
