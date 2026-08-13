#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn cargo_bin() -> PathBuf {
    let exe_name: &str = if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    };
    let mut p: PathBuf = workspace_root();
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push(exe_name);
    p
}

fn bundle() -> PathBuf {
    let path: PathBuf = workspace_root()
        .join("corpus")
        .join("mobile")
        .join("hermes")
        .join("hello")
        .join("index.android.bundle");
    assert!(
        path.is_file(),
        "this case disassembles a committed hermes bundle, so its absence is a damaged checkout: {}",
        path.display()
    );
    path
}

fn run_disasm(args: &[&str]) -> Output {
    let bin: PathBuf = cargo_bin();
    let mut command: Command = Command::new(&bin);
    command.arg("hermes").arg("disasm").arg(bundle());
    for arg in args {
        command.arg(arg);
    }
    command
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", bin.display()))
}

#[test]
fn one_function_disassembles_to_the_instructions_it_actually_holds() {
    let output: Output = run_disasm(&["--function", "1"]);
    assert!(
        output.status.success(),
        "per-function disassembly must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    for expected in ["GetGlobalObject", "LoadConstString", "Call2", "Ret"] {
        assert!(
            text.contains(expected),
            "the committed bundle's second function performs {expected}, so the disassembly must \
             name it:\n{text}"
        );
    }
    assert!(
        text.contains("bytecode version: 96"),
        "the header version must be reported beside the instructions:\n{text}"
    );
}

#[test]
fn two_functions_of_one_bundle_disassemble_differently() {
    let first: Output = run_disasm(&["--function", "0"]);
    let second: Output = run_disasm(&["--function", "1"]);
    assert!(first.status.success() && second.status.success());
    let a: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&first.stdout);
    let b: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&second.stdout);
    assert_ne!(
        a, b,
        "two distinct functions produced identical disassembly, so the index is being ignored"
    );
}

#[test]
fn an_index_past_the_end_is_refused_with_the_size_it_checked_against() {
    let output: Output = run_disasm(&["--function", "99999"]);
    assert!(
        !output.status.success(),
        "an out-of-range function index must be refused, not reported as empty"
    );
    let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("DR-CLI-0465"),
        "the refusal must carry its typed error code, got {stderr}"
    );
    assert!(
        stderr.contains('2'),
        "the refusal must name how many functions the bundle declares, got {stderr}"
    );
}

#[test]
fn asking_for_no_function_keeps_the_whole_bundle_summary() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-hermes-disasm")
            .expect("create scratch directory");
    let out: PathBuf = scratch.path().join("summary.json");
    let output: Output = run_disasm(&["--out", out.to_str().expect("utf-8 scratch path")]);
    assert!(
        output.status.success(),
        "the whole-bundle path must keep working: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        out.is_file(),
        "the whole-bundle path must still write its summary document"
    );
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("functions:"),
        "the summary must still report its function count:\n{text}"
    );
}
