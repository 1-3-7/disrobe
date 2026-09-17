#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
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

fn versioned_bundle(version: u32) -> PathBuf {
    let path: PathBuf = workspace_root()
        .join("corpus")
        .join("mobile")
        .join("hermes")
        .join("sample")
        .join(format!("sample.hbc.v{version}"));
    assert!(path.is_file(), "missing HBC {version} compiler fixture");
    path
}

fn run_disasm(input: &std::path::Path, args: &[&str]) -> Output {
    let bin: &str = env!("CARGO_BIN_EXE_disrobe");
    let mut command: Command = Command::new(bin);
    command.arg("hermes").arg("disasm").arg(input);
    for arg in args {
        command.arg(arg);
    }
    command
        .output()
        .unwrap_or_else(|error| panic!("run {bin}: {error}"))
}

fn instruction_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter_map(|line: &str| line.strip_prefix("  "))
        .filter(|line: &&str| line.starts_with("0x"))
        .collect()
}

#[test]
fn one_function_disassembles_to_the_instructions_it_actually_holds() {
    let output: Output = run_disasm(&bundle(), &["--function", "1"]);
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
    let input: PathBuf = bundle();
    let first: Output = run_disasm(&input, &["--function", "0"]);
    let second: Output = run_disasm(&input, &["--function", "1"]);
    assert!(first.status.success() && second.status.success());
    let first_text: String = String::from_utf8(first.stdout).expect("UTF-8 first output");
    let second_text: String = String::from_utf8(second.stdout).expect("UTF-8 second output");
    let first_instructions: Vec<&str> = instruction_lines(&first_text);
    let second_instructions: Vec<&str> = instruction_lines(&second_text);
    assert_ne!(
        first_instructions, second_instructions,
        "two distinct functions produced identical disassembly, so the index is being ignored"
    );
}

#[test]
fn an_exact_function_name_selects_the_same_body_as_its_index() {
    let input: PathBuf = versioned_bundle(84);
    let by_index: Output = run_disasm(&input, &["--function", "1"]);
    let by_name: Output = run_disasm(&input, &["--function", "add"]);
    assert!(by_index.status.success() && by_name.status.success());
    let indexed: String = String::from_utf8(by_index.stdout).expect("UTF-8 indexed output");
    let named: String = String::from_utf8(by_name.stdout).expect("UTF-8 named output");
    let indexed_instructions: Vec<&str> = instruction_lines(&indexed);
    let named_instructions: Vec<&str> = instruction_lines(&named);
    assert_eq!(named_instructions, indexed_instructions);
    for expected in ["LoadParam", "Add", "Ret"] {
        assert!(
            named_instructions
                .iter()
                .any(|instruction: &&str| instruction.contains(expected)),
            "named function omitted {expected}: {named_instructions:?}"
        );
    }
}

#[test]
fn a_negative_index_is_refused_as_an_index() {
    let output: Output = run_disasm(&bundle(), &["--function", "-1"]);
    assert!(!output.status.success());
    let stderr: String = String::from_utf8(output.stderr).expect("UTF-8 refusal");
    assert!(stderr.contains("DR-CLI-0875"), "{stderr}");
    assert!(stderr.contains("index -1 is negative"), "{stderr}");
}

#[test]
fn an_index_larger_than_the_host_range_is_not_misread_as_a_name() {
    let selector: &str = "999999999999999999999999999999999999999999999999999999999999999";
    let output: Output = run_disasm(&bundle(), &["--function", selector]);
    assert!(!output.status.success());
    let stderr: String = String::from_utf8(output.stderr).expect("UTF-8 refusal");
    assert!(stderr.contains("DR-CLI-0875"), "{stderr}");
    assert!(stderr.contains("supported index range"), "{stderr}");
    assert!(!stderr.contains("exact name"), "{stderr}");
}

#[test]
fn an_index_past_the_end_is_refused_with_the_size_it_checked_against() {
    let output: Output = run_disasm(&bundle(), &["--function", "99999"]);
    assert!(
        !output.status.success(),
        "an out-of-range function index must be refused, not reported as empty"
    );
    let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("DR-CLI-0875"),
        "the refusal must carry its typed error code, got {stderr}"
    );
    assert!(
        stderr.contains("declares 2 function(s)"),
        "the refusal must name how many functions the bundle declares, got {stderr}"
    );
}

#[test]
fn asking_for_no_function_keeps_the_whole_bundle_summary() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-hermes-disasm")
            .expect("create scratch directory");
    let out: PathBuf = scratch.path().join("summary.json");
    let output: Output = run_disasm(
        &bundle(),
        &["--out", out.to_str().expect("utf-8 scratch path")],
    );
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

#[test]
fn json_and_human_queries_carry_the_same_instructions() {
    let input: PathBuf = versioned_bundle(84);
    let human: Output = run_disasm(&input, &["--function", "1"]);
    let json: Output = run_disasm(&input, &["--function", "1", "--json"]);
    assert!(human.status.success() && json.status.success());
    let human_text: String = String::from_utf8(human.stdout).expect("UTF-8 human output");
    let human_instructions: Vec<&str> = human_text
        .lines()
        .filter_map(|line: &str| line.strip_prefix("  "))
        .filter(|line: &&str| line.starts_with("0x"))
        .collect();
    let document: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("JSON function disassembly");
    let json_instructions: Vec<&str> = document
        .get("instructions")
        .and_then(serde_json::Value::as_array)
        .expect("instruction array")
        .iter()
        .map(|value: &serde_json::Value| value.as_str().expect("instruction string"))
        .collect();
    assert_eq!(json_instructions, human_instructions);
    assert_eq!(
        document.get("bytecode_version"),
        Some(&serde_json::json!(84))
    );
    assert_eq!(document.get("function_index"), Some(&serde_json::json!(1)));
    assert_eq!(
        document.get("function_name"),
        Some(&serde_json::json!("add"))
    );
}

#[test]
fn every_graded_bytecode_version_uses_its_own_opcode_table() {
    for version in [76u32, 84, 96] {
        let input: PathBuf = versioned_bundle(version);
        let output: Output = run_disasm(&input, &["--function", "1"]);
        assert!(output.status.success(), "HBC {version} query failed");
        let text: String = String::from_utf8(output.stdout).expect("UTF-8 disassembly");
        assert!(text.contains(&format!("bytecode version: {version}")));
        for expected in ["LoadParam", "Add", "Ret"] {
            assert!(text.contains(expected), "HBC {version} omitted {expected}");
        }
    }
}

#[test]
fn a_version_without_an_opcode_table_is_refused_before_decode() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-hermes-unsupported-version")
            .expect("create scratch directory");
    let input: PathBuf = scratch.path().join("unsupported.hbc");
    let mut bytes: Vec<u8> = std::fs::read(versioned_bundle(76)).expect("read HBC 76 fixture");
    bytes[8..12].copy_from_slice(&75u32.to_le_bytes());
    std::fs::write(&input, bytes).expect("write unsupported-version fixture");
    let output: Output = run_disasm(&input, &["--function", "0"]);
    assert!(!output.status.success());
    let stderr: String = String::from_utf8(output.stderr).expect("UTF-8 refusal");
    assert!(stderr.contains("DR-CLI-0876"), "{stderr}");
    assert!(stderr.contains("version 75"), "{stderr}");
    assert!(
        stderr.contains("[62, 71, 74, 76, 83, 84, 89, 96]"),
        "{stderr}"
    );
}
