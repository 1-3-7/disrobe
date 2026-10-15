#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;

use common::{run_disrobe, temp_dir};
use sha2::{Digest, Sha256};

fn corpus(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/evm")
        .join(path)
}

fn corpus_arg(path: &str) -> String {
    corpus(path).to_str().expect("utf8 path").to_owned()
}

fn reference(build: &str) -> serde_json::Value {
    let text: String = std::fs::read_to_string(corpus(&format!("solc/{build}/reference.json")))
        .expect("solc reference for the build");
    serde_json::from_str(&text).expect("reference JSON")
}

fn reference_selectors(contract: &serde_json::Value) -> BTreeSet<String> {
    contract["methodIdentifiers"]
        .as_object()
        .expect("method identifiers")
        .values()
        .map(|id| format!("0x{}", id.as_str().expect("hex id")))
        .collect()
}

fn recovered_selectors(report: &serde_json::Value) -> BTreeSet<String> {
    report["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .map(|function| function["selector"].as_str().expect("selector").to_owned())
        .collect()
}

fn decode_hex(text: &str) -> Vec<u8> {
    let digits: &str = text.trim().trim_start_matches("0x");
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).expect("hex digit pair"))
        .collect()
}

#[test]
fn disrobe_evm_inspect_recovers_solc_selectors_from_creation_and_raw_runtime() {
    let erc20: serde_json::Value = reference("0.8.37-o1")["contracts"]["Erc20"].clone();
    let run: common::Run = run_disrobe(&[
        "--json",
        "evm",
        "inspect",
        &corpus_arg("solc/0.8.37-o1/Erc20.hex"),
    ]);
    assert_eq!(run.code, 0, "disrobe evm inspect failed: {}", run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).expect("JSON report");
    assert_eq!(report["layout"]["kind"], "creation");
    assert_eq!(report["metadata"]["compiler"]["version"], "0.8.37");
    assert_eq!(recovered_selectors(&report), reference_selectors(&erc20));
    let transfer = report["functions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|function| function["selector"] == "0xa9059cbb")
        .expect("transfer(address,uint256)");
    assert_eq!(transfer["mutability"], "nonpayable");
    assert_eq!(transfer["arguments"][0]["type"], "address");
    assert_eq!(transfer["arguments"][1]["type"], "uint256");

    let creation: Vec<u8> = decode_hex(
        &std::fs::read_to_string(corpus("solc/0.8.37-o1/Erc20.hex")).expect("creation hex"),
    );
    let offset: usize = report["layout"]["runtime_offset"].as_u64().unwrap() as usize;
    let len: usize = report["layout"]["runtime_bytes"].as_u64().unwrap() as usize;
    let runtime: &[u8] = &creation[offset..offset + len];
    let digest: String = Sha256::digest(runtime)
        .iter()
        .fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        });
    assert_eq!(
        digest,
        erc20["runtime"]["sha256"].as_str().unwrap(),
        "split runtime differs from solc's deployedBytecode"
    );
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("evm-cli");
    let raw: PathBuf = scratch.path().join("runtime.bin");
    std::fs::write(&raw, runtime).expect("write raw runtime");
    let raw_run: common::Run = run_disrobe(&[
        "--json",
        "evm",
        "inspect",
        "--encoding",
        "raw",
        raw.to_str().expect("utf8 path"),
    ]);
    assert_eq!(raw_run.code, 0, "{}", raw_run.stderr);
    let raw_report: serde_json::Value = serde_json::from_str(&raw_run.stdout).expect("JSON report");
    assert_eq!(raw_report["layout"]["kind"], "runtime");
    assert_eq!(
        recovered_selectors(&raw_report),
        reference_selectors(&erc20)
    );

    let text: common::Run =
        run_disrobe(&["evm", "inspect", &corpus_arg("solc/0.8.37-o1/Erc20.hex")]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    assert!(
        text.stdout.contains("transfer(address,uint256)"),
        "{}",
        text.stdout
    );
    assert!(text.stdout.contains("solc 0.8.37"), "{}", text.stdout);
}

#[test]
fn disrobe_evm_disasm_and_decompile_show_the_runtime() {
    let disasm: common::Run = run_disrobe(&[
        "evm",
        "disasm",
        "--blocks",
        &corpus_arg("solc/0.8.37-o0/Erc20.hex"),
    ]);
    assert_eq!(disasm.code, 0, "{}", disasm.stderr);
    assert!(
        disasm.stdout.contains("; constructor at input offset 0x0"),
        "{}",
        &disasm.stdout[..400.min(disasm.stdout.len())]
    );
    assert!(
        disasm.stdout.contains("; runtime at input offset"),
        "runtime section missing"
    );
    assert!(
        disasm.stdout.contains("PUSH4 0xa9059cbb"),
        "dispatcher PUSH4 missing"
    );
    assert!(
        disasm.stdout.contains("; metadata: solc 0.8.37"),
        "metadata line missing"
    );
    assert!(
        disasm.stdout.contains("; basic blocks"),
        "block listing missing"
    );

    let decompile: common::Run =
        run_disrobe(&["evm", "decompile", &corpus_arg("solc/0.8.37-o0/Erc20.hex")]);
    assert_eq!(decompile.code, 0, "{}", decompile.stderr);
    assert!(
        decompile
            .stdout
            .lines()
            .any(|line| line.contains("require(")
                && line.contains("\"Ownable: new owner is the zero address\"")),
        "{}",
        decompile.stdout
    );
    assert!(
        decompile.stdout.contains("emit Transfer("),
        "{}",
        decompile.stdout
    );
    assert!(
        decompile
            .stdout
            .contains("function transfer(address arg0, uint256 arg1) external {"),
        "{}",
        decompile.stdout
    );
}

#[test]
fn disrobe_evm_names_minimal_proxies_and_refuses_eof() {
    let clone: common::Run =
        run_disrobe(&["--json", "evm", "inspect", &corpus_arg("eip1167/clone.hex")]);
    assert_eq!(clone.code, 0, "{}", clone.stderr);
    let report: serde_json::Value = serde_json::from_str(&clone.stdout).expect("JSON report");
    assert_eq!(report["proxy"]["kind"], "eip1167");
    assert_eq!(
        report["proxy"]["implementation"],
        "0xbebebebebebebebebebebebebebebebebebebebe"
    );

    let push0: common::Run = run_disrobe(&[
        "--json",
        "evm",
        "inspect",
        &corpus_arg("eip1167/clone-push0.hex"),
    ]);
    assert_eq!(push0.code, 0, "{}", push0.stderr);
    let report: serde_json::Value = serde_json::from_str(&push0.stdout).expect("JSON report");
    assert_eq!(report["proxy"]["kind"], "eip7511");

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("evm-eof");
    let eof: PathBuf = scratch.path().join("container.hex");
    std::fs::write(&eof, "0xef000101000402000100030400000000800001600000")
        .expect("write EOF container");
    let refused: common::Run = run_disrobe(&["evm", "inspect", eof.to_str().expect("utf8 path")]);
    assert_ne!(
        refused.code, 0,
        "an EOF container was analysed: {}",
        refused.stdout
    );
    assert!(
        refused.stderr.contains("EOF container"),
        "{}",
        refused.stderr
    );
}
