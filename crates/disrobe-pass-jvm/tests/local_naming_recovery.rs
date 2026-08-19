#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};
use sha2::{Digest, Sha256};

pub mod common;

const DEX: &[u8] = include_bytes!("fixtures/locals/ParamProbe-min21.dex");
const AUTHORED: &str = include_str!("fixtures/locals/ParamProbe.java");
const HARNESS: &str = include_str!("fixtures/locals/Harness.java");
const PROVENANCE: &str = include_str!("fixtures/locals/provenance.toml");
const DEX_SHA256: &str = "0a45fc31fde46ed6b96239d9ecb3a8242ff26834196cbc70b85af3f61e971e0d";
const SOURCE_SHA256: &str = "5100be58a89ae9a829c46ccde4e2e87762cb7e26fc839a3a0d29347b738886d5";
const EXPECTED_STDOUT: &str = "8\n6\n26\n31\n5\n6\n";
const BEHAVIOURAL_UNIT: &str = "ParamProbe.java";
const STRUCTURAL_UNIT: &str = "LocalProbe.java";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn recovered() -> DecompiledDex {
    let dex: DexFile = parse_dex(DEX).expect("parse the real D8 artifact");
    decompile_dex(&dex, DEX)
}

fn recovered_unit(sources: &DecompiledDex, name: &str) -> String {
    sources
        .sources
        .get(name)
        .unwrap_or_else(|| panic!("recover {name}, saw {:?}", sources.sources.keys()))
        .clone()
}

fn assigned_names(source: &str) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for line in source.lines() {
        let trimmed: &str = line.trim();
        let Some((target, _)) = trimmed
            .strip_suffix(';')
            .and_then(|statement: &str| statement.split_once(" = "))
        else {
            continue;
        };
        if !target.contains('.') {
            names.insert(target.to_owned());
        }
    }
    names
}

fn authored_param_probe() -> String {
    AUTHORED
        .split("\nfinal class LocalProbe {")
        .next()
        .expect("the authored file splits at the second class")
        .to_owned()
}

fn compile_and_run(label: &str, probe: &str) -> Vec<u8> {
    let javac: PathBuf =
        common::find_on_path("javac").expect("the local-naming gate requires javac on PATH");
    let java: PathBuf =
        common::find_on_path("java").expect("the local-naming gate requires java on PATH");
    let scratch: ScratchDir = ScratchDir::create(label).expect("create Java scratch directory");
    let probe_path: PathBuf = scratch.path().join("ParamProbe.java");
    let harness_path: PathBuf = scratch.path().join("Harness.java");
    std::fs::write(&probe_path, probe).expect("write the probe");
    std::fs::write(&harness_path, HARNESS).expect("write the harness");
    let compiled: Output = Command::new(javac)
        .arg("-d")
        .arg(scratch.path())
        .arg(&probe_path)
        .arg(&harness_path)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "javac rejected {label}:\n{}\n----\n{probe}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed: Output = Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("Harness")
        .output()
        .expect("run the Java harness");
    assert!(
        executed.status.success(),
        "java rejected {label}:\n{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    executed.stdout
}

#[test]
fn fixture_writes_a_constant_into_a_declared_parameter_register() {
    assert_eq!(sha256_hex(DEX), DEX_SHA256);
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), SOURCE_SHA256);
    assert!(PROVENANCE.contains(DEX_SHA256));
    assert!(PROVENANCE.contains(SOURCE_SHA256));
    assert!(PROVENANCE.contains("version = \"9.1.31\""));
    assert_eq!(DEX.get(..8), Some(b"dex\n035\0".as_slice()));
    assert!(
        AUTHORED.contains("a = 7;") && AUTHORED.contains("return a + 1;"),
        "the authored program must reassign a parameter and read it afterwards"
    );

    let reference: Vec<u8> = compile_and_run("locals-authored", &authored_param_probe());
    assert_eq!(
        String::from_utf8_lossy(&reference).replace("\r\n", "\n"),
        EXPECTED_STDOUT,
        "the authored program must produce the behavior the provenance records"
    );
}

#[test]
fn a_constant_written_into_a_parameter_register_keeps_the_parameter_name() {
    let reference: Vec<u8> = compile_and_run("locals-authored-reference", &authored_param_probe());
    let sources: DecompiledDex = recovered();
    let unit: String = recovered_unit(&sources, BEHAVIOURAL_UNIT);
    let produced: Vec<u8> = compile_and_run("locals-recovered", &unit);
    assert_eq!(
        String::from_utf8_lossy(&produced).replace("\r\n", "\n"),
        String::from_utf8_lossy(&reference).replace("\r\n", "\n"),
        "a constant stored into a parameter register must be written through the same name every \
         later read uses, or the recovered method reads the original argument instead; the \
         recovered unit was:\n{unit}"
    );
}

#[test]
fn one_register_is_never_written_under_two_different_names() {
    let sources: DecompiledDex = recovered();
    for name in [BEHAVIOURAL_UNIT, STRUCTURAL_UNIT] {
        let unit: String = recovered_unit(&sources, name);
        let assigned: BTreeSet<String> = assigned_names(&unit);
        let shadowed: Vec<&String> = assigned
            .iter()
            .filter(|target: &&String| target.starts_with("var"))
            .filter(|target: &&String| {
                let suffix: &str = target.trim_start_matches("var");
                assigned.contains(&format!("arg{suffix}"))
            })
            .collect();
        assert!(
            shadowed.is_empty(),
            "in {name} the same register is written as both varN and argN, so one of the two \
             writes is invisible to every later read: {shadowed:?}\n{unit}"
        );
    }
}
