#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};
use sha2::{Digest, Sha256};

pub mod common;

const DEX: &[u8] = include_bytes!("fixtures/dead_store/AccumulateProbe-min21.dex");
const AUTHORED: &str = include_str!("fixtures/dead_store/AccumulateProbe.java");
const HARNESS: &str = include_str!("fixtures/dead_store/Harness.java");
const PROVENANCE: &str = include_str!("fixtures/dead_store/provenance.toml");
const DEX_SHA256: &str = "bf496dcb806b98ece649eadbec6e4080c075334c8f418ac2ffee07f2f777438c";
const SOURCE_SHA256: &str = "ea72b3b5e240ed4c7a2083cfb8b7f8dea7b101db20f047e815054cd74b8cae55";
const EXPECTED_STDOUT: &str = "10\n0\n18\n36\n-8\n";
const BEHAVIOURAL_UNIT: &str = "AccumulateProbe.java";
const STRUCTURAL_UNIT: &str = "CastProbe.java";
const BEHAVIOURAL_METHODS: [&str; 4] = ["accumulate", "scale", "widen", "negate"];
const STRUCTURAL_METHODS: [&str; 2] = ["narrow", "mixed"];

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

fn self_referencing_assignments(source: &str) -> Vec<String> {
    let mut offenders: Vec<String> = Vec::new();
    for line in source.lines() {
        let trimmed: &str = line.trim();
        let Some((target, value)) = trimmed
            .strip_suffix(';')
            .and_then(|statement: &str| statement.split_once(" = "))
        else {
            continue;
        };
        if target.contains('.') || !value.contains(target) {
            continue;
        }
        offenders.push(trimmed.to_owned());
    }
    offenders
}

fn compile_and_run(label: &str, probe: &str) -> Vec<u8> {
    let javac: PathBuf =
        common::find_on_path("javac").expect("the dead-store gate requires javac on PATH");
    let java: PathBuf =
        common::find_on_path("java").expect("the dead-store gate requires java on PATH");
    let scratch: ScratchDir = ScratchDir::create(label).expect("create Java scratch directory");
    let probe_path: PathBuf = scratch.path().join("AccumulateProbe.java");
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

fn authored_reference(label: &str) -> Vec<u8> {
    let stripped: String = AUTHORED
        .split("\nfinal class CastProbe {")
        .next()
        .expect("the authored file splits at the second class")
        .to_owned();
    compile_and_run(label, &stripped)
}

#[test]
fn fixture_folds_every_result_back_into_an_operand_register() {
    assert_eq!(sha256_hex(DEX), DEX_SHA256);
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), SOURCE_SHA256);
    assert!(PROVENANCE.contains(DEX_SHA256));
    assert!(PROVENANCE.contains(SOURCE_SHA256));
    assert!(PROVENANCE.contains("version = \"9.1.31\""));
    assert_eq!(DEX.get(..8), Some(b"dex\n035\0".as_slice()));

    for method in BEHAVIOURAL_METHODS.iter().chain(STRUCTURAL_METHODS.iter()) {
        assert!(
            AUTHORED.contains(&format!(" {method}(")),
            "the authored program must declare {method}"
        );
    }

    let reference: Vec<u8> = authored_reference("dead-store-authored");
    assert_eq!(
        String::from_utf8_lossy(&reference).replace("\r\n", "\n"),
        EXPECTED_STDOUT,
        "the authored program must produce the behavior the provenance records"
    );
}

#[test]
fn the_recovered_methods_compute_the_authored_values() {
    let reference: Vec<u8> = authored_reference("dead-store-authored-reference");
    let sources: DecompiledDex = recovered();
    let unit: String = recovered_unit(&sources, BEHAVIOURAL_UNIT);
    let produced: Vec<u8> = compile_and_run("dead-store-recovered", &unit);
    assert_eq!(
        String::from_utf8_lossy(&produced).replace("\r\n", "\n"),
        String::from_utf8_lossy(&reference).replace("\r\n", "\n"),
        "every recovered method must compute what the authored method computes; the recovered \
         unit was:\n{unit}"
    );
}

#[test]
fn no_recovered_statement_reassigns_a_name_its_own_value_reads() {
    let sources: DecompiledDex = recovered();
    for name in [BEHAVIOURAL_UNIT, STRUCTURAL_UNIT] {
        let unit: String = recovered_unit(&sources, name);
        let offenders: Vec<String> = self_referencing_assignments(&unit);
        assert!(
            offenders.is_empty(),
            "an assignment whose value re-reads its own target makes every later read of that \
             target compute a different number than the authored method did, in {name}: \
             {offenders:?}\n{unit}"
        );
    }
}

#[test]
fn the_structural_class_still_carries_the_shapes_it_is_there_to_cover() {
    let sources: DecompiledDex = recovered();
    let unit: String = recovered_unit(&sources, STRUCTURAL_UNIT);
    for method in STRUCTURAL_METHODS {
        assert!(
            unit.contains(&format!(" {method}(")),
            "{STRUCTURAL_UNIT} must still declare {method}, or the structural grade covers \
             nothing:\n{unit}"
        );
    }
    assert!(
        unit.contains("(int)"),
        "the structural class must keep its long-to-int cast, which is the numeric_cast path:\n\
         {unit}"
    );
}
