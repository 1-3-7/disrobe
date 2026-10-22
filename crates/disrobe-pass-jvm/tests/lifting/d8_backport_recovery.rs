#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{
    BackportApi, DecompiledDex, DexFile, backport_catalog_json, decompile_dex,
    derive_backport_catalog, parse_dex,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::common;

const DEX: &[u8] = include_bytes!("../fixtures/d8_backports/BackportProbe-min21.dex");
const AUTHORED: &str = include_str!("../fixtures/d8_backports/BackportProbe.java");
const PROVENANCE: &str = include_str!("../fixtures/d8_backports/provenance.toml");
const APIS: &str = include_str!("../fixtures/d8_backports/apis.json");
const DEX_SHA256: &str = "1fe8dd0d04201dfbbeda040a6423cc7921af70f1c6428744420d25d32a5869d7";
const AUTHORED_SHA256: &str = "c0c8d2761cd0a2712bd893ef17c797a6ec54c83148a11ef3fcab9528d923bf4c";
const PROGRAM_UNIT: &str = "BackportProbe.java";
const EXPECTED_STDOUT: &str = "[][1][1, 2][1, 2, 3][1, 2, 3, 4][1, 2, 3, 4, 5][1, 2, 3, 4, 5, 6][1, 2, 3, 4, 5, 6, 7][1, 2, 3, 4, 5, 6, 7, 8][1, 2, 3, 4, 5, 6, 7, 8, 9][1, 2, 3, 4, 5, 6, 7, 8, 9, 10][1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11][1, 2, 3][]12345112{}{a=1}2345{a=1}2k=91dtruefalse56107321753612319934112-38261-2ababtruextruev1[p, q]-1131226oknull04066true\n";

#[derive(Debug, Deserialize)]
struct ProbeApi {
    probe: String,
    owner: String,
    name: String,
    descriptor: String,
    receiver_first: bool,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn probes() -> Vec<(String, BackportApi)> {
    let entries: Vec<ProbeApi> = serde_json::from_str(APIS).expect("apis.json parses");
    entries
        .into_iter()
        .map(|entry: ProbeApi| {
            (
                entry.probe,
                BackportApi {
                    owner: entry.owner,
                    name: entry.name,
                    descriptor: entry.descriptor,
                    receiver_first: entry.receiver_first,
                },
            )
        })
        .collect()
}

fn recovered_unit() -> String {
    let dex: DexFile = parse_dex(DEX).expect("parse the backport fixture dex");
    let recovered: DecompiledDex = decompile_dex(&dex, DEX);
    recovered
        .sources
        .get(PROGRAM_UNIT)
        .expect("recover the authored compilation unit")
        .clone()
}

fn compile(label: &str, source: &str) -> (ScratchDir, Output) {
    let javac: PathBuf =
        common::find_on_path("javac").expect("the D8 backport gate requires javac on PATH");
    let scratch: ScratchDir = ScratchDir::create(label).expect("create Java scratch directory");
    let source_path: PathBuf = scratch.path().join(PROGRAM_UNIT);
    std::fs::write(&source_path, source).expect("write Java program");
    let compiled: Output = Command::new(javac)
        .arg("-nowarn")
        .arg("-d")
        .arg(scratch.path())
        .arg(&source_path)
        .output()
        .expect("run javac");
    (scratch, compiled)
}

fn compile_and_run(label: &str, source: &str) -> String {
    let java: PathBuf =
        common::find_on_path("java").expect("the D8 backport gate requires java on PATH");
    let (scratch, compiled): (ScratchDir, Output) = compile(label, source);
    assert!(
        compiled.status.success(),
        "javac rejected {label}:\n{}\n----\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed: Output = Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("BackportProbe")
        .output()
        .expect("run the Java program");
    assert!(
        executed.status.success(),
        "java rejected {label}:\n{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    String::from_utf8_lossy(&executed.stdout).replace("\r\n", "\n")
}

#[test]
fn the_backport_fixture_matches_its_provenance() {
    assert_eq!(sha256_hex(DEX), DEX_SHA256);
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), AUTHORED_SHA256);
    assert!(PROVENANCE.contains(&format!("output_sha256 = \"{DEX_SHA256}\"")));
    assert!(PROVENANCE.contains(&format!("source_sha256 = \"{AUTHORED_SHA256}\"")));
    assert_eq!(
        compile_and_run("backports-authored", AUTHORED),
        EXPECTED_STDOUT
    );
}

#[test]
fn the_committed_catalog_is_derived_from_the_probe() {
    let dex: DexFile = parse_dex(DEX).expect("parse the backport fixture dex");
    let derived: String =
        derive_backport_catalog(&dex, DEX, &probes()).expect("derive the backport catalog");
    if derived != backport_catalog_json() {
        let path: PathBuf =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/d8_backports.json");
        if std::env::var_os("DISROBE_REGEN_BACKPORT_CATALOG").is_some() {
            std::fs::write(&path, &derived).expect("write the regenerated catalog");
            panic!("regenerated {}; rerun the gate", path.display());
        }
        panic!(
            "data/d8_backports.json is stale; set DISROBE_REGEN_BACKPORT_CATALOG=1 to regenerate it from the probe\n{derived}"
        );
    }
    let entries: usize = derived.matches("\"fingerprint\"").count();
    assert!(
        entries >= 40,
        "the probe pins at least 40 helpers, found {entries}"
    );
}

#[test]
fn backport_helpers_lower_to_their_jdk_calls_and_the_unit_runs() {
    let source: String = recovered_unit();
    for expected in [
        "return java.util.List.of(Integer.valueOf(1), Integer.valueOf(2));",
        "return java.util.List.copyOf(arg0);",
        "return java.util.Set.of(Integer.valueOf(1));",
        "return java.util.Map.copyOf(arg0);",
        "return java.util.Map.entry(\"k\", Integer.valueOf(9));",
        "return java.util.Objects.checkIndex(arg0, arg1);",
        "return java.util.Objects.isNull(arg0);",
        "return Long.hashCode(arg0);",
        "return Math.floorMod(arg0, arg1);",
        "return arg0.repeat(arg1);",
        "return arg0.isBlank();",
        "return arg0.strip();",
        "return String.join(arg0, arg1);",
    ] {
        assert!(
            source.contains(expected),
            "the lowered call {expected:?} is written:\n{source}"
        );
    }
    assert!(
        !source.contains("BackportProbe$_0"),
        "no synthetic helper call survives:\n{source}"
    );
    assert_eq!(
        compile_and_run("backports-recovered", &source),
        EXPECTED_STDOUT
    );
}

#[test]
fn a_mislowered_call_turns_the_execution_grade_red() {
    let source: String = recovered_unit();
    let mutated: String = source.replacen(
        "return java.util.Objects.checkIndex(arg0, arg1);",
        "return Math.max(arg0, arg1);",
        1,
    );
    assert_ne!(source, mutated);
    assert_ne!(
        compile_and_run("backports-mutated", &mutated),
        EXPECTED_STDOUT
    );
}
