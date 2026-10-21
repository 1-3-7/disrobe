#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};
use sha2::{Digest, Sha256};

use crate::common;

const DEX: &[u8] = include_bytes!("../fixtures/d8_enum_plain/EnumProbe-min21.dex");
const AUTHORED: &str = include_str!("../fixtures/d8_enum_plain/EnumProbe.java");
const PROVENANCE: &str = include_str!("../fixtures/d8_enum_plain/provenance.toml");
const DEX_SHA256: &str = "ece7a9851917bbc855320089649e4e8e04f4eff5ccf8c7830b83196ca576d733";
const AUTHORED_SHA256: &str = "4e985774d45df4dc4b730be65c23658b4c82ff56cef6d07553c66f48f2a1bf75";
const PROGRAM_UNIT: &str = "EnumProbe.java";
const EXPECTED_STDOUT: &str =
    "LOW=low/l:1/MEDIUM;MEDIUM=medium/m:5/HIGH;HIGH=high/h:9/LOW;1;1;OFF\n";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn recovered_unit() -> String {
    let dex: DexFile = parse_dex(DEX).expect("parse the enum fixture dex");
    let recovered: DecompiledDex = decompile_dex(&dex, DEX);
    recovered
        .sources
        .get(PROGRAM_UNIT)
        .expect("recover the authored compilation unit")
        .clone()
}

fn compile_and_run(label: &str, source: &str) -> String {
    let javac: PathBuf =
        common::find_on_path("javac").expect("the D8 enum gate requires javac on PATH");
    let java: PathBuf =
        common::find_on_path("java").expect("the D8 enum gate requires java on PATH");
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
    assert!(
        compiled.status.success(),
        "javac rejected {label}:\n{}\n----\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed: Output = Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("EnumProbe")
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
fn the_enum_fixture_matches_its_provenance() {
    assert_eq!(sha256_hex(DEX), DEX_SHA256);
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), AUTHORED_SHA256);
    assert!(PROVENANCE.contains(&format!("output_sha256 = \"{DEX_SHA256}\"")));
    assert!(PROVENANCE.contains(&format!("source_sha256 = \"{AUTHORED_SHA256}\"")));
    assert_eq!(compile_and_run("enum-authored", AUTHORED), EXPECTED_STDOUT);
}

#[test]
fn d8_enums_recover_as_enum_declarations_that_recompile_and_run() {
    let source: String = recovered_unit();
    assert!(
        source.contains("public static enum Level {"),
        "the enum keyword is recovered:\n{source}"
    );
    let lines: Vec<&str> = source.lines().map(str::trim).collect();
    let level: usize = lines
        .iter()
        .position(|line: &&str| *line == "public static enum Level {")
        .expect("Level declaration");
    assert_eq!(
        &lines[level + 1..level + 4],
        [
            "LOW(1, \"low\"),",
            "MEDIUM(5, \"medium\"),",
            "HIGH(9, \"high\");"
        ],
        "constants carry their constructor arguments in ordinal order:\n{source}"
    );
    let flag: usize = lines
        .iter()
        .position(|line: &&str| *line == "public static enum Flag {")
        .expect("Flag declaration");
    assert_eq!(&lines[flag + 1..flag + 3], ["OFF,", "ON;"], "{source}");
    for synthetic in [
        "$VALUES",
        "$values()",
        "valueOf(String",
        "values() {",
        "super(arg0, arg1)",
    ] {
        assert!(
            !source.contains(synthetic),
            "the enum synthetic {synthetic:?} is not written:\n{source}"
        );
    }
    assert!(
        source.contains("Level(int arg2, String arg3) {"),
        "the constructor drops the name and ordinal parameters:\n{source}"
    );
    assert_eq!(compile_and_run("enum-recovered", &source), EXPECTED_STDOUT);
}

#[test]
fn an_extra_recovered_constant_turns_the_execution_grade_red() {
    let source: String = recovered_unit();
    let mutated: String = source.replacen(
        "LOW(1, \"low\"),\n",
        "LOW(1, \"low\"),\nEXTRA(0, \"x\"),\n",
        1,
    );
    assert_ne!(source, mutated);
    let javac: PathBuf = common::find_on_path("javac").expect("javac on PATH");
    let scratch: ScratchDir = ScratchDir::create("enum-mutated").expect("scratch");
    let source_path: PathBuf = scratch.path().join(PROGRAM_UNIT);
    std::fs::write(&source_path, &mutated).expect("write mutated program");
    let compiled: Output = Command::new(javac)
        .arg("-nowarn")
        .arg("-d")
        .arg(scratch.path())
        .arg(&source_path)
        .output()
        .expect("run javac");
    assert!(compiled.status.success(), "the mutated enum still compiles");
    let java: PathBuf = common::find_on_path("java").expect("java on PATH");
    let executed: Output = Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("EnumProbe")
        .output()
        .expect("run the mutated program");
    assert_ne!(
        String::from_utf8_lossy(&executed.stdout).replace("\r\n", "\n"),
        EXPECTED_STDOUT,
        "an extra constant changes the program's output, so the execution grade can fail"
    );
}
