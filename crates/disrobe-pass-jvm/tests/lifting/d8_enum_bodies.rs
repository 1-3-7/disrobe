#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};
use sha2::{Digest, Sha256};

use crate::common;

const DEX: &[u8] = include_bytes!("../fixtures/d8_enum_bodies/EnumBodies-min21.dex");
const AUTHORED: &str = include_str!("../fixtures/d8_enum_bodies/EnumBodies.java");
const PROVENANCE: &str = include_str!("../fixtures/d8_enum_bodies/provenance.toml");
const DEX_SHA256: &str = "b5a93136fe6092f461e99e4608f5fa5d9adf45ddc2de0da5ff8450ed6b4fbb8b";
const AUTHORED_SHA256: &str = "aeb3a45f150938e9f0edcd1712bd9cb9a2dce4a88dde9e5f985c58f8dc8afb86";
const PROGRAM_UNIT: &str = "EnumBodies.java";
const EXPECTED_STDOUT: &str = "ADD+10;SUB-4;MULx21;f;s1;1\n";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn recovered_unit() -> String {
    let dex: DexFile = parse_dex(DEX).expect("parse the enum bodies fixture dex");
    let recovered: DecompiledDex = decompile_dex(&dex, DEX);
    recovered
        .sources
        .get(PROGRAM_UNIT)
        .expect("recover the authored compilation unit")
        .clone()
}

fn compile(label: &str, source: &str) -> (ScratchDir, Output) {
    let javac: PathBuf =
        common::find_on_path("javac").expect("the D8 enum bodies gate requires javac on PATH");
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
        common::find_on_path("java").expect("the D8 enum bodies gate requires java on PATH");
    let (scratch, compiled): (ScratchDir, Output) = compile(label, source);
    assert!(
        compiled.status.success(),
        "javac rejected {label}:\n{}\n----\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed: Output = Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("EnumBodies")
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
fn the_enum_bodies_fixture_matches_its_provenance() {
    assert_eq!(sha256_hex(DEX), DEX_SHA256);
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), AUTHORED_SHA256);
    assert!(PROVENANCE.contains(&format!("output_sha256 = \"{DEX_SHA256}\"")));
    assert!(PROVENANCE.contains(&format!("source_sha256 = \"{AUTHORED_SHA256}\"")));
    assert_eq!(
        compile_and_run("enum-bodies-authored", AUTHORED),
        EXPECTED_STDOUT
    );
}

#[test]
fn constant_bodies_fold_into_the_enum_and_the_unit_recompiles_and_runs() {
    let source: String = recovered_unit();
    let lines: Vec<&str> = source.lines().map(str::trim).collect();
    let op: usize = lines
        .iter()
        .position(|line: &&str| *line == "public static enum Op {")
        .unwrap_or_else(|| panic!("the abstract enum is an enum declaration:\n{source}"));
    assert_eq!(
        &lines[op + 1..op + 6],
        [
            "ADD(\"+\") {",
            "public int apply(int arg0, int arg1) {",
            "return (arg0 + arg1);",
            "}",
            "},",
        ],
        "the first constant carries its body:\n{source}"
    );
    assert!(
        source.contains("    public abstract int apply(int arg0, int arg1);"),
        "the abstract method stays on the enum:\n{source}"
    );
    let mode: usize = lines
        .iter()
        .position(|line: &&str| *line == "public static enum Mode {")
        .unwrap_or_else(|| panic!("the concrete enum is an enum declaration:\n{source}"));
    assert_eq!(
        &lines[mode + 1..mode + 7],
        [
            "FAST {",
            "public String tag() {",
            "return \"f\";",
            "}",
            "},",
            "SLOW;",
        ],
        "a constant with a body sits beside one without:\n{source}"
    );
    for leftover in [
        "class Op$_1",
        "class Op$_2",
        "class Op$_3",
        "class Mode$_1",
        "Op$_1.",
        "$VALUES",
        "EnumBodies$_1 arg",
    ] {
        assert!(
            !source.contains(leftover),
            "the constant subclass {leftover:?} is folded away:\n{source}"
        );
    }
    assert_eq!(
        compile_and_run("enum-bodies-recovered", &source),
        EXPECTED_STDOUT
    );
}

#[test]
fn a_dropped_constant_body_turns_the_execution_grade_red() {
    let source: String = recovered_unit();
    let mutated: String = source.replacen("return \"f\";", "return \"g\";", 1);
    assert_ne!(source, mutated);
    assert_ne!(
        compile_and_run("enum-bodies-mutated", &mutated),
        EXPECTED_STDOUT
    );
    let unfolded: String = source.replacen(
        "    MUL(\"*\") {\n",
        "    MUL(\"*\"),\n    EXTRA(\"?\") {\n",
        1,
    );
    assert_ne!(source, unfolded);
    let (_scratch, compiled): (ScratchDir, Output) = compile("enum-bodies-unfolded", &unfolded);
    assert!(
        !compiled.status.success(),
        "an extra constant that inherits the abstract method does not compile"
    );
}
