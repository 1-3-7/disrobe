#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{
    BackendPreference, DecompiledDex, DexFile, android_decompile_dex, decompile_dex, parse_dex,
};
use sha2::{Digest, Sha256};

pub mod common;

const DEX: &[u8] = include_bytes!("fixtures/locals/ParamProbe-min21.dex");
const AUTHORED: &str = include_str!("fixtures/locals/ParamProbe.java");
const HARNESS: &str = include_str!("fixtures/locals/Harness.java");
const PROVENANCE: &str = include_str!("fixtures/locals/provenance.toml");
const DEX_SHA256: &str = "e33671efa1474500ed9bd780625b610d6ae9342895fb4d0d84a03b048d345d80";
const SOURCE_SHA256: &str = "cfaa1d59de3b61410ae5257713de8e23189255ea9fd8ac9866e2ef50a70dec47";
const EXPECTED_STDOUT: &str = "8\n6\n26\n31\n5\n6\n24\n7\n12\n15\n3\n7\n";
const BEHAVIOURAL_UNITS: [&str; 2] = ["ParamProbe.java", "TempProbe.java"];
const STRUCTURAL_UNIT: &str = "LocalProbe.java";
const DECLARED_TEMPORARY: &str = "        long var0;";

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

fn authored_without_residual() -> String {
    AUTHORED
        .split("\nfinal class LocalProbe {")
        .next()
        .expect("the authored file splits at the residual class")
        .to_owned()
}

fn compile_and_run(label: &str, units: &[(&str, &str)]) -> Vec<u8> {
    let javac: PathBuf =
        common::find_on_path("javac").expect("the local-naming gate requires javac on PATH");
    let java: PathBuf =
        common::find_on_path("java").expect("the local-naming gate requires java on PATH");
    let scratch: ScratchDir = ScratchDir::create(label).expect("create Java scratch directory");
    let harness_path: PathBuf = scratch.path().join("Harness.java");
    std::fs::write(&harness_path, HARNESS).expect("write the harness");
    let mut paths: Vec<PathBuf> = vec![harness_path];
    for (name, source) in units {
        let path: PathBuf = scratch.path().join(name);
        std::fs::write(&path, source).expect("write a unit");
        paths.push(path);
    }
    let compiled: Output = Command::new(javac)
        .arg("-d")
        .arg(scratch.path())
        .args(&paths)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "javac rejected {label}:\n{}\n----\n{units:?}",
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
    compile_and_run(label, &[("ParamProbe.java", &authored_without_residual())])
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
    assert!(
        AUTHORED.contains("long t = 3L;") && AUTHORED.contains("t = a * 5L;"),
        "the authored program must carry a category-two temporary across a branch join"
    );

    let reference: Vec<u8> = authored_reference("locals-authored");
    assert_eq!(
        String::from_utf8_lossy(&reference).replace("\r\n", "\n"),
        EXPECTED_STDOUT,
        "the authored program must produce the behavior the provenance records"
    );
}

#[test]
fn the_recovered_units_compute_the_authored_values() {
    let reference: Vec<u8> = authored_reference("locals-authored-reference");
    let sources: DecompiledDex = recovered();
    let units: Vec<(String, String)> = BEHAVIOURAL_UNITS
        .iter()
        .map(|name: &&str| ((*name).to_owned(), recovered_unit(&sources, name)))
        .collect();
    let borrowed: Vec<(&str, &str)> = units
        .iter()
        .map(|(name, source): &(String, String)| (name.as_str(), source.as_str()))
        .collect();
    let produced: Vec<u8> = compile_and_run("locals-recovered", &borrowed);
    assert_eq!(
        String::from_utf8_lossy(&produced).replace("\r\n", "\n"),
        String::from_utf8_lossy(&reference).replace("\r\n", "\n"),
        "a constant stored into a parameter register must use the name every later read uses, and \
         a temporary that crosses a branch join must be declared with the type its writes \
         produce; the recovered units were:\n{borrowed:?}"
    );
}

#[test]
fn the_residual_class_still_carries_the_shape_no_declaration_can_repair() {
    let sources: DecompiledDex = recovered();
    let unit: String = recovered_unit(&sources, STRUCTURAL_UNIT);
    assert!(
        unit.contains("boolean arg1") && unit.contains("arg1 = 7;"),
        "LocalProbe must keep the case where D8 reused a register the signature declares boolean \
         for an int temporary; a declaration cannot repair it because the name is already taken \
         by the parameter:\n{unit}"
    );
}

#[test]
fn a_temporary_that_crosses_a_join_is_declared_with_its_own_type() {
    let sources: DecompiledDex = recovered();
    let unit: String = recovered_unit(&sources, "TempProbe.java");
    assert!(
        unit.contains(DECLARED_TEMPORARY),
        "the category-two temporary that crosses a join must be hoisted as {DECLARED_TEMPORARY}, \
         or it has no type and the unit cannot compile:\n{unit}"
    );
    let written: BTreeSet<String> = assigned_names(&unit);
    for target in &written {
        assert!(
            !target.starts_with("var") || unit.contains(&format!(" {target};")),
            "every temporary the unit writes must also be declared, and {target} is not:\n{unit}"
        );
    }
}

#[test]
fn classfile_backend_renames_an_int_lifetime_that_reuses_a_boolean_parameter_slot() {
    let output = android_decompile_dex(DEX, BackendPreference::PreferInHouse)
        .expect("translate and decompile the real D8 artifact");
    let unit: &str = output
        .sources
        .get(STRUCTURAL_UNIT)
        .unwrap_or_else(|| panic!("recover {STRUCTURAL_UNIT}, saw {:?}", output.sources.keys()));
    assert!(unit.contains("boolean arg1"), "{unit}");
    let fresh: &str = unit
        .lines()
        .map(str::trim)
        .find_map(|line: &str| line.strip_prefix("int ")?.strip_suffix(';'))
        .expect("the replacement integer lifetime must have a declaration");
    assert_ne!(fresh, "arg1", "{unit}");
    assert!(unit.contains(&format!("{fresh} = 7;")), "{unit}");
    assert!(!unit.contains("arg1 = 7;"), "{unit}");

    let javac: PathBuf =
        common::find_on_path("javac").expect("the local-naming gate requires javac on PATH");
    let scratch: ScratchDir =
        ScratchDir::create("locals-classfile-backend").expect("create Java scratch directory");
    let source_path: PathBuf = scratch.path().join(STRUCTURAL_UNIT);
    std::fs::write(&source_path, unit).expect("write recovered LocalProbe");
    let compiled: Output = Command::new(javac)
        .arg("-d")
        .arg(scratch.path())
        .arg(&source_path)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "javac rejected the recovered LocalProbe:\n{}\n----\n{unit}",
        String::from_utf8_lossy(&compiled.stderr)
    );
}
