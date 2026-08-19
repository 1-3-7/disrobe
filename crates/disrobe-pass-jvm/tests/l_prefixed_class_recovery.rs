#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};
use sha2::{Digest, Sha256};

pub mod common;

const DEX: &[u8] = include_bytes!("fixtures/l_prefixed_classes/L-min21.dex");
const AUTHORED: &str = include_str!("fixtures/l_prefixed_classes/L.java");
const PROVENANCE: &str = include_str!("fixtures/l_prefixed_classes/provenance.toml");
const DEX_SHA256: &str = "7d3f330a9df4751d347311561c732e5f6a25cc95bc550db72ad24e57a6e63c06";
const SOURCE_SHA256: &str = "2b434519358b9439f21c956de388b68a1dca1486b7f839ba718fc83250890d99";
const EXPECTED_STDOUT: &str = "14\n-6\n";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn recovered_unit<'a>(recovered: &'a DecompiledDex, name: &str) -> &'a String {
    recovered
        .sources
        .get(name)
        .unwrap_or_else(|| panic!("recover {name}, saw {:?}", recovered.sources.keys()))
}

#[test]
fn fixture_declares_the_l_prefixed_descriptors() {
    assert_eq!(sha256_hex(DEX), DEX_SHA256);
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), SOURCE_SHA256);
    assert!(PROVENANCE.contains(DEX_SHA256));
    assert!(PROVENANCE.contains(SOURCE_SHA256));
    assert!(PROVENANCE.contains("version = \"9.1.31\""));
    assert_eq!(DEX.get(..8), Some(b"dex\n035\0".as_slice()));

    let dex: DexFile = parse_dex(DEX).expect("parse the real D8 artifact");
    let declared: BTreeSet<&str> = dex
        .class_descriptors
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<&str>>();
    assert!(
        declared.contains("LL;") && declared.contains("LLL;"),
        "the artifact must declare the default-package classes L and LL, saw {declared:?}"
    );
    assert!(
        AUTHORED.contains("class L {") && AUTHORED.contains("class LL {"),
        "the authored program must declare both classes so it can grade the recovery"
    );
}

#[test]
fn a_class_named_l_keeps_its_name_through_recovery() {
    let dex: DexFile = parse_dex(DEX).expect("parse the real D8 artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, DEX);

    let outer: &String = recovered_unit(&recovered, "L.java");
    let inner: &String = recovered_unit(&recovered, "LL.java");
    assert!(
        outer.contains("class L {"),
        "the class named L must keep its name:\n{outer}"
    );
    assert!(
        inner.contains("class LL {"),
        "the class named LL must keep its name:\n{inner}"
    );
    assert!(
        outer.contains("LL wrap(L "),
        "a signature naming both classes must spell them in full:\n{outer}"
    );
    assert!(
        inner.contains("L inner") || inner.contains("(L "),
        "the field or constructor typed L must spell it in full:\n{inner}"
    );
    for unit in [outer, inner] {
        assert!(
            !unit.contains(" () ") && !unit.contains("  ("),
            "no type may render as an empty name:\n{unit}"
        );
    }
}

fn declared_class_names(source: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter_map(|line: &str| {
            let head: &str = line.split_once(" class ")?.1;
            let name: &str = head.split_whitespace().next()?;
            let name: &str = name.split(['<', '{']).next()?;
            (!name.is_empty()).then(|| name.to_owned())
        })
        .collect()
}

#[test]
fn recovered_class_names_equal_the_authored_class_names() {
    let authored: BTreeSet<String> = declared_class_names(AUTHORED);
    assert_eq!(
        authored,
        BTreeSet::from(["L".to_owned(), "LL".to_owned()]),
        "the authored program must declare exactly L and LL for this grade to mean anything"
    );

    let dex: DexFile = parse_dex(DEX).expect("parse the real D8 artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, DEX);
    let units: BTreeSet<String> = recovered.sources.keys().cloned().collect();
    assert_eq!(
        units,
        BTreeSet::from(["L.java".to_owned(), "LL.java".to_owned()]),
        "each authored class must recover into its own compilation unit"
    );

    let mut returned: BTreeSet<String> = BTreeSet::new();
    for source in recovered.sources.values() {
        returned.extend(declared_class_names(source));
    }
    assert_eq!(
        returned, authored,
        "the recovered class names must be the names the author wrote, not a rewritten form"
    );
}

#[test]
fn the_authored_program_behaves_as_the_provenance_records() {
    let javac: PathBuf =
        common::find_on_path("javac").expect("the L-prefixed class gate requires javac on PATH");
    let java: PathBuf =
        common::find_on_path("java").expect("the L-prefixed class gate requires java on PATH");
    let scratch: ScratchDir =
        ScratchDir::create("l-prefixed-authored").expect("create Java scratch directory");
    let source_path: PathBuf = scratch.path().join("L.java");
    std::fs::write(&source_path, AUTHORED).expect("write Java program");
    let compiled: Output = Command::new(javac)
        .arg("-d")
        .arg(scratch.path())
        .arg(&source_path)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "javac rejected the authored program:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed: Output = Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("L")
        .output()
        .expect("run the Java program");
    assert!(executed.status.success());
    assert_eq!(
        String::from_utf8_lossy(&executed.stdout).replace("\r\n", "\n"),
        EXPECTED_STDOUT,
        "the fixture drifted from the behavior its provenance records"
    );
    assert!(PROVENANCE.contains("14\\n-6\\n"));
}
