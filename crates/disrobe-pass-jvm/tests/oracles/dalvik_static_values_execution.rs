#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, decompile_dex_from_bytes};
use sha2::{Digest, Sha256};

use crate::common;

const AUTHORED: &str = include_str!("../fixtures/dalvik_static_values/StaticValues.java");
const RELEASE_DEX: &[u8] =
    include_bytes!("../fixtures/dalvik_static_values/StaticValues-release-min21.dex");
const PROVENANCE: &str = include_str!("../fixtures/dalvik_static_values/provenance.toml");
const AUTHORED_SHA256: &str = "938cfcf4b44cad8e639ce7315b0acb5d0f596e3b2115a65293347667faf90e8a";
const RELEASE_SHA256: &str = "07ef16e8cd0c3a7e3771fa4988ca12d86e28c5d29e8556a681b9f766453e8a4b";
const UNIT: &str = "StaticValues.java";
const CLASS: &str = "StaticValues";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn recovered_unit() -> String {
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), AUTHORED_SHA256);
    assert_eq!(sha256_hex(RELEASE_DEX), RELEASE_SHA256);
    assert!(PROVENANCE.contains(AUTHORED_SHA256) && PROVENANCE.contains(RELEASE_SHA256));
    let decompiled: DecompiledDex =
        decompile_dex_from_bytes(RELEASE_DEX).expect("decompile StaticValues");
    decompiled.sources.get(UNIT).cloned().unwrap_or_else(|| {
        panic!(
            "recovered unit {UNIT} in {:?}",
            decompiled.sources.keys().collect::<Vec<&String>>()
        )
    })
}

fn tool(name: &str) -> PathBuf {
    common::find_on_path(name)
        .unwrap_or_else(|| panic!("{name} is required to recompile the recovered StaticValues"))
}

fn execute(scratch: &Path, tag: &str, source: &str) -> String {
    let root: PathBuf = scratch.join(tag);
    let classes: PathBuf = root.join("classes");
    std::fs::create_dir_all(&classes).expect("create source directory");
    let path: PathBuf = root.join(UNIT);
    std::fs::write(&path, source).expect("write source");
    let compiled: Output = Command::new(tool("javac"))
        .arg("-Xlint:-options")
        .arg("-nowarn")
        .arg("-encoding")
        .arg("UTF-8")
        .arg("--release")
        .arg("8")
        .arg("-d")
        .arg(&classes)
        .arg(&path)
        .env_remove("FORCE_COLOR")
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "{tag} does not recompile:\n{}{}\n{source}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
    let ran: Output = Command::new(tool("java"))
        .arg("-cp")
        .arg(&classes)
        .arg(CLASS)
        .env_remove("FORCE_COLOR")
        .output()
        .expect("run java");
    assert!(
        ran.status.success(),
        "{tag} fails at run time:\n{}\n{source}",
        String::from_utf8_lossy(&ran.stderr)
    );
    String::from_utf8(ran.stdout).expect("utf8 stdout")
}

#[test]
fn the_recovered_class_prints_the_authored_static_values() {
    let scratch: ScratchDir = ScratchDir::create("dalvik_static_values_unit").expect("scratch");
    let reference: String = execute(scratch.path(), "authored", AUTHORED);
    assert_eq!(reference.lines().count(), 27, "{reference}");
    let recovered: String = recovered_unit();
    let printed: String = execute(scratch.path(), "recovered", &recovered);
    assert_eq!(
        printed, reference,
        "the recovered class must print what the authored class prints:\n{recovered}"
    );
}

#[test]
fn a_seeded_change_in_a_static_value_changes_the_output() {
    let scratch: ScratchDir = ScratchDir::create("dalvik_static_values_control").expect("scratch");
    let reference: String = execute(scratch.path(), "authored", AUTHORED);
    let recovered: String = recovered_unit();
    assert_eq!(recovered.matches(" = -70000;").count(), 1, "{recovered}");
    let mutated: String = recovered.replace(" = -70000;", " = -70001;");
    let printed: String = execute(scratch.path(), "mutated", &mutated);
    assert_ne!(
        printed, reference,
        "grader control: a changed static value in the recovered class must change the output"
    );
}

#[test]
fn static_values_render_as_field_initialisers() {
    let recovered: String = recovered_unit();
    for declaration in [
        "public static String trace = \"\";",
        "public static String quoted = \"caf\u{e9} \\\"q\\\" \\\\ tab\\tend\\n\";",
        "public static int n = 3;",
        "public static long K = 5L;",
        "public static long wide = -1234567890123L;",
        "public static char letter = 'x';",
        "public static char newline = 10;",
        "public static boolean flag = true;",
        "public static float ratio = 2.5f;",
        "public static float negativeZero = -0.0f;",
        "public static double tiny = -0.001;",
        "public static byte small = -7;",
        "public static short medium = 300;",
        "public static String none;",
        "public static int untouched;",
        "public static boolean off;",
    ] {
        assert!(
            recovered.contains(declaration),
            "{declaration}\n{recovered}"
        );
    }
    assert!(!recovered.contains("<decompile:"), "{recovered}");
}

#[test]
fn a_class_initialiser_that_only_returns_is_dropped() {
    let recovered: String = recovered_unit();
    assert_eq!(
        recovered
            .lines()
            .filter(|line: &&str| line.trim() == "static {")
            .count(),
        1,
        "only StaticValues keeps a static block:\n{recovered}"
    );
    assert!(recovered.contains("\"clinit\""), "{recovered}");
}
