#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};
use sha2::{Digest, Sha256};

use crate::common;

const RELEASE_DEX: &[u8] = include_bytes!("../fixtures/d8_enum_plain/EnumProbe-min21.dex");
const DEBUG_DEX: &[u8] = include_bytes!("../fixtures/d8_enum_plain/EnumProbe-min21-debug.dex");
const DEBUG_SHA256: &str = "a65b232ace708a509bbd3735975f349894a7c76df131de7148e747a280a09266";
const PROGRAM_UNIT: &str = "EnumProbe.java";
const EXPECTED_STDOUT: &str =
    "LOW=low/l:1/MEDIUM;MEDIUM=medium/m:5/HIGH;HIGH=high/h:9/LOW;1;1;OFF\n";

fn recovered_unit(dex_bytes: &[u8]) -> String {
    let dex: DexFile = parse_dex(dex_bytes).expect("parse the enum fixture dex");
    let recovered: DecompiledDex = decompile_dex(&dex, dex_bytes);
    recovered
        .sources
        .get(PROGRAM_UNIT)
        .expect("recover the authored compilation unit")
        .clone()
}

fn authored_local_declarations(source: &str) -> Vec<&'static str> {
    ["StringBuilder out;", "EnumProbe.Level[] all;"]
        .into_iter()
        .filter(|declaration: &&str| source.contains(declaration))
        .collect()
}

#[test]
fn the_debug_build_carries_the_authored_local_names() {
    assert_eq!(format!("{:x}", Sha256::digest(DEBUG_DEX)), DEBUG_SHA256);
    let debug: String = recovered_unit(DEBUG_DEX);
    assert_eq!(
        authored_local_declarations(&debug),
        vec!["StringBuilder out;", "EnumProbe.Level[] all;"],
        "the debug_info_item local tables name the recovered locals:\n{debug}"
    );
    assert!(
        debug.contains("out = new StringBuilder();")
            && debug.contains("all = EnumProbe.Level.values();"),
        "{debug}"
    );
    assert!(
        debug.contains("for (EnumProbe.Level level : var1) {"),
        "the enhanced for over the values array is recovered with the debug name of its element:
{debug}"
    );
    let javac: PathBuf = common::find_on_path("javac").expect("javac on PATH");
    let java: PathBuf = common::find_on_path("java").expect("java on PATH");
    let scratch: ScratchDir = ScratchDir::create("debug-locals").expect("scratch");
    let source_path: PathBuf = scratch.path().join(PROGRAM_UNIT);
    std::fs::write(&source_path, &debug).expect("write program");
    let compiled: Output = Command::new(javac)
        .arg("-nowarn")
        .arg("-d")
        .arg(scratch.path())
        .arg(&source_path)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "javac rejected the debug recovery:\n{}\n----\n{debug}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed: Output = Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("EnumProbe")
        .output()
        .expect("run the program");
    assert_eq!(
        String::from_utf8_lossy(&executed.stdout).replace("\r\n", "\n"),
        EXPECTED_STDOUT
    );
}

#[test]
fn the_release_build_has_no_local_names_to_recover() {
    let release: String = recovered_unit(RELEASE_DEX);
    assert!(
        authored_local_declarations(&release).is_empty(),
        "a release build carries no local tables, so synthetic names stay:\n{release}"
    );
    assert!(release.contains("StringBuilder var"), "{release}");
}
