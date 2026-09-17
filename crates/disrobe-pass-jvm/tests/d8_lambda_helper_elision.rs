#![allow(clippy::expect_used, clippy::panic, clippy::print_stderr)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::dalvik::{DalvikInsn, decode_method};
use disrobe_pass_jvm::dex::{
    CodeItem, CodeItemsReport, DexCodeState, DexMethodCode, MethodId, parse_code_items,
};
use disrobe_pass_jvm::{DecompiledDex, DexFile, decompile_dex, parse_dex};
use sha2::{Digest, Sha256};

pub mod common;

const AUTHORED: &str = include_str!("fixtures/d8_lambda_elision/ElisionProbe.java");
const D8_DEX: &[u8] = include_bytes!("fixtures/d8_lambda_elision/ElisionProbe-min21.dex");
const R8_DEX: &[u8] = include_bytes!("fixtures/d8_lambda_elision/ElisionProbe-r8-min21.dex");
const PROVENANCE: &str = include_str!("fixtures/d8_lambda_elision/provenance.toml");

const AUTHORED_SHA256: &str = "9d68167deebd381f5addafd601ebe89de2fd03e04cfcddb5176062921891a9e7";
const D8_SHA256: &str = "9fd582193f24243bde767b0cea443cb8f05751839dd9745c1312a40db938f792";
const R8_SHA256: &str = "a20ba6d88349c4808904e8cb7662aad26e50254e55d371a53c4a677c5bc5a8d7";

const PROGRAM_CLASS: &str = "ElisionProbe";
const PROGRAM_UNIT: &str = "ElisionProbe.java";
const PROGRAM_DESCRIPTOR: &str = "LElisionProbe;";

const D8_HELPERS: [&str; 6] = [
    "lambda$oneCapture$0",
    "lambda$receiverCapture$0$ElisionProbe",
    "lambda$stateless$0",
    "lambda$textCapture$0",
    "lambda$twoCaptures$0$ElisionProbe",
    "lambda$wideCapture$0",
];

const R8_HELPERS: [&str; 6] = [
    "$r8$lambda$2U3Nbe12py6Pa5JHXAdCoxxga94",
    "$r8$lambda$KBZ-iAFVJR7MX-wLvg2wgQgmZ_o",
    "$r8$lambda$NiEkV_D8wTHqxB139ipk75K0_88",
    "$r8$lambda$RoPqro7_RECtjuW2Fq6gExLmXjk",
    "$r8$lambda$v3sdq-KGhF1ZT_BtLd4fHFFmuYA",
    "$r8$lambda$w4JeZF2My4aeYanQGu08YafEF2Y",
];

const LAMBDA_SITES: [&str; 6] = [
    "oneCapture",
    "receiverCapture",
    "stateless",
    "textCapture",
    "twoCaptures",
    "wideCapture",
];

const GRADED_METHODS: usize = 15;
const IDENTICAL_METHODS: usize = 13;

const ACCESS_WIDENED_METHODS: [&str; 2] = [
    "lambda$receiverCapture$0(int)",
    "lambda$twoCaptures$0(int, int, int)",
];

const DUPLICATION_DEX: &[u8] =
    include_bytes!("fixtures/d8_lambda_duplication/DuplicatingLambdaProbe-min21.dex");
const DUPLICATION_UNIT: &str = "DuplicatingLambdaProbe.java";
const DUPLICATION_HELPERS: [&str; 2] = ["lambda$duplicating$0", "lambda$single$0"];
const DUPLICATION_RETAINED: &str = "lambda$duplicating$0";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn require_jdk_tools() -> (PathBuf, PathBuf) {
    let javac: PathBuf = common::find_on_path("javac").unwrap_or_else(|| {
        panic!("the D8 lambda helper elision gate requires javac and javap on PATH")
    });
    let javap: PathBuf = common::find_on_path("javap").unwrap_or_else(|| {
        panic!("the D8 lambda helper elision gate requires javac and javap on PATH")
    });
    (javac, javap)
}

fn recovered_unit(bytes: &[u8], unit: &str) -> String {
    let dex: DexFile = parse_dex(bytes).expect("parse the real artifact");
    let decompiled: DecompiledDex = decompile_dex(&dex, bytes);
    decompiled
        .sources
        .get(unit)
        .expect("recover the authored compilation unit")
        .clone()
}

fn declared_method_names(source: &str) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for line in source.lines() {
        if !line.starts_with("    ") || line.starts_with("     ") || !line.ends_with('{') {
            continue;
        }
        let trimmed: &str = line.trim();
        if trimmed.contains(" class ")
            || trimmed.contains(" interface ")
            || trimmed.starts_with("static {")
        {
            continue;
        }
        let Some(open): Option<usize> = trimmed.find('(') else {
            continue;
        };
        let Some(head): Option<&str> = trimmed.get(..open) else {
            continue;
        };
        let Some(name): Option<&str> = head.rsplit([' ', '\t']).next() else {
            continue;
        };
        names.insert(name.to_owned());
    }
    names
}

fn helper_names_in_artifact(bytes: &[u8], owner: &str) -> BTreeSet<String> {
    let dex: DexFile = parse_dex(bytes).expect("parse the real artifact");
    dex.method_ids
        .iter()
        .filter(|method: &&MethodId| method.class == owner)
        .map(|method: &MethodId| method.name.clone())
        .filter(|name: &String| name.starts_with("lambda$") || name.starts_with("$r8$lambda$"))
        .collect()
}

fn indexed_instruction_offset(
    dex: &DexFile,
    bytes: &[u8],
    method_name: &str,
    index_byte_offset: usize,
    predicate: impl Fn(&DalvikInsn) -> bool,
) -> usize {
    let report: CodeItemsReport = parse_code_items(dex, bytes);
    let method: &DexMethodCode = report
        .methods()
        .iter()
        .find(|method: &&DexMethodCode| {
            method.class == PROGRAM_DESCRIPTOR && method.method_name == method_name
        })
        .expect("the real artifact carries the selected method");
    let DexCodeState::Decoded(item_index) = method.state else {
        panic!("the real artifact decodes the selected method");
    };
    let item: &CodeItem = report
        .decoded()
        .get(item_index)
        .expect("the selected method body exists");
    let instruction_pc: u32 = decode_method(&item.insns)
        .into_iter()
        .find(predicate)
        .map(|insn: DalvikInsn| insn.pc)
        .expect("the selected method carries the required instruction");
    usize::try_from(method.code_offset)
        .expect("the code offset fits usize")
        .checked_add(16)
        .and_then(|offset: usize| {
            usize::try_from(instruction_pc)
                .ok()
                .and_then(|pc: usize| pc.checked_mul(2))
                .and_then(|delta: usize| offset.checked_add(delta))
        })
        .and_then(|offset: usize| offset.checked_add(index_byte_offset))
        .expect("the instruction index offset is representable")
}

fn with_helper_name_string_reference(bytes: &[u8], helper: &str) -> Vec<u8> {
    let dex: DexFile = parse_dex(bytes).expect("parse the real artifact");
    let string_index: u16 = dex
        .strings
        .iter()
        .position(|value: &String| value == helper)
        .and_then(|index: usize| u16::try_from(index).ok())
        .expect("the real artifact carries the helper name in its string table");
    let instruction_offset: usize = indexed_instruction_offset(&dex, bytes, "mix", 0, |insn| {
        insn.width == 2 && !insn.is_terminator()
    });
    let mut instruction: [u8; 4] = [0; 4];
    instruction[..2].copy_from_slice(&0x001A_u16.to_le_bytes());
    instruction[2..].copy_from_slice(&string_index.to_le_bytes());
    let mut mutated: Vec<u8> = bytes.to_vec();
    mutated
        .get_mut(instruction_offset..instruction_offset.saturating_add(4))
        .expect("the string instruction is in bounds")
        .copy_from_slice(&instruction);
    mutated
}

fn with_second_helper_consumer(bytes: &[u8], consumer: &str, helper: &str) -> Vec<u8> {
    let dex: DexFile = parse_dex(bytes).expect("parse the real artifact");
    let helper_index: u16 = dex
        .method_ids
        .iter()
        .position(|method: &MethodId| method.class == PROGRAM_DESCRIPTOR && method.name == helper)
        .and_then(|index: usize| u16::try_from(index).ok())
        .expect("the real artifact carries the target helper method");
    let index_offset: usize = indexed_instruction_offset(
        &dex,
        bytes,
        consumer,
        2,
        |insn| matches!(insn.op, 0x6E..=0x72 | 0x74..=0x78),
    );
    let mut mutated: Vec<u8> = bytes.to_vec();
    mutated
        .get_mut(index_offset..index_offset.saturating_add(2))
        .expect("the invoke index is in bounds")
        .copy_from_slice(&helper_index.to_le_bytes());
    mutated
}

fn encode_uleb128(mut value: u32) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::with_capacity(5);
    loop {
        let mut byte: u8 = u8::try_from(value & 0x7F).expect("seven bits fit in u8");
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

fn with_private_helpers(bytes: &[u8], helpers: &[&str]) -> Vec<u8> {
    let dex: DexFile = parse_dex(bytes).expect("parse the real artifact");
    let report: CodeItemsReport = parse_code_items(&dex, bytes);
    let mut replacements: Vec<(usize, Vec<u8>)> = Vec::with_capacity(helpers.len());
    for helper in helpers {
        let method: &DexMethodCode = report
            .methods()
            .iter()
            .find(|method: &&DexMethodCode| method.method_name == *helper)
            .expect("the real artifact carries the selected helper");
        assert_eq!(
            method.access_flags & 0x0002,
            0,
            "the real helper starts non-private"
        );
        let encoded_access: Vec<u8> = encode_uleb128(method.access_flags);
        let private_access: Vec<u8> =
            encode_uleb128((method.access_flags & !(0x0001 | 0x0004)) | 0x0002);
        assert_eq!(
            private_access.len(),
            encoded_access.len(),
            "the access mutation must preserve class-data layout"
        );
        let mut needle: Vec<u8> = encoded_access;
        needle.extend(encode_uleb128(method.code_offset));
        let matches: Vec<usize> = bytes
            .windows(needle.len())
            .enumerate()
            .filter(|(_, window): &(usize, &[u8])| *window == needle)
            .map(|(offset, _): (usize, &[u8])| offset)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "the helper access and code-offset encoding must be unique in the real artifact"
        );
        replacements.push((
            *matches.first().expect("the access encoding exists"),
            private_access,
        ));
    }
    let mut mutated: Vec<u8> = bytes.to_vec();
    for (offset, replacement) in replacements {
        mutated
            .get_mut(offset..offset.saturating_add(replacement.len()))
            .expect("the helper access encoding is in bounds")
            .copy_from_slice(&replacement);
    }
    mutated
}

fn compile_release_eight(javac: &Path, label: &str, unit: &str, source: &str) -> ScratchDir {
    let scratch: ScratchDir = ScratchDir::create(label).expect("create a Java scratch directory");
    let path: PathBuf = scratch.path().join(unit);
    std::fs::write(&path, source).expect("write the Java compilation unit");
    let classes: PathBuf = scratch.path().join("classes");
    std::fs::create_dir_all(&classes).expect("create the class output directory");
    let compiled: Output = Command::new(javac)
        .arg("-Xlint:-options")
        .arg("--release")
        .arg("8")
        .arg("-d")
        .arg(&classes)
        .arg(&path)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "javac rejected {label}:\n{}\n----\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    scratch
}

fn normalized_methods(
    javap: &Path,
    scratch: &ScratchDir,
    class: &str,
) -> BTreeMap<String, Vec<String>> {
    let classes: PathBuf = scratch.path().join("classes");
    let out: Output = Command::new(javap)
        .arg("-c")
        .arg("-p")
        .arg("-cp")
        .arg(&classes)
        .arg(class)
        .output()
        .expect("run javap");
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "javap failed for {class}; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: BTreeMap<String, Vec<String>> = parse_javap(&stdout);
    assert!(
        !parsed.is_empty(),
        "javap produced no bytecode for {class}; stdout:\n{stdout}"
    );
    parsed
}

fn parse_javap(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for line in text.lines() {
        let trimmed: &str = line.trim();
        if trimmed.ends_with(");") && trimmed.contains('(') {
            if let Some((name, code)) = current.take() {
                found.insert(name, code);
            }
            current = javap_signature_key(trimmed).map(|key: String| (key, Vec::new()));
            continue;
        }
        let Some((_, code)): Option<&mut (String, Vec<String>)> = current.as_mut() else {
            continue;
        };
        let Some((offset, rest)): Option<(&str, &str)> = trimmed.split_once(':') else {
            continue;
        };
        if offset.parse::<u32>().is_err() {
            continue;
        }
        code.push(normalized_instruction(rest));
    }
    if let Some((name, code)) = current.take() {
        found.insert(name, code);
    }
    found
}

fn javap_signature_key(line: &str) -> Option<String> {
    let head: &str = line.trim_end_matches(';');
    let open: usize = head.find('(')?;
    let name: &str = head.get(..open)?.rsplit([' ', '\t']).next()?;
    Some(format!("{name}{}", head.get(open..)?))
}

fn normalized_instruction(rest: &str) -> String {
    let mnemonic: &str = rest.split("//").next().unwrap_or(rest).trim();
    let mut parts: Vec<&str> = mnemonic.split_whitespace().collect();
    parts.retain(|part: &&str| !part.starts_with('#'));
    let comment: String = rest
        .split_once("//")
        .map(|(_, tail): (&str, &str)| tail.trim().to_owned())
        .unwrap_or_default();
    let comment: String = match comment.split_once(':') {
        Some((head, tail)) if head.starts_with("InvokeDynamic #") => {
            format!("InvokeDynamic {tail}")
        }
        _ => comment,
    };
    format!("{} {comment}", parts.join(" "))
}

fn access_widened(authored: &[String]) -> Vec<String> {
    authored
        .iter()
        .map(|line: &String| {
            line.replace("invokespecial Method scale:", "invokevirtual Method scale:")
        })
        .collect()
}

#[test]
fn the_fixture_carries_the_declared_d8_and_r8_helper_sets() {
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), AUTHORED_SHA256);
    assert_eq!(sha256_hex(D8_DEX), D8_SHA256);
    assert_eq!(sha256_hex(R8_DEX), R8_SHA256);
    assert!(PROVENANCE.contains(AUTHORED_SHA256));
    assert!(PROVENANCE.contains(D8_SHA256));
    assert!(PROVENANCE.contains(R8_SHA256));
    assert!(PROVENANCE.contains("version = \"9.1.31\""));
    assert_eq!(D8_DEX.get(..8), Some(b"dex\n035\0".as_slice()));
    assert_eq!(R8_DEX.get(..8), Some(b"dex\n035\0".as_slice()));

    for site in LAMBDA_SITES {
        assert!(
            AUTHORED.contains(&format!(" {site}(")),
            "the authored program must declare the lambda factory {site}"
        );
    }

    let d8: BTreeSet<String> = helper_names_in_artifact(D8_DEX, PROGRAM_DESCRIPTOR);
    assert_eq!(
        d8,
        D8_HELPERS
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<String>>(),
        "the D8 artifact must carry one lambda body helper per authored lambda"
    );

    let r8: BTreeSet<String> = helper_names_in_artifact(R8_DEX, PROGRAM_DESCRIPTOR);
    assert_eq!(
        r8,
        R8_HELPERS
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<String>>(),
        "the R8 artifact must carry one renamed lambda body helper per authored lambda"
    );
    assert!(
        r8.iter().any(|name: &String| name.contains('-')),
        "at least one R8 helper name must sit outside the Java identifier grammar: {r8:?}"
    );

    let dex: DexFile = parse_dex(D8_DEX).expect("parse the real D8 artifact");
    assert_eq!(
        dex.call_site_ids_size, 0,
        "D8 must have desugared every invokedynamic away"
    );
    assert!(
        dex.strings
            .iter()
            .any(|value: &String| value.contains("~~D8{") && value.contains("\"min-api\":21")),
        "the artifact must carry its own D8 marker"
    );
}

#[test]
fn every_private_inlined_lambda_helper_is_elided_from_the_recovered_unit() {
    for (label, bytes, helpers) in [
        ("D8", D8_DEX, D8_HELPERS.as_slice()),
        ("R8", R8_DEX, R8_HELPERS.as_slice()),
    ] {
        let private: Vec<u8> = with_private_helpers(bytes, helpers);
        let unit: String = recovered_unit(&private, PROGRAM_UNIT);
        let declared: BTreeSet<String> = declared_method_names(&unit);
        let residual: Vec<&str> = helpers
            .iter()
            .copied()
            .filter(|helper: &&str| declared.contains(*helper))
            .collect();
        assert!(
            residual.is_empty(),
            "{label}: a private lambda helper whose one reference the recovery inlined must not stay \
             declared, still declared: {residual:?}\n{unit}"
        );
        for helper in helpers {
            assert!(
                !unit.contains(helper),
                "{label}: no recovered source may still name the lambda helper {helper}\n{unit}"
            );
        }
        for site in LAMBDA_SITES {
            assert!(
                declared.contains(site),
                "{label}: the recovered unit must still declare the authored factory {site}"
            );
        }
        assert_eq!(
            unit.matches(" -> ").count(),
            LAMBDA_SITES.len(),
            "{label}: the recovered unit must carry one arrow per authored lambda\n{unit}"
        );
        eprintln!(
            "{label} lambda helper elision: {}/{} toolchain helper methods elided from \
             {PROGRAM_UNIT}, graded against tests/fixtures/d8_lambda_elision/ElisionProbe.java",
            helpers.len(),
            helpers.len()
        );
    }
}

#[test]
fn a_helper_the_recovery_cannot_inline_keeps_its_declaration() {
    let private: Vec<u8> = with_private_helpers(DUPLICATION_DEX, DUPLICATION_HELPERS.as_slice());
    let unit: String = recovered_unit(&private, DUPLICATION_UNIT);
    let declared: BTreeSet<String> = declared_method_names(&unit);
    let retained: Vec<&str> = DUPLICATION_HELPERS
        .into_iter()
        .filter(|helper: &&str| declared.contains(*helper))
        .collect();
    assert_eq!(
        retained,
        vec![DUPLICATION_RETAINED],
        "the helper whose result is read twice must keep its declaration because the recovery \
         still calls it, and the helper that inlined must be elided\n{unit}"
    );
    assert!(
        unit.contains(&format!("DuplicatingLambdaProbe.{DUPLICATION_RETAINED}(")),
        "the retained helper must still be reached from the recovered lambda\n{unit}"
    );
    eprintln!(
        "reference-counted elision: {}/{} toolchain helper methods elided from \
         {DUPLICATION_UNIT}, the remaining one is still called by a recovered lambda",
        DUPLICATION_HELPERS.len().saturating_sub(retained.len()),
        DUPLICATION_HELPERS.len()
    );
}

#[test]
fn a_helper_named_by_a_string_instruction_keeps_its_declaration() {
    let helper: &str = D8_HELPERS
        .first()
        .expect("the fixture declares a D8 helper");
    let private: Vec<u8> = with_private_helpers(D8_DEX, &[helper]);
    let bytes: Vec<u8> = with_helper_name_string_reference(&private, helper);
    let dex: DexFile = parse_dex(&bytes).expect("parse the mutated real D8 artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, &bytes);
    let unit: &String = recovered
        .sources
        .get(PROGRAM_UNIT)
        .expect("recover the authored compilation unit");
    assert!(
        declared_method_names(unit).contains(helper),
        "a helper name loaded by const-string may be used through reflection and must remain declared\n{unit}"
    );
}

#[test]
fn a_helper_reached_by_a_second_consumer_keeps_its_declaration() {
    let helper: &str = "lambda$stateless$0";
    let private: Vec<u8> = with_private_helpers(D8_DEX, &[helper]);
    let bytes: Vec<u8> = with_second_helper_consumer(&private, "lambda$oneCapture$0", helper);
    let dex: DexFile = parse_dex(&bytes).expect("parse the mutated real D8 artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, &bytes);
    let unit: &String = recovered
        .sources
        .get(PROGRAM_UNIT)
        .expect("recover the authored compilation unit");
    assert!(
        declared_method_names(unit).contains(helper),
        "a helper reached by two invoke instructions is shared and must remain declared\n{unit}"
    );
    assert!(
        unit.contains(&format!("ElisionProbe.{helper}(")),
        "the recovered stateless lambda must keep its call to the shared helper\n{unit}"
    );
}

#[test]
fn a_non_private_synthetic_helper_keeps_its_declaration() {
    let helper: &str = "lambda$stateless$0";
    let dex: DexFile = parse_dex(D8_DEX).expect("parse the real D8 artifact");
    let report: CodeItemsReport = parse_code_items(&dex, D8_DEX);
    let method: &DexMethodCode = report
        .methods()
        .iter()
        .find(|method: &&DexMethodCode| {
            method.class == PROGRAM_DESCRIPTOR && method.method_name == helper
        })
        .expect("the real artifact carries the helper declaration");
    assert_eq!(method.access_flags & 0x0002, 0, "the helper is not private");
    assert_ne!(
        method.access_flags & 0x1000,
        0,
        "the helper remains synthetic"
    );
    let recovered: DecompiledDex = decompile_dex(&dex, D8_DEX);
    let unit: &String = recovered
        .sources
        .get(PROGRAM_UNIT)
        .expect("recover the authored compilation unit");
    assert!(
        declared_method_names(unit).contains(helper),
        "a non-private helper can be reached outside the recovered call graph and must remain declared\n{unit}"
    );
    assert!(
        unit.contains("return p0 -> ((p0 * 3) + 1);"),
        "the non-private helper body may still inline even though its declaration remains\n{unit}"
    );
}

#[test]
fn retained_non_private_helpers_recompile_with_every_authored_factory() {
    let (javac, javap): (PathBuf, PathBuf) = require_jdk_tools();
    for (label, bytes) in [("D8", D8_DEX), ("R8", R8_DEX)] {
        let source: String = recovered_unit(bytes, PROGRAM_UNIT);
        let scratch: ScratchDir = compile_release_eight(
            &javac,
            &format!("retained-non-private-{label}"),
            PROGRAM_UNIT,
            &source,
        );
        let methods: BTreeMap<String, Vec<String>> =
            normalized_methods(&javap, &scratch, PROGRAM_CLASS);
        for factory in LAMBDA_SITES {
            assert!(
                methods.keys().any(|name: &String| {
                    name.strip_prefix(factory)
                        .is_some_and(|suffix: &str| suffix.starts_with('('))
                }),
                "{label}: retaining non-private helpers must preserve the authored factory {factory}"
            );
        }
    }
}

#[test]
fn private_helper_elision_recompiles_to_the_authored_bytecode() {
    let (javac, javap): (PathBuf, PathBuf) = require_jdk_tools();
    let authored_scratch: ScratchDir =
        compile_release_eight(&javac, "elision-authored", PROGRAM_UNIT, AUTHORED);
    let authored: BTreeMap<String, Vec<String>> =
        normalized_methods(&javap, &authored_scratch, PROGRAM_CLASS);
    assert_eq!(
        authored.len(),
        GRADED_METHODS,
        "the authored class must carry the graded method population: {:?}",
        authored.keys().collect::<Vec<&String>>()
    );

    for (label, bytes, helpers) in [
        ("D8", D8_DEX, D8_HELPERS.as_slice()),
        ("R8", R8_DEX, R8_HELPERS.as_slice()),
    ] {
        let private: Vec<u8> = with_private_helpers(bytes, helpers);
        let source: String = recovered_unit(&private, PROGRAM_UNIT);
        let scratch: ScratchDir = compile_release_eight(
            &javac,
            &format!("elision-recovered-{label}"),
            PROGRAM_UNIT,
            &source,
        );
        let recovered: BTreeMap<String, Vec<String>> =
            normalized_methods(&javap, &scratch, PROGRAM_CLASS);
        assert_eq!(
            recovered.keys().collect::<Vec<&String>>(),
            authored.keys().collect::<Vec<&String>>(),
            "{label}: recompiling the recovered unit must reproduce the authored method set, so \
             javac has regenerated one lambda body method per recovered lambda\n{source}"
        );

        let mut identical: usize = 0;
        for (name, code) in &authored {
            let other: &Vec<String> = recovered.get(name).expect("a graded method");
            if other == code {
                identical = identical.saturating_add(1);
                continue;
            }
            assert!(
                ACCESS_WIDENED_METHODS.contains(&name.as_str()),
                "{label}: {name} must recompile to the authored bytecode\n  authored: \
                 {code:?}\n  recovered: {other:?}"
            );
            assert_eq!(
                other,
                &access_widened(code),
                "{label}: {name} may differ from the authored bytecode only where the recovered \
                 unit widens a private member to public, which turns invokespecial into \
                 invokevirtual"
            );
        }
        assert_eq!(
            identical, IDENTICAL_METHODS,
            "{label}: the byte-identical method count must hold"
        );
        eprintln!(
            "{label} lambda recompilation: {identical}/{GRADED_METHODS} methods of \
             {PROGRAM_CLASS} recompile to bytecode identical with the authored program under \
             javac --release 8; the remaining {} differ only in invokespecial against \
             invokevirtual on a member the recovery widens from private to public",
            GRADED_METHODS.saturating_sub(identical)
        );
    }
}

#[test]
fn javap_reading_fails_closed_when_the_tool_rejects_its_arguments() {
    let (javac, _javap): (PathBuf, PathBuf) = require_jdk_tools();
    let scratch: ScratchDir =
        compile_release_eight(&javac, "elision-failclosed", PROGRAM_UNIT, AUTHORED);
    let missing: PathBuf = PathBuf::from(std::env::args().next().expect("test binary path"));
    let outcome: std::thread::Result<BTreeMap<String, Vec<String>>> =
        std::panic::catch_unwind(|| normalized_methods(&missing, &scratch, PROGRAM_CLASS));
    assert!(
        outcome.is_err(),
        "a failing javap process must fail this gate rather than return an empty comparison"
    );
}
