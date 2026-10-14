#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use disrobe_pass_jvm::{
    ProguardMapping, SourceRecoveryOptions, extract_jar, parse_proguard_mapping,
    parse_yguard_renamelog, recover_sources,
};
use disrobe_testkit::{MutationKind, mutate};

const RENAMELOG_CASES: u64 = 400;
const MAPPING_CASES: u64 = 200;
const CLASSFILE_CASES: u64 = 120;
const MAX_RENAMELOG_BYTES: usize = 16 * 1024 * 1024;

fn corpus(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("jvm");
    for segment in rel.split('/') {
        path.push(segment);
    }
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn jar_classes(rel: &str) -> Vec<Vec<u8>> {
    extract_jar(&corpus(rel))
        .unwrap_or_else(|error| panic!("extract corpus/jvm/{rel}: {error}"))
        .classes
        .into_values()
        .collect()
}

fn recover_without_unwinding(classes: &[Vec<u8>], mapping: Option<&ProguardMapping>, label: &str) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let _ = recover_sources(classes, SourceRecoveryOptions { mapping });
    }));
    assert!(outcome.is_ok(), "source recovery unwound on {label}");
}

#[test]
fn mutated_yguard_rename_logs_parse_or_refuse_without_unwinding() {
    let original: Vec<u8> = corpus("obfuscators/yguard/renamelog.xml");
    let classes: Vec<Vec<u8>> = jar_classes("obfuscators/yguard/Calculator-obf.jar");
    let mut parsed: usize = 0;
    for seed in 0..RENAMELOG_CASES {
        let (bytes, kind): (Vec<u8>, MutationKind) = mutate(&original, seed);
        let text: String = String::from_utf8_lossy(&bytes).into_owned();
        let outcome = catch_unwind(AssertUnwindSafe(|| parse_yguard_renamelog(&text)));
        let Ok(result) = outcome else {
            panic!("the yGuard rename-log parser unwound on seed {seed} ({kind:?})");
        };
        if let Ok(mapping) = result {
            parsed += 1;
            recover_without_unwinding(&classes, Some(&mapping), &format!("rename-log seed {seed}"));
        }
    }
    assert!(
        parsed > 0,
        "no mutated rename log parsed, so recovery under a hostile map was never exercised"
    );
}

#[test]
fn an_oversized_yguard_rename_log_is_refused_by_name() {
    let mut text: String = String::from("<yguard>");
    text.push_str(&" ".repeat(MAX_RENAMELOG_BYTES));
    let error = parse_yguard_renamelog(&text).expect_err("an oversized log is refused");
    assert!(error.to_string().contains("exceeds 16 MiB"), "{error}");
}

#[test]
fn a_rename_log_with_too_many_entries_is_refused_by_name() {
    let mut text: String = String::from("<yguard>");
    for index in 0..300_000 {
        write!(text, "<class name=\"a.C{index}\" map=\"A\"/>").expect("write to a String");
    }
    let error = parse_yguard_renamelog(&text).expect_err("an entry flood is refused");
    assert!(error.to_string().contains("too many entries"), "{error}");
}

#[test]
fn mutated_proguard_mappings_never_unwind_source_recovery() {
    let original: Vec<u8> = corpus("proguard/real/Calculator.aggressive.mapping.txt");
    let classes: Vec<Vec<u8>> = jar_classes("proguard/real/Calculator.aggressive.jar");
    let mut parsed: usize = 0;
    for seed in 0..MAPPING_CASES {
        let (bytes, kind): (Vec<u8>, MutationKind) = mutate(&original, seed);
        let text: String = String::from_utf8_lossy(&bytes).into_owned();
        let outcome = catch_unwind(AssertUnwindSafe(|| parse_proguard_mapping(&text)));
        let Ok(result) = outcome else {
            panic!("the ProGuard mapping parser unwound on seed {seed} ({kind:?})");
        };
        if let Ok(mapping) = result {
            parsed += 1;
            recover_without_unwinding(&classes, Some(&mapping), &format!("mapping seed {seed}"));
        }
    }
    assert!(
        parsed > 0,
        "no mutated mapping parsed, so the rename path was never exercised"
    );
}

#[test]
fn mutated_obfuscated_classes_never_unwind_source_recovery() {
    let mapping: ProguardMapping = parse_proguard_mapping(
        &String::from_utf8(corpus("proguard/real/Sample.aggressive.mapping.txt")).expect("utf-8"),
    )
    .expect("parse mapping");
    let surfaces: [&str; 3] = [
        "proguard/real/Sample.aggressive.jar",
        "obfuscators/skidfuscator/real/Sample.skidfuscator.jar",
        "obfuscators/jbco/real/Sample.flow.jar",
    ];
    for surface in surfaces {
        let classes: Vec<Vec<u8>> = jar_classes(surface);
        for seed in 0..CLASSFILE_CASES {
            let mut mutated: Vec<Vec<u8>> = classes.clone();
            let target: usize = usize::try_from(seed).expect("seed fits") % mutated.len();
            let (bytes, _): (Vec<u8>, MutationKind) = mutate(&mutated[target], seed);
            mutated[target] = bytes;
            recover_without_unwinding(&mutated, Some(&mapping), &format!("{surface} seed {seed}"));
            recover_without_unwinding(&mutated, None, &format!("{surface} seed {seed} unmapped"));
        }
    }
}

#[test]
fn a_duplicated_class_is_refused_by_name() {
    let mut classes: Vec<Vec<u8>> = jar_classes("proguard/real/Sample.rename.jar");
    let first: Vec<u8> = classes[0].clone();
    classes.push(first);
    let error = recover_sources(&classes, SourceRecoveryOptions::default())
        .expect_err("a duplicate class is refused");
    assert!(error.to_string().contains("duplicate class"), "{error}");
}
