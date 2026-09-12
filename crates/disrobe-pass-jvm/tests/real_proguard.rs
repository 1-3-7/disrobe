#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{
    ClassFile, ClassMapping, JarExtract, ProguardMapping, extract_jar, parse_classfile,
    parse_proguard_mapping,
};

const HELLO_BASELINE_JAR: &[u8] = include_bytes!("../../../corpus/jvm/proguard/Hello-baseline.jar");
const HELLO_OBF_JAR: &[u8] = include_bytes!("../../../corpus/jvm/proguard/Hello-obf.jar");
const HELLO_MAPPING: &str = include_str!("../../../corpus/jvm/proguard/mapping.txt");
const EDGECASES_PG_JAR: &[u8] = include_bytes!("../../../corpus/jvm/proguard/EdgeCases-pg.jar");
const EDGECASES_PG_MAPPING: &str =
    include_str!("../../../corpus/jvm/proguard/EdgeCases-mapping.txt");
const EDGECASES_KT_PG_JAR: &[u8] =
    include_bytes!("../../../corpus/jvm/proguard/EdgeCasesKt-pg.jar");
const EDGECASES_KT_PG_MAPPING: &str =
    include_str!("../../../corpus/jvm/proguard/EdgeCasesKt-mapping.txt");

#[test]
fn baseline_hello_jar_extracts_with_javac_manifest() {
    let jx: JarExtract = extract_jar(HELLO_BASELINE_JAR).expect("extract baseline jar");
    assert!(jx.classes.contains_key("Hello.class"));
    assert!(jx.classes.contains_key("Greeter.class"));
    let manifest: &str = jx.manifest.as_deref().expect("manifest");
    assert!(manifest.contains("Manifest-Version: 1.0"));
    assert!(manifest.contains("Main-Class: Hello"));
}

#[test]
fn proguard_hello_obf_jar_keeps_main_class_only() {
    let jx: JarExtract = extract_jar(HELLO_OBF_JAR).expect("extract obf jar");
    assert!(jx.classes.contains_key("Hello.class"));
    assert!(!jx.classes.contains_key("Greeter.class"));
    let hello: &Vec<u8> = jx.classes.get("Hello.class").expect("Hello.class");
    let cf: ClassFile = parse_classfile(hello).expect("parse obf Hello");
    assert_eq!(cf.major_version, 52);
    assert_eq!(cf.this_class_name().expect("this_class"), "Hello");
}

#[test]
fn proguard_hello_mapping_parses_with_inlined_methods() {
    let m: ProguardMapping = parse_proguard_mapping(HELLO_MAPPING).expect("parse mapping");
    let hello: &ClassMapping = m.lookup_obfuscated_class("Hello").expect("Hello -> Hello");
    assert_eq!(hello.original_name, "Hello");
    assert_eq!(hello.fields.get("a").map(String::as_str), Some("name"));
    assert!(hello.methods.contains_key("main"));
}

#[test]
fn proguard_edgecases_jar_loads_and_contains_main_class() {
    let jx: JarExtract = extract_jar(EDGECASES_PG_JAR).expect("extract edgecases jar");
    assert!(jx.classes.contains_key("EdgeCases.class"));
    let edge: &Vec<u8> = jx.classes.get("EdgeCases.class").expect("EdgeCases.class");
    let cf: ClassFile = parse_classfile(edge).expect("parse EdgeCases.class");
    assert!(cf.major_version >= 52);
    assert_eq!(cf.this_class_name().expect("this_class"), "EdgeCases");
}

#[test]
fn proguard_edgecases_mapping_has_record_and_sealed_renames() {
    let m: ProguardMapping = parse_proguard_mapping(EDGECASES_PG_MAPPING).expect("parse mapping");
    assert!(m.classes.len() >= 10);
    assert!(m.lookup_original_class("EdgeCases").is_some());
    assert!(
        m.lookup_original_class("EdgeCases$Circle").is_some(),
        "expected record-class Circle in mapping"
    );
    assert!(
        m.lookup_original_class("EdgeCases$Shape").is_some(),
        "expected sealed-interface Shape in mapping"
    );
    assert!(
        m.lookup_original_class("EdgeCases$Direction").is_some(),
        "expected enum Direction in mapping"
    );
}

#[test]
fn proguard_kotlin_jar_loads_and_keeps_metadata_holders() {
    let jx: JarExtract = extract_jar(EDGECASES_KT_PG_JAR).expect("extract kotlin pg jar");
    let main: &Vec<u8> = jx
        .classes
        .get("EdgeCasesKt.class")
        .expect("EdgeCasesKt.class");
    let cf: ClassFile = parse_classfile(main).expect("parse EdgeCasesKt.class");
    assert!(cf.major_version >= 52);
}

#[test]
fn proguard_kotlin_mapping_contains_data_and_value_classes() {
    let m: ProguardMapping =
        parse_proguard_mapping(EDGECASES_KT_PG_MAPPING).expect("parse mapping");
    assert!(m.classes.len() >= 30);
    assert!(m.lookup_original_class("EdgeCasesKt").is_some());
    assert!(
        m.lookup_original_class("Point").is_some(),
        "expected data class Point in mapping"
    );
    assert!(
        m.lookup_original_class("UserId").is_some(),
        "expected value class UserId in mapping"
    );
}
