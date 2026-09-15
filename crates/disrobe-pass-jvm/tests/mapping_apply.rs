#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::case_sensitive_file_extension_comparisons
)]

use disrobe_pass_jvm::{
    AppliedNames, ClassFile, JarExtract, ProguardMapping, apply_proguard_mapping, extract_jar,
    parse_classfile, parse_proguard_mapping,
};

const HELLO_R8_JAR: &[u8] = include_bytes!("../../../corpus/jvm/r8/Hello-r8.jar");
const HELLO_R8_MAPPING: &str = include_str!("../../../corpus/jvm/r8/mapping.txt");
const HELLO_PG_JAR: &[u8] = include_bytes!("../../../corpus/jvm/proguard/Hello-obf.jar");
const HELLO_PG_MAPPING: &str = include_str!("../../../corpus/jvm/proguard/mapping.txt");

#[test]
fn applies_r8_mapping_to_restore_field_name_on_real_class() {
    let jx: JarExtract = extract_jar(HELLO_R8_JAR).expect("extract");
    let hello: &Vec<u8> = jx.classes.get("Hello.class").expect("Hello.class");
    let cf: ClassFile = parse_classfile(hello).expect("parse");
    let mapping: ProguardMapping = parse_proguard_mapping(HELLO_R8_MAPPING).expect("parse mapping");
    let applied: AppliedNames = apply_proguard_mapping(&mapping, &cf);
    assert_eq!(applied.class_name.as_deref(), Some("Hello"));
    assert!(
        applied.fields.values().any(|v: &String| v == "counter"),
        "expected obfuscated field 'a' restored to 'counter', got {:?}",
        applied.fields
    );
    assert!(applied.restored_count >= 2);
}

#[test]
fn applies_proguard_mapping_end_to_end() {
    let jx: JarExtract = extract_jar(HELLO_PG_JAR).expect("extract pg jar");
    let mapping: ProguardMapping =
        parse_proguard_mapping(HELLO_PG_MAPPING).expect("parse pg mapping");
    let mut total_restored: usize = 0;
    for (name, bytes) in &jx.classes {
        if !name.ends_with(".class") {
            continue;
        }
        let cf: ClassFile = parse_classfile(bytes).unwrap_or_else(|e| panic!("parse {name}: {e}"));
        let applied: AppliedNames = apply_proguard_mapping(&mapping, &cf);
        total_restored += applied.restored_count;
    }
    assert!(
        total_restored > 0,
        "ProGuard mapping apply restored zero names across the obfuscated jar"
    );
}
