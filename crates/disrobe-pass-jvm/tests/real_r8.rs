#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{
    ClassFile, ClassMapping, JarExtract, ProguardMapping, extract_jar, parse_classfile,
    parse_proguard_mapping,
};

const HELLO_R8_JAR: &[u8] = include_bytes!("../../../corpus/jvm/r8/Hello-r8.jar");
const HELLO_R8_MAPPING: &str = include_str!("../../../corpus/jvm/r8/mapping.txt");
const EDGECASES_R8_JAR: &[u8] = include_bytes!("../../../corpus/jvm/r8/EdgeCases-r8.jar");
const EDGECASES_R8_MAPPING: &str = include_str!("../../../corpus/jvm/r8/EdgeCases-mapping.txt");
const EDGECASES_KT_R8_JAR: &[u8] = include_bytes!("../../../corpus/jvm/r8/EdgeCasesKt-r8.jar");
const EDGECASES_KT_R8_MAPPING: &str =
    include_str!("../../../corpus/jvm/r8/EdgeCasesKt-mapping.txt");

#[test]
fn r8_hello_jar_keeps_main_class_only() {
    let jx: JarExtract = extract_jar(HELLO_R8_JAR).expect("extract r8 jar");
    assert!(jx.classes.contains_key("Hello.class"));
    let hello: &Vec<u8> = jx.classes.get("Hello.class").expect("Hello.class");
    let cf: ClassFile = parse_classfile(hello).expect("parse r8 Hello");
    assert!(cf.major_version >= 52);
    assert_eq!(cf.this_class_name().expect("this_class"), "Hello");
}

#[test]
fn r8_hello_mapping_carries_compiler_banner() {
    let m: ProguardMapping = parse_proguard_mapping(HELLO_R8_MAPPING).expect("parse r8 mapping");
    assert!(HELLO_R8_MAPPING.contains("compiler: R8"));
    assert!(HELLO_R8_MAPPING.contains("com.android.tools.r8.mapping"));
    let hello: &ClassMapping = m.lookup_obfuscated_class("Hello").expect("Hello -> Hello");
    assert_eq!(hello.original_name, "Hello");
    assert!(hello.fields.contains_key("a"));
}

#[test]
fn r8_edgecases_jar_contains_obfuscated_single_letter_classes() {
    let jx: JarExtract = extract_jar(EDGECASES_R8_JAR).expect("extract r8 edgecases");
    let single_letter: usize = jx
        .classes
        .keys()
        .filter(|k: &&String| {
            let stem: &str = k.trim_end_matches(".class");
            stem.len() == 1 && stem.chars().all(|c: char| c.is_ascii_lowercase())
        })
        .count();
    assert!(
        single_letter >= 5,
        "expected several single-letter classes after R8 repackaging, saw {single_letter}"
    );
    assert!(jx.classes.contains_key("EdgeCases.class"));
}

#[test]
fn r8_edgecases_mapping_has_residual_signature_metadata() {
    let m: ProguardMapping =
        parse_proguard_mapping(EDGECASES_R8_MAPPING).expect("parse r8 edgecases mapping");
    assert!(EDGECASES_R8_MAPPING.contains("compiler_version: 9."));
    assert!(EDGECASES_R8_MAPPING.contains("residualsignature"));
    assert!(m.lookup_original_class("EdgeCases").is_some());
    assert!(m.lookup_original_class("EdgeCases$Shape").is_some());
}

#[test]
fn r8_kotlin_jar_loads_obfuscated_classes() {
    let jx: JarExtract = extract_jar(EDGECASES_KT_R8_JAR).expect("extract r8 kotlin jar");
    assert!(jx.classes.contains_key("EdgeCasesKt.class"));
    assert!(jx.classes.len() >= 5);
}

#[test]
fn r8_kotlin_mapping_carries_compiler_banner() {
    let m: ProguardMapping =
        parse_proguard_mapping(EDGECASES_KT_R8_MAPPING).expect("parse r8 kotlin mapping");
    assert!(EDGECASES_KT_R8_MAPPING.contains("compiler: R8"));
    assert!(m.lookup_original_class("EdgeCasesKt").is_some());
}
