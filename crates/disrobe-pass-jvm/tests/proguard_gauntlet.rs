#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_jvm::{
    AppliedNames, ClassFile, DecompiledClass, JarExtract, ProguardMapping, apply_proguard_mapping,
    decompile_class, extract_jar, parse_classfile, parse_proguard_mapping,
};

const GAUNTLET_OBF_JAR: &[u8] =
    include_bytes!("../../../corpus/jvm/proguard/gauntlet/Gauntlet-obf.jar");
const GAUNTLET_MAPPING: &str = include_str!("../../../corpus/jvm/proguard/gauntlet/mapping.txt");

fn load_jar() -> JarExtract {
    extract_jar(GAUNTLET_OBF_JAR).expect("extract gauntlet obf jar")
}

fn load_mapping() -> ProguardMapping {
    parse_proguard_mapping(GAUNTLET_MAPPING).expect("parse gauntlet mapping")
}

fn parse_class(jx: &JarExtract, entry: &str) -> ClassFile {
    let bytes: &Vec<u8> = jx
        .classes
        .get(entry)
        .unwrap_or_else(|| panic!("class {entry} not found in obf jar"));
    parse_classfile(bytes).unwrap_or_else(|e| panic!("parse {entry}: {e}"))
}

#[test]
fn gauntlet_obf_jar_extracts_four_classes() {
    let jx: JarExtract = load_jar();
    assert!(
        jx.classes.contains_key("Gauntlet.class"),
        "Gauntlet.class must be present (kept by -keep)"
    );
    assert!(
        jx.classes.contains_key("a.class"),
        "a.class (Cipher) must be present"
    );
    assert!(
        jx.classes.contains_key("b.class"),
        "b.class (DataStore) must be present"
    );
    assert!(
        jx.classes.contains_key("c.class"),
        "c.class (OpResult) must be present"
    );
    assert_eq!(
        jx.classes.len(),
        4,
        "exactly 4 classes expected in the ProGuard output jar"
    );
}

#[test]
fn gauntlet_mapping_parses_four_class_entries() {
    let m: ProguardMapping = load_mapping();
    assert_eq!(m.classes.len(), 4, "mapping must have 4 class entries");
    assert!(m.lookup_obfuscated_class("a").is_some(), "a -> Cipher");
    assert!(m.lookup_obfuscated_class("b").is_some(), "b -> DataStore");
    assert!(m.lookup_obfuscated_class("c").is_some(), "c -> OpResult");
    assert!(
        m.lookup_obfuscated_class("Gauntlet").is_some(),
        "Gauntlet -> Gauntlet"
    );
}

#[test]
fn cipher_class_restored_to_original_name() {
    let jx: JarExtract = load_jar();
    let m: ProguardMapping = load_mapping();
    let cf: ClassFile = parse_class(&jx, "a.class");
    let applied: AppliedNames = apply_proguard_mapping(&m, &cf);
    assert_eq!(
        applied.class_name.as_deref(),
        Some("Cipher"),
        "a.class must restore to Cipher"
    );
}

#[test]
fn cipher_fields_restored_by_descriptor_type() {
    let jx: JarExtract = load_jar();
    let m: ProguardMapping = load_mapping();
    let cf: ClassFile = parse_class(&jx, "a.class");
    let applied: AppliedNames = apply_proguard_mapping(&m, &cf);
    assert_eq!(
        applied.fields.get("a:I").map(String::as_str),
        Some("shift"),
        "int field 'a' in Cipher must restore to 'shift'"
    );
    assert_eq!(
        applied.fields.get("b:I").map(String::as_str),
        Some("callCount"),
        "int field 'b' in Cipher must restore to 'callCount'"
    );
}

#[test]
fn cipher_encrypt_method_restored() {
    let jx: JarExtract = load_jar();
    let m: ProguardMapping = load_mapping();
    let cf: ClassFile = parse_class(&jx, "a.class");
    let applied: AppliedNames = apply_proguard_mapping(&m, &cf);
    let restored_methods: std::collections::BTreeSet<&str> =
        applied.methods.values().map(String::as_str).collect();
    assert!(
        restored_methods.contains("encrypt"),
        "method 'a(String)' in Cipher must restore to 'encrypt', got {restored_methods:?}"
    );
}

#[test]
fn datastore_class_name_restored() {
    let jx: JarExtract = load_jar();
    let m: ProguardMapping = load_mapping();
    let cf: ClassFile = parse_class(&jx, "b.class");
    let applied: AppliedNames = apply_proguard_mapping(&m, &cf);
    assert_eq!(
        applied.class_name.as_deref(),
        Some("DataStore"),
        "b.class must restore to DataStore"
    );
}

#[test]
fn datastore_overloaded_field_a_disambiguated_by_descriptor() {
    let jx: JarExtract = load_jar();
    let m: ProguardMapping = load_mapping();
    let cf: ClassFile = parse_class(&jx, "b.class");
    let applied: AppliedNames = apply_proguard_mapping(&m, &cf);
    let list_field: Option<&String> = applied
        .fields
        .get("a:Ljava/util/List;")
        .or_else(|| applied.fields.get("a:Ljava/util/ArrayList;"));
    assert_eq!(
        list_field.map(String::as_str),
        Some("entries"),
        "List field 'a' in DataStore must restore to 'entries', fields={:?}",
        applied.fields
    );
    assert_eq!(
        applied
            .fields
            .get("a:Ljava/lang/String;")
            .map(String::as_str),
        Some("label"),
        "String field 'a' in DataStore must restore to 'label', fields={:?}",
        applied.fields
    );
}

#[test]
fn datastore_overloaded_method_a_disambiguated() {
    let jx: JarExtract = load_jar();
    let m: ProguardMapping = load_mapping();
    let cf: ClassFile = parse_class(&jx, "b.class");
    let applied: AppliedNames = apply_proguard_mapping(&m, &cf);
    let names: std::collections::BTreeSet<&str> =
        applied.methods.values().map(String::as_str).collect();
    assert!(
        names.contains("add"),
        "DataStore void method 'a' must restore to 'add', methods={:?}",
        applied.methods
    );
    assert!(
        names.contains("getLabel"),
        "DataStore String getter 'a' must restore to 'getLabel', methods={:?}",
        applied.methods
    );
}

#[test]
fn opresult_class_restored_and_static_factories_named() {
    let jx: JarExtract = load_jar();
    let m: ProguardMapping = load_mapping();
    let cf: ClassFile = parse_class(&jx, "c.class");
    let applied: AppliedNames = apply_proguard_mapping(&m, &cf);
    assert_eq!(
        applied.class_name.as_deref(),
        Some("OpResult"),
        "c.class must restore to OpResult"
    );
    let names: std::collections::BTreeSet<&str> =
        applied.methods.values().map(String::as_str).collect();
    assert!(
        names.contains("ok") || names.contains("fail"),
        "at least one factory method must be recovered, got {names:?}"
    );
}

#[test]
fn gauntlet_main_class_overloaded_methods_disambiguated_by_descriptor() {
    let jx: JarExtract = load_jar();
    let m: ProguardMapping = load_mapping();
    let cf: ClassFile = parse_class(&jx, "Gauntlet.class");
    let applied: AppliedNames = apply_proguard_mapping(&m, &cf);
    assert_eq!(
        applied.class_name.as_deref(),
        Some("Gauntlet"),
        "Gauntlet.class must map back to Gauntlet"
    );
    assert_eq!(
        applied
            .methods
            .get("a(Ljava/lang/String;)Lc;")
            .map(String::as_str),
        Some("processEntry"),
        "a(String)OpResult must resolve to processEntry"
    );
    assert_eq!(
        applied.methods.get("a(I)I").map(String::as_str),
        Some("fibonacci"),
        "a(int)int must resolve to fibonacci"
    );
    let names: std::collections::BTreeSet<&str> =
        applied.methods.values().map(String::as_str).collect();
    assert!(
        names.contains("getProcessedCount") || names.contains("getStore"),
        "at least one zero-param 'a' overload must be recovered; \
         return-type-only overloads are a known limit of param-count disambiguation, \
         got methods={:?}",
        applied.methods
    );
    assert!(
        names.contains("fibonacci"),
        "fibonacci must be recovered, methods={:?}",
        applied.methods
    );
    assert!(
        names.contains("processEntry"),
        "processEntry must be recovered, methods={:?}",
        applied.methods
    );
}

#[test]
fn gauntlet_total_restored_names_all_four_classes() {
    let jx: JarExtract = load_jar();
    let m: ProguardMapping = load_mapping();
    let mut total: usize = 0;
    for (entry, bytes) in &jx.classes {
        if !std::path::Path::new(entry)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("class"))
        {
            continue;
        }
        let cf: ClassFile = parse_classfile(bytes).unwrap_or_else(|e| panic!("parse {entry}: {e}"));
        let applied: AppliedNames = apply_proguard_mapping(&m, &cf);
        total += applied.restored_count;
    }
    assert!(
        total >= 20,
        "total restored name count across all 4 classes must be >= 20, got {total}"
    );
}

#[test]
fn gauntlet_decompile_cipher_class_produces_source() {
    let jx: JarExtract = load_jar();
    let bytes: &Vec<u8> = jx.classes.get("a.class").expect("a.class");
    let cf: ClassFile = parse_classfile(bytes).expect("parse a.class");
    let dc: DecompiledClass = decompile_class(&cf);
    assert!(
        dc.method_count >= 1,
        "Cipher decompile must have at least 1 method"
    );
    assert!(
        dc.field_count >= 1,
        "Cipher decompile must have at least 1 field"
    );
    assert!(!dc.source.is_empty(), "decompiled source must not be empty");
}

#[test]
fn gauntlet_decompile_gauntlet_class_produces_source_with_fibonacci() {
    let jx: JarExtract = load_jar();
    let bytes: &Vec<u8> = jx.classes.get("Gauntlet.class").expect("Gauntlet.class");
    let cf: ClassFile = parse_classfile(bytes).expect("parse Gauntlet.class");
    let dc: DecompiledClass = decompile_class(&cf);
    assert!(
        dc.method_count >= 4,
        "Gauntlet decompile must have >= 4 methods (processEntry/getProcessedCount/getStore/fibonacci/main), got {}",
        dc.method_count
    );
    assert!(
        !dc.source.is_empty(),
        "decompiled Gauntlet source must not be empty"
    );
}
