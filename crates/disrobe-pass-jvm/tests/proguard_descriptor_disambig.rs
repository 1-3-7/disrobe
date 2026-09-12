#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_jvm::{
    AppliedNames, ClassFile, ClassMapping, FieldMapping, JarExtract, MethodMapping,
    ProguardMapping, apply_proguard_mapping, extract_jar, parse_classfile, parse_proguard_mapping,
    remap_proguard_descriptor, source_params_to_descriptor, source_type_to_descriptor,
};

const HELLO_OBF_JAR: &[u8] = include_bytes!("../../../corpus/jvm/proguard/Hello-obf.jar");
const HELLO_MAPPING: &str = include_str!("../../../corpus/jvm/proguard/mapping.txt");
const EDGECASES_PG_JAR: &[u8] = include_bytes!("../../../corpus/jvm/proguard/EdgeCases-pg.jar");
const EDGECASES_PG_MAPPING: &str =
    include_str!("../../../corpus/jvm/proguard/EdgeCases-mapping.txt");
const HELLO_R8_JAR: &[u8] = include_bytes!("../../../corpus/jvm/r8/Hello-r8.jar");
const HELLO_R8_MAPPING: &str = include_str!("../../../corpus/jvm/r8/mapping.txt");

fn obf_class(jar: &[u8], entry: &str) -> ClassFile {
    let jx: JarExtract = extract_jar(jar).expect("extract corpus jar");
    let bytes: &Vec<u8> = jx.classes.get(entry).unwrap_or_else(|| panic!("{entry}"));
    parse_classfile(bytes).unwrap_or_else(|e| panic!("parse {entry}: {e}"))
}

#[test]
fn two_real_fields_obfuscated_to_same_letter_split_by_descriptor() {
    let cf: ClassFile = obf_class(HELLO_OBF_JAR, "Hello.class");
    let int_a: usize = cf
        .fields
        .iter()
        .filter(|f| {
            cf.utf8_at(f.name_index).ok() == Some("a")
                && cf.utf8_at(f.descriptor_index).ok() == Some("I")
        })
        .count();
    let str_a: usize = cf
        .fields
        .iter()
        .filter(|f| {
            cf.utf8_at(f.name_index).ok() == Some("a")
                && cf.utf8_at(f.descriptor_index).ok() == Some("Ljava/lang/String;")
        })
        .count();
    assert_eq!(int_a, 1, "expected one int field named 'a' in the real jar");
    assert_eq!(
        str_a, 1,
        "expected one String field named 'a' in the real jar"
    );

    let mapping: ProguardMapping = parse_proguard_mapping(HELLO_MAPPING).expect("mapping");
    let applied: AppliedNames = apply_proguard_mapping(&mapping, &cf);
    assert_eq!(
        applied.fields.get("a:I").map(String::as_str),
        Some("counter"),
        "int 'a' must restore to counter, fields={:?}",
        applied.fields
    );
    assert_eq!(
        applied
            .fields
            .get("a:Ljava/lang/String;")
            .map(String::as_str),
        Some("name"),
        "String 'a' must restore to name, fields={:?}",
        applied.fields
    );
}

#[test]
fn overloads_collapsed_to_one_letter_resolve_by_full_descriptor() {
    let cf: ClassFile = obf_class(EDGECASES_PG_JAR, "EdgeCases.class");
    let mapping: ProguardMapping =
        parse_proguard_mapping(EDGECASES_PG_MAPPING).expect("edgecases mapping");

    let cls: &ClassMapping = mapping
        .lookup_obfuscated_class("EdgeCases")
        .expect("EdgeCases entry");
    let a_overloads: &Vec<MethodMapping> =
        cls.methods.get("a").expect("obf method 'a' has overloads");
    assert!(
        a_overloads.len() >= 8,
        "real EdgeCases collapses many methods onto 'a', saw {}",
        a_overloads.len()
    );

    let applied: AppliedNames = apply_proguard_mapping(&mapping, &cf);

    assert_eq!(
        applied.methods.get("a(I)I").map(String::as_str),
        Some("recursiveFactorial"),
        "the int->int overload of 'a' must be recursiveFactorial, not the first 1-arg method"
    );
    assert_eq!(
        applied
            .methods
            .get("a(Ljava/lang/String;)Ljava/lang/String;")
            .map(String::as_str),
        Some("multiCatch"),
        "the String->String overload of 'a' must be multiCatch"
    );
    assert_eq!(
        applied
            .methods
            .get("a(Ljava/lang/Object;)Ljava/lang/Object;")
            .map(String::as_str),
        Some("classify"),
        "the Object->Object overload of 'a' must be classify"
    );
    assert_eq!(
        applied.methods.get("a([D)D").map(String::as_str),
        Some("mean"),
        "the double[]->double overload of 'a' must be mean"
    );
    assert_eq!(
        applied
            .methods
            .get("a(Ljava/lang/Number;Ljava/lang/Number;)Ljava/lang/Number;")
            .map(String::as_str),
        Some("arithmeticPoly"),
        "the two-arg Number overload of 'a' must be arithmeticPoly"
    );

    let names: std::collections::BTreeSet<&str> =
        applied.methods.values().map(String::as_str).collect();
    assert!(names.contains("recursiveFactorial"));
    assert!(names.contains("multiCatch"));
    assert!(names.contains("classify"));
    assert!(
        names.len() >= 5,
        "descriptor disambiguation must recover several distinct originals, got {names:?}"
    );
}

#[test]
fn inline_residual_frames_do_not_become_phantom_methods() {
    let mapping: ProguardMapping =
        parse_proguard_mapping(EDGECASES_PG_MAPPING).expect("edgecases mapping");
    for cls in mapping.classes.values() {
        for overloads in cls.methods.values() {
            for m in overloads {
                assert!(
                    !m.original_name.contains('.'),
                    "method name '{}' in class {} leaked a qualified inline frame",
                    m.original_name,
                    cls.obfuscated_name
                );
            }
        }
    }
}

#[test]
fn r8_field_restores_and_init_resolves_on_real_class() {
    let cf: ClassFile = obf_class(HELLO_R8_JAR, "Hello.class");
    let mapping: ProguardMapping = parse_proguard_mapping(HELLO_R8_MAPPING).expect("r8 mapping");
    let applied: AppliedNames = apply_proguard_mapping(&mapping, &cf);
    assert_eq!(applied.class_name.as_deref(), Some("Hello"));
    assert!(
        applied.fields.values().any(|v| v == "counter"),
        "R8 obfuscated field must restore to counter: {:?}",
        applied.fields
    );
    assert!(
        applied.methods.values().any(|v| v == "main"),
        "main must be recovered: {:?}",
        applied.methods
    );
}

#[test]
fn inheritance_aware_descriptor_remap_uses_real_class_table() {
    let mapping: ProguardMapping =
        parse_proguard_mapping(EDGECASES_PG_MAPPING).expect("edgecases mapping");
    let cls: &ClassMapping = mapping
        .lookup_obfuscated_class("EdgeCases")
        .expect("EdgeCases");
    let obf_super: &str = &cls.obfuscated_name;
    assert_eq!(obf_super, "EdgeCases");

    let pair_obf: &str = mapping
        .lookup_original_class("EdgeCases$Pair")
        .expect("Pair is in mapping");
    let descriptor: String = format!("(L{};)I", pair_obf.replace('.', "/"));
    let remapped: Option<String> = remap_proguard_descriptor(&mapping, &descriptor);
    assert_eq!(
        remapped.as_deref(),
        Some("(LEdgeCases$Pair;)I"),
        "a descriptor referencing the obfuscated Pair class must restore to EdgeCases$Pair"
    );
}

#[test]
fn source_type_conversion_matches_jvm_descriptor_grammar() {
    assert_eq!(source_type_to_descriptor("int"), "I");
    assert_eq!(source_type_to_descriptor("double[]"), "[D");
    assert_eq!(
        source_type_to_descriptor("java.lang.String"),
        "Ljava/lang/String;"
    );
    assert_eq!(
        source_params_to_descriptor("java.lang.Object,int"),
        "Ljava/lang/Object;I"
    );
    let _f: FieldMapping = FieldMapping {
        original_name: "x".into(),
        source_type: "int".into(),
        descriptor_type: "I".into(),
    };
}
