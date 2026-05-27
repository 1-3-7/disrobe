#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_jvm::{ClassMapping, ProguardMapping, parse_proguard_mapping};

const MAPPING_TEXT: &str = include_str!("../corpus/proguard_minimal.map");

#[test]
fn parses_two_classes_with_members() {
    let m: ProguardMapping = parse_proguard_mapping(MAPPING_TEXT).expect("parse mapping");
    assert_eq!(m.classes.len(), 2);
    let foo: &ClassMapping = m
        .lookup_obfuscated_class("a.a")
        .expect("a.a -> com.example.Foo");
    assert_eq!(foo.original_name, "com.example.Foo");
    assert_eq!(foo.fields.get("a").map(String::as_str), Some("counter"));
    assert_eq!(foo.fields.get("b").map(String::as_str), Some("name"));
    assert!(foo.methods.contains_key("c"));
    assert!(foo.methods.contains_key("d"));
}

#[test]
fn lookup_by_original_round_trips() {
    let m: ProguardMapping = parse_proguard_mapping(MAPPING_TEXT).expect("parse");
    let obf: &str = m
        .lookup_original_class("com.example.Bar")
        .expect("Bar -> a.b");
    assert_eq!(obf, "a.b");
}
