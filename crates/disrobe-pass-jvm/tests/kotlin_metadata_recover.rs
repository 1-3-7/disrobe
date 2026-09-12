#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{
    ClassFile, ConstantPoolEntry, KotlinKind, KotlinMetadata, MethodInfo, parse_classfile,
    recover_kotlin_metadata,
};

const GREETER: &[u8] = include_bytes!("../../../corpus/jvm/kotlin/Greeter.class");

#[test]
fn returns_none_for_non_kotlin_class() {
    let cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: vec![ConstantPoolEntry::Placeholder],
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: Vec::new(),
        attributes: Vec::new(),
    };
    let out: Option<KotlinMetadata> = recover_kotlin_metadata(&cf).expect("ok");
    assert!(out.is_none());
}

#[test]
fn recovers_kotlin_metadata_kind_and_versions() {
    let cf: ClassFile = parse_classfile(GREETER).expect("parse kotlinc Greeter.class");
    let meta: KotlinMetadata = recover_kotlin_metadata(&cf)
        .expect("recover ok")
        .expect("Greeter carries a kotlin @Metadata annotation");
    assert_eq!(
        meta.kind,
        KotlinKind::Class,
        "Greeter is a regular class (@Metadata k=1)"
    );
    assert_eq!(
        meta.metadata_version,
        vec![2, 4, 0],
        "kotlinc 2.4.0 stamps metadata_version mv=[2,4,0]"
    );
}

#[test]
fn classfile_carries_real_kotlin_class_and_function_names() {
    let cf: ClassFile = parse_classfile(GREETER).expect("parse kotlinc Greeter.class");
    assert_eq!(
        cf.this_class_name().expect("this_class"),
        "disrobe/sample/Greeter",
        "class name from the real kotlinc output"
    );
    let method_names: Vec<&str> = cf
        .methods
        .iter()
        .filter_map(|m: &MethodInfo| cf.utf8_at(m.name_index).ok())
        .collect::<Vec<&str>>();
    assert!(
        method_names.contains(&"greet"),
        "greet() must be present: {method_names:?}"
    );
    assert!(
        method_names.contains(&"shout"),
        "shout(times) must be present: {method_names:?}"
    );
    assert!(
        method_names.contains(&"getGreeting"),
        "the greeting property getter must be present: {method_names:?}"
    );
}
