#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_jvm::{ClassFile, ConstantPoolEntry, KotlinMetadata, recover_kotlin_metadata};

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
#[ignore = "FIXTURE PENDING: needs a real kotlinc-compiled .class with @Metadata annotation populated"]
fn recovers_kotlin_metadata_kind_and_versions() {
    unreachable!("compile a Kotlin file with kotlinc and commit the .class to corpus/")
}
