#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_jvm::{ClassFile, JavaVersion, parse_classfile};

const HELLO_CLASS: &[u8] = include_bytes!("../corpus/Hello.class");

#[test]
fn parses_hand_written_minimal_class() {
    let cf: ClassFile = parse_classfile(HELLO_CLASS).expect("parse Hello.class");
    assert_eq!(cf.major_version, 52);
    assert_eq!(cf.version(), Some(JavaVersion::Jse8));
    assert_eq!(cf.this_class_name().expect("this_class"), "Hello");
    let supers: &str = cf.class_name(cf.super_class).expect("super");
    assert_eq!(supers, "java/lang/Object");
}

#[test]
fn rejects_garbage_bytes() {
    let garbage: [u8; 16] = [0u8; 16];
    let err: disrobe_pass_jvm::Error = parse_classfile(&garbage).expect_err("must reject");
    assert!(matches!(err, disrobe_pass_jvm::Error::BadMagic(_)));
}
