#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_jvm::{
    ClassFile, ConstantPoolEntry, Detection, FieldInfo, Protector, WatermarkFinding, detect_all,
    detect_allatori_watermarks,
};

fn class_with_field(name: &str) -> ClassFile {
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    cp.push(ConstantPoolEntry::Utf8(name.to_string()));
    ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cp,
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: vec![FieldInfo {
            access_flags: 0,
            name_index: 1,
            descriptor_index: 1,
            attributes: Vec::new(),
        }],
        methods: Vec::new(),
        attributes: Vec::new(),
    }
}

#[test]
fn detects_allatori_watermark_field() {
    let cf: ClassFile = class_with_field("AllatoriWM_42");
    let f: WatermarkFinding = detect_allatori_watermarks(&cf);
    assert_eq!(f.fields.len(), 1);
}

#[test]
fn allatori_marker_string_triggers_detection() {
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    cp.push(ConstantPoolEntry::Utf8("Allatori 7.4 obfuscator".into()));
    let cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cp,
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: Vec::new(),
        attributes: Vec::new(),
    };
    let d: Vec<Detection> = detect_all(&cf);
    assert!(d.iter().any(|x| x.protector == Protector::Allatori));
}
