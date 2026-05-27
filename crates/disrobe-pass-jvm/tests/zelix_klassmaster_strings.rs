#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_jvm::{
    ClassFile, ConstantPoolEntry, Detection, Protector, StringStrip, detect_all,
    strip_encrypted_strings,
};

fn synth_class_with_strings(strings: &[&str]) -> ClassFile {
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    for s in strings {
        cp.push(ConstantPoolEntry::Utf8((*s).to_string()));
    }
    ClassFile {
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
    }
}

#[test]
fn detects_zkm_marker_string() {
    let cf: ClassFile = synth_class_with_strings(&["produced by ZKM 14.0 KlassMaster"]);
    let detections: Vec<Detection> = detect_all(&cf);
    assert!(
        detections
            .iter()
            .any(|d| d.protector == Protector::ZelixKlassMaster)
    );
}

#[test]
fn strip_returns_non_encrypted_strings() {
    let cf: ClassFile = synth_class_with_strings(&["plain text", "another"]);
    let ss: StringStrip = strip_encrypted_strings(&cf, Protector::ZelixKlassMaster);
    assert_eq!(ss.recovered.len(), 2);
    assert_eq!(ss.residual_encrypted, 0);
}
