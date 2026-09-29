#![allow(clippy::expect_used, clippy::unwrap_used, clippy::missing_panics_doc)]

use disrobe_pass_jvm::{
    ClassFile, ConstantPoolEntry, PeelStatus, ProtectorFamilyKind, ProtectorPeelReport,
    allatori_protector,
};

#[test]
fn allatori_peel_without_reachable_decrypt_is_detect_only() {
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    let opaque: &[&str] = &[
        "\u{0001}\u{0091}\u{0014}\u{00b2}\u{0007}\u{00fe}\u{0033}\u{00aa}",
        "\u{0080}\u{0012}\u{00cd}\u{0005}\u{009f}\u{0061}\u{00d3}",
        "\u{0019}\u{00ee}\u{0002}\u{00b7}\u{0044}\u{0098}\u{0021}\u{00ff}\u{000c}",
    ];
    for s in opaque {
        let u: u16 = u16::try_from(cp.len()).expect("cp index");
        cp.push(ConstantPoolEntry::Utf8((*s).to_owned()));
        cp.push(ConstantPoolEntry::String { utf8_index: u });
    }
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
    let report: ProtectorPeelReport = allatori_protector::peel(&cf, "com/example/Service", "init");
    assert_eq!(report.family, ProtectorFamilyKind::Allatori);
    assert_eq!(
        report.status,
        PeelStatus::DetectOnly,
        "with no decrypt method to run, the pass must wall, not invent plaintext"
    );
    assert!(
        report.strings_recovered.is_empty(),
        "detect-only peel must not fabricate plaintext"
    );
}

#[test]
fn allatori_watermark_field_stripped() {
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    cp.push(ConstantPoolEntry::Utf8("AllatoriWM_42".into()));
    let cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cp,
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: vec![disrobe_pass_jvm::FieldInfo {
            access_flags: 0,
            name_index: 1,
            descriptor_index: 1,
            attributes: Vec::new(),
        }],
        methods: Vec::new(),
        attributes: Vec::new(),
    };
    let report: ProtectorPeelReport = allatori_protector::peel(&cf, "Cls", "init");
    assert!(
        report
            .watermarks_stripped
            .iter()
            .any(|s: &String| s.contains("AllatoriWM_42"))
    );
}
