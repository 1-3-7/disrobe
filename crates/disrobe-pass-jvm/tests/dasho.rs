#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{ClassFile, ConstantPoolEntry, Detection, Protector, detect_all};

#[test]
fn dasho_preemptive_marker_triggers_detection() {
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    cp.push(ConstantPoolEntry::Utf8(
        "Built with DashO PreEmptive Protection".into(),
    ));
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
    assert!(d.iter().any(|x| x.protector == Protector::DashO));
}
