#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_jvm::{
    Attribute, CffUndoStats, ClassFile, ConstantPoolEntry, MethodInfo, undo_control_flow,
};

#[test]
#[ignore = "FIXTURE PENDING: requires real ZKM-protected JAR to validate CFF undoer beyond heuristic counts"]
fn detects_flattened_control_flow_in_real_zkm_jar() {
    unreachable!("fixture must be supplied via authorized round-trip");
}

#[test]
fn synthetic_goto_dense_method_flagged_as_flattened() {
    let mut cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: vec![
            ConstantPoolEntry::Placeholder,
            ConstantPoolEntry::Utf8("Code".into()),
        ],
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: Vec::new(),
        attributes: Vec::new(),
    };
    let code: Vec<u8> = vec![0xA7; 20];
    cf.methods.push(MethodInfo {
        access_flags: 0,
        name_index: 0,
        descriptor_index: 0,
        attributes: vec![Attribute {
            name_index: 1,
            info: code,
        }],
    });
    let stats: CffUndoStats = undo_control_flow(&cf);
    assert_eq!(stats.flattened_methods, 1);
    assert_eq!(stats.recovered_branches, 20);
}
