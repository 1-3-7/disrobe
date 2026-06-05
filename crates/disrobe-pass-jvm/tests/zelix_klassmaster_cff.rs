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
    let mut code_body: Vec<u8> = Vec::new();
    for _ in 0..12 {
        code_body.push(0xA7);
        code_body.extend_from_slice(&[0x00, 0x03]);
    }
    let mut info: Vec<u8> = Vec::new();
    info.extend_from_slice(&0u16.to_be_bytes());
    info.extend_from_slice(&0u16.to_be_bytes());
    info.extend_from_slice(&(code_body.len() as u32).to_be_bytes());
    info.extend_from_slice(&code_body);
    info.extend_from_slice(&0u16.to_be_bytes());
    cf.methods.push(MethodInfo {
        access_flags: 0,
        name_index: 0,
        descriptor_index: 0,
        attributes: vec![Attribute {
            name_index: 1,
            info,
        }],
    });
    let stats: CffUndoStats = undo_control_flow(&cf);
    assert_eq!(stats.flattened_methods, 1);
    assert_eq!(stats.recovered_branches, 12);
}
