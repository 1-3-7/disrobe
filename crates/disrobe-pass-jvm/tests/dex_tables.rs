#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_jvm::{
    DexFile, FieldId, MethodId, ProtoId, dalvik_opcode, disassemble_dalvik, parse_dex,
};

const HELLO_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/Hello.dex");
const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const EDGECASES_KT_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex");

#[test]
fn parses_method_field_proto_tables_from_real_hello_dex() {
    let dex: DexFile = parse_dex(HELLO_DEX).expect("parse hello.dex");
    assert!(!dex.method_ids.is_empty(), "no method_ids parsed");
    assert!(!dex.proto_ids.is_empty(), "no proto_ids parsed");
    let has_main: bool = dex.method_ids.iter().any(|m: &MethodId| m.name == "main");
    assert!(has_main, "expected a main method in Hello.dex");
}

#[test]
fn method_ids_reference_valid_classes_and_protos() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse edgecases.dex");
    assert!(dex.method_ids.len() > 5, "expected many methods");
    for m in dex.method_ids.iter().take(50) {
        assert!(
            !m.name.is_empty(),
            "method name should resolve from string table"
        );
        let proto: &ProtoId = &m.proto;
        assert!(proto.parameters.len() <= 255, "proto arity sane");
    }
    let constructor_present: bool = dex.method_ids.iter().any(|m: &MethodId| m.name == "<init>");
    assert!(constructor_present, "expected <init> in field-rich class");
}

#[test]
fn field_ids_resolve_from_kotlin_dex() {
    let dex: DexFile = parse_dex(EDGECASES_KT_DEX).expect("parse kotlin dex");
    assert!(!dex.field_ids.is_empty(), "no field_ids parsed");
    for f in dex.field_ids.iter().take(20) {
        assert!(
            !f.type_name.is_empty() || !f.name.is_empty(),
            "field should resolve type or name from tables"
        );
    }
}

#[test]
fn dalvik_opcode_table_is_total() {
    for op in 0u16..=0xFFu16 {
        assert!(dalvik_opcode(op as u8).units >= 1);
    }
}

#[test]
fn dalvik_disassembles_synthetic_stream() {
    let code: Vec<u16> = vec![0x000E];
    let insns: Vec<(u32, &'static str)> = disassemble_dalvik(&code);
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].1, "return-void");
}

#[test]
fn proto_parameters_parse_as_type_list() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse edgecases.dex");
    let any_with_params: bool = dex
        .proto_ids
        .iter()
        .any(|p: &ProtoId| !p.parameters.is_empty());
    assert!(
        any_with_params,
        "expected at least one proto with parameters"
    );
}

#[test]
fn field_id_type_count_matches_header() {
    let dex: DexFile = parse_dex(HELLO_DEX).expect("parse");
    assert_eq!(dex.field_ids.len(), dex.header.field_ids_size as usize);
    assert_eq!(dex.method_ids.len(), dex.header.method_ids_size as usize);
    assert_eq!(dex.proto_ids.len(), dex.header.proto_ids_size as usize);
    let first: Option<&FieldId> = dex.field_ids.first();
    assert!(first.is_some() || dex.header.field_ids_size == 0);
}
