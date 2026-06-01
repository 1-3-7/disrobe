#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_js_deob::v8::{
    BytenodeCacheBody, Disassembly, HeaderLayout, LiftedFunction, NodeVersion, OpcodeTable,
    V8_HEADER_SIZE_V11, V8_HEADER_SIZE_V12, V8_MAGIC_NODE_18, V8_MAGIC_NODE_20, V8_MAGIC_NODE_22,
    V8_MAGIC_NODE_24, disassemble, encode_instruction, lift_disassembly, parse_bytenode_full,
};

fn enc(table: &OpcodeTable, mnemonic: &str, operands: &[i64]) -> Vec<u8> {
    encode_instruction(table, mnemonic, operands).expect("encode")
}

fn synth_jsc(magic: u32, version: u32, layout: HeaderLayout, payload: &[u8]) -> Vec<u8> {
    let header_size: usize = layout.header_size();
    let payload_len: u32 = u32::try_from(payload.len()).expect("fits u32");
    let mut out: Vec<u8> = Vec::with_capacity(header_size + payload.len());
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    if matches!(layout, HeaderLayout::V12) {
        out.extend_from_slice(&0xCAFE_BABEu32.to_le_bytes());
    }
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    if matches!(layout, HeaderLayout::V12) {
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    assert_eq!(out.len(), header_size);
    out.extend_from_slice(payload);
    out
}

#[test]
fn parses_full_bytenode_body_and_walks_payload_as_bytecode() {
    let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
    let mut bc: Vec<u8> = Vec::new();
    bc.extend(enc(&table, "LdaSmi", &[42i64]));
    bc.extend(enc(&table, "Return", &[]));
    let jsc: Vec<u8> = synth_jsc(V8_MAGIC_NODE_22, 0x79DA_FE74, HeaderLayout::V12, &bc);
    let body: BytenodeCacheBody = parse_bytenode_full(&jsc).expect("parse_full");
    assert_eq!(body.payload_offset, V8_HEADER_SIZE_V12);
    assert_eq!(body.payload_length, bc.len());
    assert_eq!(body.payload, bc);
    let disasm: Disassembly = disassemble(&body.payload, body.header.version_hash.node);
    assert_eq!(disasm.instructions.len(), 2usize);
    assert_eq!(disasm.instructions[0].mnemonic, "LdaSmi");
    assert_eq!(disasm.instructions[1].mnemonic, "Return");
}

#[test]
fn full_bytenode_lift_round_trip_hello_42() {
    let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
    let mut bc: Vec<u8> = Vec::new();
    bc.extend(enc(&table, "LdaSmi", &[42i64]));
    bc.extend(enc(&table, "Return", &[]));
    let jsc: Vec<u8> = synth_jsc(V8_MAGIC_NODE_22, 0x79DA_FE74, HeaderLayout::V12, &bc);
    let body: BytenodeCacheBody = parse_bytenode_full(&jsc).expect("parse_full");
    let disasm: Disassembly = disassemble(&body.payload, body.header.version_hash.node);
    let lifted: LiftedFunction = lift_disassembly(&disasm);
    let js: String = lifted.render_js("hello");
    assert!(js.contains("function hello"));
    assert!(js.contains("return 42;"));
    assert!(lifted.reversible_fraction() > 0.5);
}

#[test]
fn per_node_version_disasm_routes_through_correct_table() {
    let cases: [(NodeVersion, u32, u32, HeaderLayout); 4] = [
        (
            NodeVersion::Node18,
            V8_MAGIC_NODE_18,
            0x3569_A082,
            HeaderLayout::V11,
        ),
        (
            NodeVersion::Node20,
            V8_MAGIC_NODE_20,
            0x00E4_C20B,
            HeaderLayout::V11,
        ),
        (
            NodeVersion::Node22,
            V8_MAGIC_NODE_22,
            0x79DA_FE74,
            HeaderLayout::V12,
        ),
        (
            NodeVersion::Node24,
            V8_MAGIC_NODE_24,
            0xDC33_8CFA,
            HeaderLayout::V12,
        ),
    ];
    for (node, magic, version, layout) in cases {
        let table: OpcodeTable = OpcodeTable::for_node(node);
        let mut bc: Vec<u8> = Vec::new();
        bc.extend(enc(&table, "LdaTrue", &[]));
        bc.extend(enc(&table, "Return", &[]));
        let jsc: Vec<u8> = synth_jsc(magic, version, layout, &bc);
        let body: BytenodeCacheBody = parse_bytenode_full(&jsc).expect("parse_full");
        assert_eq!(body.header.version_hash.node, node);
        assert_eq!(body.header.layout, layout);
        let disasm: Disassembly = disassemble(&body.payload, body.header.version_hash.node);
        assert_eq!(disasm.instructions.len(), 2usize);
        assert_eq!(disasm.instructions[0].mnemonic, "LdaTrue");
    }
}

#[test]
fn declared_payload_length_past_input_is_rejected_not_truncated() {
    let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
    let bc: Vec<u8> = enc(&table, "LdaSmi", &[1i64]);
    let mut jsc: Vec<u8> = synth_jsc(V8_MAGIC_NODE_22, 0x79DA_FE74, HeaderLayout::V12, &bc);
    jsc[20..24].copy_from_slice(&999u32.to_le_bytes());
    let err: String = parse_bytenode_full(&jsc)
        .map(|_: BytenodeCacheBody| ())
        .map_err(|e| format!("{e}"))
        .expect_err("should reject over-declared payload");
    let msg: String = err;
    assert!(
        msg.contains("exceeds available input")
            || msg.contains("extends past")
            || msg.contains("exceeds"),
        "expected fail-fast bounds error, got: {msg}"
    );
}

#[test]
fn header_size_constants_are_correct() {
    assert_eq!(V8_HEADER_SIZE_V11, 24usize);
    assert_eq!(V8_HEADER_SIZE_V12, 32usize);
}
