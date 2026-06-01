#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_js_deob::v8::{
    BytenodeCacheBody, Disassembly, HeaderLayout, NodeVersion, OpcodeTable, V8_HEADER_SIZE_V11,
    V8_HEADER_SIZE_V12, V8_MAGIC_NODE_18, V8_MAGIC_NODE_20, V8_MAGIC_NODE_22, V8_MAGIC_NODE_24,
    disassemble, encode_instruction, parse_bytenode_full,
};

fn enc(table: &OpcodeTable, mnemonic: &str, operands: &[i64]) -> Vec<u8> {
    encode_instruction(table, mnemonic, operands).expect("encode")
}

fn synth(magic: u32, version: u32, layout: HeaderLayout, payload: &[u8]) -> Vec<u8> {
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

fn round_trip(node: NodeVersion, magic: u32, version_hash: u32, layout: HeaderLayout) {
    let table: OpcodeTable = OpcodeTable::for_node(node);
    let mut bc: Vec<u8> = Vec::new();
    bc.extend(enc(&table, "LdaSmi", &[10i64]));
    bc.extend(enc(&table, "Star0", &[]));
    bc.extend(enc(&table, "LdaSmi", &[5i64]));
    bc.extend(enc(&table, "Mul", &[0i64, 0i64]));
    bc.extend(enc(&table, "Return", &[]));
    let jsc: Vec<u8> = synth(magic, version_hash, layout, &bc);
    let body: BytenodeCacheBody = parse_bytenode_full(&jsc).expect("parse_full");
    assert_eq!(body.header.version_hash.node, node);
    assert_eq!(body.header.magic_number, magic);
    assert_eq!(body.header.layout, layout);
    assert_eq!(body.payload, bc);
    let disasm: Disassembly = disassemble(&body.payload, node);
    assert_eq!(disasm.instructions.len(), 5usize);
    assert_eq!(disasm.trailing_garbage, 0usize);
    let hist: std::collections::BTreeMap<&'static str, usize> = disasm.mnemonic_histogram();
    assert_eq!(*hist.get("LdaSmi").expect("lda smi"), 2usize);
    assert_eq!(*hist.get("Return").expect("return"), 1usize);
}

#[test]
fn node_18_synthetic_real_magic_round_trip() {
    round_trip(
        NodeVersion::Node18,
        V8_MAGIC_NODE_18,
        0x3569_A082,
        HeaderLayout::V11,
    );
}

#[test]
fn node_20_synthetic_real_magic_round_trip() {
    round_trip(
        NodeVersion::Node20,
        V8_MAGIC_NODE_20,
        0x00E4_C20B,
        HeaderLayout::V11,
    );
}

#[test]
fn node_22_synthetic_real_magic_round_trip() {
    round_trip(
        NodeVersion::Node22,
        V8_MAGIC_NODE_22,
        0x79DA_FE74,
        HeaderLayout::V12,
    );
}

#[test]
fn node_24_synthetic_real_magic_round_trip() {
    round_trip(
        NodeVersion::Node24,
        V8_MAGIC_NODE_24,
        0xDC33_8CFA,
        HeaderLayout::V12,
    );
}

#[test]
fn v11_layout_header_size_is_24_bytes() {
    assert_eq!(V8_HEADER_SIZE_V11, 24usize);
    assert_eq!(HeaderLayout::V11.header_size(), 24usize);
}

#[test]
fn v12_layout_header_size_is_32_bytes() {
    assert_eq!(V8_HEADER_SIZE_V12, 32usize);
    assert_eq!(HeaderLayout::V12.header_size(), 32usize);
}
