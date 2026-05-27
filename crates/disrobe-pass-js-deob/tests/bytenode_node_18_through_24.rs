#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_js_deob::v8::{
    BYTENODE_PREFIX_BYTES, BytenodeCacheBody, Disassembly, NodeVersion, OpcodeTable,
    V8_CACHED_DATA_MAGIC, disassemble, encode_instruction, parse_bytenode_full,
};

fn enc(table: &OpcodeTable, mnemonic: &str, operands: &[i64]) -> Vec<u8> {
    encode_instruction(table, mnemonic, operands).expect("encode")
}

fn synth(version: u32, bc: &[u8]) -> Vec<u8> {
    let payload_len: u32 = u32::try_from(bc.len()).expect("fits u32");
    let mut out: Vec<u8> = Vec::with_capacity(BYTENODE_PREFIX_BYTES + bc.len());
    out.extend_from_slice(&V8_CACHED_DATA_MAGIC.to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    out.extend_from_slice(bc);
    out
}

fn round_trip(node: NodeVersion, version_hash: u32) {
    let table: OpcodeTable = OpcodeTable::for_node(node);
    let mut bc: Vec<u8> = Vec::new();
    bc.extend(enc(&table, "LdaSmi", &[10i64]));
    bc.extend(enc(&table, "Star0", &[]));
    bc.extend(enc(&table, "LdaSmi", &[5i64]));
    bc.extend(enc(&table, "Mul", &[0i64, 0i64]));
    bc.extend(enc(&table, "Return", &[]));
    let jsc: Vec<u8> = synth(version_hash, &bc);
    let body: BytenodeCacheBody = parse_bytenode_full(&jsc).expect("parse_full");
    assert_eq!(body.header.version_hash.node, node);
    let disasm: Disassembly = disassemble(&body.bytecode, node);
    assert_eq!(disasm.instructions.len(), 5usize);
    assert_eq!(disasm.trailing_garbage, 0usize);
    let hist: std::collections::BTreeMap<&'static str, usize> = disasm.mnemonic_histogram();
    assert_eq!(*hist.get("LdaSmi").expect("lda smi"), 2usize);
    assert_eq!(*hist.get("Return").expect("return"), 1usize);
}

#[test]
fn node_18_round_trip_disasm() {
    round_trip(NodeVersion::Node18, 0xA5A5_18A5);
}

#[test]
fn node_20_round_trip_disasm() {
    round_trip(NodeVersion::Node20, 0xA5A5_20A5);
}

#[test]
fn node_22_round_trip_disasm() {
    round_trip(NodeVersion::Node22, 0xA5A5_22A5);
}

#[test]
fn node_24_round_trip_disasm() {
    round_trip(NodeVersion::Node24, 0xA5A5_24A5);
}
