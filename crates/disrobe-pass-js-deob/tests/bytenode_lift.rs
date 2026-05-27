#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_js_deob::v8::{
    BYTENODE_PREFIX_BYTES, BytenodeCacheBody, Disassembly, LiftedFunction, NodeVersion,
    OpcodeTable, V8_CACHED_DATA_MAGIC, disassemble, encode_instruction, lift_disassembly,
    parse_bytenode_full,
};

fn enc(table: &OpcodeTable, mnemonic: &str, operands: &[i64]) -> Vec<u8> {
    encode_instruction(table, mnemonic, operands).expect("encode")
}

fn synth_jsc(version: u32, bytecode: &[u8]) -> Vec<u8> {
    let payload_len: u32 = u32::try_from(bytecode.len()).expect("fits u32");
    let mut out: Vec<u8> = Vec::with_capacity(BYTENODE_PREFIX_BYTES + bytecode.len());
    out.extend_from_slice(&V8_CACHED_DATA_MAGIC.to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    out.extend_from_slice(bytecode);
    out
}

#[test]
fn parses_full_bytenode_body_and_walks_bytecode() {
    let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
    let mut bc: Vec<u8> = Vec::new();
    bc.extend(enc(&table, "LdaSmi", &[42i64]));
    bc.extend(enc(&table, "Return", &[]));
    let jsc: Vec<u8> = synth_jsc(0xA5A5_22A5, &bc);
    let body: BytenodeCacheBody = parse_bytenode_full(&jsc).expect("parse_full");
    assert_eq!(body.bytecode_offset, BYTENODE_PREFIX_BYTES);
    assert_eq!(body.bytecode_length, bc.len());
    assert_eq!(body.bytecode, bc);
    let disasm: Disassembly = disassemble(&body.bytecode, body.header.version_hash.node);
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
    let jsc: Vec<u8> = synth_jsc(0xA5A5_22A5, &bc);
    let body: BytenodeCacheBody = parse_bytenode_full(&jsc).expect("parse_full");
    let disasm: Disassembly = disassemble(&body.bytecode, body.header.version_hash.node);
    let lifted: LiftedFunction = lift_disassembly(&disasm);
    let js: String = lifted.render_js("hello");
    assert!(js.contains("function hello"));
    assert!(js.contains("return 42;"));
    assert!(lifted.reversible_fraction() > 0.5);
}

#[test]
fn per_node_version_disasm_routes_through_correct_table() {
    for (node, version) in [
        (NodeVersion::Node18, 0xA5A5_18A5u32),
        (NodeVersion::Node20, 0xA5A5_20A5u32),
        (NodeVersion::Node22, 0xA5A5_22A5u32),
        (NodeVersion::Node24, 0xA5A5_24A5u32),
    ] {
        let table: OpcodeTable = OpcodeTable::for_node(node);
        let mut bc: Vec<u8> = Vec::new();
        bc.extend(enc(&table, "LdaTrue", &[]));
        bc.extend(enc(&table, "Return", &[]));
        let jsc: Vec<u8> = synth_jsc(version, &bc);
        let body: BytenodeCacheBody = parse_bytenode_full(&jsc).expect("parse_full");
        assert_eq!(body.header.version_hash.node, node);
        let disasm: Disassembly = disassemble(&body.bytecode, body.header.version_hash.node);
        assert_eq!(disasm.instructions.len(), 2usize);
        assert_eq!(disasm.instructions[0].mnemonic, "LdaTrue");
    }
}

#[test]
fn truncated_payload_does_not_panic_and_reports_partial_bytes() {
    let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
    let bc: Vec<u8> = enc(&table, "LdaSmi", &[1i64]);
    let mut jsc: Vec<u8> = synth_jsc(0xA5A5_22A5, &bc);
    jsc[16..20].copy_from_slice(&999u32.to_le_bytes());
    let body: BytenodeCacheBody = parse_bytenode_full(&jsc).expect("parse_full");
    assert_eq!(body.bytecode_length, bc.len());
}
