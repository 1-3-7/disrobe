#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_js_deob::v8::{
    Disassembly, NodeVersion, OpcodeTable, disassemble, encode_instruction,
};

fn enc(table: &OpcodeTable, mnemonic: &str, operands: &[i64]) -> Vec<u8> {
    encode_instruction(table, mnemonic, operands).expect("encode")
}

#[test]
fn opcode_tables_cover_all_supported_node_versions() {
    for node in [
        NodeVersion::Node18,
        NodeVersion::Node20,
        NodeVersion::Node22,
        NodeVersion::Node24,
    ] {
        let table: OpcodeTable = OpcodeTable::for_node(node);
        assert!(
            table.len() > 100usize,
            "{node:?} has only {} opcodes",
            table.len()
        );
        assert!(table.lookup_mnemonic("Return").is_some());
        assert!(table.lookup_mnemonic("LdaConstant").is_some());
        assert!(table.lookup_mnemonic("CallProperty0").is_some());
    }
}

#[test]
fn round_trip_encode_then_disassemble_node_22() {
    let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
    let mut stream: Vec<u8> = Vec::new();
    stream.extend(enc(&table, "LdaSmi", &[7i64]));
    stream.extend(enc(&table, "Star0", &[]));
    stream.extend(enc(&table, "LdaSmi", &[3i64]));
    stream.extend(enc(&table, "Add", &[0i64, 0i64]));
    stream.extend(enc(&table, "Return", &[]));
    let disasm: Disassembly = disassemble(&stream, NodeVersion::Node22);
    assert_eq!(disasm.instructions.len(), 5usize);
    assert_eq!(disasm.trailing_garbage, 0usize);
    let text: String = disasm.render_text();
    assert!(text.contains("LdaSmi #7"));
    assert!(text.contains("Star0"));
    assert!(text.contains("Add r0"));
    assert!(text.contains("Return"));
}

#[test]
fn coverage_fraction_is_high_for_target_v8_version() {
    let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
    let frac: f64 = table.coverage_fraction();
    assert!(frac > 0.95, "coverage {frac} below 95%");
}

#[test]
fn wide_prefix_doubles_operand_width_on_lda_smi() {
    let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
    let wide_byte: u8 = table.lookup_mnemonic("Wide").expect("Wide");
    let lda_byte: u8 = table.lookup_mnemonic("LdaSmi").expect("LdaSmi");
    let mut stream: Vec<u8> = vec![wide_byte, lda_byte];
    stream.extend_from_slice(&30_000i16.to_le_bytes());
    let disasm: Disassembly = disassemble(&stream, NodeVersion::Node22);
    assert_eq!(disasm.instructions.len(), 1usize);
    assert_eq!(disasm.instructions[0].operands[0].signed_value, 30_000i64);
}
