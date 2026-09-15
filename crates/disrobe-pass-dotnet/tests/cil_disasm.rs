#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_dotnet::cil::{
    Instruction, MethodBody, OperandKind, OperandValue, coverage_percent, disassemble,
    ecma_335_spec_total, parse_method_body, total_opcode_count,
};

#[test]
fn opcode_table_covers_majority_of_spec() {
    let total: usize = total_opcode_count();
    let spec: usize = ecma_335_spec_total();
    assert!(
        total >= 150,
        "opcode table too small: have {total}, spec {spec}"
    );
    assert!(coverage_percent() >= 85);
}

#[test]
fn disasm_handles_full_ldc_sequence() {
    let code: [u8; 14] = [
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x42, 0x58, 0x2A,
    ];
    let insns: Vec<Instruction> = disassemble(&code).expect("disasm");
    assert_eq!(insns.len(), 13);
    assert_eq!(insns[0].name, "ldc.i4.m1");
    assert_eq!(insns[10].name, "ldc.i4.s");
    let OperandValue::U8(v) = insns[10].operand else {
        unreachable!("ldc.i4.s carries u8 operand");
    };
    assert_eq!(v, 0x42);
    assert_eq!(insns[11].name, "add");
    assert_eq!(insns[12].name, "ret");
}

#[test]
fn disasm_two_byte_ceq_opcode() {
    let code: [u8; 4] = [0x16, 0x17, 0xFE, 0x01];
    let insns: Vec<Instruction> = disassemble(&code).expect("disasm");
    assert_eq!(insns.len(), 3);
    assert_eq!(insns[2].name, "ceq");
    assert_eq!(insns[2].opcode, 0xFE01);
}

#[test]
fn parse_fat_method_body_round_trip() {
    let mut bytes: Vec<u8> = Vec::with_capacity(20);
    let flags_size: u16 = (3u16 << 12) | 0x13;
    bytes.extend_from_slice(&flags_size.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&[0x16, 0x17, 0x2A]);
    let body: MethodBody = parse_method_body(&bytes).expect("fat");
    assert_eq!(body.max_stack, 4);
    assert_eq!(body.code_size, 3);
    assert_eq!(body.instructions.len(), 3);
}

#[test]
fn all_one_byte_opcodes_have_known_operand_kinds() {
    use disrobe_pass_dotnet::cil::ONE_BYTE_OPCODES;
    for op in ONE_BYTE_OPCODES {
        assert!(matches!(
            op.operand,
            OperandKind::InlineNone
                | OperandKind::InlineI
                | OperandKind::InlineI8
                | OperandKind::InlineR
                | OperandKind::InlineShortR
                | OperandKind::InlineVar
                | OperandKind::InlineShortVar
                | OperandKind::InlineShortI
                | OperandKind::InlineMethod
                | OperandKind::InlineField
                | OperandKind::InlineType
                | OperandKind::InlineString
                | OperandKind::InlineSig
                | OperandKind::InlineTok
                | OperandKind::InlineBrTarget
                | OperandKind::InlineShortBrTarget
                | OperandKind::InlineSwitch
        ));
    }
}
