use disrobe_sleigh::lifter::{DecodedBlock, Language, RiscVWidth, decode_block_for_language};
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space};

#[test]
fn decodes_rv32_and_rv64_integer_alias_and_control_forms() {
    let words: [u32; 8] = [
        0xff95_8513,
        0x00e6_8633,
        0x4118_07b3,
        0x02c5_8533,
        0x0200_00ef,
        0x0045_8567,
        0x0000_0013,
        0x0000_8067,
    ];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    for width in [RiscVWidth::Rv32, RiscVWidth::Rv64] {
        let block: DecodedBlock = decode_block_for_language(Language::RiscV(width), &bytes, 0x1000);
        let mnemonics: Vec<&str> = block
            .instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
            .collect();
        assert_eq!(
            mnemonics,
            ["addi", "add", "sub", "mul", "jal", "jalr", "nop", "ret"],
            "{block:#?}"
        );
        assert_eq!(block.consumed, bytes.len());
        assert!(block.instructions.iter().all(|instruction: &PcodeInstr| {
            let expected: DecodeStatus = if matches!(instruction.mnemonic.as_str(), "jalr" | "ret")
            {
                DecodeStatus::CallOther
            } else {
                DecodeStatus::Supported
            };
            instruction.status == expected && instruction.length == 4
        }));
        assert!(matches!(block.instructions[6].ops.as_slice(), []));
        assert!(matches!(
            block.instructions[7].ops.as_slice(),
            [
                PcodeOp::IntAnd { .. },
                PcodeOp::CallOther { .. },
                PcodeOp::Return { .. }
            ]
        ));
    }
}

#[test]
fn applies_riscv_width_and_memory_extension_rules() {
    let rv32: DecodedBlock = decode_block_for_language(
        Language::RiscV(RiscVWidth::Rv32),
        &0x00c5_a503_u32.to_le_bytes(),
        0,
    );
    assert!(rv32.instructions[0].ops.iter().all(|operation: &PcodeOp| {
        match operation {
            PcodeOp::IntAdd { output, .. } | PcodeOp::Load { output, .. } => output.size_bytes == 4,
            _ => true,
        }
    }));

    let words: [u32; 4] = [0x00c5_a503, 0x0187_3683, 0xfef8_3023, 0x1234_5737];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let rv64: DecodedBlock =
        decode_block_for_language(Language::RiscV(RiscVWidth::Rv64), &bytes, 0);
    assert!(matches!(
        rv64.instructions[0].ops.as_slice(),
        [
            PcodeOp::IntAdd { output: pointer, .. },
            PcodeOp::Load { output: loaded, .. },
            PcodeOp::IntSext { output, input },
        ] if pointer.size_bytes == 8
            && loaded.size_bytes == 4
            && output.size_bytes == 8
            && input == loaded
    ));
    assert!(rv64.instructions[1].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Load { output, .. } if output.size_bytes == 8)
    }));
    assert!(rv64.instructions[2].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Store { value, .. } if value.size_bytes == 8)
    }));
    assert!(rv64.instructions[3].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntLeft { output, input, amount }
            if output.size_bytes == 8
                && input.space == Space::Constant
                && input.offset == 0x12345
                && amount.offset == 12)
    }));
}

#[test]
fn marks_riscv_division_edges_and_unmodeled_same_opcode_constructors() {
    let words: [u32; 3] = [0x0288_c833, 0x0339_64b3, 0x0015_a513];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let block: DecodedBlock =
        decode_block_for_language(Language::RiscV(RiscVWidth::Rv32), &bytes, 0x2000);
    assert_eq!(block.instructions[0].status, DecodeStatus::CallOther);
    assert_eq!(block.instructions[1].status, DecodeStatus::CallOther);
    assert!(block.instructions[..2].iter().all(|instruction: &PcodeInstr| {
        instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::CallOther { name, .. } if name == "riscv_division_edge_cases")
        })
    }));
    assert_eq!(block.instructions[2].mnemonic, "slti");
    assert_eq!(block.instructions[2].status, DecodeStatus::Unsupported);

    let alias_words: [u32; 2] = [0x02b5_4533, 0x02b5_65b3];
    let alias_bytes: Vec<u8> = alias_words.into_iter().flat_map(u32::to_le_bytes).collect();
    let aliases: DecodedBlock =
        decode_block_for_language(Language::RiscV(RiscVWidth::Rv32), &alias_bytes, 0);
    for instruction in &aliases.instructions {
        assert_eq!(instruction.status, DecodeStatus::CallOther);
        assert!(matches!(
            instruction.ops.as_slice(),
            [
                PcodeOp::Copy {
                    output: left_snapshot,
                    ..
                },
                PcodeOp::Copy {
                    output: right_snapshot,
                    ..
                },
                PcodeOp::IntSignedDiv { left, right, .. }
                | PcodeOp::IntSignedRem { left, right, .. },
                PcodeOp::CallOther { inputs, .. }
            ] if left_snapshot.space == Space::Unique
                && right_snapshot.space == Space::Unique
                && left == left_snapshot
                && right == right_snapshot
                && inputs.first() == Some(left_snapshot)
                && inputs.get(1) == Some(right_snapshot)
        ));
    }
}

#[test]
fn marks_riscv_instruction_alignment_edges() {
    let words: [u32; 4] = [0x00b5_0163, 0x0020_00ef, 0x0045_8567, 0x0000_8067];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let block: DecodedBlock =
        decode_block_for_language(Language::RiscV(RiscVWidth::Rv32), &bytes, 0);
    assert_eq!(
        block
            .instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
            .collect::<Vec<&str>>(),
        ["beq", "jal", "jalr", "ret"]
    );
    assert!(block.instructions.iter().all(|instruction: &PcodeInstr| {
        instruction.status == DecodeStatus::CallOther
            && instruction.ops.iter().any(|operation: &PcodeOp| {
                matches!(operation, PcodeOp::CallOther { name, .. }
                    if name == "riscv_instruction_address_alignment")
            })
    }));
    assert!(
        !block.instructions[1].ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::Copy { .. } | PcodeOp::Call { .. })
        })
    );

    let aligned: DecodedBlock = decode_block_for_language(
        Language::RiscV(RiscVWidth::Rv32),
        &0x0040_00ef_u32.to_le_bytes(),
        0,
    );
    assert_eq!(aligned.instructions[0].status, DecodeStatus::Supported);
}

#[test]
fn handles_riscv_fragments_reversed_bytes_and_wrapping_addresses() {
    let mut bytes: Vec<u8> = Vec::new();
    for _index in 0_u32..3_u32 {
        bytes.extend_from_slice(&0x0000_0013_u32.to_le_bytes());
    }
    for length in 0_usize..=9_usize {
        let block: DecodedBlock = decode_block_for_language(
            Language::RiscV(RiscVWidth::Rv64),
            &bytes[..length],
            u64::MAX.saturating_sub(3),
        );
        assert_eq!(block.consumed, length);
        assert!(
            block
                .instructions
                .iter()
                .all(|instruction: &PcodeInstr| instruction.length > 0)
        );
    }

    let reversed: [u8; 4] = 0xff95_8513_u32.to_be_bytes();
    let block: DecodedBlock =
        decode_block_for_language(Language::RiscV(RiscVWidth::Rv32), &reversed, 0);
    assert_ne!(block.instructions[0].mnemonic, "addi");
}
