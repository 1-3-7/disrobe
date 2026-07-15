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
fn distinguishes_base_and_compressed_profile_instruction_alignment() {
    let words: [u32; 4] = [0x00b5_0163, 0x0020_00ef, 0x0045_8567, 0x0000_8067];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let base: DecodedBlock =
        decode_block_for_language(Language::RiscV(RiscVWidth::Rv32), &bytes, 0);
    assert_eq!(
        base.instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
            .collect::<Vec<&str>>(),
        ["beq", "jal", "jalr", "ret"]
    );
    assert!(base.instructions.iter().all(|instruction: &PcodeInstr| {
        instruction.status == DecodeStatus::CallOther
            && instruction.ops.iter().any(|operation: &PcodeOp| {
                matches!(operation, PcodeOp::CallOther { name, .. }
                    if name == "riscv_instruction_address_alignment")
            })
    }));
    let compressed: DecodedBlock =
        decode_block_for_language(Language::RiscVCompressed(RiscVWidth::Rv32), &bytes, 0);
    assert!(
        compressed
            .instructions
            .iter()
            .all(|instruction: &PcodeInstr| {
                instruction.status == DecodeStatus::Supported
                    && !instruction.ops.iter().any(|operation: &PcodeOp| {
                        matches!(operation, PcodeOp::CallOther { name, .. }
                    if name == "riscv_instruction_address_alignment")
                    })
            })
    );
    assert!(
        compressed.instructions[1]
            .ops
            .iter()
            .any(|operation: &PcodeOp| {
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

#[test]
fn decodes_riscv_compressed_forms_at_two_byte_boundaries() {
    let halfwords: [u16; 17] = [
        0x1565, 0x45a5, 0x46d0, 0xcb98, 0xa821, 0x2819, 0x8502, 0x9582, 0xca01, 0xe699, 0x873e,
        0x952e, 0x0001, 0x0090, 0x46d2, 0xcc3a, 0x0505,
    ];
    let bytes: Vec<u8> = halfwords.into_iter().flat_map(u16::to_le_bytes).collect();
    let block: DecodedBlock =
        decode_block_for_language(Language::RiscVCompressed(RiscVWidth::Rv32), &bytes, 0x1000);
    let mnemonics: Vec<&str> = block
        .instructions
        .iter()
        .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
        .collect();
    assert_eq!(
        mnemonics,
        [
            "addi", "li", "lw", "sw", "j", "jal", "jr", "jalr", "beqz", "bnez", "mv", "add", "nop",
            "addi", "lw", "sw", "addi",
        ],
        "{block:#?}"
    );
    assert_eq!(block.consumed, bytes.len());
    assert!(
        block
            .instructions
            .iter()
            .all(|instruction: &PcodeInstr| instruction.length == 2)
    );
    assert!(
        block
            .instructions
            .iter()
            .all(|instruction: &PcodeInstr| instruction.status == DecodeStatus::Supported)
    );
    assert!(matches!(
        block.instructions[5].ops.as_slice(),
        [PcodeOp::Copy { input, .. }, PcodeOp::Call { target }]
            if input.space == Space::Constant
                && input.offset == 0x100c
                && target.space == Space::Ram
                && target.offset == 0x1020
    ));
    assert!(
        block.instructions[13]
            .ops
            .iter()
            .any(|operation: &PcodeOp| {
                matches!(operation, PcodeOp::IntAdd { right, .. }
            if right.space == Space::Constant && right.offset == 64)
            })
    );
}

#[test]
fn applies_rv64_compressed_doubleword_memory_widths() {
    let halfwords: [u16; 2] = [0x6d88, 0xea90];
    let bytes: Vec<u8> = halfwords.into_iter().flat_map(u16::to_le_bytes).collect();
    let block: DecodedBlock =
        decode_block_for_language(Language::RiscVCompressed(RiscVWidth::Rv64), &bytes, 0);
    assert_eq!(
        block
            .instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
            .collect::<Vec<&str>>(),
        ["ld", "sd"]
    );
    assert!(block.instructions[0].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Load { output, .. } if output.size_bytes == 8)
    }));
    assert!(block.instructions[1].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Store { value, .. } if value.size_bytes == 8)
    }));
}

#[test]
fn rejects_reserved_compressed_zero_register_forms_and_keeps_hints_empty() {
    let reserved_halfwords: [u16; 3] = [0x0000, 0x4002, 0x8002];
    let reserved_bytes: Vec<u8> = reserved_halfwords
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect();
    let reserved: DecodedBlock = decode_block_for_language(
        Language::RiscVCompressed(RiscVWidth::Rv32),
        &reserved_bytes,
        0,
    );
    assert!(
        reserved
            .instructions
            .iter()
            .all(|instruction: &PcodeInstr| {
                matches!(
                    instruction.status,
                    DecodeStatus::NoMatch | DecodeStatus::Unsupported
                ) && !instruction.ops.iter().any(|operation: &PcodeOp| {
                    matches!(
                        operation,
                        PcodeOp::Load { .. }
                            | PcodeOp::BranchIndirect { .. }
                            | PcodeOp::CallIndirect { .. }
                    )
                })
            }),
        "{reserved:#?}"
    );

    let hint_halfwords: [u16; 2] = [0x802a, 0x902a];
    let hint_bytes: Vec<u8> = hint_halfwords
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect();
    let hints: DecodedBlock =
        decode_block_for_language(Language::RiscVCompressed(RiscVWidth::Rv32), &hint_bytes, 0);
    assert!(hints.instructions.iter().all(|instruction: &PcodeInstr| {
        instruction.status == DecodeStatus::Supported && instruction.ops.is_empty()
    }));
}

#[test]
fn models_riscv_atomic_forms_with_a_typed_callother_contract() {
    let rv32_words: [u32; 10] = [
        0x1005_a52f,
        0x1406_a62f,
        0x1af8_272f,
        0x0884_a8af,
        0x073a_292f,
        0x616b_aaaf,
        0x419d_2c2f,
        0x21ce_adaf,
        0x81f5_2f2f,
        0xa0c6_a5af,
    ];
    let rv32_bytes: Vec<u8> = rv32_words.into_iter().flat_map(u32::to_le_bytes).collect();
    let rv32: DecodedBlock =
        decode_block_for_language(Language::RiscV(RiscVWidth::Rv32), &rv32_bytes, 0);
    assert_eq!(
        rv32.instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
            .collect::<Vec<&str>>(),
        [
            "lr.w",
            "lr.w.aq",
            "sc.w.rl",
            "amoswap.w",
            "amoadd.w.aqrl",
            "amoand.w",
            "amoor.w",
            "amoxor.w",
            "amomin.w",
            "amomax.w",
        ]
    );
    assert!(rv32.instructions.iter().all(|instruction: &PcodeInstr| {
        instruction.status == DecodeStatus::CallOther
            && matches!(
                instruction.ops.as_slice(),
                [PcodeOp::CallOther {
                    name,
                    output: _,
                    inputs,
                }] if name == "riscv_atomic_memory_v1"
                    && inputs.len() == 6
                    && inputs[0].size_bytes == 4
                    && inputs[2].space == Space::Constant
                    && inputs[3].space == Space::Constant
                    && inputs[3].offset == 4
                    && inputs[4].space == Space::Constant
                    && inputs[5].space == Space::Constant
            )
    }));
    assert!(matches!(
        rv32.instructions[4].ops.as_slice(),
        [PcodeOp::CallOther { inputs, .. }]
            if inputs[4].offset == 1 && inputs[5].offset == 1
    ));
    assert_eq!(
        rv32.instructions
            .iter()
            .map(
                |instruction: &PcodeInstr| match instruction.ops.as_slice() {
                    [PcodeOp::CallOther { inputs, .. }] => inputs[2].offset,
                    _ => u64::MAX,
                }
            )
            .collect::<Vec<u64>>(),
        [0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
    );

    let rv64_words: [u32; 9] = [
        0x1204_b42f,
        0x1f3a_392f,
        0x096b_baaf,
        0x019d_3c2f,
        0x61ce_bdaf,
        0x41f5_3f2f,
        0x20c6_b5af,
        0x80f8_372f,
        0xa084_b8af,
    ];
    let rv64_bytes: Vec<u8> = rv64_words.into_iter().flat_map(u32::to_le_bytes).collect();
    let rv64: DecodedBlock =
        decode_block_for_language(Language::RiscV(RiscVWidth::Rv64), &rv64_bytes, 0);
    assert_eq!(
        rv64.instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
            .collect::<Vec<&str>>(),
        [
            "lr.d.rl",
            "sc.d.aqrl",
            "amoswap.d",
            "amoadd.d",
            "amoand.d",
            "amoor.d",
            "amoxor.d",
            "amomin.d",
            "amomax.d",
        ]
    );
    assert!(rv64.instructions.iter().all(|instruction: &PcodeInstr| {
        matches!(
            instruction.ops.as_slice(),
            [PcodeOp::CallOther { inputs, .. }]
                if inputs[0].size_bytes == 8 && inputs[3].offset == 8
        )
    }));
    assert_eq!(
        rv64.instructions
            .iter()
            .map(
                |instruction: &PcodeInstr| match instruction.ops.as_slice() {
                    [PcodeOp::CallOther { inputs, .. }] => inputs[2].offset,
                    _ => u64::MAX,
                }
            )
            .collect::<Vec<u64>>(),
        [0, 1, 2, 3, 4, 5, 6, 7, 8]
    );

    let discarded: DecodedBlock = decode_block_for_language(
        Language::RiscV(RiscVWidth::Rv32),
        &0x1005_a02f_u32.to_le_bytes(),
        0,
    );
    assert!(matches!(
        discarded.instructions[0].ops.as_slice(),
        [PcodeOp::CallOther { output: None, .. }]
    ));
}

#[test]
fn lifts_compressed_gcc_arithmetic_and_return_aliases() {
    let halfwords: [u16; 3] = [0x8d0d, 0x8fa9, 0x8082];
    let bytes: Vec<u8> = halfwords.into_iter().flat_map(u16::to_le_bytes).collect();
    let block: DecodedBlock =
        decode_block_for_language(Language::RiscVCompressed(RiscVWidth::Rv64), &bytes, 0);
    assert_eq!(
        block
            .instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
            .collect::<Vec<&str>>(),
        ["sub", "xor", "ret"]
    );
    assert!(matches!(
        block.instructions[0].ops.as_slice(),
        [PcodeOp::IntSub { .. }]
    ));
    assert!(matches!(
        block.instructions[1].ops.as_slice(),
        [PcodeOp::IntXor { .. }]
    ));
    assert!(matches!(
        block.instructions[2].ops.as_slice(),
        [PcodeOp::IntAnd { .. }, PcodeOp::Return { .. }]
    ));
}

#[test]
fn bounds_truncated_and_unsupported_riscv_instruction_lengths() {
    let one_byte: [u8; 1] = [0x01];
    let truncated_halfword: DecodedBlock = decode_block_for_language(
        Language::RiscVCompressed(RiscVWidth::Rv64),
        &one_byte,
        0x1000,
    );
    assert_eq!(truncated_halfword.consumed, 1);
    assert_eq!(
        truncated_halfword.instructions[0].status,
        DecodeStatus::Truncated
    );

    let incomplete_word: [u8; 3] = [0x03, 0x00, 0x00];
    let truncated_word: DecodedBlock = decode_block_for_language(
        Language::RiscVCompressed(RiscVWidth::Rv64),
        &incomplete_word,
        0x1000,
    );
    assert_eq!(truncated_word.consumed, 3);
    assert_eq!(truncated_word.instructions[0].length, 3);
    assert_eq!(
        truncated_word.instructions[0].status,
        DecodeStatus::Truncated
    );

    let unsupported_six_byte: [u8; 6] = [0x1f, 0x00, 0, 0, 0, 0];
    let unsupported: DecodedBlock = decode_block_for_language(
        Language::RiscVCompressed(RiscVWidth::Rv64),
        &unsupported_six_byte,
        0x1000,
    );
    assert_eq!(unsupported.consumed, 6);
    assert_eq!(unsupported.instructions[0].length, 6);
    assert_eq!(
        unsupported.instructions[0].status,
        DecodeStatus::Unsupported
    );
    assert!(matches!(
        unsupported.instructions[0].ops.as_slice(),
        [PcodeOp::CallOther { name, .. }]
            if name == "riscv_unsupported_instruction_length"
    ));

    let reserved_unbounded: [u8; 5] = [0x7f, 0x70, 1, 2, 3];
    let bounded: DecodedBlock = decode_block_for_language(
        Language::RiscVCompressed(RiscVWidth::Rv64),
        &reserved_unbounded,
        0x1000,
    );
    assert_eq!(bounded.consumed, reserved_unbounded.len());
    assert_eq!(bounded.instructions[0].status, DecodeStatus::Truncated);

    let mut reserved_long: Vec<u8> = vec![0; 300];
    reserved_long[0] = 0x7f;
    reserved_long[1] = 0x70;
    let long: DecodedBlock = decode_block_for_language(
        Language::RiscVCompressed(RiscVWidth::Rv64),
        &reserved_long,
        0x1000,
    );
    assert_eq!(long.consumed, reserved_long.len());
    assert_eq!(long.instructions[0].status, DecodeStatus::Unsupported);
    assert_eq!(long.instructions[0].length, reserved_long.len());
    assert_eq!(long.instructions[0].bytes.len(), 24);
    assert!(long.instructions[0].operands.len() <= 72);
    assert!(matches!(
        long.instructions[0].ops.as_slice(),
        [PcodeOp::CallOther { inputs, .. }]
            if inputs[0].size_bytes == 8 && inputs[0].offset == 300
    ));
}
