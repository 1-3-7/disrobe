use disrobe_sleigh::lifter::{DecodedBlock, Language, decode_block_for_language};
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space};

#[test]
fn decodes_powerpc_integer_alias_memory_and_control_forms() {
    let words: [u32; 12] = [
        0x7c64_2a14,
        0x7cc7_4050,
        0x7d49_5838,
        0x7dac_7378,
        0x7e0f_8a78,
        0x8064_000c,
        0x90a6_fff0,
        0x3960_ff85,
        0x3d80_1234,
        0x4800_002c,
        0x4e80_0020,
        0x6000_0000,
    ];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_be_bytes).collect();
    let block: DecodedBlock = decode_block_for_language(Language::PowerPc32Be, &bytes, 0x1000);
    let mnemonics: Vec<&str> = block
        .instructions
        .iter()
        .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
        .collect();
    assert_eq!(
        mnemonics,
        [
            "add", "subf", "and", "or", "xor", "lwz", "stw", "li", "lis", "b", "blr", "nop"
        ],
        "{block:#?}"
    );
    assert_eq!(block.consumed, bytes.len());
    assert!(block.instructions.iter().all(|instruction: &PcodeInstr| {
        instruction.status == DecodeStatus::Supported && instruction.length == 4
    }));
    assert!(matches!(
        block.instructions[11].ops.as_slice(),
        [PcodeOp::IntOr { .. }]
    ));
    assert!(matches!(
        block.instructions[10].ops.as_slice(),
        [
            PcodeOp::IntAnd {
                output,
                left,
                right,
            },
            PcodeOp::Return {
                target: Some(target)
            }
        ] if output == target
            && output.size_bytes == 4
            && left.space == Space::Register
            && left.offset == 0x1020
            && right.space == Space::Constant
            && right.offset == 0xffff_fffc
    ));
}

#[test]
fn models_powerpc_condition_register_and_bo_bi_branches() {
    let words: [u32; 6] = [
        0x7c03_2000,
        0x2c85_fff9,
        0x4182_001c,
        0x4086_0018,
        0x4200_0014,
        0x4145_0010,
    ];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_be_bytes).collect();
    let block: DecodedBlock = decode_block_for_language(Language::PowerPc32Be, &bytes, 0x2000);
    assert_eq!(
        block
            .instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
            .collect::<Vec<&str>>(),
        ["cmpw", "cmpwi", "beq", "bne", "bdnz", "bdzt"]
    );
    assert!(block.instructions[0].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntOr { output, .. }
            if output.space == Space::Register && output.offset == 0x900)
    }));
    assert!(block.instructions[1].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntOr { output, .. }
            if output.space == Space::Register && output.offset == 0x901)
    }));
    assert!(
        block.instructions[2..4]
            .iter()
            .all(|instruction: &PcodeInstr| {
                instruction
                    .ops
                    .iter()
                    .any(|operation: &PcodeOp| matches!(operation, PcodeOp::CBranch { .. }))
            })
    );
    assert!(
        block.instructions[4..]
            .iter()
            .all(|instruction: &PcodeInstr| {
                instruction.ops.iter().any(|operation: &PcodeOp| {
                    matches!(operation, PcodeOp::IntSub { output, .. }
                if output.space == Space::Register && output.offset == 0x1024)
                })
            })
    );
    assert!(
        block.instructions[5]
            .ops
            .iter()
            .any(|operation: &PcodeOp| matches!(operation, PcodeOp::BoolAnd { .. }))
    );
}

#[test]
fn distinguishes_powerpc_branch_constructor_variants() {
    let cases: [(u32, u64, &str); 5] = [
        (0x4800_0005, 0x1000, "bl"),
        (0x4e80_0820, 0x2000, "bclr"),
        (0x4e80_0420, 0x2800, "bctr"),
        (0x4800_0006, 0x3000, "ba"),
        (0x4800_0007, 0x4000, "bla"),
    ];
    let decoded: Vec<PcodeInstr> = cases
        .into_iter()
        .flat_map(|(word, address, _mnemonic): (u32, u64, &str)| {
            decode_block_for_language(Language::PowerPc32Be, &word.to_be_bytes(), address)
                .instructions
        })
        .collect();
    assert_eq!(decoded.len(), cases.len());
    for (instruction, (_, _, mnemonic)) in decoded.iter().zip(cases) {
        assert_eq!(instruction.mnemonic, mnemonic);
        assert_eq!(instruction.status, DecodeStatus::Supported);
    }
    assert!(matches!(
        decoded[0].ops.as_slice(),
        [PcodeOp::Copy { .. }, PcodeOp::Branch { target }]
            if target.space == Space::Ram && target.offset == 0x1004
    ));
    assert!(matches!(
        decoded[1].ops.as_slice(),
        [
            PcodeOp::IntAnd {
                output,
                left,
                right,
            },
            PcodeOp::BranchIndirect { target }
        ] if output == target
            && output.size_bytes == 4
            && left.space == Space::Register
            && left.offset == 0x1020
            && right.space == Space::Constant
            && right.offset == 0xffff_fffc
    ));
    assert!(matches!(
        decoded[2].ops.as_slice(),
        [
            PcodeOp::IntAnd {
                output,
                left,
                right,
            },
            PcodeOp::BranchIndirect { target }
        ] if output == target
            && output.size_bytes == 4
            && left.space == Space::Register
            && left.offset == 0x1024
            && right.space == Space::Constant
            && right.offset == 0xffff_fffc
    ));
    assert!(matches!(
        decoded[3].ops.as_slice(),
        [PcodeOp::Branch { target }]
            if target.space == Space::Ram && target.offset == 4
    ));
    assert!(matches!(
        decoded[4].ops.as_slice(),
        [PcodeOp::Copy { .. }, PcodeOp::Call { target }]
            if target.space == Space::Ram && target.offset == 4
    ));
}

#[test]
fn applies_powerpc_big_endian_memory_and_r0_base_rules() {
    let words: [u32; 4] = [0x8060_000c, 0x88e8_0003, 0x9920_fffc, 0x7ed5_bc30];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_be_bytes).collect();
    let block: DecodedBlock = decode_block_for_language(Language::PowerPc32Be, &bytes, 0);
    assert!(matches!(
        block.instructions[0].ops.as_slice(),
        [PcodeOp::IntAdd { left, .. }, PcodeOp::Load { output, .. }]
            if left.space == Space::Constant && left.offset == 0 && output.size_bytes == 4
    ));
    assert!(block.instructions[1].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntZext { output, input }
            if output.size_bytes == 4 && input.size_bytes == 1)
    }));
    assert!(block.instructions[2].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Store { value, .. } if value.size_bytes == 1)
    }));
    assert!(block.instructions[3].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntRight { amount, .. } if amount.size_bytes == 4)
    }));

    let reversed: [u8; 4] = 0x7c64_2a14_u32.to_le_bytes();
    let reversed_block: DecodedBlock =
        decode_block_for_language(Language::PowerPc32Be, &reversed, 0);
    assert_ne!(reversed_block.instructions[0].mnemonic, "add");
}

#[test]
fn marks_powerpc_division_edges_and_unmodeled_record_forms() {
    let words: [u32; 2] = [0x7f7c_ebd6, 0x7c64_2a15];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_be_bytes).collect();
    let block: DecodedBlock = decode_block_for_language(Language::PowerPc32Be, &bytes, 0);
    assert_eq!(block.instructions[0].mnemonic, "divw");
    assert_eq!(block.instructions[0].status, DecodeStatus::CallOther);
    assert!(block.instructions[0].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, .. }
            if name == "powerpc_division_edge_cases")
    }));
    assert_eq!(block.instructions[1].mnemonic, "add.");
    assert_eq!(block.instructions[1].status, DecodeStatus::Unsupported);

    let alias_words: [u32; 2] = [0x7c63_23d6, 0x7c83_23d6];
    let alias_bytes: Vec<u8> = alias_words.into_iter().flat_map(u32::to_be_bytes).collect();
    let aliases: DecodedBlock = decode_block_for_language(Language::PowerPc32Be, &alias_bytes, 0);
    for instruction in &aliases.instructions {
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
                PcodeOp::IntSignedDiv { left, right, .. },
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
fn handles_powerpc_fragments_and_wrapping_addresses() {
    let bytes: [u8; 12] = [
        0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
    ];
    for length in 0_usize..=9_usize {
        let block: DecodedBlock = decode_block_for_language(
            Language::PowerPc32Be,
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
}

#[test]
fn decodes_powerpc64_scalar_memory_rotate_compare_and_control_forms() {
    let words: [u32; 12] = [
        0xe864_0000,
        0xf8a6_0008,
        0x7907_4a80,
        0x7949_5b04,
        0x7d2b_6000,
        0x7dad_7040,
        0x7df0_89d2,
        0x7e53_a3d2,
        0x4182_000c,
        0x4200_0008,
        0x4e80_0020,
        0x3ab6_0007,
    ];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_be_bytes).collect();
    let block: DecodedBlock =
        decode_block_for_language(Language::PowerPc64Be, &bytes, 0x1_0000_0000);
    assert_eq!(
        block
            .instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
            .collect::<Vec<&str>>(),
        [
            "ld", "std", "rldicl", "rldicr", "cmpd", "cmpld", "mulld", "divd", "beq", "bdnz",
            "blr", "addi",
        ],
        "{block:#?}"
    );
    assert_eq!(block.consumed, bytes.len());
    assert!(block.instructions.iter().enumerate().all(
        |(index, instruction): (usize, &PcodeInstr)| {
            let expected: DecodeStatus = if index == 7 {
                DecodeStatus::CallOther
            } else {
                DecodeStatus::Supported
            };
            instruction.status == expected && instruction.length == 4
        }
    ));
    assert!(matches!(
        block.instructions[0].ops.as_slice(),
        [PcodeOp::IntAdd { output: pointer, .. }, PcodeOp::Load { output, .. }]
            if pointer.size_bytes == 8 && output.size_bytes == 8
    ));
    assert!(block.instructions[1].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Store { pointer, value, .. }
            if pointer.size_bytes == 8 && value.size_bytes == 8)
    }));
    assert!(
        block.instructions[2..4]
            .iter()
            .all(|instruction: &PcodeInstr| {
                instruction.ops.iter().any(|operation: &PcodeOp| {
                    matches!(operation, PcodeOp::IntAnd { output, right, .. }
                if output.size_bytes == 8
                    && right.space == Space::Unique
                    && right.size_bytes == 8)
                }) && instruction.ops.iter().any(|operation: &PcodeOp| {
                    matches!(operation, PcodeOp::IntLeft { output, input, .. }
                | PcodeOp::IntRight { output, input, .. }
                if output.size_bytes == 8
                    && input.space == Space::Constant
                    && input.offset == u64::MAX)
                })
            })
    );
    assert!(block.instructions[4].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntSignedLess { left, right, .. }
            if left.size_bytes == 8 && right.size_bytes == 8)
    }));
    assert!(block.instructions[5].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntLess { left, right, .. }
            if left.size_bytes == 8 && right.size_bytes == 8)
    }));
    assert!(block.instructions[7].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, inputs, .. }
            if name == "powerpc_division_edge_cases"
                && inputs.iter().all(|input| input.size_bytes == 8))
    }));
    assert!(block.instructions[9].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntSub { output, right, .. }
            if output.size_bytes == 8 && right.size_bytes == 8)
    }));
    assert!(matches!(
        block.instructions[10].ops.as_slice(),
        [
            PcodeOp::IntAnd {
                output,
                left,
                right,
            },
            PcodeOp::Return {
                target: Some(target)
            }
        ] if output == target
            && output.size_bytes == 8
            && left.space == Space::Register
            && left.offset == 0x1040
            && right.space == Space::Constant
            && right.offset == 0xffff_ffff_ffff_fffc
    ));

    let counter_branch: DecodedBlock =
        decode_block_for_language(Language::PowerPc64Be, &0x4e80_0420_u32.to_be_bytes(), 0);
    assert!(matches!(
        counter_branch.instructions[0].ops.as_slice(),
        [
            PcodeOp::IntAnd {
                output,
                left,
                right,
            },
            PcodeOp::BranchIndirect { target }
        ] if output == target
            && output.size_bytes == 8
            && left.space == Space::Register
            && left.offset == 0x1048
            && right.space == Space::Constant
            && right.offset == 0xffff_ffff_ffff_fffc
    ));
}

#[test]
fn powerpc64_branch_targets_preserve_high_address_bits() {
    let branch: [u8; 4] = 0x4800_0004_u32.to_be_bytes();
    let block: DecodedBlock =
        decode_block_for_language(Language::PowerPc64Be, &branch, 0x1_0000_0000);
    assert!(matches!(
        block.instructions[0].ops.as_slice(),
        [PcodeOp::Branch { target }]
            if target.size_bytes == 8 && target.offset == 0x1_0000_0004
    ));
}
