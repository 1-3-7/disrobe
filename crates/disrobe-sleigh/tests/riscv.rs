use std::collections::BTreeMap;

use disrobe_sleigh::lifter::{DecodedBlock, Language, RiscVWidth, decode_block_for_language};
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};

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
fn models_riscv_division_edges_and_marks_unmodeled_same_opcode_constructors() {
    let words: [u32; 3] = [0x0288_c833, 0x0339_64b3, 0x0015_a513];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let block: DecodedBlock =
        decode_block_for_language(Language::RiscV(RiscVWidth::Rv32), &bytes, 0x2000);
    assert_eq!(block.instructions[0].status, DecodeStatus::Supported);
    assert_eq!(block.instructions[1].status, DecodeStatus::Supported);
    assert!(
        block.instructions[..2]
            .iter()
            .all(|instruction: &PcodeInstr| { !instruction.ops.iter().any(PcodeOp::is_callother) })
    );
    assert_eq!(block.instructions[2].mnemonic, "slti");
    assert_eq!(block.instructions[2].status, DecodeStatus::Unsupported);

    let alias_words: [u32; 2] = [0x02b5_4533, 0x02b5_65b3];
    let alias_bytes: Vec<u8> = alias_words.into_iter().flat_map(u32::to_le_bytes).collect();
    let aliases: DecodedBlock =
        decode_block_for_language(Language::RiscV(RiscVWidth::Rv32), &alias_bytes, 0);
    for instruction in &aliases.instructions {
        assert_eq!(instruction.status, DecodeStatus::Supported);
        assert!(!instruction.ops.iter().any(PcodeOp::is_callother));
        assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(
                operation,
                PcodeOp::IntSignedDiv { right, .. } | PcodeOp::IntSignedRem { right, .. }
                    if right.space == Space::Unique
            )
        }));
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
    assert!(
        base.instructions[..2]
            .iter()
            .all(|instruction: &PcodeInstr| {
                instruction.status == DecodeStatus::CallOther
                    && instruction.ops.iter().any(|operation: &PcodeOp| {
                        matches!(operation, PcodeOp::CallOther { name, .. }
                    if name == "riscv_instruction_address_alignment")
                    })
            })
    );
    assert!(
        base.instructions[2..]
            .iter()
            .all(|instruction: &PcodeInstr| {
                instruction.status == DecodeStatus::CallOther
                    && instruction.ops.iter().any(|operation: &PcodeOp| {
                        matches!(operation, PcodeOp::CallOther { name, .. }
                    if name == "riscv_instruction_address_alignment")
                    })
            })
    );
    assert!(
        base.instructions[2]
            .ops
            .iter()
            .any(|operation: &PcodeOp| { matches!(operation, PcodeOp::BranchIndirect { .. }) })
    );
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
fn decodes_riscv_f_d_zicsr_and_zifencei_forms() {
    let words: [u32; 36] = [
        0x00c5_2007,
        0xfe15_a827,
        0x0041_8153,
        0x0873_12d3,
        0x10c5_a553,
        0x18f7_36d3,
        0xf005_0053,
        0xe000_85d3,
        0xd006_0153,
        0xc001_96d3,
        0x3862_8243,
        0xa0b5_2753,
        0xa0d6_17d3,
        0xa0f7_0853,
        0x5808_8853,
        0x0186_3e07,
        0xffd6_b027,
        0x028f_8f53,
        0x0ab5_14d3,
        0x12e6_a653,
        0x1b18_37d3,
        0x4209_8953,
        0x401a_8a53,
        0xcb8b_8b43,
        0xa3bd_28d3,
        0xa3de_1453,
        0xa3ff_04d3,
        0x5a05_8553,
        0x3055_9573,
        0xc006_a673,
        0x3407_b773,
        0x3411_d873,
        0x3422_68f3,
        0x3432_f473,
        0x0330_000f,
        0x0000_100f,
    ];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    for width in [RiscVWidth::Rv32, RiscVWidth::Rv64] {
        let block: DecodedBlock = decode_block_for_language(Language::RiscV(width), &bytes, 0x4000);
        assert_eq!(block.consumed, bytes.len());
        assert_eq!(
            block
                .instructions
                .iter()
                .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
                .collect::<Vec<&str>>(),
            [
                "flw", "fsw", "fadd.s", "fsub.s", "fmul.s", "fdiv.s", "fmv.w.x", "fmv.x.w",
                "fcvt.s.w", "fcvt.w.s", "fmadd.s", "feq.s", "flt.s", "fle.s", "fsqrt.s", "fld",
                "fsd", "fadd.d", "fsub.d", "fmul.d", "fdiv.d", "fcvt.d.s", "fcvt.s.d", "fmadd.d",
                "feq.d", "flt.d", "fle.d", "fsqrt.d", "csrrw", "csrrs", "csrrc", "csrrwi",
                "csrrsi", "csrrci", "fence", "fence.i",
            ],
            "{block:#?}"
        );
        assert!(block.instructions.iter().all(|instruction: &PcodeInstr| {
            instruction.status.matched_constructor() && instruction.length == 4
        }));
        assert!(
            block.instructions[2..6]
                .iter()
                .all(|instruction: &PcodeInstr| {
                    instruction.ops.iter().any(|operation: &PcodeOp| {
                matches!(
                    operation.name(),
                    "FLOAT_ADD" | "FLOAT_SUB" | "FLOAT_MULT" | "FLOAT_DIV"
                )
            }) && instruction.ops.iter().any(|operation: &PcodeOp| {
                matches!(operation, PcodeOp::CallOther { name, .. } if name == "riscv_fp_binary_v1")
            })
                })
        );
        assert!(matches!(
            block.instructions[2].ops.iter().find(|operation: &&PcodeOp| {
                matches!(operation, PcodeOp::CallOther { name, .. }
                    if name == "riscv_fp_binary_v1")
            }),
            Some(PcodeOp::CallOther {
                output: Some(output),
                inputs,
                ..
            }) if output.size_bytes == 4
                && inputs.len() == 6
                && inputs[0].offset == 0
                && inputs[1].offset == 4
                && inputs[2].offset == 0
                && inputs[3].size_bytes == 4
                && inputs[4].size_bytes == 4
                && inputs[5].size_bytes == 4
        ));
        assert!(block.instructions[10].ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::CallOther { name, .. } if name == "riscv_fp_fused_v1")
        }));
        for (indices, name, input_count) in [
            (
                &[2_usize, 3, 4, 5, 17, 18, 19, 20][..],
                "riscv_fp_binary_v1",
                6_usize,
            ),
            (&[8_usize, 9, 21, 22][..], "riscv_fp_convert_v1", 6_usize),
            (&[10_usize, 23][..], "riscv_fp_fused_v1", 6_usize),
            (
                &[11_usize, 12, 13, 24, 25, 26][..],
                "riscv_fp_compare_v1",
                5_usize,
            ),
            (&[14_usize, 27][..], "riscv_fp_unary_v1", 5_usize),
        ] {
            assert!(indices.iter().all(|index: &usize| {
                block.instructions[*index]
                    .ops
                    .iter()
                    .any(|operation: &PcodeOp| {
                        matches!(
                            operation,
                            PcodeOp::CallOther {
                                name: contract_name,
                                output: Some(_),
                                inputs,
                            } if contract_name == name && inputs.len() == input_count
                        )
                    })
            }));
        }
        assert!(
            block.instructions[10]
                .ops
                .iter()
                .all(|operation: &PcodeOp| {
                    !matches!(
                        operation,
                        PcodeOp::FloatMult { .. } | PcodeOp::FloatAdd { .. }
                    )
                })
        );
        assert!(
            block.instructions[28..34]
                .iter()
                .all(|instruction: &PcodeInstr| {
                    matches!(
                        instruction.ops.as_slice(),
                        [PcodeOp::CallOther { name, inputs, .. }]
                            if name == "riscv_csr_v1" && inputs.len() == 5
                    )
                })
        );
        assert!(
            block.instructions[34..]
                .iter()
                .all(|instruction: &PcodeInstr| {
                    matches!(
                        instruction.ops.as_slice(),
                        [PcodeOp::CallOther { name, output: None, inputs }]
                            if name == "riscv_fence_v1" && inputs.len() == 4
                    )
                })
        );
        assert!(matches!(
            block.instructions[34].ops.as_slice(),
            [PcodeOp::CallOther { inputs, .. }]
                if inputs.iter().map(|input: &Varnode| input.offset).collect::<Vec<u64>>()
                    == [0, 3, 3, 0]
        ));
        assert!(matches!(
            block.instructions[35].ops.as_slice(),
            [PcodeOp::CallOther { inputs, .. }]
                if inputs.iter().map(|input: &Varnode| input.offset).collect::<Vec<u64>>()
                    == [1, 0, 0, 0]
        ));
    }
}

#[test]
fn models_riscv_csr_read_and_write_suppression() {
    let words: [u32; 4] = [0x3055_9073, 0x3050_2573, 0x3050_5073, 0x3050_6573];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let block: DecodedBlock =
        decode_block_for_language(Language::RiscVCompressed(RiscVWidth::Rv64), &bytes, 0);
    assert_eq!(
        block
            .instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
            .collect::<Vec<&str>>(),
        ["csrrw", "csrrs", "csrrwi", "csrrsi"]
    );
    let contracts: Vec<(&Option<Varnode>, &Vec<Varnode>)> = block
        .instructions
        .iter()
        .filter_map(
            |instruction: &PcodeInstr| match instruction.ops.as_slice() {
                [PcodeOp::CallOther { output, inputs, .. }] => Some((output, inputs)),
                _ => None,
            },
        )
        .collect();
    assert_eq!(contracts.len(), 4);
    assert!(contracts[0].0.is_none());
    assert_eq!((contracts[0].1[3].offset, contracts[0].1[4].offset), (0, 1));
    assert!(contracts[1].0.is_some());
    assert_eq!((contracts[1].1[3].offset, contracts[1].1[4].offset), (1, 0));
    assert!(contracts[2].0.is_none());
    assert_eq!((contracts[2].1[3].offset, contracts[2].1[4].offset), (0, 1));
    assert!(contracts[3].0.is_some());
    assert_eq!((contracts[3].1[3].offset, contracts[3].1[4].offset), (1, 0));
}

#[test]
fn lifts_compressed_riscv_float_memory_forms() {
    let rv32_bytes: Vec<u8> = [0x6548_u16, 0xa908_u16]
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect();
    let rv32: DecodedBlock =
        decode_block_for_language(Language::RiscVCompressed(RiscVWidth::Rv32), &rv32_bytes, 0);
    assert_eq!(
        rv32.instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
            .collect::<Vec<&str>>(),
        ["flw", "fsd"]
    );
    assert!(rv32.instructions.iter().all(|instruction: &PcodeInstr| {
        instruction.status == DecodeStatus::Supported && instruction.length == 2
    }));
    assert!(rv32.instructions[0].ops.iter().any(
        |operation: &PcodeOp| matches!(operation, PcodeOp::Piece { high, .. }
            if high.space == Space::Constant && high.offset == u64::from(u32::MAX))
    ));
    assert!(rv32.instructions[1].ops.iter().any(
        |operation: &PcodeOp| matches!(operation, PcodeOp::Store { value, .. }
            if value.size_bytes == 8)
    ));

    let rv64: DecodedBlock = decode_block_for_language(
        Language::RiscVCompressed(RiscVWidth::Rv64),
        &0xa908_u16.to_le_bytes(),
        0,
    );
    assert_eq!(rv64.instructions[0].mnemonic, "fsd");
    assert_eq!(rv64.instructions[0].status, DecodeStatus::Supported);
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

#[test]
fn executes_total_riscv_division_vectors() {
    for width in [RiscVWidth::Rv32, RiscVWidth::Rv64] {
        let size_bytes: u32 = match width {
            RiscVWidth::Rv32 => 4,
            RiscVWidth::Rv64 => 8,
        };
        let mask: u64 = test_mask(size_bytes);
        let minimum: u64 = 1_u64 << size_bytes.saturating_mul(8).saturating_sub(1);
        let dividend: u64 = 0x1234_5678_9abc_def0 & mask;
        for (function, zero_expected, overflow_expected) in [
            (4_u32, mask, minimum),
            (5_u32, mask, 0_u64),
            (6_u32, dividend, 0_u64),
            (7_u32, dividend, 0_u64),
        ] {
            let operations: Vec<PcodeOp> = division_operations(width, function);
            let zero_result: Option<u64> = execute_integer_pcode(
                &operations,
                width,
                BTreeMap::from([(11_u32, dividend), (12_u32, 0_u64)]),
            );
            assert_eq!(zero_result, Some(zero_expected));
            if matches!(function, 4 | 6) {
                let overflow_result: Option<u64> = execute_integer_pcode(
                    &operations,
                    width,
                    BTreeMap::from([(11_u32, minimum), (12_u32, mask)]),
                );
                assert_eq!(overflow_result, Some(overflow_expected));
            }
        }

        let signed_division: Vec<PcodeOp> = division_operations(width, 4);
        let signed_remainder: Vec<PcodeOp> = division_operations(width, 6);
        let unsigned_division: Vec<PcodeOp> = division_operations(width, 5);
        let unsigned_remainder: Vec<PcodeOp> = division_operations(width, 7);
        let mut state: u64 = 0x4d59_5df4_d0f3_3173 & mask;
        for _index in 0_u32..64_u32 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1)
                & mask;
            let left: u64 = state;
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1)
                & mask;
            let right: u64 = state | 1;
            let unsigned_quotient: u64 = left / right;
            let expected_unsigned_remainder: u64 = left % right;
            assert_eq!(
                execute_integer_pcode(
                    &unsigned_division,
                    width,
                    BTreeMap::from([(11_u32, left), (12_u32, right)]),
                ),
                Some(unsigned_quotient)
            );
            assert_eq!(
                execute_integer_pcode(
                    &unsigned_remainder,
                    width,
                    BTreeMap::from([(11_u32, left), (12_u32, right)]),
                ),
                Some(expected_unsigned_remainder)
            );
            let signed_left: i128 = signed_test_value(left, size_bytes);
            let signed_right: i128 = signed_test_value(right, size_bytes);
            if signed_right != 0 && !(left == minimum && right == mask) {
                let quotient: i128 = signed_left / signed_right;
                let remainder: i128 = signed_left % signed_right;
                assert_eq!(
                    execute_integer_pcode(
                        &signed_division,
                        width,
                        BTreeMap::from([(11_u32, left), (12_u32, right)]),
                    ),
                    Some(encoded_test_value(quotient, size_bytes))
                );
                assert_eq!(
                    execute_integer_pcode(
                        &signed_remainder,
                        width,
                        BTreeMap::from([(11_u32, left), (12_u32, right)]),
                    ),
                    Some(encoded_test_value(remainder, size_bytes))
                );
            }
        }
    }
}

#[test]
fn models_riscv_single_nan_boxes_and_payload_transfers() {
    let arithmetic: DecodedBlock = decode_block_for_language(
        Language::RiscVCompressed(RiscVWidth::Rv64),
        &0x0041_8153_u32.to_le_bytes(),
        0,
    );
    let left_register: Varnode = test_float_register(3);
    let right_register: Varnode = test_float_register(4);
    let valid: Option<(u64, u64)> = evaluate_float_operands(
        &arithmetic.instructions[0].ops,
        BTreeMap::from([
            (left_register, 0xffff_ffff_3f80_0000),
            (right_register, 0xffff_ffff_4000_0000),
        ]),
    );
    assert_eq!(valid, Some((0x3f80_0000, 0x4000_0000)));
    let invalid: Option<(u64, u64)> = evaluate_float_operands(
        &arithmetic.instructions[0].ops,
        BTreeMap::from([
            (left_register, 0x0000_0000_7fa1_2345),
            (right_register, 0xffff_fffe_3f80_0000),
        ]),
    );
    assert_eq!(invalid, Some((0x7fc0_0000, 0x7fc0_0000)));
    assert!(matches!(
        arithmetic.instructions[0].ops.last(),
        Some(PcodeOp::Piece { high, .. })
            if high.space == Space::Constant && high.offset == u64::from(u32::MAX)
    ));

    let to_float: DecodedBlock = decode_block_for_language(
        Language::RiscVCompressed(RiscVWidth::Rv64),
        &0xf005_0053_u32.to_le_bytes(),
        0,
    );
    assert!(matches!(
        to_float.instructions[0].ops.as_slice(),
        [PcodeOp::Piece { high, low, .. }]
            if high.offset == u64::from(u32::MAX)
                && low.space == Space::Register
                && low.size_bytes == 4
    ));
    let to_integer: DecodedBlock = decode_block_for_language(
        Language::RiscVCompressed(RiscVWidth::Rv64),
        &0xe000_85d3_u32.to_le_bytes(),
        0,
    );
    assert!(matches!(
        to_integer.instructions[0].ops.as_slice(),
        [PcodeOp::IntSext { input, output }]
            if input.space == Space::Register
                && input.size_bytes == 4
                && output.size_bytes == 8
    ));
}

fn division_operations(width: RiscVWidth, function: u32) -> Vec<PcodeOp> {
    let word: u32 =
        (1_u32 << 25) | (12_u32 << 20) | (11_u32 << 15) | (function << 12) | (10_u32 << 7) | 0x33;
    let block: DecodedBlock =
        decode_block_for_language(Language::RiscV(width), &word.to_le_bytes(), 0);
    assert_eq!(block.instructions.len(), 1);
    assert_eq!(block.instructions[0].status, DecodeStatus::Supported);
    block.instructions[0].ops.clone()
}

fn evaluate_float_operands(
    operations: &[PcodeOp],
    mut values: BTreeMap<Varnode, u64>,
) -> Option<(u64, u64)> {
    for operation in operations {
        let calculated: Option<(Varnode, u64)> = match operation {
            PcodeOp::BoolNegate { output, input } => {
                Some((*output, u64::from(read_test_value(*input, &values)? == 0)))
            }
            PcodeOp::FloatAdd { left, right, .. } => {
                return Some((
                    read_test_value(*left, &values)?,
                    read_test_value(*right, &values)?,
                ));
            }
            PcodeOp::IntAdd {
                output,
                left,
                right,
            } => Some((
                *output,
                read_test_value(*left, &values)?.wrapping_add(read_test_value(*right, &values)?)
                    & test_mask(output.size_bytes),
            )),
            PcodeOp::IntEqual {
                output,
                left,
                right,
            } => Some((
                *output,
                u64::from(read_test_value(*left, &values)? == read_test_value(*right, &values)?),
            )),
            PcodeOp::IntMult {
                output,
                left,
                right,
            } => Some((
                *output,
                read_test_value(*left, &values)?.wrapping_mul(read_test_value(*right, &values)?)
                    & test_mask(output.size_bytes),
            )),
            PcodeOp::IntZext { output, input } => {
                Some((*output, read_test_value(*input, &values)?))
            }
            PcodeOp::Subpiece {
                output,
                input,
                byte_offset,
            } => {
                let shift: u32 = u32::try_from(read_test_value(*byte_offset, &values)?)
                    .ok()?
                    .saturating_mul(8);
                Some((
                    *output,
                    read_test_value(*input, &values)?
                        .checked_shr(shift)
                        .unwrap_or(0)
                        & test_mask(output.size_bytes),
                ))
            }
            _ => None,
        };
        if let Some((output, value)) = calculated {
            let previous: Option<u64> = values.insert(output, value & test_mask(output.size_bytes));
            assert!(previous.is_none());
        }
    }
    None
}

fn execute_integer_pcode(
    operations: &[PcodeOp],
    width: RiscVWidth,
    registers: BTreeMap<u32, u64>,
) -> Option<u64> {
    let size_bytes: u32 = match width {
        RiscVWidth::Rv32 => 4,
        RiscVWidth::Rv64 => 8,
    };
    let mut values: BTreeMap<Varnode, u64> = BTreeMap::new();
    for (index, value) in registers {
        let node: Varnode = test_register(index, size_bytes);
        let previous: Option<u64> = values.insert(node, value & test_mask(size_bytes));
        assert!(previous.is_none());
    }
    for operation in operations {
        let (output, value): (Varnode, u64) = match operation {
            PcodeOp::BoolAnd {
                output,
                left,
                right,
            }
            | PcodeOp::IntAnd {
                output,
                left,
                right,
            } => (
                *output,
                read_test_value(*left, &values)? & read_test_value(*right, &values)?,
            ),
            PcodeOp::BoolOr {
                output,
                left,
                right,
            }
            | PcodeOp::IntOr {
                output,
                left,
                right,
            } => (
                *output,
                read_test_value(*left, &values)? | read_test_value(*right, &values)?,
            ),
            PcodeOp::Copy { output, input } | PcodeOp::IntZext { output, input } => {
                (*output, read_test_value(*input, &values)?)
            }
            PcodeOp::IntDiv {
                output,
                left,
                right,
            } => {
                let divisor: u64 = read_test_value(*right, &values)?;
                let result: u64 = read_test_value(*left, &values)?.checked_div(divisor)?;
                (*output, result)
            }
            PcodeOp::IntEqual {
                output,
                left,
                right,
            } => (
                *output,
                u64::from(read_test_value(*left, &values)? == read_test_value(*right, &values)?),
            ),
            PcodeOp::IntNegate { output, input } => (
                *output,
                !read_test_value(*input, &values)? & test_mask(output.size_bytes),
            ),
            PcodeOp::IntRem {
                output,
                left,
                right,
            } => {
                let divisor: u64 = read_test_value(*right, &values)?;
                let result: u64 = read_test_value(*left, &values)?.checked_rem(divisor)?;
                (*output, result)
            }
            PcodeOp::IntSignedDiv {
                output,
                left,
                right,
            } => {
                let dividend: i128 =
                    signed_test_value(read_test_value(*left, &values)?, left.size_bytes);
                let divisor: i128 =
                    signed_test_value(read_test_value(*right, &values)?, right.size_bytes);
                let result: i128 = dividend.checked_div(divisor)?;
                (*output, encoded_test_value(result, output.size_bytes))
            }
            PcodeOp::IntSignedRem {
                output,
                left,
                right,
            } => {
                let dividend: i128 =
                    signed_test_value(read_test_value(*left, &values)?, left.size_bytes);
                let divisor: i128 =
                    signed_test_value(read_test_value(*right, &values)?, right.size_bytes);
                let result: i128 = dividend.checked_rem(divisor)?;
                (*output, encoded_test_value(result, output.size_bytes))
            }
            PcodeOp::IntSub {
                output,
                left,
                right,
            } => (
                *output,
                read_test_value(*left, &values)?.wrapping_sub(read_test_value(*right, &values)?)
                    & test_mask(output.size_bytes),
            ),
            _ => return None,
        };
        let previous: Option<u64> = values.insert(output, value & test_mask(output.size_bytes));
        assert!(previous.is_none());
    }
    values.get(&test_register(10, size_bytes)).copied()
}

fn read_test_value(node: Varnode, values: &BTreeMap<Varnode, u64>) -> Option<u64> {
    if node.space == Space::Constant {
        Some(node.offset & test_mask(node.size_bytes))
    } else {
        values.get(&node).copied()
    }
}

fn test_register(index: u32, size_bytes: u32) -> Varnode {
    Varnode {
        offset: 0x2000_u64 + u64::from(index) * u64::from(size_bytes),
        size_bytes,
        space: Space::Register,
    }
}

fn test_float_register(index: u32) -> Varnode {
    Varnode {
        offset: 0x3000_u64 + u64::from(index) * 8,
        size_bytes: 8,
        space: Space::Register,
    }
}

fn test_mask(size_bytes: u32) -> u64 {
    if size_bytes == 8 {
        u64::MAX
    } else {
        1_u64
            .checked_shl(size_bytes.saturating_mul(8))
            .unwrap_or(0)
            .saturating_sub(1)
    }
}

fn signed_test_value(value: u64, size_bytes: u32) -> i128 {
    if size_bytes == 8 {
        i128::from(i64::from_ne_bytes(value.to_ne_bytes()))
    } else {
        let word: u32 = u32::try_from(value & u64::from(u32::MAX)).unwrap_or(0);
        i128::from(i32::from_ne_bytes(word.to_ne_bytes()))
    }
}

fn encoded_test_value(value: i128, size_bytes: u32) -> u64 {
    let signed: i64 = i64::try_from(value).unwrap_or(0);
    u64::from_ne_bytes(signed.to_ne_bytes()) & test_mask(size_bytes)
}
