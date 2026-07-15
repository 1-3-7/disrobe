#![allow(clippy::expect_used, clippy::panic)]

use disrobe_nir::{NirFunction, NirOp, SourceLang, ValueOp};
use disrobe_nir_lift::{PcodeLiftConfig, RegisterCell, lower_pcode_block, lower_x86_64};
use disrobe_sleigh::lifter::DecodedBlock;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};

const fn node(space: Space, offset: u64, size_bytes: u32) -> Varnode {
    Varnode {
        offset,
        size_bytes,
        space,
    }
}

fn block(ops: Vec<PcodeOp>) -> DecodedBlock {
    let instruction: PcodeInstr = instruction(0x1000, ops.clone());
    DecodedBlock {
        consumed: 1,
        instructions: vec![instruction],
        ordered_ops: ops,
    }
}

fn instruction(address: u64, ops: Vec<PcodeOp>) -> PcodeInstr {
    PcodeInstr {
        address,
        bytes: vec![0x90],
        length: 1,
        mnemonic: "probe".to_owned(),
        ops,
        operands: String::new(),
        status: DecodeStatus::Supported,
    }
}

#[test]
fn register_aliases_lower_to_subpiece_and_deposit_with_zero_upper() {
    let high_byte: Varnode = node(Space::Register, 1, 1);
    let low_dword: Varnode = node(Space::Register, 0, 4);
    let temporary: Varnode = node(Space::Unique, 0, 1);
    let decoded: DecodedBlock = block(vec![
        PcodeOp::Copy {
            output: high_byte,
            input: node(Space::Constant, 0x5a, 1),
        },
        PcodeOp::Copy {
            output: temporary,
            input: high_byte,
        },
        PcodeOp::Copy {
            output: low_dword,
            input: node(Space::Constant, 0x1122_3344, 4),
        },
    ]);
    let registers: Vec<RegisterCell> = vec![RegisterCell::new(0, 8, "rax", Some(4))];
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::NativeX86, registers);
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "alias_probe", &config).expect("lower p-code");

    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::Subpiece {
                src,
                offset: 1,
                size: 1
            } if src == "rax"
        )
    }));
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::Deposit {
                cell,
                offset: 1,
                size: 1,
                cell_size: 8,
                zero_upper: false,
                ..
            } if cell == "rax"
        )
    }));
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::Deposit {
                cell,
                offset: 0,
                size: 4,
                cell_size: 8,
                zero_upper: true,
                ..
            } if cell == "rax"
        )
    }));
}

#[test]
fn x86_decode_canonicalizes_vector_registers() {
    let lowered: NirFunction =
        lower_x86_64(&[0x0f, 0x28, 0xc1, 0xc3], 0x1000, "vector_move").expect("lower movaps");
    for offset in [0_u32, 4_u32, 8_u32, 12_u32] {
        assert!(lowered.instructions.iter().any(|instruction| {
            matches!(
                &instruction.op,
                NirOp::Subpiece {
                    src,
                    offset: actual_offset,
                    size: 4,
                } if src == "zmm1" && *actual_offset == offset
            )
        }));
        assert!(lowered.instructions.iter().any(|instruction| {
            matches!(
                &instruction.op,
                NirOp::Deposit {
                    cell,
                    offset: actual_offset,
                    size: 4,
                    cell_size: 64,
                    ..
                } if cell == "zmm0" && *actual_offset == offset
            )
        }));
    }
}

#[test]
fn x86_decode_canonicalizes_fs_base() {
    let lowered: NirFunction = lower_x86_64(
        &[0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0xc3],
        0x1000,
        "fs_load",
    )
    .expect("lower fs load");
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::Value { inputs, .. } if inputs.iter().any(|input: &String| input == "fsbase")
        )
    }));
}

#[test]
fn integer_memory_piece_and_effect_ops_preserve_pcode_operands() {
    let left: Varnode = node(Space::Register, 0, 8);
    let right: Varnode = node(Space::Register, 8, 8);
    let sum: Varnode = node(Space::Unique, 0, 8);
    let carry: Varnode = node(Space::Register, 0x200, 1);
    let loaded: Varnode = node(Space::Unique, 8, 4);
    let low: Varnode = node(Space::Unique, 16, 2);
    let joined: Varnode = node(Space::Unique, 24, 4);
    let decoded: DecodedBlock = block(vec![
        PcodeOp::IntAdd {
            output: sum,
            left,
            right,
        },
        PcodeOp::IntCarry {
            output: carry,
            left,
            right,
        },
        PcodeOp::Load {
            output: loaded,
            space: Space::Ram,
            pointer: left,
        },
        PcodeOp::Store {
            space: Space::Ram,
            pointer: right,
            value: loaded,
        },
        PcodeOp::Subpiece {
            output: low,
            input: loaded,
            byte_offset: node(Space::Constant, 1, 4),
        },
        PcodeOp::Piece {
            output: joined,
            high: low,
            low,
        },
        PcodeOp::CallOther {
            name: "x86_probe_reads_writes_mem_v1".to_owned(),
            output: Some(right),
            inputs: vec![left],
        },
    ]);
    let registers: Vec<RegisterCell> = vec![
        RegisterCell::new(0, 8, "rax", Some(4)),
        RegisterCell::new(8, 8, "rcx", Some(4)),
        RegisterCell::new(0x200, 1, "cf", None),
    ];
    let config: PcodeLiftConfig =
        PcodeLiftConfig::new(SourceLang::NativeX86, registers).with_x86_callother_contracts();
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "semantic_probe", &config).expect("lower p-code");

    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::Value {
                op: ValueOp::IntAdd,
                inputs,
                input_sizes,
                size: 8,
            } if inputs == &["rax".to_owned(), "rcx".to_owned()]
                && input_sizes == &[8, 8]
        )
    }));
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::Value {
                op: ValueOp::IntCarry,
                inputs,
                size: 1,
                ..
            } if inputs == &["rax".to_owned(), "rcx".to_owned()]
        )
    }));
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::RawLoad { addr, size: 4 } if addr == "rax"
        )
    }));
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::RawStore { addr, size: 4, .. } if addr == "rcx"
        )
    }));
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::Subpiece {
                offset: 1,
                size: 2,
                ..
            }
        )
    }));
    assert!(
        lowered
            .instructions
            .iter()
            .any(|instruction| { matches!(&instruction.op, NirOp::Piece { size: 4, .. }) })
    );
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::CallOther { effect }
                if effect.name == "x86_probe_reads_writes_mem_v1"
                    && effect.reads == ["rax".to_owned()]
                    && effect.writes == ["rcx".to_owned()]
                    && effect.reads_memory
                    && effect.writes_memory
                    && !effect.unknown_registers
        )
    }));
}

#[test]
fn every_value_pcode_op_maps_to_its_nir_semantic() {
    let out8: Varnode = node(Space::Unique, 0, 8);
    let out4: Varnode = node(Space::Unique, 0, 4);
    let out1: Varnode = node(Space::Unique, 0, 1);
    let left8: Varnode = node(Space::Constant, 0x11, 8);
    let right8: Varnode = node(Space::Constant, 0x22, 8);
    let left1: Varnode = node(Space::Constant, 0, 1);
    let right1: Varnode = node(Space::Constant, 1, 1);
    let amount: Varnode = node(Space::Constant, 3, 4);
    let cases: Vec<(PcodeOp, ValueOp)> = vec![
        (
            PcodeOp::BoolAnd {
                output: out1,
                left: left1,
                right: right1,
            },
            ValueOp::BoolAnd,
        ),
        (
            PcodeOp::BoolNegate {
                output: out1,
                input: left1,
            },
            ValueOp::BoolNegate,
        ),
        (
            PcodeOp::BoolOr {
                output: out1,
                left: left1,
                right: right1,
            },
            ValueOp::BoolOr,
        ),
        (
            PcodeOp::BoolXor {
                output: out1,
                left: left1,
                right: right1,
            },
            ValueOp::BoolXor,
        ),
        (
            PcodeOp::FloatAdd {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::FloatAdd,
        ),
        (
            PcodeOp::FloatDiv {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::FloatDiv,
        ),
        (
            PcodeOp::FloatEqual {
                output: out1,
                left: left8,
                right: right8,
            },
            ValueOp::FloatEqual,
        ),
        (
            PcodeOp::FloatLess {
                output: out1,
                left: left8,
                right: right8,
            },
            ValueOp::FloatLess,
        ),
        (
            PcodeOp::FloatLessEqual {
                output: out1,
                left: left8,
                right: right8,
            },
            ValueOp::FloatLessEqual,
        ),
        (
            PcodeOp::FloatMult {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::FloatMult,
        ),
        (
            PcodeOp::FloatSqrt {
                output: out8,
                input: left8,
            },
            ValueOp::FloatSqrt,
        ),
        (
            PcodeOp::FloatSub {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::FloatSub,
        ),
        (
            PcodeOp::FloatToFloat {
                output: out4,
                input: left8,
            },
            ValueOp::FloatToFloat,
        ),
        (
            PcodeOp::FloatTrunc {
                output: out8,
                input: left8,
            },
            ValueOp::FloatTrunc,
        ),
        (
            PcodeOp::IntToFloat {
                output: out8,
                input: left8,
            },
            ValueOp::IntToFloat,
        ),
        (
            PcodeOp::IntAdd {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::IntAdd,
        ),
        (
            PcodeOp::IntAnd {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::IntAnd,
        ),
        (
            PcodeOp::IntCarry {
                output: out1,
                left: left8,
                right: right8,
            },
            ValueOp::IntCarry,
        ),
        (
            PcodeOp::IntDiv {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::IntDiv,
        ),
        (
            PcodeOp::IntEqual {
                output: out1,
                left: left8,
                right: right8,
            },
            ValueOp::IntEqual,
        ),
        (
            PcodeOp::IntLeft {
                output: out8,
                input: left8,
                amount,
            },
            ValueOp::IntLeft,
        ),
        (
            PcodeOp::IntLess {
                output: out1,
                left: left8,
                right: right8,
            },
            ValueOp::IntLess,
        ),
        (
            PcodeOp::IntLessEqual {
                output: out1,
                left: left8,
                right: right8,
            },
            ValueOp::IntLessEqual,
        ),
        (
            PcodeOp::IntMult {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::IntMult,
        ),
        (
            PcodeOp::IntNegate {
                output: out8,
                input: left8,
            },
            ValueOp::IntNegate,
        ),
        (
            PcodeOp::IntNotEqual {
                output: out1,
                left: left8,
                right: right8,
            },
            ValueOp::IntNotEqual,
        ),
        (
            PcodeOp::IntOr {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::IntOr,
        ),
        (
            PcodeOp::IntRem {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::IntRem,
        ),
        (
            PcodeOp::IntRight {
                output: out8,
                input: left8,
                amount,
            },
            ValueOp::IntRight,
        ),
        (
            PcodeOp::IntSignedBorrow {
                output: out1,
                left: left8,
                right: right8,
            },
            ValueOp::IntSignedBorrow,
        ),
        (
            PcodeOp::IntSignedCarry {
                output: out1,
                left: left8,
                right: right8,
            },
            ValueOp::IntSignedCarry,
        ),
        (
            PcodeOp::IntSignedDiv {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::IntSignedDiv,
        ),
        (
            PcodeOp::IntSignedLess {
                output: out1,
                left: left8,
                right: right8,
            },
            ValueOp::IntSignedLess,
        ),
        (
            PcodeOp::IntSignedLessEqual {
                output: out1,
                left: left8,
                right: right8,
            },
            ValueOp::IntSignedLessEqual,
        ),
        (
            PcodeOp::IntSignedRem {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::IntSignedRem,
        ),
        (
            PcodeOp::IntSignedRight {
                output: out8,
                input: left8,
                amount,
            },
            ValueOp::IntSignedRight,
        ),
        (
            PcodeOp::IntSub {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::IntSub,
        ),
        (
            PcodeOp::IntXor {
                output: out8,
                left: left8,
                right: right8,
            },
            ValueOp::IntXor,
        ),
        (
            PcodeOp::IntSext {
                output: out8,
                input: node(Space::Constant, 0x80, 4),
            },
            ValueOp::IntSext,
        ),
        (
            PcodeOp::IntZext {
                output: out8,
                input: node(Space::Constant, 0x80, 4),
            },
            ValueOp::IntZext,
        ),
    ];
    assert_eq!(cases.len(), 40);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::Unknown, Vec::new());
    for (operation, expected) in cases {
        let name: &'static str = operation.name();
        let lowered: NirFunction = lower_pcode_block(&block(vec![operation]), name, &config)
            .unwrap_or_else(|error: disrobe_nir_lift::LiftError| panic!("lower {name}: {error}"));
        let actual: Option<ValueOp> =
            lowered
                .instructions
                .iter()
                .find_map(|instruction: &disrobe_nir::NirInstr| match instruction.op {
                    NirOp::Value { op, .. } => Some(op),
                    _ => None,
                });
        assert_eq!(actual, Some(expected), "{name}");
    }
}

#[test]
fn x86_dead_flags_are_removed_but_branch_flags_remain_explicit() {
    let zf: Varnode = node(Space::Register, 0x206, 1);
    let comparison: PcodeOp = PcodeOp::IntEqual {
        output: zf,
        left: node(Space::Constant, 1, 8),
        right: node(Space::Constant, 1, 8),
    };
    let dead: DecodedBlock = block(vec![comparison.clone(), PcodeOp::Return { target: None }]);
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64();
    let dead_lowered: NirFunction =
        lower_pcode_block(&dead, "dead_flag", &config).expect("lower dead flag");
    assert!(!dead_lowered.instructions.iter().any(|instruction| {
        matches!(
            instruction.op,
            NirOp::Value {
                op: ValueOp::IntEqual,
                ..
            }
        )
    }));

    let live: DecodedBlock = block(vec![
        comparison,
        PcodeOp::CBranch {
            target: node(Space::Ram, 0x2000, 8),
            condition: zf,
        },
    ]);
    let live_lowered: NirFunction =
        lower_pcode_block(&live, "live_flag", &config).expect("lower live flag");
    assert!(live_lowered.instructions.iter().any(|instruction| {
        matches!(
            instruction.op,
            NirOp::Value {
                op: ValueOp::IntEqual,
                ..
            }
        )
    }));
}

#[test]
fn flag_elimination_retains_only_the_reaching_linear_definition() {
    let zf: Varnode = node(Space::Register, 0x206, 1);
    let decoded: DecodedBlock = block(vec![
        PcodeOp::IntEqual {
            output: zf,
            left: node(Space::Constant, 1, 8),
            right: node(Space::Constant, 1, 8),
        },
        PcodeOp::IntEqual {
            output: zf,
            left: node(Space::Constant, 0, 8),
            right: node(Space::Constant, 1, 8),
        },
        PcodeOp::CBranch {
            target: node(Space::Ram, 0x2000, 8),
            condition: zf,
        },
    ]);
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64();
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "reaching_flag", &config).expect("lower reaching flag");
    let comparisons: Vec<&disrobe_nir::NirInstr> = lowered
        .instructions
        .iter()
        .filter(|instruction: &&disrobe_nir::NirInstr| {
            matches!(
                instruction.op,
                NirOp::Value {
                    op: ValueOp::IntEqual,
                    ..
                }
            )
        })
        .collect();
    assert_eq!(comparisons.len(), 1);
    assert!(matches!(
        &comparisons[0].op,
        NirOp::Value { inputs, .. } if inputs == &["0x0".to_owned(), "0x1".to_owned()]
    ));
}

#[test]
fn flag_elimination_retains_definitions_from_both_join_paths() {
    let zf: Varnode = node(Space::Register, 0x206, 1);
    let instructions: Vec<PcodeInstr> = vec![
        instruction(
            0x1000,
            vec![PcodeOp::CBranch {
                target: node(Space::Ram, 0x1002, 8),
                condition: node(Space::Constant, 1, 1),
            }],
        ),
        instruction(
            0x1001,
            vec![
                PcodeOp::IntEqual {
                    output: zf,
                    left: node(Space::Constant, 1, 8),
                    right: node(Space::Constant, 1, 8),
                },
                PcodeOp::Branch {
                    target: node(Space::Ram, 0x1003, 8),
                },
            ],
        ),
        instruction(
            0x1002,
            vec![PcodeOp::IntEqual {
                output: zf,
                left: node(Space::Constant, 0, 8),
                right: node(Space::Constant, 1, 8),
            }],
        ),
        instruction(
            0x1003,
            vec![PcodeOp::CBranch {
                target: node(Space::Ram, 0x2000, 8),
                condition: zf,
            }],
        ),
    ];
    let ordered_ops: Vec<PcodeOp> = instructions
        .iter()
        .flat_map(|item: &PcodeInstr| item.ops.iter().cloned())
        .collect();
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 4,
        instructions,
        ordered_ops,
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64();
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "joined_flags", &config).expect("lower joined flags");
    assert_eq!(
        lowered
            .instructions
            .iter()
            .filter(|instruction: &&disrobe_nir::NirInstr| {
                matches!(
                    instruction.op,
                    NirOp::Value {
                        op: ValueOp::IntEqual,
                        ..
                    }
                )
            })
            .count(),
        2
    );
}

#[test]
fn flag_elimination_retains_loop_carried_definitions() {
    let zf: Varnode = node(Space::Register, 0x206, 1);
    let instructions: Vec<PcodeInstr> = vec![
        instruction(
            0x1000,
            vec![
                PcodeOp::IntEqual {
                    output: zf,
                    left: node(Space::Constant, 1, 8),
                    right: node(Space::Constant, 1, 8),
                },
                PcodeOp::Branch {
                    target: node(Space::Ram, 0x1001, 8),
                },
            ],
        ),
        instruction(
            0x1001,
            vec![PcodeOp::CBranch {
                target: node(Space::Ram, 0x1003, 8),
                condition: zf,
            }],
        ),
        instruction(
            0x1002,
            vec![
                PcodeOp::IntEqual {
                    output: zf,
                    left: node(Space::Constant, 0, 8),
                    right: node(Space::Constant, 1, 8),
                },
                PcodeOp::Branch {
                    target: node(Space::Ram, 0x1001, 8),
                },
            ],
        ),
        instruction(0x1003, vec![PcodeOp::Return { target: None }]),
    ];
    let ordered_ops: Vec<PcodeOp> = instructions
        .iter()
        .flat_map(|item: &PcodeInstr| item.ops.iter().cloned())
        .collect();
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 4,
        instructions,
        ordered_ops,
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64();
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "loop_flags", &config).expect("lower loop flags");
    assert_eq!(
        lowered
            .instructions
            .iter()
            .filter(|instruction: &&disrobe_nir::NirInstr| {
                matches!(
                    instruction.op,
                    NirOp::Value {
                        op: ValueOp::IntEqual,
                        ..
                    }
                )
            })
            .count(),
        2
    );
}

#[test]
fn flag_elimination_preserves_direct_branch_target_anchors() {
    let zf: Varnode = node(Space::Register, 0x206, 1);
    let instructions: Vec<PcodeInstr> = vec![
        instruction(
            0x1000,
            vec![PcodeOp::CBranch {
                target: node(Space::Ram, 0x1002, 8),
                condition: node(Space::Constant, 1, 1),
            }],
        ),
        instruction(
            0x1001,
            vec![PcodeOp::Branch {
                target: node(Space::Ram, 0x1003, 8),
            }],
        ),
        instruction(
            0x1002,
            vec![PcodeOp::IntEqual {
                output: zf,
                left: node(Space::Constant, 1, 8),
                right: node(Space::Constant, 1, 8),
            }],
        ),
        instruction(0x1003, vec![PcodeOp::Return { target: None }]),
    ];
    let ordered_ops: Vec<PcodeOp> = instructions
        .iter()
        .flat_map(|item: &PcodeInstr| item.ops.iter().cloned())
        .collect();
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 4,
        instructions,
        ordered_ops,
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64();
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "branch_anchor", &config).expect("lower branch anchor");
    assert!(
        lowered
            .instructions
            .iter()
            .any(|instruction| { instruction.address == 0x1002 && instruction.op == NirOp::Nop })
    );
    let blocks: Vec<disrobe_nir::NirBlock> = disrobe_nir::basic_blocks(&lowered);
    assert!(blocks.iter().any(|block| block.start == 0x1002));
    assert!(
        blocks
            .iter()
            .find(|block| block.start == 0x1000)
            .is_some_and(|block| block.successors.contains(&0x1002))
    );
}

#[test]
fn unresolved_indirect_flow_uses_conservative_flag_reaching_definitions() {
    let zf: Varnode = node(Space::Register, 0x206, 1);
    let instructions: Vec<PcodeInstr> = vec![
        instruction(
            0x1000,
            vec![
                PcodeOp::IntEqual {
                    output: zf,
                    left: node(Space::Constant, 1, 8),
                    right: node(Space::Constant, 1, 8),
                },
                PcodeOp::BranchIndirect {
                    target: node(Space::Register, 0, 8),
                },
            ],
        ),
        instruction(
            0x1001,
            vec![PcodeOp::CBranch {
                target: node(Space::Ram, 0x2000, 8),
                condition: zf,
            }],
        ),
    ];
    let ordered_ops: Vec<PcodeOp> = instructions
        .iter()
        .flat_map(|item: &PcodeInstr| item.ops.iter().cloned())
        .collect();
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 2,
        instructions,
        ordered_ops,
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64();
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "indirect_flags", &config).expect("lower indirect flags");
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            instruction.op,
            NirOp::Value {
                op: ValueOp::IntEqual,
                ..
            }
        )
    }));
}

#[test]
fn supported_zero_op_instructions_anchor_direct_branch_targets() {
    let instructions: Vec<PcodeInstr> = vec![
        instruction(
            0x1000,
            vec![PcodeOp::Branch {
                target: node(Space::Ram, 0x1001, 8),
            }],
        ),
        instruction(0x1001, Vec::new()),
        instruction(0x1002, vec![PcodeOp::Return { target: None }]),
    ];
    let ordered_ops: Vec<PcodeOp> = instructions
        .iter()
        .flat_map(|item: &PcodeInstr| item.ops.iter().cloned())
        .collect();
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 3,
        instructions,
        ordered_ops,
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64();
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "zero_op_anchor", &config).expect("lower zero-op anchor");
    assert!(
        lowered
            .instructions
            .iter()
            .any(|instruction| { instruction.address == 0x1001 && instruction.op == NirOp::Nop })
    );
    let blocks: Vec<disrobe_nir::NirBlock> = disrobe_nir::basic_blocks(&lowered);
    assert!(blocks.iter().any(|block| block.start == 0x1001));
}

#[test]
fn supported_zero_op_instructions_remain_machine_boundaries() {
    let instructions: Vec<PcodeInstr> = vec![
        instruction(
            0x1000,
            vec![PcodeOp::Copy {
                output: node(Space::Register, 0, 8),
                input: node(Space::Constant, 1, 8),
            }],
        ),
        instruction(0x1001, Vec::new()),
        instruction(0x1002, vec![PcodeOp::Return { target: None }]),
    ];
    let ordered_ops: Vec<PcodeOp> = instructions
        .iter()
        .flat_map(|item: &PcodeInstr| item.ops.iter().cloned())
        .collect();
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 3,
        instructions,
        ordered_ops,
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64();
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "zero_op_boundary", &config).expect("lower zero-op boundary");
    assert!(
        lowered
            .instructions
            .iter()
            .any(|instruction| { instruction.address == 0x1001 && instruction.op == NirOp::Nop })
    );
}

#[test]
fn non_supported_zero_op_instructions_fail_with_a_typed_error() {
    let mut truncated: PcodeInstr = instruction(0x1000, Vec::new());
    truncated.status = DecodeStatus::Truncated;
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 1,
        instructions: vec![truncated],
        ordered_ops: Vec::new(),
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::NativeX86, Vec::new());
    let error: disrobe_nir_lift::LiftError =
        lower_pcode_block(&decoded, "truncated_semantics", &config)
            .expect_err("reject missing unsupported semantics");
    assert!(matches!(
        error,
        disrobe_nir_lift::LiftError::InvalidPcode { .. }
    ));
}

#[test]
fn opaque_side_effecting_callother_clobbers_unknown_registers_and_memory() {
    let decoded: DecodedBlock = block(vec![PcodeOp::CallOther {
        name: "x86_decode_invalid_side_effecting_v1".to_owned(),
        output: None,
        inputs: Vec::new(),
    }]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::NativeX86, Vec::new());
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "opaque_effect", &config).expect("lower opaque effect");
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::CallOther { effect }
                if effect.reads_memory
                    && effect.writes_memory
                    && effect.unknown_registers
        )
    }));
}

#[test]
fn opaque_callother_keeps_unknown_register_inputs_live() {
    let carry: Varnode = node(Space::Register, 0x200, 1);
    let decoded: DecodedBlock = block(vec![
        PcodeOp::IntCarry {
            output: carry,
            left: node(Space::Constant, u64::MAX, 8),
            right: node(Space::Constant, 1, 8),
        },
        PcodeOp::CallOther {
            name: "x86_decode_invalid_side_effecting_v1".to_owned(),
            output: None,
            inputs: Vec::new(),
        },
    ]);
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64();
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "opaque_flag_input", &config).expect("lower opaque input");
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            instruction.op,
            NirOp::Value {
                op: ValueOp::IntCarry,
                ..
            }
        )
    }));
}

#[test]
fn generic_callother_does_not_trust_x86_effect_name_tokens() {
    let decoded: DecodedBlock = block(vec![PcodeOp::CallOther {
        name: "foreign_probe_pure_v1".to_owned(),
        output: None,
        inputs: Vec::new(),
    }]);
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64();
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "foreign_effect", &config).expect("lower foreign effect");
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::CallOther { effect }
                if effect.reads_memory
                    && effect.writes_memory
                    && effect.unknown_registers
        )
    }));
}

#[test]
fn callother_names_must_be_pseudo_source_identifiers() {
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::NativeX86, Vec::new());
    for name in ["bad name", "effect);injected(", "line\nbreak", "9effect"] {
        let decoded: DecodedBlock = block(vec![PcodeOp::CallOther {
            name: name.to_owned(),
            output: None,
            inputs: Vec::new(),
        }]);
        let error: disrobe_nir_lift::LiftError =
            lower_pcode_block(&decoded, "invalid_effect", &config)
                .expect_err("reject invalid callother name");
        assert!(matches!(
            error,
            disrobe_nir_lift::LiftError::InvalidPcode { .. }
        ));
    }
}

#[test]
fn oversized_callother_inputs_are_rejected() {
    let inputs: Vec<Varnode> = (0_u64..4097)
        .map(|offset: u64| node(Space::Constant, offset, 8))
        .collect();
    let decoded: DecodedBlock = block(vec![PcodeOp::CallOther {
        name: "bounded_effect".to_owned(),
        output: None,
        inputs,
    }]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::Unknown, Vec::new());
    let error: disrobe_nir_lift::LiftError = lower_pcode_block(&decoded, "bounded_effect", &config)
        .expect_err("reject oversized effect inputs");
    assert!(matches!(
        error,
        disrobe_nir_lift::LiftError::InvalidPcode { .. }
    ));
}

#[test]
fn control_flow_recovers_constant_indirect_edges_and_terminal_calls() {
    let indirect: Varnode = node(Space::Unique, 0, 8);
    let condition: Varnode = node(Space::Register, 0x206, 1);
    let pcode_instructions: Vec<PcodeInstr> = vec![
        instruction(
            0x1000,
            vec![
                PcodeOp::Copy {
                    output: indirect,
                    input: node(Space::Constant, 0x1020, 8),
                },
                PcodeOp::BranchIndirect { target: indirect },
            ],
        ),
        instruction(
            0x1001,
            vec![PcodeOp::CBranch {
                target: node(Space::Ram, 0x1030, 8),
                condition,
            }],
        ),
        instruction(
            0x1002,
            vec![PcodeOp::Call {
                target: node(Space::Ram, 0x2000, 8),
            }],
        ),
        instruction(
            0x1003,
            vec![PcodeOp::Call {
                target: node(Space::Ram, 0x3000, 8),
            }],
        ),
        instruction(0x1004, vec![PcodeOp::Return { target: None }]),
    ];
    let ordered_ops: Vec<PcodeOp> = pcode_instructions
        .iter()
        .flat_map(|item: &PcodeInstr| item.ops.iter().cloned())
        .collect();
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 5,
        instructions: pcode_instructions,
        ordered_ops,
    };
    let registers: Vec<RegisterCell> = vec![RegisterCell::new(0x206, 1, "zf", None)];
    let config: PcodeLiftConfig =
        PcodeLiftConfig::new(SourceLang::NativeX86, registers).with_no_return_target(0x2000);
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "control_probe", &config).expect("lower control p-code");

    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            instruction.op,
            NirOp::Branch {
                target: Some(0x1020)
            }
        )
    }));
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            instruction.op,
            NirOp::CondBranch {
                target: Some(0x1030)
            }
        ) && instruction.operands == ["zf".to_owned()]
    }));
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            instruction.op,
            NirOp::NoReturnCall {
                target: Some(0x2000)
            }
        )
    }));
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            instruction.op,
            NirOp::Call {
                target: Some(0x3000)
            }
        )
    }));
    assert!(
        lowered
            .instructions
            .iter()
            .any(|instruction| instruction.op == NirOp::Return)
    );
}

#[test]
fn ram_copy_does_not_fabricate_an_indirect_branch_target() {
    let indirect: Varnode = node(Space::Unique, 0, 8);
    let decoded: DecodedBlock = block(vec![
        PcodeOp::Copy {
            output: indirect,
            input: node(Space::Ram, 0x4040, 8),
        },
        PcodeOp::BranchIndirect { target: indirect },
    ]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::NativeX86, Vec::new());
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "ram_indirect", &config).expect("lower ram branch");
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            &instruction.op,
            NirOp::RawLoad { addr, size: 8 } if addr == "0x4040"
        )
    }));
    assert!(
        lowered
            .instructions
            .iter()
            .any(|instruction| { matches!(instruction.op, NirOp::Branch { target: None }) })
    );
}

#[test]
fn calls_invalidate_register_constants_before_indirect_branch_recovery() {
    let target_register: Varnode = node(Space::Register, 0, 8);
    let decoded: DecodedBlock = block(vec![
        PcodeOp::Copy {
            output: target_register,
            input: node(Space::Constant, 0x4040, 8),
        },
        PcodeOp::Call {
            target: node(Space::Ram, 0x5000, 8),
        },
        PcodeOp::BranchIndirect {
            target: target_register,
        },
    ]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(
        SourceLang::NativeX86,
        vec![RegisterCell::new(0, 8, "rax", Some(4))],
    );
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "call_clobber", &config).expect("lower call clobber");
    assert!(
        lowered
            .instructions
            .iter()
            .any(|instruction| { matches!(instruction.op, NirOp::Branch { target: None }) })
    );
}

#[test]
fn branch_joins_do_not_inherit_one_paths_indirect_target() {
    let target_register: Varnode = node(Space::Register, 0, 8);
    let instructions: Vec<PcodeInstr> = vec![
        instruction(
            0x1000,
            vec![PcodeOp::CBranch {
                target: node(Space::Ram, 0x1003, 8),
                condition: node(Space::Constant, 1, 1),
            }],
        ),
        instruction(
            0x1001,
            vec![PcodeOp::Copy {
                output: target_register,
                input: node(Space::Constant, 0x4040, 8),
            }],
        ),
        instruction(
            0x1002,
            vec![PcodeOp::Branch {
                target: node(Space::Ram, 0x1004, 8),
            }],
        ),
        instruction(
            0x1003,
            vec![PcodeOp::Copy {
                output: target_register,
                input: node(Space::Constant, 0x5050, 8),
            }],
        ),
        instruction(
            0x1004,
            vec![PcodeOp::BranchIndirect {
                target: target_register,
            }],
        ),
    ];
    let ordered_ops: Vec<PcodeOp> = instructions
        .iter()
        .flat_map(|item: &PcodeInstr| item.ops.iter().cloned())
        .collect();
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 5,
        instructions,
        ordered_ops,
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::new(
        SourceLang::NativeX86,
        vec![RegisterCell::new(0, 8, "rax", Some(4))],
    );
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "branch_join", &config).expect("lower branch join");
    let final_branch: &disrobe_nir::NirInstr = lowered
        .instructions
        .iter()
        .rev()
        .find(|item: &&disrobe_nir::NirInstr| matches!(item.op, NirOp::Branch { .. }))
        .expect("find final branch");
    assert!(matches!(final_branch.op, NirOp::Branch { target: None }));
}

#[test]
fn indirect_call_keeps_its_computed_unique_target() {
    let target: Varnode = node(Space::Unique, 0, 8);
    let decoded: DecodedBlock = block(vec![
        PcodeOp::IntAdd {
            output: target,
            left: node(Space::Constant, 0x1000, 8),
            right: node(Space::Constant, 0x20, 8),
        },
        PcodeOp::CallIndirect { target },
    ]);
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64();
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "computed_call", &config).expect("lower computed call");
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            instruction.op,
            NirOp::Value {
                op: ValueOp::IntAdd,
                ..
            }
        )
    }));
    assert!(
        lowered
            .instructions
            .iter()
            .any(|instruction| instruction.op == NirOp::IndirectCall)
    );
}

#[test]
fn unknown_register_effects_invalidate_constants_before_branch_recovery() {
    let target_register: Varnode = node(Space::Register, 0, 8);
    let decoded: DecodedBlock = block(vec![
        PcodeOp::Copy {
            output: target_register,
            input: node(Space::Constant, 0x4040, 8),
        },
        PcodeOp::CallOther {
            name: "unknown_effect".to_owned(),
            output: None,
            inputs: Vec::new(),
        },
        PcodeOp::BranchIndirect {
            target: target_register,
        },
    ]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(
        SourceLang::NativeX86,
        vec![RegisterCell::new(0, 8, "rax", Some(4))],
    );
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "effect_clobber", &config).expect("lower effect clobber");
    assert!(
        lowered
            .instructions
            .iter()
            .any(|instruction| { matches!(instruction.op, NirOp::Branch { target: None }) })
    );
}

#[test]
fn configured_tail_jump_becomes_a_terminal_call() {
    let decoded: DecodedBlock = block(vec![PcodeOp::Branch {
        target: node(Space::Ram, 0x4000, 8),
    }]);
    let config: PcodeLiftConfig =
        PcodeLiftConfig::new(SourceLang::NativeX86, Vec::new()).with_tail_call_site(0x1000);
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "tail_jump", &config).expect("lower tail jump");
    assert!(matches!(
        lowered
            .instructions
            .first()
            .map(|instruction| &instruction.op),
        Some(NirOp::TailCall {
            target: Some(0x4000)
        })
    ));
}

#[test]
fn malformed_widths_fail_with_typed_errors() {
    let decoded: DecodedBlock = block(vec![PcodeOp::IntAdd {
        output: node(Space::Unique, 0, 8),
        left: node(Space::Register, 0, 8),
        right: node(Space::Register, 8, 4),
    }]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(
        SourceLang::NativeX86,
        vec![
            RegisterCell::new(0, 8, "rax", Some(4)),
            RegisterCell::new(8, 8, "rcx", Some(4)),
        ],
    );
    let error: disrobe_nir_lift::LiftError =
        lower_pcode_block(&decoded, "bad_width", &config).expect_err("reject width mismatch");
    assert!(matches!(
        error,
        disrobe_nir_lift::LiftError::InvalidPcode { .. }
    ));
}

#[test]
fn copy_width_mismatch_fails_with_a_typed_error() {
    let decoded: DecodedBlock = block(vec![PcodeOp::Copy {
        output: node(Space::Unique, 0, 8),
        input: node(Space::Constant, 1, 4),
    }]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::Unknown, Vec::new());
    let error: disrobe_nir_lift::LiftError = lower_pcode_block(&decoded, "bad_copy_width", &config)
        .expect_err("reject copy width mismatch");
    assert!(matches!(
        error,
        disrobe_nir_lift::LiftError::InvalidPcode { .. }
    ));
}

#[test]
fn malformed_subpiece_offset_varnode_fails_with_a_typed_error() {
    let decoded: DecodedBlock = block(vec![PcodeOp::Subpiece {
        output: node(Space::Unique, 0, 4),
        input: node(Space::Constant, 0x1122_3344_5566_7788, 8),
        byte_offset: node(Space::Constant, 0, 0),
    }]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::Unknown, Vec::new());
    let error: disrobe_nir_lift::LiftError =
        lower_pcode_block(&decoded, "bad_subpiece_offset", &config)
            .expect_err("reject malformed subpiece offset");
    assert!(matches!(
        error,
        disrobe_nir_lift::LiftError::InvalidPcode { .. }
    ));
}

#[test]
fn subpiece_masks_its_constant_offset_to_the_varnode_width() {
    let decoded: DecodedBlock = block(vec![PcodeOp::Subpiece {
        output: node(Space::Unique, 0, 4),
        input: node(Space::Constant, 0x1122_3344_5566_7788, 8),
        byte_offset: node(Space::Constant, 0x100, 1),
    }]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::Unknown, Vec::new());
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "masked_subpiece", &config).expect("lower masked subpiece");
    assert!(lowered.instructions.iter().any(|instruction| {
        matches!(
            instruction.op,
            NirOp::Subpiece {
                offset: 0,
                size: 4,
                ..
            }
        )
    }));
}

#[test]
fn unique_redefinitions_receive_fresh_names_and_reads_follow_latest() {
    let temporary: Varnode = node(Space::Unique, 0, 8);
    let decoded: DecodedBlock = block(vec![
        PcodeOp::Copy {
            output: temporary,
            input: node(Space::Constant, 1, 8),
        },
        PcodeOp::Copy {
            output: temporary,
            input: node(Space::Constant, 2, 8),
        },
        PcodeOp::Copy {
            output: node(Space::Register, 0, 8),
            input: temporary,
        },
    ]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(
        SourceLang::NativeX86,
        vec![RegisterCell::new(0, 8, "rax", Some(4))],
    );
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "fresh_unique", &config).expect("lower redefinitions");
    let copies: Vec<&disrobe_nir::NirInstr> = lowered
        .instructions
        .iter()
        .filter(|instruction: &&disrobe_nir::NirInstr| matches!(instruction.op, NirOp::Copy { .. }))
        .collect();
    assert_eq!(copies.len(), 3);
    assert_eq!(copies[0].operands[0], "t0");
    assert_eq!(copies[1].operands[0], "t1");
    assert_eq!(copies[2].operands, ["rax".to_owned(), "t1".to_owned()]);
}

#[test]
fn temporary_names_skip_configured_register_names() {
    let temporary: Varnode = node(Space::Unique, 0, 8);
    let decoded: DecodedBlock = block(vec![PcodeOp::Copy {
        output: temporary,
        input: node(Space::Constant, 1, 8),
    }]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(
        SourceLang::Unknown,
        vec![RegisterCell::new(0, 8, "t0", None)],
    );
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "temp_namespace", &config).expect("lower temp namespace");
    assert!(matches!(
        lowered.instructions.first().and_then(|instruction| instruction.operands.first()),
        Some(name) if name == "t1"
    ));
}

#[test]
fn operations_after_machine_terminators_are_rejected() {
    let trailing: PcodeOp = PcodeOp::Copy {
        output: node(Space::Unique, 0, 8),
        input: node(Space::Constant, 1, 8),
    };
    let cases: Vec<(DecodedBlock, PcodeLiftConfig)> = vec![
        (
            block(vec![PcodeOp::Return { target: None }, trailing.clone()]),
            PcodeLiftConfig::new(SourceLang::NativeX86, Vec::new()),
        ),
        (
            block(vec![
                PcodeOp::CBranch {
                    target: node(Space::Ram, 0x2000, 8),
                    condition: node(Space::Constant, 1, 1),
                },
                trailing.clone(),
            ]),
            PcodeLiftConfig::new(SourceLang::NativeX86, Vec::new()),
        ),
        (
            block(vec![
                PcodeOp::Call {
                    target: node(Space::Ram, 0x3000, 8),
                },
                trailing,
            ]),
            PcodeLiftConfig::new(SourceLang::NativeX86, Vec::new()).with_no_return_target(0x3000),
        ),
    ];
    for (decoded, config) in cases {
        let error: disrobe_nir_lift::LiftError =
            lower_pcode_block(&decoded, "trailing_op", &config)
                .expect_err("reject operation after terminator");
        assert!(matches!(
            error,
            disrobe_nir_lift::LiftError::InvalidPcode { .. }
        ));
    }
}

#[test]
fn nonmonotonic_machine_instruction_addresses_are_rejected() {
    let instructions: Vec<PcodeInstr> = vec![
        instruction(0x1001, vec![PcodeOp::Return { target: None }]),
        instruction(0x1000, vec![PcodeOp::Return { target: None }]),
    ];
    let ordered_ops: Vec<PcodeOp> = instructions
        .iter()
        .flat_map(|item: &PcodeInstr| item.ops.iter().cloned())
        .collect();
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 2,
        instructions,
        ordered_ops,
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::NativeX86, Vec::new());
    let error: disrobe_nir_lift::LiftError = lower_pcode_block(&decoded, "unordered", &config)
        .expect_err("reject nonmonotonic addresses");
    assert!(matches!(
        error,
        disrobe_nir_lift::LiftError::InvalidPcode { .. }
    ));
}

#[test]
fn duplicate_register_names_are_rejected() {
    let decoded: DecodedBlock = block(vec![PcodeOp::Return { target: None }]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(
        SourceLang::Unknown,
        vec![
            RegisterCell::new(0, 8, "cell", None),
            RegisterCell::new(8, 8, "CELL", None),
        ],
    );
    let error: disrobe_nir_lift::LiftError =
        lower_pcode_block(&decoded, "duplicate_names", &config)
            .expect_err("reject duplicate register names");
    assert!(matches!(
        error,
        disrobe_nir_lift::LiftError::InvalidPcode { .. }
    ));
}

#[test]
fn branch_target_width_controls_join_invalidation() {
    let target_register: Varnode = node(Space::Register, 0, 8);
    let instructions: Vec<PcodeInstr> = vec![
        instruction(
            0x1000,
            vec![PcodeOp::CBranch {
                target: node(Space::Ram, 0x1003, 8),
                condition: node(Space::Constant, 1, 1),
            }],
        ),
        instruction(
            0x1001,
            vec![PcodeOp::Copy {
                output: target_register,
                input: node(Space::Constant, 0x4040, 8),
            }],
        ),
        instruction(
            0x1002,
            vec![PcodeOp::Branch {
                target: node(Space::Ram, 0x1_1004, 2),
            }],
        ),
        instruction(
            0x1003,
            vec![PcodeOp::Copy {
                output: target_register,
                input: node(Space::Constant, 0x5050, 8),
            }],
        ),
        instruction(
            0x1004,
            vec![PcodeOp::CBranch {
                target: target_register,
                condition: node(Space::Constant, 1, 1),
            }],
        ),
    ];
    let ordered_ops: Vec<PcodeOp> = instructions
        .iter()
        .flat_map(|item: &PcodeInstr| item.ops.iter().cloned())
        .collect();
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 5,
        instructions,
        ordered_ops,
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::new(
        SourceLang::NativeX86,
        vec![RegisterCell::new(0, 8, "rax", Some(4))],
    );
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "masked_join", &config).expect("lower masked join");
    let final_branch: &disrobe_nir::NirInstr = lowered
        .instructions
        .iter()
        .rev()
        .find(|item: &&disrobe_nir::NirInstr| matches!(item.op, NirOp::CondBranch { .. }))
        .expect("find final branch");
    assert!(matches!(
        final_branch.op,
        NirOp::CondBranch { target: None }
    ));
}

#[test]
fn zero_length_supported_instructions_are_rejected() {
    let mut zero_length: PcodeInstr = instruction(0x1000, vec![PcodeOp::Return { target: None }]);
    zero_length.bytes.clear();
    zero_length.length = 0;
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 0,
        ordered_ops: zero_length.ops.clone(),
        instructions: vec![zero_length],
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::NativeX86, Vec::new());
    let error: disrobe_nir_lift::LiftError = lower_pcode_block(&decoded, "zero_length", &config)
        .expect_err("reject zero-length supported instruction");
    assert!(matches!(
        error,
        disrobe_nir_lift::LiftError::InvalidPcode { .. }
    ));
}

#[test]
fn overlapping_machine_instruction_spans_are_rejected() {
    let mut first: PcodeInstr = instruction(0x1000, Vec::new());
    first.bytes = vec![0x90, 0x90];
    first.length = 2;
    let second: PcodeInstr = instruction(0x1001, vec![PcodeOp::Return { target: None }]);
    let instructions: Vec<PcodeInstr> = vec![first, second];
    let ordered_ops: Vec<PcodeOp> = instructions
        .iter()
        .flat_map(|item: &PcodeInstr| item.ops.iter().cloned())
        .collect();
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 3,
        instructions,
        ordered_ops,
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::NativeX86, Vec::new());
    let error: disrobe_nir_lift::LiftError = lower_pcode_block(&decoded, "overlap", &config)
        .expect_err("reject overlapping instructions");
    assert!(matches!(
        error,
        disrobe_nir_lift::LiftError::InvalidPcode { .. }
    ));
}

#[test]
fn register_names_must_be_pseudo_source_identifiers() {
    let decoded: DecodedBlock = block(vec![PcodeOp::Return { target: None }]);
    for name in ["bad name", "rax);injected(", "line\nbreak", "9cell"] {
        let config: PcodeLiftConfig = PcodeLiftConfig::new(
            SourceLang::Unknown,
            vec![RegisterCell::new(0, 8, name, None)],
        );
        let error: disrobe_nir_lift::LiftError =
            lower_pcode_block(&decoded, "invalid_name", &config)
                .expect_err("reject invalid register name");
        assert!(matches!(
            error,
            disrobe_nir_lift::LiftError::InvalidPcode { .. }
        ));
    }
}

#[test]
fn function_names_must_be_pseudo_source_identifiers() {
    let decoded: DecodedBlock = block(vec![PcodeOp::Return { target: None }]);
    let config: PcodeLiftConfig = PcodeLiftConfig::new(SourceLang::Unknown, Vec::new());
    for name in ["bad name", "function()", "line\nbreak", "9function"] {
        let error: disrobe_nir_lift::LiftError =
            lower_pcode_block(&decoded, name, &config).expect_err("reject invalid function name");
        assert!(matches!(
            error,
            disrobe_nir_lift::LiftError::InvalidPcode { .. }
        ));
    }
}

#[test]
fn configured_return_values_must_be_pseudo_source_identifiers() {
    let decoded: DecodedBlock = block(vec![PcodeOp::Return { target: None }]);
    let config: PcodeLiftConfig =
        PcodeLiftConfig::new(SourceLang::Unknown, Vec::new()).with_return_value("rax);injected(");
    let error: disrobe_nir_lift::LiftError =
        lower_pcode_block(&decoded, "invalid_return_value", &config)
            .expect_err("reject invalid return value");
    assert!(matches!(
        error,
        disrobe_nir_lift::LiftError::InvalidPcode { .. }
    ));
}
