use disrobe_pass_native::aarch64::lift::{
    A64Function, AtomicDestination, AtomicOp, AtomicOrdering, BasicBlock, Expr, FpBinaryOp,
    FpCondition, FpExpr, FpFlagSource, FpRounding, FpType, LiftOutcome, Location, Predicate,
    Statement, Target, Terminator, Width, lift,
};
use disrobe_pass_native::aarch64::{A64Opcode, DecodeClass, DecodeError, MCInst, Operand, decode};

fn decode_words(words: &[u32], base: u64) -> Vec<MCInst> {
    let mut instructions: Vec<MCInst> = Vec::with_capacity(words.len());
    for (index, word) in words.iter().enumerate() {
        let index_value: u64 = match u64::try_from(index) {
            Ok(value) => value,
            Err(_) => return Vec::new(),
        };
        let offset: u64 = match index_value.checked_mul(4) {
            Some(value) => value,
            None => return Vec::new(),
        };
        let va: u64 = match base.checked_add(offset) {
            Some(value) => value,
            None => return Vec::new(),
        };
        let decoded: Result<MCInst, DecodeError> = decode(&word.to_le_bytes(), va);
        let instruction: MCInst = match decoded {
            Ok(value) => value,
            Err(_) => return Vec::new(),
        };
        instructions.push(instruction);
    }
    instructions
}

fn complete(outcome: LiftOutcome) -> A64Function {
    match outcome {
        LiftOutcome::Complete(function) => function,
        LiftOutcome::BudgetExhausted { .. } | LiftOutcome::Rejected(_) => A64Function {
            entry: None,
            blocks: Vec::new(),
        },
    }
}

#[test]
fn paciasp_and_retab_recover_a_return() {
    let instructions: Vec<MCInst> = decode_words(&[0xd503_233f, 0xd65f_0fff], 0x1000);
    let function: A64Function = complete(lift(&instructions, instructions.len()));
    let block: &BasicBlock = &function.blocks[0];
    assert_eq!(
        block,
        &BasicBlock {
            address: 0x1000,
            statements: vec![Statement::NoOp {
                va: 0x1000,
                opcode: A64Opcode::Paciasp,
            }],
            terminator: Terminator::Return {
                target: Expr::Read(Location::X(30)),
            },
        }
    );
}

#[test]
fn bti_recovers_without_abstention() {
    let instructions: Vec<MCInst> = decode_words(&[0xd503_245f], 0x1100);
    let function: A64Function = complete(lift(&instructions, instructions.len()));
    let block: &BasicBlock = &function.blocks[0];
    assert_eq!(
        block,
        &BasicBlock {
            address: 0x1100,
            statements: vec![Statement::NoOp {
                va: 0x1100,
                opcode: A64Opcode::Bti,
            }],
            terminator: Terminator::Goto {
                target: Target::Exit,
            },
        }
    );
}

#[test]
fn authenticated_indirect_control_and_load_drop_authentication() {
    let instructions: Vec<MCInst> = decode_words(&[0xd71f_0822, 0xd73f_08a6, 0xf820_0549], 0x1180);
    let function: A64Function = complete(lift(&instructions, instructions.len()));
    assert_eq!(
        function.blocks,
        vec![
            BasicBlock {
                address: 0x1180,
                statements: Vec::new(),
                terminator: Terminator::IndirectGoto {
                    target: Expr::Read(Location::X(1)),
                },
            },
            BasicBlock {
                address: 0x1184,
                statements: vec![Statement::Assign {
                    destination: Location::X(30),
                    value: Expr::Constant(0x1188),
                }],
                terminator: Terminator::IndirectCall {
                    target: Expr::Read(Location::X(5)),
                    return_to: Target::Block(0x1188),
                },
            },
            BasicBlock {
                address: 0x1188,
                statements: vec![Statement::Load {
                    result: AtomicDestination::Register {
                        location: Location::X(9),
                        width: Width::W64,
                    },
                    address: Expr::Read(Location::X(10)),
                    width: Width::W64,
                }],
                terminator: Terminator::Goto {
                    target: Target::Exit,
                },
            },
        ]
    );
}

#[test]
fn fp_compare_zero_is_not_an_fmov_immediate() {
    let instructions: Vec<MCInst> = decode_words(&[0x1e60_20d8], 0x11c0);
    let function: A64Function = complete(lift(&instructions, instructions.len()));
    let block: &BasicBlock = &function.blocks[0];
    assert!(matches!(
        block.statements.get(1),
        Some(Statement::FpCapture {
            expression: FpExpr::Zero { ty: FpType::F64 },
            ..
        })
    ));
}

#[test]
fn conditional_selects_accept_any_nzcv_producer() {
    let integer_flags: Vec<MCInst> = decode_words(&[0xeb02_003f, 0x1e69_0d07], 0x11d0);
    let integer_function: A64Function = complete(lift(&integer_flags, integer_flags.len()));
    let integer_statements: &[Statement] = &integer_function.blocks[0].statements;
    assert!(!matches!(
        integer_statements.last(),
        Some(Statement::Abstain { .. })
    ));

    let floating_flags: Vec<MCInst> = decode_words(&[0x1e25_2080, 0x9a82_0020], 0x11e0);
    let floating_function: A64Function = complete(lift(&floating_flags, floating_flags.len()));
    let floating_statements: &[Statement] = &floating_function.blocks[0].statements;
    assert!(!matches!(
        floating_statements.last(),
        Some(Statement::Abstain { .. })
    ));
}

#[test]
fn malformed_pac_operands_abstain() {
    let instruction: MCInst = MCInst {
        opcode: A64Opcode::Paciasp,
        operands: vec![Operand::Imm(0)],
        sets_flags: false,
        va: 0x11f0,
        len: 4,
    };
    let function: A64Function = complete(lift(&[instruction], 1));
    assert_eq!(
        function.blocks[0].statements,
        vec![Statement::Abstain {
            va: 0x11f0,
            opcode: A64Opcode::Paciasp,
        }]
    );
}

#[test]
fn malformed_authenticated_return_operands_abstain() {
    let instruction: MCInst = MCInst {
        opcode: A64Opcode::Retab,
        operands: vec![Operand::Imm(0)],
        sets_flags: false,
        va: 0x11f4,
        len: 4,
    };
    let function: A64Function = complete(lift(&[instruction], 1));
    assert_eq!(
        function.blocks[0].terminator,
        Terminator::Abstain {
            va: 0x11f4,
            opcode: A64Opcode::Retab,
        }
    );
}

#[test]
fn scalar_fp_forms_recover_without_abstention() {
    let instructions: Vec<MCInst> = decode_words(
        &[0x1e62_2820, 0x1e25_2080, 0x1e69_0d07, 0x9e62_0230],
        0x1200,
    );
    let function: A64Function = complete(lift(&instructions, instructions.len()));
    let block: &BasicBlock = &function.blocks[0];
    assert_eq!(
        block,
        &BasicBlock {
            address: 0x1200,
            statements: vec![
                Statement::AssignFp {
                    register: 0,
                    ty: FpType::F64,
                    value: FpExpr::Binary {
                        op: FpBinaryOp::Add,
                        left: Box::new(FpExpr::Read {
                            register: 1,
                            ty: FpType::F64,
                        }),
                        right: Box::new(FpExpr::Read {
                            register: 2,
                            ty: FpType::F64,
                        }),
                        ty: FpType::F64,
                    },
                },
                Statement::FpCapture {
                    value: 0,
                    expression: FpExpr::Read {
                        register: 4,
                        ty: FpType::F32,
                    },
                },
                Statement::FpCapture {
                    value: 1,
                    expression: FpExpr::Read {
                        register: 5,
                        ty: FpType::F32,
                    },
                },
                Statement::SetFpFlags {
                    source: FpFlagSource {
                        id: 0,
                        left: 0,
                        right: 1,
                        ty: FpType::F32,
                        signaling: false,
                    },
                },
                Statement::AssignFp {
                    register: 7,
                    ty: FpType::F64,
                    value: FpExpr::Select {
                        predicate: Box::new(Predicate::FpCondition {
                            condition: FpCondition::Eq,
                            left: FpExpr::Captured(0),
                            right: FpExpr::Captured(1),
                            ty: FpType::F32,
                        }),
                        when_true: Box::new(FpExpr::Read {
                            register: 8,
                            ty: FpType::F64,
                        }),
                        when_false: Box::new(FpExpr::Read {
                            register: 9,
                            ty: FpType::F64,
                        }),
                        ty: FpType::F64,
                    },
                },
                Statement::AssignFp {
                    register: 16,
                    ty: FpType::F64,
                    value: FpExpr::FromInteger {
                        value: Box::new(Expr::Read(Location::X(17))),
                        signed: true,
                        ty: FpType::F64,
                        rounding: FpRounding::FpControl,
                    },
                },
            ],
            terminator: Terminator::Goto {
                target: Target::Exit,
            },
        }
    );
}

#[test]
fn remaining_scalar_fp_operations_recover_without_abstention() {
    let instructions: Vec<MCInst> = decode_words(
        &[
            0x1e25_3883,
            0x1e68_08e6,
            0x1e2b_1949,
            0x1e62_41ac,
            0x1e22_c1ee,
            0x1e23_0272,
            0x9e78_02b4,
            0x1e39_02f6,
            0x1e60_4338,
            0x1e6e_101a,
            0x9e66_039b,
            0x9e67_03dd,
            0x1e26_0020,
            0x1e27_0062,
        ],
        0x1280,
    );
    let function: A64Function = complete(lift(&instructions, instructions.len()));
    let statements: &[Statement] = &function.blocks[0].statements;
    assert_eq!(statements.len(), instructions.len());
    assert!(
        statements
            .iter()
            .all(|statement: &Statement| !matches!(statement, Statement::Abstain { .. }))
    );
}

#[test]
fn lse_compare_exchange_and_add_recover_without_abstention() {
    let instructions: Vec<MCInst> = decode_words(&[0xc8a3_7ca4, 0xb829_016a], 0x1300);
    let function: A64Function = complete(lift(&instructions, instructions.len()));
    let block: &BasicBlock = &function.blocks[0];
    assert_eq!(
        block.statements,
        vec![
            Statement::Capture {
                value: 0,
                expression: Expr::Read(Location::X(3)),
            },
            Statement::Capture {
                value: 1,
                expression: Expr::Read(Location::X(4)),
            },
            Statement::AtomicCompareExchange {
                result: AtomicDestination::Register {
                    location: Location::X(3),
                    width: Width::W64,
                },
                expected: Expr::Captured(0),
                replacement: Expr::Captured(1),
                address: Expr::Read(Location::X(5)),
                width: Width::W64,
                ordering: AtomicOrdering::Relaxed,
            },
            Statement::Capture {
                value: 2,
                expression: Expr::Truncate32(Box::new(Expr::Read(Location::X(9)))),
            },
            Statement::AtomicRmw {
                operation: AtomicOp::Add,
                result: AtomicDestination::Register {
                    location: Location::X(10),
                    width: Width::W32,
                },
                value: Expr::Captured(2),
                address: Expr::Read(Location::X(11)),
                width: Width::W32,
                ordering: AtomicOrdering::Relaxed,
            },
        ]
    );
}

#[test]
fn exclusive_load_store_pair_recovers_without_abstention() {
    let instructions: Vec<MCInst> = decode_words(&[0x885f_7c41, 0x8804_7cc5], 0x1400);
    let function: A64Function = complete(lift(&instructions, instructions.len()));
    let block: &BasicBlock = &function.blocks[0];
    assert_eq!(
        block.statements,
        vec![
            Statement::LoadExclusive {
                result: AtomicDestination::Register {
                    location: Location::X(1),
                    width: Width::W32,
                },
                address: Expr::Read(Location::X(2)),
                width: Width::W32,
                ordering: AtomicOrdering::Relaxed,
            },
            Statement::Capture {
                value: 0,
                expression: Expr::Truncate32(Box::new(Expr::Read(Location::X(5)))),
            },
            Statement::StoreExclusive {
                status: AtomicDestination::Register {
                    location: Location::X(4),
                    width: Width::W32,
                },
                value: Expr::Captured(0),
                address: Expr::Read(Location::X(6)),
                width: Width::W32,
                ordering: AtomicOrdering::Relaxed,
            },
        ]
    );
}

#[test]
fn packed_vector_decode_abstains() {
    let instructions: Vec<MCInst> = decode_words(&[0x2518_e3e0], 0x1500);
    let function: A64Function = complete(lift(&instructions, instructions.len()));
    assert_eq!(
        function.blocks,
        vec![BasicBlock {
            address: 0x1500,
            statements: Vec::new(),
            terminator: Terminator::Abstain {
                va: 0x1500,
                opcode: A64Opcode::Unmodeled(DecodeClass::ScalableVector),
            },
        }]
    );
}

#[test]
fn decoded_pathological_input_respects_budget() {
    let words: Vec<u32> = vec![0x1e62_2820; 257];
    let instructions: Vec<MCInst> = decode_words(&words, 0x1600);
    assert_eq!(
        lift(&instructions, 256),
        LiftOutcome::BudgetExhausted {
            available_steps: 256,
            instruction_count: 257,
        }
    );
}

#[test]
fn no_op_keeps_integer_flags_available_to_later_control_flow() {
    let instructions: Vec<MCInst> = decode_words(&[0x6b01_001f, 0xd503_233f, 0x5400_0040], 0x1700);
    let function: A64Function = complete(lift(&instructions, instructions.len()));
    let block: &BasicBlock = &function.blocks[0];
    assert!(matches!(
        block.terminator,
        Terminator::Branch {
            predicate: Predicate::Equal { .. },
            ..
        }
    ));
}

#[test]
fn fcmpe_records_signaling_and_uses_an_fp_zero() {
    let instructions: Vec<MCInst> = decode_words(&[0x1e60_20d8], 0x1710);
    let function: A64Function = complete(lift(&instructions, instructions.len()));
    let statements: &[Statement] = &function.blocks[0].statements;
    assert!(matches!(
        statements.get(1),
        Some(Statement::FpCapture {
            expression: FpExpr::Zero { ty: FpType::F64 },
            ..
        })
    ));
    assert!(matches!(
        statements.get(2),
        Some(Statement::SetFpFlags {
            source: FpFlagSource {
                signaling: true,
                ..
            }
        })
    ));
}

#[test]
fn acquire_release_atomic_variants_preserve_ordering() {
    let instructions: Vec<MCInst> = decode_words(
        &[0x88ec_fdcd, 0xf8f2_0293, 0xc85f_ffe3, 0xc807_ffe8],
        0x1720,
    );
    let function: A64Function = complete(lift(&instructions, instructions.len()));
    let statements: &[Statement] = &function.blocks[0].statements;
    assert!(matches!(
        statements.get(2),
        Some(Statement::AtomicCompareExchange {
            ordering: AtomicOrdering::AcqRel,
            ..
        })
    ));
    assert!(matches!(
        statements.get(4),
        Some(Statement::AtomicRmw {
            ordering: AtomicOrdering::AcqRel,
            ..
        })
    ));
    assert!(matches!(
        statements.get(5),
        Some(Statement::LoadExclusive {
            ordering: AtomicOrdering::Acquire,
            ..
        })
    ));
    assert!(matches!(
        statements.get(7),
        Some(Statement::StoreExclusive {
            ordering: AtomicOrdering::Release,
            ..
        })
    ));
}
