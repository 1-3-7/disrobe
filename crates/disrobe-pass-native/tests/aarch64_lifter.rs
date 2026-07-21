use disrobe_pass_native::aarch64::lift::{
    A64Function, BasicBlock, BinaryOp, Expr, FlagOperation, FlagSource, LiftOutcome, Location,
    Predicate, Statement, Target, Terminator, Width, lift,
};
use disrobe_pass_native::aarch64::{A64Opcode, DecodeClass, MCInst, Operand, RegView, decode};

fn decode_words(words: &[u32], base: u64) -> Vec<MCInst> {
    let mut instructions: Vec<MCInst> = Vec::with_capacity(words.len());
    for (index, word) in words.iter().enumerate() {
        let index_result: Result<u64, std::num::TryFromIntError> = u64::try_from(index);
        assert!(index_result.is_ok());
        let offset: u64 = match index_result {
            Ok(value) => value * 4,
            Err(_) => return Vec::new(),
        };
        let address: Option<u64> = base.checked_add(offset);
        assert!(address.is_some());
        let va: u64 = match address {
            Some(value) => value,
            None => return Vec::new(),
        };
        let decoded: Result<MCInst, disrobe_pass_native::aarch64::DecodeError> =
            decode(&word.to_le_bytes(), va);
        assert!(decoded.is_ok());
        let instruction: MCInst = match decoded {
            Ok(value) => value,
            Err(_) => return Vec::new(),
        };
        instructions.push(instruction);
    }
    instructions
}

fn completed(outcome: LiftOutcome) -> A64Function {
    assert!(matches!(&outcome, LiftOutcome::Complete(_)));
    match outcome {
        LiftOutcome::Complete(function) => function,
        LiftOutcome::BudgetExhausted { .. } | LiftOutcome::Rejected(_) => A64Function {
            entry: None,
            blocks: Vec::new(),
        },
    }
}

const fn x(n: u8) -> Expr {
    Expr::Read(Location::X(n))
}

fn w(n: u8) -> Expr {
    Expr::Truncate32(Box::new(x(n)))
}

const fn constant(value: u64) -> Expr {
    Expr::Constant(value)
}

const fn captured(id: u32) -> Expr {
    Expr::Captured(id)
}

fn binary(op: BinaryOp, left: Expr, right: Expr, width: Width) -> Expr {
    Expr::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
        width,
    }
}

fn write_w(n: u8, value: Expr) -> Statement {
    Statement::Assign {
        destination: Location::X(n),
        value: Expr::ZeroExtend32(Box::new(value)),
    }
}

#[test]
fn decoded_gcd_lifts_to_exact_predicate_cfg() {
    let words: [u32; 13] = [
        0x3400_0181,
        0x6b01_001f,
        0x5400_00c3,
        0x1ac1_0802,
        0x1b01_8043,
        0x2a01_03e0,
        0x2a03_03e1,
        0x17ff_fff9,
        0x2a00_03e2,
        0x2a01_03e0,
        0x2a02_03e1,
        0x17ff_fff5,
        0xd65f_03c0,
    ];
    let instructions: Vec<MCInst> = decode_words(&words, 0x1000);
    let actual: A64Function = completed(lift(&instructions, 13));
    let expected: A64Function = A64Function {
        entry: Some(0x1000),
        blocks: vec![
            BasicBlock {
                address: 0x1000,
                statements: Vec::new(),
                terminator: Terminator::Branch {
                    predicate: Predicate::Equal {
                        left: w(1),
                        right: constant(0),
                        width: Width::W32,
                    },
                    taken: Target::Block(0x1030),
                    not_taken: Target::Block(0x1004),
                },
            },
            BasicBlock {
                address: 0x1004,
                statements: vec![
                    Statement::Capture {
                        value: 0,
                        expression: w(0),
                    },
                    Statement::Capture {
                        value: 1,
                        expression: w(1),
                    },
                    Statement::Capture {
                        value: 2,
                        expression: binary(BinaryOp::Sub, captured(0), captured(1), Width::W32),
                    },
                    Statement::SetFlags {
                        source: FlagSource {
                            id: 0,
                            operation: FlagOperation::Sub,
                            left: 0,
                            right: 1,
                            result: 2,
                            width: Width::W32,
                        },
                    },
                ],
                terminator: Terminator::Branch {
                    predicate: Predicate::UnsignedLessThan {
                        left: captured(0),
                        right: captured(1),
                        width: Width::W32,
                    },
                    taken: Target::Block(0x1020),
                    not_taken: Target::Block(0x100c),
                },
            },
            BasicBlock {
                address: 0x100c,
                statements: vec![
                    write_w(2, binary(BinaryOp::UnsignedDiv, w(0), w(1), Width::W32)),
                    write_w(
                        3,
                        binary(
                            BinaryOp::Sub,
                            w(0),
                            binary(BinaryOp::Mul, w(2), w(1), Width::W32),
                            Width::W32,
                        ),
                    ),
                    write_w(0, w(1)),
                    write_w(1, w(3)),
                ],
                terminator: Terminator::Goto {
                    target: Target::Block(0x1000),
                },
            },
            BasicBlock {
                address: 0x1020,
                statements: vec![write_w(2, w(0)), write_w(0, w(1)), write_w(1, w(2))],
                terminator: Terminator::Goto {
                    target: Target::Block(0x1000),
                },
            },
            BasicBlock {
                address: 0x1030,
                statements: Vec::new(),
                terminator: Terminator::Return { target: x(30) },
            },
        ],
    };
    assert_eq!(actual, expected);
}

#[test]
fn zero_register_reads_are_zero_and_writes_zero_extend() {
    let words: [u32; 2] = [0x8b1f_0020, 0x2a02_03e1];
    let instructions: Vec<MCInst> = decode_words(&words, 0x2000);
    let function: A64Function = completed(lift(&instructions, 2));
    assert_eq!(
        function,
        A64Function {
            entry: Some(0x2000),
            blocks: vec![BasicBlock {
                address: 0x2000,
                statements: vec![
                    Statement::Assign {
                        destination: Location::X(0),
                        value: binary(BinaryOp::Add, x(1), constant(0), Width::W64),
                    },
                    write_w(1, w(2)),
                ],
                terminator: Terminator::Goto {
                    target: Target::Exit,
                },
            }],
        }
    );
}

#[test]
fn subtract_then_unsigned_branch_uses_unsigned_predicate() {
    let words: [u32; 4] = [0x6b01_001f, 0x5400_0043, 0xd65f_03c0, 0xd65f_03c0];
    let instructions: Vec<MCInst> = decode_words(&words, 0x3000);
    let function: A64Function = completed(lift(&instructions, 4));
    assert_eq!(
        function.blocks[0].terminator,
        Terminator::Branch {
            predicate: Predicate::UnsignedLessThan {
                left: captured(0),
                right: captured(1),
                width: Width::W32,
            },
            taken: Target::Block(0x300c),
            not_taken: Target::Block(0x3008),
        }
    );
}

#[test]
fn unmodeled_instruction_lifts_to_abstention_barrier() {
    let instruction: MCInst = MCInst {
        opcode: A64Opcode::Unmodeled(DecodeClass::SimdFloatingPoint),
        operands: Vec::new(),
        sets_flags: false,
        va: 0x5000,
        len: 4,
    };
    let function: A64Function = completed(lift(&[instruction], 1));
    assert_eq!(
        function,
        A64Function {
            entry: Some(0x5000),
            blocks: vec![BasicBlock {
                address: 0x5000,
                statements: Vec::new(),
                terminator: Terminator::Abstain {
                    va: 0x5000,
                    opcode: A64Opcode::Unmodeled(DecodeClass::SimdFloatingPoint),
                },
            }],
        }
    );
}

#[test]
fn budget_exhaustion_is_deterministic_for_long_input() {
    let decoded: Result<MCInst, disrobe_pass_native::aarch64::DecodeError> =
        decode(&0x2a02_03e1_u32.to_le_bytes(), 0x6000);
    assert!(decoded.is_ok());
    let instruction: MCInst = match decoded {
        Ok(value) => value,
        Err(_) => return,
    };
    let instructions: Vec<MCInst> = vec![instruction; 4097];
    assert_eq!(
        lift(&instructions, 4096),
        LiftOutcome::BudgetExhausted {
            available_steps: 4096,
            instruction_count: 4097,
        }
    );
}

#[test]
fn malformed_cset_shape_is_not_assumed_to_be_a_register_write() {
    let instruction: MCInst = MCInst {
        opcode: A64Opcode::Csinc,
        operands: vec![
            Operand::Reg {
                n: 0,
                view: RegView::X,
            },
            Operand::Reg {
                n: 31,
                view: RegView::Zr,
            },
            Operand::Reg {
                n: 1,
                view: RegView::X,
            },
            Operand::CondCode(0),
        ],
        sets_flags: false,
        va: 0x7000,
        len: 4,
    };
    let function: A64Function = completed(lift(&[instruction], 1));
    assert_eq!(
        function.blocks[0].statements,
        vec![Statement::Abstain {
            va: 0x7000,
            opcode: A64Opcode::Csinc,
        }]
    );
}

#[test]
fn conditional_select_forms_reuse_the_semantic_predicate() {
    let words: [u32; 5] = [
        0xeb02_003f,
        0x9a82_0020,
        0x1a85_1483,
        0x9a9f_17e6,
        0xd65f_03c0,
    ];
    let instructions: Vec<MCInst> = decode_words(&words, 0x8000);
    let function: A64Function = completed(lift(&instructions, 5));
    let equal: Predicate = Predicate::Equal {
        left: captured(0),
        right: captured(1),
        width: Width::W64,
    };
    let not_equal: Predicate = Predicate::NotEqual {
        left: captured(0),
        right: captured(1),
        width: Width::W64,
    };
    assert_eq!(
        function,
        A64Function {
            entry: Some(0x8000),
            blocks: vec![BasicBlock {
                address: 0x8000,
                statements: vec![
                    Statement::Capture {
                        value: 0,
                        expression: x(1),
                    },
                    Statement::Capture {
                        value: 1,
                        expression: x(2),
                    },
                    Statement::Capture {
                        value: 2,
                        expression: binary(BinaryOp::Sub, captured(0), captured(1), Width::W64,),
                    },
                    Statement::SetFlags {
                        source: FlagSource {
                            id: 0,
                            operation: FlagOperation::Sub,
                            left: 0,
                            right: 1,
                            result: 2,
                            width: Width::W64,
                        },
                    },
                    Statement::Assign {
                        destination: Location::X(0),
                        value: Expr::Select {
                            predicate: Box::new(equal.clone()),
                            when_true: Box::new(x(1)),
                            when_false: Box::new(x(2)),
                        },
                    },
                    write_w(
                        3,
                        Expr::Select {
                            predicate: Box::new(not_equal),
                            when_true: Box::new(w(4)),
                            when_false: Box::new(binary(
                                BinaryOp::Add,
                                w(5),
                                constant(1),
                                Width::W32,
                            )),
                        },
                    ),
                    Statement::Assign {
                        destination: Location::X(6),
                        value: Expr::ZeroExtendPredicate {
                            predicate: Box::new(equal),
                            width: Width::W64,
                        },
                    },
                ],
                terminator: Terminator::Return { target: x(30) },
            }],
        }
    );
}

#[test]
fn shifted_and_extended_register_operands_stay_in_the_expression_tree() {
    let words: [u32; 2] = [0x8b42_0c20, 0x8b21_4be0];
    let instructions: Vec<MCInst> = decode_words(&words, 0x8800);
    let function: A64Function = completed(lift(&instructions, 2));
    assert_eq!(
        function.blocks[0].statements,
        vec![
            Statement::Assign {
                destination: Location::X(0),
                value: binary(
                    BinaryOp::Add,
                    x(1),
                    Expr::Shift {
                        kind: disrobe_pass_native::aarch64::ShiftKind::Lsr,
                        value: Box::new(x(2)),
                        amount: 3,
                        width: Width::W64,
                    },
                    Width::W64,
                ),
            },
            Statement::Assign {
                destination: Location::X(0),
                value: binary(
                    BinaryOp::Add,
                    Expr::Read(Location::Sp),
                    Expr::Shift {
                        kind: disrobe_pass_native::aarch64::ShiftKind::Lsl,
                        value: Box::new(Expr::Extend {
                            kind: disrobe_pass_native::aarch64::ExtendKind::Uxtw,
                            value: Box::new(w(1)),
                        }),
                        amount: 2,
                        width: Width::W64,
                    },
                    Width::W64,
                ),
            },
        ]
    );
}

#[test]
fn direct_calls_and_remaining_branch_forms_build_explicit_edges() {
    let words: [u32; 8] = [
        0x1400_0003,
        0x9400_0004,
        0xd65f_03c0,
        0x3500_0040,
        0x3628_0042,
        0xd65f_03c0,
        0xb710_0023,
        0xd65f_03c0,
    ];
    let instructions: Vec<MCInst> = decode_words(&words, 0x9000);
    let function: A64Function = completed(lift(&instructions, 8));
    let terms: Vec<Terminator> = function
        .blocks
        .iter()
        .map(|block: &BasicBlock| block.terminator.clone())
        .collect();
    assert_eq!(
        terms,
        vec![
            Terminator::Goto {
                target: Target::Block(0x900c),
            },
            Terminator::Call {
                target: Target::Block(0x9014),
                return_to: Target::Block(0x9008),
            },
            Terminator::Return { target: x(30) },
            Terminator::Branch {
                predicate: Predicate::NotEqual {
                    left: w(0),
                    right: constant(0),
                    width: Width::W32,
                },
                taken: Target::Block(0x9014),
                not_taken: Target::Block(0x9010),
            },
            Terminator::Branch {
                predicate: Predicate::BitClear {
                    value: w(2),
                    bit: 5,
                    width: Width::W32,
                },
                taken: Target::Block(0x9018),
                not_taken: Target::Block(0x9014),
            },
            Terminator::Return { target: x(30) },
            Terminator::Branch {
                predicate: Predicate::BitSet {
                    value: x(3),
                    bit: 34,
                    width: Width::W64,
                },
                taken: Target::Block(0x901c),
                not_taken: Target::Block(0x901c),
            },
            Terminator::Return { target: x(30) },
        ]
    );
    assert_eq!(
        function.blocks[1].statements,
        vec![Statement::Assign {
            destination: Location::X(30),
            value: constant(0x9008),
        }]
    );
}

#[test]
fn internal_direct_call_target_is_a_basic_block() {
    let words: [u32; 3] = [0x9400_0002, 0x2a01_03e0, 0xd65f_03c0];
    let instructions: Vec<MCInst> = decode_words(&words, 0xa000);
    let function: A64Function = completed(lift(&instructions, 3));
    assert_eq!(
        function.blocks,
        vec![
            BasicBlock {
                address: 0xa000,
                statements: vec![Statement::Assign {
                    destination: Location::X(30),
                    value: constant(0xa004),
                }],
                terminator: Terminator::Call {
                    target: Target::Block(0xa008),
                    return_to: Target::Block(0xa004),
                },
            },
            BasicBlock {
                address: 0xa004,
                statements: vec![write_w(0, w(1))],
                terminator: Terminator::Goto {
                    target: Target::Block(0xa008),
                },
            },
            BasicBlock {
                address: 0xa008,
                statements: Vec::new(),
                terminator: Terminator::Return { target: x(30) },
            },
        ]
    );
}

#[test]
fn noncontiguous_instruction_slices_are_rejected() {
    let first: MCInst = MCInst {
        opcode: A64Opcode::Mov,
        operands: vec![
            Operand::Reg {
                n: 0,
                view: RegView::W,
            },
            Operand::Reg {
                n: 1,
                view: RegView::W,
            },
        ],
        sets_flags: false,
        va: 0xb000,
        len: 4,
    };
    let second: MCInst = MCInst {
        va: 0xb008,
        ..first.clone()
    };
    assert_eq!(
        lift(&[first, second], 2),
        LiftOutcome::Rejected(
            disrobe_pass_native::aarch64::lift::LiftReject::NonContiguousAddress {
                instruction: 0xb000,
                next: 0xb008,
            }
        )
    );
}

#[test]
fn malformed_zero_register_destination_becomes_an_abstention_barrier() {
    let instruction: MCInst = MCInst {
        opcode: A64Opcode::Add,
        operands: vec![
            Operand::Reg {
                n: 0,
                view: RegView::Zr,
            },
            Operand::Reg {
                n: 1,
                view: RegView::X,
            },
            Operand::Reg {
                n: 2,
                view: RegView::X,
            },
        ],
        sets_flags: false,
        va: 0xc000,
        len: 4,
    };
    let function: A64Function = completed(lift(&[instruction], 1));
    assert_eq!(
        function.blocks[0].statements,
        vec![Statement::Abstain {
            va: 0xc000,
            opcode: A64Opcode::Add,
        }]
    );
}
