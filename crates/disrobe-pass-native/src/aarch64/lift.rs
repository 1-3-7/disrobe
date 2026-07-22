use std::collections::BTreeSet;

use super::{A64Opcode, ExtendKind, MCInst, Operand, RegView, ShiftKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    W32,
    W64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    X(u8),
    Sp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    And,
    Orr,
    Eor,
    Mul,
    UnsignedDiv,
    SignedDiv,
    Lslv,
    Lsrv,
    Asrv,
    Rorv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagOperation {
    Add,
    Sub,
    And,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Read(Location),
    Captured(u32),
    Constant(u64),
    Truncate32(Box<Self>),
    ZeroExtend32(Box<Self>),
    Extend {
        kind: ExtendKind,
        value: Box<Self>,
    },
    Shift {
        kind: ShiftKind,
        value: Box<Self>,
        amount: u8,
        width: Width,
    },
    Binary {
        op: BinaryOp,
        left: Box<Self>,
        right: Box<Self>,
        width: Width,
    },
    Select {
        predicate: Box<Predicate>,
        when_true: Box<Self>,
        when_false: Box<Self>,
    },
    ZeroExtendPredicate {
        predicate: Box<Predicate>,
        width: Width,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Constant(bool),
    Equal {
        left: Expr,
        right: Expr,
        width: Width,
    },
    NotEqual {
        left: Expr,
        right: Expr,
        width: Width,
    },
    UnsignedLessThan {
        left: Expr,
        right: Expr,
        width: Width,
    },
    UnsignedLessOrEqual {
        left: Expr,
        right: Expr,
        width: Width,
    },
    UnsignedGreaterThan {
        left: Expr,
        right: Expr,
        width: Width,
    },
    UnsignedGreaterOrEqual {
        left: Expr,
        right: Expr,
        width: Width,
    },
    SignedLessThan {
        left: Expr,
        right: Expr,
        width: Width,
    },
    SignedLessOrEqual {
        left: Expr,
        right: Expr,
        width: Width,
    },
    SignedGreaterThan {
        left: Expr,
        right: Expr,
        width: Width,
    },
    SignedGreaterOrEqual {
        left: Expr,
        right: Expr,
        width: Width,
    },
    Negative {
        value: Expr,
        width: Width,
    },
    UnsignedAddOverflow {
        left: Expr,
        right: Expr,
        width: Width,
    },
    SignedOverflow {
        operation: FlagOperation,
        left: Expr,
        right: Expr,
        width: Width,
    },
    BitClear {
        value: Expr,
        bit: u8,
        width: Width,
    },
    BitSet {
        value: Expr,
        bit: u8,
        width: Width,
    },
    All(Vec<Self>),
    Any(Vec<Self>),
    Not(Box<Self>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagSource {
    pub id: u32,
    pub operation: FlagOperation,
    pub left: u32,
    pub right: u32,
    pub result: u32,
    pub width: Width,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    Capture { value: u32, expression: Expr },
    SetFlags { source: FlagSource },
    Assign { destination: Location, value: Expr },
    Abstain { va: u64, opcode: A64Opcode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Block(u64),
    External(u64),
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminator {
    Goto {
        target: Target,
    },
    Branch {
        predicate: Predicate,
        taken: Target,
        not_taken: Target,
    },
    Call {
        target: Target,
        return_to: Target,
    },
    Return {
        target: Expr,
    },
    Abstain {
        va: u64,
        opcode: A64Opcode,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    pub address: u64,
    pub statements: Vec<Statement>,
    pub terminator: Terminator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A64Function {
    pub entry: Option<u64>,
    pub blocks: Vec<BasicBlock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiftReject {
    DuplicateAddress(u64),
    NonContiguousAddress { instruction: u64, next: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftOutcome {
    Complete(A64Function),
    BudgetExhausted {
        available_steps: usize,
        instruction_count: usize,
    },
    Rejected(LiftReject),
}

#[derive(Debug, Clone, Copy)]
struct FlagState {
    source: FlagSource,
}

#[derive(Debug, Clone, Copy)]
struct Identifiers {
    next_value: u32,
    next_flag: u32,
}

#[derive(Debug, Clone)]
struct ControlLowering {
    statements: Vec<Statement>,
    terminator: Terminator,
}

enum DestinationWrite {
    Assign(Statement),
    Discard,
    Invalid,
}

pub fn lift(instructions: &[MCInst], step_budget: usize) -> LiftOutcome {
    let instruction_count: usize = instructions.len();
    if instruction_count > step_budget {
        return LiftOutcome::BudgetExhausted {
            available_steps: step_budget,
            instruction_count,
        };
    }
    if instructions.is_empty() {
        return LiftOutcome::Complete(A64Function {
            entry: None,
            blocks: Vec::new(),
        });
    }
    let mut addresses: BTreeSet<u64> = BTreeSet::new();
    for instruction in instructions {
        if !addresses.insert(instruction.va) {
            return LiftOutcome::Rejected(LiftReject::DuplicateAddress(instruction.va));
        }
    }
    for pair in instructions.windows(2) {
        let instruction: &MCInst = &pair[0];
        let next: &MCInst = &pair[1];
        let expected: Option<u64> = instruction.va.checked_add(u64::from(instruction.len));
        if expected != Some(next.va) {
            return LiftOutcome::Rejected(LiftReject::NonContiguousAddress {
                instruction: instruction.va,
                next: next.va,
            });
        }
    }
    let mut starts: BTreeSet<u64> = BTreeSet::new();
    starts.insert(instructions[0].va);
    for (index, instruction) in instructions.iter().enumerate() {
        let direct_target: Option<u64> = direct_branch_target(instruction);
        match direct_target {
            Some(target) if addresses.contains(&target) => {
                starts.insert(target);
            }
            Some(_) | None => {}
        }
        if ends_block(instruction.opcode) {
            let next_index: usize = index + 1;
            if let Some(next) = instructions.get(next_index) {
                starts.insert(next.va);
            }
        }
    }
    let mut identifiers: Identifiers = Identifiers {
        next_value: 0,
        next_flag: 0,
    };
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut start_index: usize = 0;
    while start_index < instruction_count {
        let address: u64 = instructions[start_index].va;
        let mut end_index: usize = start_index + 1;
        while end_index < instruction_count && !starts.contains(&instructions[end_index].va) {
            end_index += 1;
        }
        let mut statements: Vec<Statement> = Vec::new();
        let mut flags: Option<FlagState> = None;
        let mut terminator: Option<Terminator> = None;
        for index in start_index..end_index {
            let instruction: &MCInst = &instructions[index];
            let fallthrough: Target = instructions
                .get(index + 1)
                .map_or(Target::Exit, |next: &MCInst| target_for(next.va, &starts));
            match lower_control(instruction, fallthrough, flags, &starts) {
                Some(control) => {
                    statements.extend(control.statements);
                    terminator = Some(control.terminator);
                    break;
                }
                None => lower_statement(instruction, &mut statements, &mut flags, &mut identifiers),
            }
        }
        let fallthrough_terminator: Terminator = instructions.get(end_index).map_or(
            Terminator::Goto {
                target: Target::Exit,
            },
            |next: &MCInst| Terminator::Goto {
                target: target_for(next.va, &starts),
            },
        );
        let block_terminator: Terminator =
            terminator.map_or(fallthrough_terminator, core::convert::identity);
        blocks.push(BasicBlock {
            address,
            statements,
            terminator: block_terminator,
        });
        start_index = end_index;
    }
    LiftOutcome::Complete(A64Function {
        entry: Some(instructions[0].va),
        blocks,
    })
}

fn direct_branch_target(instruction: &MCInst) -> Option<u64> {
    match instruction.opcode {
        A64Opcode::B
        | A64Opcode::Bl
        | A64Opcode::BCond
        | A64Opcode::Cbz
        | A64Opcode::Cbnz
        | A64Opcode::Tbz
        | A64Opcode::Tbnz => label_operand(&instruction.operands),
        _ => None,
    }
}

const fn ends_block(opcode: A64Opcode) -> bool {
    matches!(
        opcode,
        A64Opcode::B
            | A64Opcode::Bl
            | A64Opcode::Ret
            | A64Opcode::Br
            | A64Opcode::Blr
            | A64Opcode::BCond
            | A64Opcode::Cbz
            | A64Opcode::Cbnz
            | A64Opcode::Tbz
            | A64Opcode::Tbnz
            | A64Opcode::Unallocated
            | A64Opcode::Unmodeled(_)
    )
}

fn target_for(address: u64, addresses: &BTreeSet<u64>) -> Target {
    if addresses.contains(&address) {
        Target::Block(address)
    } else {
        Target::External(address)
    }
}

fn lower_control(
    instruction: &MCInst,
    fallthrough: Target,
    flags: Option<FlagState>,
    addresses: &BTreeSet<u64>,
) -> Option<ControlLowering> {
    match instruction.opcode {
        A64Opcode::B => Some(direct_goto(instruction, addresses)),
        A64Opcode::Bl => Some(direct_call(instruction, fallthrough, addresses)),
        A64Opcode::Ret => Some(return_control(instruction)),
        A64Opcode::BCond => Some(conditional_branch(
            instruction,
            fallthrough,
            flags,
            addresses,
        )),
        A64Opcode::Cbz | A64Opcode::Cbnz => {
            Some(compare_branch(instruction, fallthrough, addresses))
        }
        A64Opcode::Tbz | A64Opcode::Tbnz => Some(test_branch(instruction, fallthrough, addresses)),
        A64Opcode::Br | A64Opcode::Blr | A64Opcode::Unallocated | A64Opcode::Unmodeled(_) => {
            Some(abstain_control(instruction))
        }
        _ => None,
    }
}

fn direct_goto(instruction: &MCInst, addresses: &BTreeSet<u64>) -> ControlLowering {
    let target: Option<u64> = label_operand(&instruction.operands);
    target.map_or_else(
        || abstain_control(instruction),
        |address: u64| ControlLowering {
            statements: Vec::new(),
            terminator: Terminator::Goto {
                target: target_for(address, addresses),
            },
        },
    )
}

fn direct_call(
    instruction: &MCInst,
    fallthrough: Target,
    addresses: &BTreeSet<u64>,
) -> ControlLowering {
    let target: Option<u64> = label_operand(&instruction.operands);
    let return_address: Option<u64> = instruction.va.checked_add(u64::from(instruction.len));
    match (target, return_address) {
        (Some(address), Some(link)) => ControlLowering {
            statements: vec![Statement::Assign {
                destination: Location::X(30),
                value: Expr::Constant(link),
            }],
            terminator: Terminator::Call {
                target: target_for(address, addresses),
                return_to: fallthrough,
            },
        },
        _ => abstain_control(instruction),
    }
}

fn return_control(instruction: &MCInst) -> ControlLowering {
    let target: Option<Expr> = instruction
        .operands
        .first()
        .and_then(|operand: &Operand| read_operand(operand, Width::W64));
    target.map_or_else(
        || abstain_control(instruction),
        |value: Expr| ControlLowering {
            statements: Vec::new(),
            terminator: Terminator::Return { target: value },
        },
    )
}

fn conditional_branch(
    instruction: &MCInst,
    fallthrough: Target,
    flags: Option<FlagState>,
    addresses: &BTreeSet<u64>,
) -> ControlLowering {
    let target: Option<u64> = instruction.operands.first().and_then(label_from_operand);
    let condition: Option<u8> = instruction.operands.get(1).and_then(condition_from_operand);
    let predicate: Option<Predicate> = match (flags, condition) {
        (Some(state), Some(code)) => predicate_from_flags(state.source, code),
        (None, Some(14)) => Some(Predicate::Constant(true)),
        _ => None,
    };
    match (target, predicate) {
        (Some(address), Some(condition)) => ControlLowering {
            statements: Vec::new(),
            terminator: Terminator::Branch {
                predicate: condition,
                taken: target_for(address, addresses),
                not_taken: fallthrough,
            },
        },
        _ => abstain_control(instruction),
    }
}

fn compare_branch(
    instruction: &MCInst,
    fallthrough: Target,
    addresses: &BTreeSet<u64>,
) -> ControlLowering {
    let register: Option<&Operand> = instruction.operands.first();
    let target: Option<u64> = instruction.operands.get(1).and_then(label_from_operand);
    match (register, target) {
        (Some(operand), Some(address)) => {
            let width: Option<Width> = operand_width(operand);
            match width
                .and_then(|value: Width| read_operand(operand, value).map(|read| (value, read)))
            {
                Some((value_width, value)) => {
                    let predicate: Predicate = match instruction.opcode {
                        A64Opcode::Cbz => Predicate::Equal {
                            left: value,
                            right: Expr::Constant(0),
                            width: value_width,
                        },
                        A64Opcode::Cbnz => Predicate::NotEqual {
                            left: value,
                            right: Expr::Constant(0),
                            width: value_width,
                        },
                        _ => return abstain_control(instruction),
                    };
                    ControlLowering {
                        statements: Vec::new(),
                        terminator: Terminator::Branch {
                            predicate,
                            taken: target_for(address, addresses),
                            not_taken: fallthrough,
                        },
                    }
                }
                None => abstain_control(instruction),
            }
        }
        _ => abstain_control(instruction),
    }
}

fn test_branch(
    instruction: &MCInst,
    fallthrough: Target,
    addresses: &BTreeSet<u64>,
) -> ControlLowering {
    let register: Option<&Operand> = instruction.operands.first();
    let bit: Option<i64> = instruction.operands.get(1).and_then(immediate_from_operand);
    let target: Option<u64> = instruction.operands.get(2).and_then(label_from_operand);
    match (register, bit, target) {
        (Some(operand), Some(index), Some(address)) => {
            let width: Option<Width> = operand_width(operand);
            let bit_index: Option<u8> = u8::try_from(index).ok();
            match (width, bit_index) {
                (Some(value_width), Some(bit_value)) if bit_value < width_bits(value_width) => {
                    match read_operand(operand, value_width) {
                        Some(value) => {
                            let predicate: Predicate = match instruction.opcode {
                                A64Opcode::Tbz => Predicate::BitClear {
                                    value,
                                    bit: bit_value,
                                    width: value_width,
                                },
                                A64Opcode::Tbnz => Predicate::BitSet {
                                    value,
                                    bit: bit_value,
                                    width: value_width,
                                },
                                _ => return abstain_control(instruction),
                            };
                            ControlLowering {
                                statements: Vec::new(),
                                terminator: Terminator::Branch {
                                    predicate,
                                    taken: target_for(address, addresses),
                                    not_taken: fallthrough,
                                },
                            }
                        }
                        None => abstain_control(instruction),
                    }
                }
                _ => abstain_control(instruction),
            }
        }
        _ => abstain_control(instruction),
    }
}

fn abstain_control(instruction: &MCInst) -> ControlLowering {
    ControlLowering {
        statements: Vec::new(),
        terminator: Terminator::Abstain {
            va: instruction.va,
            opcode: instruction.opcode,
        },
    }
}

fn lower_statement(
    instruction: &MCInst,
    statements: &mut Vec<Statement>,
    flags: &mut Option<FlagState>,
    identifiers: &mut Identifiers,
) {
    let lowered: bool = match instruction.opcode {
        A64Opcode::Add => lower_binary(instruction, BinaryOp::Add, statements),
        A64Opcode::Sub => lower_binary(instruction, BinaryOp::Sub, statements),
        A64Opcode::And => lower_binary(instruction, BinaryOp::And, statements),
        A64Opcode::Orr => lower_binary(instruction, BinaryOp::Orr, statements),
        A64Opcode::Eor => lower_binary(instruction, BinaryOp::Eor, statements),
        A64Opcode::Mul => lower_binary(instruction, BinaryOp::Mul, statements),
        A64Opcode::Udiv => lower_binary(instruction, BinaryOp::UnsignedDiv, statements),
        A64Opcode::Sdiv => lower_binary(instruction, BinaryOp::SignedDiv, statements),
        A64Opcode::Lslv => lower_binary(instruction, BinaryOp::Lslv, statements),
        A64Opcode::Lsrv => lower_binary(instruction, BinaryOp::Lsrv, statements),
        A64Opcode::Asrv => lower_binary(instruction, BinaryOp::Asrv, statements),
        A64Opcode::Rorv => lower_binary(instruction, BinaryOp::Rorv, statements),
        A64Opcode::Madd => lower_multiply_accumulate(instruction, false, statements),
        A64Opcode::Msub => lower_multiply_accumulate(instruction, true, statements),
        A64Opcode::Mov => lower_move(instruction, statements),
        A64Opcode::Adds => lower_flagged(
            instruction,
            FlagOperation::Add,
            statements,
            flags,
            identifiers,
        ),
        A64Opcode::Subs => lower_flagged(
            instruction,
            FlagOperation::Sub,
            statements,
            flags,
            identifiers,
        ),
        A64Opcode::Ands => lower_flagged(
            instruction,
            FlagOperation::And,
            statements,
            flags,
            identifiers,
        ),
        A64Opcode::Cmn => lower_flagged_compare(
            instruction,
            FlagOperation::Add,
            statements,
            flags,
            identifiers,
        ),
        A64Opcode::Cmp => lower_flagged_compare(
            instruction,
            FlagOperation::Sub,
            statements,
            flags,
            identifiers,
        ),
        A64Opcode::Tst => lower_flagged_compare(
            instruction,
            FlagOperation::And,
            statements,
            flags,
            identifiers,
        ),
        A64Opcode::Csel | A64Opcode::Csinc => {
            lower_conditional_select(instruction, statements, *flags)
        }
        _ => false,
    };
    if !lowered {
        statements.push(Statement::Abstain {
            va: instruction.va,
            opcode: instruction.opcode,
        });
        *flags = None;
    }
}

fn lower_binary(instruction: &MCInst, op: BinaryOp, statements: &mut Vec<Statement>) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let left: Option<&Operand> = instruction.operands.get(1);
    let right: Option<&Operand> = instruction.operands.get(2);
    match (destination, left, right) {
        (Some(dest), Some(lhs), Some(rhs)) => {
            let width: Width = binary_width(dest, lhs);
            let left_value: Option<Expr> = read_operand(lhs, width);
            let right_value: Option<Expr> = read_operand(rhs, width);
            match (left_value, right_value) {
                (Some(left_expr), Some(right_expr)) => {
                    let expression: Expr = binary(op, left_expr, right_expr, width);
                    match write_destination(dest, expression) {
                        DestinationWrite::Assign(statement) => statements.push(statement),
                        DestinationWrite::Discard => {}
                        DestinationWrite::Invalid => return false,
                    }
                    true
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn lower_multiply_accumulate(
    instruction: &MCInst,
    subtract: bool,
    statements: &mut Vec<Statement>,
) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let left: Option<&Operand> = instruction.operands.get(1);
    let right: Option<&Operand> = instruction.operands.get(2);
    let accumulator: Option<&Operand> = instruction.operands.get(3);
    match (destination, left, right, accumulator) {
        (Some(dest), Some(lhs), Some(rhs), Some(addend)) => {
            let width: Width = destination_width_or_64(dest);
            let left_value: Option<Expr> = read_operand(lhs, width);
            let right_value: Option<Expr> = read_operand(rhs, width);
            let addend_value: Option<Expr> = read_operand(addend, width);
            match (left_value, right_value, addend_value) {
                (Some(lhs_expr), Some(rhs_expr), Some(addend_expr)) => {
                    let product: Expr = binary(BinaryOp::Mul, lhs_expr, rhs_expr, width);
                    let op: BinaryOp = if subtract {
                        BinaryOp::Sub
                    } else {
                        BinaryOp::Add
                    };
                    let expression: Expr = binary(op, addend_expr, product, width);
                    match write_destination(dest, expression) {
                        DestinationWrite::Assign(statement) => statements.push(statement),
                        DestinationWrite::Discard => {}
                        DestinationWrite::Invalid => return false,
                    }
                    true
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn lower_move(instruction: &MCInst, statements: &mut Vec<Statement>) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let source: Option<&Operand> = instruction.operands.get(1);
    match (destination, source) {
        (Some(dest), Some(value)) => {
            let width: Width = destination_width_or_64(dest);
            read_operand(value, width).map_or(false, |expression: Expr| {
                match write_destination(dest, expression) {
                    DestinationWrite::Assign(statement) => {
                        statements.push(statement);
                        true
                    }
                    DestinationWrite::Discard => true,
                    DestinationWrite::Invalid => false,
                }
            })
        }
        _ => false,
    }
}

fn lower_flagged(
    instruction: &MCInst,
    operation: FlagOperation,
    statements: &mut Vec<Statement>,
    flags: &mut Option<FlagState>,
    identifiers: &mut Identifiers,
) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let left: Option<&Operand> = instruction.operands.get(1);
    let right: Option<&Operand> = instruction.operands.get(2);
    match (destination, left, right) {
        (Some(dest), Some(lhs), Some(rhs)) => lower_flag_operation(
            Some(dest),
            lhs,
            rhs,
            operation,
            statements,
            flags,
            identifiers,
        ),
        _ => false,
    }
}

fn lower_flagged_compare(
    instruction: &MCInst,
    operation: FlagOperation,
    statements: &mut Vec<Statement>,
    flags: &mut Option<FlagState>,
    identifiers: &mut Identifiers,
) -> bool {
    let left: Option<&Operand> = instruction.operands.first();
    let right: Option<&Operand> = instruction.operands.get(1);
    match (left, right) {
        (Some(lhs), Some(rhs)) => {
            lower_flag_operation(None, lhs, rhs, operation, statements, flags, identifiers)
        }
        _ => false,
    }
}

fn lower_flag_operation(
    destination: Option<&Operand>,
    left: &Operand,
    right: &Operand,
    operation: FlagOperation,
    statements: &mut Vec<Statement>,
    flags: &mut Option<FlagState>,
    identifiers: &mut Identifiers,
) -> bool {
    let width: Width = destination.map_or_else(
        || operand_width_or_64(left),
        |value: &Operand| binary_width(value, left),
    );
    let left_expression: Option<Expr> = read_operand(left, width);
    let right_expression: Option<Expr> = read_operand(right, width);
    let identifiers: Option<(u32, u32, u32, u32)> = identifiers.reserve_flag_values();
    match (left_expression, right_expression, identifiers) {
        (Some(lhs), Some(rhs), Some((left_id, right_id, result_id, flag_id))) => {
            let binary_op: BinaryOp = flag_binary_op(operation);
            let result: Expr = binary(
                binary_op,
                Expr::Captured(left_id),
                Expr::Captured(right_id),
                width,
            );
            let source: FlagSource = FlagSource {
                id: flag_id,
                operation,
                left: left_id,
                right: right_id,
                result: result_id,
                width,
            };
            let mut produced: Vec<Statement> = vec![
                Statement::Capture {
                    value: left_id,
                    expression: lhs,
                },
                Statement::Capture {
                    value: right_id,
                    expression: rhs,
                },
                Statement::Capture {
                    value: result_id,
                    expression: result,
                },
                Statement::SetFlags { source },
            ];
            if let Some(dest) = destination {
                match write_destination(dest, Expr::Captured(result_id)) {
                    DestinationWrite::Assign(statement) => produced.push(statement),
                    DestinationWrite::Discard => {}
                    DestinationWrite::Invalid => return false,
                }
            }
            statements.append(&mut produced);
            *flags = Some(FlagState { source });
            true
        }
        _ => false,
    }
}

fn lower_conditional_select(
    instruction: &MCInst,
    statements: &mut Vec<Statement>,
    flags: Option<FlagState>,
) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let when_true: Option<&Operand> = instruction.operands.get(1);
    let when_false: Option<&Operand> = instruction.operands.get(2);
    let condition: Option<u8> = instruction.operands.get(3).and_then(condition_from_operand);
    match (destination, when_true, when_false, condition, flags) {
        (Some(dest), Some(on_true), Some(on_false), Some(code), Some(state)) => {
            let width: Width = destination_width_or_64(dest);
            if instruction.opcode == A64Opcode::Csinc
                && is_zero_register(on_true)
                && is_zero_register(on_false)
            {
                let cset_code: Option<u8> = invert_condition(code);
                cset_code
                    .and_then(|value: u8| predicate_from_flags(state.source, value))
                    .map_or(false, |predicate: Predicate| {
                        match write_destination(
                            dest,
                            Expr::ZeroExtendPredicate {
                                predicate: Box::new(predicate),
                                width,
                            },
                        ) {
                            DestinationWrite::Assign(statement) => {
                                statements.push(statement);
                                true
                            }
                            DestinationWrite::Discard => true,
                            DestinationWrite::Invalid => false,
                        }
                    })
            } else {
                let predicate: Option<Predicate> = predicate_from_flags(state.source, code);
                let true_value: Option<Expr> = read_operand(on_true, width);
                let false_value: Option<Expr> = read_operand(on_false, width);
                match (predicate, true_value, false_value) {
                    (Some(test), Some(true_expr), Some(false_expr)) => {
                        let alternative: Expr = match instruction.opcode {
                            A64Opcode::Csel => false_expr,
                            A64Opcode::Csinc => {
                                binary(BinaryOp::Add, false_expr, Expr::Constant(1), width)
                            }
                            _ => return false,
                        };
                        let expression: Expr = Expr::Select {
                            predicate: Box::new(test),
                            when_true: Box::new(true_expr),
                            when_false: Box::new(alternative),
                        };
                        match write_destination(dest, expression) {
                            DestinationWrite::Assign(statement) => statements.push(statement),
                            DestinationWrite::Discard => {}
                            DestinationWrite::Invalid => return false,
                        }
                        true
                    }
                    _ => false,
                }
            }
        }
        _ => false,
    }
}

fn predicate_from_flags(source: FlagSource, code: u8) -> Option<Predicate> {
    match source.operation {
        FlagOperation::Add => predicate_from_add(source, code),
        FlagOperation::Sub => predicate_from_sub(source, code),
        FlagOperation::And => predicate_from_and(source, code),
    }
}

fn predicate_from_sub(source: FlagSource, code: u8) -> Option<Predicate> {
    let left: Expr = Expr::Captured(source.left);
    let right: Expr = Expr::Captured(source.right);
    let result: Expr = Expr::Captured(source.result);
    let overflow: Predicate = signed_overflow(source);
    let negative: Predicate = Predicate::Negative {
        value: result,
        width: source.width,
    };
    match code {
        0 => Some(equal(left, right, source.width)),
        1 => Some(not_equal(left, right, source.width)),
        2 => Some(unsigned_greater_or_equal(left, right, source.width)),
        3 => Some(unsigned_less_than(left, right, source.width)),
        4 => Some(negative),
        5 => Some(not(negative)),
        6 => Some(overflow),
        7 => Some(not(overflow)),
        8 => Some(unsigned_greater_than(left, right, source.width)),
        9 => Some(unsigned_less_or_equal(left, right, source.width)),
        10 => Some(signed_greater_or_equal(left, right, source.width)),
        11 => Some(signed_less_than(left, right, source.width)),
        12 => Some(signed_greater_than(left, right, source.width)),
        13 => Some(signed_less_or_equal(left, right, source.width)),
        14 => Some(Predicate::Constant(true)),
        _ => None,
    }
}

fn predicate_from_add(source: FlagSource, code: u8) -> Option<Predicate> {
    let left: Expr = Expr::Captured(source.left);
    let right: Expr = Expr::Captured(source.right);
    let result: Expr = Expr::Captured(source.result);
    let zero: Expr = Expr::Constant(0);
    let carry: Predicate = Predicate::UnsignedAddOverflow {
        left,
        right,
        width: source.width,
    };
    let overflow: Predicate = signed_overflow(source);
    let negative: Predicate = Predicate::Negative {
        value: result.clone(),
        width: source.width,
    };
    let nonzero: Predicate = not(equal(result.clone(), zero.clone(), source.width));
    let nonnegative: Predicate = not(negative.clone());
    let no_overflow: Predicate = not(overflow.clone());
    let n_equals_v: Predicate = any(vec![
        all(vec![nonnegative.clone(), no_overflow.clone()]),
        all(vec![negative.clone(), overflow.clone()]),
    ]);
    let n_not_equals_v: Predicate = any(vec![
        all(vec![negative.clone(), no_overflow]),
        all(vec![nonnegative, overflow.clone()]),
    ]);
    match code {
        0 => Some(equal(result, zero, source.width)),
        1 => Some(nonzero),
        2 => Some(carry),
        3 => Some(not(carry)),
        4 => Some(negative),
        5 => Some(not(negative)),
        6 => Some(overflow),
        7 => Some(not(overflow)),
        8 => Some(all(vec![carry, nonzero])),
        9 => Some(any(vec![not(carry), equal(result, zero, source.width)])),
        10 => Some(n_equals_v),
        11 => Some(n_not_equals_v),
        12 => Some(all(vec![
            not(equal(result, zero, source.width)),
            n_equals_v,
        ])),
        13 => Some(any(vec![equal(result, zero, source.width), n_not_equals_v])),
        14 => Some(Predicate::Constant(true)),
        _ => None,
    }
}

fn predicate_from_and(source: FlagSource, code: u8) -> Option<Predicate> {
    let result: Expr = Expr::Captured(source.result);
    let zero: Expr = Expr::Constant(0);
    let negative: Predicate = Predicate::Negative {
        value: result.clone(),
        width: source.width,
    };
    let nonzero: Predicate = not(equal(result.clone(), zero.clone(), source.width));
    let nonnegative: Predicate = not(negative.clone());
    match code {
        0 => Some(equal(result, zero, source.width)),
        1 => Some(nonzero),
        2 => Some(Predicate::Constant(false)),
        3 => Some(Predicate::Constant(true)),
        4 => Some(negative),
        5 => Some(nonnegative),
        6 => Some(Predicate::Constant(false)),
        7 => Some(Predicate::Constant(true)),
        8 => Some(Predicate::Constant(false)),
        9 => Some(Predicate::Constant(true)),
        10 => Some(nonnegative),
        11 => Some(negative),
        12 => Some(all(vec![nonzero, nonnegative])),
        13 => Some(any(vec![equal(result, zero, source.width), negative])),
        14 => Some(Predicate::Constant(true)),
        _ => None,
    }
}

fn signed_overflow(source: FlagSource) -> Predicate {
    Predicate::SignedOverflow {
        operation: source.operation,
        left: Expr::Captured(source.left),
        right: Expr::Captured(source.right),
        width: source.width,
    }
}

fn equal(left: Expr, right: Expr, width: Width) -> Predicate {
    Predicate::Equal { left, right, width }
}

fn not_equal(left: Expr, right: Expr, width: Width) -> Predicate {
    Predicate::NotEqual { left, right, width }
}

fn unsigned_less_than(left: Expr, right: Expr, width: Width) -> Predicate {
    Predicate::UnsignedLessThan { left, right, width }
}

fn unsigned_less_or_equal(left: Expr, right: Expr, width: Width) -> Predicate {
    Predicate::UnsignedLessOrEqual { left, right, width }
}

fn unsigned_greater_than(left: Expr, right: Expr, width: Width) -> Predicate {
    Predicate::UnsignedGreaterThan { left, right, width }
}

fn unsigned_greater_or_equal(left: Expr, right: Expr, width: Width) -> Predicate {
    Predicate::UnsignedGreaterOrEqual { left, right, width }
}

fn signed_less_than(left: Expr, right: Expr, width: Width) -> Predicate {
    Predicate::SignedLessThan { left, right, width }
}

fn signed_less_or_equal(left: Expr, right: Expr, width: Width) -> Predicate {
    Predicate::SignedLessOrEqual { left, right, width }
}

fn signed_greater_than(left: Expr, right: Expr, width: Width) -> Predicate {
    Predicate::SignedGreaterThan { left, right, width }
}

fn signed_greater_or_equal(left: Expr, right: Expr, width: Width) -> Predicate {
    Predicate::SignedGreaterOrEqual { left, right, width }
}

fn all(predicates: Vec<Predicate>) -> Predicate {
    Predicate::All(predicates)
}

fn any(predicates: Vec<Predicate>) -> Predicate {
    Predicate::Any(predicates)
}

fn not(predicate: Predicate) -> Predicate {
    Predicate::Not(Box::new(predicate))
}

fn invert_condition(code: u8) -> Option<u8> {
    if code < 14 { Some(code ^ 1) } else { None }
}

fn flag_binary_op(operation: FlagOperation) -> BinaryOp {
    match operation {
        FlagOperation::Add => BinaryOp::Add,
        FlagOperation::Sub => BinaryOp::Sub,
        FlagOperation::And => BinaryOp::And,
    }
}

fn binary(op: BinaryOp, left: Expr, right: Expr, width: Width) -> Expr {
    Expr::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
        width,
    }
}

fn label_operand(operands: &[Operand]) -> Option<u64> {
    operands.iter().find_map(label_from_operand)
}

fn label_from_operand(operand: &Operand) -> Option<u64> {
    match operand {
        Operand::PcRelLabel { target } => Some(*target),
        _ => None,
    }
}

fn condition_from_operand(operand: &Operand) -> Option<u8> {
    match operand {
        Operand::CondCode(code) => Some(*code),
        _ => None,
    }
}

fn immediate_from_operand(operand: &Operand) -> Option<i64> {
    match operand {
        Operand::Imm(value) => Some(*value),
        _ => None,
    }
}

fn destination_width(operand: &Operand) -> Option<Width> {
    match operand {
        Operand::Reg {
            view: RegView::W, ..
        } => Some(Width::W32),
        Operand::Reg {
            view: RegView::X | RegView::Sp,
            ..
        } => Some(Width::W64),
        Operand::Reg {
            view: RegView::Zr, ..
        } => None,
        _ => None,
    }
}

fn destination_width_or_64(operand: &Operand) -> Width {
    destination_width(operand).map_or(Width::W64, |width: Width| width)
}

fn operand_width_or_64(operand: &Operand) -> Width {
    operand_width(operand).map_or(Width::W64, |width: Width| width)
}

fn binary_width(destination: &Operand, left: &Operand) -> Width {
    let fallback: Width = operand_width_or_64(left);
    destination_width(destination).map_or(fallback, core::convert::identity)
}

fn operand_width(operand: &Operand) -> Option<Width> {
    match operand {
        Operand::Reg { view, .. }
        | Operand::ShiftedReg { view, .. }
        | Operand::ExtendedReg { view, .. } => match view {
            RegView::W => Some(Width::W32),
            RegView::X | RegView::Sp => Some(Width::W64),
            RegView::Zr | RegView::S | RegView::D => None,
        },
        _ => None,
    }
}

fn read_operand(operand: &Operand, width: Width) -> Option<Expr> {
    match operand {
        Operand::Reg { n, view } => read_register(*n, *view, width),
        Operand::Imm(value) => Some(Expr::Constant(u64::from_ne_bytes(value.to_ne_bytes()))),
        Operand::ShiftedReg {
            n,
            view,
            shift,
            amount,
        } => {
            let value: Expr = read_register(*n, *view, width)?;
            if *amount == 0 {
                Some(value)
            } else {
                Some(Expr::Shift {
                    kind: *shift,
                    value: Box::new(value),
                    amount: *amount,
                    width,
                })
            }
        }
        Operand::ExtendedReg {
            n,
            view,
            extend,
            amount,
        } => {
            let value: Expr = read_register(*n, *view, width)?;
            let extended: Expr = Expr::Extend {
                kind: *extend,
                value: Box::new(value),
            };
            if *amount == 0 {
                Some(extended)
            } else {
                Some(Expr::Shift {
                    kind: ShiftKind::Lsl,
                    value: Box::new(extended),
                    amount: *amount,
                    width,
                })
            }
        }
        Operand::PcRelLabel { target } => Some(Expr::Constant(*target)),
        Operand::CondCode(_)
        | Operand::BtiTarget(_)
        | Operand::FpImm(_)
        | Operand::SysReg(_)
        | Operand::MemBaseImm { .. }
        | Operand::MemBaseReg { .. } => None,
    }
}

fn read_register(n: u8, view: RegView, _expected_width: Width) -> Option<Expr> {
    match view {
        RegView::W if n < 31 => Some(Expr::Truncate32(Box::new(Expr::Read(Location::X(n))))),
        RegView::X if n < 31 => Some(Expr::Read(Location::X(n))),
        RegView::Sp if n == 31 => Some(Expr::Read(Location::Sp)),
        RegView::Zr if n == 31 => Some(Expr::Constant(0)),
        _ => None,
    }
}

fn write_destination(operand: &Operand, value: Expr) -> DestinationWrite {
    match operand {
        Operand::Reg {
            n,
            view: RegView::W,
        } if *n < 31 => DestinationWrite::Assign(Statement::Assign {
            destination: Location::X(*n),
            value: Expr::ZeroExtend32(Box::new(value)),
        }),
        Operand::Reg {
            n,
            view: RegView::X,
        } if *n < 31 => DestinationWrite::Assign(Statement::Assign {
            destination: Location::X(*n),
            value,
        }),
        Operand::Reg {
            n: 31,
            view: RegView::Sp,
        } => DestinationWrite::Assign(Statement::Assign {
            destination: Location::Sp,
            value,
        }),
        Operand::Reg {
            n: 31,
            view: RegView::Zr,
        } => DestinationWrite::Discard,
        _ => DestinationWrite::Invalid,
    }
}

fn is_zero_register(operand: &Operand) -> bool {
    matches!(
        operand,
        Operand::Reg {
            n: 31,
            view: RegView::Zr
        }
    )
}

const fn width_bits(width: Width) -> u8 {
    match width {
        Width::W32 => 32,
        Width::W64 => 64,
    }
}

impl Identifiers {
    fn reserve_flag_values(&mut self) -> Option<(u32, u32, u32, u32)> {
        let left: u32 = self.next_value;
        let right: u32 = left.checked_add(1)?;
        let result: u32 = right.checked_add(1)?;
        let next_value: u32 = result.checked_add(1)?;
        let flag: u32 = self.next_flag;
        let next_flag: u32 = flag.checked_add(1)?;
        self.next_value = next_value;
        self.next_flag = next_flag;
        Some((left, right, result, flag))
    }
}
