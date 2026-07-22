use std::collections::BTreeSet;

use super::{A64Opcode, ExtendKind, IndexMode, MCInst, Operand, RegView, ShiftKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    W32,
    W64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpType {
    F32,
    F64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    X(u8),
    Sp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpBinaryOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpCondition {
    Eq,
    Ne,
    Hs,
    Lo,
    Mi,
    Pl,
    Vs,
    Vc,
    Hi,
    Ls,
    Ge,
    Lt,
    Gt,
    Le,
    Al,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpRounding {
    FpControl,
    TowardZero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOrdering {
    Relaxed,
    Acquire,
    Release,
    AcqRel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOp {
    Add,
    Clear,
    Eor,
    Set,
    Swap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicDestination {
    Register { location: Location, width: Width },
    Discard,
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
    FpToBits {
        value: Box<FpExpr>,
        ty: FpType,
    },
    FpToInteger {
        value: Box<FpExpr>,
        ty: FpType,
        signed: bool,
        width: Width,
        rounding: FpRounding,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FpExpr {
    Read {
        register: u8,
        ty: FpType,
    },
    Captured(u32),
    Zero {
        ty: FpType,
    },
    Immediate {
        encoding: u8,
        ty: FpType,
    },
    Binary {
        op: FpBinaryOp,
        left: Box<Self>,
        right: Box<Self>,
        ty: FpType,
    },
    Convert {
        value: Box<Self>,
        source: FpType,
        destination: FpType,
        rounding: FpRounding,
    },
    FromInteger {
        value: Box<Expr>,
        signed: bool,
        ty: FpType,
        rounding: FpRounding,
    },
    FromBits {
        value: Box<Expr>,
        ty: FpType,
    },
    Select {
        predicate: Box<Predicate>,
        when_true: Box<Self>,
        when_false: Box<Self>,
        ty: FpType,
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
    FpCondition {
        condition: FpCondition,
        left: FpExpr,
        right: FpExpr,
        ty: FpType,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FpFlagSource {
    pub id: u32,
    pub left: u32,
    pub right: u32,
    pub ty: FpType,
    pub signaling: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    NoOp {
        va: u64,
        opcode: A64Opcode,
    },
    Capture {
        value: u32,
        expression: Expr,
    },
    FpCapture {
        value: u32,
        expression: FpExpr,
    },
    SetFlags {
        source: FlagSource,
    },
    SetFpFlags {
        source: FpFlagSource,
    },
    Assign {
        destination: Location,
        value: Expr,
    },
    AssignFp {
        register: u8,
        ty: FpType,
        value: FpExpr,
    },
    Load {
        result: AtomicDestination,
        address: Expr,
        width: Width,
    },
    AtomicCompareExchange {
        result: AtomicDestination,
        expected: Expr,
        replacement: Expr,
        address: Expr,
        width: Width,
        ordering: AtomicOrdering,
    },
    AtomicRmw {
        operation: AtomicOp,
        result: AtomicDestination,
        value: Expr,
        address: Expr,
        width: Width,
        ordering: AtomicOrdering,
    },
    LoadExclusive {
        result: AtomicDestination,
        address: Expr,
        width: Width,
        ordering: AtomicOrdering,
    },
    StoreExclusive {
        status: AtomicDestination,
        value: Expr,
        address: Expr,
        width: Width,
        ordering: AtomicOrdering,
    },
    Abstain {
        va: u64,
        opcode: A64Opcode,
    },
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
    IndirectGoto {
        target: Expr,
    },
    IndirectCall {
        target: Expr,
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
enum FlagState {
    Integer(FlagSource),
    Floating(FpFlagSource),
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
            | A64Opcode::Retaa
            | A64Opcode::Retab
            | A64Opcode::Br
            | A64Opcode::Blr
            | A64Opcode::Braa
            | A64Opcode::Brab
            | A64Opcode::Blraa
            | A64Opcode::Blrab
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
        A64Opcode::Ret | A64Opcode::Retaa | A64Opcode::Retab => Some(return_control(instruction)),
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
        A64Opcode::Br => Some(indirect_goto(instruction, false)),
        A64Opcode::Braa | A64Opcode::Brab => Some(indirect_goto(instruction, true)),
        A64Opcode::Blr => Some(indirect_call(instruction, fallthrough, false)),
        A64Opcode::Blraa | A64Opcode::Blrab => Some(indirect_call(instruction, fallthrough, true)),
        A64Opcode::Unallocated | A64Opcode::Unmodeled(_) => Some(abstain_control(instruction)),
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
    if matches!(instruction.opcode, A64Opcode::Retaa | A64Opcode::Retab)
        && !instruction.operands.is_empty()
    {
        return abstain_control(instruction);
    }
    let target: Option<Expr> = instruction
        .operands
        .first()
        .and_then(|operand: &Operand| read_operand(operand, Width::W64))
        .or_else(|| {
            matches!(instruction.opcode, A64Opcode::Retaa | A64Opcode::Retab)
                .then_some(Expr::Read(Location::X(30)))
        });
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
        (Some(state), Some(code)) => predicate_from_flag_state(state, code),
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

fn indirect_goto(instruction: &MCInst, has_modifier: bool) -> ControlLowering {
    let target: Option<Expr> = instruction
        .operands
        .first()
        .and_then(|operand: &Operand| read_operand(operand, Width::W64));
    let modifier: bool = !has_modifier
        || instruction
            .operands
            .get(1)
            .and_then(|operand: &Operand| read_operand(operand, Width::W64))
            .is_some();
    match (target, modifier) {
        (Some(value), true) => ControlLowering {
            statements: Vec::new(),
            terminator: Terminator::IndirectGoto { target: value },
        },
        _ => abstain_control(instruction),
    }
}

fn indirect_call(instruction: &MCInst, fallthrough: Target, has_modifier: bool) -> ControlLowering {
    let target: Option<Expr> = instruction
        .operands
        .first()
        .and_then(|operand: &Operand| read_operand(operand, Width::W64));
    let modifier: bool = !has_modifier
        || instruction
            .operands
            .get(1)
            .and_then(|operand: &Operand| read_operand(operand, Width::W64))
            .is_some();
    let return_address: Option<u64> = instruction.va.checked_add(u64::from(instruction.len));
    match (target, modifier, return_address) {
        (Some(value), true, Some(link)) => ControlLowering {
            statements: vec![Statement::Assign {
                destination: Location::X(30),
                value: Expr::Constant(link),
            }],
            terminator: Terminator::IndirectCall {
                target: value,
                return_to: fallthrough,
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
        A64Opcode::Paciasp
        | A64Opcode::Pacibsp
        | A64Opcode::Autiasp
        | A64Opcode::Autibsp
        | A64Opcode::Bti => lower_no_op(instruction, statements),
        A64Opcode::Ldraa | A64Opcode::Ldrab => lower_authenticated_load(instruction, statements),
        A64Opcode::Fadd => lower_fp_binary(instruction, FpBinaryOp::Add, statements),
        A64Opcode::Fsub => lower_fp_binary(instruction, FpBinaryOp::Sub, statements),
        A64Opcode::Fmul => lower_fp_binary(instruction, FpBinaryOp::Mul, statements),
        A64Opcode::Fdiv => lower_fp_binary(instruction, FpBinaryOp::Div, statements),
        A64Opcode::Fcvt => lower_fp_convert(instruction, statements),
        A64Opcode::Scvtf => lower_integer_to_fp(instruction, true, statements),
        A64Opcode::Ucvtf => lower_integer_to_fp(instruction, false, statements),
        A64Opcode::Fcvtzs => lower_fp_to_integer(instruction, true, statements),
        A64Opcode::Fcvtzu => lower_fp_to_integer(instruction, false, statements),
        A64Opcode::Fmov => lower_fp_move(instruction, statements),
        A64Opcode::Fcmp | A64Opcode::Fcmpe => {
            lower_fp_compare(instruction, statements, flags, identifiers)
        }
        A64Opcode::Fcsel => lower_fp_conditional_select(instruction, statements, *flags),
        A64Opcode::Cas | A64Opcode::Casa | A64Opcode::Casl | A64Opcode::Casal => {
            lower_compare_exchange(instruction, statements, identifiers)
        }
        A64Opcode::Ldadd
        | A64Opcode::Ldadda
        | A64Opcode::Ldaddl
        | A64Opcode::Ldaddal
        | A64Opcode::Ldclr
        | A64Opcode::Ldclra
        | A64Opcode::Ldclrl
        | A64Opcode::Ldclral
        | A64Opcode::Ldeor
        | A64Opcode::Ldeora
        | A64Opcode::Ldeorl
        | A64Opcode::Ldeoral
        | A64Opcode::Ldset
        | A64Opcode::Ldseta
        | A64Opcode::Ldsetl
        | A64Opcode::Ldsetal
        | A64Opcode::Swp
        | A64Opcode::Swpa
        | A64Opcode::Swpl
        | A64Opcode::Swpal => lower_atomic_rmw(instruction, statements, identifiers),
        A64Opcode::Ldxr | A64Opcode::Ldaxr => lower_exclusive_load(instruction, statements),
        A64Opcode::Stxr | A64Opcode::Stlxr => {
            lower_exclusive_store(instruction, statements, identifiers)
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

fn lower_no_op(instruction: &MCInst, statements: &mut Vec<Statement>) -> bool {
    let valid: bool = match instruction.opcode {
        A64Opcode::Paciasp | A64Opcode::Pacibsp | A64Opcode::Autiasp | A64Opcode::Autibsp => {
            instruction.operands.is_empty()
        }
        A64Opcode::Bti => {
            instruction.operands.is_empty()
                || matches!(instruction.operands.as_slice(), [Operand::BtiTarget(_)])
        }
        _ => false,
    };
    if !valid {
        return false;
    }
    statements.push(Statement::NoOp {
        va: instruction.va,
        opcode: instruction.opcode,
    });
    true
}

fn lower_authenticated_load(instruction: &MCInst, statements: &mut Vec<Statement>) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let address: Option<&Operand> = instruction.operands.get(1);
    match (destination, address) {
        (Some(output), Some(memory)) => {
            let result: Option<AtomicDestination> = atomic_destination(output, Width::W64);
            let address_value: Option<Expr> = memory_address(memory);
            match (result, address_value) {
                (Some(destination), Some(value)) => {
                    statements.push(Statement::Load {
                        result: destination,
                        address: value,
                        width: Width::W64,
                    });
                    true
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn lower_fp_binary(
    instruction: &MCInst,
    operation: FpBinaryOp,
    statements: &mut Vec<Statement>,
) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let left: Option<&Operand> = instruction.operands.get(1);
    let right: Option<&Operand> = instruction.operands.get(2);
    match (destination, left, right) {
        (Some(output), Some(lhs), Some(rhs)) => {
            let ty: Option<FpType> = fp_type(output);
            ty.map_or(false, |value_type: FpType| {
                let left_value: Option<FpExpr> = read_fp_register(lhs, value_type);
                let right_value: Option<FpExpr> = read_fp_register(rhs, value_type);
                match (left_value, right_value, fp_destination(output, value_type)) {
                    (Some(left_expr), Some(right_expr), Some(register)) => {
                        statements.push(Statement::AssignFp {
                            register,
                            ty: value_type,
                            value: FpExpr::Binary {
                                op: operation,
                                left: Box::new(left_expr),
                                right: Box::new(right_expr),
                                ty: value_type,
                            },
                        });
                        true
                    }
                    _ => false,
                }
            })
        }
        _ => false,
    }
}

fn lower_fp_convert(instruction: &MCInst, statements: &mut Vec<Statement>) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let source: Option<&Operand> = instruction.operands.get(1);
    match (destination, source) {
        (Some(output), Some(input)) => {
            let destination_type: Option<FpType> = fp_type(output);
            let source_type: Option<FpType> = fp_type(input);
            match (destination_type, source_type) {
                (Some(output_type), Some(input_type)) if output_type != input_type => {
                    match (
                        read_fp_register(input, input_type),
                        fp_destination(output, output_type),
                    ) {
                        (Some(value), Some(register)) => {
                            statements.push(Statement::AssignFp {
                                register,
                                ty: output_type,
                                value: FpExpr::Convert {
                                    value: Box::new(value),
                                    source: input_type,
                                    destination: output_type,
                                    rounding: FpRounding::FpControl,
                                },
                            });
                            true
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn lower_integer_to_fp(
    instruction: &MCInst,
    signed: bool,
    statements: &mut Vec<Statement>,
) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let source: Option<&Operand> = instruction.operands.get(1);
    match (destination, source) {
        (Some(output), Some(input)) => {
            let ty: Option<FpType> = fp_type(output);
            let width: Option<Width> = operand_width(input);
            match (ty, width) {
                (Some(value_type), Some(integer_width))
                    if integer_width == fp_width(value_type) =>
                {
                    match (
                        read_data_operand(input, integer_width),
                        fp_destination(output, value_type),
                    ) {
                        (Some(value), Some(register)) => {
                            statements.push(Statement::AssignFp {
                                register,
                                ty: value_type,
                                value: FpExpr::FromInteger {
                                    value: Box::new(value),
                                    signed,
                                    ty: value_type,
                                    rounding: FpRounding::FpControl,
                                },
                            });
                            true
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn lower_fp_to_integer(
    instruction: &MCInst,
    signed: bool,
    statements: &mut Vec<Statement>,
) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let source: Option<&Operand> = instruction.operands.get(1);
    match (destination, source) {
        (Some(output), Some(input)) => {
            let ty: Option<FpType> = fp_type(input);
            let width: Option<Width> = match (destination_width(output), ty) {
                (Some(value), Some(_)) => Some(value),
                (None, Some(value_type)) if is_zero_register(output) => Some(fp_width(value_type)),
                _ => None,
            };
            match (width, ty) {
                (Some(integer_width), Some(value_type))
                    if integer_width == fp_width(value_type) =>
                {
                    let value: Option<FpExpr> = read_fp_register(input, value_type);
                    value.map_or(false, |input_value: FpExpr| {
                        match write_destination(
                            output,
                            Expr::FpToInteger {
                                value: Box::new(input_value),
                                ty: value_type,
                                signed,
                                width: integer_width,
                                rounding: FpRounding::TowardZero,
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
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn lower_fp_move(instruction: &MCInst, statements: &mut Vec<Statement>) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let source: Option<&Operand> = instruction.operands.get(1);
    match (destination, source) {
        (Some(output), Some(input)) => match (fp_type(output), fp_type(input)) {
            (Some(output_type), Some(input_type)) if output_type == input_type => {
                match (
                    read_fp_register(input, input_type),
                    fp_destination(output, output_type),
                ) {
                    (Some(value), Some(register)) => {
                        statements.push(Statement::AssignFp {
                            register,
                            ty: output_type,
                            value,
                        });
                        true
                    }
                    _ => false,
                }
            }
            (Some(output_type), None) => match input {
                Operand::FpImm(encoding) => {
                    fp_destination(output, output_type).map_or(false, |register: u8| {
                        statements.push(Statement::AssignFp {
                            register,
                            ty: output_type,
                            value: FpExpr::Immediate {
                                encoding: *encoding,
                                ty: output_type,
                            },
                        });
                        true
                    })
                }
                _ => {
                    let width: Width = fp_width(output_type);
                    match (
                        read_data_operand(input, width),
                        fp_destination(output, output_type),
                    ) {
                        (Some(value), Some(register)) => {
                            statements.push(Statement::AssignFp {
                                register,
                                ty: output_type,
                                value: FpExpr::FromBits {
                                    value: Box::new(value),
                                    ty: output_type,
                                },
                            });
                            true
                        }
                        _ => false,
                    }
                }
            },
            (None, Some(input_type)) => {
                let width: Width = fp_width(input_type);
                let value: Option<FpExpr> = read_fp_register(input, input_type);
                match value {
                    Some(input_value) if data_destination_matches(output, width) => {
                        match write_destination(
                            output,
                            Expr::FpToBits {
                                value: Box::new(input_value),
                                ty: input_type,
                            },
                        ) {
                            DestinationWrite::Assign(statement) => {
                                statements.push(statement);
                                true
                            }
                            DestinationWrite::Discard => true,
                            DestinationWrite::Invalid => false,
                        }
                    }
                    _ => false,
                }
            }
            _ => false,
        },
        _ => false,
    }
}

fn lower_fp_compare(
    instruction: &MCInst,
    statements: &mut Vec<Statement>,
    flags: &mut Option<FlagState>,
    identifiers: &mut Identifiers,
) -> bool {
    let left: Option<&Operand> = instruction.operands.first();
    let right: Option<&Operand> = instruction.operands.get(1);
    match (left, right) {
        (Some(lhs), Some(rhs)) => {
            let ty: Option<FpType> = fp_type(lhs);
            ty.map_or(false, |value_type: FpType| {
                let left_value: Option<FpExpr> = read_fp_register(lhs, value_type);
                let right_value: Option<FpExpr> = read_fp_compare_operand(rhs, value_type);
                let identifiers: Option<(u32, u32, u32)> = identifiers.reserve_fp_flag_values();
                match (left_value, right_value, identifiers) {
                    (Some(left_expr), Some(right_expr), Some((left_id, right_id, flag_id))) => {
                        let source: FpFlagSource = FpFlagSource {
                            id: flag_id,
                            left: left_id,
                            right: right_id,
                            ty: value_type,
                            signaling: instruction.opcode == A64Opcode::Fcmpe,
                        };
                        statements.push(Statement::FpCapture {
                            value: left_id,
                            expression: left_expr,
                        });
                        statements.push(Statement::FpCapture {
                            value: right_id,
                            expression: right_expr,
                        });
                        statements.push(Statement::SetFpFlags { source });
                        *flags = Some(FlagState::Floating(source));
                        true
                    }
                    _ => false,
                }
            })
        }
        _ => false,
    }
}

fn lower_fp_conditional_select(
    instruction: &MCInst,
    statements: &mut Vec<Statement>,
    flags: Option<FlagState>,
) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let when_true: Option<&Operand> = instruction.operands.get(1);
    let when_false: Option<&Operand> = instruction.operands.get(2);
    let condition: Option<u8> = instruction.operands.get(3).and_then(condition_from_operand);
    match (destination, when_true, when_false, condition, flags) {
        (Some(output), Some(on_true), Some(on_false), Some(code), Some(source)) => {
            let ty: Option<FpType> = fp_type(output);
            ty.map_or(false, |value_type: FpType| {
                let predicate: Option<Predicate> = predicate_from_flag_state(source, code);
                let true_value: Option<FpExpr> = read_fp_register(on_true, value_type);
                let false_value: Option<FpExpr> = read_fp_register(on_false, value_type);
                match (
                    predicate,
                    true_value,
                    false_value,
                    fp_destination(output, value_type),
                ) {
                    (Some(test), Some(true_expr), Some(false_expr), Some(register)) => {
                        statements.push(Statement::AssignFp {
                            register,
                            ty: value_type,
                            value: FpExpr::Select {
                                predicate: Box::new(test),
                                when_true: Box::new(true_expr),
                                when_false: Box::new(false_expr),
                                ty: value_type,
                            },
                        });
                        true
                    }
                    _ => false,
                }
            })
        }
        _ => false,
    }
}

fn lower_compare_exchange(
    instruction: &MCInst,
    statements: &mut Vec<Statement>,
    identifiers: &mut Identifiers,
) -> bool {
    let expected: Option<&Operand> = instruction.operands.first();
    let replacement: Option<&Operand> = instruction.operands.get(1);
    let memory: Option<&Operand> = instruction.operands.get(2);
    match (expected, replacement, memory) {
        (Some(compare), Some(value), Some(address_operand)) => {
            let width: Option<Width> = operand_width(value);
            let ordering: Option<AtomicOrdering> = atomic_ordering(instruction.opcode);
            match (width, ordering) {
                (Some(value_width), Some(order)) => {
                    let expected_value: Option<Expr> = read_data_operand(compare, value_width);
                    let replacement_value: Option<Expr> = read_data_operand(value, value_width);
                    let result: Option<AtomicDestination> =
                        atomic_destination(compare, value_width);
                    let address: Option<Expr> = memory_address(address_operand);
                    let values: Option<(u32, u32)> = identifiers.reserve_values();
                    match (expected_value, replacement_value, result, address, values) {
                        (
                            Some(compare_value),
                            Some(replacement_expr),
                            Some(output),
                            Some(memory_address),
                            Some((expected_id, replacement_id)),
                        ) => {
                            statements.push(Statement::Capture {
                                value: expected_id,
                                expression: compare_value,
                            });
                            statements.push(Statement::Capture {
                                value: replacement_id,
                                expression: replacement_expr,
                            });
                            statements.push(Statement::AtomicCompareExchange {
                                result: output,
                                expected: Expr::Captured(expected_id),
                                replacement: Expr::Captured(replacement_id),
                                address: memory_address,
                                width: value_width,
                                ordering: order,
                            });
                            true
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn lower_atomic_rmw(
    instruction: &MCInst,
    statements: &mut Vec<Statement>,
    identifiers: &mut Identifiers,
) -> bool {
    let source: Option<&Operand> = instruction.operands.first();
    let destination: Option<&Operand> = instruction.operands.get(1);
    let memory: Option<&Operand> = instruction.operands.get(2);
    match (source, destination, memory) {
        (Some(input), Some(output), Some(address_operand)) => {
            let width: Option<Width> = operand_width(input);
            let ordering: Option<AtomicOrdering> = atomic_ordering(instruction.opcode);
            let operation: Option<AtomicOp> = atomic_operation(instruction.opcode);
            match (width, ordering, operation) {
                (Some(value_width), Some(order), Some(op)) => {
                    let value: Option<Expr> = read_data_operand(input, value_width);
                    let result: Option<AtomicDestination> = atomic_destination(output, value_width);
                    let address: Option<Expr> = memory_address(address_operand);
                    let value_id: Option<u32> = identifiers.reserve_value();
                    match (value, result, address, value_id) {
                        (Some(input_value), Some(output_value), Some(memory_address), Some(id)) => {
                            statements.push(Statement::Capture {
                                value: id,
                                expression: input_value,
                            });
                            statements.push(Statement::AtomicRmw {
                                operation: op,
                                result: output_value,
                                value: Expr::Captured(id),
                                address: memory_address,
                                width: value_width,
                                ordering: order,
                            });
                            true
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn lower_exclusive_load(instruction: &MCInst, statements: &mut Vec<Statement>) -> bool {
    let destination: Option<&Operand> = instruction.operands.first();
    let memory: Option<&Operand> = instruction.operands.get(1);
    match (destination, memory) {
        (Some(output), Some(address_operand)) => {
            let width: Option<Width> = operand_width(output);
            let ordering: Option<AtomicOrdering> = atomic_ordering(instruction.opcode);
            match (width, ordering) {
                (Some(value_width), Some(order)) => {
                    let result: Option<AtomicDestination> = atomic_destination(output, value_width);
                    let address: Option<Expr> = memory_address(address_operand);
                    match (result, address) {
                        (Some(destination_value), Some(memory_address)) => {
                            statements.push(Statement::LoadExclusive {
                                result: destination_value,
                                address: memory_address,
                                width: value_width,
                                ordering: order,
                            });
                            true
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn lower_exclusive_store(
    instruction: &MCInst,
    statements: &mut Vec<Statement>,
    identifiers: &mut Identifiers,
) -> bool {
    let status: Option<&Operand> = instruction.operands.first();
    let source: Option<&Operand> = instruction.operands.get(1);
    let memory: Option<&Operand> = instruction.operands.get(2);
    match (status, source, memory) {
        (Some(output), Some(input), Some(address_operand)) => {
            let width: Option<Width> = operand_width(input);
            let ordering: Option<AtomicOrdering> = atomic_ordering(instruction.opcode);
            match (width, ordering) {
                (Some(value_width), Some(order)) => {
                    let status_value: Option<AtomicDestination> =
                        atomic_destination(output, Width::W32);
                    let value: Option<Expr> = read_data_operand(input, value_width);
                    let address: Option<Expr> = memory_address(address_operand);
                    let value_id: Option<u32> = identifiers.reserve_value();
                    match (status_value, value, address, value_id) {
                        (
                            Some(status_destination),
                            Some(input_value),
                            Some(memory_address),
                            Some(id),
                        ) => {
                            statements.push(Statement::Capture {
                                value: id,
                                expression: input_value,
                            });
                            statements.push(Statement::StoreExclusive {
                                status: status_destination,
                                value: Expr::Captured(id),
                                address: memory_address,
                                width: value_width,
                                ordering: order,
                            });
                            true
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        }
        _ => false,
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
            *flags = Some(FlagState::Integer(source));
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
                    .and_then(|value: u8| predicate_from_flag_state(state, value))
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
                let predicate: Option<Predicate> = predicate_from_flag_state(state, code);
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

fn predicate_from_flag_state(state: FlagState, code: u8) -> Option<Predicate> {
    match state {
        FlagState::Integer(source) => predicate_from_flags(source, code),
        FlagState::Floating(source) => predicate_from_fp_flags(source, code),
    }
}

fn predicate_from_fp_flags(source: FpFlagSource, code: u8) -> Option<Predicate> {
    let condition: Option<FpCondition> = fp_condition(code);
    condition.map(|value: FpCondition| Predicate::FpCondition {
        condition: value,
        left: FpExpr::Captured(source.left),
        right: FpExpr::Captured(source.right),
        ty: source.ty,
    })
}

fn fp_condition(code: u8) -> Option<FpCondition> {
    match code {
        0 => Some(FpCondition::Eq),
        1 => Some(FpCondition::Ne),
        2 => Some(FpCondition::Hs),
        3 => Some(FpCondition::Lo),
        4 => Some(FpCondition::Mi),
        5 => Some(FpCondition::Pl),
        6 => Some(FpCondition::Vs),
        7 => Some(FpCondition::Vc),
        8 => Some(FpCondition::Hi),
        9 => Some(FpCondition::Ls),
        10 => Some(FpCondition::Ge),
        11 => Some(FpCondition::Lt),
        12 => Some(FpCondition::Gt),
        13 => Some(FpCondition::Le),
        14 => Some(FpCondition::Al),
        _ => None,
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

fn fp_type(operand: &Operand) -> Option<FpType> {
    match operand {
        Operand::Reg {
            n: 0..=31,
            view: RegView::S,
        } => Some(FpType::F32),
        Operand::Reg {
            n: 0..=31,
            view: RegView::D,
        } => Some(FpType::F64),
        _ => None,
    }
}

fn fp_width(ty: FpType) -> Width {
    match ty {
        FpType::F32 => Width::W32,
        FpType::F64 => Width::W64,
    }
}

fn fp_destination(operand: &Operand, ty: FpType) -> Option<u8> {
    match (operand, ty) {
        (
            Operand::Reg {
                n,
                view: RegView::S,
            },
            FpType::F32,
        ) if *n <= 31 => Some(*n),
        (
            Operand::Reg {
                n,
                view: RegView::D,
            },
            FpType::F64,
        ) if *n <= 31 => Some(*n),
        _ => None,
    }
}

fn read_fp_register(operand: &Operand, ty: FpType) -> Option<FpExpr> {
    match (operand, ty) {
        (
            Operand::Reg {
                n,
                view: RegView::S,
            },
            FpType::F32,
        ) if *n <= 31 => Some(FpExpr::Read { register: *n, ty }),
        (
            Operand::Reg {
                n,
                view: RegView::D,
            },
            FpType::F64,
        ) if *n <= 31 => Some(FpExpr::Read { register: *n, ty }),
        _ => None,
    }
}

fn read_fp_compare_operand(operand: &Operand, ty: FpType) -> Option<FpExpr> {
    match operand {
        Operand::FpImm(0) => Some(FpExpr::Zero { ty }),
        Operand::FpImm(_) => None,
        _ => read_fp_register(operand, ty),
    }
}

fn read_data_operand(operand: &Operand, width: Width) -> Option<Expr> {
    match (operand, width) {
        (
            Operand::Reg {
                view: RegView::W, ..
            },
            Width::W32,
        )
        | (
            Operand::Reg {
                view: RegView::X, ..
            },
            Width::W64,
        )
        | (
            Operand::Reg {
                view: RegView::Zr, ..
            },
            _,
        ) => read_operand(operand, width),
        _ => None,
    }
}

fn data_destination_matches(operand: &Operand, width: Width) -> bool {
    matches!(
        (operand, width),
        (
            Operand::Reg {
                view: RegView::W,
                ..
            },
            Width::W32
        ) | (
            Operand::Reg {
                view: RegView::X,
                ..
            },
            Width::W64
        ) | (
            Operand::Reg {
                view: RegView::Zr,
                ..
            },
            _
        )
    )
}

fn atomic_destination(operand: &Operand, width: Width) -> Option<AtomicDestination> {
    match (operand, width) {
        (
            Operand::Reg {
                n,
                view: RegView::W,
            },
            Width::W32,
        ) if *n < 31 => Some(AtomicDestination::Register {
            location: Location::X(*n),
            width,
        }),
        (
            Operand::Reg {
                n,
                view: RegView::X,
            },
            Width::W64,
        ) if *n < 31 => Some(AtomicDestination::Register {
            location: Location::X(*n),
            width,
        }),
        (
            Operand::Reg {
                n: 31,
                view: RegView::Zr,
            },
            _,
        ) => Some(AtomicDestination::Discard),
        _ => None,
    }
}

fn memory_address(operand: &Operand) -> Option<Expr> {
    match operand {
        Operand::MemBaseImm {
            base,
            off,
            mode: IndexMode::Offset,
        } => {
            let base_value: Expr = match *base {
                0..=30 => Expr::Read(Location::X(*base)),
                31 => Expr::Read(Location::Sp),
                _ => return None,
            };
            if *off == 0 {
                Some(base_value)
            } else {
                Some(binary(
                    BinaryOp::Add,
                    base_value,
                    Expr::Constant(u64::from_ne_bytes(off.to_ne_bytes())),
                    Width::W64,
                ))
            }
        }
        _ => None,
    }
}

fn atomic_ordering(opcode: A64Opcode) -> Option<AtomicOrdering> {
    match opcode {
        A64Opcode::Cas
        | A64Opcode::Ldadd
        | A64Opcode::Ldclr
        | A64Opcode::Ldeor
        | A64Opcode::Ldset
        | A64Opcode::Swp
        | A64Opcode::Ldxr
        | A64Opcode::Stxr => Some(AtomicOrdering::Relaxed),
        A64Opcode::Casa
        | A64Opcode::Ldadda
        | A64Opcode::Ldclra
        | A64Opcode::Ldeora
        | A64Opcode::Ldseta
        | A64Opcode::Swpa
        | A64Opcode::Ldaxr => Some(AtomicOrdering::Acquire),
        A64Opcode::Casl
        | A64Opcode::Ldaddl
        | A64Opcode::Ldclrl
        | A64Opcode::Ldeorl
        | A64Opcode::Ldsetl
        | A64Opcode::Swpl
        | A64Opcode::Stlxr => Some(AtomicOrdering::Release),
        A64Opcode::Casal
        | A64Opcode::Ldaddal
        | A64Opcode::Ldclral
        | A64Opcode::Ldeoral
        | A64Opcode::Ldsetal
        | A64Opcode::Swpal => Some(AtomicOrdering::AcqRel),
        _ => None,
    }
}

fn atomic_operation(opcode: A64Opcode) -> Option<AtomicOp> {
    match opcode {
        A64Opcode::Ldadd | A64Opcode::Ldadda | A64Opcode::Ldaddl | A64Opcode::Ldaddal => {
            Some(AtomicOp::Add)
        }
        A64Opcode::Ldclr | A64Opcode::Ldclra | A64Opcode::Ldclrl | A64Opcode::Ldclral => {
            Some(AtomicOp::Clear)
        }
        A64Opcode::Ldeor | A64Opcode::Ldeora | A64Opcode::Ldeorl | A64Opcode::Ldeoral => {
            Some(AtomicOp::Eor)
        }
        A64Opcode::Ldset | A64Opcode::Ldseta | A64Opcode::Ldsetl | A64Opcode::Ldsetal => {
            Some(AtomicOp::Set)
        }
        A64Opcode::Swp | A64Opcode::Swpa | A64Opcode::Swpl | A64Opcode::Swpal => {
            Some(AtomicOp::Swap)
        }
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
    fn reserve_value(&mut self) -> Option<u32> {
        let value: u32 = self.next_value;
        self.next_value = value.checked_add(1)?;
        Some(value)
    }

    fn reserve_values(&mut self) -> Option<(u32, u32)> {
        let first: u32 = self.next_value;
        let second: u32 = first.checked_add(1)?;
        self.next_value = second.checked_add(1)?;
        Some((first, second))
    }

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

    fn reserve_fp_flag_values(&mut self) -> Option<(u32, u32, u32)> {
        let left: u32 = self.next_value;
        let right: u32 = left.checked_add(1)?;
        let next_value: u32 = right.checked_add(1)?;
        let flag: u32 = self.next_flag;
        let next_flag: u32 = flag.checked_add(1)?;
        self.next_value = next_value;
        self.next_flag = next_flag;
        Some((left, right, flag))
    }
}
