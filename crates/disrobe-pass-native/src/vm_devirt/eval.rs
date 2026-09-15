use std::collections::BTreeMap;

use super::lift::{LiftedProgram, VmInsn};
use super::microop::MicroOp;
use super::{MAX_VM_REGS, MAX_VM_STACK};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalOutcome {
    pub return_value: i64,
    pub steps: u64,
    pub final_regs: Vec<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalError {
    EntryNotFound,
    StackUnderflow,
    StackOverflow,
    StepCapExceeded,
    UnknownOpcode(u8),
    BranchToNowhere(u32),
    NoReturn,
    MissingImmediate(u32),
    MissingRegister(u32),
    RegisterOutOfRange(u8),
    TooManyArgs(usize),
    OffsetOverflow(u32),
    DuplicateOffset(u32),
}

const STEP_CAP: u64 = 5_000_000;

pub fn evaluate(
    program: &LiftedProgram,
    args: &[i64],
    initial_regs: usize,
) -> Result<EvalOutcome, EvalError> {
    if args.len() > MAX_VM_REGS {
        return Err(EvalError::TooManyArgs(args.len()));
    }

    let mut index: BTreeMap<u32, usize> = BTreeMap::new();
    for (i, insn) in program.insns.iter().enumerate() {
        if index.insert(insn.offset, i).is_some() {
            return Err(EvalError::DuplicateOffset(insn.offset));
        }
    }

    let mut lifted_reg_count: usize = 0;
    for insn in &program.insns {
        if let Some(reg) = insn.reg {
            let count: usize = usize::from(reg).saturating_add(1);
            lifted_reg_count = lifted_reg_count.max(count);
        }
    }
    let declared_reg_count: usize = usize::from(program.max_reg).saturating_add(1);
    let reg_count: usize = initial_regs
        .max(declared_reg_count)
        .max(lifted_reg_count)
        .max(args.len())
        .min(MAX_VM_REGS);
    let mut regs: Vec<i64> = vec![0i64; reg_count];
    for (i, a) in args.iter().enumerate() {
        if i < regs.len() {
            regs[i] = *a;
        }
    }
    let mut stack: Vec<i64> = Vec::with_capacity(64);

    let mut pc: u32 = program.entry_offset;
    let mut steps: u64 = 0;

    loop {
        steps = steps.checked_add(1).ok_or(EvalError::StepCapExceeded)?;
        if steps > STEP_CAP {
            return Err(EvalError::StepCapExceeded);
        }
        let idx: usize = *index.get(&pc).ok_or(EvalError::BranchToNowhere(pc))?;
        let insn: &VmInsn = &program.insns[idx];

        match insn.micro_op {
            MicroOp::PushImm => {
                let value: i64 = insn.imm.ok_or(EvalError::MissingImmediate(insn.offset))?;
                push(&mut stack, value)?;
                pc = fallthrough_offset(program, idx, insn.offset)?;
            }
            MicroOp::PushReg => {
                let (raw, r): (u8, usize) = reg_index(insn.reg, insn.offset)?;
                let value: i64 = regs
                    .get(r)
                    .copied()
                    .ok_or(EvalError::RegisterOutOfRange(raw))?;
                push(&mut stack, value)?;
                pc = fallthrough_offset(program, idx, insn.offset)?;
            }
            MicroOp::PopReg => {
                let value: i64 = pop(&mut stack)?;
                let (raw, r): (u8, usize) = reg_index(insn.reg, insn.offset)?;
                let slot: &mut i64 = regs.get_mut(r).ok_or(EvalError::RegisterOutOfRange(raw))?;
                *slot = value;
                pc = fallthrough_offset(program, idx, insn.offset)?;
            }
            MicroOp::LoadMem => {
                let _addr: i64 = pop(&mut stack)?;
                push(&mut stack, 0)?;
                pc = fallthrough_offset(program, idx, insn.offset)?;
            }
            MicroOp::StoreMem => {
                let _value: i64 = pop(&mut stack)?;
                let _addr: i64 = pop(&mut stack)?;
                pc = fallthrough_offset(program, idx, insn.offset)?;
            }
            MicroOp::Binary { op } => {
                let b: i64 = pop(&mut stack)?;
                let a: i64 = pop(&mut stack)?;
                push(&mut stack, op.apply(a, b))?;
                pc = fallthrough_offset(program, idx, insn.offset)?;
            }
            MicroOp::Unary { op } => {
                let a: i64 = pop(&mut stack)?;
                push(&mut stack, op.apply(a))?;
                pc = fallthrough_offset(program, idx, insn.offset)?;
            }
            MicroOp::Compare { op } => {
                let b: i64 = pop(&mut stack)?;
                let a: i64 = pop(&mut stack)?;
                push(&mut stack, i64::from(op.apply(a, b)))?;
                pc = fallthrough_offset(program, idx, insn.offset)?;
            }
            MicroOp::BranchTrue => {
                let cond: i64 = pop(&mut stack)?;
                let target: u32 = insn.branch_target.ok_or(EvalError::BranchToNowhere(pc))?;
                let next: u32 = fallthrough_offset(program, idx, insn.offset)?;
                pc = if cond != 0 { target } else { next };
            }
            MicroOp::BranchFalse => {
                let cond: i64 = pop(&mut stack)?;
                let target: u32 = insn.branch_target.ok_or(EvalError::BranchToNowhere(pc))?;
                let next: u32 = fallthrough_offset(program, idx, insn.offset)?;
                pc = if cond == 0 { target } else { next };
            }
            MicroOp::Jump => {
                pc = insn.branch_target.ok_or(EvalError::BranchToNowhere(pc))?;
            }
            MicroOp::Call => {
                pc = fallthrough_offset(program, idx, insn.offset)?;
            }
            MicroOp::Return => {
                let return_value: i64 = match stack.last().copied() {
                    Some(value) => value,
                    None => *regs.first().ok_or(EvalError::RegisterOutOfRange(0))?,
                };
                return Ok(EvalOutcome {
                    return_value,
                    steps,
                    final_regs: regs,
                });
            }
            MicroOp::Nop => {
                pc = fallthrough_offset(program, idx, insn.offset)?;
            }
            MicroOp::Unknown => {
                return Err(EvalError::UnknownOpcode(insn.opcode));
            }
        }
    }
}

fn fallthrough_offset(program: &LiftedProgram, idx: usize, current: u32) -> Result<u32, EvalError> {
    let next_idx: usize = idx
        .checked_add(1)
        .ok_or(EvalError::OffsetOverflow(current))?;
    match program.insns.get(next_idx) {
        Some(next) => Ok(next.offset),
        None => current
            .checked_add(1)
            .ok_or(EvalError::OffsetOverflow(current)),
    }
}

fn reg_index(reg: Option<u8>, offset: u32) -> Result<(u8, usize), EvalError> {
    let raw: u8 = reg.ok_or(EvalError::MissingRegister(offset))?;
    let index: usize = usize::from(raw);
    if index >= MAX_VM_REGS {
        return Err(EvalError::RegisterOutOfRange(raw));
    }
    Ok((raw, index))
}

fn push(stack: &mut Vec<i64>, value: i64) -> Result<(), EvalError> {
    if stack.len() >= MAX_VM_STACK {
        return Err(EvalError::StackOverflow);
    }
    stack.push(value);
    Ok(())
}

fn pop(stack: &mut Vec<i64>) -> Result<i64, EvalError> {
    stack.pop().ok_or(EvalError::StackUnderflow)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::vm_devirt::lift::LiftedProgram;
    use crate::vm_devirt::microop::{BinKind, MicroOp};

    fn insn(
        offset: u32,
        op: MicroOp,
        imm: Option<i64>,
        reg: Option<u8>,
        bt: Option<u32>,
    ) -> VmInsn {
        VmInsn {
            offset,
            opcode: 0,
            micro_op: op,
            imm,
            reg,
            branch_target: bt,
        }
    }

    #[test]
    fn evaluates_add_of_two_consts() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![
                insn(0, MicroOp::PushImm, Some(20), None, None),
                insn(9, MicroOp::PushImm, Some(22), None, None),
                insn(18, MicroOp::Binary { op: BinKind::Add }, None, None, None),
                insn(19, MicroOp::Return, None, None, None),
            ],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        let out: EvalOutcome = evaluate(&prog, &[], 1).unwrap();
        assert_eq!(out.return_value, 42);
    }

    #[test]
    fn evaluates_arg_passthrough_via_reg() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![
                insn(0, MicroOp::PushReg, None, Some(0), None),
                insn(2, MicroOp::PushReg, None, Some(1), None),
                insn(4, MicroOp::Binary { op: BinKind::Add }, None, None, None),
                insn(5, MicroOp::Return, None, None, None),
            ],
            entry_offset: 0,
            max_reg: 1,
            unresolved_opcodes: vec![],
        };
        let out: EvalOutcome = evaluate(&prog, &[15, 27], 2).unwrap();
        assert_eq!(out.return_value, 42);
    }

    #[test]
    fn underflow_is_reported() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![insn(
                0,
                MicroOp::Binary { op: BinKind::Add },
                None,
                None,
                None,
            )],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        assert_eq!(evaluate(&prog, &[], 1), Err(EvalError::StackUnderflow));
    }

    #[test]
    fn missing_immediate_is_reported() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![insn(0, MicroOp::PushImm, None, None, None)],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        assert_eq!(evaluate(&prog, &[], 1), Err(EvalError::MissingImmediate(0)));
    }

    #[test]
    fn missing_register_is_reported() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![insn(0, MicroOp::PushReg, None, None, None)],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        assert_eq!(evaluate(&prog, &[], 1), Err(EvalError::MissingRegister(0)));
    }

    #[test]
    fn duplicate_offsets_are_reported() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![
                insn(0, MicroOp::Nop, None, None, None),
                insn(0, MicroOp::Return, None, None, None),
            ],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        assert_eq!(evaluate(&prog, &[], 1), Err(EvalError::DuplicateOffset(0)));
    }

    #[test]
    fn too_many_args_are_reported() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![insn(0, MicroOp::Return, None, None, None)],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        let args: Vec<i64> = vec![0; MAX_VM_REGS + 1];
        assert_eq!(
            evaluate(&prog, &args, 1),
            Err(EvalError::TooManyArgs(MAX_VM_REGS + 1))
        );
    }

    #[test]
    fn terminal_offset_overflow_is_reported() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![insn(u32::MAX, MicroOp::Nop, None, None, None)],
            entry_offset: u32::MAX,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        assert_eq!(
            evaluate(&prog, &[], 1),
            Err(EvalError::OffsetOverflow(u32::MAX))
        );
    }

    #[test]
    fn terminal_return_at_max_offset_is_valid() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![insn(u32::MAX, MicroOp::Return, None, None, None)],
            entry_offset: u32::MAX,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        let out: EvalOutcome = evaluate(&prog, &[77], 1).unwrap();
        assert_eq!(out.return_value, 77);
    }
}
