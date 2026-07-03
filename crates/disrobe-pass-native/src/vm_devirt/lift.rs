use serde::{Deserialize, Serialize};

use super::detect::VmStructure;
use super::fingerprint::HandlerSemantics;
use super::microop::{MicroOp, VmOperand};
use super::{MAX_BYTECODE_INSNS, MAX_VM_REGS};

const OPCODE_SPACE: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmInsn {
    pub offset: u32,
    pub opcode: u8,
    pub micro_op: MicroOp,
    pub imm: Option<i64>,
    pub reg: Option<u8>,
    pub branch_target: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiftedProgram {
    pub insns: Vec<VmInsn>,
    pub entry_offset: u32,
    pub max_reg: u8,
    pub unresolved_opcodes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiftError {
    EntryOutOfRange,
    BytecodeEmpty,
    TooLarge,
    TruncatedOperand(u32),
    InvalidOperandWidth(u8),
    BranchOutOfRange(i64),
}

impl LiftedProgram {
    #[must_use]
    pub fn insn_at(&self, offset: u32) -> Option<&VmInsn> {
        self.insns.iter().find(|i: &&VmInsn| i.offset == offset)
    }
}

pub fn lift_bytecode(
    _bytes: &[u8],
    structure: &VmStructure,
    semantics: &[HandlerSemantics],
) -> Result<LiftedProgram, LiftError> {
    let prog: &[u8] = &structure.bytecode;
    if prog.is_empty() {
        return Err(LiftError::BytecodeEmpty);
    }
    let entry: u32 = u32::try_from(structure.entry_vip).map_err(|_| LiftError::EntryOutOfRange)?;
    let entry_index: usize = usize::try_from(entry).map_err(|_| LiftError::EntryOutOfRange)?;
    if entry_index >= prog.len() {
        return Err(LiftError::EntryOutOfRange);
    }

    let sem_by_index: Vec<Option<&HandlerSemantics>> = index_semantics(semantics);
    let mut insns: Vec<VmInsn> = Vec::new();
    let mut unresolved: Vec<u8> = Vec::new();
    let mut max_reg: u8 = 0;
    let mut saw_return: bool = false;

    let mut offset: usize = 0;
    while offset < prog.len() {
        if insns.len() >= MAX_BYTECODE_INSNS {
            return Err(LiftError::TooLarge);
        }
        let opcode: u8 = prog[offset];
        let sem: Option<&HandlerSemantics> =
            sem_by_index.get(usize::from(opcode)).copied().flatten();
        let Some(sem) = sem else {
            if !unresolved.contains(&opcode) {
                unresolved.push(opcode);
            }
            let start: u32 = checked_u32(offset)?;
            insns.push(VmInsn {
                offset: start,
                opcode,
                micro_op: MicroOp::Unknown,
                imm: None,
                reg: None,
                branch_target: None,
            });
            offset = advance_offset(offset, 1)?;
            continue;
        };

        let start: usize = offset;
        let start_u32: u32 = checked_u32(start)?;
        offset = advance_offset(offset, 1)?;
        let mut imm: Option<i64> = None;
        let mut reg: Option<u8> = None;
        let mut branch_target: Option<u32> = None;

        match sem.operand {
            VmOperand::Imm => {
                let width: usize = operand_width(sem.operand_width)?;
                let Some(value) = tail_truncation(
                    read_required_imm(prog, offset, width, start_u32),
                    saw_return,
                )?
                else {
                    break;
                };
                imm = Some(value);
                offset = advance_offset(offset, width)?;
            }
            VmOperand::RegIndex => {
                let Some(b) =
                    tail_truncation(read_required_byte(prog, offset, start_u32), saw_return)?
                else {
                    break;
                };
                reg = Some(b);
                max_reg = max_reg.max(b);
                offset = advance_offset(offset, 1)?;
            }
            VmOperand::StackSlot => {
                let Some(b) =
                    tail_truncation(read_required_byte(prog, offset, start_u32), saw_return)?
                else {
                    break;
                };
                reg = Some(b);
                offset = advance_offset(offset, 1)?;
            }
            VmOperand::BranchTarget => {
                let Some(raw) =
                    tail_truncation(read_required_imm(prog, offset, 4, start_u32), saw_return)?
                else {
                    break;
                };
                offset = advance_offset(offset, 4)?;
                branch_target = Some(resolve_branch(start, raw)?);
            }
            VmOperand::None => {}
        }

        if matches!(
            sem.micro_op,
            MicroOp::BranchTrue | MicroOp::BranchFalse | MicroOp::Jump
        ) && branch_target.is_none()
        {
            let Some(raw) =
                tail_truncation(read_required_imm(prog, offset, 4, start_u32), saw_return)?
            else {
                break;
            };
            offset = advance_offset(offset, 4)?;
            branch_target = Some(resolve_branch(start, raw)?);
        }

        insns.push(VmInsn {
            offset: start_u32,
            opcode,
            micro_op: sem.micro_op,
            imm,
            reg,
            branch_target,
        });
        if matches!(sem.micro_op, MicroOp::Return) {
            saw_return = true;
        }
    }

    let max_reg: u8 = max_reg.min((MAX_VM_REGS - 1) as u8);

    Ok(LiftedProgram {
        insns,
        entry_offset: entry,
        max_reg,
        unresolved_opcodes: unresolved,
    })
}

fn index_semantics(semantics: &[HandlerSemantics]) -> Vec<Option<&HandlerSemantics>> {
    let mut out: Vec<Option<&HandlerSemantics>> = vec![None; OPCODE_SPACE];
    for sem in semantics {
        if sem.index < out.len() {
            out[sem.index] = Some(sem);
        }
    }
    out
}

fn read_imm(prog: &[u8], offset: usize, width: usize) -> Option<i64> {
    let end: usize = offset.checked_add(width)?;
    let bytes: &[u8] = prog.get(offset..end)?;
    match width {
        1 => Some(i64::from(i8::from_le_bytes([bytes[0]]))),
        2 => {
            let arr: [u8; 2] = bytes.try_into().ok()?;
            Some(i64::from(i16::from_le_bytes(arr)))
        }
        4 => {
            let arr: [u8; 4] = bytes.try_into().ok()?;
            Some(i64::from(i32::from_le_bytes(arr)))
        }
        8 => {
            let arr: [u8; 8] = bytes.try_into().ok()?;
            Some(i64::from_le_bytes(arr))
        }
        _ => None,
    }
}

fn read_required_imm(
    prog: &[u8],
    offset: usize,
    width: usize,
    insn_start: u32,
) -> Result<i64, LiftError> {
    read_imm(prog, offset, width).ok_or(LiftError::TruncatedOperand(insn_start))
}

fn read_required_byte(prog: &[u8], offset: usize, insn_start: u32) -> Result<u8, LiftError> {
    prog.get(offset)
        .copied()
        .ok_or(LiftError::TruncatedOperand(insn_start))
}

fn tail_truncation<T>(
    result: Result<T, LiftError>,
    saw_return: bool,
) -> Result<Option<T>, LiftError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(LiftError::TruncatedOperand(_)) if saw_return => Ok(None),
        Err(err) => Err(err),
    }
}

fn advance_offset(offset: usize, amount: usize) -> Result<usize, LiftError> {
    offset.checked_add(amount).ok_or(LiftError::TooLarge)
}

fn checked_u32(offset: usize) -> Result<u32, LiftError> {
    u32::try_from(offset).map_err(|_| LiftError::TooLarge)
}

fn operand_width(width: u8) -> Result<usize, LiftError> {
    match width {
        0 => Ok(8),
        1 | 2 | 4 | 8 => Ok(usize::from(width)),
        other => Err(LiftError::InvalidOperandWidth(other)),
    }
}

fn resolve_branch(insn_start: usize, raw: i64) -> Result<u32, LiftError> {
    if let Ok(abs) = u32::try_from(raw) {
        return Ok(abs);
    }
    let base: i64 = i64::try_from(insn_start).map_err(|_| LiftError::TooLarge)?;
    let rel: i64 = base
        .checked_add(raw)
        .ok_or(LiftError::BranchOutOfRange(raw))?;
    u32::try_from(rel).map_err(|_| LiftError::BranchOutOfRange(raw))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::vm_devirt::detect::{Bitness, DispatchKind};

    #[test]
    fn read_imm_sign_extends() {
        let prog: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(read_imm(&prog, 0, 4), Some(-1));
        let prog2: [u8; 4] = [0x80, 0, 0, 0];
        assert_eq!(read_imm(&prog2, 0, 1), Some(-128));
    }

    #[test]
    fn read_imm_bounds_checked() {
        let prog: [u8; 2] = [1, 2];
        assert_eq!(read_imm(&prog, 0, 8), None);
    }

    fn structure(bytecode: Vec<u8>) -> VmStructure {
        VmStructure {
            bitness: Bitness::Bits64,
            image_base: 0x1000,
            dispatcher_va: 0x1000,
            dispatch_kind: DispatchKind::SwitchJumpTable,
            handlers: vec![],
            bytecode_va: 0x2000,
            bytecode,
            entry_vip: 0,
            loaded: vec![],
        }
    }

    fn sem(
        index: usize,
        micro_op: MicroOp,
        operand: VmOperand,
        operand_width: u8,
    ) -> HandlerSemantics {
        HandlerSemantics {
            index,
            micro_op,
            operand,
            operand_width,
            pc_advance: 1,
            sp_delta: 0,
        }
    }

    #[test]
    fn truncated_imm_operand_fails_lift() {
        let structure: VmStructure = structure(vec![1, 0xAA]);
        let semantics: [HandlerSemantics; 1] = [sem(1, MicroOp::PushImm, VmOperand::Imm, 4)];
        assert_eq!(
            lift_bytecode(&[], &structure, &semantics),
            Err(LiftError::TruncatedOperand(0))
        );
    }

    #[test]
    fn truncated_reg_operand_fails_lift() {
        let structure: VmStructure = structure(vec![2]);
        let semantics: [HandlerSemantics; 1] = [sem(2, MicroOp::PushReg, VmOperand::RegIndex, 1)];
        assert_eq!(
            lift_bytecode(&[], &structure, &semantics),
            Err(LiftError::TruncatedOperand(0))
        );
    }

    #[test]
    fn truncated_tail_after_return_stops_lift() {
        let structure: VmStructure = structure(vec![1, 2, 0xAA]);
        let semantics: [HandlerSemantics; 2] = [
            sem(1, MicroOp::Return, VmOperand::None, 0),
            sem(2, MicroOp::PushImm, VmOperand::Imm, 4),
        ];
        let lifted: LiftedProgram = lift_bytecode(&[], &structure, &semantics).unwrap();
        assert_eq!(lifted.insns.len(), 1);
        assert_eq!(lifted.insns[0].micro_op, MicroOp::Return);
    }

    #[test]
    fn invalid_operand_width_fails_lift() {
        let structure: VmStructure = structure(vec![3, 1, 2, 3]);
        let semantics: [HandlerSemantics; 1] = [sem(3, MicroOp::PushImm, VmOperand::Imm, 3)];
        assert_eq!(
            lift_bytecode(&[], &structure, &semantics),
            Err(LiftError::InvalidOperandWidth(3))
        );
    }

    #[test]
    fn semantics_index_is_capped_to_opcode_space() {
        let structure: VmStructure = structure(vec![42]);
        let semantics: [HandlerSemantics; 1] = [sem(300, MicroOp::Return, VmOperand::None, 0)];
        let lifted: LiftedProgram = lift_bytecode(&[], &structure, &semantics).unwrap();
        assert_eq!(lifted.unresolved_opcodes, vec![42]);
        assert_eq!(lifted.insns[0].micro_op, MicroOp::Unknown);
    }

    #[test]
    fn negative_branch_before_start_fails_lift() {
        let mut bytecode: Vec<u8> = vec![4];
        bytecode.extend_from_slice(&(-16i32).to_le_bytes());
        let structure: VmStructure = structure(bytecode);
        let semantics: [HandlerSemantics; 1] =
            [sem(4, MicroOp::BranchTrue, VmOperand::BranchTarget, 4)];
        assert_eq!(
            lift_bytecode(&[], &structure, &semantics),
            Err(LiftError::BranchOutOfRange(-16))
        );
    }

    #[test]
    fn negative_branch_inside_program_lifts() {
        let mut bytecode: Vec<u8> = vec![0xFF, 4];
        bytecode.extend_from_slice(&(-1i32).to_le_bytes());
        let structure: VmStructure = structure(bytecode);
        let semantics: [HandlerSemantics; 1] =
            [sem(4, MicroOp::BranchTrue, VmOperand::BranchTarget, 4)];
        let lifted: LiftedProgram = lift_bytecode(&[], &structure, &semantics).unwrap();
        assert_eq!(lifted.insns[1].branch_target, Some(0));
    }
}
