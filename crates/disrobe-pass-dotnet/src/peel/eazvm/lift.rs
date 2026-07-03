use std::collections::BTreeMap;

use super::disasm::{DecodedOperand, VirtualInstr};
use super::opcodes::CilOp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftedInstr {
    pub op: CilOp,
    pub operand: LiftedOperand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftedOperand {
    None,
    I32(i32),
    Var(u16),
    BranchTo(usize),
    Member(i32),
    StringLit(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftedBody {
    pub instrs: Vec<LiftedInstr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiftError {
    UnresolvedBranch(u32),
}

pub fn lift(virtuals: &[VirtualInstr]) -> Result<LiftedBody, LiftError> {
    let index_by_offset: BTreeMap<u32, usize> = virtuals
        .iter()
        .enumerate()
        .map(|(i, v): (usize, &VirtualInstr)| (v.virtual_offset, i))
        .collect();

    let mut instrs: Vec<LiftedInstr> = Vec::with_capacity(virtuals.len());
    for v in virtuals {
        let operand: LiftedOperand = match &v.operand {
            DecodedOperand::None => LiftedOperand::None,
            DecodedOperand::I32(value) => LiftedOperand::I32(*value),
            DecodedOperand::Var(idx) => LiftedOperand::Var(*idx),
            DecodedOperand::MemberId(id) => LiftedOperand::Member(*id),
            DecodedOperand::StringId(id) => LiftedOperand::StringLit(*id),
            DecodedOperand::Branch(target) => {
                let dest: usize = *index_by_offset
                    .get(target)
                    .ok_or(LiftError::UnresolvedBranch(*target))?;
                LiftedOperand::BranchTo(dest)
            }
        };
        instrs.push(LiftedInstr { op: v.op, operand });
    }

    Ok(LiftedBody { instrs })
}

impl LiftedBody {
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let mut lines: Vec<String> = Vec::with_capacity(self.instrs.len());
        for (i, ins) in self.instrs.iter().enumerate() {
            let text: String = match &ins.operand {
                LiftedOperand::None => format!("IL_{i:04} {}", ins.op.handler_key()),
                LiftedOperand::I32(v) => format!("IL_{i:04} {} {v}", ins.op.handler_key()),
                LiftedOperand::Var(v) => format!("IL_{i:04} {} {v}", ins.op.handler_key()),
                LiftedOperand::BranchTo(dest) => {
                    format!("IL_{i:04} {} IL_{dest:04}", ins.op.handler_key())
                }
                LiftedOperand::Member(id) => {
                    format!("IL_{i:04} {} member#{id:08X}", ins.op.handler_key())
                }
                LiftedOperand::StringLit(id) => {
                    format!("IL_{i:04} {} string#{id:08X}", ins.op.handler_key())
                }
            };
            lines.push(text);
        }
        lines
    }
}
