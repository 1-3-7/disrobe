use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::lift::{LiftedProgram, VmInsn};
use super::microop::MicroOp;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmBlock {
    pub start_offset: u32,
    pub insns: Vec<VmInsn>,
    pub successors: Vec<u32>,
    pub fallthrough: Option<u32>,
    pub branch: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmCfg {
    pub entry: u32,
    pub blocks: Vec<VmBlock>,
}

impl VmCfg {
    #[must_use]
    pub fn block_at(&self, offset: u32) -> Option<&VmBlock> {
        self.blocks
            .iter()
            .find(|b: &&VmBlock| b.start_offset == offset)
    }
}

#[must_use]
pub fn build_cfg(program: &LiftedProgram) -> VmCfg {
    let ordered: Vec<&VmInsn> = {
        let mut v: Vec<&VmInsn> = program.insns.iter().collect();
        v.sort_by_key(|i: &&VmInsn| i.offset);
        v
    };
    let offset_set: BTreeSet<u32> = ordered.iter().map(|i: &&VmInsn| i.offset).collect();

    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    leaders.insert(program.entry_offset);
    if let Some(first) = ordered.first() {
        leaders.insert(first.offset);
    }

    for (i, insn) in ordered.iter().enumerate() {
        if insn.micro_op.is_terminator() {
            if let Some(target) = insn.branch_target
                && offset_set.contains(&target)
            {
                leaders.insert(target);
            }
            if insn.micro_op.is_conditional_branch()
                && let Some(next) = ordered.get(i + 1)
            {
                leaders.insert(next.offset);
            }
            if matches!(insn.micro_op, MicroOp::Jump | MicroOp::Return)
                && let Some(next) = ordered.get(i + 1)
            {
                leaders.insert(next.offset);
            }
        }
    }

    let mut blocks: Vec<VmBlock> = Vec::new();
    let mut current: Vec<VmInsn> = Vec::new();
    let mut current_start: Option<u32> = None;

    for (i, insn) in ordered.iter().enumerate() {
        if leaders.contains(&insn.offset) && current_start.is_some() {
            let start: u32 = match current_start.take() {
                Some(value) => value,
                None => continue,
            };
            let next_offset: Option<u32> = Some(insn.offset);
            blocks.push(finish_block(
                start,
                std::mem::take(&mut current),
                next_offset,
            ));
        }
        if current_start.is_none() {
            current_start = Some(insn.offset);
        }
        current.push((*insn).clone());

        let is_last: bool = i + 1 == ordered.len();
        let ends_block: bool = insn.micro_op.is_terminator()
            || ordered
                .get(i + 1)
                .is_some_and(|n: &&VmInsn| leaders.contains(&n.offset));
        if (ends_block || is_last) && current_start.is_some() {
            let start: u32 = match current_start.take() {
                Some(value) => value,
                None => continue,
            };
            let next_offset: Option<u32> = ordered.get(i + 1).map(|n: &&VmInsn| n.offset);
            blocks.push(finish_block(
                start,
                std::mem::take(&mut current),
                next_offset,
            ));
        }
    }

    let starts: BTreeSet<u32> = blocks.iter().map(|b: &VmBlock| b.start_offset).collect();
    let mut deduped: BTreeMap<u32, VmBlock> = BTreeMap::new();
    for b in blocks {
        deduped.entry(b.start_offset).or_insert(b);
    }
    let mut blocks: Vec<VmBlock> = deduped.into_values().collect();

    for block in &mut blocks {
        let block_start: u32 = block.start_offset;
        block.branch = block
            .branch
            .filter(|target: &u32| starts.contains(target) || *target == block_start);
        block.fallthrough = block
            .fallthrough
            .filter(|target: &u32| starts.contains(target) || *target == block_start);
        block
            .successors
            .retain(|s: &u32| starts.contains(s) || *s == block_start);
        block.successors.sort_unstable();
        block.successors.dedup();
    }

    VmCfg {
        entry: program.entry_offset,
        blocks,
    }
}

fn finish_block(start: u32, insns: Vec<VmInsn>, next_offset: Option<u32>) -> VmBlock {
    let mut successors: Vec<u32> = Vec::new();
    let mut fallthrough: Option<u32> = None;
    let mut branch: Option<u32> = None;
    match insns.last() {
        Some(last) if last.micro_op.is_conditional_branch() => {
            if let Some(t) = last.branch_target {
                branch = Some(t);
                successors.push(t);
            }
            if let Some(n) = next_offset {
                fallthrough = Some(n);
                successors.push(n);
            }
        }
        Some(last) if matches!(last.micro_op, MicroOp::Jump) => {
            if let Some(t) = last.branch_target {
                branch = Some(t);
                successors.push(t);
            }
        }
        Some(last) if matches!(last.micro_op, MicroOp::Return) => {}
        _ => {
            if let Some(n) = next_offset {
                fallthrough = Some(n);
                successors.push(n);
            }
        }
    }
    VmBlock {
        start_offset: start,
        insns,
        successors,
        fallthrough,
        branch,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::vm_devirt::microop::MicroOp;

    fn insn(offset: u32, op: MicroOp, branch: Option<u32>) -> VmInsn {
        VmInsn {
            offset,
            opcode: 0,
            micro_op: op,
            imm: None,
            reg: None,
            branch_target: branch,
        }
    }

    #[test]
    fn straight_line_is_one_block() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![
                insn(0, MicroOp::PushImm, None),
                insn(9, MicroOp::PushImm, None),
                insn(
                    18,
                    MicroOp::Binary {
                        op: super::super::microop::BinKind::Add,
                    },
                    None,
                ),
                insn(19, MicroOp::Return, None),
            ],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        let cfg: VmCfg = build_cfg(&prog);
        assert_eq!(cfg.blocks.len(), 1);
        assert_eq!(cfg.blocks[0].insns.len(), 4);
    }

    #[test]
    fn conditional_branch_splits_blocks() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![
                insn(0, MicroOp::PushImm, None),
                insn(9, MicroOp::BranchTrue, Some(20)),
                insn(14, MicroOp::PushImm, None),
                insn(20, MicroOp::Return, None),
            ],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        let cfg: VmCfg = build_cfg(&prog);
        assert!(cfg.blocks.len() >= 3, "blocks: {:?}", cfg.blocks);
        let b0: &VmBlock = cfg.block_at(0).unwrap();
        assert_eq!(b0.branch, Some(20));
        assert_eq!(b0.fallthrough, Some(14));
    }

    #[test]
    fn missing_conditional_branch_target_is_not_kept_as_edge_metadata() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![
                insn(0, MicroOp::PushImm, None),
                insn(9, MicroOp::BranchTrue, Some(1000)),
                insn(14, MicroOp::Return, None),
            ],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        let cfg: VmCfg = build_cfg(&prog);
        let block: Option<&VmBlock> = cfg.block_at(0);
        assert!(block.is_some());
        let b0: &VmBlock = match block {
            Some(value) => value,
            None => return,
        };
        assert_eq!(b0.branch, None);
        assert_eq!(b0.fallthrough, Some(14));
        assert_eq!(b0.successors, vec![14]);
    }

    #[test]
    fn missing_jump_target_is_not_kept_as_edge_metadata() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![insn(0, MicroOp::Jump, Some(1000))],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        let cfg: VmCfg = build_cfg(&prog);
        let block: Option<&VmBlock> = cfg.block_at(0);
        assert!(block.is_some());
        let b0: &VmBlock = match block {
            Some(value) => value,
            None => return,
        };
        assert_eq!(b0.branch, None);
        assert_eq!(b0.fallthrough, None);
        assert!(b0.successors.is_empty());
    }
}
