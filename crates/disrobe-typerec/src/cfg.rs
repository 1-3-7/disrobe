use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{FlowControl, Instruction};

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start: usize,
    pub end: usize,
    pub succs: Vec<usize>,
    pub preds: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    block_of_index: BTreeMap<usize, usize>,
}

impl Cfg {
    #[must_use]
    pub fn block_containing(&self, instr_index: usize) -> Option<usize> {
        self.block_of_index
            .range(..=instr_index)
            .next_back()
            .and_then(|(_, block): (&usize, &usize)| {
                let candidate: &BasicBlock = self.blocks.get(*block)?;
                (instr_index >= candidate.start && instr_index < candidate.end).then_some(*block)
            })
    }
}

#[must_use]
pub fn build(instrs: &[Instruction]) -> Cfg {
    if instrs.is_empty() {
        return Cfg::default();
    }
    let ip_to_index: BTreeMap<u64, usize> = instrs
        .iter()
        .enumerate()
        .map(|(index, insn): (usize, &Instruction)| (insn.ip(), index))
        .collect();

    let leaders: BTreeSet<usize> = collect_leaders(instrs, &ip_to_index);
    let starts: Vec<usize> = leaders.into_iter().collect();
    let mut blocks: Vec<BasicBlock> = Vec::with_capacity(starts.len());
    for (position, &start) in starts.iter().enumerate() {
        let end: usize = starts.get(position + 1).copied().unwrap_or(instrs.len());
        blocks.push(BasicBlock {
            start,
            end,
            succs: Vec::new(),
            preds: Vec::new(),
        });
    }

    let block_of_index: BTreeMap<usize, usize> = blocks
        .iter()
        .enumerate()
        .map(|(block_index, block): (usize, &BasicBlock)| (block.start, block_index))
        .collect();

    wire_edges(instrs, &mut blocks, &block_of_index, &ip_to_index);
    Cfg {
        blocks,
        block_of_index,
    }
}

fn collect_leaders(instrs: &[Instruction], ip_to_index: &BTreeMap<u64, usize>) -> BTreeSet<usize> {
    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    leaders.insert(0);
    for (index, insn) in instrs.iter().enumerate() {
        match insn.flow_control() {
            FlowControl::ConditionalBranch
            | FlowControl::UnconditionalBranch
            | FlowControl::Return
            | FlowControl::IndirectBranch => {
                if index + 1 < instrs.len() {
                    leaders.insert(index + 1);
                }
                if let Some(target) = branch_target_index(insn, ip_to_index) {
                    leaders.insert(target);
                }
            }
            _ => {}
        }
    }
    leaders
}

fn wire_edges(
    instrs: &[Instruction],
    blocks: &mut [BasicBlock],
    block_of_index: &BTreeMap<usize, usize>,
    ip_to_index: &BTreeMap<u64, usize>,
) {
    let mut edges: Vec<(usize, usize)> = Vec::new();
    for (block_index, block) in blocks.iter().enumerate() {
        let last: usize = block.end - 1;
        let Some(insn): Option<&Instruction> = instrs.get(last) else {
            continue;
        };
        let fallthrough: Option<usize> = block_index_of(block.end, block_of_index);
        match insn.flow_control() {
            FlowControl::Return | FlowControl::IndirectBranch => {}
            FlowControl::UnconditionalBranch => {
                if let Some(target) = branch_target_index(insn, ip_to_index)
                    .and_then(|index: usize| block_index_of(index, block_of_index))
                {
                    edges.push((block_index, target));
                }
            }
            FlowControl::ConditionalBranch => {
                if let Some(target) = branch_target_index(insn, ip_to_index)
                    .and_then(|index: usize| block_index_of(index, block_of_index))
                {
                    edges.push((block_index, target));
                }
                if let Some(next) = fallthrough {
                    edges.push((block_index, next));
                }
            }
            _ => {
                if let Some(next) = fallthrough {
                    edges.push((block_index, next));
                }
            }
        }
    }
    for (from, to) in edges {
        if !blocks[from].succs.contains(&to) {
            blocks[from].succs.push(to);
        }
        if !blocks[to].preds.contains(&from) {
            blocks[to].preds.push(from);
        }
    }
}

fn branch_target_index(insn: &Instruction, ip_to_index: &BTreeMap<u64, usize>) -> Option<usize> {
    if !matches!(
        insn.flow_control(),
        FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
    ) {
        return None;
    }
    ip_to_index.get(&insn.near_branch_target()).copied()
}

fn block_index_of(instr_index: usize, block_of_index: &BTreeMap<usize, usize>) -> Option<usize> {
    block_of_index.get(&instr_index).copied()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bytes: &[u8]) -> Vec<Instruction> {
        let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut out: Vec<Instruction> = Vec::new();
        while decoder.can_decode() {
            let insn: Instruction = decoder.decode();
            if insn.is_invalid() {
                break;
            }
            out.push(insn);
        }
        out
    }

    #[test]
    fn diamond_has_two_branch_successors_and_a_join() {
        let bytes: &[u8] = &[
            0x85, 0xc9, 0x7e, 0x07, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xb8, 0x02, 0x00,
            0x00, 0x00, 0xc3,
        ];
        let instrs: Vec<Instruction> = decode(bytes);
        let cfg: Cfg = build(&instrs);
        assert!(cfg.blocks.len() >= 3, "diamond must split into blocks");
        let entry: &BasicBlock = &cfg.blocks[0];
        assert_eq!(
            entry.succs.len(),
            2,
            "conditional branch has two successors"
        );
        let join: &BasicBlock = cfg
            .blocks
            .iter()
            .find(|block: &&BasicBlock| block.preds.len() >= 2)
            .expect("a join block exists");
        assert!(join.preds.len() >= 2);
    }

    #[test]
    fn straight_line_is_one_block() {
        let bytes: &[u8] = &[0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0, 0xc3];
        let instrs: Vec<Instruction> = decode(bytes);
        let cfg: Cfg = build(&instrs);
        assert_eq!(cfg.blocks.len(), 1);
        assert!(cfg.blocks[0].succs.is_empty());
    }

    #[test]
    fn block_containing_maps_instruction_indices() {
        let bytes: &[u8] = &[
            0x85, 0xc9, 0x7e, 0x07, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xb8, 0x02, 0x00,
            0x00, 0x00, 0xc3,
        ];
        let instrs: Vec<Instruction> = decode(bytes);
        let cfg: Cfg = build(&instrs);
        assert_eq!(cfg.block_containing(0), Some(0));
        let last: usize = instrs.len() - 1;
        assert!(cfg.block_containing(last).is_some());
        assert_eq!(cfg.block_containing(instrs.len()), None);
    }
}
