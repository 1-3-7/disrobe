use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg::FlowGraph;

use crate::dalvik::DalvikInsn;
use crate::decompile_struct::{
    BasicBlock, BlockId, Cfg, Edge, EdgeKind, GroupedTry, block_flow, group_exception_regions,
};

const MAX_REGION_BLOCKS: usize = 4_096;

type HandlerList = Vec<(Option<String>, u32)>;

#[derive(Debug, Default)]
pub(crate) struct TryLayout {
    pub(crate) groups: Vec<GroupedTry>,
    pub(crate) split_heads: BTreeSet<BlockId>,
}

pub(crate) fn merged_try_layout(cfg: &Cfg, insns: &[DalvikInsn]) -> Option<TryLayout> {
    let defaults: Vec<GroupedTry> = group_exception_regions(cfg);
    let mut by_handlers: BTreeMap<HandlerList, Vec<usize>> = BTreeMap::new();
    for (index, group) in defaults.iter().enumerate() {
        by_handlers
            .entry(group.handlers.clone())
            .or_default()
            .push(index);
    }
    let flow: FlowGraph<BlockId> = block_flow(cfg)?;
    let handler_blocks: BTreeSet<BlockId> = cfg
        .exception_regions
        .iter()
        .filter_map(|region| cfg.pc_to_block.get(&region.handler_pc).copied())
        .collect();
    let mut replaced: BTreeSet<usize> = BTreeSet::new();
    let mut layout: TryLayout = TryLayout::default();
    for (handlers, members) in by_handlers {
        let others: Vec<(u32, u32)> = defaults
            .iter()
            .enumerate()
            .filter(|(index, _): &(usize, &GroupedTry)| !members.contains(index))
            .map(|(_, group): (usize, &GroupedTry)| (group.try_start_pc, group.try_end_pc))
            .collect();
        let ranges: Vec<(u32, u32)> = members
            .iter()
            .filter_map(|&index: &usize| defaults.get(index))
            .flat_map(|group: &GroupedTry| group.ranges.iter().copied())
            .collect();
        let Some(merged): Option<MergedTry> =
            merge_ranges(cfg, insns, &flow, &handler_blocks, &ranges, members.len())
        else {
            continue;
        };
        let head_pc: u32 = cfg.blocks.get(merged.head.0 as usize)?.start_pc;
        let crosses_enclosing_try: bool = others.iter().any(|(low, high): &(u32, u32)| {
            let span: std::ops::Range<u32> = *low..*high;
            ranges
                .iter()
                .any(|(start, _): &(u32, u32)| span.contains(start))
                && !span.contains(&head_pc)
        });
        if crosses_enclosing_try {
            continue;
        }
        replaced.extend(members.iter().copied());
        if merged.split_head {
            layout.split_heads.insert(merged.head);
        }
        layout.groups.push(GroupedTry {
            try_start_pc: head_pc,
            try_end_pc: merged.continuation_pc,
            handlers,
            ranges,
        });
    }
    if replaced.is_empty() {
        return None;
    }
    layout.groups.extend(
        defaults
            .into_iter()
            .enumerate()
            .filter(|(index, _): &(usize, GroupedTry)| !replaced.contains(index))
            .map(|(_, group): (usize, GroupedTry)| group),
    );
    Some(layout)
}

struct MergedTry {
    head: BlockId,
    split_head: bool,
    continuation_pc: u32,
}

fn merge_ranges(
    cfg: &Cfg,
    insns: &[DalvikInsn],
    flow: &FlowGraph<BlockId>,
    handler_blocks: &BTreeSet<BlockId>,
    ranges: &[(u32, u32)],
    groups: usize,
) -> Option<MergedTry> {
    let covered: BTreeSet<BlockId> = cfg
        .blocks
        .iter()
        .filter(|block: &&BasicBlock| {
            ranges
                .iter()
                .any(|(low, high): &(u32, u32)| block.start_pc >= *low && block.start_pc < *high)
        })
        .map(|block: &BasicBlock| block.id)
        .collect();
    let entries: Vec<BlockId> = covered
        .iter()
        .copied()
        .filter(|block: &BlockId| {
            *block == cfg.entry
                || normal_predecessors(cfg, *block).any(|pred: BlockId| !covered.contains(&pred))
        })
        .collect();
    if entries.len() <= 1 && groups <= 1 {
        return None;
    }
    let head: BlockId =
        entries
            .iter()
            .copied()
            .try_fold(
                None,
                |common: Option<BlockId>, entry: BlockId| match common {
                    None => Some(Some(entry)),
                    Some(current) => nearest_common_dominator(flow, current, entry).map(Some),
                },
            )??;
    if handler_blocks.contains(&head) {
        return None;
    }
    let mut region: BTreeSet<BlockId> = covered.clone();
    region.insert(head);
    let mut pending: Vec<BlockId> = entries;
    while let Some(block) = pending.pop() {
        if region.len() > MAX_REGION_BLOCKS {
            return None;
        }
        for pred in normal_predecessors(cfg, block) {
            if pred == head || region.contains(&pred) {
                continue;
            }
            if !flow.dominates(head, pred) {
                return None;
            }
            region.insert(pred);
            pending.push(pred);
        }
    }
    let widened_safely: bool = region
        .iter()
        .filter(|block: &&BlockId| **block != head && !covered.contains(*block))
        .all(|block: &BlockId| {
            !handler_blocks.contains(block) && !block_may_throw(cfg, insns, *block)
        });
    let single_entry: bool = region
        .iter()
        .filter(|block: &&BlockId| **block != head)
        .all(|block: &BlockId| {
            normal_predecessors(cfg, *block).all(|pred: BlockId| region.contains(&pred))
        });
    if !widened_safely || !single_entry {
        return None;
    }
    let head_block: &BasicBlock = cfg.blocks.get(head.0 as usize)?;
    let split_head: bool = !covered.contains(&head);
    if split_head {
        let branches: bool = head_block
            .insn_range
            .1
            .checked_sub(1)
            .and_then(|last: usize| insns.get(last))
            .is_some_and(|last: &DalvikInsn| last.is_conditional_branch() || last.is_switch());
        if !branches {
            return None;
        }
    }
    let continuation_pc: u32 = region
        .iter()
        .filter_map(|block: &BlockId| cfg.blocks.get(block.0 as usize))
        .flat_map(|block: &BasicBlock| normal_targets(block))
        .filter(|target: &BlockId| !region.contains(target))
        .filter_map(|target: BlockId| cfg.blocks.get(target.0 as usize))
        .map(|block: &BasicBlock| block.start_pc)
        .max()
        .unwrap_or(u32::MAX);
    Some(MergedTry {
        head,
        split_head,
        continuation_pc,
    })
}

fn nearest_common_dominator(
    flow: &FlowGraph<BlockId>,
    left: BlockId,
    right: BlockId,
) -> Option<BlockId> {
    let mut candidate: BlockId = left;
    for _ in 0..MAX_REGION_BLOCKS {
        if flow.dominates(candidate, right) {
            return Some(candidate);
        }
        candidate = flow.immediate_dominator(candidate)?;
    }
    None
}

fn block_may_throw(cfg: &Cfg, insns: &[DalvikInsn], block: BlockId) -> bool {
    cfg.blocks
        .get(block.0 as usize)
        .and_then(|found: &BasicBlock| insns.get(found.insn_range.0..found.insn_range.1))
        .is_none_or(|body: &[DalvikInsn]| {
            body.iter()
                .any(|insn: &DalvikInsn| crate::dalvik_decompile::may_throw(insn.op))
        })
}

fn normal_targets(block: &BasicBlock) -> impl Iterator<Item = BlockId> + '_ {
    block
        .successors
        .iter()
        .filter(|edge: &&Edge| !matches!(edge.kind, EdgeKind::Exception))
        .map(|edge: &Edge| edge.target)
}

fn normal_predecessors(cfg: &Cfg, block: BlockId) -> impl Iterator<Item = BlockId> + '_ {
    cfg.blocks
        .get(block.0 as usize)
        .into_iter()
        .flat_map(|found: &BasicBlock| found.predecessors.iter().copied())
        .filter(move |pred: &BlockId| {
            cfg.blocks
                .get(pred.0 as usize)
                .is_some_and(|source: &BasicBlock| {
                    normal_targets(source).any(|target: BlockId| target == block)
                })
        })
}
