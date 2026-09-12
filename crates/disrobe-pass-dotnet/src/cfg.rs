use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg::{Flow, FlowGraph, PostDominator};

use crate::cil::{ExceptionClause, FlowControl, Instruction, MethodBody, OperandValue};
use crate::debug::dbg_kv;

pub type BlockId = usize;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start: u32,

    pub first: usize,
    pub last: usize,

    pub succs: Vec<BlockId>,

    pub preds: Vec<BlockId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminator {
    FallThrough(BlockId),

    Goto(BlockId),

    Cond {
        taken: BlockId,
        fallthrough: BlockId,
    },

    Switch {
        cases: Vec<BlockId>,
        fallthrough: BlockId,
    },

    Return,

    Throw,

    EndFinally,
}

#[derive(Debug, Clone)]
pub struct NaturalLoop {
    pub header: BlockId,
    pub body: BTreeSet<BlockId>,
    pub latches: Vec<BlockId>,
}

#[derive(Debug, Clone)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    pub terminators: Vec<Terminator>,

    pub start_to_block: BTreeMap<u32, BlockId>,

    flow: Option<FlowGraph<BlockId>>,

    pub postorder_num: Vec<usize>,

    pub rpo: Vec<BlockId>,
    pub loops: Vec<NaturalLoop>,
    pub entry: BlockId,
}

impl Cfg {
    #[must_use]
    pub fn build(body: &MethodBody) -> Self {
        let leaders: BTreeSet<u32> = collect_leaders(body);
        let (blocks, start_to_block): (Vec<BasicBlock>, BTreeMap<u32, BlockId>) =
            partition_blocks(body, &leaders);
        let mut cfg: Self = Self {
            blocks,
            terminators: Vec::new(),
            start_to_block,
            flow: None,
            postorder_num: Vec::new(),
            rpo: Vec::new(),
            loops: Vec::new(),
            entry: 0,
        };
        if cfg.blocks.is_empty() {
            return cfg;
        }
        cfg.wire_edges(body);
        cfg.compute_postorder();
        cfg.compute_dominators();
        cfg.detect_loops();
        dbg_kv("cfg", || {
            let unreachable: usize = (0..cfg.blocks.len())
                .filter(|&b: &BlockId| b != cfg.entry && !cfg.is_reachable(b))
                .count();
            format!(
                "blocks={} edges={} entry={} unreachable={} natural_loops={}",
                cfg.blocks.len(),
                cfg.blocks
                    .iter()
                    .map(|b: &BasicBlock| b.succs.len())
                    .sum::<usize>(),
                cfg.entry,
                unreachable,
                cfg.loops.len()
            )
        });
        cfg
    }

    fn block_of_offset(&self, off: u32) -> Option<BlockId> {
        self.start_to_block.get(&off).copied()
    }

    fn wire_edges(&mut self, body: &MethodBody) {
        let count: usize = self.blocks.len();
        let mut terminators: Vec<Terminator> = Vec::with_capacity(count);
        let mut edges: Vec<Vec<BlockId>> = Vec::with_capacity(count);
        for (bid, block) in self.blocks.iter().enumerate() {
            let next_block: Option<BlockId> = (bid + 1 < count).then_some(bid + 1);
            let ins: &Instruction = &body.instructions[block.last];
            let term: Terminator = self.terminator_for(ins, next_block);
            let mut succs: Vec<BlockId> = Vec::new();
            for s in term_successors(&term) {
                if !succs.contains(&s) {
                    succs.push(s);
                }
            }
            edges.push(succs);
            terminators.push(term);
        }
        for (block, succs) in self.blocks.iter_mut().zip(edges) {
            block.succs = succs;
        }
        let mut pred_lists: Vec<Vec<BlockId>> = vec![Vec::new(); count];
        for (bid, block) in self.blocks.iter().enumerate() {
            for &s in &block.succs {
                if !pred_lists[s].contains(&bid) {
                    pred_lists[s].push(bid);
                }
            }
        }
        for (block, preds) in self.blocks.iter_mut().zip(pred_lists) {
            block.preds = preds;
        }
        self.terminators = terminators;
    }

    fn terminator_for(&self, ins: &Instruction, next_block: Option<BlockId>) -> Terminator {
        let resolve = |off: u32| -> Option<BlockId> { self.block_of_offset(off) };
        match ins.flow {
            FlowControl::Return => match ins.name.as_str() {
                "endfinally" | "endfilter" => Terminator::EndFinally,
                _ => Terminator::Return,
            },
            FlowControl::Throw => Terminator::Throw,
            FlowControl::Branch => {
                let target: Option<BlockId> = match ins.operand {
                    OperandValue::BrTarget(rel) => {
                        resolve((i64::from(ins.offset) + i64::from(rel)) as u32)
                    }
                    _ => None,
                };
                target.map_or_else(|| fallthrough_or_return(next_block), Terminator::Goto)
            }
            FlowControl::CondBranch => match &ins.operand {
                OperandValue::BrTarget(rel) => {
                    let taken: Option<BlockId> =
                        resolve((i64::from(ins.offset) + i64::from(*rel)) as u32);
                    match (taken, next_block) {
                        (Some(t), Some(f)) => Terminator::Cond {
                            taken: t,
                            fallthrough: f,
                        },
                        (Some(t), None) => Terminator::Goto(t),
                        _ => fallthrough_or_return(next_block),
                    }
                }
                OperandValue::Switch(rels) => {
                    let cases: Vec<BlockId> = rels
                        .iter()
                        .filter_map(|r: &i32| {
                            resolve((i64::from(ins.offset) + i64::from(*r)) as u32)
                        })
                        .collect();
                    Terminator::Switch {
                        cases,
                        fallthrough: next_block.unwrap_or(self.entry),
                    }
                }
                _ => fallthrough_or_return(next_block),
            },
            FlowControl::Next | FlowControl::Call | FlowControl::Break | FlowControl::Meta => {
                fallthrough_or_return(next_block)
            }
        }
    }

    fn compute_postorder(&mut self) {
        let count: usize = self.blocks.len();
        let mut visited: Vec<bool> = vec![false; count];
        let mut order: Vec<BlockId> = Vec::with_capacity(count);
        let mut stack: Vec<(BlockId, usize)> = vec![(self.entry, 0)];
        visited[self.entry] = true;
        while let Some(&mut (node, ref mut idx)) = stack.last_mut() {
            let succs: &[BlockId] = &self.blocks[node].succs;
            if *idx < succs.len() {
                let child: BlockId = succs[*idx];
                *idx += 1;
                if !visited[child] {
                    visited[child] = true;
                    stack.push((child, 0));
                }
            } else {
                order.push(node);
                stack.pop();
            }
        }
        let mut postorder_num: Vec<usize> = vec![usize::MAX; count];
        for (i, &b) in order.iter().enumerate() {
            postorder_num[b] = i;
        }
        let mut rpo: Vec<BlockId> = order.clone();
        rpo.reverse();
        self.postorder_num = postorder_num;
        self.rpo = rpo;
    }

    fn compute_dominators(&mut self) {
        let flow: Option<FlowGraph<BlockId>> = block_flow(self);
        self.flow = flow;
    }

    #[must_use]
    pub fn immediate_dominator(&self, b: BlockId) -> Option<BlockId> {
        self.flow
            .as_ref()
            .and_then(|flow: &FlowGraph<BlockId>| flow.immediate_dominator(b))
    }

    #[must_use]
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        self.flow
            .as_ref()
            .is_some_and(|flow: &FlowGraph<BlockId>| flow.dominates(a, b))
    }

    #[must_use]
    pub fn is_reachable(&self, b: BlockId) -> bool {
        self.postorder_num
            .get(b)
            .is_some_and(|n: &usize| *n != usize::MAX)
    }

    fn detect_loops(&mut self) {
        let mut loops: Vec<NaturalLoop> = Vec::new();
        let mut header_to_loop: BTreeMap<BlockId, usize> = BTreeMap::new();
        for bid in 0..self.blocks.len() {
            if !self.is_reachable(bid) {
                continue;
            }
            for &succ in &self.blocks[bid].succs {
                if self.dominates(succ, bid) {
                    let body: BTreeSet<BlockId> = self.natural_loop_body(succ, &[bid]);
                    if let Some(idx) = header_to_loop.get(&succ).copied() {
                        loops[idx].body.extend(body);
                        loops[idx].latches.push(bid);
                    } else {
                        header_to_loop.insert(succ, loops.len());
                        loops.push(NaturalLoop {
                            header: succ,
                            body,
                            latches: vec![bid],
                        });
                    }
                }
            }
        }
        self.loops = loops;
    }

    fn natural_loop_body(&self, header: BlockId, latches: &[BlockId]) -> BTreeSet<BlockId> {
        self.flow
            .as_ref()
            .map_or_else(BTreeSet::new, |flow: &FlowGraph<BlockId>| {
                flow.natural_loop_body(header, latches)
            })
    }

    #[must_use]
    pub fn loop_at_header(&self, bid: BlockId) -> Option<&NaturalLoop> {
        self.loops.iter().find(|l: &&NaturalLoop| l.header == bid)
    }

    pub(crate) fn cut_edge(&mut self, from: BlockId, to: BlockId) {
        self.blocks[from].succs.retain(|&s: &BlockId| s != to);
        self.blocks[to].preds.retain(|&p: &BlockId| p != from);
        self.terminators[from] = match self.terminators[from].clone() {
            Terminator::FallThrough(b) | Terminator::Goto(b) if b == to => Terminator::Return,
            Terminator::Cond { taken, fallthrough } if taken == to => Terminator::Goto(fallthrough),
            Terminator::Cond { taken, fallthrough } if fallthrough == to => Terminator::Goto(taken),
            Terminator::Switch { cases, fallthrough } => {
                let kept: Vec<BlockId> = cases.into_iter().filter(|&c: &BlockId| c != to).collect();
                Terminator::Switch {
                    cases: kept,
                    fallthrough,
                }
            }
            other => other,
        };
    }

    pub(crate) fn retarget_to_goto(&mut self, from: BlockId, to: BlockId) {
        let old_succs: Vec<BlockId> = std::mem::take(&mut self.blocks[from].succs);
        for s in old_succs {
            self.blocks[s].preds.retain(|&p: &BlockId| p != from);
        }
        self.blocks[from].succs = vec![to];
        if !self.blocks[to].preds.contains(&from) {
            self.blocks[to].preds.push(from);
        }
        self.terminators[from] = Terminator::Goto(to);
    }

    pub(crate) fn recompute_derived(&mut self) {
        self.compute_postorder();
        self.compute_dominators();
        self.loops.clear();
        self.detect_loops();
    }

    #[must_use]
    pub fn immediate_post_dominators(&self) -> Vec<BlockId> {
        let count: usize = self.blocks.len();
        let Some(flow): Option<&FlowGraph<BlockId>> = self.flow.as_ref() else {
            return vec![usize::MAX; count];
        };
        (0..count)
            .map(|bid: BlockId| match flow.immediate_post_dominator(bid) {
                PostDominator::Node(target) => target,
                PostDominator::FunctionExit | PostDominator::Undefined => usize::MAX,
            })
            .collect()
    }
}

fn block_flow(cfg: &Cfg) -> Option<FlowGraph<BlockId>> {
    FlowGraph::build(
        0..cfg.blocks.len(),
        cfg.entry,
        |node: BlockId, emit: &mut dyn FnMut(Flow<BlockId>)| {
            let Some(block): Option<&BasicBlock> = cfg.blocks.get(node) else {
                return;
            };
            for &successor in &block.succs {
                emit(Flow::To(successor));
            }
            if matches!(
                cfg.terminators.get(node),
                Some(Terminator::Return | Terminator::Throw | Terminator::EndFinally)
            ) {
                emit(Flow::Exit);
            }
        },
    )
    .ok()
}

fn fallthrough_or_return(next_block: Option<BlockId>) -> Terminator {
    next_block.map_or(Terminator::Return, Terminator::FallThrough)
}

fn term_successors(term: &Terminator) -> Vec<BlockId> {
    match term {
        Terminator::FallThrough(b) | Terminator::Goto(b) => vec![*b],
        Terminator::Cond { taken, fallthrough } => vec![*taken, *fallthrough],
        Terminator::Switch { cases, fallthrough } => {
            let mut v: Vec<BlockId> = cases.clone();
            v.push(*fallthrough);
            v
        }
        Terminator::Return | Terminator::Throw | Terminator::EndFinally => Vec::new(),
    }
}

fn collect_leaders(body: &MethodBody) -> BTreeSet<u32> {
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    let offsets: Vec<u32> = body
        .instructions
        .iter()
        .map(|i: &Instruction| i.offset)
        .collect();
    if let Some(&first) = offsets.first() {
        leaders.insert(first);
    }
    for (idx, ins) in body.instructions.iter().enumerate() {
        match ins.flow {
            FlowControl::Branch | FlowControl::CondBranch => {
                match &ins.operand {
                    OperandValue::BrTarget(rel) => {
                        leaders.insert((i64::from(ins.offset) + i64::from(*rel)) as u32);
                    }
                    OperandValue::Switch(rels) => {
                        for r in rels {
                            leaders.insert((i64::from(ins.offset) + i64::from(*r)) as u32);
                        }
                    }
                    _ => {}
                }
                if let Some(&next) = offsets.get(idx + 1) {
                    leaders.insert(next);
                }
            }
            FlowControl::Return | FlowControl::Throw => {
                if let Some(&next) = offsets.get(idx + 1) {
                    leaders.insert(next);
                }
            }
            _ => {}
        }
    }
    for clause in &body.exception_clauses {
        leaders.insert(clause.try_offset);
        leaders.insert(clause.handler_offset);
        leaders.insert(clause.try_offset.saturating_add(clause.try_length));
        leaders.insert(clause.handler_offset.saturating_add(clause.handler_length));
        if let Some(f) = clause_filter_offset(clause) {
            leaders.insert(f);
        }
    }
    leaders
}

fn clause_filter_offset(clause: &ExceptionClause) -> Option<u32> {
    matches!(clause.kind, crate::cil::ExceptionClauseKind::Filter)
        .then_some(clause.class_token_or_filter)
}

fn partition_blocks(
    body: &MethodBody,
    leaders: &BTreeSet<u32>,
) -> (Vec<BasicBlock>, BTreeMap<u32, BlockId>) {
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut start_to_block: BTreeMap<u32, BlockId> = BTreeMap::new();
    let instrs: &[Instruction] = &body.instructions;
    let mut i: usize = 0;
    while i < instrs.len() {
        let start: u32 = instrs[i].offset;
        let first: usize = i;
        let mut last: usize = i;
        i += 1;
        while i < instrs.len() && !leaders.contains(&instrs[i].offset) {
            last = i;
            i += 1;
        }
        if i <= instrs.len() && last < i.saturating_sub(1) {
            last = i - 1;
        }
        let bid: BlockId = blocks.len();
        start_to_block.insert(start, bid);
        blocks.push(BasicBlock {
            start,
            first,
            last,
            succs: Vec::new(),
            preds: Vec::new(),
        });
    }
    (blocks, start_to_block)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cil::disassemble;
    use crate::structurize::normalize_branches_pub;

    fn cfg_from(code: &[u8]) -> Cfg {
        let body: MethodBody = MethodBody {
            max_stack: 8,
            code_size: code.len() as u32,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: disassemble(code).expect("disasm"),
            exception_clauses: Vec::new(),
        };
        Cfg::build(&normalize_branches_pub(&body))
    }

    fn cfg_from_terminators(terminators: Vec<Terminator>) -> Cfg {
        let count: usize = terminators.len();
        let successors: Vec<Vec<BlockId>> = terminators.iter().map(term_successors).collect();
        let mut predecessors: Vec<Vec<BlockId>> = vec![Vec::new(); count];
        for (source, targets) in successors.iter().enumerate() {
            for &target in targets {
                predecessors[target].push(source);
            }
        }
        let blocks: Vec<BasicBlock> = successors
            .into_iter()
            .zip(predecessors)
            .enumerate()
            .map(
                |(index, (succs, preds)): (usize, (Vec<BlockId>, Vec<BlockId>))| BasicBlock {
                    start: u32::try_from(index).expect("block index fits u32") * 10,
                    first: index,
                    last: index,
                    succs,
                    preds,
                },
            )
            .collect();
        let start_to_block: BTreeMap<u32, BlockId> = blocks
            .iter()
            .enumerate()
            .map(|(index, block): (usize, &BasicBlock)| (block.start, index))
            .collect();
        let mut cfg: Cfg = Cfg {
            blocks,
            terminators,
            start_to_block,
            flow: None,
            postorder_num: Vec::new(),
            rpo: Vec::new(),
            loops: Vec::new(),
            entry: 0,
        };
        cfg.recompute_derived();
        cfg
    }

    #[test]
    fn straight_line_is_single_block() {
        let cfg: Cfg = cfg_from(&[0x16, 0x17, 0x58, 0x2A]);
        assert_eq!(cfg.blocks.len(), 1);
        assert_eq!(cfg.terminators[0], Terminator::Return);
    }

    #[test]
    fn conditional_branch_splits_into_three_blocks_with_cond_terminator() {
        let cfg: Cfg = cfg_from(&[0x02, 0x2C, 0x01, 0x2A, 0x2A]);
        assert!(cfg.blocks.len() >= 2, "cond branch must split blocks");
        assert!(
            cfg.terminators
                .iter()
                .any(|t: &Terminator| matches!(t, Terminator::Cond { .. })),
            "must recover a Cond terminator"
        );
    }

    #[test]
    fn entry_dominates_all_reachable_blocks() {
        let cfg: Cfg = cfg_from(&[0x02, 0x2C, 0x01, 0x2A, 0x2A]);
        for b in 0..cfg.blocks.len() {
            if cfg.is_reachable(b) {
                assert!(cfg.dominates(cfg.entry, b), "entry dominates block {b}");
            }
        }
    }

    #[test]
    fn backward_branch_forms_natural_loop() {
        let code: [u8; 6] = [0x16, 0x0A, 0x06, 0x2D, 0xFD, 0x2A];
        let cfg: Cfg = cfg_from(&code);
        assert!(
            !cfg.loops.is_empty(),
            "a backward conditional branch must form a natural loop; blocks={}",
            cfg.blocks.len()
        );
        let lp: &NaturalLoop = &cfg.loops[0];
        assert!(cfg.dominates(lp.header, *lp.latches.first().expect("latch")));
    }

    #[test]
    fn diamond_uses_its_merge_as_the_immediate_post_dominator() {
        let cfg: Cfg = cfg_from_terminators(vec![
            Terminator::Cond {
                taken: 1,
                fallthrough: 2,
            },
            Terminator::Goto(3),
            Terminator::Goto(3),
            Terminator::Return,
        ]);
        let immediate: Vec<BlockId> = cfg.immediate_post_dominators();
        assert_eq!(immediate, vec![3, 3, 3, usize::MAX]);
    }

    #[test]
    fn looped_sibling_branches_use_the_later_merge_not_the_loop_header() {
        let cfg: Cfg = cfg_from_terminators(vec![
            Terminator::Cond {
                taken: 1,
                fallthrough: 4,
            },
            Terminator::Cond {
                taken: 3,
                fallthrough: 2,
            },
            Terminator::Goto(3),
            Terminator::Goto(0),
            Terminator::Return,
        ]);
        let immediate: Vec<BlockId> = cfg.immediate_post_dominators();
        assert_eq!(immediate, vec![4, 3, 3, 0, usize::MAX]);
    }
}
