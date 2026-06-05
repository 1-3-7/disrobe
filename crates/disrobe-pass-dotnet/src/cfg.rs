//! Basic-block CFG over a CIL instruction stream, with dominance and natural-loop analysis.

use std::collections::{BTreeMap, BTreeSet};

use crate::cil::{ExceptionClause, FlowControl, Instruction, MethodBody, OperandValue};

/// Index of a basic block within [`Cfg::blocks`].
pub type BlockId = usize;

/// One basic block: a maximal straight-line instruction run.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// IL offset of the block's first instruction (its stable label).
    pub start: u32,
    /// Index range `[first, last]` into the normalized instruction vector (inclusive).
    pub first: usize,
    pub last: usize,
    /// Fall-through / branch successors as block ids.
    pub succs: Vec<BlockId>,
    /// Predecessor block ids.
    pub preds: Vec<BlockId>,
}

/// How a block transfers control at its tail, recovered from the terminator instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminator {
    /// Falls through to the textually-next block.
    FallThrough(BlockId),
    /// Unconditional branch (`br`/`leave`) to a single target.
    Goto(BlockId),
    /// Conditional branch: `taken` when the condition holds, else `fallthrough`.
    Cond {
        taken: BlockId,
        fallthrough: BlockId,
    },
    /// Jump table: one target per case index.
    Switch {
        cases: Vec<BlockId>,
        fallthrough: BlockId,
    },
    /// `ret` (function exit).
    Return,
    /// `throw`/`rethrow`.
    Throw,
    /// `endfinally`/`endfilter` (leaves the EH handler region).
    EndFinally,
}

/// A recovered natural loop: a header, its body blocks, and its back-edge latches.
#[derive(Debug, Clone)]
pub struct NaturalLoop {
    pub header: BlockId,
    pub body: BTreeSet<BlockId>,
    pub latches: Vec<BlockId>,
}

/// Control-flow graph of a method body plus computed dominance and loop information.
#[derive(Debug, Clone)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    pub terminators: Vec<Terminator>,
    /// `start_to_block[offset]` -> block id whose `start == offset`.
    pub start_to_block: BTreeMap<u32, BlockId>,
    /// Immediate dominator of each block; the entry's idom is itself.
    pub idom: Vec<BlockId>,
    /// Postorder traversal numbers (higher = closer to entry).
    pub postorder_num: Vec<usize>,
    /// Reverse-postorder block ordering (entry first), reachable blocks only.
    pub rpo: Vec<BlockId>,
    pub loops: Vec<NaturalLoop>,
    pub entry: BlockId,
}

impl Cfg {
    /// Build the CFG from a branch-normalized method body.
    #[must_use]
    pub fn build(body: &MethodBody) -> Self {
        let leaders: BTreeSet<u32> = collect_leaders(body);
        let (blocks, start_to_block): (Vec<BasicBlock>, BTreeMap<u32, BlockId>) =
            partition_blocks(body, &leaders);
        let mut cfg: Self = Self {
            blocks,
            terminators: Vec::new(),
            start_to_block,
            idom: Vec::new(),
            postorder_num: Vec::new(),
            rpo: Vec::new(),
            loops: Vec::new(),
            entry: 0,
        };
        cfg.wire_edges(body);
        cfg.compute_postorder();
        cfg.compute_dominators();
        cfg.detect_loops();
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
        let count: usize = self.blocks.len();
        let undefined: BlockId = usize::MAX;
        let mut idom: Vec<BlockId> = vec![undefined; count];
        idom[self.entry] = self.entry;
        let mut changed: bool = true;
        while changed {
            changed = false;
            for &b in &self.rpo {
                if b == self.entry {
                    continue;
                }
                let mut new_idom: BlockId = undefined;
                for &p in &self.blocks[b].preds {
                    if idom[p] == undefined {
                        continue;
                    }
                    new_idom = if new_idom == undefined {
                        p
                    } else {
                        self.intersect(p, new_idom, &idom)
                    };
                }
                if new_idom != undefined && idom[b] != new_idom {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }
        for d in &mut idom {
            if *d == undefined {
                *d = self.entry;
            }
        }
        self.idom = idom;
    }

    fn intersect(&self, mut a: BlockId, mut b: BlockId, idom: &[BlockId]) -> BlockId {
        while a != b {
            while self.postorder_num[a] < self.postorder_num[b] {
                a = idom[a];
            }
            while self.postorder_num[b] < self.postorder_num[a] {
                b = idom[b];
            }
        }
        a
    }

    /// Whether `a` dominates `b` (walks the dominator tree from `b` to the entry).
    #[must_use]
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        if a == b {
            return true;
        }
        let mut cur: BlockId = b;
        while cur != self.entry {
            let up: BlockId = self.idom[cur];
            if up == cur {
                break;
            }
            cur = up;
            if cur == a {
                return true;
            }
        }
        a == self.entry && self.is_reachable(b)
    }

    /// Whether a block is reachable from the entry (has a valid postorder number).
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
                    let body: BTreeSet<BlockId> = self.natural_loop_body(succ, bid);
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

    fn natural_loop_body(&self, header: BlockId, latch: BlockId) -> BTreeSet<BlockId> {
        let mut body: BTreeSet<BlockId> = BTreeSet::new();
        body.insert(header);
        if latch == header {
            return body;
        }
        let mut worklist: Vec<BlockId> = vec![latch];
        body.insert(latch);
        while let Some(n) = worklist.pop() {
            for &p in &self.blocks[n].preds {
                if body.insert(p) {
                    worklist.push(p);
                }
            }
        }
        body
    }

    /// The innermost natural loop whose header is `bid`, if any.
    #[must_use]
    pub fn loop_at_header(&self, bid: BlockId) -> Option<&NaturalLoop> {
        self.loops.iter().find(|l: &&NaturalLoop| l.header == bid)
    }

    /// Compute immediate post-dominators over the reverse CFG with a single virtual exit.
    #[must_use]
    pub fn immediate_post_dominators(&self) -> Vec<BlockId> {
        let count: usize = self.blocks.len();
        let virtual_exit: BlockId = count;
        let total: usize = count + 1;
        let mut rsuccs: Vec<Vec<BlockId>> = vec![Vec::new(); total];
        for (bid, block) in self.blocks.iter().enumerate() {
            match &self.terminators[bid] {
                Terminator::Return | Terminator::Throw | Terminator::EndFinally => {
                    rsuccs[bid].push(virtual_exit);
                }
                _ => rsuccs[bid].extend(block.succs.iter().copied()),
            }
        }
        let mut rpreds: Vec<Vec<BlockId>> = vec![Vec::new(); total];
        for (n, succs) in rsuccs.iter().enumerate() {
            for &s in succs {
                rpreds[s].push(n);
            }
        }
        let (post_num, rpo): (Vec<usize>, Vec<BlockId>) =
            reverse_postorder(virtual_exit, &rpreds, total);
        let undefined: BlockId = usize::MAX;
        let mut ipdom: Vec<BlockId> = vec![undefined; total];
        ipdom[virtual_exit] = virtual_exit;
        let mut changed: bool = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == virtual_exit {
                    continue;
                }
                let mut new_ipdom: BlockId = undefined;
                for &p in &rpreds[b] {
                    if ipdom[p] == undefined {
                        continue;
                    }
                    new_ipdom = if new_ipdom == undefined {
                        p
                    } else {
                        intersect_by(p, new_ipdom, &ipdom, &post_num)
                    };
                }
                if new_ipdom != undefined && ipdom[b] != new_ipdom {
                    ipdom[b] = new_ipdom;
                    changed = true;
                }
            }
        }
        ipdom.truncate(count);
        for d in &mut ipdom {
            if *d == virtual_exit {
                *d = usize::MAX;
            }
        }
        ipdom
    }
}

fn reverse_postorder(
    entry: BlockId,
    succs: &[Vec<BlockId>],
    total: usize,
) -> (Vec<usize>, Vec<BlockId>) {
    let mut visited: Vec<bool> = vec![false; total];
    let mut order: Vec<BlockId> = Vec::with_capacity(total);
    let mut stack: Vec<(BlockId, usize)> = vec![(entry, 0)];
    visited[entry] = true;
    while let Some(&mut (node, ref mut idx)) = stack.last_mut() {
        if *idx < succs[node].len() {
            let child: BlockId = succs[node][*idx];
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
    let mut post_num: Vec<usize> = vec![usize::MAX; total];
    for (i, &b) in order.iter().enumerate() {
        post_num[b] = i;
    }
    order.reverse();
    (post_num, order)
}

fn intersect_by(mut a: BlockId, mut b: BlockId, idom: &[BlockId], post_num: &[usize]) -> BlockId {
    while a != b {
        while post_num[a] < post_num[b] {
            a = idom[a];
        }
        while post_num[b] < post_num[a] {
            b = idom[b];
        }
    }
    a
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

/// Block leaders per ECMA-335: entry, branch/switch targets, post-transfer instructions, EH boundaries.
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
}
