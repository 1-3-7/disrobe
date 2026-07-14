use std::collections::{BTreeMap, BTreeSet};

use disrobe_core::DiGraph;
use serde::{Deserialize, Serialize};

use crate::bytecode::{CodeAttribute, ExceptionEntry, Instruction, Operands, branch_target};
use crate::classfile::{ClassFile, ConstantPoolEntry};

const MAX_BLOCKS: usize = 16_384;
const MAX_STRUCTURE_DEPTH: usize = 256;
const MAX_STRUCTURE_WORK: usize = 200_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    Fallthrough,
    Jump,
    CondTrue,
    CondFalse,
    Switch,
    SwitchDefault,
    Exception,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub kind: EdgeKind,
    pub target: BlockId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BlockId,
    pub start_pc: u32,
    pub end_pc: u32,
    pub insn_range: (usize, usize),
    pub successors: Vec<Edge>,
    pub predecessors: Vec<BlockId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionRegion {
    pub try_start_pc: u32,
    pub try_end_pc: u32,
    pub handler_pc: u32,
    pub catch_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    pub pc_to_block: BTreeMap<u32, BlockId>,
    pub entry: BlockId,
    pub exception_regions: Vec<ExceptionRegion>,
}

pub fn build_cfg(
    insns: &[Instruction],
    code: &CodeAttribute,
    resolve_class: impl Fn(u16) -> Option<String>,
) -> Result<Cfg, StructureError> {
    if insns.is_empty() {
        return Err(StructureError::Empty);
    }
    let leaders: BTreeSet<u32> = collect_leaders(insns, &code.exception_table);
    if leaders.len() > MAX_BLOCKS {
        return Err(StructureError::TooManyBlocks(leaders.len()));
    }
    let pc_to_idx: BTreeMap<u32, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, ins)| (ins.pc, i))
        .collect();

    let leader_vec: Vec<u32> = leaders.iter().copied().collect();
    let mut blocks: Vec<BasicBlock> = Vec::with_capacity(leader_vec.len());
    let mut pc_to_block: BTreeMap<u32, BlockId> = BTreeMap::new();

    for (i, &start_pc) in leader_vec.iter().enumerate() {
        let end_exclusive_pc: u32 = leader_vec.get(i + 1).copied().unwrap_or(u32::MAX);
        let start_idx: usize = *pc_to_idx.get(&start_pc).ok_or(StructureError::BadLeader)?;
        let mut end_idx: usize = start_idx;
        while end_idx < insns.len() && insns[end_idx].pc < end_exclusive_pc {
            end_idx += 1;
        }
        let last_pc: u32 = insns
            .get(end_idx.saturating_sub(1))
            .map_or(start_pc, |ins| ins.pc);
        let id: BlockId = BlockId(i as u32);
        pc_to_block.insert(start_pc, id);
        blocks.push(BasicBlock {
            id,
            start_pc,
            end_pc: last_pc,
            insn_range: (start_idx, end_idx),
            successors: Vec::new(),
            predecessors: Vec::new(),
        });
    }

    let mut successors_by_id: Vec<Vec<Edge>> = vec![Vec::new(); blocks.len()];
    for (i, block) in blocks.iter().enumerate() {
        let last: &Instruction = &insns[block.insn_range.1.saturating_sub(1)];
        let next_pc: Option<u32> = leader_vec.get(i + 1).copied();
        let block_succs: Vec<Edge> = block_successors(last, next_pc, &pc_to_block);
        successors_by_id[i] = block_succs;
    }
    for (i, succs) in successors_by_id.iter().enumerate() {
        let src_id: BlockId = blocks[i].id;
        for edge in succs {
            let preds: &mut Vec<BlockId> = &mut blocks[edge.target.0 as usize].predecessors;
            if !preds.contains(&src_id) {
                preds.push(src_id);
            }
        }
        blocks[i].successors.clone_from(succs);
    }

    for entry in &code.exception_table {
        let handler_pc: u32 = u32::from(entry.handler_pc);
        if let Some(&handler_id) = pc_to_block.get(&handler_pc) {
            let mut covered: Vec<BlockId> = Vec::new();
            for (&pc, &bid) in &pc_to_block {
                if pc >= u32::from(entry.start_pc) && pc < u32::from(entry.end_pc) {
                    covered.push(bid);
                }
            }
            for bid in covered {
                let succs: &mut Vec<Edge> = &mut blocks[bid.0 as usize].successors;
                if !succs
                    .iter()
                    .any(|e| e.target == handler_id && matches!(e.kind, EdgeKind::Exception))
                {
                    succs.push(Edge {
                        kind: EdgeKind::Exception,
                        target: handler_id,
                    });
                }
                let preds: &mut Vec<BlockId> = &mut blocks[handler_id.0 as usize].predecessors;
                if !preds.contains(&bid) {
                    preds.push(bid);
                }
            }
        }
    }

    let exception_regions: Vec<ExceptionRegion> = code
        .exception_table
        .iter()
        .map(|e: &ExceptionEntry| ExceptionRegion {
            try_start_pc: u32::from(e.start_pc),
            try_end_pc: u32::from(e.end_pc),
            handler_pc: u32::from(e.handler_pc),
            catch_type: if e.catch_type == 0 {
                None
            } else {
                resolve_class(e.catch_type)
            },
        })
        .collect();

    let entry: BlockId = BlockId(0);
    Ok(Cfg {
        blocks,
        pc_to_block,
        entry,
        exception_regions,
    })
}

fn collect_leaders(insns: &[Instruction], exception_table: &[ExceptionEntry]) -> BTreeSet<u32> {
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    leaders.insert(insns[0].pc);
    let mut prev_terminator: bool = false;
    for ins in insns {
        if prev_terminator {
            leaders.insert(ins.pc);
        }
        let term: bool = is_terminator(ins);
        if let Some(t) = branch_target(ins) {
            leaders.insert(t);
        }
        match &ins.operands {
            Operands::TableSwitch {
                default, offsets, ..
            } => {
                leaders.insert((i64::from(ins.pc) + i64::from(*default)) as u32);
                for off in offsets {
                    leaders.insert((i64::from(ins.pc) + i64::from(*off)) as u32);
                }
            }
            Operands::LookupSwitch { default, pairs } => {
                leaders.insert((i64::from(ins.pc) + i64::from(*default)) as u32);
                for (_, off) in pairs {
                    leaders.insert((i64::from(ins.pc) + i64::from(*off)) as u32);
                }
            }
            _ => {}
        }
        prev_terminator = term;
    }
    for e in exception_table {
        leaders.insert(u32::from(e.start_pc));
        leaders.insert(u32::from(e.end_pc));
        leaders.insert(u32::from(e.handler_pc));
    }
    let valid_pcs: BTreeSet<u32> = insns.iter().map(|i| i.pc).collect();
    leaders.retain(|pc| valid_pcs.contains(pc));
    leaders
}

const fn is_terminator(ins: &Instruction) -> bool {
    matches!(
        ins.opcode,
        0xA7 | 0xC8 | 0xAC..=0xB1 | 0xBF | 0xAA | 0xAB | 0xA9
    ) || is_conditional_branch(ins.opcode)
}

const fn is_conditional_branch(op: u8) -> bool {
    matches!(op, 0x99..=0xA6 | 0xC6 | 0xC7)
}

fn block_successors(
    last: &Instruction,
    fallthrough_pc: Option<u32>,
    pc_to_block: &BTreeMap<u32, BlockId>,
) -> Vec<Edge> {
    let mut out: Vec<Edge> = Vec::new();
    let op: u8 = last.opcode;
    if is_conditional_branch(op) {
        if let Some(t) = branch_target(last)
            && let Some(&bid) = pc_to_block.get(&t)
        {
            out.push(Edge {
                kind: EdgeKind::CondTrue,
                target: bid,
            });
        }
        if let Some(fpc) = fallthrough_pc
            && let Some(&bid) = pc_to_block.get(&fpc)
        {
            out.push(Edge {
                kind: EdgeKind::CondFalse,
                target: bid,
            });
        }
        return out;
    }
    match op {
        0xA7 | 0xC8 => {
            if let Some(t) = branch_target(last)
                && let Some(&bid) = pc_to_block.get(&t)
            {
                out.push(Edge {
                    kind: EdgeKind::Jump,
                    target: bid,
                });
            }
        }
        0xAC..=0xB1 | 0xBF | 0xA9 => {}
        0xAA => {
            if let Operands::TableSwitch {
                default, offsets, ..
            } = &last.operands
            {
                let dpc: u32 = (i64::from(last.pc) + i64::from(*default)) as u32;
                if let Some(&bid) = pc_to_block.get(&dpc) {
                    out.push(Edge {
                        kind: EdgeKind::SwitchDefault,
                        target: bid,
                    });
                }
                for off in offsets {
                    let tpc: u32 = (i64::from(last.pc) + i64::from(*off)) as u32;
                    if let Some(&bid) = pc_to_block.get(&tpc) {
                        out.push(Edge {
                            kind: EdgeKind::Switch,
                            target: bid,
                        });
                    }
                }
            }
        }
        0xAB => {
            if let Operands::LookupSwitch { default, pairs } = &last.operands {
                let dpc: u32 = (i64::from(last.pc) + i64::from(*default)) as u32;
                if let Some(&bid) = pc_to_block.get(&dpc) {
                    out.push(Edge {
                        kind: EdgeKind::SwitchDefault,
                        target: bid,
                    });
                }
                for (_, off) in pairs {
                    let tpc: u32 = (i64::from(last.pc) + i64::from(*off)) as u32;
                    if let Some(&bid) = pc_to_block.get(&tpc) {
                        out.push(Edge {
                            kind: EdgeKind::Switch,
                            target: bid,
                        });
                    }
                }
            }
        }
        _ => {
            if let Some(fpc) = fallthrough_pc
                && let Some(&bid) = pc_to_block.get(&fpc)
            {
                out.push(Edge {
                    kind: EdgeKind::Fallthrough,
                    target: bid,
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum StructureError {
    #[error("empty instruction stream")]
    Empty,
    #[error("too many basic blocks: {0}")]
    TooManyBlocks(usize),
    #[error("leader index missing from instruction stream")]
    BadLeader,
    #[error("structuring recursion depth exceeded")]
    StructuringDepthExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dominators {
    pub idom: Vec<Option<BlockId>>,
    pub order: Vec<BlockId>,
}

#[must_use]
pub fn compute_dominators(cfg: &Cfg) -> Dominators {
    let n: usize = cfg.blocks.len();
    let order: Vec<BlockId> = reverse_postorder(cfg);
    let entry_idx: usize = cfg.entry.0 as usize;
    let graph: BlockGraph<'_> = BlockGraph { cfg };
    let doms: disrobe_core::Dominators = disrobe_core::Dominators::compute(&graph);
    let idom: Vec<Option<BlockId>> = (0..n)
        .map(|i: usize| {
            if i == entry_idx {
                Some(cfg.entry)
            } else {
                doms.immediate_dominator(i as u32).map(BlockId)
            }
        })
        .collect();
    Dominators { idom, order }
}

struct BlockGraph<'a> {
    cfg: &'a Cfg,
}

impl DiGraph for BlockGraph<'_> {
    fn node_count(&self) -> usize {
        self.cfg.blocks.len()
    }

    fn entry(&self) -> u32 {
        self.cfg.entry.0
    }

    fn for_each_successor(&self, node: u32, visit: &mut dyn FnMut(u32)) {
        for edge in &self.cfg.blocks[node as usize].successors {
            visit(edge.target.0);
        }
    }
}

fn reverse_postorder(cfg: &Cfg) -> Vec<BlockId> {
    let n: usize = cfg.blocks.len();
    let mut visited: Vec<bool> = vec![false; n];
    let mut order: Vec<BlockId> = Vec::with_capacity(n);
    let mut stack: Vec<(BlockId, usize)> = Vec::new();
    visited[cfg.entry.0 as usize] = true;
    stack.push((cfg.entry, 0));
    while let Some(&mut (b, ref mut i)) = stack.last_mut() {
        let block: &BasicBlock = &cfg.blocks[b.0 as usize];
        if *i < block.successors.len() {
            let next: BlockId = block.successors[*i].target;
            *i += 1;
            let ni: usize = next.0 as usize;
            if !visited[ni] {
                visited[ni] = true;
                stack.push((next, 0));
            }
        } else {
            order.push(b);
            stack.pop();
        }
    }
    for (i, seen) in visited.iter().enumerate().take(n) {
        if !seen {
            order.push(BlockId(i as u32));
        }
    }
    order.reverse();
    order
}

#[must_use]
pub fn dominates(dom: &Dominators, ancestor: BlockId, child: BlockId) -> bool {
    let mut cur: Option<BlockId> = Some(child);
    let mut steps: usize = 0;
    while let Some(c) = cur {
        if c == ancestor {
            return true;
        }
        let idom: Option<BlockId> = dom.idom.get(c.0 as usize).copied().flatten();
        match idom {
            Some(parent) if parent == c => return false,
            Some(parent) => cur = Some(parent),
            None => return false,
        }
        steps += 1;
        if steps > MAX_STRUCTURE_DEPTH {
            return false;
        }
    }
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NaturalLoop {
    pub header: BlockId,
    pub latches: Vec<BlockId>,
    pub body: BTreeSet<BlockId>,
}

#[must_use]
pub fn find_natural_loops(cfg: &Cfg, dom: &Dominators) -> Vec<NaturalLoop> {
    let mut by_header: BTreeMap<BlockId, NaturalLoop> = BTreeMap::new();
    for block in &cfg.blocks {
        for edge in &block.successors {
            if matches!(edge.kind, EdgeKind::Exception) && edge.target == block.id {
                continue;
            }
            if dominates(dom, edge.target, block.id) {
                let entry: &mut NaturalLoop =
                    by_header.entry(edge.target).or_insert_with(|| NaturalLoop {
                        header: edge.target,
                        latches: Vec::new(),
                        body: BTreeSet::new(),
                    });
                if !entry.latches.contains(&block.id) {
                    entry.latches.push(block.id);
                }
                expand_loop_body(cfg, edge.target, block.id, &mut entry.body);
            }
        }
    }
    let mut loops: Vec<NaturalLoop> = by_header.into_values().collect();
    loops.sort_by_key(|l| (l.body.len(), l.header.0));
    loops
}

fn expand_loop_body(cfg: &Cfg, header: BlockId, latch: BlockId, body: &mut BTreeSet<BlockId>) {
    body.insert(header);
    let mut stack: Vec<BlockId> = vec![latch];
    let mut steps: usize = 0;
    while let Some(n) = stack.pop() {
        steps += 1;
        if steps > MAX_BLOCKS {
            return;
        }
        if body.insert(n) {
            for &p in &cfg.blocks[n.0 as usize].predecessors {
                if p != header && !body.contains(&p) {
                    stack.push(p);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Region {
    Block(BlockId),
    Sequence(Vec<Self>),
    IfThen {
        head: BlockId,
        cond_negated: bool,
        then_body: Box<Self>,
        join: Option<BlockId>,
    },
    IfThenElse {
        head: BlockId,
        cond_negated: bool,
        then_body: Box<Self>,
        else_body: Box<Self>,
        join: Option<BlockId>,
    },
    While {
        header: BlockId,
        body: Box<Self>,
        exit: Option<BlockId>,
    },
    DoWhile {
        header: BlockId,
        body: Box<Self>,
        exit: Option<BlockId>,
    },
    Switch {
        head: BlockId,
        cases: Vec<(SwitchKey, Self)>,
        default: Option<Box<Self>>,
        join: Option<BlockId>,
    },
    Try {
        try_body: Box<Self>,
        handlers: Vec<(Vec<String>, Self)>,
    },
    TryFinally {
        try_body: Box<Self>,
        handlers: Vec<(Vec<String>, Self)>,
        finally_chain: Vec<BlockId>,
    },
    TryWithResources {
        resource_slot: u16,
        try_body: Box<Self>,
    },
    Synchronized {
        lock_block: BlockId,
        lock_slot: u16,
        body: Box<Self>,
    },
    LabeledLoop {
        label: u32,
        body: Box<Self>,
    },
    Break {
        label: Option<u32>,
    },
    Continue {
        label: Option<u32>,
        latch: Option<BlockId>,
    },
    Irreducible {
        blocks: Vec<BlockId>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwitchKey {
    Range { low: i32, high: i32 },
    Values(Vec<i32>),
}

#[derive(Debug, Clone, Default)]
pub struct PrecomputedSwitch {
    pub default: Option<BlockId>,
    pub cases: Vec<(SwitchKey, BlockId)>,
}

#[derive(Debug, Clone)]
pub struct StringSwitchTable {
    pub prefix_block: BlockId,
    pub prefix_len: usize,
    pub subject_source_slot: u16,
    pub idx_switch_head: BlockId,
    pub idx_to_literal: BTreeMap<i32, String>,
    pub bucket_blocks: Vec<BlockId>,
}

#[derive(Debug)]
pub struct Structurer<'a> {
    cf: Option<&'a ClassFile>,
    cfg: &'a Cfg,
    dom: &'a Dominators,
    loops: &'a [NaturalLoop],
    insns: &'a [Instruction],
    switch_map: BTreeMap<BlockId, PrecomputedSwitch>,
    string_switch_tables: BTreeMap<BlockId, StringSwitchTable>,
    finally_inline_skips: BTreeMap<BlockId, usize>,
    finally_return_stores: BTreeMap<BlockId, u16>,
    finally_exception_slots: BTreeSet<u16>,
    visited: BTreeSet<BlockId>,
    loop_header_of: BTreeMap<BlockId, BlockId>,
    loop_exits: BTreeMap<BlockId, BlockId>,
    try_groups: Vec<GroupedTry>,
    suppress_try_at: Option<BlockId>,
    active_finally: Vec<BlockId>,
    loop_stack: Vec<LoopFrame>,
    labels_used: BTreeSet<u32>,
    next_label: u32,
    depth: usize,
    work: usize,
    pub had_irreducible: bool,
}

#[derive(Debug, Clone, Copy)]
struct LoopFrame {
    header: BlockId,
    exit: Option<BlockId>,
    label: u32,
}

impl<'a> Structurer<'a> {
    #[must_use]
    pub fn new(
        cfg: &'a Cfg,
        dom: &'a Dominators,
        loops: &'a [NaturalLoop],
        insns: &'a [Instruction],
    ) -> Self {
        Self::with_switch_map(cfg, dom, loops, insns, BTreeMap::new())
    }

    #[must_use]
    pub fn with_switch_map(
        cfg: &'a Cfg,
        dom: &'a Dominators,
        loops: &'a [NaturalLoop],
        insns: &'a [Instruction],
        switch_map: BTreeMap<BlockId, PrecomputedSwitch>,
    ) -> Self {
        let mut loop_header_of: BTreeMap<BlockId, BlockId> = BTreeMap::new();
        for l in loops {
            for &b in &l.body {
                loop_header_of.entry(b).or_insert(l.header);
            }
        }
        let mut loop_exits: BTreeMap<BlockId, BlockId> = BTreeMap::new();
        for l in loops {
            if let Some(exit) = find_loop_exit(cfg, l) {
                loop_exits.insert(l.header, exit);
            }
        }
        let try_groups: Vec<GroupedTry> = group_exception_regions(cfg);
        Self {
            cf: None,
            cfg,
            dom,
            loops,
            insns,
            switch_map,
            string_switch_tables: BTreeMap::new(),
            finally_inline_skips: BTreeMap::new(),
            finally_return_stores: BTreeMap::new(),
            finally_exception_slots: BTreeSet::new(),
            visited: BTreeSet::new(),
            loop_header_of,
            loop_exits,
            try_groups,
            suppress_try_at: None,
            active_finally: Vec::new(),
            loop_stack: Vec::new(),
            labels_used: BTreeSet::new(),
            next_label: 0,
            depth: 0,
            work: 0,
            had_irreducible: false,
        }
    }

    #[must_use]
    pub const fn with_class(mut self, cf: &'a ClassFile) -> Self {
        self.cf = Some(cf);
        self
    }

    #[must_use]
    pub fn take_string_switch_tables(&mut self) -> BTreeMap<BlockId, StringSwitchTable> {
        std::mem::take(&mut self.string_switch_tables)
    }

    #[must_use]
    pub fn take_finally_inline_skips(&mut self) -> BTreeMap<BlockId, usize> {
        std::mem::take(&mut self.finally_inline_skips)
    }

    #[must_use]
    pub fn take_finally_return_stores(&mut self) -> BTreeMap<BlockId, u16> {
        std::mem::take(&mut self.finally_return_stores)
    }

    #[must_use]
    pub fn take_finally_exception_slots(&mut self) -> BTreeSet<u16> {
        std::mem::take(&mut self.finally_exception_slots)
    }

    pub fn structure(&mut self) -> Region {
        let entry: BlockId = self.cfg.entry;
        self.structure_at(entry, None)
    }

    #[must_use]
    pub fn try_group_at_block(&self, bid: BlockId) -> Option<GroupedTry> {
        let pc: u32 = self.cfg.blocks[bid.0 as usize].start_pc;
        self.try_groups
            .iter()
            .find(|g| g.try_start_pc == pc)
            .cloned()
    }

    fn block_instructions(&self, bid: BlockId) -> &[Instruction] {
        let (lo, hi): (usize, usize) = self.cfg.blocks[bid.0 as usize].insn_range;
        let len: usize = self.insns.len();
        let lo: usize = lo.min(len);
        let hi: usize = hi.min(len);
        if lo >= hi {
            return &[];
        }
        &self.insns[lo..hi]
    }

    fn try_with_resources_slot(&self, handler_bid: BlockId) -> Option<u16> {
        let primary_slot: u16 = astore_slot(self.block_instructions(handler_bid).first()?)?;
        let mut seen: BTreeSet<BlockId> = BTreeSet::new();
        let mut resource_slot: Option<u16> = None;
        let mut saw_suppress: bool = false;
        let mut saw_athrow: bool = false;
        let mut stack: Vec<BlockId> = vec![handler_bid];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            if seen.len() > MAX_BLOCKS {
                return None;
            }
            let block_insns: &[Instruction] = self.block_instructions(cur);
            let mut prev_aload: Option<u16> = None;
            for ins in block_insns {
                if matches!(ins.opcode, 0xC6 | 0xC7)
                    && let Some(slot) = prev_aload
                    && slot != primary_slot
                {
                    resource_slot.get_or_insert(slot);
                }
                if matches!(ins.opcode, 0xB6..=0xB9) && block_insns.len() >= 3 {
                    saw_suppress = true;
                }
                if ins.opcode == 0xBF {
                    if aload_slot_of_prev(block_insns, ins) == Some(primary_slot) {
                        saw_athrow = true;
                    } else {
                        return None;
                    }
                }
                prev_aload = aload_slot(ins);
            }
            for edge in &self.cfg.blocks[cur.0 as usize].successors {
                stack.push(edge.target);
            }
        }
        if saw_suppress && saw_athrow {
            resource_slot
        } else {
            None
        }
    }

    fn try_with_resources_at(
        &mut self,
        try_start: BlockId,
        group: &GroupedTry,
    ) -> Option<TwrResult> {
        if group.handlers.len() != 1 {
            return None;
        }
        let (catch_type, handler_pc): &(Option<String>, u32) = group.handlers.first()?;
        if catch_type.as_deref() != Some("java/lang/Throwable") {
            return None;
        }
        let handler_bid: BlockId = *self.cfg.pc_to_block.get(handler_pc)?;
        let resource_slot: u16 = self.try_with_resources_slot(handler_bid)?;

        let try_end: u32 = group.try_end_pc;
        let normal_close: BlockId = *self
            .cfg
            .pc_to_block
            .range(try_end..)
            .next()
            .map(|(_, b)| b)?;
        let (after, close_blocks): (Option<BlockId>, Vec<BlockId>) =
            self.normal_close_continuation(normal_close, resource_slot)?;

        let body: Region = self.structure_try_body(try_start, try_end);

        for &cb in &close_blocks {
            self.visited.insert(cb);
        }
        let mut handler_walk: Vec<BlockId> = vec![handler_bid];
        let mut handler_seen: BTreeSet<BlockId> = BTreeSet::new();
        while let Some(cur) = handler_walk.pop() {
            if !handler_seen.insert(cur) || handler_seen.len() > MAX_BLOCKS {
                continue;
            }
            self.visited.insert(cur);
            for edge in &self.cfg.blocks[cur.0 as usize].successors {
                if !matches!(edge.kind, EdgeKind::Exception) {
                    handler_walk.push(edge.target);
                }
            }
            for hpc in group.handlers.iter().map(|(_, pc)| *pc) {
                if let Some(&bid) = self.cfg.pc_to_block.get(&hpc) {
                    handler_walk.push(bid);
                }
            }
        }

        Some(TwrResult {
            region: Region::TryWithResources {
                resource_slot,
                try_body: Box::new(body),
            },
            after,
        })
    }

    fn normal_close_continuation(
        &self,
        head: BlockId,
        resource_slot: u16,
    ) -> Option<(Option<BlockId>, Vec<BlockId>)> {
        let head_insns: &[Instruction] = self.block_instructions(head);
        let first: &Instruction = head_insns.first()?;
        if aload_slot(first) != Some(resource_slot) {
            return None;
        }
        let last: &Instruction = head_insns.last()?;
        if !matches!(last.opcode, 0xC6 | 0xC7) {
            return None;
        }
        let mut close_blocks: Vec<BlockId> = vec![head];
        let succs: &[Edge] = &self.cfg.blocks[head.0 as usize].successors;
        let true_t: Option<BlockId> = succs
            .iter()
            .find(|e| matches!(e.kind, EdgeKind::CondTrue))
            .map(|e| e.target);
        let false_t: Option<BlockId> = succs
            .iter()
            .find(|e| matches!(e.kind, EdgeKind::CondFalse))
            .map(|e| e.target);
        let (null_target, close_target): (BlockId, BlockId) = if last.opcode == 0xC6 {
            (true_t?, false_t?)
        } else {
            (false_t?, true_t?)
        };
        let close_insns: &[Instruction] = self.block_instructions(close_target);
        let invokes_close: bool = close_insns
            .iter()
            .any(|i| matches!(i.opcode, 0xB6 | 0xB9 | 0xB8));
        if !invokes_close {
            return None;
        }
        close_blocks.push(close_target);
        Some((Some(null_target), close_blocks))
    }

    fn structure_try_body(&mut self, start: BlockId, try_end: u32) -> Region {
        let mut seq: Vec<Region> = Vec::new();
        let mut cur: Option<BlockId> = Some(start);
        while let Some(b) = cur {
            self.work += 1;
            if self.work > MAX_STRUCTURE_WORK {
                self.had_irreducible = true;
                break;
            }
            if self.cfg.blocks[b.0 as usize].start_pc >= try_end {
                break;
            }
            if let Some(jump) = self.outer_loop_jump(b) {
                seq.push(jump);
                break;
            }
            if self.visited.contains(&b) {
                break;
            }
            self.visited.insert(b);
            if let Some(loop_info) = self.loops.iter().find(|l| l.header == b) {
                let loop_info: NaturalLoop = loop_info.clone();
                let exit: Option<BlockId> = self.loop_exits.get(&b).copied();
                let label: u32 = self.next_label;
                self.next_label += 1;
                let body_region: Region = self.structure_loop_body(
                    &loop_info,
                    exit,
                    LoopFrame {
                        header: b,
                        exit,
                        label,
                    },
                );
                let header_kind: LoopKind = classify_loop_header(self.cfg, &loop_info);
                let header_region: Region = match header_kind {
                    LoopKind::While => Region::While {
                        header: b,
                        body: Box::new(body_region),
                        exit,
                    },
                    LoopKind::DoWhile => Region::DoWhile {
                        header: b,
                        body: Box::new(body_region),
                        exit,
                    },
                };
                let header_region: Region = if self.labels_used.remove(&label) {
                    Region::LabeledLoop {
                        label,
                        body: Box::new(header_region),
                    }
                } else {
                    header_region
                };
                seq.push(header_region);
                cur = exit.filter(|e| self.cfg.blocks[e.0 as usize].start_pc < try_end);
                continue;
            }
            let block: &BasicBlock = &self.cfg.blocks[b.0 as usize];
            if is_switch(block, &self.cfg.blocks) {
                seq.push(self.structure_switch(b, None));
                cur = self
                    .find_switch_join(b)
                    .filter(|e| self.cfg.blocks[e.0 as usize].start_pc < try_end);
                continue;
            }
            if is_if(block) {
                let if_region: Region = self.structure_if(b, None);
                let join: Option<BlockId> = match &if_region {
                    Region::IfThen { join, .. } | Region::IfThenElse { join, .. } => *join,
                    _ => None,
                };
                seq.push(if_region);
                cur = join.filter(|e| self.cfg.blocks[e.0 as usize].start_pc < try_end);
                continue;
            }
            seq.push(Region::Block(b));
            cur = self.cfg.blocks[b.0 as usize]
                .successors
                .iter()
                .find(|e| !matches!(e.kind, EdgeKind::Exception))
                .map(|e| e.target)
                .filter(|t| self.cfg.blocks[t.0 as usize].start_pc < try_end);
        }
        match <[Region; 1]>::try_from(seq) {
            Ok([single]) => single,
            Err(seq) => Region::Sequence(seq),
        }
    }

    fn finally_handler_chain(&self, handler_bid: BlockId) -> Option<Vec<BlockId>> {
        let entry_insns: &[Instruction] = self.block_instructions(handler_bid);
        let slot: u16 = astore_slot(entry_insns.first()?)?;
        let mut chain: Vec<BlockId> = vec![handler_bid];
        let mut cur: BlockId = handler_bid;
        let mut steps: usize = 0;
        loop {
            steps += 1;
            if steps > MAX_BLOCKS {
                return None;
            }
            let block_insns: &[Instruction] = self.block_instructions(cur);
            if let Some(last) = block_insns.last()
                && last.opcode == 0xBF
                && block_insns.len() >= 2
                && aload_slot(&block_insns[block_insns.len() - 2]) == Some(slot)
            {
                return Some(chain);
            }
            let mut normal_succs = self.cfg.blocks[cur.0 as usize]
                .successors
                .iter()
                .filter(|e| !matches!(e.kind, EdgeKind::Exception));
            let next: BlockId = match (normal_succs.next(), normal_succs.next()) {
                (Some(only), None) => only.target,
                _ => return None,
            };
            if chain.contains(&next) {
                return None;
            }
            chain.push(next);
            cur = next;
        }
    }

    fn finally_body_instructions(&self, chain: &[BlockId]) -> Option<Vec<Instruction>> {
        let (&first, &last): (&BlockId, &BlockId) = chain.first().zip(chain.last())?;
        let mut body: Vec<Instruction> = Vec::new();
        for &bid in chain {
            let insns: &[Instruction] = self.block_instructions(bid);
            let lo: usize = usize::from(bid == first);
            let hi: usize = if bid == last {
                insns.len().checked_sub(2)?
            } else {
                insns.len()
            };
            if lo > hi {
                return None;
            }
            body.extend_from_slice(&insns[lo..hi]);
        }
        if body.is_empty()
            || body
                .iter()
                .any(|ins: &Instruction| matches!(ins.opcode, 0x99..=0xB1 | 0xBF | 0xC6..=0xC9))
        {
            return None;
        }
        Some(body)
    }

    fn slot_total_uses(&self, slot: u16) -> usize {
        self.insns
            .iter()
            .filter(|ins: &&Instruction| {
                any_load_slot(ins) == Some(slot) || any_store_slot(ins) == Some(slot)
            })
            .count()
    }

    fn single_try_predecessor(&self, group: &GroupedTry, cont: BlockId) -> Option<BlockId> {
        let block: &BasicBlock = &self.cfg.blocks[cont.0 as usize];
        let real_preds: Vec<BlockId> = block
            .predecessors
            .iter()
            .copied()
            .filter(|p: &BlockId| {
                self.cfg.blocks[p.0 as usize]
                    .successors
                    .iter()
                    .any(|e: &Edge| e.target == cont && !matches!(e.kind, EdgeKind::Exception))
            })
            .collect();
        let &[pred]: &[BlockId] = real_preds.as_slice() else {
            return None;
        };
        let pred_pc: u32 = self.cfg.blocks[pred.0 as usize].start_pc;
        (pred_pc >= group.try_start_pc && pred_pc < group.try_end_pc).then_some(pred)
    }

    fn finally_value_return_temp(
        &self,
        group: &GroupedTry,
        cont: BlockId,
        skip: usize,
    ) -> Option<(BlockId, u16)> {
        let insns: &[Instruction] = self.block_instructions(cont);
        let tail: &[Instruction] = insns.get(skip..)?;
        let [load, ret]: &[Instruction; 2] = tail.try_into().ok()?;
        if !matches!(ret.opcode, 0xAC..=0xB0) {
            return None;
        }
        let slot: u16 = any_load_slot(load)?;
        let pred: BlockId = self.single_try_predecessor(group, cont)?;
        let pred_last: &Instruction = self.block_instructions(pred).last()?;
        if any_store_slot(pred_last) != Some(slot) {
            return None;
        }
        (self.slot_total_uses(slot) == 2).then_some((pred, slot))
    }

    fn finally_return_exit(&self, group: &GroupedTry, cont: BlockId, skip: usize) -> bool {
        let insns: &[Instruction] = self.block_instructions(cont);
        if skip >= insns.len() {
            return false;
        }
        let Some(last): Option<&Instruction> = insns.last() else {
            return false;
        };
        if !matches!(last.opcode, 0xAC..=0xB1) {
            return false;
        }
        let block: &BasicBlock = &self.cfg.blocks[cont.0 as usize];
        if block
            .successors
            .iter()
            .any(|e: &Edge| !matches!(e.kind, EdgeKind::Exception))
        {
            return false;
        }
        let real_preds: Vec<BlockId> = block
            .predecessors
            .iter()
            .copied()
            .filter(|p: &BlockId| {
                self.cfg.blocks[p.0 as usize]
                    .successors
                    .iter()
                    .any(|e: &Edge| e.target == cont && !matches!(e.kind, EdgeKind::Exception))
            })
            .collect();
        let &[pred]: &[BlockId] = real_preds.as_slice() else {
            return false;
        };
        let pred_pc: u32 = self.cfg.blocks[pred.0 as usize].start_pc;
        pred_pc >= group.try_start_pc && pred_pc < group.try_end_pc
    }

    fn finally_inline_skip(&self, chain: &[BlockId], cont: BlockId) -> Option<usize> {
        let body: Vec<Instruction> = self.finally_body_instructions(chain)?;
        let cont_insns: &[Instruction] = self.block_instructions(cont);
        if cont_insns.len() <= body.len() {
            return None;
        }
        let matched: bool =
            body.iter()
                .zip(cont_insns.iter())
                .all(|(a, b): (&Instruction, &Instruction)| {
                    a.opcode == b.opcode && a.operands == b.operands
                });
        matched.then_some(body.len())
    }

    fn outer_loop_jump(&mut self, target: BlockId) -> Option<Region> {
        if self.loop_stack.len() < 2 {
            return None;
        }
        let outer: &[LoopFrame] = &self.loop_stack[..self.loop_stack.len() - 1];
        for frame in outer.iter().rev() {
            if frame.exit == Some(target) {
                self.labels_used.insert(frame.label);
                return Some(Region::Break {
                    label: Some(frame.label),
                });
            }
            if let Some(continue_stmts) = self.outer_continue_at(target, frame) {
                self.labels_used.insert(frame.label);
                return Some(continue_stmts);
            }
        }
        None
    }

    fn outer_continue_at(&self, target: BlockId, frame: &LoopFrame) -> Option<Region> {
        if target == frame.header {
            return Some(Region::Continue {
                label: Some(frame.label),
                latch: None,
            });
        }
        let block: &BasicBlock = &self.cfg.blocks[target.0 as usize];
        let mut normal = block
            .successors
            .iter()
            .filter(|e| !matches!(e.kind, EdgeKind::Exception));
        let only: Option<BlockId> = match (normal.next(), normal.next()) {
            (Some(e), None) => Some(e.target),
            _ => None,
        };
        if only == Some(frame.header) {
            return Some(Region::Continue {
                label: Some(frame.label),
                latch: Some(target),
            });
        }
        None
    }

    fn synchronized_lock_block(&self, try_start: BlockId) -> Option<(BlockId, u16)> {
        let pred: BlockId = self
            .cfg
            .blocks
            .iter()
            .filter(|blk| {
                blk.successors
                    .iter()
                    .any(|e| e.target == try_start && !matches!(e.kind, EdgeKind::Exception))
            })
            .map(|blk| blk.id)
            .min_by_key(|id| id.0)?;
        let pred_insns: &[Instruction] = self.block_instructions(pred);
        let n: usize = pred_insns.len();
        if n < 3 {
            return None;
        }
        let monitorenter: &Instruction = &pred_insns[n - 1];
        let astore: &Instruction = &pred_insns[n - 2];
        let dup: &Instruction = &pred_insns[n - 3];
        if monitorenter.opcode != 0xC2 || dup.opcode != 0x59 {
            return None;
        }
        let slot: u16 = astore_slot(astore)?;
        Some((pred, slot))
    }

    fn is_synchronized_finally(&self, chain: &[BlockId], lock_slot: u16) -> bool {
        let mut released: bool = false;
        let mut rethrown: bool = false;
        let mut other_effect: bool = false;
        for &cb in chain {
            let insns: &[Instruction] = self.block_instructions(cb);
            for (i, ins) in insns.iter().enumerate() {
                match ins.opcode {
                    0xC3 => {
                        if i > 0 && aload_slot(&insns[i - 1]) == Some(lock_slot) {
                            released = true;
                        } else {
                            other_effect = true;
                        }
                    }
                    0xBF => rethrown = true,
                    0x19 | 0x2A..=0x2D | 0x3A | 0x4B..=0x4E => {}
                    _ => other_effect = true,
                }
            }
        }
        released && rethrown && !other_effect
    }

    fn is_finally_handler(&self, handler_bid: BlockId) -> bool {
        self.finally_handler_chain(handler_bid).is_some()
    }

    fn absorbable_value_return(
        &self,
        group: &GroupedTry,
        try_end_block: Option<BlockId>,
        handler_set: &BTreeSet<BlockId>,
    ) -> Option<BlockId> {
        let terminal: BlockId = try_end_block?;
        if handler_set.contains(&terminal) || self.visited.contains(&terminal) {
            return None;
        }
        let block: &BasicBlock = &self.cfg.blocks[terminal.0 as usize];
        if block
            .successors
            .iter()
            .any(|e: &Edge| !matches!(e.kind, EdgeKind::Exception))
        {
            return None;
        }
        let last: &Instruction = self.block_instructions(terminal).last()?;
        if !matches!(last.opcode, 0xAC..=0xB0) {
            return None;
        }
        let real_preds: Vec<BlockId> = block
            .predecessors
            .iter()
            .copied()
            .filter(|p: &BlockId| {
                self.cfg.blocks[p.0 as usize]
                    .successors
                    .iter()
                    .any(|e: &Edge| e.target == terminal && !matches!(e.kind, EdgeKind::Exception))
            })
            .collect();
        let [pred]: [BlockId; 1] = real_preds.as_slice().try_into().ok()?;
        let falls_through: bool = self.cfg.blocks[pred.0 as usize]
            .successors
            .iter()
            .any(|e: &Edge| e.target == terminal && matches!(e.kind, EdgeKind::Fallthrough));
        if !falls_through {
            return None;
        }
        let pred_pc: u32 = self.cfg.blocks[pred.0 as usize].start_pc;
        if pred_pc < group.try_start_pc || pred_pc >= group.try_end_pc {
            return None;
        }
        Some(terminal)
    }

    fn structure_at(&mut self, start: BlockId, stop: Option<BlockId>) -> Region {
        self.work += 1;
        if self.work > MAX_STRUCTURE_WORK {
            self.had_irreducible = true;
            return Region::Irreducible {
                blocks: vec![start],
            };
        }
        self.depth += 1;
        if self.depth > MAX_STRUCTURE_DEPTH {
            self.had_irreducible = true;
            self.depth -= 1;
            return Region::Irreducible {
                blocks: vec![start],
            };
        }
        let mut seq: Vec<Region> = Vec::new();
        let mut cur: Option<BlockId> = Some(start);
        while let Some(b) = cur {
            self.work += 1;
            if self.work > MAX_STRUCTURE_WORK {
                self.had_irreducible = true;
                break;
            }
            if Some(b) == stop {
                break;
            }
            if let Some(jump) = self.outer_loop_jump(b) {
                seq.push(jump);
                break;
            }
            if self.visited.contains(&b) {
                break;
            }

            if self.suppress_try_at != Some(b)
                && let Some(try_group) = self.try_group_at_block(b)
            {
                if let Some(twr) = self.try_with_resources_at(b, &try_group) {
                    seq.push(twr.region);
                    cur = twr.after;
                    continue;
                }
                let try_end_block: Option<BlockId> = self
                    .cfg
                    .pc_to_block
                    .range(try_group.try_end_pc..)
                    .next()
                    .map(|(_, &bid)| bid);
                let handler_block_ids: Vec<(Option<String>, BlockId)> = try_group
                    .handlers
                    .iter()
                    .filter_map(|(t, hpc)| {
                        self.cfg.pc_to_block.get(hpc).map(|&bid| (t.clone(), bid))
                    })
                    .collect();
                let finally_handler: Option<BlockId> = handler_block_ids
                    .iter()
                    .find(|(t, bid)| t.is_none() && self.is_finally_handler(*bid))
                    .map(|(_, bid)| *bid);
                let finally_chain: Option<Vec<BlockId>> =
                    finally_handler.and_then(|bid| self.finally_handler_chain(bid));
                let redundant_finally: bool = finally_handler
                    .is_some_and(|h| self.active_finally.contains(&h))
                    && handler_block_ids
                        .iter()
                        .all(|(_, bid)| Some(*bid) == finally_handler);
                if redundant_finally {
                    let prev_suppress: Option<BlockId> = self.suppress_try_at;
                    self.suppress_try_at = Some(b);
                    let body_region: Region = self.structure_at(b, try_end_block);
                    self.suppress_try_at = prev_suppress;
                    seq.push(body_region);
                    cur = try_end_block;
                    continue;
                }
                let catch_handler_ids: Vec<(Option<String>, BlockId)> = handler_block_ids
                    .iter()
                    .filter(|(_, bid)| Some(*bid) != finally_handler)
                    .cloned()
                    .collect();
                let handler_set: BTreeSet<BlockId> =
                    catch_handler_ids.iter().map(|(_, bid)| *bid).collect();
                let end_is_handler: bool = try_end_block.is_some_and(|e| handler_set.contains(&e));
                let prev_suppress: Option<BlockId> = self.suppress_try_at;
                self.suppress_try_at = Some(b);
                let pushed_finally: bool = if let Some(h) = finally_handler {
                    self.active_finally.push(h);
                    true
                } else {
                    false
                };
                let mut body_region: Region = self.structure_at(b, try_end_block);
                self.suppress_try_at = prev_suppress;
                let mut handlers_out: Vec<(Vec<String>, Region)> = Vec::new();
                let absorbed_terminal: Option<BlockId> = if finally_handler.is_none() {
                    self.absorbable_value_return(&try_group, try_end_block, &handler_set)
                } else {
                    None
                };
                let mut after_try: Option<BlockId> = if let Some(terminal) = absorbed_terminal {
                    self.visited.insert(terminal);
                    body_region = append_region_block(body_region, terminal);
                    None
                } else if end_is_handler {
                    handler_continuation(self.cfg, &handler_set)
                } else {
                    try_end_block
                };
                let mut handler_index: BTreeMap<BlockId, usize> = BTreeMap::new();
                for (catch_type, handler_bid) in catch_handler_ids {
                    if let Some(&idx) = handler_index.get(&handler_bid) {
                        if let Some(ty) = catch_type
                            && !handlers_out[idx].0.contains(&ty)
                        {
                            handlers_out[idx].0.push(ty);
                        }
                        continue;
                    }
                    if self.visited.contains(&handler_bid) {
                        continue;
                    }
                    let handler_region: Region = self.structure_at(handler_bid, after_try);
                    handler_index.insert(handler_bid, handlers_out.len());
                    handlers_out.push((catch_type.into_iter().collect(), handler_region));
                }
                if pushed_finally {
                    self.active_finally.pop();
                }
                if let Some(chain) = finally_chain {
                    for &fb in &chain {
                        self.visited.insert(fb);
                    }
                    if handlers_out.is_empty()
                        && let Some((lock_block, lock_slot)) = self.synchronized_lock_block(b)
                        && self.is_synchronized_finally(&chain, lock_slot)
                        && matches!(seq.last(), Some(Region::Block(prev)) if *prev == lock_block)
                    {
                        seq.pop();
                        seq.push(Region::Synchronized {
                            lock_block,
                            lock_slot,
                            body: Box::new(body_region),
                        });
                        cur = after_try;
                        continue;
                    }
                    if handlers_out.is_empty()
                        && let Some(&first) = chain.first()
                        && let Some(entry) = self.block_instructions(first).first()
                        && let Some(exc_slot) = astore_slot(entry)
                        && self.slot_total_uses(exc_slot) == 2
                    {
                        self.finally_exception_slots.insert(exc_slot);
                    }
                    if let Some(cont) = after_try
                        && let Some(skip) = self.finally_inline_skip(&chain, cont)
                        && handlers_out.is_empty()
                        && !self.visited.contains(&cont)
                    {
                        self.finally_inline_skips.insert(cont, skip);
                        if let Some((pred, slot)) =
                            self.finally_value_return_temp(&try_group, cont, skip)
                        {
                            self.finally_return_stores.insert(pred, slot);
                            self.visited.insert(cont);
                            after_try = None;
                        } else if self.finally_return_exit(&try_group, cont, skip) {
                            self.visited.insert(cont);
                            body_region = append_region_block(body_region, cont);
                            after_try = None;
                        }
                    } else if let Some(cont) = after_try
                        && let Some(skip) = self.finally_inline_skip(&chain, cont)
                    {
                        self.finally_inline_skips.insert(cont, skip);
                    }
                    seq.push(Region::TryFinally {
                        try_body: Box::new(body_region),
                        handlers: handlers_out,
                        finally_chain: chain,
                    });
                } else {
                    seq.push(Region::Try {
                        try_body: Box::new(body_region),
                        handlers: handlers_out,
                    });
                }
                cur = after_try;
                continue;
            }

            self.visited.insert(b);

            if let Some(loop_info) = self.loops.iter().find(|l| l.header == b) {
                let loop_info: NaturalLoop = loop_info.clone();
                let exit: Option<BlockId> = self.loop_exits.get(&b).copied();
                let label: u32 = self.next_label;
                self.next_label += 1;
                let body_region: Region = self.structure_loop_body(
                    &loop_info,
                    exit,
                    LoopFrame {
                        header: b,
                        exit,
                        label,
                    },
                );
                let header_kind: LoopKind = classify_loop_header(self.cfg, &loop_info);
                let header_region: Region = match header_kind {
                    LoopKind::While => Region::While {
                        header: b,
                        body: Box::new(body_region),
                        exit,
                    },
                    LoopKind::DoWhile => Region::DoWhile {
                        header: b,
                        body: Box::new(body_region),
                        exit,
                    },
                };
                let header_region: Region = if self.labels_used.remove(&label) {
                    Region::LabeledLoop {
                        label,
                        body: Box::new(header_region),
                    }
                } else {
                    header_region
                };
                seq.push(header_region);
                cur = exit;
                continue;
            }

            let block: &BasicBlock = &self.cfg.blocks[b.0 as usize];
            if is_switch(block, &self.cfg.blocks) {
                if let Some(cf) = self.cf
                    && let Some(table) = detect_string_switch(cf, self.cfg, self.insns, b)
                {
                    let idx_head: BlockId = table.idx_switch_head;
                    for &bucket in &table.bucket_blocks {
                        self.visited.insert(bucket);
                    }
                    self.string_switch_tables.insert(idx_head, table);
                    cur = Some(idx_head);
                    continue;
                }
                let switch_region: Region = self.structure_switch(b, stop);
                seq.push(switch_region);
                cur = self.find_switch_join(b);
                continue;
            }
            if is_if(block) {
                let if_region: Region = self.structure_if(b, stop);
                let join: Option<BlockId> = match &if_region {
                    Region::IfThen { join, .. } | Region::IfThenElse { join, .. } => *join,
                    _ => None,
                };
                seq.push(if_region);
                cur = join;
                continue;
            }
            seq.push(Region::Block(b));
            cur = follow_single_successor(block);
        }
        self.depth -= 1;
        match <[Region; 1]>::try_from(seq) {
            Ok([single]) => single,
            Err(seq) => Region::Sequence(seq),
        }
    }

    fn structure_loop_body(
        &mut self,
        loop_info: &NaturalLoop,
        exit: Option<BlockId>,
        frame: LoopFrame,
    ) -> Region {
        let mut loop_stack: Vec<LoopFrame> = self.loop_stack.clone();
        loop_stack.push(frame);
        let mut inner: Structurer<'_> = Structurer {
            cf: self.cf,
            cfg: self.cfg,
            dom: self.dom,
            loops: self.loops,
            insns: self.insns,
            switch_map: self.switch_map.clone(),
            string_switch_tables: BTreeMap::new(),
            finally_inline_skips: BTreeMap::new(),
            finally_return_stores: BTreeMap::new(),
            finally_exception_slots: BTreeSet::new(),
            visited: BTreeSet::new(),
            loop_header_of: self.loop_header_of.clone(),
            loop_exits: self.loop_exits.clone(),
            try_groups: self.try_groups.clone(),
            suppress_try_at: None,
            active_finally: self.active_finally.clone(),
            loop_stack,
            labels_used: BTreeSet::new(),
            next_label: self.next_label,
            depth: self.depth,
            work: self.work,
            had_irreducible: false,
        };
        inner.visited.insert(loop_info.header);
        let header_block: &BasicBlock = &self.cfg.blocks[loop_info.header.0 as usize];
        let first_succ: Option<BlockId> = header_block
            .successors
            .iter()
            .find(|e| Some(e.target) != exit && loop_info.body.contains(&e.target))
            .map(|e| e.target);
        let region: Region = match first_succ {
            Some(start) => inner.structure_at(start, exit),
            None => Region::Block(loop_info.header),
        };
        self.work = inner.work;
        self.next_label = inner.next_label;
        self.had_irreducible |= inner.had_irreducible;
        self.string_switch_tables
            .extend(inner.take_string_switch_tables());
        self.finally_inline_skips
            .extend(inner.take_finally_inline_skips());
        self.finally_return_stores
            .extend(inner.take_finally_return_stores());
        self.finally_exception_slots
            .extend(inner.take_finally_exception_slots());
        self.labels_used.extend(inner.labels_used);
        region
    }

    fn structure_if(&mut self, head: BlockId, stop: Option<BlockId>) -> Region {
        let block: &BasicBlock = &self.cfg.blocks[head.0 as usize];
        let (true_t, false_t): (BlockId, BlockId) = if_targets(block);
        let join: Option<BlockId> = find_if_join(self.cfg, self.dom, head, true_t, false_t);
        let then_stop: Option<BlockId> = join;
        let then_region: Region = self.structure_at(false_t, then_stop);
        let has_else: bool = match join {
            Some(j) => true_t != j,
            None => true,
        };
        if has_else {
            let else_stop: Option<BlockId> = join;
            let else_region: Region = self.structure_at(true_t, else_stop);
            let _ = stop;
            Region::IfThenElse {
                head,
                cond_negated: false,
                then_body: Box::new(then_region),
                else_body: Box::new(else_region),
                join,
            }
        } else {
            let _ = stop;
            Region::IfThen {
                head,
                cond_negated: false,
                then_body: Box::new(then_region),
                join,
            }
        }
    }

    fn structure_switch(&mut self, head: BlockId, _stop: Option<BlockId>) -> Region {
        if let Some(precomputed) = self.switch_map.get(&head).cloned() {
            let join: Option<BlockId> = find_switch_join(self.cfg, self.dom, head);
            let mut cases: Vec<(SwitchKey, Region)> = Vec::with_capacity(precomputed.cases.len());
            for (key, target) in precomputed.cases {
                if Some(target) == precomputed.default {
                    continue;
                }
                let r: Region = self.structure_at(target, join);
                cases.push((key, r));
            }
            let default_region: Option<Box<Region>> = precomputed
                .default
                .map(|d| Box::new(self.structure_at(d, join)));
            return Region::Switch {
                head,
                cases,
                default: default_region,
                join,
            };
        }
        let block: &BasicBlock = &self.cfg.blocks[head.0 as usize];
        let last_idx: usize = block.insn_range.1.saturating_sub(1);
        let switch_insn: Option<&Instruction> = self.insns.get(last_idx);

        let mut default: Option<BlockId> = None;
        let mut key_pairs: BTreeMap<BlockId, Vec<i32>> = BTreeMap::new();
        let mut ordered_targets: Vec<BlockId> = Vec::new();

        if let Some(insn) = switch_insn {
            match &insn.operands {
                Operands::TableSwitch {
                    default: d,
                    low,
                    offsets,
                    ..
                } => {
                    let dpc: u32 = (i64::from(insn.pc) + i64::from(*d)) as u32;
                    default = self.cfg.pc_to_block.get(&dpc).copied();
                    for (i, off) in offsets.iter().enumerate() {
                        let tpc: u32 = (i64::from(insn.pc) + i64::from(*off)) as u32;
                        if let Some(&bid) = self.cfg.pc_to_block.get(&tpc) {
                            let key_value: i32 = low.saturating_add(i as i32);
                            key_pairs.entry(bid).or_default().push(key_value);
                            if !ordered_targets.contains(&bid) {
                                ordered_targets.push(bid);
                            }
                        }
                    }
                }
                Operands::LookupSwitch { default: d, pairs } => {
                    let dpc: u32 = (i64::from(insn.pc) + i64::from(*d)) as u32;
                    default = self.cfg.pc_to_block.get(&dpc).copied();
                    for (k, off) in pairs {
                        let tpc: u32 = (i64::from(insn.pc) + i64::from(*off)) as u32;
                        if let Some(&bid) = self.cfg.pc_to_block.get(&tpc) {
                            key_pairs.entry(bid).or_default().push(*k);
                            if !ordered_targets.contains(&bid) {
                                ordered_targets.push(bid);
                            }
                        }
                    }
                }
                _ => {
                    for edge in &block.successors {
                        match edge.kind {
                            EdgeKind::SwitchDefault => default = Some(edge.target),
                            EdgeKind::Switch if !ordered_targets.contains(&edge.target) => {
                                ordered_targets.push(edge.target);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let join: Option<BlockId> = find_switch_join(self.cfg, self.dom, head);
        let mut cases: Vec<(SwitchKey, Region)> = Vec::new();
        for target in ordered_targets {
            if Some(target) == default {
                continue;
            }
            let values: Vec<i32> = key_pairs.remove(&target).unwrap_or_default();
            let key: SwitchKey = compact_key(&values);
            let r: Region = self.structure_at(target, join);
            cases.push((key, r));
        }
        let default_region: Option<Box<Region>> =
            default.map(|d| Box::new(self.structure_at(d, join)));
        Region::Switch {
            head,
            cases,
            default: default_region,
            join,
        }
    }

    fn find_switch_join(&self, head: BlockId) -> Option<BlockId> {
        find_switch_join(self.cfg, self.dom, head)
    }
}

#[derive(Debug, Clone, Copy)]
enum LoopKind {
    While,
    DoWhile,
}

fn classify_loop_header(cfg: &Cfg, loop_info: &NaturalLoop) -> LoopKind {
    let header_block: &BasicBlock = &cfg.blocks[loop_info.header.0 as usize];
    let cond_succs: Vec<&Edge> = header_block
        .successors
        .iter()
        .filter(|e| matches!(e.kind, EdgeKind::CondTrue | EdgeKind::CondFalse))
        .collect();
    if cond_succs.len() == 2 {
        let exits: usize = cond_succs
            .iter()
            .filter(|e| !loop_info.body.contains(&e.target))
            .count();
        if exits == 1 {
            return LoopKind::While;
        }
    }
    LoopKind::DoWhile
}

fn find_loop_exit(cfg: &Cfg, loop_info: &NaturalLoop) -> Option<BlockId> {
    for &b in &loop_info.body {
        let block: &BasicBlock = &cfg.blocks[b.0 as usize];
        for edge in &block.successors {
            if !loop_info.body.contains(&edge.target) && !matches!(edge.kind, EdgeKind::Exception) {
                return Some(edge.target);
            }
        }
    }
    None
}

fn is_if(block: &BasicBlock) -> bool {
    block.successors.len() == 2
        && block
            .successors
            .iter()
            .any(|e| matches!(e.kind, EdgeKind::CondTrue))
        && block
            .successors
            .iter()
            .any(|e| matches!(e.kind, EdgeKind::CondFalse))
}

fn is_switch(block: &BasicBlock, _blocks: &[BasicBlock]) -> bool {
    block
        .successors
        .iter()
        .any(|e| matches!(e.kind, EdgeKind::Switch | EdgeKind::SwitchDefault))
}

fn if_targets(block: &BasicBlock) -> (BlockId, BlockId) {
    let mut true_t: BlockId = block.id;
    let mut false_t: BlockId = block.id;
    for edge in &block.successors {
        match edge.kind {
            EdgeKind::CondTrue => true_t = edge.target,
            EdgeKind::CondFalse => false_t = edge.target,
            _ => {}
        }
    }
    (true_t, false_t)
}

const fn astore_slot(ins: &Instruction) -> Option<u16> {
    match (ins.opcode, &ins.operands) {
        (0x3A, Operands::Local(idx)) => Some(*idx),
        (0x4B..=0x4E, _) => Some((ins.opcode - 0x4B) as u16),
        _ => None,
    }
}

const fn aload_slot(ins: &Instruction) -> Option<u16> {
    match (ins.opcode, &ins.operands) {
        (0x19, Operands::Local(idx)) => Some(*idx),
        (0x2A..=0x2D, _) => Some((ins.opcode - 0x2A) as u16),
        _ => None,
    }
}

const fn any_load_slot(ins: &Instruction) -> Option<u16> {
    match (ins.opcode, &ins.operands) {
        (0x15..=0x19, Operands::Local(idx)) => Some(*idx),
        (0x1A..=0x1D, _) => Some((ins.opcode - 0x1A) as u16),
        (0x1E..=0x21, _) => Some((ins.opcode - 0x1E) as u16),
        (0x22..=0x25, _) => Some((ins.opcode - 0x22) as u16),
        (0x26..=0x29, _) => Some((ins.opcode - 0x26) as u16),
        (0x2A..=0x2D, _) => Some((ins.opcode - 0x2A) as u16),
        _ => None,
    }
}

const fn any_store_slot(ins: &Instruction) -> Option<u16> {
    match (ins.opcode, &ins.operands) {
        (0x36..=0x3A, Operands::Local(idx)) => Some(*idx),
        (0x3B..=0x3E, _) => Some((ins.opcode - 0x3B) as u16),
        (0x3F..=0x42, _) => Some((ins.opcode - 0x3F) as u16),
        (0x43..=0x46, _) => Some((ins.opcode - 0x43) as u16),
        (0x47..=0x4A, _) => Some((ins.opcode - 0x47) as u16),
        (0x4B..=0x4E, _) => Some((ins.opcode - 0x4B) as u16),
        _ => None,
    }
}

fn aload_slot_of_prev(block_insns: &[Instruction], target: &Instruction) -> Option<u16> {
    let idx: usize = block_insns.iter().position(|i| i.pc == target.pc)?;
    aload_slot(block_insns.get(idx.checked_sub(1)?)?)
}

fn append_region_block(region: Region, bid: BlockId) -> Region {
    match region {
        Region::Sequence(mut items) => {
            items.push(Region::Block(bid));
            Region::Sequence(items)
        }
        other => Region::Sequence(vec![other, Region::Block(bid)]),
    }
}

fn handler_continuation(cfg: &Cfg, handler_set: &BTreeSet<BlockId>) -> Option<BlockId> {
    let mut exits: BTreeSet<BlockId> = BTreeSet::new();
    for &h in handler_set {
        for edge in &cfg.blocks[h.0 as usize].successors {
            if !matches!(edge.kind, EdgeKind::Exception) && !handler_set.contains(&edge.target) {
                exits.insert(edge.target);
            }
        }
    }
    if exits.len() == 1 {
        exits.into_iter().next()
    } else {
        None
    }
}

fn follow_single_successor(block: &BasicBlock) -> Option<BlockId> {
    let normal: Vec<&Edge> = block
        .successors
        .iter()
        .filter(|e: &&Edge| !matches!(e.kind, EdgeKind::Exception))
        .collect();
    let [edge]: [&Edge; 1] = normal.as_slice().try_into().ok()?;
    Some(edge.target)
}

fn find_if_join(
    cfg: &Cfg,
    dom: &Dominators,
    head: BlockId,
    true_t: BlockId,
    false_t: BlockId,
) -> Option<BlockId> {
    let true_reach: BTreeSet<BlockId> = forward_reach(cfg, true_t, head);
    let false_reach: BTreeSet<BlockId> = forward_reach(cfg, false_t, head);
    let mut candidates: Vec<BlockId> = true_reach.intersection(&false_reach).copied().collect();
    candidates.retain(|c| dominates(dom, head, *c));
    candidates.sort_by_key(|c| cfg.blocks[c.0 as usize].start_pc);
    candidates.into_iter().next()
}

fn find_switch_join(cfg: &Cfg, dom: &Dominators, head: BlockId) -> Option<BlockId> {
    let head_block: &BasicBlock = &cfg.blocks[head.0 as usize];
    let mut reach_sets: Vec<BTreeSet<BlockId>> = Vec::new();
    for edge in &head_block.successors {
        reach_sets.push(forward_reach(cfg, edge.target, head));
    }
    if reach_sets.is_empty() {
        return None;
    }
    let mut common: BTreeSet<BlockId> = reach_sets[0].clone();
    for r in &reach_sets[1..] {
        common = common.intersection(r).copied().collect();
    }
    let mut candidates: Vec<BlockId> = common.into_iter().collect();
    candidates.retain(|c| dominates(dom, head, *c));
    candidates.sort_by_key(|c| cfg.blocks[c.0 as usize].start_pc);
    candidates.into_iter().next()
}

fn forward_reach(cfg: &Cfg, start: BlockId, exclude: BlockId) -> BTreeSet<BlockId> {
    let mut seen: BTreeSet<BlockId> = BTreeSet::new();
    let mut stack: Vec<BlockId> = vec![start];
    let mut steps: usize = 0;
    while let Some(n) = stack.pop() {
        steps += 1;
        if steps > MAX_BLOCKS {
            break;
        }
        if n == exclude {
            continue;
        }
        if seen.insert(n) {
            for edge in &cfg.blocks[n.0 as usize].successors {
                if !matches!(edge.kind, EdgeKind::Exception) && !seen.contains(&edge.target) {
                    stack.push(edge.target);
                }
            }
        }
    }
    seen
}

#[must_use]
pub fn exception_handler_blocks(cfg: &Cfg) -> BTreeSet<BlockId> {
    let mut out: BTreeSet<BlockId> = BTreeSet::new();
    for region in &cfg.exception_regions {
        if let Some(&bid) = cfg.pc_to_block.get(&region.handler_pc) {
            out.insert(bid);
        }
    }
    out
}

#[must_use]
pub fn try_region_blocks(cfg: &Cfg, region: &ExceptionRegion) -> Vec<BlockId> {
    let mut out: Vec<BlockId> = Vec::new();
    for (&pc, &bid) in &cfg.pc_to_block {
        if pc >= region.try_start_pc && pc < region.try_end_pc {
            out.push(bid);
        }
    }
    out
}

#[must_use]
pub fn group_exception_regions(cfg: &Cfg) -> Vec<GroupedTry> {
    let mut by_try: BTreeMap<(u32, u32), Vec<&ExceptionRegion>> = BTreeMap::new();
    for r in &cfg.exception_regions {
        by_try
            .entry((r.try_start_pc, r.try_end_pc))
            .or_default()
            .push(r);
    }
    let mut out: Vec<GroupedTry> = Vec::with_capacity(by_try.len());
    for ((start, end), regions) in by_try {
        let handlers: Vec<(Option<String>, u32)> = regions
            .iter()
            .map(|r| (r.catch_type.clone(), r.handler_pc))
            .collect();
        out.push(GroupedTry {
            try_start_pc: start,
            try_end_pc: end,
            handlers,
        });
    }
    out
}

#[derive(Debug)]
struct TwrResult {
    region: Region,
    after: Option<BlockId>,
}

#[derive(Debug, Clone)]
pub struct GroupedTry {
    pub try_start_pc: u32,
    pub try_end_pc: u32,
    pub handlers: Vec<(Option<String>, u32)>,
}

fn compact_key(values: &[i32]) -> SwitchKey {
    if values.is_empty() {
        return SwitchKey::Values(Vec::new());
    }
    let mut sorted: Vec<i32> = values.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() >= 3 {
        let low: i32 = sorted[0];
        let high: i32 = sorted[sorted.len() - 1];
        let span: i64 = i64::from(high) - i64::from(low) + 1;
        if span == sorted.len() as i64 {
            return SwitchKey::Range { low, high };
        }
    }
    SwitchKey::Values(sorted)
}

fn block_insn_slice<'i>(cfg: &Cfg, insns: &'i [Instruction], bid: BlockId) -> &'i [Instruction] {
    let (lo, hi): (usize, usize) = cfg.blocks[bid.0 as usize].insn_range;
    let len: usize = insns.len();
    let lo: usize = lo.min(len);
    let hi: usize = hi.min(len);
    if lo >= hi { &[] } else { &insns[lo..hi] }
}

const fn istore_slot(ins: &Instruction) -> Option<u16> {
    match (ins.opcode, &ins.operands) {
        (0x36, Operands::Local(idx)) => Some(*idx),
        (0x3B..=0x3E, _) => Some((ins.opcode - 0x3B) as u16),
        _ => None,
    }
}

const fn iload_slot(ins: &Instruction) -> Option<u16> {
    match (ins.opcode, &ins.operands) {
        (0x15, Operands::Local(idx)) => Some(*idx),
        (0x1A..=0x1D, _) => Some((ins.opcode - 0x1A) as u16),
        _ => None,
    }
}

const fn small_int_push(ins: &Instruction) -> Option<i32> {
    match (ins.opcode, &ins.operands) {
        (0x02, _) => Some(-1),
        (0x03..=0x08, _) => Some(ins.opcode as i32 - 3),
        (0x10 | 0x11, Operands::Byte(v) | Operands::Short(v)) => Some(*v),
        _ => None,
    }
}

fn invoke_member(cf: &ClassFile, ins: &Instruction) -> Option<(String, String)> {
    if ins.opcode != 0xB6 {
        return None;
    }
    let Operands::ConstPool(idx) = &ins.operands else {
        return None;
    };
    let reference: String = crate::bytecode::resolve_ref(cf, *idx)?;
    let (member, desc): (&str, &str) = reference.rsplit_once(':')?;
    Some((member.to_string(), desc.to_string()))
}

fn is_hashcode_invoke(cf: &ClassFile, ins: &Instruction) -> bool {
    invoke_member(cf, ins).is_some_and(|(member, desc): (String, String)| {
        member.ends_with(".hashCode") && desc == "()I"
    })
}

fn is_equals_invoke(cf: &ClassFile, ins: &Instruction) -> bool {
    invoke_member(cf, ins).is_some_and(|(member, desc): (String, String)| {
        member.ends_with(".equals") && desc == "(Ljava/lang/Object;)Z"
    })
}

fn ldc_string_literal(cf: &ClassFile, ins: &Instruction) -> Option<String> {
    if !matches!(ins.opcode, 0x12 | 0x13) {
        return None;
    }
    let Operands::ConstPool(idx) = &ins.operands else {
        return None;
    };
    match cf.constant_pool.get(usize::from(*idx))? {
        ConstantPoolEntry::String { .. } => crate::bytecode::resolve_ref(cf, *idx),
        _ => None,
    }
}

fn cond_targets(block: &BasicBlock) -> (Option<BlockId>, Option<BlockId>) {
    let mut cond_true: Option<BlockId> = None;
    let mut cond_false: Option<BlockId> = None;
    for edge in &block.successors {
        match edge.kind {
            EdgeKind::CondTrue => cond_true = Some(edge.target),
            EdgeKind::CondFalse => cond_false = Some(edge.target),
            _ => {}
        }
    }
    (cond_true, cond_false)
}

fn parse_idx_store_key(
    cfg: &Cfg,
    insns: &[Instruction],
    bid: BlockId,
    idx_slot: u16,
) -> Option<i32> {
    let block_insns: &[Instruction] = block_insn_slice(cfg, insns, bid);
    let store_pos: usize = block_insns
        .iter()
        .position(|ins: &Instruction| istore_slot(ins) == Some(idx_slot))?;
    small_int_push(block_insns.get(store_pos.checked_sub(1)?)?)
}

struct BucketAccum<'a> {
    idx_to_literal: &'a mut BTreeMap<i32, String>,
    bucket_blocks: &'a mut Vec<BlockId>,
}

fn walk_string_bucket(
    cf: &ClassFile,
    cfg: &Cfg,
    insns: &[Instruction],
    start: BlockId,
    idx_head: BlockId,
    selector_slot: u16,
    idx_slot: u16,
    accum: &mut BucketAccum<'_>,
) -> Option<()> {
    let mut current: BlockId = start;
    let mut guard: usize = 0;
    loop {
        guard += 1;
        if guard > MAX_BLOCKS {
            return None;
        }
        if current == idx_head {
            return Some(());
        }
        let block_insns: &[Instruction] = block_insn_slice(cfg, insns, current);
        let eq_pos: usize = block_insns
            .iter()
            .position(|ins: &Instruction| is_equals_invoke(cf, ins))?;
        if !block_insns[..eq_pos]
            .iter()
            .any(|ins: &Instruction| aload_slot(ins) == Some(selector_slot))
        {
            return None;
        }
        let literal: String = ldc_string_literal(cf, block_insns.get(eq_pos.checked_sub(1)?)?)?;
        if block_insns.last()?.opcode != 0x99 {
            return None;
        }
        let block: &BasicBlock = &cfg.blocks[current.0 as usize];
        let (cond_true, cond_false): (Option<BlockId>, Option<BlockId>) = cond_targets(block);
        let match_block: BlockId = cond_false?;
        let next: BlockId = cond_true?;
        let key: i32 = parse_idx_store_key(cfg, insns, match_block, idx_slot)?;
        accum.idx_to_literal.insert(key, literal);
        accum.bucket_blocks.push(current);
        accum.bucket_blocks.push(match_block);
        current = next;
    }
}

#[must_use]
pub fn cfg_has_string_switch(cf: &ClassFile, cfg: &Cfg, insns: &[Instruction]) -> bool {
    cfg.blocks.iter().any(|block: &BasicBlock| {
        is_switch(block, &cfg.blocks) && detect_string_switch(cf, cfg, insns, block.id).is_some()
    })
}

fn detect_string_switch(
    cf: &ClassFile,
    cfg: &Cfg,
    insns: &[Instruction],
    head_bid: BlockId,
) -> Option<StringSwitchTable> {
    let head_insns: &[Instruction] = block_insn_slice(cfg, insns, head_bid);
    let last: &Instruction = head_insns.last()?;
    let Operands::LookupSwitch { default, pairs } = &last.operands else {
        return None;
    };
    if pairs.is_empty() {
        return None;
    }
    let hc_pos: usize = head_insns
        .iter()
        .position(|ins: &Instruction| is_hashcode_invoke(cf, ins))?;
    let selector_slot: u16 = aload_slot(head_insns.get(hc_pos.checked_sub(1)?)?)?;
    let mut idx_slot: Option<u16> = None;
    let mut idx_init_pos: Option<usize> = None;
    for w in 0..head_insns.len().saturating_sub(1) {
        if head_insns[w].opcode == 0x02
            && let Some(slot) = istore_slot(&head_insns[w + 1])
        {
            idx_slot = Some(slot);
            idx_init_pos = Some(w);
            break;
        }
    }
    let idx_slot: u16 = idx_slot?;
    let idx_init_pos: usize = idx_init_pos?;
    let sel_astore_pos: usize = head_insns
        .iter()
        .position(|ins: &Instruction| astore_slot(ins) == Some(selector_slot))?;
    let source_pos: usize = sel_astore_pos.checked_sub(1)?;
    let subject_source_slot: u16 = aload_slot(head_insns.get(source_pos)?)?;
    let machinery_start: usize = idx_init_pos.min(source_pos);
    let j_pc: u32 = (i64::from(last.pc) + i64::from(*default)) as u32;
    let idx_head: BlockId = *cfg.pc_to_block.get(&j_pc)?;
    let j_insns: &[Instruction] = block_insn_slice(cfg, insns, idx_head);
    if iload_slot(j_insns.first()?) != Some(idx_slot) {
        return None;
    }
    let j_switch: &Instruction = j_insns.last()?;
    let idx_keys: Vec<i32> = match &j_switch.operands {
        Operands::TableSwitch { low, offsets, .. } => (0..offsets.len())
            .map(|i: usize| low.saturating_add(i as i32))
            .collect(),
        Operands::LookupSwitch { pairs, .. } => pairs.iter().map(|(k, _)| *k).collect(),
        _ => return None,
    };
    let mut idx_to_literal: BTreeMap<i32, String> = BTreeMap::new();
    let mut bucket_blocks: Vec<BlockId> = Vec::new();
    let mut accum: BucketAccum<'_> = BucketAccum {
        idx_to_literal: &mut idx_to_literal,
        bucket_blocks: &mut bucket_blocks,
    };
    for (_hash, off) in pairs {
        let bucket_pc: u32 = (i64::from(last.pc) + i64::from(*off)) as u32;
        let bucket_bid: BlockId = *cfg.pc_to_block.get(&bucket_pc)?;
        walk_string_bucket(
            cf,
            cfg,
            insns,
            bucket_bid,
            idx_head,
            selector_slot,
            idx_slot,
            &mut accum,
        )?;
    }
    if idx_to_literal.is_empty() {
        return None;
    }
    if !idx_keys
        .iter()
        .all(|k: &i32| idx_to_literal.contains_key(k))
    {
        return None;
    }
    Some(StringSwitchTable {
        prefix_block: head_bid,
        prefix_len: machinery_start,
        subject_source_slot,
        idx_switch_head: idx_head,
        idx_to_literal,
        bucket_blocks,
    })
}
