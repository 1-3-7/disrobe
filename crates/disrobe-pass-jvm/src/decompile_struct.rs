use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg::{Flow, FlowGraph};
use serde::{Deserialize, Serialize};

use crate::bytecode::{CodeAttribute, ExceptionEntry, Instruction, Operands, branch_target};
use crate::classfile::{ClassFile, ConstantPoolEntry};

const MAX_BLOCKS: usize = 16_384;
const MAX_STRUCTURE_DEPTH: usize = 256;
const MAX_STRUCTURE_WORK: usize = 200_000;
const MAX_JOIN_CHAIN: usize = 8;

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

#[derive(Debug, Clone)]
pub struct Dominators {
    flow: Option<FlowGraph<BlockId>>,
    pub order: Vec<BlockId>,
}

#[must_use]
pub fn compute_dominators(cfg: &Cfg) -> Dominators {
    let flow: Option<FlowGraph<BlockId>> = block_flow(cfg);
    let order: Vec<BlockId> = block_order(cfg, flow.as_ref());
    Dominators { flow, order }
}

fn block_order(cfg: &Cfg, flow: Option<&FlowGraph<BlockId>>) -> Vec<BlockId> {
    let count: usize = cfg.blocks.len();
    let Some(flow): Option<&FlowGraph<BlockId>> = flow else {
        return (0..count as u32).rev().map(BlockId).collect();
    };
    let mut order: Vec<BlockId> = (0..count as u32)
        .rev()
        .map(BlockId)
        .filter(|block: &BlockId| !flow.is_reachable(*block))
        .collect();
    order.extend(flow.reverse_postorder());
    order
}

#[must_use]
pub fn block_flow(cfg: &Cfg) -> Option<FlowGraph<BlockId>> {
    FlowGraph::build(
        (0..cfg.blocks.len() as u32).map(BlockId),
        cfg.entry,
        |node: BlockId, emit: &mut dyn FnMut(Flow<BlockId>)| {
            let Some(block): Option<&BasicBlock> = cfg.blocks.get(node.0 as usize) else {
                return;
            };
            if block.successors.is_empty() {
                emit(Flow::Exit);
            }
            for edge in &block.successors {
                emit(Flow::To(edge.target));
            }
        },
    )
    .ok()
}

#[must_use]
pub fn dominates(dom: &Dominators, ancestor: BlockId, child: BlockId) -> bool {
    dom.flow
        .as_ref()
        .is_some_and(|flow: &FlowGraph<BlockId>| flow.dominates(ancestor, child))
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
        finally_body: Box<Self>,
        finally_completes_normally: bool,
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
    finally_tail_trims: BTreeMap<BlockId, usize>,
    finally_return_stores: BTreeMap<BlockId, u16>,
    finally_exception_slots: BTreeSet<u16>,
    finally_catch_parameter_slots: BTreeSet<u16>,
    slot_use_counts: BTreeMap<u16, usize>,
    visited: BTreeSet<BlockId>,
    loop_header_of: BTreeMap<BlockId, BlockId>,
    loop_exits: BTreeMap<BlockId, BlockId>,
    try_groups: Vec<GroupedTry>,
    suppressed_spans: BTreeSet<(u32, u32)>,
    handler_stops: BTreeSet<BlockId>,
    active_finally: Vec<BlockId>,
    loop_stack: Vec<LoopFrame>,
    labels_used: BTreeSet<u32>,
    next_label: u32,
    depth: usize,
    work: usize,
    finally_body_depth: usize,
    pub had_irreducible: bool,
    unmodelled_finally: Option<&'static str>,
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
        let slot_use_counts: BTreeMap<u16, usize> = count_slot_uses(insns);
        Self {
            cf: None,
            cfg,
            dom,
            loops,
            insns,
            switch_map,
            string_switch_tables: BTreeMap::new(),
            finally_inline_skips: BTreeMap::new(),
            finally_tail_trims: BTreeMap::new(),
            finally_return_stores: BTreeMap::new(),
            finally_exception_slots: BTreeSet::new(),
            finally_catch_parameter_slots: BTreeSet::new(),
            slot_use_counts,
            visited: BTreeSet::new(),
            loop_header_of,
            loop_exits,
            try_groups,
            suppressed_spans: BTreeSet::new(),
            handler_stops: BTreeSet::new(),
            active_finally: Vec::new(),
            loop_stack: Vec::new(),
            labels_used: BTreeSet::new(),
            next_label: 0,
            depth: 0,
            work: 0,
            finally_body_depth: 0,
            had_irreducible: false,
            unmodelled_finally: None,
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
    pub fn take_finally_tail_trims(&mut self) -> BTreeMap<BlockId, usize> {
        std::mem::take(&mut self.finally_tail_trims)
    }

    #[must_use]
    pub fn take_finally_return_stores(&mut self) -> BTreeMap<BlockId, u16> {
        std::mem::take(&mut self.finally_return_stores)
    }

    #[must_use]
    pub fn take_finally_exception_slots(&mut self) -> BTreeSet<u16> {
        std::mem::take(&mut self.finally_exception_slots)
    }

    #[must_use]
    pub fn take_finally_catch_parameter_slots(&mut self) -> BTreeSet<u16> {
        std::mem::take(&mut self.finally_catch_parameter_slots)
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
            .filter(|g: &&GroupedTry| {
                g.try_start_pc == pc && !self.suppressed_spans.contains(&(pc, g.try_end_pc))
            })
            .max_by_key(|g: &&GroupedTry| g.try_end_pc)
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

    fn finally_handler_chain(&self, handler_bid: BlockId) -> Option<FinallyChain> {
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
            if let Some(last) = block_insns.last() {
                if last.opcode == 0xBF
                    && block_insns.len() >= 2
                    && aload_slot(&block_insns[block_insns.len() - 2]) == Some(slot)
                {
                    return Some(FinallyChain {
                        blocks: chain,
                        trim: 2,
                    });
                }
                if matches!(last.opcode, 0xAC..=0xB1 | 0xBF)
                    && !self.chain_reloads_slot(&chain, slot)
                    && self.slot_total_uses(slot) == 1
                {
                    return Some(FinallyChain {
                        blocks: chain,
                        trim: 0,
                    });
                }
            }
            let next: BlockId = self.next_block_by_pc(cur)?;
            if chain.contains(&next) {
                return None;
            }
            let normal_predecessors: Vec<BlockId> = self.cfg.blocks[next.0 as usize]
                .predecessors
                .iter()
                .filter(|predecessor: &&BlockId| {
                    self.cfg.blocks[predecessor.0 as usize]
                        .successors
                        .iter()
                        .any(|edge: &Edge| {
                            edge.target == next && !matches!(edge.kind, EdgeKind::Exception)
                        })
                })
                .copied()
                .collect();
            let exception_only_predecessors_admitted: bool = normal_predecessors.is_empty()
                && !self.cfg.blocks[next.0 as usize].predecessors.is_empty()
                && self.cfg.blocks[next.0 as usize]
                    .predecessors
                    .iter()
                    .all(|predecessor: &BlockId| chain.contains(predecessor));
            if !exception_only_predecessors_admitted
                && (normal_predecessors.is_empty()
                    || !normal_predecessors
                        .iter()
                        .all(|predecessor: &BlockId| chain.contains(predecessor)))
            {
                return None;
            }
            chain.push(next);
            cur = next;
        }
    }

    fn self_protecting_spans(&self, head: BlockId) -> Vec<(u32, u32)> {
        let head_pc: u32 = self.cfg.blocks[head.0 as usize].start_pc;
        self.try_groups
            .iter()
            .filter(|group: &&GroupedTry| group.try_start_pc == head_pc)
            .map(|group: &GroupedTry| (group.try_start_pc, group.try_end_pc))
            .collect()
    }

    fn next_block_by_pc(&self, current: BlockId) -> Option<BlockId> {
        let start_pc: u32 = self.cfg.blocks[current.0 as usize].start_pc;
        self.cfg
            .pc_to_block
            .range(start_pc.checked_add(1)?..)
            .next()
            .map(|(_, block): (&u32, &BlockId)| *block)
    }

    fn chain_reloads_slot(&self, chain: &[BlockId], slot: u16) -> bool {
        chain.iter().any(|&bid: &BlockId| {
            self.block_instructions(bid)
                .iter()
                .any(|ins: &Instruction| aload_slot(ins) == Some(slot))
        })
    }

    fn finally_body_span(&self, chain: &FinallyChain) -> Option<Vec<Instruction>> {
        let (&first, &last): (&BlockId, &BlockId) =
            chain.blocks.first().zip(chain.blocks.last())?;
        let mut body: Vec<Instruction> = Vec::new();
        for &bid in &chain.blocks {
            let insns: &[Instruction] = self.block_instructions(bid);
            let lo: usize = usize::from(bid == first);
            let hi: usize = if bid == last {
                insns.len().checked_sub(chain.trim)?
            } else {
                insns.len()
            };
            if lo > hi {
                return None;
            }
            body.extend_from_slice(insns.get(lo..hi)?);
        }
        Some(body)
    }

    fn pc_after_last(&self, seq: &[Instruction]) -> Option<u32> {
        let last: &Instruction = seq.last()?;
        let idx: usize = self
            .insns
            .binary_search_by_key(&last.pc, |ins: &Instruction| ins.pc)
            .ok()?;
        self.insns.get(idx + 1).map(|ins: &Instruction| ins.pc)
    }

    fn finally_copy_match(
        &mut self,
        body: &[Instruction],
        copy: &[Instruction],
    ) -> Option<FinallyCopyMatch> {
        if body.len() != copy.len() || body.is_empty() {
            return None;
        }
        let body_end: Option<u32> = self.pc_after_last(body);
        let copy_end: Option<u32> = self.pc_after_last(copy);
        let identity: FinallyCopyIndex = FinallyCopyIndex::build(
            body,
            copy,
            body_end,
            copy_end,
            &self.cfg.exception_regions,
            &mut self.work,
            MAX_STRUCTURE_WORK,
        )?;
        let mut exit_pc: Option<u32> = None;
        let mut catch_parameter_slots: BTreeSet<u16> = BTreeSet::new();
        let mut paired_catch_slots: BTreeMap<u16, u16> = BTreeMap::new();
        let mut paired_copy_slots: BTreeMap<u16, u16> = BTreeMap::new();
        for (a, b) in body.iter().zip(copy.iter()) {
            match identity.catch_store_match(a, b) {
                FinallyCatchStoreMatch::Absent => {}
                FinallyCatchStoreMatch::Matched(body_slot, copy_slot) => {
                    let uses: usize = identity.body_slot_uses(body_slot);
                    let copy_contained: bool =
                        self.slot_total_uses(copy_slot) == identity.copy_slot_uses(copy_slot);
                    if self.slot_total_uses(body_slot) != uses
                        || (uses > 1 && !copy_contained)
                        || paired_catch_slots
                            .get(&body_slot)
                            .is_some_and(|mapped: &u16| *mapped != copy_slot)
                        || paired_copy_slots
                            .get(&copy_slot)
                            .is_some_and(|mapped: &u16| *mapped != body_slot)
                    {
                        return None;
                    }
                    paired_catch_slots.insert(body_slot, copy_slot);
                    paired_copy_slots.insert(copy_slot, body_slot);
                    catch_parameter_slots.insert(body_slot);
                    if copy_contained {
                        catch_parameter_slots.insert(copy_slot);
                    }
                    continue;
                }
                FinallyCatchStoreMatch::MatchedDiscard => continue,
                FinallyCatchStoreMatch::Invalid => return None,
            }
            let reference_loads: (Option<u16>, Option<u16>) = (aload_slot(a), aload_slot(b));
            if let (Some(body_slot), Some(copy_slot)) = reference_loads
                && paired_catch_slots.get(&body_slot) == Some(&copy_slot)
            {
                continue;
            }
            if a.opcode != b.opcode {
                return None;
            }
            let (Operands::Branch(_), Operands::Branch(_)) = (&a.operands, &b.operands) else {
                if a.operands != b.operands {
                    return None;
                }
                continue;
            };
            let (Some(a_target), Some(b_target)): (Option<u32>, Option<u32>) =
                (branch_target(a), branch_target(b))
            else {
                return None;
            };
            let a_index: Option<usize> = identity.body_position(a_target);
            let b_index: Option<usize> = identity.copy_position(b_target);
            if a_index == Some(body.len()) {
                if b_index.is_some_and(|index: usize| index < copy.len())
                    || identity
                        .body_position(b_target)
                        .is_some_and(|index: usize| index < body.len())
                {
                    return None;
                }
                match exit_pc {
                    Some(previous) if previous != b_target => return None,
                    _ => exit_pc = Some(b_target),
                }
                continue;
            }
            match (a_index, b_index) {
                (Some(a_idx), Some(b_idx)) if a_idx == b_idx => {}
                (None, None) if a_target == b_target => {}
                _ => return None,
            }
        }
        Some(FinallyCopyMatch {
            exit_pc,
            catch_parameter_slots,
        })
    }

    fn finally_copy_matches(&mut self, body: &[Instruction], copy: &[Instruction]) -> bool {
        let Some(matched): Option<FinallyCopyMatch> = self.finally_copy_match(body, copy) else {
            return false;
        };
        matched.exit_pc.is_none() || matched.exit_pc == self.pc_after_last(copy)
    }

    fn finally_body_instructions(&self, chain: &FinallyChain) -> Option<Vec<Instruction>> {
        let body: Vec<Instruction> = self.finally_body_span(chain)?;
        if body.is_empty() {
            return None;
        }
        let exception_slot: u16 =
            astore_slot(self.block_instructions(*chain.blocks.first()?).first()?)?;
        let tail_return: usize = usize::from(chain.trim == 0);
        let scanned: &[Instruction] = body.get(..body.len() - tail_return)?;
        if scanned
            .iter()
            .enumerate()
            .any(|(index, ins): (usize, &Instruction)| {
                matches!(ins.opcode, 0xA8..=0xB1 | 0xC9)
                    || (ins.opcode == 0xBF
                        && index
                            .checked_sub(1)
                            .and_then(|previous: usize| scanned.get(previous))
                            .and_then(aload_slot)
                            == Some(exception_slot))
                    || (matches!(ins.opcode, 0x99..=0xA7 | 0xC6..=0xC8)
                        && branch_target(ins).is_none())
            })
        {
            return None;
        }
        Some(body)
    }

    fn finally_inline_blocks(
        &mut self,
        chain: &FinallyChain,
        start: BlockId,
    ) -> Option<(Vec<BlockId>, Option<BlockId>)> {
        let body: Vec<Instruction> = self.finally_body_instructions(chain)?;
        let mut copy: Vec<Instruction> = Vec::new();
        let mut blocks: Vec<BlockId> = Vec::new();
        let mut current: BlockId = start;
        let mut trailing_exit_pc: Option<u32> = None;
        while copy.len() < body.len() {
            if blocks.len() >= MAX_BLOCKS || blocks.contains(&current) {
                return None;
            }
            let instructions: &[Instruction] = self.block_instructions(current);
            if instructions.is_empty() {
                return None;
            }
            let remaining: usize = body.len().checked_sub(copy.len())?;
            if instructions.len() > remaining {
                let (prefix, suffix): (&[Instruction], &[Instruction]) =
                    instructions.split_at(remaining);
                let [trailing]: &[Instruction; 1] = suffix.try_into().ok()?;
                if !matches!(trailing.opcode, 0xA7 | 0xC8) {
                    return None;
                }
                trailing_exit_pc = Some(branch_target(trailing)?);
                copy.extend_from_slice(prefix);
                blocks.push(current);
                break;
            }
            copy.extend_from_slice(instructions);
            blocks.push(current);
            if copy.len() < body.len() {
                current = self.next_block_by_pc(current)?;
            }
        }
        let FinallyCopyMatch {
            exit_pc: matched_exit_pc,
            catch_parameter_slots,
        }: FinallyCopyMatch = self.finally_copy_match(&body, &copy)?;
        self.finally_catch_parameter_slots
            .extend(catch_parameter_slots);
        let exit_pc: Option<u32> = match (matched_exit_pc, trailing_exit_pc) {
            (Some(left), Some(right)) if left != right => return None,
            (Some(pc), _) | (_, Some(pc)) => Some(pc),
            (None, None) => None,
        };
        let exit: Option<BlockId> = match exit_pc {
            Some(pc) => Some(self.cfg.pc_to_block.get(&pc).copied()?),
            None => None,
        };
        Some((blocks, exit))
    }

    fn finally_nested_return_fold(
        &mut self,
        group: &GroupedTry,
        chain: &FinallyChain,
        start: BlockId,
    ) -> Option<(Vec<BlockId>, BlockId, u16)> {
        let body: Vec<Instruction> = self.finally_body_instructions(chain)?;
        let body_end: u32 = self.pc_after_last(&body)?;
        let exit_branches: Vec<&Instruction> = body
            .iter()
            .filter(|instruction: &&Instruction| {
                matches!(instruction.opcode, 0xA7 | 0xC8)
                    && branch_target(instruction) == Some(body_end)
            })
            .collect();
        let [body_exit]: [&Instruction; 1] = exit_branches.as_slice().try_into().ok()?;
        let success_return: BlockId = self.next_block_by_pc(start)?;
        let catch_block: BlockId = self.next_block_by_pc(success_return)?;
        let (slot, return_opcode): (u16, u8) =
            typed_return_slot(self.block_instructions(success_return))?;
        let catch_instructions: &[Instruction] = self.block_instructions(catch_block);
        let catch_prefix_length: usize = catch_instructions.len().checked_sub(2)?;
        let (catch_prefix, catch_return): (&[Instruction], &[Instruction]) =
            catch_instructions.split_at(catch_prefix_length);
        let (catch_slot, catch_return_opcode): (u16, u8) = typed_return_slot(catch_return)?;
        if catch_prefix.first()?.opcode != 0x57
            || catch_slot != slot
            || catch_return_opcode != return_opcode
            || self.slot_total_uses(slot) != 3
        {
            return None;
        }
        let start_block: &BasicBlock = &self.cfg.blocks[start.0 as usize];
        let normal_successors: Vec<BlockId> = start_block
            .successors
            .iter()
            .filter(|edge: &&Edge| !matches!(edge.kind, EdgeKind::Exception))
            .map(|edge: &Edge| edge.target)
            .collect();
        if normal_successors.as_slice() != [success_return]
            || self.cfg.blocks[success_return.0 as usize]
                .successors
                .iter()
                .any(|edge: &Edge| !matches!(edge.kind, EdgeKind::Exception))
            || self.cfg.blocks[catch_block.0 as usize]
                .successors
                .iter()
                .any(|edge: &Edge| !matches!(edge.kind, EdgeKind::Exception))
        {
            return None;
        }
        let start_pc: u32 = start_block.start_pc;
        let return_pc: u32 = self.cfg.blocks[success_return.0 as usize].start_pc;
        let catch_pc: u32 = self.cfg.blocks[catch_block.0 as usize].start_pc;
        if !self
            .cfg
            .exception_regions
            .iter()
            .any(|region: &ExceptionRegion| {
                region.catch_type.is_some()
                    && region.try_start_pc == start_pc
                    && region.try_end_pc == return_pc
                    && region.handler_pc == catch_pc
            })
        {
            return None;
        }
        let predecessor: BlockId = self.single_try_predecessor(group, start)?;
        if any_store_slot(self.block_instructions(predecessor).last()?) != Some(slot) {
            return None;
        }
        let copy_end: u32 = catch_return.first()?.pc;
        let synthetic_pc: u32 = self.block_instructions(success_return).first()?.pc;
        let relative_exit: i32 =
            i32::try_from(i64::from(copy_end) - i64::from(synthetic_pc)).ok()?;
        let mut synthetic_exit: Instruction = (*body_exit).clone();
        synthetic_exit.pc = synthetic_pc;
        synthetic_exit.operands = Operands::Branch(relative_exit);
        let mut copy: Vec<Instruction> = Vec::with_capacity(body.len());
        copy.extend_from_slice(self.block_instructions(start));
        copy.push(synthetic_exit);
        copy.extend_from_slice(catch_prefix);
        let FinallyCopyMatch {
            exit_pc,
            catch_parameter_slots,
        }: FinallyCopyMatch = self.finally_copy_match(&body, &copy)?;
        if exit_pc != Some(copy_end) || !catch_parameter_slots.is_empty() {
            return None;
        }
        Some((vec![start, success_return, catch_block], predecessor, slot))
    }

    fn finally_value_return_after_blocks(
        &self,
        group: &GroupedTry,
        copy_head: BlockId,
        continuation: BlockId,
    ) -> Option<(BlockId, u16)> {
        let [load, ret]: &[Instruction; 2] =
            self.block_instructions(continuation).try_into().ok()?;
        if !matches!(ret.opcode, 0xAC..=0xB0) {
            return None;
        }
        let slot: u16 = any_load_slot(load)?;
        let predecessor: BlockId = self.single_try_predecessor(group, copy_head)?;
        if any_store_slot(self.block_instructions(predecessor).last()?) != Some(slot)
            || self.slot_total_uses(slot) != 2
        {
            return None;
        }
        Some((predecessor, slot))
    }

    fn slot_total_uses(&self, slot: u16) -> usize {
        self.slot_use_counts.get(&slot).copied().unwrap_or(0)
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
        self.finally_value_return_temp_uses(group, cont, skip, 2)
    }

    fn finally_value_return_temp_uses(
        &self,
        group: &GroupedTry,
        cont: BlockId,
        skip: usize,
        expected_uses: usize,
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
        (self.slot_total_uses(slot) == expected_uses).then_some((pred, slot))
    }

    fn multi_exit_return_folds(
        &mut self,
        group: &GroupedTry,
        chain: &FinallyChain,
        exits: &[BlockId],
    ) -> Option<Vec<(BlockId, BlockId, u16)>> {
        if exits.len() < 2 {
            return None;
        }
        let expected_uses: usize = exits.len().checked_mul(2)?;
        let mut folds: Vec<(BlockId, BlockId, u16)> = Vec::with_capacity(exits.len());
        for &exit in exits {
            let skip: usize = self.finally_inline_skip(chain, exit)?;
            let (pred, slot): (BlockId, u16) =
                self.finally_value_return_temp_uses(group, exit, skip, expected_uses)?;
            if folds
                .iter()
                .any(|(_, _, s): &(BlockId, BlockId, u16)| *s != slot)
            {
                return None;
            }
            folds.push((exit, pred, slot));
        }
        Some(folds)
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

    fn try_gap_blocks(&self, group: &GroupedTry) -> Vec<BlockId> {
        if group.ranges.len() < 2 {
            return Vec::new();
        }
        self.cfg
            .blocks
            .iter()
            .filter(|b: &&BasicBlock| {
                b.start_pc >= group.try_start_pc
                    && b.start_pc < group.try_end_pc
                    && !group
                        .ranges
                        .iter()
                        .any(|(lo, hi): &(u32, u32)| b.start_pc >= *lo && b.start_pc < *hi)
            })
            .map(|b: &BasicBlock| b.id)
            .collect()
    }

    fn finally_return_copy(&mut self, chain: &FinallyChain, cont: BlockId) -> bool {
        let Some(body): Option<Vec<Instruction>> = self.finally_body_instructions(chain) else {
            return false;
        };
        let cont_insns: Vec<Instruction> = self.block_instructions(cont).to_vec();
        self.finally_copy_matches(&body, &cont_insns)
    }

    fn finally_inline_skip(&mut self, chain: &FinallyChain, cont: BlockId) -> Option<usize> {
        let body: Vec<Instruction> = self.finally_body_instructions(chain)?;
        let cont_insns: &[Instruction] = self.block_instructions(cont);
        if cont_insns.len() <= body.len() {
            return None;
        }
        let head: Vec<Instruction> = cont_insns.get(..body.len())?.to_vec();
        self.finally_copy_matches(&body, &head)
            .then_some(body.len())
    }

    fn finally_inline_prefix(&mut self, chain: &FinallyChain, cont: BlockId) -> Option<usize> {
        let body: Vec<Instruction> = self.finally_body_instructions(chain)?;
        let head: Vec<Instruction> = self.block_instructions(cont).get(..body.len())?.to_vec();
        self.finally_copy_matches(&body, &head)
            .then_some(body.len())
    }

    fn continuation_joins(&self, after_try: Option<BlockId>) -> BTreeSet<BlockId> {
        let mut joins: BTreeSet<BlockId> = BTreeSet::new();
        let mut cur: Option<BlockId> = after_try;
        while let Some(bid) = cur {
            if self.visited.contains(&bid) || !joins.insert(bid) || joins.len() > MAX_JOIN_CHAIN {
                break;
            }
            cur = follow_single_successor(&self.cfg.blocks[bid.0 as usize]);
        }
        joins
    }

    fn protected_exit_inline_sites(
        &self,
        chain: &FinallyChain,
        finally_handler: BlockId,
    ) -> Vec<BlockId> {
        let handler_pc: u32 = self.cfg.blocks[finally_handler.0 as usize].start_pc;
        let chain_blocks: BTreeSet<BlockId> = chain.blocks.iter().copied().collect();
        let mut sites: Vec<BlockId> = Vec::new();
        for region in &self.cfg.exception_regions {
            if region.catch_type.is_some() || region.handler_pc != handler_pc {
                continue;
            }
            let Some(&site): Option<&BlockId> = self.cfg.pc_to_block.get(&region.try_end_pc) else {
                continue;
            };
            if chain_blocks.contains(&site) || sites.contains(&site) {
                continue;
            }
            sites.push(site);
        }
        sites
    }

    fn unprotected_catch_inline_skip(
        &mut self,
        chain: &FinallyChain,
        finally_handler: BlockId,
        handler_bid: BlockId,
    ) -> Option<usize> {
        let handler_pc: u32 = self.cfg.blocks[finally_handler.0 as usize].start_pc;
        let catch_pc: u32 = self.cfg.blocks[handler_bid.0 as usize].start_pc;
        if self
            .cfg
            .exception_regions
            .iter()
            .any(|r: &ExceptionRegion| {
                r.catch_type.is_none() && r.handler_pc == handler_pc && r.try_start_pc == catch_pc
            })
        {
            return None;
        }
        let exc_slot: u16 = astore_slot(self.block_instructions(handler_bid).first()?)?;
        if self.slot_total_uses(exc_slot) != 1 {
            return None;
        }
        let body: Vec<Instruction> = self.finally_body_instructions(chain)?;
        let head: Vec<Instruction> = self
            .block_instructions(handler_bid)
            .get(1..=body.len())?
            .to_vec();
        self.finally_copy_matches(&body, &head)
            .then_some(body.len() + 1)
    }

    fn outer_loop_jump(&mut self, target: BlockId) -> Option<Region> {
        let reserved: usize = usize::from(self.finally_body_depth == 0);
        let visible: usize = self.loop_stack.len().checked_sub(reserved)?;
        let frames: Vec<LoopFrame> = self.loop_stack.get(..visible)?.to_vec();
        let innermost: usize = self.loop_stack.len().checked_sub(1)?;
        for (index, frame) in frames.iter().enumerate().rev() {
            let label: Option<u32> = (index != innermost).then_some(frame.label);
            if frame.exit == Some(target) {
                if let Some(used) = label {
                    self.labels_used.insert(used);
                }
                return Some(Region::Break { label });
            }
            if let Some(jump) = self.continue_jump_at(target, frame, label) {
                if let Some(used) = label {
                    self.labels_used.insert(used);
                }
                return Some(jump);
            }
        }
        None
    }

    fn continue_jump_at(
        &self,
        target: BlockId,
        frame: &LoopFrame,
        label: Option<u32>,
    ) -> Option<Region> {
        if target == frame.header {
            return Some(Region::Continue { label, latch: None });
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
        (only == Some(frame.header)).then_some(Region::Continue {
            label,
            latch: Some(target),
        })
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

    fn rethrows_stored_exception(&self, handler_bid: BlockId) -> bool {
        let Some(slot): Option<u16> = self
            .block_instructions(handler_bid)
            .first()
            .and_then(astore_slot)
        else {
            return false;
        };
        let mut seen: BTreeSet<BlockId> = BTreeSet::new();
        let mut stack: Vec<BlockId> = vec![handler_bid];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) || seen.len() > MAX_BLOCKS {
                continue;
            }
            let insns: &[Instruction] = self.block_instructions(cur);
            if insns
                .last()
                .is_some_and(|last: &Instruction| last.opcode == 0xBF)
                && insns
                    .len()
                    .checked_sub(2)
                    .and_then(|i: usize| insns.get(i))
                    .and_then(aload_slot)
                    == Some(slot)
            {
                return true;
            }
            for edge in &self.cfg.blocks[cur.0 as usize].successors {
                if !matches!(edge.kind, EdgeKind::Exception) {
                    stack.push(edge.target);
                }
            }
        }
        false
    }

    #[must_use]
    pub const fn structured_finally_defect(&self) -> Option<&'static str> {
        self.unmodelled_finally
    }

    #[must_use]
    pub fn unmodelled_finally_reason(&self) -> Option<&'static str> {
        for group in &self.try_groups {
            for (catch_type, handler_pc) in &group.handlers {
                if catch_type.is_some() {
                    continue;
                }
                let Some(&handler_bid): Option<&BlockId> = self.cfg.pc_to_block.get(handler_pc)
                else {
                    continue;
                };
                if self.try_with_resources_slot(handler_bid).is_some() {
                    continue;
                }
                match self.finally_handler_chain(handler_bid) {
                    Some(chain) => {
                        let empty_finally: bool = self
                            .finally_body_span(&chain)
                            .is_some_and(|body: Vec<Instruction>| body.is_empty());
                        if !empty_finally && self.finally_body_instructions(&chain).is_none() {
                            return Some(
                                "a finally body with internal control flow cannot be folded back \
                                 out of every exit path",
                            );
                        }
                    }
                    None => {
                        if self.rethrows_stored_exception(handler_bid) {
                            return Some(
                                "a compiler-inserted finally handler with internal control flow \
                                 has no source form this structurer can build",
                            );
                        }
                    }
                }
            }
        }
        None
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
            if Some(b) == stop || self.handler_stops.contains(&b) {
                break;
            }
            if let Some(jump) = self.outer_loop_jump(b) {
                seq.push(jump);
                break;
            }
            if self.visited.contains(&b) {
                break;
            }

            if let Some(try_group) = self.try_group_at_block(b) {
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
                let unchained_finally: bool = handler_block_ids.iter().any(
                    |(catch_type, bid): &(Option<String>, BlockId)| {
                        catch_type.is_none() && !self.is_finally_handler(*bid)
                    },
                );
                if unchained_finally {
                    self.unmodelled_finally.get_or_insert(
                        "a compiler-inserted finally handler forms no foldable chain, so its body \
                         cannot be recovered without changing what the method does with a pending \
                         exception",
                    );
                }
                let finally_chain: Option<FinallyChain> =
                    finally_handler.and_then(|bid| self.finally_handler_chain(bid));
                if let Some(chain) = finally_chain.as_ref() {
                    self.visited.extend(chain.blocks.iter().copied());
                }
                let redundant_finally: bool = finally_handler
                    .is_some_and(|h| self.active_finally.contains(&h))
                    && handler_block_ids
                        .iter()
                        .all(|(_, bid)| Some(*bid) == finally_handler);
                if redundant_finally {
                    let span: (u32, u32) = (try_group.try_start_pc, try_group.try_end_pc);
                    let fresh_span: bool = self.suppressed_spans.insert(span);
                    let body_region: Region = self.structure_at(b, try_end_block);
                    if fresh_span {
                        self.suppressed_spans.remove(&span);
                    }
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
                let span: (u32, u32) = (try_group.try_start_pc, try_group.try_end_pc);
                let fresh_span: bool = self.suppressed_spans.insert(span);
                let pushed_finally: bool = if let Some(h) = finally_handler {
                    self.active_finally.push(h);
                    true
                } else {
                    false
                };
                let mut body_region: Region = self.structure_at(b, try_end_block);
                if fresh_span {
                    self.suppressed_spans.remove(&span);
                }
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
                let joins: BTreeSet<BlockId> = self.continuation_joins(after_try);
                let prev_handler_stops: BTreeSet<BlockId> =
                    std::mem::replace(&mut self.handler_stops, joins);
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
                self.handler_stops = prev_handler_stops;
                if pushed_finally {
                    self.active_finally.pop();
                }
                if let Some(chain) = finally_chain {
                    if handlers_out.is_empty()
                        && let Some((lock_block, lock_slot)) = self.synchronized_lock_block(b)
                        && self.is_synchronized_finally(&chain.blocks, lock_slot)
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
                    let gap_exits: Vec<BlockId> = self.try_gap_blocks(&try_group);
                    let all_exits: Vec<BlockId> =
                        gap_exits.iter().copied().chain(after_try).collect();
                    let has_internal_control_flow: bool = self
                        .finally_body_instructions(&chain)
                        .is_some_and(|body: Vec<Instruction>| {
                            body.iter().any(|instruction: &Instruction| {
                                matches!(instruction.opcode, 0x99..=0xA7 | 0xC6..=0xC8)
                            })
                        });
                    let multi_folds: Option<Vec<(BlockId, BlockId, u16)>> =
                        self.multi_exit_return_folds(&try_group, &chain, &all_exits);
                    if let Some(folds) = multi_folds {
                        for (exit, pred, slot) in folds {
                            self.finally_return_stores.insert(pred, slot);
                            self.finally_inline_skips
                                .insert(exit, self.block_instructions(exit).len());
                            self.visited.insert(exit);
                        }
                        after_try = None;
                    } else {
                        for gap in &gap_exits {
                            if let Some(skip) = self.finally_inline_skip(&chain, *gap) {
                                self.finally_inline_skips.insert(*gap, skip);
                            }
                        }
                        if has_internal_control_flow && let Some(copy_head) = after_try {
                            if let Some((blocks, predecessor, slot)) =
                                self.finally_nested_return_fold(&try_group, &chain, copy_head)
                            {
                                for block in blocks {
                                    self.finally_inline_skips
                                        .insert(block, self.block_instructions(block).len());
                                    self.visited.insert(block);
                                }
                                self.finally_return_stores.insert(predecessor, slot);
                                after_try = None;
                            } else {
                                match self.finally_inline_blocks(&chain, copy_head) {
                                    Some((blocks, exit)) if blocks.len() > 1 => {
                                        let continuation: Option<BlockId> = exit.or_else(|| {
                                            blocks.last().and_then(|last: &BlockId| {
                                                self.next_block_by_pc(*last)
                                            })
                                        });
                                        for block in blocks {
                                            self.finally_inline_skips.insert(
                                                block,
                                                self.block_instructions(block).len(),
                                            );
                                            self.visited.insert(block);
                                        }
                                        if let Some(continuation) = continuation
                                            && let Some((predecessor, slot)) = self
                                                .finally_value_return_after_blocks(
                                                    &try_group,
                                                    copy_head,
                                                    continuation,
                                                )
                                        {
                                            self.finally_return_stores.insert(predecessor, slot);
                                            self.visited.insert(continuation);
                                            after_try = None;
                                        } else {
                                            after_try = continuation;
                                        }
                                    }
                                    _ => {
                                        self.unmodelled_finally.get_or_insert(
                                        "a finally body with internal control flow was not folded \
                                         out of every exit path",
                                    );
                                    }
                                }
                            }
                        }
                    }
                    let expected_exc_uses: usize = if chain.trim == 0 { 1 } else { 2 };
                    if handlers_out.is_empty()
                        && let Some(&first) = chain.blocks.first()
                        && let Some(entry) = self.block_instructions(first).first()
                        && let Some(exc_slot) = astore_slot(entry)
                        && self.slot_total_uses(exc_slot) == expected_exc_uses
                    {
                        self.finally_exception_slots.insert(exc_slot);
                    }
                    if chain.trim == 0
                        && let Some(cont) = after_try
                        && self.finally_return_copy(&chain, cont)
                        && !self.visited.contains(&cont)
                    {
                        self.visited.insert(cont);
                        after_try = None;
                    } else if let Some(cont) = after_try
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
                    if let Some(handler) = finally_handler {
                        let protected_sites: Vec<BlockId> =
                            self.protected_exit_inline_sites(&chain, handler);
                        for site in &protected_sites {
                            if self.finally_inline_skips.contains_key(site) {
                                continue;
                            }
                            if let Some(skip) = self.finally_inline_prefix(&chain, *site) {
                                self.finally_inline_skips.insert(*site, skip);
                            }
                        }
                        for &catch_bid in &handler_set {
                            if self.finally_inline_skips.contains_key(&catch_bid) {
                                continue;
                            }
                            if let Some(skip) =
                                self.unprotected_catch_inline_skip(&chain, handler, catch_bid)
                            {
                                self.finally_inline_skips.insert(catch_bid, skip);
                            }
                        }
                        let partial_copy: bool = has_internal_control_flow
                            && (gap_exits.iter().any(|site: &BlockId| {
                                !self.finally_inline_skips.contains_key(site)
                                    && !self.visited.contains(site)
                            }) || protected_sites.iter().any(|site: &BlockId| {
                                !self.finally_inline_skips.contains_key(site)
                                    && !self.visited.contains(site)
                            }) || handler_set.iter().any(|site: &BlockId| {
                                !self.finally_inline_skips.contains_key(site)
                                    && !self.visited.contains(site)
                            }));
                        if partial_copy {
                            self.unmodelled_finally.get_or_insert(
                                "a finally body with internal control flow was only partly folded \
                                 out of its exit paths",
                            );
                        }
                    }
                    if chain.trim == 0 && after_try.is_some() {
                        self.unmodelled_finally.get_or_insert(
                            "a finally that returns still leaves a reachable continuation, so the \
                             recovered try would run code the class cannot reach",
                        );
                    }
                    if let Some(&head) = chain.blocks.first() {
                        self.finally_inline_skips.entry(head).or_insert(1);
                    }
                    if let Some(&tail) = chain.blocks.last()
                        && chain.trim > 0
                    {
                        self.finally_tail_trims.insert(tail, chain.trim);
                    }
                    let finally_body: Region =
                        match (chain.blocks.first().copied(), chain.blocks.last().copied()) {
                            (Some(head), Some(tail))
                                if head != tail && has_internal_control_flow =>
                            {
                                for block in &chain.blocks {
                                    self.visited.remove(block);
                                }
                                let candidates: Vec<(u32, u32)> = self.self_protecting_spans(head);
                                let mut reentrant: Vec<(u32, u32)> =
                                    Vec::with_capacity(candidates.len());
                                for span in candidates {
                                    if self.suppressed_spans.insert(span) {
                                        reentrant.push(span);
                                    }
                                }
                                self.finally_body_depth += 1;
                                let body: Region = self.structure_at(head, Some(tail));
                                self.finally_body_depth -= 1;
                                for span in &reentrant {
                                    self.suppressed_spans.remove(span);
                                }
                                self.visited.insert(tail);
                                body
                            }
                            (Some(_), Some(_)) => {
                                for block in &chain.blocks {
                                    self.visited.insert(*block);
                                }
                                Region::Sequence(
                                    chain.blocks.iter().copied().map(Region::Block).collect(),
                                )
                            }
                            _ => Region::Sequence(Vec::new()),
                        };
                    seq.push(Region::TryFinally {
                        try_body: Box::new(body_region),
                        handlers: handlers_out,
                        finally_completes_normally: chain.trim == 2,
                        finally_body: Box::new(finally_body),
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
            finally_tail_trims: BTreeMap::new(),
            finally_return_stores: BTreeMap::new(),
            finally_exception_slots: BTreeSet::new(),
            finally_catch_parameter_slots: BTreeSet::new(),
            slot_use_counts: self.slot_use_counts.clone(),
            visited: BTreeSet::new(),
            loop_header_of: self.loop_header_of.clone(),
            loop_exits: self.loop_exits.clone(),
            try_groups: self.try_groups.clone(),
            suppressed_spans: self.suppressed_spans.clone(),
            handler_stops: self.handler_stops.clone(),
            active_finally: self.active_finally.clone(),
            loop_stack,
            labels_used: BTreeSet::new(),
            next_label: self.next_label,
            depth: self.depth,
            work: self.work,
            finally_body_depth: 0,
            had_irreducible: false,
            unmodelled_finally: None,
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
        self.unmodelled_finally = self.unmodelled_finally.or(inner.unmodelled_finally);
        self.string_switch_tables
            .extend(inner.take_string_switch_tables());
        self.finally_inline_skips
            .extend(inner.take_finally_inline_skips());
        self.finally_tail_trims
            .extend(inner.take_finally_tail_trims());
        self.finally_return_stores
            .extend(inner.take_finally_return_stores());
        self.finally_exception_slots
            .extend(inner.take_finally_exception_slots());
        self.finally_catch_parameter_slots
            .extend(inner.take_finally_catch_parameter_slots());
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
    let normal: Vec<&Edge> = block
        .successors
        .iter()
        .filter(|e: &&Edge| !matches!(e.kind, EdgeKind::Exception))
        .collect();
    normal.len() == 2
        && normal
            .iter()
            .any(|e: &&Edge| matches!(e.kind, EdgeKind::CondTrue))
        && normal
            .iter()
            .any(|e: &&Edge| matches!(e.kind, EdgeKind::CondFalse))
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

fn typed_return_slot(instructions: &[Instruction]) -> Option<(u16, u8)> {
    let [load, returned]: &[Instruction; 2] = instructions.try_into().ok()?;
    let compatible: bool = matches!(
        (load.opcode, returned.opcode),
        (0x15 | 0x1A..=0x1D, 0xAC)
            | (0x16 | 0x1E..=0x21, 0xAD)
            | (0x17 | 0x22..=0x25, 0xAE)
            | (0x18 | 0x26..=0x29, 0xAF)
            | (0x19 | 0x2A..=0x2D, 0xB0)
    );
    if !compatible {
        return None;
    }
    Some((any_load_slot(load)?, returned.opcode))
}

fn count_slot_uses(insns: &[Instruction]) -> BTreeMap<u16, usize> {
    let mut counts: BTreeMap<u16, usize> = BTreeMap::new();
    for instruction in insns {
        if let Some(slot) = any_load_slot(instruction).or_else(|| any_store_slot(instruction)) {
            let count: &mut usize = counts.entry(slot).or_default();
            *count = count.saturating_add(1);
        }
    }
    counts
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
    let handler_pcs: BTreeSet<u32> = cfg
        .exception_regions
        .iter()
        .map(|r: &ExceptionRegion| r.handler_pc)
        .collect();
    let mut out: Vec<GroupedTry> = Vec::with_capacity(by_try.len());
    for ((start, end), regions) in by_try {
        let handlers: Vec<(Option<String>, u32)> = regions
            .iter()
            .map(|r| (r.catch_type.clone(), r.handler_pc))
            .collect();
        let starts_a_handler_body: bool = handler_pcs.contains(&start);
        match out
            .iter_mut()
            .find(|g: &&mut GroupedTry| g.handlers == handlers)
            .filter(|_: &&mut GroupedTry| !starts_a_handler_body)
            .filter(|g: &&mut GroupedTry| mergeable_try_span(g, end, &handlers))
        {
            Some(existing) => {
                existing.try_end_pc = end;
                existing.ranges.push((start, end));
            }
            None => out.push(GroupedTry {
                try_start_pc: start,
                try_end_pc: end,
                handlers,
                ranges: vec![(start, end)],
            }),
        }
    }
    out
}

fn mergeable_try_span(group: &GroupedTry, end: u32, handlers: &[(Option<String>, u32)]) -> bool {
    end > group.try_start_pc
        && handlers
            .iter()
            .all(|(_, hpc): &(Option<String>, u32)| *hpc < group.try_start_pc || *hpc >= end)
}

#[derive(Debug)]
struct TwrResult {
    region: Region,
    after: Option<BlockId>,
}

#[derive(Debug, Clone)]
struct FinallyChain {
    blocks: Vec<BlockId>,
    trim: usize,
}

#[derive(Debug, Clone)]
struct FinallyCopyMatch {
    exit_pc: Option<u32>,
    catch_parameter_slots: BTreeSet<u16>,
}

type FinallyHandlerShape = BTreeSet<(String, usize, usize)>;
type FinallyHandlerShapes = BTreeMap<u32, Option<FinallyHandlerShape>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinallyCatchStoreMatch {
    Absent,
    Matched(u16, u16),
    MatchedDiscard,
    Invalid,
}

#[derive(Debug)]
struct FinallyCopyIndex {
    body_positions: BTreeMap<u32, usize>,
    copy_positions: BTreeMap<u32, usize>,
    body_slot_uses: BTreeMap<u16, usize>,
    copy_slot_uses: BTreeMap<u16, usize>,
    body_handlers: FinallyHandlerShapes,
    copy_handlers: FinallyHandlerShapes,
}

impl FinallyCopyIndex {
    fn build(
        body: &[Instruction],
        copy: &[Instruction],
        body_end: Option<u32>,
        copy_end: Option<u32>,
        exception_regions: &[ExceptionRegion],
        work: &mut usize,
        work_budget: usize,
    ) -> Option<Self> {
        let (body_positions, body_slot_uses): (BTreeMap<u32, usize>, BTreeMap<u16, usize>) =
            Self::positions(body, body_end, work, work_budget)?;
        let (copy_positions, copy_slot_uses): (BTreeMap<u32, usize>, BTreeMap<u16, usize>) =
            Self::positions(copy, copy_end, work, work_budget)?;
        let mut body_handlers: FinallyHandlerShapes = BTreeMap::new();
        let mut copy_handlers: FinallyHandlerShapes = BTreeMap::new();
        for region in exception_regions {
            Self::claim_work(work, work_budget)?;
            let Some(catch_type): Option<&String> = region.catch_type.as_ref() else {
                continue;
            };
            Self::record_handler(&body_positions, &mut body_handlers, region, catch_type);
            Self::record_handler(&copy_positions, &mut copy_handlers, region, catch_type);
        }
        Some(Self {
            body_positions,
            copy_positions,
            body_slot_uses,
            copy_slot_uses,
            body_handlers,
            copy_handlers,
        })
    }

    fn positions(
        sequence: &[Instruction],
        end: Option<u32>,
        work: &mut usize,
        work_budget: usize,
    ) -> Option<(BTreeMap<u32, usize>, BTreeMap<u16, usize>)> {
        let mut positions: BTreeMap<u32, usize> = BTreeMap::new();
        let mut slot_uses: BTreeMap<u16, usize> = BTreeMap::new();
        for (index, instruction) in sequence.iter().enumerate() {
            Self::claim_work(work, work_budget)?;
            if positions.insert(instruction.pc, index).is_some() {
                return None;
            }
            if let Some(slot) = any_load_slot(instruction).or_else(|| any_store_slot(instruction)) {
                let uses: &mut usize = slot_uses.entry(slot).or_default();
                *uses = uses.checked_add(1)?;
            }
        }
        if let Some(end_pc) = end
            && positions.insert(end_pc, sequence.len()).is_some()
        {
            return None;
        }
        Some((positions, slot_uses))
    }

    fn claim_work(work: &mut usize, work_budget: usize) -> Option<()> {
        *work = work.checked_add(1)?;
        (*work <= work_budget).then_some(())
    }

    fn record_handler(
        positions: &BTreeMap<u32, usize>,
        handlers: &mut FinallyHandlerShapes,
        region: &ExceptionRegion,
        catch_type: &str,
    ) {
        if !positions.contains_key(&region.handler_pc) {
            return;
        }
        let shape: &mut Option<FinallyHandlerShape> = handlers
            .entry(region.handler_pc)
            .or_insert_with(|| Some(BTreeSet::new()));
        let (Some(start), Some(end)): (Option<usize>, Option<usize>) = (
            positions.get(&region.try_start_pc).copied(),
            positions.get(&region.try_end_pc).copied(),
        ) else {
            *shape = None;
            return;
        };
        if let Some(entries) = shape {
            entries.insert((catch_type.to_string(), start, end));
        }
    }

    fn body_position(&self, pc: u32) -> Option<usize> {
        self.body_positions.get(&pc).copied()
    }

    fn copy_position(&self, pc: u32) -> Option<usize> {
        self.copy_positions.get(&pc).copied()
    }

    fn body_slot_uses(&self, slot: u16) -> usize {
        self.body_slot_uses.get(&slot).copied().unwrap_or(0)
    }

    fn copy_slot_uses(&self, slot: u16) -> usize {
        self.copy_slot_uses.get(&slot).copied().unwrap_or(0)
    }

    fn catch_store_match(&self, body: &Instruction, copy: &Instruction) -> FinallyCatchStoreMatch {
        match (
            self.body_handlers.get(&body.pc),
            self.copy_handlers.get(&copy.pc),
        ) {
            (None, None) => FinallyCatchStoreMatch::Absent,
            (Some(Some(body_shape)), Some(Some(copy_shape)))
                if !body_shape.is_empty() && body_shape == copy_shape =>
            {
                if body.opcode == 0x57 && copy.opcode == 0x57 {
                    return FinallyCatchStoreMatch::MatchedDiscard;
                }
                let (Some(body_slot), Some(copy_slot)): (Option<u16>, Option<u16>) =
                    (astore_slot(body), astore_slot(copy))
                else {
                    return FinallyCatchStoreMatch::Invalid;
                };
                let body_uses: usize = self.body_slot_uses(body_slot);
                if body_uses >= 1 && body_uses == self.copy_slot_uses(copy_slot) {
                    FinallyCatchStoreMatch::Matched(body_slot, copy_slot)
                } else {
                    FinallyCatchStoreMatch::Invalid
                }
            }
            _ => FinallyCatchStoreMatch::Invalid,
        }
    }
}

#[cfg(test)]
mod finally_copy_index_tests {
    use super::*;

    fn instruction(pc: u32) -> Instruction {
        Instruction {
            pc,
            opcode: 0,
            mnemonic: "nop",
            wide: false,
            operands: Operands::None,
        }
    }

    fn astore(pc: u32, slot: u16) -> Instruction {
        Instruction {
            pc,
            opcode: 0x3A,
            mnemonic: "astore",
            wide: false,
            operands: Operands::Local(slot),
        }
    }

    fn pop(pc: u32) -> Instruction {
        Instruction {
            pc,
            opcode: 0x57,
            mnemonic: "pop",
            wide: false,
            operands: Operands::None,
        }
    }

    #[test]
    fn identity_preprocessing_debits_each_instruction_and_region_once() {
        let body: Vec<Instruction> = vec![instruction(10), instruction(20), astore(30, 1)];
        let copy: Vec<Instruction> = vec![instruction(110), instruction(120), astore(130, 2)];
        let regions: Vec<ExceptionRegion> = [
            (10, 20, 30, "A"),
            (10, 20, 30, "B"),
            (110, 120, 130, "A"),
            (110, 120, 130, "B"),
        ]
        .into_iter()
        .map(
            |(try_start_pc, try_end_pc, handler_pc, catch_type): (u32, u32, u32, &str)| {
                ExceptionRegion {
                    try_start_pc,
                    try_end_pc,
                    handler_pc,
                    catch_type: Some(catch_type.to_string()),
                }
            },
        )
        .collect();
        let exact_work: usize = body.len() + copy.len() + regions.len();
        let work_budget: usize = exact_work * 2;
        let mut work: usize = 0;
        let index: Option<FinallyCopyIndex> = FinallyCopyIndex::build(
            &body,
            &copy,
            Some(40),
            Some(140),
            &regions,
            &mut work,
            work_budget,
        );
        assert!(
            index.as_ref().is_some_and(|value: &FinallyCopyIndex| {
                value.catch_store_match(&body[2], &copy[2]) == FinallyCatchStoreMatch::Matched(1, 2)
            }),
            "one debit per input"
        );
        assert_eq!(work, exact_work);
        assert!(
            FinallyCopyIndex::build(
                &body,
                &copy,
                Some(40),
                Some(140),
                &regions,
                &mut work,
                work_budget,
            )
            .is_some(),
            "the second comparison fits the shared budget"
        );
        assert_eq!(work, work_budget);
        assert!(
            FinallyCopyIndex::build(
                &body,
                &copy,
                Some(40),
                Some(140),
                &regions,
                &mut work,
                work_budget,
            )
            .is_none(),
            "the third comparison must exhaust the shared budget"
        );
        assert_eq!(work, work_budget + 1);
    }

    #[test]
    fn typed_catch_stores_cannot_bypass_descriptor_or_slot_use_validation()
    -> Result<(), &'static str> {
        let body: Vec<Instruction> = vec![instruction(10), astore(20, 1)];
        let copy: Vec<Instruction> = vec![instruction(110), astore(120, 1)];
        let regions: Vec<ExceptionRegion> = vec![
            ExceptionRegion {
                try_start_pc: 10,
                try_end_pc: 20,
                handler_pc: 20,
                catch_type: Some("A".to_owned()),
            },
            ExceptionRegion {
                try_start_pc: 110,
                try_end_pc: 120,
                handler_pc: 120,
                catch_type: Some("A".to_owned()),
            },
        ];
        let mut work: usize = 0;
        let mut index: FinallyCopyIndex = FinallyCopyIndex::build(
            &body,
            &copy,
            Some(30),
            Some(130),
            &regions,
            &mut work,
            MAX_STRUCTURE_WORK,
        )
        .ok_or("bounded typed handlers must build")?;
        assert_eq!(
            index.catch_store_match(&body[1], &copy[1]),
            FinallyCatchStoreMatch::Matched(1, 1)
        );
        {
            let shape: &mut FinallyHandlerShape = index
                .copy_handlers
                .get_mut(&120)
                .and_then(Option::as_mut)
                .ok_or("copy handler shape must exist")?;
            shape.insert(("B".to_owned(), 0, 1));
        }
        assert_eq!(
            index.catch_store_match(&body[1], &copy[1]),
            FinallyCatchStoreMatch::Invalid
        );
        {
            let shape: &mut FinallyHandlerShape = index
                .copy_handlers
                .get_mut(&120)
                .and_then(Option::as_mut)
                .ok_or("copy handler shape must exist")?;
            assert!(shape.remove(&("B".to_owned(), 0, 1)));
        }
        index.copy_slot_uses.insert(1, 2);
        assert_eq!(
            index.catch_store_match(&body[1], &copy[1]),
            FinallyCatchStoreMatch::Invalid
        );
        Ok(())
    }

    #[test]
    fn typed_catch_discards_match_only_when_both_copies_discard() -> Result<(), &'static str> {
        let body: Vec<Instruction> = vec![instruction(10), pop(20)];
        let copy: Vec<Instruction> = vec![instruction(110), pop(120)];
        let regions: Vec<ExceptionRegion> = vec![
            ExceptionRegion {
                try_start_pc: 10,
                try_end_pc: 20,
                handler_pc: 20,
                catch_type: Some("A".to_owned()),
            },
            ExceptionRegion {
                try_start_pc: 110,
                try_end_pc: 120,
                handler_pc: 120,
                catch_type: Some("A".to_owned()),
            },
        ];
        let mut work: usize = 0;
        let index: FinallyCopyIndex = FinallyCopyIndex::build(
            &body,
            &copy,
            Some(30),
            Some(130),
            &regions,
            &mut work,
            MAX_STRUCTURE_WORK,
        )
        .ok_or("typed discard handlers must build")?;
        assert_eq!(
            index.catch_store_match(&body[1], &copy[1]),
            FinallyCatchStoreMatch::MatchedDiscard
        );
        assert_eq!(
            index.catch_store_match(&body[1], &astore(120, 1)),
            FinallyCatchStoreMatch::Invalid
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GroupedTry {
    pub try_start_pc: u32,
    pub try_end_pc: u32,
    pub handlers: Vec<(Option<String>, u32)>,
    pub ranges: Vec<(u32, u32)>,
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
