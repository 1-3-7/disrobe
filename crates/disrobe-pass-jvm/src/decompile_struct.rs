use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::bytecode::{CodeAttribute, ExceptionEntry, Instruction, Operands, branch_target};

const MAX_BLOCKS: usize = 16_384;
const MAX_DOM_ITERATIONS: usize = 256;
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
    #[error("dominator computation did not converge")]
    DominatorFixpointFailure,
    #[error("structuring recursion depth exceeded")]
    StructuringDepthExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dominators {
    pub idom: Vec<Option<BlockId>>,
    pub order: Vec<BlockId>,
}

pub fn compute_dominators(cfg: &Cfg) -> Result<Dominators, StructureError> {
    let n: usize = cfg.blocks.len();
    let order: Vec<BlockId> = reverse_postorder(cfg);
    let rpo_index: BTreeMap<BlockId, usize> =
        order.iter().enumerate().map(|(i, b)| (*b, i)).collect();
    let mut idom: Vec<Option<usize>> = vec![None; n];
    let entry_idx: usize = cfg.entry.0 as usize;
    idom[entry_idx] = Some(entry_idx);

    let mut changed: bool = true;
    let mut iters: usize = 0;
    while changed {
        changed = false;
        iters += 1;
        if iters > MAX_DOM_ITERATIONS {
            return Err(StructureError::DominatorFixpointFailure);
        }
        for &b in &order {
            let bi: usize = b.0 as usize;
            if bi == entry_idx {
                continue;
            }
            let preds: &[BlockId] = &cfg.blocks[bi].predecessors;
            let mut new_idom: Option<usize> = None;
            for &p in preds {
                let pi: usize = p.0 as usize;
                if idom[pi].is_some() {
                    new_idom = Some(match new_idom {
                        None => pi,
                        Some(cur) => intersect(cur, pi, &idom, &rpo_index, cfg),
                    });
                }
            }
            if new_idom.is_some() && new_idom != idom[bi] {
                idom[bi] = new_idom;
                changed = true;
            }
        }
    }

    Ok(Dominators {
        idom: idom
            .into_iter()
            .map(|o| o.map(|i| BlockId(i as u32)))
            .collect(),
        order,
    })
}

fn intersect(
    mut b1: usize,
    mut b2: usize,
    idom: &[Option<usize>],
    rpo: &BTreeMap<BlockId, usize>,
    cfg: &Cfg,
) -> usize {
    while b1 != b2 {
        while rpo.get(&cfg.blocks[b1].id).copied().unwrap_or(usize::MAX)
            > rpo.get(&cfg.blocks[b2].id).copied().unwrap_or(usize::MAX)
        {
            b1 = match idom[b1] {
                Some(x) => x,
                None => return b1,
            };
        }
        while rpo.get(&cfg.blocks[b2].id).copied().unwrap_or(usize::MAX)
            > rpo.get(&cfg.blocks[b1].id).copied().unwrap_or(usize::MAX)
        {
            b2 = match idom[b2] {
                Some(x) => x,
                None => return b2,
            };
        }
    }
    b1
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

pub fn find_natural_loops(cfg: &Cfg, dom: &Dominators) -> Vec<NaturalLoop> {
    let mut by_header: BTreeMap<BlockId, NaturalLoop> = BTreeMap::new();
    for block in &cfg.blocks {
        for edge in &block.successors {
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
        handlers: Vec<(Option<String>, Self)>,
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

#[derive(Debug)]
pub struct Structurer<'a> {
    cfg: &'a Cfg,
    dom: &'a Dominators,
    loops: &'a [NaturalLoop],
    insns: &'a [Instruction],
    visited: BTreeSet<BlockId>,
    loop_header_of: BTreeMap<BlockId, BlockId>,
    loop_exits: BTreeMap<BlockId, BlockId>,
    try_groups: Vec<GroupedTry>,
    depth: usize,
    work: usize,
    pub had_irreducible: bool,
}

impl<'a> Structurer<'a> {
    pub fn new(
        cfg: &'a Cfg,
        dom: &'a Dominators,
        loops: &'a [NaturalLoop],
        insns: &'a [Instruction],
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
            cfg,
            dom,
            loops,
            insns,
            visited: BTreeSet::new(),
            loop_header_of,
            loop_exits,
            try_groups,
            depth: 0,
            work: 0,
            had_irreducible: false,
        }
    }

    pub fn structure(&mut self) -> Region {
        let entry: BlockId = self.cfg.entry;
        self.structure_at(entry, None)
    }

    pub fn try_group_at_block(&self, bid: BlockId) -> Option<GroupedTry> {
        let pc: u32 = self.cfg.blocks[bid.0 as usize].start_pc;
        self.try_groups
            .iter()
            .find(|g| g.try_start_pc == pc)
            .cloned()
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
            if self.visited.contains(&b) {
                break;
            }

            if let Some(try_group) = self.try_group_at_block(b) {
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
                let body_region: Region = self.structure_at(b, try_end_block);
                let mut handlers_out: Vec<(Option<String>, Region)> = Vec::new();
                let after_try: Option<BlockId> = try_end_block;
                for (catch_type, handler_bid) in handler_block_ids {
                    if self.visited.contains(&handler_bid) {
                        continue;
                    }
                    let handler_region: Region = self.structure_at(handler_bid, after_try);
                    handlers_out.push((catch_type, handler_region));
                }
                seq.push(Region::Try {
                    try_body: Box::new(body_region),
                    handlers: handlers_out,
                });
                cur = after_try;
                continue;
            }

            self.visited.insert(b);

            if let Some(loop_info) = self.loops.iter().find(|l| l.header == b) {
                let exit: Option<BlockId> = self.loop_exits.get(&b).copied();
                let body_region: Region = self.structure_loop_body(loop_info, exit);
                let header_kind: LoopKind = classify_loop_header(self.cfg, loop_info);
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
                seq.push(header_region);
                cur = exit;
                continue;
            }

            let block: &BasicBlock = &self.cfg.blocks[b.0 as usize];
            if is_switch(block, &self.cfg.blocks) {
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

    fn structure_loop_body(&mut self, loop_info: &NaturalLoop, exit: Option<BlockId>) -> Region {
        let mut inner: Structurer<'_> = Structurer {
            cfg: self.cfg,
            dom: self.dom,
            loops: self.loops,
            insns: self.insns,
            visited: BTreeSet::new(),
            loop_header_of: self.loop_header_of.clone(),
            loop_exits: self.loop_exits.clone(),
            try_groups: self.try_groups.clone(),
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
        self.had_irreducible |= inner.had_irreducible;
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
    let header_succs: &[Edge] = &header_block.successors;
    if header_succs.len() == 2 {
        let exits: usize = header_succs
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

fn follow_single_successor(block: &BasicBlock) -> Option<BlockId> {
    if block.successors.len() == 1 {
        let edge: &Edge = &block.successors[0];
        if !matches!(edge.kind, EdgeKind::Exception) {
            return Some(edge.target);
        }
    }
    None
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

pub fn exception_handler_blocks(cfg: &Cfg) -> BTreeSet<BlockId> {
    let mut out: BTreeSet<BlockId> = BTreeSet::new();
    for region in &cfg.exception_regions {
        if let Some(&bid) = cfg.pc_to_block.get(&region.handler_pc) {
            out.insert(bid);
        }
    }
    out
}

pub fn try_region_blocks(cfg: &Cfg, region: &ExceptionRegion) -> Vec<BlockId> {
    let mut out: Vec<BlockId> = Vec::new();
    for (&pc, &bid) in &cfg.pc_to_block {
        if pc >= region.try_start_pc && pc < region.try_end_pc {
            out.push(bid);
        }
    }
    out
}

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
