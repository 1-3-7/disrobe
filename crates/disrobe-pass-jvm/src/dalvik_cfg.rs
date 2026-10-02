use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::{
    DalvikInsn, SwitchPayload, decode_method, parse_packed_switch, parse_sparse_switch,
};
use crate::decompile_struct::{
    BasicBlock, BlockId, Cfg, Edge, EdgeKind, ExceptionRegion, PrecomputedSwitch, StructureError,
    SwitchKey,
};
use crate::dex::{CodeItem, TryItem};

const MAX_DALVIK_BLOCKS: usize = 16_384;

const MAX_FLOW_WORDS: usize = 1 << 22;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RegisterAccess {
    pub(crate) uses: Vec<u16>,
    pub(crate) defs: Vec<u16>,
    pub(crate) throws: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegisterSet {
    words: Vec<u64>,
}

impl RegisterSet {
    pub(crate) fn empty(registers: u16) -> Self {
        Self {
            words: vec![0; usize::from(registers).div_ceil(64)],
        }
    }

    pub(crate) fn contains(&self, register: u16) -> bool {
        self.words
            .get(usize::from(register) / 64)
            .is_some_and(|word: &u64| (word >> (register % 64)) & 1 == 1)
    }

    fn insert(&mut self, register: u16) {
        if let Some(word) = self.words.get_mut(usize::from(register) / 64) {
            *word |= 1u64 << (register % 64);
        }
    }

    fn remove(&mut self, register: u16) {
        if let Some(word) = self.words.get_mut(usize::from(register) / 64) {
            *word &= !(1u64 << (register % 64));
        }
    }

    pub(crate) fn union_with(&mut self, other: &Self) {
        for (word, extra) in self.words.iter_mut().zip(&other.words) {
            *word |= *extra;
        }
    }

    fn subtract(&mut self, other: &Self) {
        for (word, removed) in self.words.iter_mut().zip(&other.words) {
            *word &= !*removed;
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.words
            .iter()
            .enumerate()
            .flat_map(|(index, word): (usize, &u64)| {
                (0..64u16).filter_map(move |bit: u16| {
                    let register: usize = index * 64 + usize::from(bit);
                    ((word >> bit) & 1 == 1)
                        .then(|| u16::try_from(register).ok())
                        .flatten()
                })
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueNode {
    Entry { block: u32, register: u16 },
    Def { insn: usize, register: u16 },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DefUses {
    pub(crate) local_uses: u32,
    pub(crate) escapes: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct RegisterFlow {
    live_out: Vec<RegisterSet>,
    handler_live: Vec<RegisterSet>,
    nodes: Vec<ValueNode>,
    web: Vec<usize>,
    entry_nodes: BTreeMap<(u32, u16), usize>,
    def_nodes: BTreeMap<(usize, u16), usize>,
    use_nodes: BTreeMap<(usize, u16), usize>,
    def_uses: BTreeMap<usize, DefUses>,
}

fn find_root(parent: &mut [usize], node: usize) -> usize {
    let mut root: usize = node;
    while let Some(&up) = parent.get(root) {
        if up == root {
            break;
        }
        root = up;
    }
    let mut cursor: usize = node;
    while let Some(&up) = parent.get(cursor) {
        if up == root {
            break;
        }
        if let Some(slot) = parent.get_mut(cursor) {
            *slot = root;
        }
        cursor = up;
    }
    root
}

fn unite(parent: &mut [usize], left: usize, right: usize) {
    let (keep, folded): (usize, usize) = {
        let a: usize = find_root(parent, left);
        let b: usize = find_root(parent, right);
        (a.min(b), a.max(b))
    };
    if let Some(slot) = parent.get_mut(folded) {
        *slot = keep;
    }
}

impl RegisterFlow {
    pub(crate) fn analyze(cfg: &Cfg, accesses: &[RegisterAccess], registers: u16) -> Option<Self> {
        let blocks: usize = cfg.blocks.len();
        let words: usize = usize::from(registers).div_ceil(64);
        if blocks.saturating_mul(words).saturating_mul(3) > MAX_FLOW_WORDS {
            return None;
        }
        let mut generated: Vec<RegisterSet> = Vec::with_capacity(blocks);
        let mut killed: Vec<RegisterSet> = Vec::with_capacity(blocks);
        let mut before_throw: Vec<Option<RegisterSet>> = Vec::with_capacity(blocks);
        for block in &cfg.blocks {
            let mut uses: RegisterSet = RegisterSet::empty(registers);
            let mut defs: RegisterSet = RegisterSet::empty(registers);
            let mut first_throw: Option<RegisterSet> = None;
            for access in accesses.get(block.insn_range.0..block.insn_range.1)? {
                if access.throws && first_throw.is_none() {
                    first_throw = Some(defs.clone());
                }
                for &register in &access.uses {
                    if !defs.contains(register) {
                        uses.insert(register);
                    }
                }
                for &register in &access.defs {
                    defs.insert(register);
                }
            }
            generated.push(uses);
            killed.push(defs);
            before_throw.push(first_throw);
        }
        let mut live_in: Vec<RegisterSet> = vec![RegisterSet::empty(registers); blocks];
        let mut live_out: Vec<RegisterSet> = vec![RegisterSet::empty(registers); blocks];
        let mut handler_live: Vec<RegisterSet> = vec![RegisterSet::empty(registers); blocks];
        let max_rounds: usize = blocks.saturating_mul(2).saturating_add(8);
        let mut settled: bool = false;
        for _ in 0..max_rounds {
            let mut changed: bool = false;
            for index in (0..blocks).rev() {
                let block: &BasicBlock = cfg.blocks.get(index)?;
                let mut out: RegisterSet = RegisterSet::empty(registers);
                let mut handlers: RegisterSet = RegisterSet::empty(registers);
                for edge in &block.successors {
                    let successor: &RegisterSet = live_in.get(edge.target.0 as usize)?;
                    if matches!(edge.kind, EdgeKind::Exception) {
                        handlers.union_with(successor);
                    } else {
                        out.union_with(successor);
                    }
                }
                let mut entry: RegisterSet = out.clone();
                entry.subtract(killed.get(index)?);
                entry.union_with(generated.get(index)?);
                if let Some(defined) = before_throw.get(index)? {
                    let mut thrown: RegisterSet = handlers.clone();
                    thrown.subtract(defined);
                    entry.union_with(&thrown);
                }
                if live_in.get(index) != Some(&entry) {
                    changed = true;
                    *live_in.get_mut(index)? = entry;
                }
                *live_out.get_mut(index)? = out;
                *handler_live.get_mut(index)? = handlers;
            }
            if !changed {
                settled = true;
                break;
            }
        }
        if !settled {
            return None;
        }

        let mut nodes: Vec<ValueNode> = Vec::new();
        let mut entry_nodes: BTreeMap<(u32, u16), usize> = BTreeMap::new();
        for (index, live) in live_in.iter().enumerate() {
            let block: u32 = u32::try_from(index).ok()?;
            for register in live.iter() {
                entry_nodes.insert((block, register), nodes.len());
                nodes.push(ValueNode::Entry { block, register });
            }
        }
        let mut parent: Vec<usize> = (0..nodes.len()).collect();
        let mut def_nodes: BTreeMap<(usize, u16), usize> = BTreeMap::new();
        let mut use_nodes: BTreeMap<(usize, u16), usize> = BTreeMap::new();
        let mut def_uses: BTreeMap<usize, DefUses> = BTreeMap::new();
        for (index, block) in cfg.blocks.iter().enumerate() {
            let block_id: u32 = u32::try_from(index).ok()?;
            let mut current: BTreeMap<u16, usize> = live_in
                .get(index)?
                .iter()
                .filter_map(|register: u16| {
                    entry_nodes
                        .get(&(block_id, register))
                        .map(|&node: &usize| (register, node))
                })
                .collect();
            let handler_registers: &RegisterSet = handler_live.get(index)?;
            let mut thrown: BTreeMap<u16, BTreeSet<usize>> = BTreeMap::new();
            for insn in block.insn_range.0..block.insn_range.1 {
                let access: &RegisterAccess = accesses.get(insn)?;
                if access.throws {
                    for register in handler_registers.iter() {
                        if let Some(&node) = current.get(&register) {
                            thrown.entry(register).or_default().insert(node);
                        }
                    }
                }
                for &register in &access.uses {
                    let Some(&node): Option<&usize> = current.get(&register) else {
                        continue;
                    };
                    use_nodes.insert((insn, register), node);
                    if let Some(facts) = def_uses.get_mut(&node) {
                        facts.local_uses = facts.local_uses.saturating_add(1);
                    }
                }
                for &register in &access.defs {
                    let node: usize = nodes.len();
                    nodes.push(ValueNode::Def { insn, register });
                    parent.push(node);
                    def_nodes.insert((insn, register), node);
                    def_uses.insert(node, DefUses::default());
                    current.insert(register, node);
                }
            }
            for edge in &block.successors {
                let target: u32 = edge.target.0;
                for register in live_in.get(target as usize)?.iter() {
                    let Some(&joined): Option<&usize> = entry_nodes.get(&(target, register)) else {
                        continue;
                    };
                    let flowing: Vec<usize> = if matches!(edge.kind, EdgeKind::Exception) {
                        thrown
                            .get(&register)
                            .map(|nodes: &BTreeSet<usize>| nodes.iter().copied().collect())
                            .unwrap_or_default()
                    } else {
                        current.get(&register).copied().into_iter().collect()
                    };
                    for node in flowing {
                        unite(&mut parent, node, joined);
                        if let Some(facts) = def_uses.get_mut(&node) {
                            facts.escapes = true;
                        }
                    }
                }
            }
        }
        let web: Vec<usize> = (0..nodes.len())
            .map(|node: usize| find_root(&mut parent, node))
            .collect();
        Some(Self {
            live_out,
            handler_live,
            nodes,
            web,
            entry_nodes,
            def_nodes,
            use_nodes,
            def_uses,
        })
    }

    pub(crate) fn live_out(&self, block: BlockId) -> Option<&RegisterSet> {
        self.live_out.get(block.0 as usize)
    }

    pub(crate) fn handler_live(&self, block: BlockId) -> Option<&RegisterSet> {
        self.handler_live.get(block.0 as usize)
    }

    pub(crate) fn live_points(
        &self,
        block: &BasicBlock,
        accesses: &[RegisterAccess],
    ) -> Option<Vec<RegisterSet>> {
        let index: usize = block.id.0 as usize;
        let handlers: &RegisterSet = self.handler_live.get(index)?;
        let mut live: RegisterSet = self.live_out.get(index)?.clone();
        live.union_with(handlers);
        let (start, end): (usize, usize) = block.insn_range;
        let mut points: Vec<RegisterSet> = vec![live.clone(); end.saturating_sub(start) + 1];
        for insn in (start..end).rev() {
            let access: &RegisterAccess = accesses.get(insn)?;
            for &register in &access.defs {
                live.remove(register);
            }
            for &register in &access.uses {
                live.insert(register);
            }
            live.union_with(handlers);
            *points.get_mut(insn - start)? = live.clone();
        }
        Some(points)
    }

    pub(crate) fn nodes(&self) -> &[ValueNode] {
        &self.nodes
    }

    pub(crate) fn web_of(&self, node: usize) -> Option<usize> {
        self.web.get(node).copied()
    }

    pub(crate) fn entry_web(&self, block: BlockId, register: u16) -> Option<usize> {
        self.entry_nodes
            .get(&(block.0, register))
            .and_then(|&node: &usize| self.web_of(node))
    }

    pub(crate) fn uses(&self) -> impl Iterator<Item = (usize, u16, usize)> + '_ {
        self.use_nodes
            .iter()
            .filter_map(|(&(insn, register), &node): (&(usize, u16), &usize)| {
                self.web_of(node).map(|web: usize| (insn, register, web))
            })
    }

    pub(crate) fn def_uses(&self, insn: usize, register: u16) -> Option<DefUses> {
        self.def_nodes
            .get(&(insn, register))
            .and_then(|node: &usize| self.def_uses.get(node))
            .copied()
    }
}

#[derive(Debug, Clone)]
pub struct DalvikMethodCfg {
    pub cfg: Cfg,
    pub insns: Vec<DalvikInsn>,
    pub switch_payloads: Vec<(u32, SwitchPayload)>,
    pub switch_map: BTreeMap<BlockId, PrecomputedSwitch>,
}

#[must_use]
pub fn build_dalvik_cfg_from_code_item(item: &CodeItem) -> Option<DalvikMethodCfg> {
    let insns: Vec<DalvikInsn> = decode_method(&item.insns);
    if insns.is_empty() {
        return None;
    }
    let switch_payloads: Vec<(u32, SwitchPayload)> = collect_switch_payloads(&item.insns, &insns);
    let cfg: Cfg = build_dalvik_cfg(&insns, &item.tries, &switch_payloads).ok()?;
    let switch_map: BTreeMap<BlockId, PrecomputedSwitch> =
        build_switch_map(&cfg, &insns, &switch_payloads);
    Some(DalvikMethodCfg {
        cfg,
        insns,
        switch_payloads,
        switch_map,
    })
}

pub fn collect_switch_payloads(code: &[u16], insns: &[DalvikInsn]) -> Vec<(u32, SwitchPayload)> {
    let mut out: Vec<(u32, SwitchPayload)> = Vec::new();
    for insn in insns {
        if !insn.is_switch() {
            continue;
        }
        let Some(payload_off): Option<u32> = insn.payload_off else {
            continue;
        };
        let payload: Option<SwitchPayload> = if insn.op == 0x2B {
            parse_packed_switch(code, insn.pc, payload_off)
        } else {
            parse_sparse_switch(code, insn.pc, payload_off)
        };
        if let Some(p) = payload {
            out.push((insn.pc, p));
        }
    }
    out
}

pub fn build_dalvik_cfg(
    insns: &[DalvikInsn],
    tries: &[TryItem],
    switches: &[(u32, SwitchPayload)],
) -> Result<Cfg, StructureError> {
    if insns.is_empty() {
        return Err(StructureError::Empty);
    }
    let valid_pcs: BTreeSet<u32> = insns.iter().map(|ins| ins.pc).collect();
    let pc_to_idx: BTreeMap<u32, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, ins)| (ins.pc, i))
        .collect();
    let switch_by_pc: BTreeMap<u32, &SwitchPayload> =
        switches.iter().map(|(pc, p)| (*pc, p)).collect();

    let leaders: BTreeSet<u32> = collect_leaders(insns, tries, &switch_by_pc, &valid_pcs);
    if leaders.len() > MAX_DALVIK_BLOCKS {
        return Err(StructureError::TooManyBlocks(leaders.len()));
    }

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
        let last: &DalvikInsn = &insns[block.insn_range.1.saturating_sub(1)];
        let next_pc: Option<u32> = leader_vec.get(i + 1).copied();
        successors_by_id[i] = block_successors(last, next_pc, &pc_to_block, &switch_by_pc);
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

    let exception_regions: Vec<ExceptionRegion> = build_exception_regions(tries);
    attach_exception_edges(&mut blocks, &pc_to_block, &exception_regions);

    Ok(Cfg {
        blocks,
        pc_to_block,
        entry: BlockId(0),
        exception_regions,
        compound_conditions: BTreeMap::new(),
    })
}

fn collect_leaders(
    insns: &[DalvikInsn],
    tries: &[TryItem],
    switch_by_pc: &BTreeMap<u32, &SwitchPayload>,
    valid_pcs: &BTreeSet<u32>,
) -> BTreeSet<u32> {
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    leaders.insert(insns[0].pc);
    let mut prev_terminator: bool = false;
    for ins in insns {
        if prev_terminator {
            leaders.insert(ins.pc);
        }
        if let Some(t) = ins.branch_target_pc() {
            leaders.insert(t);
        }
        if ins.is_switch()
            && let Some(payload) = switch_by_pc.get(&ins.pc)
        {
            for &t in &payload.targets {
                leaders.insert(t);
            }
        }
        prev_terminator = ins.is_terminator() || matches!(ins.op, 0x1D | 0x1E);
    }
    for t in tries {
        leaders.insert(t.start_addr);
        leaders.insert(t.start_addr + u32::from(t.insn_count));
        for (_, handler_addr) in &t.handlers {
            leaders.insert(*handler_addr);
        }
        if let Some(addr) = t.catch_all {
            leaders.insert(addr);
        }
    }
    leaders.retain(|pc| valid_pcs.contains(pc));
    leaders
}

fn block_successors(
    last: &DalvikInsn,
    fallthrough_pc: Option<u32>,
    pc_to_block: &BTreeMap<u32, BlockId>,
    switch_by_pc: &BTreeMap<u32, &SwitchPayload>,
) -> Vec<Edge> {
    let mut out: Vec<Edge> = Vec::new();
    if last.is_conditional_branch() {
        if let Some(t) = last.branch_target_pc()
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
    if last.is_unconditional_goto() {
        if let Some(t) = last.branch_target_pc()
            && let Some(&bid) = pc_to_block.get(&t)
        {
            out.push(Edge {
                kind: EdgeKind::Jump,
                target: bid,
            });
        }
        return out;
    }
    if last.is_switch() {
        if let Some(payload) = switch_by_pc.get(&last.pc) {
            for &t in &payload.targets {
                if let Some(&bid) = pc_to_block.get(&t) {
                    out.push(Edge {
                        kind: EdgeKind::Switch,
                        target: bid,
                    });
                }
            }
        }
        if let Some(fpc) = fallthrough_pc
            && let Some(&bid) = pc_to_block.get(&fpc)
        {
            out.push(Edge {
                kind: EdgeKind::SwitchDefault,
                target: bid,
            });
        }
        return out;
    }
    if last.is_return() || last.is_throw() {
        return out;
    }
    if let Some(fpc) = fallthrough_pc
        && let Some(&bid) = pc_to_block.get(&fpc)
    {
        out.push(Edge {
            kind: EdgeKind::Fallthrough,
            target: bid,
        });
    }
    out
}

fn build_exception_regions(tries: &[TryItem]) -> Vec<ExceptionRegion> {
    let mut out: Vec<ExceptionRegion> = Vec::new();
    for t in tries {
        let try_start_pc: u32 = t.start_addr;
        let try_end_pc: u32 = t.start_addr + u32::from(t.insn_count);
        for (catch_type, handler_addr) in &t.handlers {
            out.push(ExceptionRegion {
                try_start_pc,
                try_end_pc,
                handler_pc: *handler_addr,
                catch_type: catch_type.clone(),
            });
        }
        if let Some(addr) = t.catch_all {
            out.push(ExceptionRegion {
                try_start_pc,
                try_end_pc,
                handler_pc: addr,
                catch_type: None,
            });
        }
    }
    out
}

pub(crate) fn drop_silent_try_ranges(built: &mut DalvikMethodCfg) {
    let insns: &[DalvikInsn] = &built.insns;
    let before: usize = built.cfg.exception_regions.len();
    built.cfg.exception_regions.retain(|region| {
        insns.iter().any(|insn: &DalvikInsn| {
            insn.pc >= region.try_start_pc
                && insn.pc < region.try_end_pc
                && crate::dalvik_decompile::may_throw(insn)
        })
    });
    if built.cfg.exception_regions.len() == before {
        return;
    }
    for block in &mut built.cfg.blocks {
        block
            .successors
            .retain(|edge: &Edge| !matches!(edge.kind, EdgeKind::Exception));
    }
    let mut predecessors: Vec<Vec<BlockId>> = vec![Vec::new(); built.cfg.blocks.len()];
    for block in &built.cfg.blocks {
        for edge in &block.successors {
            if let Some(slot) = predecessors.get_mut(edge.target.0 as usize)
                && !slot.contains(&block.id)
            {
                slot.push(block.id);
            }
        }
    }
    for (block, incoming) in built.cfg.blocks.iter_mut().zip(predecessors) {
        block.predecessors = incoming;
    }
    attach_exception_edges(
        &mut built.cfg.blocks,
        &built.cfg.pc_to_block,
        &built.cfg.exception_regions,
    );
}

fn attach_exception_edges(
    blocks: &mut [BasicBlock],
    pc_to_block: &BTreeMap<u32, BlockId>,
    regions: &[ExceptionRegion],
) {
    for region in regions {
        let Some(&handler_id): Option<&BlockId> = pc_to_block.get(&region.handler_pc) else {
            continue;
        };
        let mut covered: Vec<BlockId> = Vec::new();
        for (&pc, &bid) in pc_to_block {
            if pc >= region.try_start_pc && pc < region.try_end_pc {
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

fn build_switch_map(
    cfg: &Cfg,
    insns: &[DalvikInsn],
    switches: &[(u32, SwitchPayload)],
) -> BTreeMap<BlockId, PrecomputedSwitch> {
    let switch_by_pc: BTreeMap<u32, &SwitchPayload> =
        switches.iter().map(|(pc, p)| (*pc, p)).collect();
    let mut map: BTreeMap<BlockId, PrecomputedSwitch> = BTreeMap::new();
    for block in &cfg.blocks {
        let last_idx: usize = block.insn_range.1.saturating_sub(1);
        let Some(last): Option<&DalvikInsn> = insns.get(last_idx) else {
            continue;
        };
        if !last.is_switch() {
            continue;
        }
        let Some(payload): Option<&&SwitchPayload> = switch_by_pc.get(&last.pc) else {
            continue;
        };
        let mut by_target: BTreeMap<BlockId, Vec<i32>> = BTreeMap::new();
        let mut ordered: Vec<BlockId> = Vec::new();
        for (k, &target_pc) in payload.targets.iter().enumerate() {
            let Some(&bid): Option<&BlockId> = cfg.pc_to_block.get(&target_pc) else {
                continue;
            };
            let key_value: i32 = payload.keys.get(k).copied().unwrap_or(k as i32);
            by_target.entry(bid).or_default().push(key_value);
            if !ordered.contains(&bid) {
                ordered.push(bid);
            }
        }
        let default: Option<BlockId> = block
            .successors
            .iter()
            .find(|e| matches!(e.kind, EdgeKind::SwitchDefault))
            .map(|e| e.target);
        let mut cases: Vec<(SwitchKey, BlockId)> = Vec::with_capacity(ordered.len());
        for bid in ordered {
            if Some(bid) == default {
                continue;
            }
            let values: Vec<i32> = by_target.remove(&bid).unwrap_or_default();
            cases.push((compact_switch_key(&values), bid));
        }
        map.insert(block.id, PrecomputedSwitch { default, cases });
    }
    map
}

fn compact_switch_key(values: &[i32]) -> SwitchKey {
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
