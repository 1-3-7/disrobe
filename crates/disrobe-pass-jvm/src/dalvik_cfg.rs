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

#[derive(Debug, Clone)]
pub struct DalvikMethodCfg {
    pub cfg: Cfg,
    pub insns: Vec<DalvikInsn>,
    pub switch_map: BTreeMap<BlockId, PrecomputedSwitch>,
}

#[must_use]
pub fn build_dalvik_cfg_from_code_item(item: &CodeItem) -> Option<DalvikMethodCfg> {
    let insns: Vec<DalvikInsn> = decode_method(&item.insns);
    if insns.is_empty() {
        return None;
    }
    let switches: Vec<(u32, SwitchPayload)> = collect_switch_payloads(&item.insns, &insns);
    let cfg: Cfg = build_dalvik_cfg(&insns, &item.tries, &switches).ok()?;
    let switch_map: BTreeMap<BlockId, PrecomputedSwitch> =
        build_switch_map(&cfg, &insns, &switches);
    Some(DalvikMethodCfg {
        cfg,
        insns,
        switch_map,
    })
}

fn collect_switch_payloads(code: &[u16], insns: &[DalvikInsn]) -> Vec<(u32, SwitchPayload)> {
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
        prev_terminator = ins.is_terminator();
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
