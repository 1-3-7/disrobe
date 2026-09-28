use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::dalvik::{DalvikInsn, SwitchPayload};
use crate::dalvik_cfg::{DalvikMethodCfg, build_dalvik_cfg_from_code_item};
use crate::decompile_struct::{BasicBlock, BlockId, Cfg, Edge, EdgeKind};
use crate::dex::CodeItem;

const MIN_DISPATCHER_PREDECESSORS: usize = 2;
const MIN_DISPATCHER_CASES: usize = 2;
const MAX_RESOLVE_ROUNDS: usize = 65_536;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DalvikCffReport {
    pub methods_scanned: u32,
    pub flattened_methods: u32,
    pub methods_unflattened: u32,
    pub dispatchers_resolved: u32,
    pub edges_redirected: u32,
    pub dead_branches_folded: u32,
    pub dispatcher_blocks_pruned: u32,
    pub residual_dispatcher_edges: u32,
    pub unhandled_shapes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DalvikMethodCff {
    pub class: String,
    pub method_name: String,
    pub method_descriptor: String,
    pub flattened: bool,
    pub fully_unflattened: bool,
    pub dispatchers_resolved: u32,
    pub edges_redirected: u32,
    pub dead_branches_folded: u32,
    pub dispatcher_blocks_pruned: u32,
    pub residual_dispatcher_edges: u32,
    pub recovered_block_order: Vec<u32>,
    pub rewire_refusal: Option<CffRewireRefusal>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CffRewireRefusal {
    #[error(
        "{0} edge(s) still enter a dispatcher: a predecessor's state write was not a single \
         static const into the switch register"
    )]
    ResidualDispatcherEdges(u32),
    #[error("the dispatcher at pc {pc} stays reachable after rewiring")]
    DispatcherReachable { pc: u32 },
    #[error(
        "state register v{register} is used at pc {pc} outside a const write or its dispatcher \
         switch"
    )]
    StateRegisterEscapes { register: u16, pc: u32 },
    #[error("the dispatcher block writes v{register} at pc {pc}, which the method reads elsewhere")]
    DispatcherPrefixLive { register: u16, pc: u32 },
}

#[must_use]
pub fn unflatten_dex_methods(items: &[CodeItem]) -> (DalvikCffReport, Vec<DalvikMethodCff>) {
    let mut report: DalvikCffReport = DalvikCffReport::default();
    let mut per_method: Vec<DalvikMethodCff> = Vec::new();
    for item in items {
        report.methods_scanned += 1;
        let Some(method): Option<DalvikMethodCff> = unflatten_code_item(item) else {
            continue;
        };
        if !method.flattened {
            continue;
        }
        report.flattened_methods += 1;
        report.dispatchers_resolved += method.dispatchers_resolved;
        report.edges_redirected += method.edges_redirected;
        report.dead_branches_folded += method.dead_branches_folded;
        report.dispatcher_blocks_pruned += method.dispatcher_blocks_pruned;
        report.residual_dispatcher_edges += method.residual_dispatcher_edges;
        crate::debug::dbg_kv("dalvik-cff", || {
            format!(
                "{}->{}{} flattened: dispatchers={} edges_redirected={} dead_folded={} \
                 blocks_pruned={} residual={} fully_unflattened={}",
                method.class,
                method.method_name,
                method.method_descriptor,
                method.dispatchers_resolved,
                method.edges_redirected,
                method.dead_branches_folded,
                method.dispatcher_blocks_pruned,
                method.residual_dispatcher_edges,
                method.fully_unflattened
            )
        });
        match &method.rewire_refusal {
            None => report.methods_unflattened += 1,
            Some(refusal) => report.unhandled_shapes.push(format!(
                "{}->{}{}: not rewired after {} dispatcher round(s): {refusal}",
                method.class,
                method.method_name,
                method.method_descriptor,
                method.dispatchers_resolved,
            )),
        }
        per_method.push(method);
    }
    (report, per_method)
}

#[must_use]
pub fn unflatten_code_item(item: &CodeItem) -> Option<DalvikMethodCff> {
    unflatten_with_graph(item).map(|(method, _): (DalvikMethodCff, DalvikMethodCfg)| method)
}

#[must_use]
pub(crate) fn rewired_method_cfg(item: &CodeItem) -> Option<DalvikMethodCfg> {
    let (method, rewired): (DalvikMethodCff, DalvikMethodCfg) = unflatten_with_graph(item)?;
    method.fully_unflattened.then_some(rewired)
}

#[must_use]
fn unflatten_with_graph(item: &CodeItem) -> Option<(DalvikMethodCff, DalvikMethodCfg)> {
    let mut built: DalvikMethodCfg = build_dalvik_cfg_from_code_item(item)?;
    let dispatchers: Vec<Dispatcher> =
        find_dispatchers(&built.cfg, &built.insns, &built.switch_payloads);
    if dispatchers.is_empty() {
        let method: DalvikMethodCff = DalvikMethodCff {
            class: item.class.clone(),
            method_name: item.method_name.clone(),
            method_descriptor: item.method_descriptor.clone(),
            flattened: false,
            fully_unflattened: false,
            dispatchers_resolved: 0,
            edges_redirected: 0,
            dead_branches_folded: 0,
            dispatcher_blocks_pruned: 0,
            residual_dispatcher_edges: 0,
            recovered_block_order: Vec::new(),
            rewire_refusal: None,
        };
        return Some((method, built));
    }
    let mut seen_dispatchers: BTreeMap<BlockId, u16> = dispatchers
        .iter()
        .map(|d: &Dispatcher| (d.block, d.state_reg))
        .collect();

    let cfg: &mut Cfg = &mut built.cfg;
    let insns: &[DalvikInsn] = &built.insns;
    let switch_payloads: &[(u32, SwitchPayload)] = &built.switch_payloads;
    let mut stats: ResolveStats = ResolveStats::default();
    stats.dead_branches_folded += fold_opaque_conditionals(cfg, insns);
    if stats.dead_branches_folded > 0 {
        rebuild_predecessors(cfg);
    }

    let mut rounds: usize = 0;
    loop {
        rounds += 1;
        if rounds > MAX_RESOLVE_ROUNDS {
            break;
        }
        let live_dispatchers: Vec<Dispatcher> = find_dispatchers(cfg, insns, switch_payloads);
        if live_dispatchers.is_empty() {
            break;
        }
        let mut progressed: bool = false;
        for dispatcher in &live_dispatchers {
            seen_dispatchers.insert(dispatcher.block, dispatcher.state_reg);
            if resolve_dispatcher(cfg, insns, dispatcher, &mut stats) {
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
        rebuild_predecessors(cfg);
    }

    let pruned: u32 = prune_unreachable(cfg);
    stats.dispatcher_blocks_pruned += pruned;
    rebuild_predecessors(cfg);

    let residual_dispatcher_edges: u32 =
        residual_dispatcher_edge_count(cfg, insns, switch_payloads);
    let recovered_block_order: Vec<u32> = reachable_order(cfg);
    let rewire_refusal: Option<CffRewireRefusal> = if residual_dispatcher_edges > 0 {
        Some(CffRewireRefusal::ResidualDispatcherEdges(
            residual_dispatcher_edges,
        ))
    } else {
        rewire_refusal(cfg, insns, &seen_dispatchers)
    };
    if rewire_refusal.is_none() {
        let state_registers: BTreeSet<u16> = seen_dispatchers.values().copied().collect();
        for insn in &mut built.insns {
            if const_int_to(insn).is_some_and(|(dst, _): (u16, i32)| state_registers.contains(&dst))
            {
                *insn = DalvikInsn {
                    pc: insn.pc,
                    op: 0x00,
                    mnemonic: "nop",
                    width: insn.width,
                    format: crate::dalvik::InsnFormat::Fmt10x,
                    regs: Vec::new(),
                    literal: None,
                    index: None,
                    branch: None,
                    payload_off: None,
                };
            }
        }
    }

    let method: DalvikMethodCff = DalvikMethodCff {
        class: item.class.clone(),
        method_name: item.method_name.clone(),
        method_descriptor: item.method_descriptor.clone(),
        flattened: true,
        fully_unflattened: rewire_refusal.is_none(),
        dispatchers_resolved: stats.dispatchers_resolved,
        edges_redirected: stats.edges_redirected,
        dead_branches_folded: stats.dead_branches_folded,
        dispatcher_blocks_pruned: stats.dispatcher_blocks_pruned,
        residual_dispatcher_edges,
        recovered_block_order,
        rewire_refusal,
    };
    Some((method, built))
}

#[must_use]
fn rewire_refusal(
    cfg: &Cfg,
    insns: &[DalvikInsn],
    dispatchers: &BTreeMap<BlockId, u16>,
) -> Option<CffRewireRefusal> {
    let reachable: BTreeSet<BlockId> = reachable_set(cfg);
    let mut switch_registers: BTreeMap<usize, u16> = BTreeMap::new();
    let mut prefix_indices: BTreeSet<usize> = BTreeSet::new();
    for (&block_id, &state_reg) in dispatchers {
        let block: &BasicBlock = &cfg.blocks[block_id.0 as usize];
        if reachable.contains(&block_id) {
            return Some(CffRewireRefusal::DispatcherReachable { pc: block.start_pc });
        }
        let (start_idx, end_idx): (usize, usize) = block.insn_range;
        let Some(switch_idx): Option<usize> = end_idx.checked_sub(1) else {
            return Some(CffRewireRefusal::DispatcherReachable { pc: block.start_pc });
        };
        switch_registers.insert(switch_idx, state_reg);
        prefix_indices.extend(start_idx..switch_idx);
    }
    for &state_reg in dispatchers.values() {
        for (idx, insn) in insns.iter().enumerate() {
            if !touches_register(insn, state_reg) {
                continue;
            }
            let state_const: bool =
                const_int_to(insn).is_some_and(|(dst, _): (u16, i32)| dst == state_reg);
            let dispatch_read: bool = switch_registers.get(&idx) == Some(&state_reg);
            if !state_const && !dispatch_read {
                return Some(CffRewireRefusal::StateRegisterEscapes {
                    register: state_reg,
                    pc: insn.pc,
                });
            }
        }
    }
    for &prefix_idx in &prefix_indices {
        let insn: &DalvikInsn = &insns[prefix_idx];
        let Some(written): Option<Vec<u16>> = const_destinations(insn) else {
            return Some(CffRewireRefusal::DispatcherPrefixLive {
                register: insn.regs.first().copied().unwrap_or_default(),
                pc: insn.pc,
            });
        };
        for register in written {
            let read_elsewhere: bool =
                insns
                    .iter()
                    .enumerate()
                    .any(|(idx, other): (usize, &DalvikInsn)| {
                        !prefix_indices.contains(&idx) && touches_register(other, register)
                    });
            if read_elsewhere {
                return Some(CffRewireRefusal::DispatcherPrefixLive {
                    register,
                    pc: insn.pc,
                });
            }
        }
    }
    None
}

#[must_use]
fn const_destinations(insn: &DalvikInsn) -> Option<Vec<u16>> {
    let dst: u16 = insn.regs.first().copied()?;
    match insn.op {
        0x12..=0x15 => Some(vec![dst]),
        0x16..=0x19 => Some(vec![dst, dst.checked_add(1)?]),
        _ => None,
    }
}

#[must_use]
fn touches_register(insn: &DalvikInsn, reg: u16) -> bool {
    insn.regs.contains(&reg)
        || has_wide_register_operand(insn.op)
            && reg
                .checked_sub(1)
                .is_some_and(|low: u16| insn.regs.contains(&low))
}

#[inline]
const fn has_wide_register_operand(op: u8) -> bool {
    matches!(
        op,
        0x04..=0x06
            | 0x0B
            | 0x10
            | 0x16..=0x19
            | 0x2F..=0x31
            | 0x45
            | 0x4C
            | 0x53
            | 0x5A
            | 0x61
            | 0x68
            | 0x7D..=0x8C
            | 0x9B..=0xA5
            | 0xAB..=0xAF
            | 0xBB..=0xC5
            | 0xCB..=0xCF
    )
}

#[derive(Debug, Clone, Default)]
struct ResolveStats {
    dispatchers_resolved: u32,
    edges_redirected: u32,
    dead_branches_folded: u32,
    dispatcher_blocks_pruned: u32,
}

#[derive(Debug, Clone)]
struct Dispatcher {
    block: BlockId,
    state_reg: u16,
    cases: BTreeMap<i32, BlockId>,
    default: Option<BlockId>,
}

#[inline]
fn switch_register(insn: &DalvikInsn) -> Option<u16> {
    insn.regs.first().copied()
}

#[must_use]
fn find_dispatchers(
    cfg: &Cfg,
    insns: &[DalvikInsn],
    switches: &[(u32, SwitchPayload)],
) -> Vec<Dispatcher> {
    let switch_by_pc: BTreeMap<u32, &SwitchPayload> = switches
        .iter()
        .map(|(pc, p): &(u32, SwitchPayload)| (*pc, p))
        .collect();
    let mut out: Vec<Dispatcher> = Vec::new();
    for block in &cfg.blocks {
        if block.predecessors.len() < MIN_DISPATCHER_PREDECESSORS {
            continue;
        }
        let Some(dispatcher): Option<Dispatcher> =
            dispatcher_at_block(cfg, block, insns, &switch_by_pc)
        else {
            continue;
        };
        out.push(dispatcher);
    }
    out
}

#[must_use]
fn dispatcher_at_block(
    cfg: &Cfg,
    block: &BasicBlock,
    insns: &[DalvikInsn],
    switch_by_pc: &BTreeMap<u32, &SwitchPayload>,
) -> Option<Dispatcher> {
    let (_, end_idx): (usize, usize) = block.insn_range;
    let last: &DalvikInsn = insns.get(end_idx.checked_sub(1)?)?;
    if !last.is_switch() {
        return None;
    }
    let state_reg: u16 = switch_register(last)?;
    let payload: &&SwitchPayload = switch_by_pc.get(&last.pc)?;
    if payload.keys.len() < MIN_DISPATCHER_CASES {
        return None;
    }
    let mut cases: BTreeMap<i32, BlockId> = BTreeMap::new();
    for (key, target_pc) in payload.keys.iter().zip(payload.targets.iter()) {
        let &bid: &BlockId = cfg.pc_to_block.get(target_pc)?;
        cases.insert(*key, bid);
    }
    if cases.is_empty() {
        return None;
    }
    if !register_is_const_pure(insns, state_reg) {
        return None;
    }
    if !has_const_state_predecessor(cfg, block, insns, state_reg) {
        return None;
    }
    let default: Option<BlockId> = block
        .successors
        .iter()
        .find(|e: &&Edge| matches!(e.kind, EdgeKind::SwitchDefault))
        .map(|e: &Edge| e.target);
    Some(Dispatcher {
        block: block.id,
        state_reg,
        cases,
        default,
    })
}

#[must_use]
fn register_is_const_pure(insns: &[DalvikInsn], reg: u16) -> bool {
    let mut written_by_const: bool = false;
    for insn in insns {
        if !writes_register(insn, reg) {
            continue;
        }
        if const_int_to(insn).map(|(dst, _): (u16, i32)| dst) == Some(reg) {
            written_by_const = true;
            continue;
        }
        return false;
    }
    written_by_const
}

#[must_use]
fn has_const_state_predecessor(
    cfg: &Cfg,
    block: &BasicBlock,
    insns: &[DalvikInsn],
    state_reg: u16,
) -> bool {
    block.predecessors.iter().any(|pred: &BlockId| {
        if *pred == block.id {
            return false;
        }
        let pred_block: &BasicBlock = &cfg.blocks[pred.0 as usize];
        if !only_normal_edge_to(pred_block, block.id) {
            return false;
        }
        block_tail_state(pred_block, insns, state_reg).is_some()
    })
}

#[derive(Debug, Clone, Copy)]
struct StateTail {
    const_value: i32,
    truncate_to: usize,
}

#[must_use]
fn block_tail_state(block: &BasicBlock, insns: &[DalvikInsn], state_reg: u16) -> Option<StateTail> {
    let (start_idx, end_idx): (usize, usize) = block.insn_range;
    if end_idx <= start_idx {
        return None;
    }
    let last: &DalvikInsn = insns.get(end_idx - 1)?;
    let body_end: usize = if last.is_unconditional_goto() {
        end_idx - 1
    } else {
        end_idx
    };
    let write_idx: usize = (start_idx..body_end).rev().find(|&idx: &usize| {
        insns
            .get(idx)
            .is_some_and(|insn: &DalvikInsn| writes_register(insn, state_reg))
    })?;
    let (dst, value): (u16, i32) = const_int_to(insns.get(write_idx)?)?;
    if dst != state_reg {
        return None;
    }
    let truncate_to: usize = if write_idx + 1 == body_end {
        write_idx
    } else {
        body_end
    };
    Some(StateTail {
        const_value: value,
        truncate_to,
    })
}

#[inline]
fn const_int_to(insn: &DalvikInsn) -> Option<(u16, i32)> {
    match insn.op {
        0x12..=0x14 => {
            let dst: u16 = insn.regs.first().copied()?;
            let value: i64 = insn.literal?;
            Some((dst, value as i32))
        }
        0x15 => {
            let dst: u16 = insn.regs.first().copied()?;
            let high: i64 = insn.literal?;
            Some((dst, (high as i32) << 16))
        }
        _ => None,
    }
}

#[must_use]
pub(crate) fn writes_register(insn: &DalvikInsn, reg: u16) -> bool {
    if const_int_to(insn).map(|(dst, _): (u16, i32)| dst) == Some(reg) {
        return true;
    }
    let writes_first: bool = matches!(
        insn.op,
        0x01..=0x0D
            | 0x16..=0x19
            | 0x1A..=0x1C
            | 0x1F..=0x23
            | 0x44..=0x4A
            | 0x52..=0x58
            | 0x60..=0x66
            | 0x7B..=0xE2
    );
    writes_first && insn.regs.first().copied() == Some(reg)
}

#[must_use]
fn resolve_dispatcher(
    cfg: &mut Cfg,
    insns: &[DalvikInsn],
    dispatcher: &Dispatcher,
    stats: &mut ResolveStats,
) -> bool {
    let predecessors: Vec<BlockId> = cfg.blocks[dispatcher.block.0 as usize].predecessors.clone();
    let mut redirects: Vec<(BlockId, BlockId, usize)> = Vec::new();
    for pred in predecessors {
        if pred == dispatcher.block {
            continue;
        }
        let pred_block: &BasicBlock = &cfg.blocks[pred.0 as usize];
        if !only_normal_edge_to(pred_block, dispatcher.block) {
            continue;
        }
        let Some(tail): Option<StateTail> =
            block_tail_state(pred_block, insns, dispatcher.state_reg)
        else {
            continue;
        };
        let target: Option<BlockId> = dispatcher
            .cases
            .get(&tail.const_value)
            .copied()
            .or(dispatcher.default);
        let Some(target): Option<BlockId> = target else {
            continue;
        };
        if target == dispatcher.block {
            continue;
        }
        redirects.push((pred, target, tail.truncate_to));
    }

    if redirects.is_empty() {
        return false;
    }

    let count: u32 = u32::try_from(redirects.len()).unwrap_or(u32::MAX);
    for (pred, target, truncate_to) in redirects {
        let pred_block: &mut BasicBlock = &mut cfg.blocks[pred.0 as usize];
        let exception_edges: Vec<Edge> = pred_block
            .successors
            .iter()
            .filter(|e: &&Edge| matches!(e.kind, EdgeKind::Exception))
            .cloned()
            .collect();
        let mut new_succs: Vec<Edge> = vec![Edge {
            kind: EdgeKind::Jump,
            target,
        }];
        new_succs.extend(exception_edges);
        pred_block.successors = new_succs;
        pred_block.insn_range.1 = truncate_to;
    }

    stats.edges_redirected = stats.edges_redirected.saturating_add(count);
    stats.dispatchers_resolved = stats.dispatchers_resolved.saturating_add(1);
    true
}

#[must_use]
fn only_normal_edge_to(block: &BasicBlock, target: BlockId) -> bool {
    let mut saw_target: bool = false;
    for edge in &block.successors {
        if matches!(edge.kind, EdgeKind::Exception) {
            continue;
        }
        if edge.target != target {
            return false;
        }
        saw_target = true;
    }
    saw_target
}

#[must_use]
fn fold_opaque_conditionals(cfg: &mut Cfg, insns: &[DalvikInsn]) -> u32 {
    let mut folds: Vec<(BlockId, BlockId, usize)> = Vec::new();
    for block in &cfg.blocks {
        let (start_idx, end_idx): (usize, usize) = block.insn_range;
        let Some(branch): Option<&DalvikInsn> = end_idx.checked_sub(1).and_then(|i| insns.get(i))
        else {
            continue;
        };
        if !branch.is_conditional_branch() {
            continue;
        }
        let Some(taken): Option<bool> = const_condition_outcome(insns, branch, start_idx, end_idx)
        else {
            continue;
        };
        let true_target: Option<BlockId> = block
            .successors
            .iter()
            .find(|e: &&Edge| matches!(e.kind, EdgeKind::CondTrue))
            .map(|e: &Edge| e.target);
        let false_target: Option<BlockId> = block
            .successors
            .iter()
            .find(|e: &&Edge| matches!(e.kind, EdgeKind::CondFalse))
            .map(|e: &Edge| e.target);
        let live: Option<BlockId> = if taken { true_target } else { false_target };
        let Some(live_target): Option<BlockId> = live else {
            continue;
        };
        folds.push((block.id, live_target, end_idx - 1));
    }

    if folds.is_empty() {
        return 0;
    }

    let count: u32 = u32::try_from(folds.len()).unwrap_or(u32::MAX);
    for (bid, live_target, branch_idx) in folds {
        let block: &mut BasicBlock = &mut cfg.blocks[bid.0 as usize];
        let exception_edges: Vec<Edge> = block
            .successors
            .iter()
            .filter(|e: &&Edge| matches!(e.kind, EdgeKind::Exception))
            .cloned()
            .collect();
        let mut new_succs: Vec<Edge> = vec![Edge {
            kind: EdgeKind::Jump,
            target: live_target,
        }];
        new_succs.extend(exception_edges);
        block.successors = new_succs;
        block.insn_range.1 = branch_idx;
    }
    count
}

#[must_use]
fn const_condition_outcome(
    insns: &[DalvikInsn],
    branch: &DalvikInsn,
    start_idx: usize,
    end_idx: usize,
) -> Option<bool> {
    match branch.op {
        0x38..=0x3D => {
            let reg: u16 = branch.regs.first().copied()?;
            let value: i32 = last_const_into(insns, reg, start_idx, end_idx - 1)?;
            Some(unary_compare(branch.op, value))
        }
        0x32..=0x37 => {
            let lhs_reg: u16 = branch.regs.first().copied()?;
            let rhs_reg: u16 = branch.regs.get(1).copied()?;
            let lhs: i32 = last_const_into(insns, lhs_reg, start_idx, end_idx - 1)?;
            let rhs: i32 = last_const_into(insns, rhs_reg, start_idx, end_idx - 1)?;
            Some(binary_compare(branch.op, lhs, rhs))
        }
        _ => None,
    }
}

#[must_use]
fn last_const_into(
    insns: &[DalvikInsn],
    reg: u16,
    start_idx: usize,
    before_idx: usize,
) -> Option<i32> {
    let mut value: Option<i32> = None;
    for insn in insns.get(start_idx..before_idx)? {
        match const_int_to(insn) {
            Some((dst, v)) if dst == reg => value = Some(v),
            _ if writes_register(insn, reg) => value = None,
            _ => {}
        }
    }
    value
}

#[inline]
const fn unary_compare(op: u8, v: i32) -> bool {
    match op {
        0x38 => v == 0,
        0x39 => v != 0,
        0x3A => v < 0,
        0x3B => v >= 0,
        0x3C => v > 0,
        0x3D => v <= 0,
        _ => false,
    }
}

#[inline]
const fn binary_compare(op: u8, a: i32, b: i32) -> bool {
    match op {
        0x32 => a == b,
        0x33 => a != b,
        0x34 => a < b,
        0x35 => a >= b,
        0x36 => a > b,
        0x37 => a <= b,
        _ => false,
    }
}

fn rebuild_predecessors(cfg: &mut Cfg) {
    for block in &mut cfg.blocks {
        block.predecessors.clear();
    }
    let edges: Vec<(BlockId, BlockId)> = cfg
        .blocks
        .iter()
        .flat_map(|b: &BasicBlock| b.successors.iter().map(move |e: &Edge| (b.id, e.target)))
        .collect();
    for (src, dst) in edges {
        let preds: &mut Vec<BlockId> = &mut cfg.blocks[dst.0 as usize].predecessors;
        if !preds.contains(&src) {
            preds.push(src);
        }
    }
}

#[must_use]
fn reachable_set(cfg: &Cfg) -> BTreeSet<BlockId> {
    let mut seen: BTreeSet<BlockId> = BTreeSet::new();
    let mut stack: Vec<BlockId> = vec![cfg.entry];
    seen.insert(cfg.entry);
    while let Some(b) = stack.pop() {
        for edge in &cfg.blocks[b.0 as usize].successors {
            if seen.insert(edge.target) {
                stack.push(edge.target);
            }
        }
    }
    seen
}

#[must_use]
fn reachable_order(cfg: &Cfg) -> Vec<u32> {
    let mut order: Vec<u32> = Vec::new();
    let mut seen: BTreeSet<BlockId> = BTreeSet::new();
    let mut stack: Vec<BlockId> = vec![cfg.entry];
    while let Some(b) = stack.pop() {
        if !seen.insert(b) {
            continue;
        }
        order.push(cfg.blocks[b.0 as usize].start_pc);
        let mut succ_targets: Vec<BlockId> = cfg.blocks[b.0 as usize]
            .successors
            .iter()
            .map(|e: &Edge| e.target)
            .collect();
        succ_targets.reverse();
        stack.extend(succ_targets);
    }
    order
}

#[must_use]
fn prune_unreachable(cfg: &mut Cfg) -> u32 {
    let reachable: BTreeSet<BlockId> = reachable_set(cfg);
    let mut pruned: u32 = 0;
    for block in &mut cfg.blocks {
        if reachable.contains(&block.id) {
            continue;
        }
        if !block.successors.is_empty() || !block.predecessors.is_empty() {
            pruned += 1;
        }
        block.successors.clear();
        block.predecessors.clear();
    }
    pruned
}

#[must_use]
fn residual_dispatcher_edge_count(
    cfg: &Cfg,
    insns: &[DalvikInsn],
    switches: &[(u32, SwitchPayload)],
) -> u32 {
    let reachable: BTreeSet<BlockId> = reachable_set(cfg);
    let dispatchers: Vec<Dispatcher> = find_dispatchers(cfg, insns, switches);
    let dispatcher_ids: BTreeSet<BlockId> =
        dispatchers.iter().map(|d: &Dispatcher| d.block).collect();
    let mut residual: u32 = 0;
    for block in &cfg.blocks {
        if !reachable.contains(&block.id) {
            continue;
        }
        for edge in &block.successors {
            if matches!(edge.kind, EdgeKind::Exception) {
                continue;
            }
            if dispatcher_ids.contains(&edge.target) {
                residual = residual.saturating_add(1);
            }
        }
    }
    residual
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
