use std::collections::{BTreeMap, BTreeSet};

use walrus::ir::{Instr, InstrSeq, InstrSeqId, InstrSeqType, Value, Visitor, dfs_in_order};
use walrus::{
    ExportItem, FunctionId, FunctionKind, GlobalId, GlobalKind, LocalFunction, LocalId, MemoryId,
    Module,
};

use super::reloop::ElidableCells;

const NESTED_SEQ_LIMIT: usize = 4096;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CffRecovery {
    pub functions_restructured: usize,
    pub conditional_restructured: usize,
    pub walled_branching_dispatchers: usize,
}

pub(super) fn restructure_flattened(module: &mut Module) -> CffRecovery {
    let local_ids: Vec<FunctionId> = module.funcs.iter_local().map(|(id, _)| id).collect();
    let elidable: BTreeMap<FunctionId, ElidableCells> = elidable_state_cells(module);
    let empty: ElidableCells = ElidableCells::default();
    let mut recovery: CffRecovery = CffRecovery::default();
    for fid in local_ids {
        let cells: &ElidableCells = elidable.get(&fid).unwrap_or(&empty);
        let FunctionKind::Local(func): &mut FunctionKind = &mut module.funcs.get_mut(fid).kind
        else {
            continue;
        };
        match restructure_one(func, cells) {
            Restructure::Linearized => recovery.functions_restructured += 1,
            Restructure::Relooped { count, walled } => {
                recovery.functions_restructured += 1;
                recovery.conditional_restructured += count;
                recovery.walled_branching_dispatchers += walled;
            }
            Restructure::WalledBranching => recovery.walled_branching_dispatchers += 1,
            Restructure::NotFlattened => {}
        }
    }
    recovery
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CellOwner {
    Function(FunctionId),
    Shared,
}

fn elidable_state_cells(module: &Module) -> BTreeMap<FunctionId, ElidableCells> {
    let globals: BTreeMap<FunctionId, BTreeSet<GlobalId>> = elidable_state_globals(module);
    let memories: BTreeMap<FunctionId, BTreeSet<MemoryId>> = elidable_state_memories(module);
    let exported_memories: BTreeSet<MemoryId> = module
        .exports
        .iter()
        .filter_map(|export| match export.item {
            ExportItem::Memory(id) => Some(id),
            ExportItem::Function(_)
            | ExportItem::Global(_)
            | ExportItem::Table(_)
            | ExportItem::Tag(_) => None,
        })
        .collect();
    module
        .funcs
        .iter_local()
        .map(|(fid, _)| {
            let function_memories: BTreeSet<MemoryId> =
                memories.get(&fid).cloned().unwrap_or_default();
            let fixed_memories: BTreeSet<MemoryId> = function_memories
                .difference(&exported_memories)
                .filter(|memory: &&MemoryId| !module.memories.get(**memory).shared)
                .copied()
                .collect();
            let cells: ElidableCells = ElidableCells {
                globals: globals.get(&fid).cloned().unwrap_or_default(),
                memories: function_memories,
                memory_min_bytes: fixed_memories
                    .iter()
                    .filter_map(|memory: &MemoryId| {
                        minimum_memory_bytes(module, *memory).map(|bytes: u64| (*memory, bytes))
                    })
                    .collect(),
                fixed_memories,
            };
            (fid, cells)
        })
        .collect()
}

fn elidable_state_memories(module: &Module) -> BTreeMap<FunctionId, BTreeSet<MemoryId>> {
    let imported: BTreeSet<MemoryId> = module
        .memories
        .iter()
        .filter(|memory: &&walrus::Memory| memory.import.is_some())
        .map(walrus::Memory::id)
        .collect();
    let mut owners: BTreeMap<MemoryId, CellOwner> = BTreeMap::new();
    let mut referenced: BTreeMap<FunctionId, BTreeSet<MemoryId>> = BTreeMap::new();
    for (fid, func) in module.funcs.iter_local() {
        let Some(memories): Option<BTreeSet<MemoryId>> = referenced_memories(func) else {
            return BTreeMap::new();
        };
        for memory in &memories {
            claim(&mut owners, *memory, fid);
        }
        referenced.insert(fid, memories);
    }
    referenced
        .into_iter()
        .map(|(fid, memories): (FunctionId, BTreeSet<MemoryId>)| {
            let owned: BTreeSet<MemoryId> = memories
                .into_iter()
                .filter(|memory: &MemoryId| {
                    owners.get(memory) == Some(&CellOwner::Function(fid))
                        && !imported.contains(memory)
                })
                .collect();
            (fid, owned)
        })
        .collect()
}

fn minimum_memory_bytes(module: &Module, memory: MemoryId) -> Option<u64> {
    let entry: &walrus::Memory = module.memories.get(memory);
    entry
        .initial
        .checked_shl(entry.page_size_log2.unwrap_or(16))
}

fn claim<T: Ord>(owners: &mut BTreeMap<T, CellOwner>, cell: T, fid: FunctionId) {
    owners
        .entry(cell)
        .and_modify(|owner: &mut CellOwner| {
            if *owner != CellOwner::Function(fid) {
                *owner = CellOwner::Shared;
            }
        })
        .or_insert(CellOwner::Function(fid));
}

#[derive(Debug, Default)]
struct MemoryScan {
    memories: BTreeSet<MemoryId>,
    sequences: usize,
    truncated: bool,
}

impl<'instr> Visitor<'instr> for MemoryScan {
    fn start_instr_seq(&mut self, _instr_seq: &'instr InstrSeq) {
        self.sequences = self.sequences.saturating_add(1);
        if self.sequences > NESTED_SEQ_LIMIT {
            self.truncated = true;
        }
    }

    fn visit_memory_id(&mut self, memory: &MemoryId) {
        self.memories.insert(*memory);
    }
}

fn referenced_memories(func: &LocalFunction) -> Option<BTreeSet<MemoryId>> {
    let mut scan: MemoryScan = MemoryScan::default();
    dfs_in_order(&mut scan, func, func.entry_block());
    (!scan.truncated).then_some(scan.memories)
}

fn elidable_state_globals(module: &Module) -> BTreeMap<FunctionId, BTreeSet<GlobalId>> {
    let exported: BTreeSet<GlobalId> = module
        .exports
        .iter()
        .filter_map(|export| match export.item {
            ExportItem::Global(id) => Some(id),
            ExportItem::Function(_)
            | ExportItem::Table(_)
            | ExportItem::Memory(_)
            | ExportItem::Tag(_) => None,
        })
        .collect();
    let mut owners: BTreeMap<GlobalId, CellOwner> = BTreeMap::new();
    let mut referenced: BTreeMap<FunctionId, BTreeSet<GlobalId>> = BTreeMap::new();
    for (fid, func) in module.funcs.iter_local() {
        let Some(globals): Option<BTreeSet<GlobalId>> = referenced_globals(func) else {
            return BTreeMap::new();
        };
        for global in &globals {
            claim(&mut owners, *global, fid);
        }
        referenced.insert(fid, globals);
    }
    referenced
        .into_iter()
        .map(|(fid, globals): (FunctionId, BTreeSet<GlobalId>)| {
            let owned: BTreeSet<GlobalId> = globals
                .into_iter()
                .filter(|global: &GlobalId| {
                    owners.get(global) == Some(&CellOwner::Function(fid))
                        && !exported.contains(global)
                        && is_private_mutable_global(module, *global)
                })
                .collect();
            (fid, owned)
        })
        .collect()
}

fn is_private_mutable_global(module: &Module, global: GlobalId) -> bool {
    let entry: &walrus::Global = module.globals.get(global);
    entry.mutable && matches!(entry.kind, GlobalKind::Local(_))
}

fn referenced_globals(func: &LocalFunction) -> Option<BTreeSet<GlobalId>> {
    let mut out: BTreeSet<GlobalId> = BTreeSet::new();
    for seq in reachable_seqs(func, func.entry_block())? {
        for (instr, _) in &func.block(seq).instrs {
            match instr {
                Instr::GlobalGet(get) => {
                    out.insert(get.global);
                }
                Instr::GlobalSet(set) => {
                    out.insert(set.global);
                }
                _ => {}
            }
        }
    }
    Some(out)
}

fn reachable_seqs(func: &LocalFunction, root: InstrSeqId) -> Option<BTreeSet<InstrSeqId>> {
    let mut seen: BTreeSet<InstrSeqId> = BTreeSet::new();
    let mut stack: Vec<InstrSeqId> = vec![root];
    while let Some(seq) = stack.pop() {
        if !seen.insert(seq) {
            continue;
        }
        if seen.len() > NESTED_SEQ_LIMIT {
            return None;
        }
        for (instr, _) in &func.block(seq).instrs {
            for child in child_seqs(instr).into_iter().flatten() {
                stack.push(child);
            }
        }
    }
    Some(seen)
}

const fn child_seqs(instr: &Instr) -> [Option<InstrSeqId>; 2] {
    match instr {
        Instr::Block(b) => [Some(b.seq), None],
        Instr::Loop(l) => [Some(l.seq), None],
        Instr::IfElse(ie) => [Some(ie.consequent), Some(ie.alternative)],
        _ => [None, None],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Restructure {
    Linearized,
    Relooped { count: usize, walled: usize },
    WalledBranching,
    NotFlattened,
}

fn restructure_one(func: &mut LocalFunction, elidable: &ElidableCells) -> Restructure {
    let Some(plan): Option<Dispatcher> = detect_dispatcher(func) else {
        return match super::reloop::try_reloop(func, elidable) {
            super::reloop::ReloopOutcome::Restructured { count, walled } => {
                Restructure::Relooped { count, walled }
            }
            super::reloop::ReloopOutcome::Walled(_) => Restructure::WalledBranching,
            super::reloop::ReloopOutcome::NotApplicable => Restructure::NotFlattened,
        };
    };
    let Some(flow): Option<ExecutionPlan> = execution_plan(&plan) else {
        return match super::reloop::try_reloop(func, elidable) {
            super::reloop::ReloopOutcome::Restructured { count, walled } => {
                Restructure::Relooped { count, walled }
            }
            super::reloop::ReloopOutcome::Walled(_)
            | super::reloop::ReloopOutcome::NotApplicable => Restructure::WalledBranching,
        };
    };
    rewrite_entry(func, &plan, &flow);
    Restructure::Linearized
}

type Body = Vec<(Instr, walrus::ir::InstrLocId)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseExit {
    Next(i32),
    Return,
    FallThrough,
    Unresolved,
}

#[derive(Debug, Clone)]
struct CaseBody {
    body: Body,
    exit: CaseExit,
}

#[derive(Debug, Clone)]
struct Dispatcher {
    state_local: LocalId,
    entry_state: i32,
    cases: BTreeMap<i32, CaseBody>,
    container: InstrSeqId,
    loop_seq: InstrSeqId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExecutionPlan {
    Linear(Vec<i32>),
    Cycle { prefix: Vec<i32>, cycle: Vec<i32> },
}

fn detect_dispatcher(func: &LocalFunction) -> Option<Dispatcher> {
    let site: DispatchSite = find_dispatch_site(func)?;
    let loop_body: &Body = &func.block(site.loop_seq).instrs;
    let outer_block: InstrSeqId = single_inner_block(loop_body)?;
    let layers: Vec<Layer> = peel_switch_layers(func, outer_block)?;
    let switch: &Layer = layers.last()?;
    let (targets, switch_local): (Vec<InstrSeqId>, LocalId) = match &switch.kind {
        LayerKind::Switch { targets, local } => (targets.clone(), *local),
        LayerKind::Tail(_) => return None,
    };
    if switch_local != site.state_local {
        return None;
    }
    let has_tail: bool = layers
        .iter()
        .any(|layer| matches!(layer.kind, LayerKind::Tail(_)));
    let mut block_to_body: BTreeMap<InstrSeqId, Body> = map_blocks_to_bodies(&layers);
    block_to_body.insert(outer_block, tail_after_block(loop_body, outer_block));
    let mut cases: BTreeMap<i32, CaseBody> = BTreeMap::new();
    for (state, target_block) in targets.iter().enumerate() {
        let body: Body = block_to_body.get(target_block).cloned().unwrap_or_default();
        let case: CaseBody = lift_case(func, body, site.state_local, site.loop_seq);
        let state_i32: i32 = i32::try_from(state).ok()?;
        cases.insert(state_i32, case);
    }
    if cases.is_empty() || !has_tail {
        return None;
    }
    Some(Dispatcher {
        state_local: site.state_local,
        entry_state: site.entry_state,
        cases,
        container: site.container,
        loop_seq: site.loop_seq,
    })
}

#[derive(Debug, Clone, Copy)]
struct DispatchSite {
    state_local: LocalId,
    entry_state: i32,
    container: InstrSeqId,
    loop_seq: InstrSeqId,
}

fn find_dispatch_site(func: &LocalFunction) -> Option<DispatchSite> {
    let entry: InstrSeqId = func.entry_block();
    let entry_instrs: &Body = &func.block(entry).instrs;
    let (state_local, entry_state): (LocalId, i32) = find_state_init(entry_instrs)?;
    let entry_loop: Option<InstrSeqId> = direct_loop(entry_instrs);
    if let Some(loop_seq) = entry_loop {
        return Some(DispatchSite {
            state_local,
            entry_state,
            container: entry,
            loop_seq,
        });
    }
    let wrapper: InstrSeqId = single_inner_block(entry_instrs)?;
    let loop_seq: InstrSeqId = direct_loop(&func.block(wrapper).instrs)?;
    Some(DispatchSite {
        state_local,
        entry_state,
        container: wrapper,
        loop_seq,
    })
}

fn direct_loop(instrs: &Body) -> Option<InstrSeqId> {
    instrs.iter().find_map(|(instr, _)| match instr {
        Instr::Loop(l) => Some(l.seq),
        _ => None,
    })
}

#[derive(Debug, Clone)]
struct Layer {
    block: InstrSeqId,
    kind: LayerKind,
}

#[derive(Debug, Clone)]
enum LayerKind {
    Tail(Body),
    Switch {
        targets: Vec<InstrSeqId>,
        local: LocalId,
    },
}

fn peel_switch_layers(func: &LocalFunction, outer: InstrSeqId) -> Option<Vec<Layer>> {
    let mut layers: Vec<Layer> = Vec::new();
    let mut current: InstrSeqId = outer;
    let mut depth: usize = 0;
    loop {
        depth += 1;
        if depth > 128 {
            return None;
        }
        let instrs: &Body = &func.block(current).instrs;
        if let Some((targets, local)) = brtable_targets(instrs) {
            layers.push(Layer {
                block: current,
                kind: LayerKind::Switch { targets, local },
            });
            return Some(layers);
        }
        let inner: InstrSeqId = first_inner_block(instrs)?;
        let tail: Body = tail_after_block(instrs, inner);
        layers.push(Layer {
            block: current,
            kind: LayerKind::Tail(tail),
        });
        current = inner;
    }
}

fn map_blocks_to_bodies(layers: &[Layer]) -> BTreeMap<InstrSeqId, Body> {
    let mut out: BTreeMap<InstrSeqId, Body> = BTreeMap::new();
    for window in layers.windows(2) {
        let outer: &Layer = &window[0];
        let inner: &Layer = &window[1];
        if let LayerKind::Tail(body) = &outer.kind {
            out.insert(inner.block, body.clone());
        }
    }
    out
}

fn find_state_init(instrs: &Body) -> Option<(LocalId, i32)> {
    let mut last_const: Option<i32> = None;
    let mut state_local: Option<(LocalId, i32)> = None;
    for (instr, _) in instrs {
        match instr {
            Instr::Const(c) => {
                if let Value::I32(v) = c.value {
                    last_const = Some(v);
                }
            }
            Instr::LocalSet(ls) => {
                if let Some(v) = last_const.take() {
                    state_local = Some((ls.local, v));
                }
            }
            Instr::Loop(_) | Instr::Block(_) => return state_local,
            _ => last_const = None,
        }
    }
    state_local
}

fn single_inner_block(instrs: &Body) -> Option<InstrSeqId> {
    let mut found: Option<InstrSeqId> = None;
    for (instr, _) in instrs {
        if let Instr::Block(b) = instr {
            if found.is_some() {
                return None;
            }
            found = Some(b.seq);
        }
    }
    found
}

fn first_inner_block(instrs: &Body) -> Option<InstrSeqId> {
    instrs.iter().find_map(|(instr, _)| match instr {
        Instr::Block(b) => Some(b.seq),
        _ => None,
    })
}

fn tail_after_block(instrs: &Body, inner: InstrSeqId) -> Body {
    let mut after: bool = false;
    let mut out: Body = Vec::new();
    for (instr, loc) in instrs {
        if after {
            out.push((instr.clone(), *loc));
            continue;
        }
        if matches!(instr, Instr::Block(b) if b.seq == inner) {
            after = true;
        }
    }
    out
}

fn brtable_targets(instrs: &Body) -> Option<(Vec<InstrSeqId>, LocalId)> {
    let mut local: Option<LocalId> = None;
    for (instr, _) in instrs {
        match instr {
            Instr::LocalGet(lg) => local = Some(lg.local),
            Instr::BrTable(bt) => {
                let targets: Vec<InstrSeqId> = bt.blocks.to_vec();
                return Some((targets, local?));
            }
            Instr::Block(_) => {}
            _ => local = None,
        }
    }
    None
}

fn lift_case(
    func: &LocalFunction,
    instrs: Body,
    state_local: LocalId,
    loop_seq: InstrSeqId,
) -> CaseBody {
    let mut body: Body = Vec::new();
    let mut next_state: Option<i32> = None;
    let mut last_const: Option<i32> = None;
    let mut returns: bool = false;
    let mut unresolved: bool = false;
    let mut pending_set: Option<usize> = None;
    for (instr, loc) in instrs {
        for child in child_seqs(&instr).into_iter().flatten() {
            if !nested_is_transparent(func, child, state_local) {
                unresolved = true;
            }
        }
        match &instr {
            Instr::Const(c) => {
                if let Value::I32(v) = c.value {
                    last_const = Some(v);
                }
                body.push((instr, loc));
            }
            Instr::LocalSet(ls) if ls.local == state_local => {
                next_state = last_const.take();
                pending_set = Some(body.len());
                body.push((instr, loc));
            }
            Instr::Br(br) if br.block == loop_seq => {
                if let Some(set_idx) = pending_set.take() {
                    truncate_state_write(&mut body, set_idx);
                }
                let exit: CaseExit = match next_state {
                    Some(state) if !unresolved => CaseExit::Next(state),
                    Some(_) | None => CaseExit::Unresolved,
                };
                return CaseBody { body, exit };
            }
            Instr::Br(_) | Instr::BrIf(_) | Instr::BrTable(_) => {
                unresolved = true;
                last_const = None;
                body.push((instr, loc));
            }
            Instr::Return(_) => {
                returns = true;
                body.push((instr, loc));
            }
            _ => {
                last_const = None;
                body.push((instr, loc));
            }
        }
    }
    CaseBody {
        body,
        exit: trailing_exit(unresolved, next_state, returns),
    }
}

const fn trailing_exit(unresolved: bool, next_state: Option<i32>, returns: bool) -> CaseExit {
    if unresolved {
        return CaseExit::Unresolved;
    }
    match next_state {
        Some(state) => CaseExit::Next(state),
        None if returns => CaseExit::Return,
        None => CaseExit::FallThrough,
    }
}

fn nested_is_transparent(func: &LocalFunction, root: InstrSeqId, state_local: LocalId) -> bool {
    let Some(inside): Option<BTreeSet<InstrSeqId>> = reachable_seqs(func, root) else {
        return false;
    };
    inside.iter().all(|seq: &InstrSeqId| {
        func.block(*seq)
            .instrs
            .iter()
            .all(|(instr, _)| nested_instr_is_transparent(instr, &inside, state_local))
    })
}

fn nested_instr_is_transparent(
    instr: &Instr,
    inside: &BTreeSet<InstrSeqId>,
    state_local: LocalId,
) -> bool {
    match instr {
        Instr::Br(br) => inside.contains(&br.block),
        Instr::BrIf(br) => inside.contains(&br.block),
        Instr::BrTable(bt) => {
            inside.contains(&bt.default) && bt.blocks.iter().all(|b| inside.contains(b))
        }
        Instr::LocalSet(set) => set.local != state_local,
        Instr::LocalTee(tee) => tee.local != state_local,
        _ => true,
    }
}

fn truncate_state_write(body: &mut Body, set_idx: usize) {
    if set_idx < body.len() && matches!(body[set_idx].0, Instr::LocalSet(_)) {
        body.remove(set_idx);
        if set_idx > 0 && matches!(body[set_idx - 1].0, Instr::Const(_)) {
            body.remove(set_idx - 1);
        }
    }
}

#[cfg(test)]
fn linear_order(plan: &Dispatcher) -> Option<Vec<i32>> {
    match execution_plan(plan)? {
        ExecutionPlan::Linear(order) => Some(order),
        ExecutionPlan::Cycle { .. } => None,
    }
}

fn execution_plan(plan: &Dispatcher) -> Option<ExecutionPlan> {
    let mut order: Vec<i32> = Vec::new();
    let mut seen: BTreeMap<i32, usize> = BTreeMap::new();
    let mut current: i32 = plan.entry_state;
    let mut guard: usize = 0;
    let limit: usize = plan.cases.len().saturating_add(1);
    loop {
        guard += 1;
        if guard > limit {
            return None;
        }
        let cycle_start: Option<usize> = seen.insert(current, order.len());
        if let Some(cycle_start) = cycle_start {
            return Some(ExecutionPlan::Cycle {
                prefix: order[..cycle_start].to_vec(),
                cycle: order[cycle_start..].to_vec(),
            });
        }
        let Some(case): Option<&CaseBody> = plan.cases.get(&current) else {
            return Some(ExecutionPlan::Linear(order));
        };
        order.push(current);
        match case.exit {
            CaseExit::Unresolved => return None,
            CaseExit::Return | CaseExit::FallThrough => {
                return Some(ExecutionPlan::Linear(order));
            }
            CaseExit::Next(next) => current = next,
        }
    }
}

fn rewrite_entry(func: &mut LocalFunction, plan: &Dispatcher, flow: &ExecutionPlan) {
    let mut linear: Body = Vec::new();
    match flow {
        ExecutionPlan::Linear(order) => {
            append_cases(&mut linear, plan, order);
        }
        ExecutionPlan::Cycle { prefix, cycle } => {
            append_cases(&mut linear, plan, prefix);
            let loop_loc: walrus::ir::InstrLocId = first_case_loc(plan, cycle).unwrap_or_default();
            let loop_id: InstrSeqId = {
                let mut seq: walrus::InstrSeqBuilder<'_> = func
                    .builder_mut()
                    .dangling_instr_seq(InstrSeqType::Simple(None));
                let id: InstrSeqId = seq.id();
                let mut body: Body = cycle_body(plan, cycle, id, loop_loc);
                seq.instrs_mut().append(&mut body);
                id
            };
            linear.push((Instr::Loop(walrus::ir::Loop { seq: loop_id }), loop_loc));
        }
    }
    let entry: InstrSeqId = func.entry_block();
    let (preamble, suffix): (Body, Body) = entry_split(func, entry, plan);
    let seq: &mut walrus::ir::InstrSeq = func.block_mut(entry);
    seq.instrs.clear();
    seq.instrs.extend(preamble);
    seq.instrs.extend(linear);
    seq.instrs.extend(suffix);
}

fn append_cases(out: &mut Body, plan: &Dispatcher, order: &[i32]) {
    for state in order {
        if let Some(case) = plan.cases.get(state) {
            out.extend(case.body.iter().cloned());
        }
    }
}

fn first_case_loc(plan: &Dispatcher, order: &[i32]) -> Option<walrus::ir::InstrLocId> {
    for state in order {
        let case: &CaseBody = plan.cases.get(state)?;
        if let Some((_, loc)) = case.body.first() {
            return Some(*loc);
        }
    }
    None
}

fn cycle_body(
    plan: &Dispatcher,
    order: &[i32],
    loop_id: InstrSeqId,
    loc: walrus::ir::InstrLocId,
) -> Body {
    let mut body: Body = Vec::new();
    append_cases(&mut body, plan, order);
    body.push((Instr::Br(walrus::ir::Br { block: loop_id }), loc));
    body
}

fn entry_split(func: &LocalFunction, entry: InstrSeqId, plan: &Dispatcher) -> (Body, Body) {
    let instrs: &Body = &func.block(entry).instrs;
    let state_local: LocalId = plan.state_local;
    let mut preamble: Body = Vec::new();
    let mut idx: usize = 0;
    while idx < instrs.len() {
        if is_dispatch_region(&instrs[idx].0, plan) {
            break;
        }
        let is_state_init: bool = matches!(&instrs[idx].0, Instr::Const(c) if matches!(c.value, Value::I32(_)))
            && idx + 1 < instrs.len()
            && matches!(&instrs[idx + 1].0, Instr::LocalSet(ls) if ls.local == state_local);
        if is_state_init {
            idx += 2;
            continue;
        }
        preamble.push(instrs[idx].clone());
        idx += 1;
    }
    let suffix: Body = instrs
        .get(idx + 1..)
        .map(<[(Instr, walrus::ir::InstrLocId)]>::to_vec)
        .unwrap_or_default();
    (preamble, suffix)
}

fn is_dispatch_region(instr: &Instr, plan: &Dispatcher) -> bool {
    match instr {
        Instr::Loop(l) => l.seq == plan.loop_seq,
        Instr::Block(b) => b.seq == plan.container,
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn case(exit: CaseExit) -> CaseBody {
        CaseBody {
            body: Vec::new(),
            exit,
        }
    }

    fn scaffold() -> (LocalId, InstrSeqId) {
        use walrus::FunctionBuilder;
        let mut module: Module = Module::default();
        let local: LocalId = module.locals.add(walrus::ValType::I32);
        let builder: FunctionBuilder = FunctionBuilder::new(&mut module.types, &[], &[]);
        let seq: InstrSeqId = builder.func_body_id();
        (local, seq)
    }

    fn plan_with(entry: i32, cases: &[(i32, CaseExit)]) -> Dispatcher {
        let mut map: BTreeMap<i32, CaseBody> = BTreeMap::new();
        for (state, exit) in cases {
            map.insert(*state, case(*exit));
        }
        let (state_local, seq): (LocalId, InstrSeqId) = scaffold();
        Dispatcher {
            state_local,
            entry_state: entry,
            cases: map,
            container: seq,
            loop_seq: seq,
        }
    }

    #[test]
    fn linear_chain_resolves_in_execution_order() {
        let plan: Dispatcher = plan_with(
            0,
            &[
                (0, CaseExit::Next(1)),
                (1, CaseExit::Next(2)),
                (2, CaseExit::Return),
            ],
        );
        let order: Vec<i32> = linear_order(&plan).expect("linear order");
        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn cyclic_state_machine_uses_cycle_plan() {
        let plan: Dispatcher = plan_with(0, &[(0, CaseExit::Next(1)), (1, CaseExit::Next(0))]);
        assert!(linear_order(&plan).is_none(), "cycle must not linearize");
        assert_eq!(
            execution_plan(&plan),
            Some(ExecutionPlan::Cycle {
                prefix: Vec::new(),
                cycle: vec![0, 1],
            })
        );
    }

    #[test]
    fn dangling_next_state_falls_through_to_loop_exit() {
        let plan: Dispatcher = plan_with(0, &[(0, CaseExit::Next(5))]);
        let order: Vec<i32> =
            linear_order(&plan).expect("dangling next routes to br_table default");
        assert_eq!(order, vec![0], "state 5 has no case so it is the loop exit");
    }

    fn module_with_sibling_blocks(count: usize) -> Module {
        let mut text: String = String::from(
            "(module (memory 1) (global (mut i32) (i32.const 0)) (func (export \"f\")",
        );
        for _ in 0..count {
            text.push_str(" (block)");
        }
        text.push_str(" global.get 0 drop i32.const 0 i32.load drop))");
        let bytes: Vec<u8> = wat::parse_str(&text).expect("assemble sibling blocks");
        Module::from_buffer(&bytes).expect("parse sibling blocks")
    }

    #[test]
    fn a_global_scan_that_hits_its_bound_elides_nothing() {
        let within: Module = module_with_sibling_blocks(4);
        assert!(
            elidable_state_globals(&within)
                .values()
                .any(|globals: &BTreeSet<GlobalId>| !globals.is_empty()),
            "a private mutable global touched by one function is elidable"
        );

        let beyond: Module = module_with_sibling_blocks(NESTED_SEQ_LIMIT + 2);
        assert!(
            elidable_state_globals(&beyond).is_empty(),
            "a truncated global scan must not report any global as privately owned"
        );
    }

    #[test]
    fn a_memory_scan_that_hits_its_bound_elides_nothing() {
        let within: Module = module_with_sibling_blocks(4);
        assert!(
            elidable_state_memories(&within)
                .values()
                .any(|memories: &BTreeSet<MemoryId>| !memories.is_empty()),
            "a defined memory touched by one function is elidable"
        );

        let beyond: Module = module_with_sibling_blocks(NESTED_SEQ_LIMIT + 2);
        assert!(
            elidable_state_memories(&beyond).is_empty(),
            "a truncated memory scan must not report any memory as privately owned"
        );
    }

    #[test]
    fn a_memory_a_second_function_touches_is_not_privately_owned() {
        let text: &str = "(module (memory 1) \
            (func (export \"f\") i32.const 0 i32.load drop) \
            (func (export \"g\") i32.const 4 i32.load drop))";
        let bytes: Vec<u8> = wat::parse_str(text).expect("assemble shared memory module");
        let module: Module = Module::from_buffer(&bytes).expect("parse shared memory module");
        assert!(
            elidable_state_memories(&module)
                .values()
                .all(|memories: &BTreeSet<MemoryId>| memories.is_empty()),
            "a memory two functions access belongs to neither"
        );
    }

    #[test]
    fn an_imported_memory_is_never_privately_owned() {
        let text: &str = "(module (import \"env\" \"memory\" (memory 1)) \
            (func (export \"f\") i32.const 0 i32.load drop))";
        let bytes: Vec<u8> = wat::parse_str(text).expect("assemble imported memory module");
        let module: Module = Module::from_buffer(&bytes).expect("parse imported memory module");
        assert!(
            elidable_state_memories(&module)
                .values()
                .all(|memories: &BTreeSet<MemoryId>| memories.is_empty()),
            "an imported memory is owned by the host"
        );
    }

    #[test]
    fn an_unresolved_case_refuses_the_linear_plan() {
        let plan: Dispatcher = plan_with(0, &[(0, CaseExit::Next(1)), (1, CaseExit::Unresolved)]);
        assert_eq!(
            execution_plan(&plan),
            None,
            "a case whose transition is hidden behind control flow must not linearize"
        );
    }

    #[test]
    fn three_state_chain_to_exit_state_linearizes() {
        let plan: Dispatcher = plan_with(
            0,
            &[
                (0, CaseExit::Next(1)),
                (1, CaseExit::Next(2)),
                (2, CaseExit::Next(3)),
            ],
        );
        let order: Vec<i32> = linear_order(&plan).expect("linearize");
        assert_eq!(order, vec![0, 1, 2], "state 3 is the exit default");
    }
}
