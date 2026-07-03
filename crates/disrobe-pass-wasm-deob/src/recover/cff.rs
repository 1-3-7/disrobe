use std::collections::BTreeMap;

use walrus::ir::{Instr, InstrSeqId, InstrSeqType, Value};
use walrus::{FunctionId, FunctionKind, LocalFunction, LocalId, Module};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CffRecovery {
    pub functions_restructured: usize,
    pub conditional_restructured: usize,
    pub walled_branching_dispatchers: usize,
}

pub(super) fn restructure_flattened(module: &mut Module) -> CffRecovery {
    let local_ids: Vec<FunctionId> = module.funcs.iter_local().map(|(id, _)| id).collect();
    let mut recovery: CffRecovery = CffRecovery::default();
    for fid in local_ids {
        let FunctionKind::Local(func): &mut FunctionKind = &mut module.funcs.get_mut(fid).kind
        else {
            continue;
        };
        match restructure_one(func) {
            Restructure::Linearized => recovery.functions_restructured += 1,
            Restructure::Relooped => {
                recovery.functions_restructured += 1;
                recovery.conditional_restructured += 1;
            }
            Restructure::WalledBranching => recovery.walled_branching_dispatchers += 1,
            Restructure::NotFlattened => {}
        }
    }
    recovery
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Restructure {
    Linearized,
    Relooped,
    WalledBranching,
    NotFlattened,
}

fn restructure_one(func: &mut LocalFunction) -> Restructure {
    let Some(plan): Option<Dispatcher> = detect_dispatcher(func) else {
        return match super::reloop::try_reloop(func) {
            super::reloop::ReloopOutcome::Restructured => Restructure::Relooped,
            super::reloop::ReloopOutcome::Walled => Restructure::WalledBranching,
            super::reloop::ReloopOutcome::NotApplicable => Restructure::NotFlattened,
        };
    };
    let Some(flow): Option<ExecutionPlan> = execution_plan(&plan) else {
        return match super::reloop::try_reloop(func) {
            super::reloop::ReloopOutcome::Restructured => Restructure::Relooped,
            _ => Restructure::WalledBranching,
        };
    };
    rewrite_entry(func, &plan, &flow);
    Restructure::Linearized
}

type Body = Vec<(Instr, walrus::ir::InstrLocId)>;

#[derive(Debug, Clone)]
struct CaseBody {
    body: Body,
    next_state: Option<i32>,
    exits: bool,
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
        let case: CaseBody = lift_case(body, site.state_local, site.loop_seq);
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

fn lift_case(instrs: Body, state_local: LocalId, loop_seq: InstrSeqId) -> CaseBody {
    let mut body: Body = Vec::new();
    let mut next_state: Option<i32> = None;
    let mut last_const: Option<i32> = None;
    let mut exits: bool = false;
    let mut pending_set: Option<usize> = None;
    for (instr, loc) in instrs {
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
                return CaseBody {
                    body,
                    next_state,
                    exits: false,
                };
            }
            Instr::Return(_) => {
                exits = true;
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
        next_state,
        exits,
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
        if case.exits {
            return Some(ExecutionPlan::Linear(order));
        }
        match case.next_state {
            Some(next) => current = next,
            None => return Some(ExecutionPlan::Linear(order)),
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

    fn case(next: Option<i32>, exits: bool) -> CaseBody {
        CaseBody {
            body: Vec::new(),
            next_state: next,
            exits,
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

    fn plan_with(entry: i32, cases: &[(i32, Option<i32>, bool)]) -> Dispatcher {
        let mut map: BTreeMap<i32, CaseBody> = BTreeMap::new();
        for (state, next, exits) in cases {
            map.insert(*state, case(*next, *exits));
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
            &[(0, Some(1), false), (1, Some(2), false), (2, None, true)],
        );
        let order: Vec<i32> = linear_order(&plan).expect("linear order");
        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn cyclic_state_machine_uses_cycle_plan() {
        let plan: Dispatcher = plan_with(0, &[(0, Some(1), false), (1, Some(0), false)]);
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
        let plan: Dispatcher = plan_with(0, &[(0, Some(5), false)]);
        let order: Vec<i32> =
            linear_order(&plan).expect("dangling next routes to br_table default");
        assert_eq!(order, vec![0], "state 5 has no case so it is the loop exit");
    }

    #[test]
    fn three_state_chain_to_exit_state_linearizes() {
        let plan: Dispatcher = plan_with(
            0,
            &[
                (0, Some(1), false),
                (1, Some(2), false),
                (2, Some(3), false),
            ],
        );
        let order: Vec<i32> = linear_order(&plan).expect("linearize");
        assert_eq!(order, vec![0, 1, 2], "state 3 is the exit default");
    }
}
