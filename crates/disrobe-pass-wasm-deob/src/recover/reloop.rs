use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg::{Flow, FlowGraph, PostDominator};
use walrus::ir::{
    BinaryOp, Instr, InstrSeqId, InstrSeqType, LegacyCatch, LoadKind, StoreKind, UnaryOp, Value,
};
use walrus::{GlobalId, LocalFunction, LocalId, MemoryId};

use super::opaque::eval_i32_expression_suffix;

type Body = Vec<(Instr, walrus::ir::InstrLocId)>;

const NODE_LIMIT: usize = 512;
const RENDER_GUARD: usize = 4096;
const MULTI_EXIT_LIMIT: usize = 16;
const TRANSITION_INSTRUCTION_LIMIT: usize = 512;
const STATE_EXPRESSION_LIMIT: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WallReason {
    ObservableStateCell,
    UnsupportedTransition,
    UnstructurableStateGraph,
}

impl WallReason {
    const fn name(self) -> &'static str {
        match self {
            Self::ObservableStateCell => "state cell is observable outside the dispatcher",
            Self::UnsupportedTransition => "state transition is not a resolvable constant edge",
            Self::UnstructurableStateGraph => "state graph has no sound structured form",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReloopOutcome {
    Restructured { count: usize, walled: usize },
    Walled(WallReason),
    NotApplicable,
}

#[derive(Debug, Default, Clone)]
pub(super) struct ElidableCells {
    pub(super) globals: BTreeSet<GlobalId>,
    pub(super) memories: BTreeSet<MemoryId>,
    pub(super) fixed_memories: BTreeSet<MemoryId>,
    pub(super) memory_min_bytes: BTreeMap<MemoryId, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RootCandidate {
    sequence: InstrSeqId,
    branch_exits: bool,
}

pub(super) fn try_reloop(func: &mut LocalFunction, elidable: &ElidableCells) -> ReloopOutcome {
    let Some(roots): Option<Vec<RootCandidate>> = nested_roots(func) else {
        return wall(WallReason::UnstructurableStateGraph);
    };
    let mut restructured: usize = 0;
    let mut first_wall: Option<WallReason> = None;
    let mut walled: usize = 0;
    for root in roots {
        match try_reloop_root(func, elidable, root) {
            ReloopOutcome::Restructured {
                count,
                walled: nested_walls,
            } => {
                restructured = restructured.saturating_add(count);
                walled = walled.saturating_add(nested_walls);
            }
            ReloopOutcome::Walled(reason) => {
                first_wall.get_or_insert(reason);
                walled = walled.saturating_add(1);
            }
            ReloopOutcome::NotApplicable => {}
        }
    }
    if restructured != 0 {
        return ReloopOutcome::Restructured {
            count: restructured,
            walled,
        };
    }
    first_wall.map_or(ReloopOutcome::NotApplicable, ReloopOutcome::Walled)
}

fn try_reloop_root(
    func: &mut LocalFunction,
    elidable: &ElidableCells,
    root: RootCandidate,
) -> ReloopOutcome {
    let Some(mut disp): Option<Dispatcher> = detect(func, root) else {
        return ReloopOutcome::NotApplicable;
    };
    if !cell_is_elidable(func, &disp, elidable) {
        return wall(WallReason::ObservableStateCell);
    }
    disp.remove_address_setup();
    let Some(graph): Option<Graph> = build_graph(func, &disp) else {
        return wall(WallReason::UnsupportedTransition);
    };
    let Some(tree): Option<SNode> = structure(&graph) else {
        return wall(WallReason::UnstructurableStateGraph);
    };
    if !emit(func, root.sequence, &disp, &graph, &tree) {
        return wall(WallReason::UnstructurableStateGraph);
    }
    ReloopOutcome::Restructured {
        count: 1,
        walled: 0,
    }
}

fn nested_roots(func: &LocalFunction) -> Option<Vec<RootCandidate>> {
    let entry: InstrSeqId = func.entry_block();
    let mut pending: Vec<(RootCandidate, bool)> = vec![(
        RootCandidate {
            sequence: entry,
            branch_exits: false,
        },
        false,
    )];
    let mut seen: BTreeSet<InstrSeqId> = BTreeSet::new();
    let mut roots: Vec<RootCandidate> = Vec::new();
    while let Some((candidate, expanded)) = pending.pop() {
        if expanded {
            roots.push(candidate);
            continue;
        }
        let sequence: InstrSeqId = candidate.sequence;
        if !seen.insert(sequence) {
            continue;
        }
        if seen.len() > NODE_LIMIT {
            return None;
        }
        pending.push((candidate, true));
        let body: &Body = &func.block(sequence).instrs;
        let mut children: Vec<InstrSeqId> = Vec::new();
        for (instruction, _location) in body {
            if !push_nested_sequences(instruction, &mut children, NODE_LIMIT) {
                return None;
            }
        }
        for child in children.into_iter().rev() {
            let branch_exits: bool = body.iter().any(|(instruction, _location)| {
                matches!(instruction, Instr::Block(block) if block.seq == child)
                    || matches!(instruction, Instr::IfElse(if_else) if if_else.consequent == child || if_else.alternative == child)
            });
            pending.push((
                RootCandidate {
                    sequence: child,
                    branch_exits,
                },
                false,
            ));
        }
    }
    Some(roots)
}

fn wall(reason: WallReason) -> ReloopOutcome {
    crate::debug::dbg_kv("unflatten-wall", || reason.name().to_owned());
    ReloopOutcome::Walled(reason)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateCell {
    Local(LocalId),
    Global(GlobalId),
    MemorySlot {
        address: MemoryAddress,
        memory: MemoryId,
        offset: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryAddress {
    Local(LocalId),
    LocalOffset { local: LocalId, offset: u32 },
    Fixed(i32),
}

impl MemoryAddress {
    fn expression_suffix(
        body: &[(Instr, walrus::ir::InstrLocId)],
        end: usize,
    ) -> Option<(Self, usize)> {
        let last_index: usize = end.checked_sub(1)?;
        if matches!(&body.get(last_index)?.0, Instr::Binop(binary) if matches!(binary.op, BinaryOp::I32Add))
        {
            let constant_index: usize = last_index.checked_sub(1)?;
            let local_index: usize = constant_index.checked_sub(1)?;
            let Instr::Const(constant) = &body.get(constant_index)?.0 else {
                return None;
            };
            let Value::I32(offset) = constant.value else {
                return None;
            };
            let offset: u32 = u32::try_from(offset).ok()?;
            let Instr::LocalGet(get) = &body.get(local_index)?.0 else {
                return None;
            };
            return Some((
                Self::LocalOffset {
                    local: get.local,
                    offset,
                },
                local_index,
            ));
        }
        if let Instr::LocalGet(get) = &body.get(last_index)?.0 {
            return Some((Self::Local(get.local), last_index));
        }
        let expression_floor: usize = end.saturating_sub(STATE_EXPRESSION_LIMIT);
        let expression: Vec<Instr> = body
            .get(expression_floor..end)?
            .iter()
            .map(|(instr, _location): &(Instr, walrus::ir::InstrLocId)| instr.clone())
            .collect();
        let (value, relative_start): (i32, usize) =
            eval_i32_expression_suffix(&expression, expression.len(), STATE_EXPRESSION_LIMIT)?;
        let start: usize = expression_floor.checked_add(relative_start)?;
        Some((Self::Fixed(value), start))
    }

    fn matching_expression_start(
        self,
        body: &[(Instr, walrus::ir::InstrLocId)],
        end: usize,
    ) -> Option<usize> {
        let (candidate, start): (Self, usize) = Self::expression_suffix(body, end)?;
        (candidate == self).then_some(start)
    }
}

impl StateCell {
    fn address_expression_start(
        self,
        body: &[(Instr, walrus::ir::InstrLocId)],
        end: usize,
    ) -> Option<usize> {
        match self {
            Self::MemorySlot { address, .. } => address.matching_expression_start(body, end),
            Self::Local(_) | Self::Global(_) => Some(end),
        }
    }

    fn commit_matches(self, instr: &Instr) -> bool {
        match self {
            Self::Local(local) => matches!(instr, Instr::LocalSet(set) if set.local == local),
            Self::Global(global) => matches!(instr, Instr::GlobalSet(set) if set.global == global),
            Self::MemorySlot { memory, offset, .. } => matches!(
                instr,
                Instr::Store(store)
                    if store.memory == memory
                        && store.arg.offset == offset
                        && matches!(store.kind, StoreKind::I32 { atomic: false })
            ),
        }
    }

    fn read_matches(self, instr: &Instr) -> bool {
        match self {
            Self::Local(local) => {
                matches!(instr, Instr::LocalGet(get) if get.local == local)
                    || matches!(instr, Instr::LocalTee(tee) if tee.local == local)
            }
            Self::Global(global) => matches!(instr, Instr::GlobalGet(get) if get.global == global),
            Self::MemorySlot { memory, offset, .. } => {
                matches!(instr, Instr::Load(load) if load.memory == memory && load.arg.offset == offset)
            }
        }
    }

    fn write_matches(self, instr: &Instr) -> bool {
        match self {
            Self::Local(local) => {
                matches!(instr, Instr::LocalSet(set) if set.local == local)
                    || matches!(instr, Instr::LocalTee(tee) if tee.local == local)
            }
            Self::Global(global) => matches!(instr, Instr::GlobalSet(set) if set.global == global),
            Self::MemorySlot { memory, offset, .. } => {
                matches!(instr, Instr::Store(store) if store.memory == memory && store.arg.offset == offset)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selector {
    Local(LocalId),
    Global(GlobalId),
}

#[derive(Debug, Clone)]
struct Dispatcher {
    root: InstrSeqId,
    root_branch_exits: bool,
    preamble: Body,
    suffix: Body,
    entry_state: i32,
    cell: StateCell,
    address_setup: Option<std::ops::Range<usize>>,
    local_address_in_bounds: bool,
    transition_cell: StateCell,
    latch_work: Body,
    branch_transitions: BTreeMap<InstrSeqId, (i32, Body)>,
    case_count: u32,
    default_state: i32,
    state_to_body: BTreeMap<i32, Body>,
}

impl Dispatcher {
    fn remove_address_setup(&mut self) {
        if let Some(range) = self.address_setup.take() {
            drop(self.preamble.drain(range));
        }
    }
}

fn cell_is_elidable(func: &LocalFunction, disp: &Dispatcher, elidable: &ElidableCells) -> bool {
    if disp.transition_cell != disp.cell {
        return spilled_cells_are_owned(func, disp, elidable);
    }
    state_cell_is_elidable(
        func,
        disp,
        elidable,
        disp.cell,
        disp.local_address_in_bounds,
    )
}

fn spilled_cells_are_owned(
    func: &LocalFunction,
    disp: &Dispatcher,
    elidable: &ElidableCells,
) -> bool {
    let owned_by_dispatcher: bool = match (disp.cell, disp.transition_cell) {
        (
            StateCell::MemorySlot {
                address: MemoryAddress::Local(left),
                memory: left_memory,
                ..
            },
            StateCell::MemorySlot {
                address: MemoryAddress::Local(right),
                memory: right_memory,
                ..
            },
        ) if left == right && left_memory == right_memory => {
            elidable.memories.contains(&left_memory)
                && stable_local_address(func, &disp.preamble, left, &elidable.globals)
        }
        (
            StateCell::MemorySlot {
                address: MemoryAddress::Fixed(left),
                memory: left_memory,
                ..
            },
            StateCell::MemorySlot {
                address: MemoryAddress::Fixed(right),
                memory: right_memory,
                ..
            },
        ) if left == right && left_memory == right_memory => {
            elidable.fixed_memories.contains(&left_memory)
        }
        _ => false,
    };
    owned_by_dispatcher
        && !accesses_cell(func, &disp.suffix, disp.cell)
        && !accesses_cell(func, &disp.suffix, disp.transition_cell)
        && !accesses_cell_outside_root(func, disp.root, disp.cell)
        && !accesses_cell_outside_root(func, disp.root, disp.transition_cell)
        && cell_access_count(func, disp.cell, StateCell::read_matches) == Some(1)
        && cell_access_count(func, disp.transition_cell, StateCell::read_matches) == Some(1)
}

fn state_cell_is_elidable(
    func: &LocalFunction,
    disp: &Dispatcher,
    elidable: &ElidableCells,
    cell: StateCell,
    local_address_in_bounds: bool,
) -> bool {
    let owned_by_dispatcher: bool = match cell {
        StateCell::Local(_) => true,
        StateCell::Global(global) => elidable.globals.contains(&global),
        StateCell::MemorySlot {
            address,
            memory,
            offset,
            ..
        } => match address {
            MemoryAddress::Local(local) => {
                elidable.memories.contains(&memory)
                    && stable_local_address(func, &disp.preamble, local, &elidable.globals)
                    && resolved_local_address(&disp.preamble, local).map_or_else(
                        || local_address_in_bounds,
                        |value: i32| {
                            memory_address_is_in_bounds(
                                value,
                                offset,
                                &elidable.memory_min_bytes,
                                memory,
                            )
                        },
                    )
            }
            MemoryAddress::LocalOffset {
                local,
                offset: address_offset,
            } => {
                let Some((base, _setup)): Option<(i32, std::ops::Range<usize>)> =
                    constant_local_setup(&disp.preamble, local)
                else {
                    return false;
                };
                disp.address_setup.is_some()
                    && elidable.fixed_memories.contains(&memory)
                    && memory_address_with_offset_is_in_bounds(
                        base,
                        address_offset,
                        offset,
                        &elidable.memory_min_bytes,
                        memory,
                    )
                    && local_offset_accesses_are_exclusive(func, cell, base)
            }
            MemoryAddress::Fixed(value) => {
                elidable.fixed_memories.contains(&memory)
                    && memory_address_is_in_bounds(
                        value,
                        offset,
                        &elidable.memory_min_bytes,
                        memory,
                    )
            }
        },
    };
    owned_by_dispatcher
        && !accesses_cell(func, &disp.suffix, cell)
        && !accesses_cell_outside_root(func, disp.root, cell)
}

fn accesses_cell_outside_root(func: &LocalFunction, root: InstrSeqId, cell: StateCell) -> bool {
    let mut pending: Vec<InstrSeqId> = vec![func.entry_block()];
    let mut seen: BTreeSet<InstrSeqId> = BTreeSet::new();
    let mut remaining: usize = RENDER_GUARD;
    while let Some(sequence) = pending.pop() {
        if sequence == root || !seen.insert(sequence) {
            continue;
        }
        if seen.len() > NODE_LIMIT
            || body_accesses_cell(
                &func.block(sequence).instrs,
                cell,
                &mut pending,
                &mut remaining,
            )
        {
            return true;
        }
    }
    false
}

fn memory_address_is_in_bounds(
    address: i32,
    offset: u32,
    minimums: &BTreeMap<MemoryId, u64>,
    memory: MemoryId,
) -> bool {
    let dynamic: u64 = u64::from(u32::from_ne_bytes(address.to_ne_bytes()));
    dynamic
        .checked_add(u64::from(offset))
        .and_then(|effective: u64| effective.checked_add(4))
        .is_some_and(|end: u64| minimums.get(&memory).is_some_and(|limit| end <= *limit))
}

fn memory_address_with_offset_is_in_bounds(
    base: i32,
    address_offset: u32,
    memory_offset: u32,
    minimums: &BTreeMap<MemoryId, u64>,
    memory: MemoryId,
) -> bool {
    let base: u32 = u32::from_ne_bytes(base.to_ne_bytes());
    base.checked_add(address_offset)
        .and_then(|address: u32| address.checked_add(memory_offset))
        .and_then(|effective: u32| effective.checked_add(4))
        .is_some_and(|end: u32| {
            minimums
                .get(&memory)
                .is_some_and(|limit: &u64| u64::from(end) <= *limit)
        })
}

fn constant_local_setup(
    preamble: &[(Instr, walrus::ir::InstrLocId)],
    local: LocalId,
) -> Option<(i32, std::ops::Range<usize>)> {
    preamble.iter().enumerate().find_map(
        |(index, (instruction, _location)): (usize, &(Instr, walrus::ir::InstrLocId))| {
            if !matches!(instruction, Instr::LocalSet(set) if set.local == local) {
                return None;
            }
            let constant_index: usize = index.checked_sub(1)?;
            let Instr::Const(constant) = &preamble.get(constant_index)?.0 else {
                return None;
            };
            let Value::I32(value) = constant.value else {
                return None;
            };
            Some((value, constant_index..index.checked_add(1)?))
        },
    )
}

struct MemoryAccess {
    memory: MemoryId,
    offset: u32,
    exact_kind: bool,
    expression: Option<(MemoryAddress, usize)>,
}

fn local_offset_accesses_are_exclusive(func: &LocalFunction, cell: StateCell, base: i32) -> bool {
    let StateCell::MemorySlot {
        address:
            MemoryAddress::LocalOffset {
                local,
                offset: address_offset,
            },
        memory,
        offset: memory_offset,
    } = cell
    else {
        return false;
    };
    let Some(target): Option<u32> = effective_address(base, address_offset, memory_offset) else {
        return false;
    };
    let mut pending: Vec<InstrSeqId> = vec![func.entry_block()];
    let mut seen: BTreeSet<InstrSeqId> = BTreeSet::new();
    let mut definitions: usize = 0;
    let mut remaining: usize = RENDER_GUARD;
    while let Some(sequence) = pending.pop() {
        if !seen.insert(sequence) {
            continue;
        }
        if seen.len() > NODE_LIMIT {
            return false;
        }
        let body: &Body = &func.block(sequence).instrs;
        let mut admitted_gets: BTreeSet<usize> = BTreeSet::new();
        for (index, (instruction, _location)) in body.iter().enumerate() {
            let Some(next_remaining): Option<usize> = remaining.checked_sub(1) else {
                return false;
            };
            remaining = next_remaining;
            if matches!(instruction, Instr::LocalSet(set) if set.local == local)
                || matches!(instruction, Instr::LocalTee(tee) if tee.local == local)
            {
                definitions = definitions.saturating_add(1);
                if definitions > 1 {
                    return false;
                }
            }
            let access: Option<MemoryAccess> = match instruction {
                Instr::Load(load) => Some(MemoryAccess {
                    memory: load.memory,
                    offset: load.arg.offset,
                    exact_kind: matches!(load.kind, LoadKind::I32 { atomic: false }),
                    expression: MemoryAddress::expression_suffix(body, index),
                }),
                Instr::Store(store) => {
                    let address_end: Option<usize> = stack_expression_start(body, index);
                    Some(MemoryAccess {
                        memory: store.memory,
                        offset: store.arg.offset,
                        exact_kind: matches!(store.kind, StoreKind::I32 { atomic: false }),
                        expression: address_end
                            .and_then(|end: usize| MemoryAddress::expression_suffix(body, end)),
                    })
                }
                _ => None,
            };
            if let Some(MemoryAccess {
                memory: access_memory,
                offset: access_offset,
                exact_kind,
                expression,
            }) = access
                && access_memory == memory
            {
                let Some((candidate, start)): Option<(MemoryAddress, usize)> = expression else {
                    return false;
                };
                let Some(effective): Option<u32> =
                    candidate.effective_address(base, local, access_offset)
                else {
                    return false;
                };
                if candidate.uses_local(local) {
                    if candidate
                        != (MemoryAddress::LocalOffset {
                            local,
                            offset: address_offset,
                        })
                        || access_offset != memory_offset
                        || !exact_kind
                    {
                        return false;
                    }
                    admitted_gets.insert(start);
                }
                if effective == target
                    && (candidate
                        != (MemoryAddress::LocalOffset {
                            local,
                            offset: address_offset,
                        })
                        || access_offset != memory_offset
                        || !exact_kind)
                {
                    return false;
                }
            }
            let node_capacity: usize = NODE_LIMIT.saturating_sub(seen.len());
            if !push_nested_sequences(instruction, &mut pending, node_capacity) {
                return false;
            }
        }
        if body
            .iter()
            .enumerate()
            .any(|(index, (instruction, _location))| {
                matches!(instruction, Instr::LocalGet(get) if get.local == local)
                    && !admitted_gets.contains(&index)
            })
        {
            return false;
        }
    }
    definitions == 1
}

fn effective_address(base: i32, address_offset: u32, memory_offset: u32) -> Option<u32> {
    u32::from_ne_bytes(base.to_ne_bytes())
        .checked_add(address_offset)?
        .checked_add(memory_offset)
}

impl MemoryAddress {
    fn uses_local(self, local: LocalId) -> bool {
        matches!(self, Self::Local(candidate) if candidate == local)
            || matches!(self, Self::LocalOffset { local: candidate, .. } if candidate == local)
    }

    fn effective_address(self, base: i32, local: LocalId, memory_offset: u32) -> Option<u32> {
        match self {
            Self::Local(candidate) if candidate == local => {
                effective_address(base, 0, memory_offset)
            }
            Self::LocalOffset {
                local: candidate,
                offset,
            } if candidate == local => effective_address(base, offset, memory_offset),
            Self::Fixed(value) => effective_address(value, 0, memory_offset),
            Self::Local(_) | Self::LocalOffset { .. } => None,
        }
    }
}

fn stable_local_address(
    func: &LocalFunction,
    preamble: &[(Instr, walrus::ir::InstrLocId)],
    local: LocalId,
    allowed_globals: &BTreeSet<GlobalId>,
) -> bool {
    let mut pending: Vec<InstrSeqId> = vec![func.entry_block()];
    let mut seen: BTreeSet<InstrSeqId> = BTreeSet::new();
    let mut definitions: usize = 0;
    let mut remaining: usize = RENDER_GUARD;
    while let Some(sequence) = pending.pop() {
        if !seen.insert(sequence) {
            continue;
        }
        if seen.len() > NODE_LIMIT {
            return false;
        }
        for (instr, _location) in &func.block(sequence).instrs {
            let Some(next_remaining) = remaining.checked_sub(1) else {
                return false;
            };
            remaining = next_remaining;
            if matches!(instr, Instr::LocalSet(set) if set.local == local)
                || matches!(instr, Instr::LocalTee(tee) if tee.local == local)
            {
                let Some(next_definitions) = definitions.checked_add(1) else {
                    return false;
                };
                definitions = next_definitions;
                if definitions > 1 {
                    return false;
                }
            }
            let node_capacity: usize = NODE_LIMIT.saturating_sub(seen.len());
            if !push_nested_sequences(instr, &mut pending, node_capacity) {
                return false;
            }
        }
    }
    if definitions != 1 {
        return false;
    }
    preamble.iter().enumerate().any(
        |(index, (instr, _location)): (usize, &(Instr, walrus::ir::InstrLocId))| {
            matches!(instr, Instr::LocalSet(set) if set.local == local)
                && stable_address_expression_start(preamble, index, allowed_globals).is_some()
        },
    )
}

fn stable_address_expression_start(
    body: &[(Instr, walrus::ir::InstrLocId)],
    end: usize,
    allowed_globals: &BTreeSet<GlobalId>,
) -> Option<usize> {
    let mut cursor: usize = end;
    let mut budget: usize = STATE_EXPRESSION_LIMIT;
    stable_address_value(body, &mut cursor, &mut budget, allowed_globals)?;
    Some(cursor)
}

fn stable_address_value(
    body: &[(Instr, walrus::ir::InstrLocId)],
    cursor: &mut usize,
    budget: &mut usize,
    allowed_globals: &BTreeSet<GlobalId>,
) -> Option<()> {
    if *cursor == 0 || *budget == 0 {
        return None;
    }
    *budget -= 1;
    let index: usize = cursor.checked_sub(1)?;
    match &body.get(index)?.0 {
        Instr::Const(constant) if matches!(constant.value, Value::I32(_)) => {
            *cursor = index;
            Some(())
        }
        Instr::GlobalGet(get) if allowed_globals.contains(&get.global) => {
            *cursor = index;
            Some(())
        }
        Instr::Unop(unary) if selector_unary_op_is_inert(unary.op) => {
            *cursor = index;
            stable_address_value(body, cursor, budget, allowed_globals)
        }
        Instr::Binop(binary) if selector_binary_op_is_inert(binary.op) => {
            *cursor = index;
            stable_address_value(body, cursor, budget, allowed_globals)?;
            stable_address_value(body, cursor, budget, allowed_globals)
        }
        _ => None,
    }
}

fn resolved_local_address(body: &[(Instr, walrus::ir::InstrLocId)], local: LocalId) -> Option<i32> {
    body.iter().enumerate().find_map(
        |(index, (instr, _location)): (usize, &(Instr, walrus::ir::InstrLocId))| {
            matches!(instr, Instr::LocalSet(set) if set.local == local)
                .then(|| resolved_address_expression(body, index))
                .flatten()
        },
    )
}

fn resolved_address_expression(
    body: &[(Instr, walrus::ir::InstrLocId)],
    end: usize,
) -> Option<i32> {
    let expression_floor: usize = end.saturating_sub(STATE_EXPRESSION_LIMIT);
    let expression: Vec<Instr> = body
        .get(expression_floor..end)?
        .iter()
        .map(|(instr, _location): &(Instr, walrus::ir::InstrLocId)| instr.clone())
        .collect();
    let (value, _relative_start): (i32, usize) =
        eval_i32_expression_suffix(&expression, expression.len(), STATE_EXPRESSION_LIMIT)?;
    Some(value)
}

fn preamble_proves_local_address_in_bounds(
    body: &[(Instr, walrus::ir::InstrLocId)],
    before: usize,
    local: LocalId,
    memory: MemoryId,
    offset: u32,
) -> bool {
    let Some(required_end): Option<u32> = offset.checked_add(4) else {
        return false;
    };
    body.get(..before)
        .is_some_and(|prefix: &[(Instr, walrus::ir::InstrLocId)]| {
            prefix.iter().enumerate().any(
                |(index, (instr, _location)): (usize, &(Instr, walrus::ir::InstrLocId))| {
                    let Instr::Store(store) = instr else {
                        return false;
                    };
                    if store.memory != memory
                        || !matches!(store.kind, StoreKind::I32 { atomic: false })
                    {
                        return false;
                    }
                    let Some(access_end): Option<u32> = store.arg.offset.checked_add(4) else {
                        return false;
                    };
                    let Some(value_start): Option<usize> = stack_expression_start(prefix, index)
                    else {
                        return false;
                    };
                    access_end >= required_end
                        && MemoryAddress::Local(local)
                            .matching_expression_start(prefix, value_start)
                            .is_some()
                },
            )
        })
}

fn stack_expression_start(body: &[(Instr, walrus::ir::InstrLocId)], end: usize) -> Option<usize> {
    let mut cursor: usize = end;
    let mut budget: usize = STATE_EXPRESSION_LIMIT;
    stack_expression_value(body, &mut cursor, &mut budget)?;
    Some(cursor)
}

fn stack_expression_value(
    body: &[(Instr, walrus::ir::InstrLocId)],
    cursor: &mut usize,
    budget: &mut usize,
) -> Option<()> {
    if *cursor == 0 || *budget == 0 {
        return None;
    }
    *budget -= 1;
    let index: usize = cursor.checked_sub(1)?;
    match &body.get(index)?.0 {
        Instr::Const(_) | Instr::LocalGet(_) | Instr::GlobalGet(_) => {
            *cursor = index;
            Some(())
        }
        Instr::Unop(_) => {
            *cursor = index;
            stack_expression_value(body, cursor, budget)
        }
        Instr::Binop(_) => {
            *cursor = index;
            stack_expression_value(body, cursor, budget)?;
            stack_expression_value(body, cursor, budget)
        }
        _ => None,
    }
}

fn reads_cell(
    func: &LocalFunction,
    instrs: &[(Instr, walrus::ir::InstrLocId)],
    cell: StateCell,
) -> bool {
    let mut pending: Vec<InstrSeqId> = Vec::new();
    let mut remaining: usize = RENDER_GUARD;
    let mut seen: BTreeSet<InstrSeqId> = BTreeSet::new();
    if body_reads_cell(instrs, cell, &mut pending, &mut remaining) {
        return true;
    }
    while let Some(seq) = pending.pop() {
        if !seen.insert(seq) {
            continue;
        }
        if seen.len() > NODE_LIMIT {
            return true;
        }
        if body_reads_cell(&func.block(seq).instrs, cell, &mut pending, &mut remaining) {
            return true;
        }
    }
    false
}

fn accesses_cell(
    func: &LocalFunction,
    instrs: &[(Instr, walrus::ir::InstrLocId)],
    cell: StateCell,
) -> bool {
    let mut pending: Vec<InstrSeqId> = Vec::new();
    let mut remaining: usize = RENDER_GUARD;
    let mut seen: BTreeSet<InstrSeqId> = BTreeSet::new();
    if body_accesses_cell(instrs, cell, &mut pending, &mut remaining) {
        return true;
    }
    while let Some(seq) = pending.pop() {
        if !seen.insert(seq) {
            continue;
        }
        if seen.len() > NODE_LIMIT
            || body_accesses_cell(&func.block(seq).instrs, cell, &mut pending, &mut remaining)
        {
            return true;
        }
    }
    false
}

fn body_reads_cell(
    instrs: &[(Instr, walrus::ir::InstrLocId)],
    cell: StateCell,
    pending: &mut Vec<InstrSeqId>,
    remaining: &mut usize,
) -> bool {
    for (instr, _) in instrs {
        let Some(next_remaining): Option<usize> = remaining.checked_sub(1) else {
            return true;
        };
        *remaining = next_remaining;
        if !push_nested_sequences(instr, pending, NODE_LIMIT) {
            return true;
        }
        if cell.read_matches(instr) {
            return true;
        }
    }
    false
}

fn body_accesses_cell(
    instrs: &[(Instr, walrus::ir::InstrLocId)],
    cell: StateCell,
    pending: &mut Vec<InstrSeqId>,
    remaining: &mut usize,
) -> bool {
    for (instr, _) in instrs {
        let Some(next_remaining): Option<usize> = remaining.checked_sub(1) else {
            return true;
        };
        *remaining = next_remaining;
        if !push_nested_sequences(instr, pending, NODE_LIMIT) {
            return true;
        }
        if cell.read_matches(instr) || cell.write_matches(instr) {
            return true;
        }
    }
    false
}

fn cell_access_count(
    func: &LocalFunction,
    cell: StateCell,
    matches_access: fn(StateCell, &Instr) -> bool,
) -> Option<usize> {
    cell_access_count_in_body(
        func,
        &func.block(func.entry_block()).instrs,
        cell,
        matches_access,
    )
}

fn cell_access_count_in_body(
    func: &LocalFunction,
    instrs: &[(Instr, walrus::ir::InstrLocId)],
    cell: StateCell,
    matches_access: fn(StateCell, &Instr) -> bool,
) -> Option<usize> {
    let mut pending: Vec<InstrSeqId> = Vec::new();
    let mut seen: BTreeSet<InstrSeqId> = BTreeSet::new();
    let mut remaining: usize = RENDER_GUARD;
    let mut count: usize = 0;
    count_cell_accesses(
        instrs,
        cell,
        matches_access,
        &mut pending,
        &mut remaining,
        &mut count,
    )?;
    while let Some(sequence) = pending.pop() {
        if !seen.insert(sequence) {
            continue;
        }
        if seen.len() > NODE_LIMIT {
            return None;
        }
        count_cell_accesses(
            &func.block(sequence).instrs,
            cell,
            matches_access,
            &mut pending,
            &mut remaining,
            &mut count,
        )?;
    }
    Some(count)
}

fn count_cell_accesses(
    instrs: &[(Instr, walrus::ir::InstrLocId)],
    cell: StateCell,
    matches_access: fn(StateCell, &Instr) -> bool,
    pending: &mut Vec<InstrSeqId>,
    remaining: &mut usize,
    count: &mut usize,
) -> Option<()> {
    for (instr, _) in instrs {
        *remaining = remaining.checked_sub(1)?;
        if !push_nested_sequences(instr, pending, NODE_LIMIT) {
            return None;
        }
        if matches_access(cell, instr) {
            *count = count.checked_add(1)?;
        }
    }
    Some(())
}

fn push_nested_sequences(instr: &Instr, pending: &mut Vec<InstrSeqId>, capacity: usize) -> bool {
    match instr {
        Instr::Block(block) => push_nested_sequence(pending, capacity, block.seq),
        Instr::Loop(loop_) => push_nested_sequence(pending, capacity, loop_.seq),
        Instr::IfElse(if_else) => {
            push_nested_sequence(pending, capacity, if_else.consequent)
                && push_nested_sequence(pending, capacity, if_else.alternative)
        }
        Instr::TryTable(try_table) => push_nested_sequence(pending, capacity, try_table.seq),
        Instr::Try(try_) => {
            if !push_nested_sequence(pending, capacity, try_.seq) {
                return false;
            }
            for catch in &try_.catches {
                let handler: InstrSeqId = match catch {
                    LegacyCatch::Catch { handler, .. } | LegacyCatch::CatchAll { handler } => {
                        *handler
                    }
                    LegacyCatch::Delegate { .. } => continue,
                };
                if !push_nested_sequence(pending, capacity, handler) {
                    return false;
                }
            }
            true
        }
        _ => true,
    }
}

fn push_nested_sequence(
    pending: &mut Vec<InstrSeqId>,
    capacity: usize,
    sequence: InstrSeqId,
) -> bool {
    if pending.len() >= capacity {
        return false;
    }
    pending.push(sequence);
    true
}

fn detect(func: &LocalFunction, root: RootCandidate) -> Option<Dispatcher> {
    let entry_instrs: &Body = &func.block(root.sequence).instrs;
    let loop_index: usize = entry_instrs
        .iter()
        .position(|(instr, _)| matches!(instr, Instr::Loop(_)))?;
    let Instr::Loop(dispatch_loop): &Instr = &entry_instrs[loop_index].0 else {
        return None;
    };
    let loop_seq: InstrSeqId = dispatch_loop.seq;
    let loop_body: &Body = &func.block(loop_seq).instrs;

    if !ends_with_branch_to(loop_body, loop_seq) {
        return None;
    }
    let wrapper: InstrSeqId = loop_body.iter().find_map(|(instr, _)| match instr {
        Instr::Block(b) => Some(b.seq),
        _ => None,
    })?;

    let parents: BTreeMap<InstrSeqId, (InstrSeqId, usize)> = build_parent_map(func, root.sequence);
    let (targets, default, selector): (Vec<InstrSeqId>, InstrSeqId, Selector) =
        find_switch(func, wrapper)?;
    let cell: StateCell = resolve_state_cell(loop_body, selector)?;
    let (transition_cell, latch_work): (StateCell, Body) =
        latch_transition_cell(loop_body, cell).unwrap_or((cell, Vec::new()));
    let branch_transitions: BTreeMap<InstrSeqId, (i32, Body)> = if transition_cell == cell {
        BTreeMap::new()
    } else {
        collect_branch_transitions(func, &parents, transition_cell)
    };

    let case_count: u32 = u32::try_from(targets.len()).ok()?;
    let mut state_to_body: BTreeMap<i32, Body> = BTreeMap::new();
    for (state, target) in targets.iter().enumerate() {
        let state_i32: i32 = i32::try_from(state).ok()?;
        let body: Body = case_body(func, *target, &parents)?;
        state_to_body.insert(state_i32, body);
    }
    let default_state: i32 = i32::try_from(case_count).ok()?;
    let default_body: Body = case_body(func, default, &parents)?;
    state_to_body.entry(default_state).or_insert(default_body);

    let mut preamble: Body = entry_instrs[..loop_index].to_vec();
    let suffix: Body = entry_instrs[loop_index + 1..].to_vec();
    let (entry_state, entry_write): (i32, Option<std::ops::Range<usize>>) =
        initial_state(func, &preamble, cell)?;
    let address_setup: Option<std::ops::Range<usize>> = match cell {
        StateCell::MemorySlot {
            address: MemoryAddress::LocalOffset { local, .. },
            ..
        } => constant_local_setup(&preamble, local)
            .map(|(_value, range): (i32, std::ops::Range<usize>)| range)
            .filter(|range: &std::ops::Range<usize>| {
                entry_write
                    .as_ref()
                    .is_some_and(|write: &std::ops::Range<usize>| range.end <= write.start)
            }),
        StateCell::Local(_)
        | StateCell::Global(_)
        | StateCell::MemorySlot {
            address: MemoryAddress::Local(_) | MemoryAddress::Fixed(_),
            ..
        } => None,
    };
    let local_address_in_bounds: bool = match (cell, entry_write.as_ref()) {
        (
            StateCell::MemorySlot {
                address: MemoryAddress::Local(local),
                memory,
                offset,
            },
            Some(span),
        ) => preamble_proves_local_address_in_bounds(&preamble, span.start, local, memory, offset),
        (
            StateCell::Local(_)
            | StateCell::Global(_)
            | StateCell::MemorySlot {
                address: MemoryAddress::LocalOffset { .. } | MemoryAddress::Fixed(_),
                ..
            },
            _,
        )
        | (StateCell::MemorySlot { .. }, None) => false,
    };
    if transition_cell == cell
        && let Some(span) = entry_write
    {
        drop(preamble.drain(span));
    }

    Some(Dispatcher {
        root: root.sequence,
        root_branch_exits: root.branch_exits,
        preamble,
        suffix,
        entry_state,
        cell,
        address_setup,
        local_address_in_bounds,
        transition_cell,
        latch_work,
        branch_transitions,
        case_count,
        default_state,
        state_to_body,
    })
}

fn collect_branch_transitions(
    func: &LocalFunction,
    parents: &BTreeMap<InstrSeqId, (InstrSeqId, usize)>,
    cell: StateCell,
) -> BTreeMap<InstrSeqId, (i32, Body)> {
    parents
        .keys()
        .filter_map(|target: &InstrSeqId| {
            let body: Body = case_body(func, *target, parents)?;
            let transition: &[(Instr, walrus::ir::InstrLocId)] = strip_trailing_branch(&body);
            let state: i32 = state_write_full_expression(transition, cell)?;
            Some((*target, (state, transition.to_vec())))
        })
        .take(NODE_LIMIT)
        .collect()
}

fn latch_transition_cell(loop_body: &Body, destination: StateCell) -> Option<(StateCell, Body)> {
    let StateCell::MemorySlot {
        address: destination_address,
        memory: destination_memory,
        offset: destination_offset,
    } = destination
    else {
        return None;
    };
    let stripped: &[(Instr, walrus::ir::InstrLocId)] = strip_trailing_branch(loop_body);
    let (commit, prefix): (
        &(Instr, walrus::ir::InstrLocId),
        &[(Instr, walrus::ir::InstrLocId)],
    ) = stripped.split_last()?;
    if !destination.commit_matches(&commit.0) {
        return None;
    }
    let load_index: usize = prefix.len().checked_sub(1)?;
    let Instr::Load(load): &Instr = &prefix.get(load_index)?.0 else {
        return None;
    };
    if load.memory != destination_memory
        || !matches!(load.kind, LoadKind::I32 { atomic: false })
        || !i32_offsets_are_disjoint(destination_offset, load.arg.offset)
    {
        return None;
    }
    let (source_address, source_start): (MemoryAddress, usize) =
        MemoryAddress::expression_suffix(prefix, load_index)?;
    if source_address != destination_address {
        return None;
    }
    let destination_start: usize =
        destination_address.matching_expression_start(prefix, source_start)?;
    Some((
        StateCell::MemorySlot {
            address: source_address,
            memory: load.memory,
            offset: load.arg.offset,
        },
        stripped.get(destination_start..)?.to_vec(),
    ))
}

fn i32_offsets_are_disjoint(left: u32, right: u32) -> bool {
    left.checked_add(4).is_some_and(|end: u32| end <= right)
        || right.checked_add(4).is_some_and(|end: u32| end <= left)
}

fn resolve_state_cell(loop_body: &Body, selector: Selector) -> Option<StateCell> {
    match selector {
        Selector::Global(global) => Some(StateCell::Global(global)),
        Selector::Local(temp) => resolve_local_selector(loop_body, temp),
    }
}

fn resolve_local_selector(loop_body: &Body, temp: LocalId) -> Option<StateCell> {
    let definitions: usize = loop_body
        .iter()
        .filter(|(instr, _)| {
            matches!(instr, Instr::LocalSet(set) if set.local == temp)
                || matches!(instr, Instr::LocalTee(tee) if tee.local == temp)
        })
        .count();
    match definitions {
        0 => Some(StateCell::Local(temp)),
        1 => copied_state_cell(loop_body, temp),
        _ => None,
    }
}

fn copied_state_cell(loop_body: &Body, temp: LocalId) -> Option<StateCell> {
    let definition_index: usize = loop_body.iter().position(|(instr, _)| {
        matches!(instr, Instr::LocalSet(set) if set.local == temp)
            || matches!(instr, Instr::LocalTee(tee) if tee.local == temp)
    })?;
    let selector_end: usize = match &loop_body.get(definition_index)?.0 {
        Instr::LocalSet(_) => definition_index.checked_add(1)?,
        Instr::LocalTee(_) => {
            let drop_index: usize = definition_index.checked_add(1)?;
            if !matches!(loop_body.get(drop_index)?.0, Instr::Drop(_)) {
                return None;
            }
            drop_index.checked_add(1)?
        }
        _ => return None,
    };
    let source_index: usize = definition_index.checked_sub(1)?;
    let memory_address: Option<(MemoryAddress, usize)> = match &loop_body.get(source_index)?.0 {
        Instr::Load(_) => Some(MemoryAddress::expression_suffix(loop_body, source_index)?),
        _ => None,
    };
    let source_start: usize = memory_address
        .map_or(source_index, |(_address, start): (MemoryAddress, usize)| {
            start
        });
    if !selector_noise_is_inert(loop_body.get(..source_start)?) {
        return None;
    }
    let wrapper_relative: usize = loop_body
        .get(selector_end..)?
        .iter()
        .position(|(instr, _)| matches!(instr, Instr::Block(_)))?;
    let wrapper_index: usize = selector_end.checked_add(wrapper_relative)?;
    if !selector_noise_is_inert(loop_body.get(selector_end..wrapper_index)?) {
        return None;
    }
    match &loop_body.get(source_index)?.0 {
        Instr::LocalGet(get) => Some(StateCell::Local(get.local)),
        Instr::GlobalGet(get) => Some(StateCell::Global(get.global)),
        Instr::Load(load) => {
            if !matches!(load.kind, LoadKind::I32 { atomic: false }) {
                return None;
            }
            let (address, _address_start): (MemoryAddress, usize) = memory_address?;
            Some(StateCell::MemorySlot {
                address,
                memory: load.memory,
                offset: load.arg.offset,
            })
        }
        _ => None,
    }
}

fn selector_noise_is_inert(instrs: &[(Instr, walrus::ir::InstrLocId)]) -> bool {
    let mut height: usize = 0;
    for (instr, _) in instrs {
        let (pops, pushes): (usize, usize) = match instr {
            Instr::Const(_) | Instr::LocalGet(_) | Instr::GlobalGet(_) => (0, 1),
            Instr::Unop(unary) if selector_unary_op_is_inert(unary.op) => (1, 1),
            Instr::Binop(binary) if selector_binary_op_is_inert(binary.op) => (2, 1),
            Instr::Select(_) => (3, 1),
            Instr::Drop(_) => (1, 0),
            _ => return false,
        };
        let Some(reduced): Option<usize> = height.checked_sub(pops) else {
            return false;
        };
        let Some(next): Option<usize> = reduced.checked_add(pushes) else {
            return false;
        };
        height = next;
    }
    height == 0
}

const fn selector_binary_op_is_inert(op: BinaryOp) -> bool {
    !matches!(
        op,
        BinaryOp::I32DivS
            | BinaryOp::I32DivU
            | BinaryOp::I32RemS
            | BinaryOp::I32RemU
            | BinaryOp::I64DivS
            | BinaryOp::I64DivU
            | BinaryOp::I64RemS
            | BinaryOp::I64RemU
    )
}

const fn selector_unary_op_is_inert(op: UnaryOp) -> bool {
    !matches!(
        op,
        UnaryOp::I32TruncSF32
            | UnaryOp::I32TruncUF32
            | UnaryOp::I32TruncSF64
            | UnaryOp::I32TruncUF64
            | UnaryOp::I64TruncSF32
            | UnaryOp::I64TruncUF32
            | UnaryOp::I64TruncSF64
            | UnaryOp::I64TruncUF64
    )
}

fn ends_with_branch_to(body: &Body, target: InstrSeqId) -> bool {
    body.iter()
        .any(|(instr, _)| matches!(instr, Instr::Br(br) if br.block == target))
}

fn find_switch(
    func: &LocalFunction,
    wrapper: InstrSeqId,
) -> Option<(Vec<InstrSeqId>, InstrSeqId, Selector)> {
    let mut current: InstrSeqId = wrapper;
    let mut depth: usize = 0;
    loop {
        depth += 1;
        if depth > NODE_LIMIT {
            return None;
        }
        let instrs: &Body = &func.block(current).instrs;
        let found: Option<(Vec<InstrSeqId>, InstrSeqId, Selector)> = switch_here(instrs);
        if let Some(result) = found {
            return Some(result);
        }
        let inner: InstrSeqId = instrs.iter().find_map(|(instr, _)| match instr {
            Instr::Block(b) => Some(b.seq),
            _ => None,
        })?;
        current = inner;
    }
}

fn switch_here(instrs: &Body) -> Option<(Vec<InstrSeqId>, InstrSeqId, Selector)> {
    let mut last_read: Option<Selector> = None;
    for (instr, _) in instrs {
        match instr {
            Instr::LocalGet(lg) => last_read = Some(Selector::Local(lg.local)),
            Instr::GlobalGet(gg) => last_read = Some(Selector::Global(gg.global)),
            Instr::BrTable(bt) => {
                return last_read
                    .map(|selector: Selector| (bt.blocks.to_vec(), bt.default, selector));
            }
            Instr::Block(_) => {}
            _ => last_read = None,
        }
    }
    None
}

fn build_parent_map(
    func: &LocalFunction,
    entry: InstrSeqId,
) -> BTreeMap<InstrSeqId, (InstrSeqId, usize)> {
    let mut out: BTreeMap<InstrSeqId, (InstrSeqId, usize)> = BTreeMap::new();
    let mut stack: Vec<InstrSeqId> = vec![entry];
    while let Some(seq_id) = stack.pop() {
        for (idx, (instr, _)) in func.block(seq_id).instrs.iter().enumerate() {
            let child: Option<InstrSeqId> = match instr {
                Instr::Block(b) => Some(b.seq),
                Instr::Loop(l) => Some(l.seq),
                _ => None,
            };
            if let Some(child) = child {
                out.insert(child, (seq_id, idx));
                stack.push(child);
            }
            if let Instr::IfElse(ie) = instr {
                out.insert(ie.consequent, (seq_id, idx));
                out.insert(ie.alternative, (seq_id, idx));
                stack.push(ie.consequent);
                stack.push(ie.alternative);
            }
        }
    }
    out
}

fn case_body(
    func: &LocalFunction,
    target: InstrSeqId,
    parents: &BTreeMap<InstrSeqId, (InstrSeqId, usize)>,
) -> Option<Body> {
    let (parent, index): (InstrSeqId, usize) = *parents.get(&target)?;
    let parent_instrs: &Body = &func.block(parent).instrs;
    Some(parent_instrs.get(index + 1..)?.to_vec())
}

fn initial_state(
    func: &LocalFunction,
    preamble: &Body,
    cell: StateCell,
) -> Option<(i32, Option<std::ops::Range<usize>>)> {
    let mut found: Option<(i32, usize, usize)> = None;
    for end in 1..=preamble.len() {
        if let Some((value, write_start)) = state_write_expression(preamble.get(..end)?, cell) {
            found = Some((value, write_start, end));
        }
    }
    let (value, write_start, write_end): (i32, usize, usize) = found?;
    let entry_write: Option<std::ops::Range<usize>> =
        (!reads_cell(func, preamble.get(write_end..)?, cell)).then_some(write_start..write_end);
    Some((value, entry_write))
}

fn state_write_expression(
    body: &[(Instr, walrus::ir::InstrLocId)],
    cell: StateCell,
) -> Option<(i32, usize)> {
    let (commit, prefix): (
        &(Instr, walrus::ir::InstrLocId),
        &[(Instr, walrus::ir::InstrLocId)],
    ) = body.split_last()?;
    if !cell.commit_matches(&commit.0) {
        return None;
    }
    let expression_floor: usize = prefix.len().saturating_sub(STATE_EXPRESSION_LIMIT);
    let expression: Vec<Instr> = prefix
        .get(expression_floor..)?
        .iter()
        .map(|(instr, _location): &(Instr, walrus::ir::InstrLocId)| instr.clone())
        .collect();
    let (value, relative_start): (i32, usize) =
        eval_i32_expression_suffix(&expression, expression.len(), STATE_EXPRESSION_LIMIT)?;
    let expression_start: usize = expression_floor.checked_add(relative_start)?;
    let write_start: usize = match cell {
        StateCell::MemorySlot { address, .. } => {
            address.matching_expression_start(prefix, expression_start)?
        }
        StateCell::Local(_) | StateCell::Global(_) => expression_start,
    };
    Some((value, write_start))
}

fn state_write_full_expression(
    body: &[(Instr, walrus::ir::InstrLocId)],
    cell: StateCell,
) -> Option<i32> {
    let (value, write_start): (i32, usize) = state_write_expression(body, cell)?;
    (write_start == 0).then_some(value)
}

#[derive(Debug, Clone)]
enum Trans {
    Exit,
    Goto(i32),
    Cond { then_state: i32, else_state: i32 },
}

#[derive(Debug, Clone)]
struct Node {
    work: Body,
    cond: Body,
    edge_work: EdgeWork,
    trans: Trans,
}

#[derive(Debug, Clone)]
enum EdgeWork {
    None,
    Goto(Body),
    Cond { then_work: Body, else_work: Body },
}

#[derive(Debug)]
struct Graph {
    entry: i32,
    nodes: BTreeMap<i32, Node>,
}

fn build_graph(func: &LocalFunction, disp: &Dispatcher) -> Option<Graph> {
    let mut nodes: BTreeMap<i32, Node> = BTreeMap::new();
    let entry: i32 = canonical_state(disp, disp.entry_state);
    let mut work: Vec<i32> = vec![entry];
    while let Some(state) = work.pop() {
        if nodes.contains_key(&state) {
            continue;
        }
        if nodes.len() > NODE_LIMIT {
            return None;
        }
        let body: &Body = disp.state_to_body.get(&state)?;
        let mut node: Node = classify_case(func, body, disp, disp.transition_cell)?;
        canonicalize_transition(&mut node.trans, disp);
        match &node.trans {
            Trans::Exit => {}
            Trans::Goto(k) => work.push(*k),
            Trans::Cond {
                then_state,
                else_state,
            } => {
                work.push(*then_state);
                work.push(*else_state);
            }
        }
        nodes.insert(state, node);
    }
    Some(Graph { entry, nodes })
}

const fn canonical_state(disp: &Dispatcher, state: i32) -> i32 {
    let selector: u32 = u32::from_ne_bytes(state.to_ne_bytes());
    if selector < disp.case_count {
        state
    } else {
        disp.default_state
    }
}

const fn canonicalize_transition(trans: &mut Trans, disp: &Dispatcher) {
    match trans {
        Trans::Exit => {}
        Trans::Goto(state) => *state = canonical_state(disp, *state),
        Trans::Cond {
            then_state,
            else_state,
        } => {
            *then_state = canonical_state(disp, *then_state);
            *else_state = canonical_state(disp, *else_state);
        }
    }
}

fn classify_case(
    func: &LocalFunction,
    body: &Body,
    disp: &Dispatcher,
    transition_cell: StateCell,
) -> Option<Node> {
    let spill: bool = transition_cell != disp.cell;
    let empty_latch: Body = Vec::new();
    let (node, direct_transition): (Node, bool) = if spill {
        if let Some(node) =
            classify_case_shape(func, body, disp, disp.cell, true, false, &empty_latch)
        {
            (node, true)
        } else {
            (
                classify_case_shape(
                    func,
                    body,
                    disp,
                    transition_cell,
                    true,
                    true,
                    &disp.latch_work,
                )?,
                false,
            )
        }
    } else {
        (
            classify_case_shape(
                func,
                body,
                disp,
                transition_cell,
                false,
                false,
                &empty_latch,
            )?,
            false,
        )
    };
    if accesses_cell(func, &node.work, transition_cell)
        || accesses_cell(func, &node.cond, transition_cell)
        || (direct_transition
            && edge_work_accesses(func, &node.edge_work, disp.cell)
            && edge_work_accesses(func, &node.edge_work, transition_cell))
        || (transition_cell != disp.cell
            && (accesses_cell(func, &node.work, disp.cell)
                || accesses_cell(func, &node.cond, disp.cell)))
    {
        return None;
    }
    Some(node)
}

fn edge_work_accesses(func: &LocalFunction, edge_work: &EdgeWork, cell: StateCell) -> bool {
    match edge_work {
        EdgeWork::None => false,
        EdgeWork::Goto(work) => accesses_cell(func, work, cell),
        EdgeWork::Cond {
            then_work,
            else_work,
        } => accesses_cell(func, then_work, cell) || accesses_cell(func, else_work, cell),
    }
}

fn classify_case_shape(
    func: &LocalFunction,
    body: &Body,
    disp: &Dispatcher,
    transition_cell: StateCell,
    preserve_transition_writes: bool,
    allow_branch_transitions: bool,
    latch_work: &Body,
) -> Option<Node> {
    let return_pos: Option<usize> = body
        .iter()
        .position(|(instr, _)| matches!(instr, Instr::Return(_)));
    if let Some(pos) = return_pos {
        let work: Body = body[..=pos].to_vec();
        if !is_flat_except_return(&work) {
            return None;
        }
        return Some(Node {
            work,
            cond: Vec::new(),
            edge_work: EdgeWork::None,
            trans: Trans::Exit,
        });
    }

    if let Some(((Instr::Br(branch), _location), work)) = body.split_last()
        && disp.root_branch_exits
        && branch.block == disp.root
        && structured_work_is_bounded(func, work)
    {
        return Some(Node {
            work: if disp.suffix.is_empty() {
                work.to_vec()
            } else {
                body.clone()
            },
            cond: Vec::new(),
            edge_work: EdgeWork::None,
            trans: Trans::Exit,
        });
    }

    if allow_branch_transitions
        && let Some(node) = classify_direct_branch_conditional(func, body, disp)
    {
        return Some(node);
    }
    let stripped: &[(Instr, walrus::ir::InstrLocId)] = strip_trailing_branch(body);
    if !preserve_transition_writes
        && let Some(node) = classify_select_conditional(func, stripped, transition_cell)
    {
        return Some(node);
    }
    let (last, head): (
        &(Instr, walrus::ir::InstrLocId),
        &[(Instr, walrus::ir::InstrLocId)],
    ) = stripped.split_last()?;

    if let Instr::Block(_) = &last.0 {
        return classify_conditional(
            func,
            head,
            last,
            transition_cell,
            preserve_transition_writes,
            latch_work,
        );
    }
    classify_goto(
        func,
        stripped,
        transition_cell,
        preserve_transition_writes,
        latch_work,
    )
}

fn classify_direct_branch_conditional(
    func: &LocalFunction,
    stripped: &[(Instr, walrus::ir::InstrLocId)],
    disp: &Dispatcher,
) -> Option<Node> {
    let (else_branch, prefix): (
        &(Instr, walrus::ir::InstrLocId),
        &[(Instr, walrus::ir::InstrLocId)],
    ) = stripped.split_last()?;
    let (then_branch, head): (
        &(Instr, walrus::ir::InstrLocId),
        &[(Instr, walrus::ir::InstrLocId)],
    ) = prefix.split_last()?;
    let Instr::BrIf(then_branch): &Instr = &then_branch.0 else {
        return None;
    };
    let Instr::Br(else_branch): &Instr = &else_branch.0 else {
        return None;
    };
    let (then_state, then_write): &(i32, Body) = disp.branch_transitions.get(&then_branch.block)?;
    let (else_state, else_write): &(i32, Body) = disp.branch_transitions.get(&else_branch.block)?;
    let condition_start: usize = (0..head.len()).rev().find(|start: &usize| {
        condition_has_isolated_value_stack(head.get(*start..).unwrap_or_default())
    })?;
    let work: Body = head.get(..condition_start)?.to_vec();
    let cond: Body = head.get(condition_start..)?.to_vec();
    if !structured_work_is_bounded(func, &work) || !is_flat(&cond) {
        return None;
    }
    let mut then_work: Body = then_write.clone();
    then_work.extend(disp.latch_work.clone());
    let mut else_work: Body = else_write.clone();
    else_work.extend(disp.latch_work.clone());
    Some(Node {
        work,
        cond,
        edge_work: EdgeWork::Cond {
            then_work,
            else_work,
        },
        trans: Trans::Cond {
            then_state: *then_state,
            else_state: *else_state,
        },
    })
}

fn strip_trailing_branch(body: &Body) -> &[(Instr, walrus::ir::InstrLocId)] {
    match body.split_last() {
        Some(((Instr::Br(_), _), head)) => head,
        _ => body,
    }
}

fn classify_goto(
    func: &LocalFunction,
    stripped: &[(Instr, walrus::ir::InstrLocId)],
    cell: StateCell,
    preserve_transition_write: bool,
    latch_work: &Body,
) -> Option<Node> {
    let (next, head_len): (i32, usize) = state_write_expression(stripped, cell)?;
    let work: Body = stripped.get(..head_len)?.to_vec();
    if !structured_work_is_bounded(func, &work) {
        return None;
    }
    Some(Node {
        work,
        cond: Vec::new(),
        edge_work: if preserve_transition_write {
            let mut edge_work: Body = stripped.get(head_len..)?.to_vec();
            edge_work.extend(latch_work.clone());
            EdgeWork::Goto(edge_work)
        } else {
            EdgeWork::None
        },
        trans: Trans::Goto(next),
    })
}

fn classify_select_conditional(
    func: &LocalFunction,
    stripped: &[(Instr, walrus::ir::InstrLocId)],
    cell: StateCell,
) -> Option<Node> {
    if stripped.len() > TRANSITION_INSTRUCTION_LIMIT {
        return None;
    }
    let commit_index: usize = stripped.len().checked_sub(1)?;
    let select_index: usize = commit_index.checked_sub(1)?;
    if !matches!(stripped.get(select_index)?.0, Instr::Select(_)) {
        return None;
    }
    let commit: &Instr = &stripped.get(commit_index)?.0;
    let prefix: &[(Instr, walrus::ir::InstrLocId)] = stripped.get(..select_index)?;
    let candidate: SelectTransition = select_transition_candidate(prefix, commit, cell)?;
    let work: Body = stripped.get(..candidate.anchor)?.to_vec();
    let cond: Body = stripped
        .get(candidate.condition_start..select_index)?
        .to_vec();
    if cond.is_empty()
        || !structured_work_is_bounded(func, &work)
        || !is_flat(&cond)
        || !condition_has_isolated_value_stack(&cond)
    {
        return None;
    }
    Some(Node {
        work,
        cond,
        edge_work: EdgeWork::None,
        trans: Trans::Cond {
            then_state: candidate.then_state,
            else_state: candidate.else_state,
        },
    })
}

fn condition_has_isolated_value_stack(condition: &[(Instr, walrus::ir::InstrLocId)]) -> bool {
    let mut height: usize = 0;
    for (instr, _) in condition {
        let (pops, pushes): (usize, usize) = match instr {
            Instr::Const(_) | Instr::LocalGet(_) | Instr::GlobalGet(_) => (0, 1),
            Instr::LocalSet(_) | Instr::GlobalSet(_) | Instr::Drop(_) => (1, 0),
            Instr::LocalTee(_) | Instr::Unop(_) | Instr::Load(_) => (1, 1),
            Instr::Binop(_) => (2, 1),
            Instr::Select(_) => (3, 1),
            _ => return false,
        };
        if height < pops {
            return false;
        }
        height = height - pops + pushes;
        if height > TRANSITION_INSTRUCTION_LIMIT {
            return false;
        }
    }
    height == 1
}

struct SelectTransition {
    anchor: usize,
    condition_start: usize,
    then_state: i32,
    else_state: i32,
}

fn select_transition_candidate(
    prefix: &[(Instr, walrus::ir::InstrLocId)],
    commit: &Instr,
    cell: StateCell,
) -> Option<SelectTransition> {
    if !cell.commit_matches(commit) {
        return None;
    }
    let instructions: Vec<Instr> = prefix
        .iter()
        .map(|(instr, _location): &(Instr, walrus::ir::InstrLocId)| instr.clone())
        .collect();
    let mut found: Option<SelectTransition> = None;
    for values_start in 0..=prefix.len() {
        let Some(anchor) = cell.address_expression_start(prefix, values_start) else {
            continue;
        };
        for condition_start in values_start.checked_add(2)?..instructions.len() {
            let Some((else_state, else_start)): Option<(i32, usize)> =
                eval_i32_expression_suffix(&instructions, condition_start, STATE_EXPRESSION_LIMIT)
            else {
                continue;
            };
            let Some((then_state, then_start)): Option<(i32, usize)> =
                eval_i32_expression_suffix(&instructions, else_start, STATE_EXPRESSION_LIMIT)
            else {
                continue;
            };
            if then_start != values_start {
                continue;
            }
            if !condition_has_isolated_value_stack(prefix.get(condition_start..)?) {
                continue;
            }
            let candidate: SelectTransition = SelectTransition {
                anchor,
                condition_start,
                then_state,
                else_state,
            };
            if found.is_some() {
                return None;
            }
            found = Some(candidate);
        }
    }
    found
}

fn classify_conditional(
    func: &LocalFunction,
    head: &[(Instr, walrus::ir::InstrLocId)],
    outer_instr: &(Instr, walrus::ir::InstrLocId),
    cell: StateCell,
    preserve_transition_writes: bool,
    latch_work: &Body,
) -> Option<Node> {
    let work: Body = head.to_vec();
    if !structured_work_is_bounded(func, &work) {
        return None;
    }
    let idiom: Conditional = condition_from_blocks(func, outer_instr, cell)?;
    if !is_flat(&idiom.cond) {
        return None;
    }
    Some(Node {
        work,
        cond: idiom.cond,
        edge_work: if preserve_transition_writes {
            let mut then_work: Body = idiom.then_work;
            then_work.extend(latch_work.clone());
            let mut else_work: Body = idiom.else_work;
            else_work.extend(latch_work.clone());
            EdgeWork::Cond {
                then_work,
                else_work,
            }
        } else {
            EdgeWork::None
        },
        trans: Trans::Cond {
            then_state: idiom.then_state,
            else_state: idiom.else_state,
        },
    })
}

struct Conditional {
    cond: Body,
    then_state: i32,
    else_state: i32,
    then_work: Body,
    else_work: Body,
}

fn condition_from_blocks(
    func: &LocalFunction,
    outer_instr: &(Instr, walrus::ir::InstrLocId),
    cell: StateCell,
) -> Option<Conditional> {
    let Instr::Block(outer) = &outer_instr.0 else {
        return None;
    };
    let outer_body: &Body = &func.block(outer.seq).instrs;
    let (Instr::Block(inner), _): &(Instr, walrus::ir::InstrLocId) = outer_body.first()? else {
        return None;
    };
    let inner_id: InstrSeqId = inner.seq;
    let sb_store: &[(Instr, walrus::ir::InstrLocId)] = outer_body.get(1..)?;
    let guard_nonzero_state: i32 = state_write_full_expression(sb_store, cell)?;

    let inner_body: &Body = &func.block(inner_id).instrs;
    let brif_index: usize = inner_body
        .iter()
        .position(|(instr, _)| matches!(instr, Instr::BrIf(br) if br.block == inner_id))?;
    let cond: Body = inner_body[..brif_index].to_vec();
    if cond.is_empty() {
        return None;
    }
    let after: &[(Instr, walrus::ir::InstrLocId)] = inner_body.get(brif_index + 1..)?;
    let (br_out, sa_store): (
        &(Instr, walrus::ir::InstrLocId),
        &[(Instr, walrus::ir::InstrLocId)],
    ) = after.split_last()?;
    if !matches!(&br_out.0, Instr::Br(br) if br.block == outer.seq) {
        return None;
    }
    let guard_zero_state: i32 = state_write_full_expression(sa_store, cell)?;
    Some(Conditional {
        cond,
        then_state: guard_nonzero_state,
        else_state: guard_zero_state,
        then_work: sb_store.to_vec(),
        else_work: sa_store.to_vec(),
    })
}

fn is_flat(instrs: &[(Instr, walrus::ir::InstrLocId)]) -> bool {
    instrs.iter().all(|(instr, _)| !is_control(instr))
}

fn structured_work_is_bounded(
    func: &LocalFunction,
    instrs: &[(Instr, walrus::ir::InstrLocId)],
) -> bool {
    let mut budget: usize = TRANSITION_INSTRUCTION_LIMIT;
    let mut pending: Vec<&[(Instr, walrus::ir::InstrLocId)]> = vec![instrs];
    while let Some(sequence) = pending.pop() {
        if sequence.len() > budget {
            return false;
        }
        budget -= sequence.len();
        for (instruction, _location) in sequence {
            match instruction {
                Instr::Block(block) => pending.push(&func.block(block.seq).instrs),
                Instr::Loop(_)
                | Instr::IfElse(_)
                | Instr::Br(_)
                | Instr::BrIf(_)
                | Instr::BrTable(_)
                | Instr::Return(_) => return false,
                _ => {}
            }
        }
    }
    true
}

fn is_flat_except_return(instrs: &[(Instr, walrus::ir::InstrLocId)]) -> bool {
    instrs.iter().enumerate().all(|(idx, (instr, _))| {
        if matches!(instr, Instr::Return(_)) {
            return idx + 1 == instrs.len();
        }
        !is_control(instr)
    })
}

const fn is_control(instr: &Instr) -> bool {
    matches!(
        instr,
        Instr::Block(_)
            | Instr::Loop(_)
            | Instr::IfElse(_)
            | Instr::Br(_)
            | Instr::BrIf(_)
            | Instr::BrTable(_)
            | Instr::Return(_)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum NodeRef {
    State(i32),
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    At(NodeRef),
    Open,
}

impl Stop {
    const EXIT: Self = Self::At(NodeRef::Exit);

    const fn state(state: i32) -> Self {
        Self::At(NodeRef::State(state))
    }
}

#[derive(Debug, Clone)]
enum SNode {
    Seq(Vec<Self>),
    Work(i32),
    If {
        state: i32,
        then_branch: Box<Self>,
        else_branch: Box<Self>,
    },
    Loop {
        header: i32,
        body: Box<Self>,
    },
    MultiExitLoop {
        header: i32,
        body: Box<Self>,
        tails: Vec<(i32, Self)>,
    },
    Continue(i32),
    Break(i32),
}

fn ends_explicitly(graph: &Graph, node: &SNode) -> bool {
    match node {
        SNode::Break(_) | SNode::Continue(_) => true,
        SNode::Work(state) => graph.nodes.get(state).is_some_and(|node: &Node| {
            matches!(node.trans, Trans::Exit)
                && matches!(node.work.last(), Some((Instr::Return(_) | Instr::Br(_), _)))
        }),
        SNode::Seq(items) => items
            .last()
            .is_some_and(|last: &SNode| ends_explicitly(graph, last)),
        SNode::If {
            then_branch,
            else_branch,
            ..
        } => ends_explicitly(graph, then_branch) && ends_explicitly(graph, else_branch),
        SNode::Loop { body, .. } => ends_explicitly(graph, body),
        SNode::MultiExitLoop { tails, .. } => tails
            .iter()
            .all(|(_state, tail): &(i32, SNode)| ends_explicitly(graph, tail)),
    }
}

struct Analysis<'g> {
    graph: &'g Graph,
    flow: FlowGraph<i32>,
}

fn structure(graph: &Graph) -> Option<SNode> {
    let analysis: Analysis<'_> = Analysis::build(graph)?;
    let mut loops: Vec<i32> = Vec::new();
    let mut breaks: Vec<i32> = Vec::new();
    let mut guard: usize = 0;
    analysis.render(
        NodeRef::State(graph.entry),
        Stop::EXIT,
        &mut loops,
        &mut breaks,
        &mut guard,
    )
}

impl<'g> Analysis<'g> {
    fn build(graph: &'g Graph) -> Option<Self> {
        let order: Vec<i32> = reverse_postorder(graph);
        if order.len() != graph.nodes.len() {
            return None;
        }
        let flow: FlowGraph<i32> = state_flow(graph)?;
        Some(Analysis { graph, flow })
    }

    fn dominates(&self, a: i32, b: i32) -> bool {
        self.flow.dominates(a, b)
    }

    fn is_header(&self, state: i32) -> bool {
        self.graph.nodes.keys().any(|&u| {
            successors(self.graph, u)
                .into_iter()
                .any(|s| matches!(s, NodeRef::State(v) if v == state) && self.dominates(state, u))
        })
    }

    fn loop_exits(&self, header: i32) -> BTreeSet<i32> {
        let body: BTreeSet<i32> = self.loop_body(header);
        let mut exits: BTreeSet<i32> = BTreeSet::new();
        for &n in &body {
            for succ in successors(self.graph, n) {
                if let NodeRef::State(s) = succ {
                    if !body.contains(&s) {
                        exits.insert(s);
                    }
                }
            }
        }
        exits
    }

    fn loop_body(&self, header: i32) -> BTreeSet<i32> {
        let mut body: BTreeSet<i32> = BTreeSet::new();
        body.insert(header);
        let mut stack: Vec<i32> = Vec::new();
        for &u in self.graph.nodes.keys() {
            let branches_back: bool = successors(self.graph, u)
                .into_iter()
                .any(|s| matches!(s, NodeRef::State(v) if v == header))
                && self.dominates(header, u);
            if branches_back {
                stack.push(u);
            }
        }
        while let Some(n) = stack.pop() {
            if !body.insert(n) {
                continue;
            }
            for &p in self.graph.nodes.keys() {
                let is_pred: bool = successors(self.graph, p)
                    .into_iter()
                    .any(|s| matches!(s, NodeRef::State(v) if v == n));
                if is_pred && p != header && self.dominates(header, p) {
                    stack.push(p);
                }
            }
        }
        body
    }

    fn render(
        &self,
        start: NodeRef,
        stop: Stop,
        loops: &mut Vec<i32>,
        breaks: &mut Vec<i32>,
        guard: &mut usize,
    ) -> Option<SNode> {
        let mut items: Vec<SNode> = Vec::new();
        let mut cur: Stop = Stop::At(start);
        loop {
            *guard += 1;
            if *guard > RENDER_GUARD {
                return None;
            }
            if cur == stop {
                break;
            }
            let Stop::At(NodeRef::State(state)) = cur else {
                break;
            };
            if loops.contains(&state) {
                items.push(SNode::Continue(state));
                break;
            }
            if breaks.contains(&state) {
                items.push(SNode::Break(state));
                break;
            }
            if self.is_header(state) {
                let exits: BTreeSet<i32> = self.loop_exits(state);
                match exits.len() {
                    1 => {
                        let exit: i32 = exits.into_iter().next()?;
                        loops.push(state);
                        let body: SNode = self.render_loop(state, exit, loops, breaks, guard)?;
                        loops.pop();
                        items.push(SNode::Loop {
                            header: state,
                            body: Box::new(body),
                        });
                        cur = Stop::state(exit);
                    }
                    2..=MULTI_EXIT_LIMIT => {
                        let (node, next): (SNode, Stop) =
                            self.render_multi_exit_loop(state, &exits, stop, loops, breaks, guard)?;
                        items.push(node);
                        cur = next;
                    }
                    _ => return None,
                }
                continue;
            }
            let node: &Node = self.graph.nodes.get(&state)?;
            match &node.trans {
                Trans::Exit => {
                    items.push(SNode::Work(state));
                    break;
                }
                Trans::Goto(next) => {
                    items.push(SNode::Work(state));
                    cur = Stop::At(self.node_ref(*next));
                }
                Trans::Cond {
                    then_state,
                    else_state,
                } => {
                    let merge: Stop = self.merge_of(state, stop);
                    let then_branch: SNode =
                        self.render(self.node_ref(*then_state), merge, loops, breaks, guard)?;
                    let else_branch: SNode =
                        self.render(self.node_ref(*else_state), merge, loops, breaks, guard)?;
                    items.push(SNode::If {
                        state,
                        then_branch: Box::new(then_branch),
                        else_branch: Box::new(else_branch),
                    });
                    cur = merge;
                }
            }
        }
        Some(collapse(items))
    }

    fn render_loop(
        &self,
        header: i32,
        exit: i32,
        loops: &mut Vec<i32>,
        breaks: &mut Vec<i32>,
        guard: &mut usize,
    ) -> Option<SNode> {
        let node: &Node = self.graph.nodes.get(&header)?;
        match &node.trans {
            Trans::Cond {
                then_state,
                else_state,
            } => {
                let stop: Stop = Stop::state(exit);
                let then_branch: SNode =
                    self.render(self.node_ref(*then_state), stop, loops, breaks, guard)?;
                let else_branch: SNode =
                    self.render(self.node_ref(*else_state), stop, loops, breaks, guard)?;
                Some(SNode::If {
                    state: header,
                    then_branch: Box::new(then_branch),
                    else_branch: Box::new(else_branch),
                })
            }
            Trans::Goto(next) => {
                let stop: Stop = Stop::state(exit);
                let body: SNode = self.render(self.node_ref(*next), stop, loops, breaks, guard)?;
                Some(collapse(vec![SNode::Work(header), body]))
            }
            Trans::Exit => None,
        }
    }

    fn render_multi_exit_loop(
        &self,
        header: i32,
        exits: &BTreeSet<i32>,
        stop: Stop,
        loops: &mut Vec<i32>,
        breaks: &mut Vec<i32>,
        guard: &mut usize,
    ) -> Option<(SNode, Stop)> {
        let join: Stop = self.merge_of(header, stop);
        let depth: usize = breaks.len();
        breaks.extend(exits.iter().copied());
        loops.push(header);
        let body: SNode = self.render_multi_exit_body(header, loops, breaks, guard)?;
        breaks.truncate(depth);
        if !ends_explicitly(self.graph, &body) {
            return None;
        }
        let mut tails: Vec<(i32, SNode)> = Vec::with_capacity(exits.len());
        for &exit in exits {
            let tail: SNode = self.render(self.node_ref(exit), join, loops, breaks, guard)?;
            tails.push((exit, tail));
        }
        loops.pop();
        Some((
            SNode::MultiExitLoop {
                header,
                body: Box::new(body),
                tails,
            },
            join,
        ))
    }

    fn render_multi_exit_body(
        &self,
        header: i32,
        loops: &mut Vec<i32>,
        breaks: &mut Vec<i32>,
        guard: &mut usize,
    ) -> Option<SNode> {
        let node: &Node = self.graph.nodes.get(&header)?;
        match &node.trans {
            Trans::Cond {
                then_state,
                else_state,
            } => {
                let then_branch: SNode =
                    self.render(self.node_ref(*then_state), Stop::Open, loops, breaks, guard)?;
                let else_branch: SNode =
                    self.render(self.node_ref(*else_state), Stop::Open, loops, breaks, guard)?;
                Some(SNode::If {
                    state: header,
                    then_branch: Box::new(then_branch),
                    else_branch: Box::new(else_branch),
                })
            }
            Trans::Goto(next) => {
                let body: SNode =
                    self.render(self.node_ref(*next), Stop::Open, loops, breaks, guard)?;
                Some(collapse(vec![SNode::Work(header), body]))
            }
            Trans::Exit => None,
        }
    }

    fn node_ref(&self, state: i32) -> NodeRef {
        if self.graph.nodes.contains_key(&state) {
            NodeRef::State(state)
        } else {
            NodeRef::Exit
        }
    }

    fn merge_of(&self, state: i32, stop: Stop) -> Stop {
        match self.flow.immediate_post_dominator(state) {
            PostDominator::Node(merge) => Stop::state(merge),
            PostDominator::FunctionExit => Stop::EXIT,
            PostDominator::Undefined => stop,
        }
    }
}

fn collapse(items: Vec<SNode>) -> SNode {
    if items.len() == 1 {
        items.into_iter().next().unwrap_or(SNode::Seq(Vec::new()))
    } else {
        SNode::Seq(items)
    }
}

fn successors(graph: &Graph, state: i32) -> Vec<NodeRef> {
    match graph.nodes.get(&state) {
        Some(Node {
            trans: Trans::Exit, ..
        }) => vec![NodeRef::Exit],
        Some(Node {
            trans: Trans::Goto(k),
            ..
        }) => vec![state_ref(graph, *k)],
        Some(Node {
            trans:
                Trans::Cond {
                    then_state,
                    else_state,
                },
            ..
        }) => vec![state_ref(graph, *then_state), state_ref(graph, *else_state)],
        None => Vec::new(),
    }
}

fn state_ref(graph: &Graph, state: i32) -> NodeRef {
    if graph.nodes.contains_key(&state) {
        NodeRef::State(state)
    } else {
        NodeRef::Exit
    }
}

fn reverse_postorder(graph: &Graph) -> Vec<i32> {
    let mut visited: BTreeSet<i32> = BTreeSet::new();
    let mut post: Vec<i32> = Vec::new();
    let mut stack: Vec<(i32, usize)> = vec![(graph.entry, 0)];
    while let Some((node, idx)) = stack.pop() {
        if idx == 0 && !visited.insert(node) {
            continue;
        }
        let succs: Vec<NodeRef> = successors(graph, node);
        if idx < succs.len() {
            stack.push((node, idx + 1));
            if let NodeRef::State(next) = succs[idx] {
                if !visited.contains(&next) {
                    stack.push((next, 0));
                }
            }
        } else {
            post.push(node);
        }
    }
    post.reverse();
    post
}

fn state_flow(graph: &Graph) -> Option<FlowGraph<i32>> {
    FlowGraph::build(
        graph.nodes.keys().copied(),
        graph.entry,
        |state: i32, emit: &mut dyn FnMut(Flow<i32>)| {
            for succ in successors(graph, state) {
                match succ {
                    NodeRef::State(next) if graph.nodes.contains_key(&next) => {
                        emit(Flow::To(next));
                    }
                    NodeRef::State(_) | NodeRef::Exit => emit(Flow::Exit),
                }
            }
        },
    )
    .ok()
}

fn emit(
    func: &mut LocalFunction,
    root: InstrSeqId,
    disp: &Dispatcher,
    graph: &Graph,
    tree: &SNode,
) -> bool {
    let mut loop_labels: BTreeMap<i32, InstrSeqId> = BTreeMap::new();
    let mut exit_labels: Vec<(i32, InstrSeqId)> = Vec::new();
    let Some(body): Option<Body> =
        emit_snode(func, tree, graph, &mut loop_labels, &mut exit_labels)
    else {
        return false;
    };

    let mut rebuilt: Body = disp.preamble.clone();
    rebuilt.extend(body);
    rebuilt.extend(disp.suffix.clone());

    let seq: &mut walrus::ir::InstrSeq = func.block_mut(root);
    seq.instrs = rebuilt;
    true
}

fn located(instr: Instr) -> (Instr, walrus::ir::InstrLocId) {
    (instr, walrus::ir::InstrLocId::default())
}

fn dangling_seq(func: &mut LocalFunction) -> InstrSeqId {
    func.builder_mut()
        .dangling_instr_seq(InstrSeqType::Simple(None))
        .id()
}

fn emit_snode(
    func: &mut LocalFunction,
    node: &SNode,
    graph: &Graph,
    loop_labels: &mut BTreeMap<i32, InstrSeqId>,
    exit_labels: &mut Vec<(i32, InstrSeqId)>,
) -> Option<Body> {
    match node {
        SNode::Seq(items) => {
            let mut out: Body = Vec::new();
            for item in items {
                out.extend(emit_snode(func, item, graph, loop_labels, exit_labels)?);
            }
            Some(out)
        }
        SNode::Work(state) => Some(graph.nodes.get(state).map_or_else(Vec::new, |node: &Node| {
            let mut out: Body = node.work.clone();
            if let EdgeWork::Goto(edge_work) = &node.edge_work {
                out.extend(edge_work.clone());
            }
            out
        })),
        SNode::If {
            state,
            then_branch,
            else_branch,
        } => {
            let mut out: Body = Vec::new();
            let mut then_body: Body =
                emit_snode(func, then_branch, graph, loop_labels, exit_labels)?;
            let mut else_body: Body =
                emit_snode(func, else_branch, graph, loop_labels, exit_labels)?;
            if let Some(current) = graph.nodes.get(state) {
                out.extend(current.work.clone());
                out.extend(current.cond.clone());
                if let EdgeWork::Cond {
                    then_work,
                    else_work,
                } = &current.edge_work
                {
                    then_body.splice(..0, then_work.clone());
                    else_body.splice(..0, else_work.clone());
                }
            }
            let consequent: InstrSeqId = new_seq(func, then_body);
            let alternative: InstrSeqId = new_seq(func, else_body);
            out.push(located(Instr::IfElse(walrus::ir::IfElse {
                consequent,
                alternative,
            })));
            Some(out)
        }
        SNode::Loop { header, body } => {
            let loop_id: InstrSeqId = dangling_seq(func);
            loop_labels.insert(*header, loop_id);
            let loop_body: Body = emit_snode(func, body, graph, loop_labels, exit_labels)?;
            loop_labels.remove(header);
            func.block_mut(loop_id).instrs = loop_body;
            Some(vec![located(Instr::Loop(walrus::ir::Loop {
                seq: loop_id,
            }))])
        }
        SNode::MultiExitLoop {
            header,
            body,
            tails,
        } => emit_multi_exit_loop(func, *header, body, tails, graph, loop_labels, exit_labels),
        SNode::Continue(header) => {
            let &loop_id: &InstrSeqId = loop_labels.get(header)?;
            Some(vec![located(Instr::Br(walrus::ir::Br { block: loop_id }))])
        }
        SNode::Break(exit) => {
            let &(_state, block): &(i32, InstrSeqId) = exit_labels
                .iter()
                .rev()
                .find(|(state, _block): &&(i32, InstrSeqId)| state == exit)?;
            Some(vec![located(Instr::Br(walrus::ir::Br { block }))])
        }
    }
}

fn emit_multi_exit_loop(
    func: &mut LocalFunction,
    header: i32,
    body: &SNode,
    tails: &[(i32, SNode)],
    graph: &Graph,
    loop_labels: &mut BTreeMap<i32, InstrSeqId>,
    exit_labels: &mut Vec<(i32, InstrSeqId)>,
) -> Option<Body> {
    let done: InstrSeqId = dangling_seq(func);
    let depth: usize = exit_labels.len();
    let mut blocks: Vec<InstrSeqId> = Vec::with_capacity(tails.len());
    for &(state, ref _tail) in tails {
        let block: InstrSeqId = dangling_seq(func);
        blocks.push(block);
        exit_labels.push((state, block));
    }

    let loop_id: InstrSeqId = dangling_seq(func);
    loop_labels.insert(header, loop_id);
    let loop_body: Body = emit_snode(func, body, graph, loop_labels, exit_labels)?;
    loop_labels.remove(&header);
    func.block_mut(loop_id).instrs = loop_body;
    exit_labels.truncate(depth);

    let &innermost: &InstrSeqId = blocks.first()?;
    func.block_mut(innermost).instrs =
        vec![located(Instr::Loop(walrus::ir::Loop { seq: loop_id }))];

    for index in 1..blocks.len() {
        let &inner: &InstrSeqId = blocks.get(index.checked_sub(1)?)?;
        let &outer: &InstrSeqId = blocks.get(index)?;
        let (_state, tail): &(i32, SNode) = tails.get(index.checked_sub(1)?)?;
        let mut wrapper: Body = vec![located(Instr::Block(walrus::ir::Block { seq: inner }))];
        wrapper.extend(emit_snode(func, tail, graph, loop_labels, exit_labels)?);
        if !ends_explicitly(graph, tail) {
            wrapper.push(located(Instr::Br(walrus::ir::Br { block: done })));
        }
        func.block_mut(outer).instrs = wrapper;
    }

    let &outermost: &InstrSeqId = blocks.last()?;
    let (_state, last_tail): &(i32, SNode) = tails.last()?;
    let mut done_body: Body = vec![located(Instr::Block(walrus::ir::Block { seq: outermost }))];
    done_body.extend(emit_snode(
        func,
        last_tail,
        graph,
        loop_labels,
        exit_labels,
    )?);
    func.block_mut(done).instrs = done_body;

    let mut out: Body = vec![located(Instr::Block(walrus::ir::Block { seq: done }))];
    if tails
        .iter()
        .all(|(_state, tail): &(i32, SNode)| ends_explicitly(graph, tail))
    {
        out.push(located(Instr::Unreachable(walrus::ir::Unreachable {})));
    }
    Some(out)
}

fn new_seq(func: &mut LocalFunction, body: Body) -> InstrSeqId {
    let mut builder: walrus::InstrSeqBuilder<'_> = func
        .builder_mut()
        .dangling_instr_seq(InstrSeqType::Simple(None));
    let id: InstrSeqId = builder.id();
    let instrs: &mut Body = builder.instrs_mut();
    for entry in body {
        instrs.push(entry);
    }
    id
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use walrus::ir::Value;

    #[test]
    fn memory_slot_identity_ignores_alignment_but_requires_semantic_metadata() {
        let mut module: walrus::Module = walrus::Module::default();
        let selected_memory: MemoryId = module.memories.add_local(false, false, 1, None, None);
        let other_memory: MemoryId = module.memories.add_local(false, false, 1, None, None);
        let cell: StateCell = StateCell::MemorySlot {
            address: MemoryAddress::Fixed(32),
            memory: selected_memory,
            offset: 4,
        };
        let store = |memory: MemoryId, offset: u32, align: u32, kind: StoreKind| -> Instr {
            Instr::Store(walrus::ir::Store {
                memory,
                kind,
                arg: walrus::ir::MemArg { align, offset },
            })
        };

        assert!(cell.commit_matches(&store(
            selected_memory,
            4,
            1,
            StoreKind::I32 { atomic: false },
        )));
        assert!(
            !cell.commit_matches(&store(other_memory, 4, 4, StoreKind::I32 { atomic: false },))
        );
        assert!(!cell.commit_matches(&store(
            selected_memory,
            8,
            4,
            StoreKind::I32 { atomic: false },
        )));
        assert!(!cell.commit_matches(&store(
            selected_memory,
            4,
            4,
            StoreKind::I32 { atomic: true },
        )));
        assert!(!cell.commit_matches(&store(
            selected_memory,
            4,
            4,
            StoreKind::I64 { atomic: false },
        )));
        let matching_address: Body = vec![(
            Instr::Const(walrus::ir::Const {
                value: Value::I32(32),
            }),
            walrus::ir::InstrLocId::default(),
        )];
        let different_address: Body = vec![(
            Instr::Const(walrus::ir::Const {
                value: Value::I32(36),
            }),
            walrus::ir::InstrLocId::default(),
        )];
        assert_eq!(
            cell.address_expression_start(&matching_address, matching_address.len()),
            Some(0)
        );
        assert_eq!(
            cell.address_expression_start(&different_address, different_address.len()),
            None
        );
    }

    #[test]
    fn unresolved_local_bounds_proof_rejects_another_memory() {
        let mut module: walrus::Module = walrus::Module::default();
        let selected_memory: MemoryId = module.memories.add_local(false, false, 1, None, None);
        let other_memory: MemoryId = module.memories.add_local(false, false, 1, None, None);
        let local: LocalId = module.locals.add(walrus::ValType::I32);
        let body: Body = vec![
            (
                Instr::LocalGet(walrus::ir::LocalGet { local }),
                walrus::ir::InstrLocId::default(),
            ),
            (
                Instr::Const(walrus::ir::Const {
                    value: Value::I32(91),
                }),
                walrus::ir::InstrLocId::default(),
            ),
            (
                Instr::Store(walrus::ir::Store {
                    memory: other_memory,
                    kind: StoreKind::I32 { atomic: false },
                    arg: walrus::ir::MemArg {
                        align: 4,
                        offset: 8,
                    },
                }),
                walrus::ir::InstrLocId::default(),
            ),
        ];
        assert!(!preamble_proves_local_address_in_bounds(
            &body,
            body.len(),
            local,
            selected_memory,
            4,
        ));
    }

    #[test]
    fn nested_sequence_collection_does_not_exceed_the_node_limit() {
        let mut module: walrus::Module = walrus::Module::default();
        let mut builder: walrus::FunctionBuilder =
            walrus::FunctionBuilder::new(&mut module.types, &[], &[]);
        let try_body: InstrSeqId = builder.dangling_instr_seq(InstrSeqType::Simple(None)).id();
        let catches: Vec<LegacyCatch> = (0..NODE_LIMIT)
            .map(|_index: usize| LegacyCatch::CatchAll {
                handler: builder.dangling_instr_seq(InstrSeqType::Simple(None)).id(),
            })
            .collect();
        let instruction: Instr = Instr::Try(walrus::ir::Try {
            seq: try_body,
            catches,
        });
        let mut pending: Vec<InstrSeqId> = Vec::new();
        assert!(!push_nested_sequences(
            &instruction,
            &mut pending,
            NODE_LIMIT
        ));
        assert!(pending.len() <= NODE_LIMIT);
    }

    #[test]
    fn nested_root_enumeration_debits_one_aggregate_node_budget() {
        let mut module: walrus::Module = walrus::Module::default();
        let mut builder: walrus::FunctionBuilder =
            walrus::FunctionBuilder::new(&mut module.types, &[], &[]);
        let children: Vec<InstrSeqId> = (0..NODE_LIMIT)
            .map(|_index: usize| builder.dangling_instr_seq(InstrSeqType::Simple(None)).id())
            .collect();
        for child in children {
            builder
                .func_body()
                .instr(Instr::Block(walrus::ir::Block { seq: child }));
        }
        let function: walrus::FunctionId = builder.finish(Vec::new(), &mut module.funcs);
        let walrus::FunctionKind::Local(local): &walrus::FunctionKind =
            &module.funcs.get(function).kind
        else {
            panic!("constructed function must be local");
        };

        assert_eq!(nested_roots(local), None);
    }

    fn node(trans: Trans) -> Node {
        Node {
            work: Vec::new(),
            cond: Vec::new(),
            trans,
            edge_work: EdgeWork::None,
        }
    }

    fn graph(entry: i32, pairs: Vec<(i32, Trans)>) -> Graph {
        let mut nodes: BTreeMap<i32, Node> = BTreeMap::new();
        for (state, trans) in pairs {
            nodes.insert(state, node(trans));
        }
        Graph { entry, nodes }
    }

    #[test]
    fn diamond_structures_into_if_then_merge() {
        let g: Graph = graph(
            0,
            vec![
                (
                    0,
                    Trans::Cond {
                        then_state: 2,
                        else_state: 1,
                    },
                ),
                (1, Trans::Goto(3)),
                (2, Trans::Goto(3)),
                (3, Trans::Exit),
            ],
        );
        let tree: SNode = structure(&g).expect("diamond structures");
        let SNode::Seq(items): SNode = tree else {
            panic!("expected sequence, got {tree:?}");
        };
        assert_eq!(items.len(), 2, "if-diamond then merged exit");
        assert!(matches!(items[0], SNode::If { state: 0, .. }));
        assert!(matches!(items[1], SNode::Work(3)));
    }

    #[test]
    fn while_loop_with_nested_diamond_structures_into_loop_then_exit() {
        let g: Graph = graph(
            0,
            vec![
                (
                    0,
                    Trans::Cond {
                        then_state: 4,
                        else_state: 1,
                    },
                ),
                (
                    1,
                    Trans::Cond {
                        then_state: 3,
                        else_state: 2,
                    },
                ),
                (2, Trans::Goto(5)),
                (3, Trans::Goto(5)),
                (5, Trans::Goto(0)),
                (4, Trans::Exit),
            ],
        );
        let tree: SNode = structure(&g).expect("loop structures");
        let SNode::Seq(items): SNode = tree else {
            panic!("expected sequence, got {tree:?}");
        };
        assert_eq!(items.len(), 2, "loop then exit case");
        assert!(matches!(items[0], SNode::Loop { header: 0, .. }));
        assert!(matches!(items[1], SNode::Work(4)));
    }

    #[test]
    fn a_loop_header_below_the_entry_is_still_recognised() {
        let g: Graph = graph(
            0,
            vec![
                (0, Trans::Goto(1)),
                (
                    1,
                    Trans::Cond {
                        then_state: 2,
                        else_state: 3,
                    },
                ),
                (2, Trans::Goto(1)),
                (3, Trans::Exit),
            ],
        );
        let tree: SNode = structure(&g).expect("a loop headed below the entry structures");
        let SNode::Seq(items): SNode = tree else {
            panic!("expected sequence, got {tree:?}");
        };
        assert_eq!(
            items.len(),
            3,
            "entry work, loop, then exit case: {items:?}"
        );
        assert!(matches!(items[0], SNode::Work(0)));
        assert!(
            matches!(items[1], SNode::Loop { header: 1, .. }),
            "state 1 dominates its latch and must be the loop header: {:?}",
            items[1]
        );
        assert!(matches!(items[2], SNode::Work(3)));
    }

    #[test]
    fn an_irreducible_two_entry_loop_is_walled_not_faked() {
        let g: Graph = graph(
            0,
            vec![
                (
                    0,
                    Trans::Cond {
                        then_state: 1,
                        else_state: 2,
                    },
                ),
                (1, Trans::Goto(2)),
                (2, Trans::Goto(1)),
            ],
        );
        assert!(
            structure(&g).is_none(),
            "a cycle entered at two distinct states is irreducible and must wall"
        );
    }

    fn two_exit_loop() -> Graph {
        graph(
            0,
            vec![
                (
                    0,
                    Trans::Cond {
                        then_state: 1,
                        else_state: 9,
                    },
                ),
                (
                    1,
                    Trans::Cond {
                        then_state: 0,
                        else_state: 8,
                    },
                ),
                (8, Trans::Exit),
                (9, Trans::Exit),
            ],
        )
    }

    #[test]
    fn a_two_exit_loop_structures_into_nested_exit_blocks() {
        let g: Graph = two_exit_loop();
        let tree: SNode = structure(&g).expect("a loop with two distinct exits structures");
        let SNode::MultiExitLoop {
            header,
            body,
            tails,
        } = tree
        else {
            panic!("expected a multi-exit loop, got {tree:?}");
        };
        assert_eq!(header, 0, "state 0 dominates its latch and heads the loop");
        assert_eq!(
            tails
                .iter()
                .map(|(state, _tail)| *state)
                .collect::<Vec<i32>>(),
            vec![8, 9],
            "exit blocks nest in ascending state order so output is deterministic"
        );
        assert!(
            ends_explicitly(&g, &body),
            "every path out of the loop body must be an explicit branch: {body:?}"
        );
        let SNode::If {
            state: outer_state,
            then_branch,
            else_branch,
        } = *body
        else {
            panic!("expected the header conditional, got {body:?}");
        };
        assert_eq!(outer_state, 0);
        assert!(
            matches!(*else_branch, SNode::Break(9)),
            "the header's else edge leaves through exit 9: {else_branch:?}"
        );
        let SNode::If {
            state: inner_state,
            then_branch: latch,
            else_branch: second_exit,
        } = *then_branch
        else {
            panic!("expected the latch conditional, got {then_branch:?}");
        };
        assert_eq!(inner_state, 1);
        assert!(matches!(*latch, SNode::Continue(0)), "{latch:?}");
        assert!(matches!(*second_exit, SNode::Break(8)), "{second_exit:?}");
    }

    #[test]
    fn a_multi_exit_body_that_can_fall_out_of_the_loop_is_refused() {
        let g: Graph = two_exit_loop();
        let fallthrough: SNode = SNode::Seq(vec![SNode::Work(8), SNode::Work(1)]);
        assert!(
            !ends_explicitly(&g, &fallthrough),
            "a body ending on a transitional state falls off the loop and must be refused"
        );
        assert!(
            ends_explicitly(&g, &SNode::Seq(vec![SNode::Work(1), SNode::Break(8)])),
            "a body ending on an explicit exit branch is structurable"
        );
        assert!(
            !ends_explicitly(
                &g,
                &SNode::If {
                    state: 0,
                    then_branch: Box::new(SNode::Break(8)),
                    else_branch: Box::new(SNode::Work(1)),
                }
            ),
            "one unterminated conditional arm is enough to refuse the body"
        );
    }

    #[test]
    fn a_loop_with_more_exits_than_the_nesting_ceiling_is_refused() {
        let mut transitions: Vec<(i32, Trans)> = vec![(
            0,
            Trans::Cond {
                then_state: 1,
                else_state: 1000,
            },
        )];
        let ceiling: i32 = i32::try_from(MULTI_EXIT_LIMIT).expect("ceiling fits an i32");
        for step in 1..=ceiling {
            transitions.push((
                step,
                Trans::Cond {
                    then_state: if step == ceiling { 0 } else { step + 1 },
                    else_state: 1000 + step,
                },
            ));
        }
        for exit in 0..=ceiling {
            transitions.push((1000 + exit, Trans::Exit));
        }
        let g: Graph = graph(0, transitions);
        assert!(
            structure(&g).is_none(),
            "a loop leaving through more than {MULTI_EXIT_LIMIT} states exceeds the nesting ceiling"
        );
    }
}
