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
    Restructured,
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

pub(super) fn try_reloop(func: &mut LocalFunction, elidable: &ElidableCells) -> ReloopOutcome {
    let Some(disp): Option<Dispatcher> = detect(func) else {
        return ReloopOutcome::NotApplicable;
    };
    if !cell_is_elidable(func, &disp, elidable) {
        return wall(WallReason::ObservableStateCell);
    }
    let Some(graph): Option<Graph> = build_graph(func, &disp) else {
        return wall(WallReason::UnsupportedTransition);
    };
    let Some(tree): Option<SNode> = structure(&graph) else {
        return wall(WallReason::UnstructurableStateGraph);
    };
    emit(func, &disp, &graph, &tree);
    ReloopOutcome::Restructured
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
    I32Const(i32),
}

impl MemoryAddress {
    const fn from_instr(instr: &Instr) -> Option<Self> {
        match instr {
            Instr::LocalGet(get) => Some(Self::Local(get.local)),
            Instr::Const(constant) => match constant.value {
                Value::I32(value) => Some(Self::I32Const(value)),
                Value::I64(_) | Value::F32(_) | Value::F64(_) | Value::V128(_) => None,
            },
            _ => None,
        }
    }

    fn matches(self, instr: &Instr) -> bool {
        Self::from_instr(instr) == Some(self)
    }
}

impl StateCell {
    const fn address_prefix_len(self) -> usize {
        match self {
            Self::MemorySlot { .. } => 1,
            Self::Local(_) | Self::Global(_) => 0,
        }
    }

    fn address_prefix_matches(self, prefix: &[(Instr, walrus::ir::InstrLocId)]) -> bool {
        match self {
            Self::MemorySlot { address, .. } => prefix
                .first()
                .is_some_and(|(instr, _location)| address.matches(instr)),
            Self::Local(_) | Self::Global(_) => prefix.is_empty(),
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selector {
    Local(LocalId),
    Global(GlobalId),
}

#[derive(Debug, Clone)]
struct Dispatcher {
    preamble: Body,
    suffix: Body,
    entry_state: i32,
    cell: StateCell,
    case_count: u32,
    default_state: i32,
    state_to_body: BTreeMap<i32, Body>,
}

fn cell_is_elidable(func: &LocalFunction, disp: &Dispatcher, elidable: &ElidableCells) -> bool {
    let owned_by_dispatcher: bool = match disp.cell {
        StateCell::Local(_) => true,
        StateCell::Global(global) => elidable.globals.contains(&global),
        StateCell::MemorySlot {
            address,
            memory,
            offset,
            ..
        } => {
            let eligible: bool = match address {
                MemoryAddress::Local(_) => elidable.memories.contains(&memory),
                MemoryAddress::I32Const(_) => elidable.fixed_memories.contains(&memory),
            };
            eligible
                && memory_address_is_in_bounds(address, offset, &elidable.memory_min_bytes, memory)
        }
    };
    owned_by_dispatcher && !reads_cell(func, &disp.suffix, disp.cell)
}

fn memory_address_is_in_bounds(
    address: MemoryAddress,
    offset: u32,
    minimums: &BTreeMap<MemoryId, u64>,
    memory: MemoryId,
) -> bool {
    match address {
        MemoryAddress::Local(_) => true,
        MemoryAddress::I32Const(value) => {
            let dynamic: u64 = u64::from(u32::from_ne_bytes(value.to_ne_bytes()));
            dynamic
                .checked_add(u64::from(offset))
                .and_then(|effective: u64| effective.checked_add(4))
                .is_some_and(|end: u64| minimums.get(&memory).is_some_and(|limit| end <= *limit))
        }
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
        match instr {
            Instr::Block(block) => pending.push(block.seq),
            Instr::Loop(loop_) => pending.push(loop_.seq),
            Instr::IfElse(if_else) => {
                pending.push(if_else.consequent);
                pending.push(if_else.alternative);
            }
            Instr::TryTable(try_table) => pending.push(try_table.seq),
            Instr::Try(try_) => {
                pending.push(try_.seq);
                pending.extend(
                    try_.catches
                        .iter()
                        .filter_map(|catch: &LegacyCatch| match catch {
                            LegacyCatch::Catch { handler, .. }
                            | LegacyCatch::CatchAll { handler } => Some(*handler),
                            LegacyCatch::Delegate { .. } => None,
                        }),
                );
            }
            _ => {}
        }
        if cell.read_matches(instr) {
            return true;
        }
    }
    false
}

fn detect(func: &LocalFunction) -> Option<Dispatcher> {
    let entry: InstrSeqId = func.entry_block();
    let entry_instrs: &Body = &func.block(entry).instrs;
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

    let parents: BTreeMap<InstrSeqId, (InstrSeqId, usize)> = build_parent_map(func, entry);
    let (targets, default, selector): (Vec<InstrSeqId>, InstrSeqId, Selector) =
        find_switch(func, wrapper)?;
    let cell: StateCell = resolve_state_cell(loop_body, selector)?;

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
    if let Some(span) = entry_write {
        drop(preamble.drain(span));
    }

    Some(Dispatcher {
        preamble,
        suffix,
        entry_state,
        cell,
        case_count,
        default_state,
        state_to_body,
    })
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
    let source_start: usize = match &loop_body.get(source_index)?.0 {
        Instr::Load(_) => source_index.checked_sub(1)?,
        _ => source_index,
    };
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
            let address_index: usize = source_index.checked_sub(1)?;
            let address: MemoryAddress =
                MemoryAddress::from_instr(&loop_body.get(address_index)?.0)?;
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
    let write_start: usize = expression_start.checked_sub(cell.address_prefix_len())?;
    if !cell.address_prefix_matches(prefix.get(write_start..expression_start)?) {
        return None;
    }
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
    trans: Trans,
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
        let mut node: Node = classify_case(func, body, disp.cell)?;
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

fn classify_case(func: &LocalFunction, body: &Body, cell: StateCell) -> Option<Node> {
    let node: Node = classify_case_shape(func, body, cell)?;
    if reads_cell(func, &node.work, cell) || reads_cell(func, &node.cond, cell) {
        return None;
    }
    Some(node)
}

fn classify_case_shape(func: &LocalFunction, body: &Body, cell: StateCell) -> Option<Node> {
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
            trans: Trans::Exit,
        });
    }

    let stripped: &[(Instr, walrus::ir::InstrLocId)] = strip_trailing_branch(body);
    if let Some(node) = classify_select_conditional(stripped, cell) {
        return Some(node);
    }
    let (last, head): (
        &(Instr, walrus::ir::InstrLocId),
        &[(Instr, walrus::ir::InstrLocId)],
    ) = stripped.split_last()?;

    if let Instr::Block(_) = &last.0 {
        return classify_conditional(func, head, last, cell);
    }
    classify_goto(stripped, cell)
}

fn strip_trailing_branch(body: &Body) -> &[(Instr, walrus::ir::InstrLocId)] {
    match body.split_last() {
        Some(((Instr::Br(_), _), head)) => head,
        _ => body,
    }
}

fn classify_goto(stripped: &[(Instr, walrus::ir::InstrLocId)], cell: StateCell) -> Option<Node> {
    let (next, head_len): (i32, usize) = state_write_expression(stripped, cell)?;
    let work: Body = stripped.get(..head_len)?.to_vec();
    if !is_flat(&work) {
        return None;
    }
    Some(Node {
        work,
        cond: Vec::new(),
        trans: Trans::Goto(next),
    })
}

fn classify_select_conditional(
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
        || !is_flat(&work)
        || !is_flat(&cond)
        || !condition_has_isolated_value_stack(&cond)
    {
        return None;
    }
    Some(Node {
        work,
        cond,
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
    let address_len: usize = cell.address_prefix_len();
    let instructions: Vec<Instr> = prefix
        .iter()
        .map(|(instr, _location): &(Instr, walrus::ir::InstrLocId)| instr.clone())
        .collect();
    let mut found: Option<SelectTransition> = None;
    for anchor in 0..=prefix.len().checked_sub(address_len)? {
        let values_start: usize = anchor.checked_add(address_len)?;
        if !cell.address_prefix_matches(prefix.get(anchor..values_start)?) {
            continue;
        }
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
) -> Option<Node> {
    let work: Body = head.to_vec();
    if !is_flat(&work) {
        return None;
    }
    let idiom: Conditional = condition_from_blocks(func, outer_instr, cell)?;
    if !is_flat(&idiom.cond) {
        return None;
    }
    Some(Node {
        work,
        cond: idiom.cond,
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
    })
}

fn is_flat(instrs: &[(Instr, walrus::ir::InstrLocId)]) -> bool {
    instrs.iter().all(|(instr, _)| !is_control(instr))
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
    Continue(i32),
}

struct Analysis<'g> {
    graph: &'g Graph,
    flow: FlowGraph<i32>,
}

fn structure(graph: &Graph) -> Option<SNode> {
    let analysis: Analysis<'_> = Analysis::build(graph)?;
    let mut loops: Vec<i32> = Vec::new();
    let mut guard: usize = 0;
    analysis.render(
        NodeRef::State(graph.entry),
        NodeRef::Exit,
        &mut loops,
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

    fn loop_exit(&self, header: i32) -> Option<i32> {
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
        if exits.len() == 1 {
            exits.into_iter().next()
        } else {
            None
        }
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
        stop: NodeRef,
        loops: &mut Vec<i32>,
        guard: &mut usize,
    ) -> Option<SNode> {
        let mut items: Vec<SNode> = Vec::new();
        let mut cur: NodeRef = start;
        loop {
            *guard += 1;
            if *guard > RENDER_GUARD {
                return None;
            }
            if cur == stop {
                break;
            }
            let NodeRef::State(state) = cur else {
                break;
            };
            if loops.contains(&state) {
                items.push(SNode::Continue(state));
                break;
            }
            if self.is_header(state) {
                let exit: i32 = self.loop_exit(state)?;
                loops.push(state);
                let body: SNode = self.render_loop(state, exit, loops, guard)?;
                loops.pop();
                items.push(SNode::Loop {
                    header: state,
                    body: Box::new(body),
                });
                cur = NodeRef::State(exit);
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
                    cur = self.node_ref(*next);
                }
                Trans::Cond {
                    then_state,
                    else_state,
                } => {
                    let merge: NodeRef = self.merge_of(state, stop);
                    let then_branch: SNode =
                        self.render(self.node_ref(*then_state), merge, loops, guard)?;
                    let else_branch: SNode =
                        self.render(self.node_ref(*else_state), merge, loops, guard)?;
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
        guard: &mut usize,
    ) -> Option<SNode> {
        let node: &Node = self.graph.nodes.get(&header)?;
        match &node.trans {
            Trans::Cond {
                then_state,
                else_state,
            } => {
                let stop: NodeRef = NodeRef::State(exit);
                let then_branch: SNode =
                    self.render(self.node_ref(*then_state), stop, loops, guard)?;
                let else_branch: SNode =
                    self.render(self.node_ref(*else_state), stop, loops, guard)?;
                Some(SNode::If {
                    state: header,
                    then_branch: Box::new(then_branch),
                    else_branch: Box::new(else_branch),
                })
            }
            Trans::Goto(next) => {
                let stop: NodeRef = NodeRef::State(exit);
                let body: SNode = self.render(self.node_ref(*next), stop, loops, guard)?;
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

    fn merge_of(&self, state: i32, stop: NodeRef) -> NodeRef {
        match self.flow.immediate_post_dominator(state) {
            PostDominator::Node(merge) => NodeRef::State(merge),
            PostDominator::FunctionExit => NodeRef::Exit,
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

fn emit(func: &mut LocalFunction, disp: &Dispatcher, graph: &Graph, tree: &SNode) {
    let mut loop_labels: BTreeMap<i32, InstrSeqId> = BTreeMap::new();
    let body: Body = emit_snode(func, tree, graph, &mut loop_labels);

    let mut rebuilt: Body = disp.preamble.clone();
    rebuilt.extend(body);
    rebuilt.extend(disp.suffix.clone());

    let entry: InstrSeqId = func.entry_block();
    let seq: &mut walrus::ir::InstrSeq = func.block_mut(entry);
    seq.instrs = rebuilt;
}

fn emit_snode(
    func: &mut LocalFunction,
    node: &SNode,
    graph: &Graph,
    loop_labels: &mut BTreeMap<i32, InstrSeqId>,
) -> Body {
    match node {
        SNode::Seq(items) => {
            let mut out: Body = Vec::new();
            for item in items {
                out.extend(emit_snode(func, item, graph, loop_labels));
            }
            out
        }
        SNode::Work(state) => graph
            .nodes
            .get(state)
            .map(|n| n.work.clone())
            .unwrap_or_default(),
        SNode::If {
            state,
            then_branch,
            else_branch,
        } => {
            let mut out: Body = Vec::new();
            if let Some(n) = graph.nodes.get(state) {
                out.extend(n.work.clone());
                out.extend(n.cond.clone());
            }
            let then_body: Body = emit_snode(func, then_branch, graph, loop_labels);
            let else_body: Body = emit_snode(func, else_branch, graph, loop_labels);
            let consequent: InstrSeqId = new_seq(func, then_body);
            let alternative: InstrSeqId = new_seq(func, else_body);
            out.push((
                Instr::IfElse(walrus::ir::IfElse {
                    consequent,
                    alternative,
                }),
                walrus::ir::InstrLocId::default(),
            ));
            out
        }
        SNode::Loop { header, body } => {
            let loop_id: InstrSeqId = func
                .builder_mut()
                .dangling_instr_seq(InstrSeqType::Simple(None))
                .id();
            loop_labels.insert(*header, loop_id);
            let loop_body: Body = emit_snode(func, body, graph, loop_labels);
            loop_labels.remove(header);
            func.block_mut(loop_id).instrs = loop_body;
            vec![(
                Instr::Loop(walrus::ir::Loop { seq: loop_id }),
                walrus::ir::InstrLocId::default(),
            )]
        }
        SNode::Continue(header) => match loop_labels.get(header) {
            Some(&loop_id) => vec![(
                Instr::Br(walrus::ir::Br { block: loop_id }),
                walrus::ir::InstrLocId::default(),
            )],
            None => Vec::new(),
        },
    }
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

    #[test]
    fn memory_slot_identity_ignores_alignment_but_requires_semantic_metadata() {
        let mut module: walrus::Module = walrus::Module::default();
        let selected_memory: MemoryId = module.memories.add_local(false, false, 1, None, None);
        let other_memory: MemoryId = module.memories.add_local(false, false, 1, None, None);
        let cell: StateCell = StateCell::MemorySlot {
            address: MemoryAddress::I32Const(32),
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
        assert!(cell.address_prefix_matches(&matching_address));
        assert!(!cell.address_prefix_matches(&different_address));
    }

    fn node(trans: Trans) -> Node {
        Node {
            work: Vec::new(),
            cond: Vec::new(),
            trans,
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

    #[test]
    fn multi_exit_loop_is_walled_not_faked() {
        let g: Graph = graph(
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
        );
        assert!(
            structure(&g).is_none(),
            "a loop with two distinct exits is irreducible-for-this-structurer and must wall"
        );
    }
}
