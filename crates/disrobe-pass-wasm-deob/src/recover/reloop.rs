use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg::{Flow, FlowGraph, PostDominator};
use walrus::ir::{Instr, InstrSeqId, InstrSeqType, LoadKind, StoreKind, Value};
use walrus::{LocalFunction, LocalId};

type Body = Vec<(Instr, walrus::ir::InstrLocId)>;

const NODE_LIMIT: usize = 512;
const RENDER_GUARD: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReloopOutcome {
    Restructured,
    Walled,
    NotApplicable,
}

pub(super) fn try_reloop(func: &mut LocalFunction) -> ReloopOutcome {
    let Some(disp): Option<Dispatcher> = detect(func) else {
        return ReloopOutcome::NotApplicable;
    };
    let Some(graph): Option<Graph> = build_graph(func, &disp) else {
        return ReloopOutcome::Walled;
    };
    let Some(tree): Option<SNode> = structure(&graph) else {
        return ReloopOutcome::Walled;
    };
    emit(func, &disp, &graph, &tree);
    ReloopOutcome::Restructured
}

#[derive(Debug, Clone, Copy)]
struct StateSlot {
    base: LocalId,
    offset: u32,
}

#[derive(Debug, Clone)]
struct Dispatcher {
    preamble: Body,
    suffix: Body,
    entry_state: i32,
    slot: StateSlot,
    case_count: u32,
    default_state: i32,
    state_to_body: BTreeMap<i32, Body>,
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

    let (slot, temp): (StateSlot, LocalId) = state_read(loop_body)?;
    if !ends_with_branch_to(loop_body, loop_seq) {
        return None;
    }
    let wrapper: InstrSeqId = loop_body.iter().find_map(|(instr, _)| match instr {
        Instr::Block(b) => Some(b.seq),
        _ => None,
    })?;

    let parents: BTreeMap<InstrSeqId, (InstrSeqId, usize)> = build_parent_map(func, entry);
    let (targets, default): (Vec<InstrSeqId>, InstrSeqId) = find_switch(func, wrapper, temp)?;

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

    let preamble: Body = entry_instrs[..loop_index].to_vec();
    let suffix: Body = entry_instrs[loop_index + 1..].to_vec();
    let entry_state: i32 = last_slot_init(&preamble, slot)?;

    Some(Dispatcher {
        preamble,
        suffix,
        entry_state,
        slot,
        case_count,
        default_state,
        state_to_body,
    })
}

fn state_read(loop_body: &Body) -> Option<(StateSlot, LocalId)> {
    for window in loop_body.windows(3) {
        let Instr::LocalGet(base) = &window[0].0 else {
            continue;
        };
        let Instr::Load(load) = &window[1].0 else {
            continue;
        };
        let Instr::LocalSet(temp) = &window[2].0 else {
            continue;
        };
        if !matches!(load.kind, LoadKind::I32 { .. }) {
            continue;
        }
        return Some((
            StateSlot {
                base: base.local,
                offset: load.arg.offset,
            },
            temp.local,
        ));
    }
    None
}

fn ends_with_branch_to(body: &Body, target: InstrSeqId) -> bool {
    body.iter()
        .any(|(instr, _)| matches!(instr, Instr::Br(br) if br.block == target))
}

fn find_switch(
    func: &LocalFunction,
    wrapper: InstrSeqId,
    temp: LocalId,
) -> Option<(Vec<InstrSeqId>, InstrSeqId)> {
    let mut current: InstrSeqId = wrapper;
    let mut depth: usize = 0;
    loop {
        depth += 1;
        if depth > NODE_LIMIT {
            return None;
        }
        let instrs: &Body = &func.block(current).instrs;
        let found: Option<(Vec<InstrSeqId>, InstrSeqId)> = switch_here(instrs, temp);
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

fn switch_here(instrs: &Body, temp: LocalId) -> Option<(Vec<InstrSeqId>, InstrSeqId)> {
    let mut last_get: Option<LocalId> = None;
    for (instr, _) in instrs {
        match instr {
            Instr::LocalGet(lg) => last_get = Some(lg.local),
            Instr::BrTable(bt) => {
                if last_get == Some(temp) {
                    return Some((bt.blocks.to_vec(), bt.default));
                }
                return None;
            }
            Instr::Block(_) => {}
            _ => last_get = None,
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

fn last_slot_init(preamble: &Body, slot: StateSlot) -> Option<i32> {
    let mut found: Option<i32> = None;
    for window in preamble.windows(3) {
        let Instr::LocalGet(base) = &window[0].0 else {
            continue;
        };
        let Instr::Const(c) = &window[1].0 else {
            continue;
        };
        let Instr::Store(store) = &window[2].0 else {
            continue;
        };
        if base.local != slot.base
            || store.arg.offset != slot.offset
            || !matches!(store.kind, StoreKind::I32 { .. })
        {
            continue;
        }
        if let Value::I32(v) = c.value {
            found = Some(v);
        }
    }
    found
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
        let mut node: Node = classify_case(func, body, disp.slot)?;
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

fn classify_case(func: &LocalFunction, body: &Body, slot: StateSlot) -> Option<Node> {
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
    let (last, head): (
        &(Instr, walrus::ir::InstrLocId),
        &[(Instr, walrus::ir::InstrLocId)],
    ) = stripped.split_last()?;

    if let Instr::Block(_) = &last.0 {
        return classify_conditional(func, head, last, slot);
    }
    classify_goto(stripped, slot)
}

fn strip_trailing_branch(body: &Body) -> &[(Instr, walrus::ir::InstrLocId)] {
    match body.split_last() {
        Some(((Instr::Br(_), _), head)) => head,
        _ => body,
    }
}

fn classify_goto(stripped: &[(Instr, walrus::ir::InstrLocId)], slot: StateSlot) -> Option<Node> {
    let len: usize = stripped.len();
    if len < 3 {
        return None;
    }
    let base_get: &Instr = &stripped[len - 3].0;
    let const_val: &Instr = &stripped[len - 2].0;
    let store: &Instr = &stripped[len - 1].0;
    let next: i32 = match_state_store(base_get, const_val, store, slot)?;
    let work: Body = stripped[..len - 3].to_vec();
    if !is_flat(&work) {
        return None;
    }
    Some(Node {
        work,
        cond: Vec::new(),
        trans: Trans::Goto(next),
    })
}

fn classify_conditional(
    func: &LocalFunction,
    head: &[(Instr, walrus::ir::InstrLocId)],
    outer_instr: &(Instr, walrus::ir::InstrLocId),
    slot: StateSlot,
) -> Option<Node> {
    let work: Body = head.to_vec();
    if !is_flat(&work) {
        return None;
    }
    let idiom: Conditional = condition_from_blocks(func, outer_instr, slot)?;
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
    slot: StateSlot,
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
    let guard_nonzero_state: i32 = trailing_state_store(sb_store, slot)?;

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
    let guard_zero_state: i32 = trailing_state_store(sa_store, slot)?;
    Some(Conditional {
        cond,
        then_state: guard_nonzero_state,
        else_state: guard_zero_state,
    })
}

fn trailing_state_store(
    instrs: &[(Instr, walrus::ir::InstrLocId)],
    slot: StateSlot,
) -> Option<i32> {
    if instrs.len() != 3 {
        return None;
    }
    match_state_store(&instrs[0].0, &instrs[1].0, &instrs[2].0, slot)
}

fn match_state_store(
    base_get: &Instr,
    const_val: &Instr,
    store: &Instr,
    slot: StateSlot,
) -> Option<i32> {
    let Instr::LocalGet(base) = base_get else {
        return None;
    };
    let Instr::Const(c) = const_val else {
        return None;
    };
    let Instr::Store(s) = store else {
        return None;
    };
    if base.local != slot.base
        || s.arg.offset != slot.offset
        || !matches!(s.kind, StoreKind::I32 { .. })
    {
        return None;
    }
    match c.value {
        Value::I32(v) => Some(v),
        _ => None,
    }
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
