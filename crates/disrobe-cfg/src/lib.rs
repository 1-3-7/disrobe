use std::collections::{BTreeMap, BTreeSet};

use disrobe_core::{AdjGraph, DiGraph, Dominators, immediate_post_dominators};

pub type NodeId = u32;
pub type RegionId = u32;
pub type Atom = u32;
pub type CondId = u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminator {
    Return,
    #[allow(dead_code)]
    Unreachable,
    Goto(NodeId),
    Branch {
        atom: Atom,
        taken: NodeId,
        not_taken: NodeId,
    },
    #[allow(dead_code)]
    Switch {
        atom: Atom,
        cases: Vec<(i64, NodeId)>,
        default: Option<NodeId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgNode {
    pub term: Terminator,
    pub pure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgError {
    EmptyGraph,
    EntryOutOfRange,
    TargetOutOfRange,
}

#[derive(Debug, Clone)]
pub struct Cfg {
    entry: NodeId,
    nodes: Vec<CfgNode>,
}

impl Cfg {
    pub fn new(entry: NodeId, nodes: Vec<CfgNode>) -> Result<Self, CfgError> {
        if nodes.is_empty() {
            return Err(CfgError::EmptyGraph);
        }
        let count: u32 = nodes.len() as u32;
        if entry >= count {
            return Err(CfgError::EntryOutOfRange);
        }
        for node in &nodes {
            let ok: bool = match &node.term {
                Terminator::Return | Terminator::Unreachable => true,
                Terminator::Goto(t) => *t < count,
                Terminator::Branch {
                    taken, not_taken, ..
                } => *taken < count && *not_taken < count,
                Terminator::Switch { cases, default, .. } => {
                    cases.iter().all(|(_, t): &(i64, NodeId)| *t < count)
                        && default.is_none_or(|d: NodeId| d < count)
                }
            };
            if !ok {
                return Err(CfgError::TargetOutOfRange);
            }
        }
        Ok(Self { entry, nodes })
    }

    pub const fn len(&self) -> usize {
        self.nodes.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub const fn entry(&self) -> NodeId {
        self.entry
    }

    pub fn node(&self, node: NodeId) -> Option<&CfgNode> {
        self.nodes.get(node as usize)
    }

    fn successors(&self, node: NodeId) -> Vec<NodeId> {
        term_successors(&self.nodes[node as usize].term)
    }
}

fn term_successors(term: &Terminator) -> Vec<NodeId> {
    match term {
        Terminator::Return | Terminator::Unreachable => Vec::new(),
        Terminator::Goto(t) => vec![*t],
        Terminator::Branch {
            taken, not_taken, ..
        } => {
            if taken == not_taken {
                vec![*taken]
            } else {
                vec![*taken, *not_taken]
            }
        }
        Terminator::Switch { cases, default, .. } => {
            let mut out: Vec<NodeId> = Vec::new();
            for (_, t) in cases {
                if !out.contains(t) {
                    out.push(*t);
                }
            }
            if let Some(d) = default
                && !out.contains(d)
            {
                out.push(*d);
            }
            out
        }
    }
}

struct CfgGraph<'a> {
    cfg: &'a Cfg,
}

impl DiGraph for CfgGraph<'_> {
    fn node_count(&self) -> usize {
        self.cfg.len()
    }

    fn entry(&self) -> u32 {
        self.cfg.entry
    }

    fn for_each_successor(&self, node: u32, visit: &mut dyn FnMut(u32)) {
        for s in self.cfg.successors(node) {
            visit(s);
        }
    }
}

pub fn dominators(cfg: &Cfg) -> Dominators {
    let graph: CfgGraph<'_> = CfgGraph { cfg };
    Dominators::compute(&graph)
}

#[derive(Debug, Clone)]
pub struct PostDominators {
    ipdom: Vec<Option<NodeId>>,
    exit: NodeId,
}

impl PostDominators {
    pub fn compute(cfg: &Cfg) -> Self {
        let count: usize = cfg.len();
        let exit: NodeId = count as NodeId;
        let report = |node: u32, visit: &mut dyn FnMut(u32)| match &cfg.nodes[node as usize].term {
            Terminator::Return | Terminator::Unreachable => visit(exit),
            other => {
                for s in term_successors(other) {
                    visit(s);
                }
            }
        };
        let ipdom: Vec<Option<NodeId>> = immediate_post_dominators(count, report);
        Self { ipdom, exit }
    }

    pub fn immediate_post_dominator(&self, node: NodeId) -> Option<NodeId> {
        self.ipdom.get(node as usize).copied().flatten()
    }

    pub const fn exit(&self) -> NodeId {
        self.exit
    }

    pub fn post_dominates(&self, a: NodeId, b: NodeId) -> bool {
        if a == b {
            return true;
        }
        let mut cur: NodeId = b;
        loop {
            match self.immediate_post_dominator(cur) {
                Some(next) if next == a => return true,
                Some(next) if next == self.exit => return false,
                Some(next) if next == cur => return false,
                Some(next) => cur = next,
                None => return false,
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct NaturalLoop {
    pub header: NodeId,
    pub latches: Vec<NodeId>,
    pub body: BTreeSet<NodeId>,
    pub parent: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct LoopForest {
    pub loops: Vec<NaturalLoop>,
    pub irreducible: bool,
}

fn reachable(cfg: &Cfg) -> Vec<bool> {
    let count: usize = cfg.len();
    let mut seen: Vec<bool> = vec![false; count];
    let mut stack: Vec<NodeId> = vec![cfg.entry];
    seen[cfg.entry as usize] = true;
    while let Some(node) = stack.pop() {
        for s in cfg.successors(node) {
            if !seen[s as usize] {
                seen[s as usize] = true;
                stack.push(s);
            }
        }
    }
    seen
}

fn dfs_intervals(cfg: &Cfg) -> (Vec<u32>, Vec<u32>) {
    let count: usize = cfg.len();
    let mut discover: Vec<u32> = vec![u32::MAX; count];
    let mut finish: Vec<u32> = vec![u32::MAX; count];
    let mut clock: u32 = 0;
    let mut stack: Vec<(NodeId, Vec<NodeId>, usize)> = Vec::new();
    let entry: NodeId = cfg.entry;
    discover[entry as usize] = clock;
    clock += 1;
    stack.push((entry, cfg.successors(entry), 0));
    while let Some((node, succs, idx)) = stack.last_mut() {
        if *idx < succs.len() {
            let child: NodeId = succs[*idx];
            *idx += 1;
            if discover[child as usize] == u32::MAX {
                discover[child as usize] = clock;
                clock += 1;
                let child_succs: Vec<NodeId> = cfg.successors(child);
                stack.push((child, child_succs, 0));
            }
        } else {
            finish[*node as usize] = clock;
            clock += 1;
            stack.pop();
        }
    }
    (discover, finish)
}

pub fn loop_forest(cfg: &Cfg) -> LoopForest {
    let dom: Dominators = dominators(cfg);
    let reach: Vec<bool> = reachable(cfg);
    let (discover, finish): (Vec<u32>, Vec<u32>) = dfs_intervals(cfg);
    let is_ancestor = |a: NodeId, b: NodeId| -> bool {
        discover[a as usize] != u32::MAX
            && discover[b as usize] != u32::MAX
            && discover[a as usize] <= discover[b as usize]
            && finish[b as usize] <= finish[a as usize]
    };

    let preds: Vec<Vec<NodeId>> = predecessors(cfg);
    let mut irreducible: bool = false;
    let mut headers: Vec<NodeId> = Vec::new();
    let mut latches_by_header: BTreeMap<NodeId, Vec<NodeId>> = BTreeMap::new();
    for u in 0..cfg.len() as NodeId {
        if !reach[u as usize] {
            continue;
        }
        for v in cfg.successors(u) {
            let retreating: bool = is_ancestor(v, u);
            let back: bool = dom.dominates(v, u);
            if retreating && !back {
                irreducible = true;
            }
            if back {
                if !headers.contains(&v) {
                    headers.push(v);
                }
                latches_by_header.entry(v).or_default().push(u);
            }
        }
    }

    headers.sort_unstable();
    let mut loops: Vec<NaturalLoop> = Vec::new();
    for header in headers {
        let latches: Vec<NodeId> = latches_by_header.remove(&header).unwrap_or_default();
        let mut body: BTreeSet<NodeId> = BTreeSet::from([header]);
        let mut stack: Vec<NodeId> = Vec::new();
        for &latch in &latches {
            if body.insert(latch) {
                stack.push(latch);
            }
        }
        while let Some(node) = stack.pop() {
            for &pred in &preds[node as usize] {
                if body.insert(pred) {
                    stack.push(pred);
                }
            }
        }
        loops.push(NaturalLoop {
            header,
            latches,
            body,
            parent: None,
        });
    }

    loops.sort_by_key(|l: &NaturalLoop| l.body.len());
    for i in 0..loops.len() {
        let mut parent: Option<usize> = None;
        let mut parent_size: usize = usize::MAX;
        for j in 0..loops.len() {
            if i == j {
                continue;
            }
            if loops[i].body.is_subset(&loops[j].body) && loops[j].body.len() < parent_size {
                parent = Some(j);
                parent_size = loops[j].body.len();
            }
        }
        loops[i].parent = parent;
    }

    LoopForest { loops, irreducible }
}

fn predecessors(cfg: &Cfg) -> Vec<Vec<NodeId>> {
    let count: usize = cfg.len();
    let mut preds: Vec<Vec<NodeId>> = vec![Vec::new(); count];
    for from in 0..count as NodeId {
        for s in cfg.successors(from) {
            if !preds[s as usize].contains(&from) {
                preds[s as usize].push(from);
            }
        }
    }
    preds
}

const RETURN_TAIL_NODE_CAP: usize = 64;

trait FlowView {
    fn flow_node_count(&self) -> usize;
    fn flow_is_live(&self, node: NodeId) -> bool;
    fn flow_successors(&self, node: NodeId) -> Vec<NodeId>;
    fn flow_returns(&self, node: NodeId) -> bool;
}

struct CfgFlow<'a> {
    cfg: &'a Cfg,
    live: Vec<bool>,
}

impl FlowView for CfgFlow<'_> {
    fn flow_node_count(&self) -> usize {
        self.cfg.len()
    }

    fn flow_is_live(&self, node: NodeId) -> bool {
        self.live.get(node as usize).copied().unwrap_or(false)
    }

    fn flow_successors(&self, node: NodeId) -> Vec<NodeId> {
        self.cfg.successors(node)
    }

    fn flow_returns(&self, node: NodeId) -> bool {
        matches!(
            self.cfg.nodes.get(node as usize).map(|n: &CfgNode| &n.term),
            Some(Terminator::Return)
        )
    }
}

fn flow_predecessors<V: FlowView>(view: &V) -> Vec<Vec<NodeId>> {
    let count: usize = view.flow_node_count();
    let mut preds: Vec<Vec<NodeId>> = vec![Vec::new(); count];
    for from in 0..count as NodeId {
        if !view.flow_is_live(from) {
            continue;
        }
        for successor in view.flow_successors(from) {
            let Some(slot): Option<&mut Vec<NodeId>> = preds.get_mut(successor as usize) else {
                continue;
            };
            if !slot.contains(&from) {
                slot.push(from);
            }
        }
    }
    preds
}

fn flow_exit_targets<V: FlowView>(view: &V, body: &BTreeSet<NodeId>) -> Vec<NodeId> {
    let mut targets: Vec<NodeId> = Vec::new();
    for node in body {
        for successor in view.flow_successors(*node) {
            if !body.contains(&successor) && !targets.contains(&successor) {
                targets.push(successor);
            }
        }
    }
    targets
}

fn tail_is_acyclic<V: FlowView>(view: &V, tail: &BTreeSet<NodeId>) -> bool {
    let mut indegree: BTreeMap<NodeId, usize> =
        tail.iter().map(|node: &NodeId| (*node, 0usize)).collect();
    for node in tail {
        for successor in view.flow_successors(*node) {
            if let Some(degree) = indegree.get_mut(&successor) {
                *degree += 1;
            }
        }
    }
    let mut ready: Vec<NodeId> = indegree
        .iter()
        .filter(|(_, degree): &(&NodeId, &usize)| **degree == 0)
        .map(|(node, _): (&NodeId, &usize)| *node)
        .collect();
    let mut removed: usize = 0;
    while let Some(node) = ready.pop() {
        removed += 1;
        for successor in view.flow_successors(node) {
            if let Some(degree) = indegree.get_mut(&successor) {
                *degree = degree.saturating_sub(1);
                if *degree == 0 {
                    ready.push(successor);
                }
            }
        }
    }
    removed == tail.len()
}

fn private_return_tail<V: FlowView>(
    view: &V,
    body: &BTreeSet<NodeId>,
    preds: &[Vec<NodeId>],
    seed: NodeId,
) -> Option<BTreeSet<NodeId>> {
    let mut tail: BTreeSet<NodeId> = BTreeSet::new();
    let mut pending: Vec<NodeId> = vec![seed];
    let mut returns: bool = false;
    while let Some(node) = pending.pop() {
        if body.contains(&node) || !view.flow_is_live(node) {
            return None;
        }
        if !tail.insert(node) {
            continue;
        }
        if tail.len() > RETURN_TAIL_NODE_CAP {
            return None;
        }
        let successors: Vec<NodeId> = view.flow_successors(node);
        if successors.is_empty() {
            if !view.flow_returns(node) {
                return None;
            }
            returns = true;
            continue;
        }
        pending.extend(successors);
    }
    if !returns {
        return None;
    }
    for node in &tail {
        let entering: &[NodeId] = preds.get(*node as usize).map_or(&[], Vec::as_slice);
        if entering
            .iter()
            .any(|pred: &NodeId| !body.contains(pred) && !tail.contains(pred))
        {
            return None;
        }
    }
    tail_is_acyclic(view, &tail).then_some(tail)
}

fn preferred_follow<V: FlowView>(
    view: &V,
    header: NodeId,
    body: &BTreeSet<NodeId>,
    targets: &[NodeId],
) -> Option<NodeId> {
    let latch_exit: Option<NodeId> = body
        .iter()
        .filter(|node: &&NodeId| view.flow_successors(**node).contains(&header))
        .flat_map(|node: &NodeId| view.flow_successors(*node))
        .find(|successor: &NodeId| targets.contains(successor));
    latch_exit
        .or_else(|| {
            view.flow_successors(header)
                .into_iter()
                .find(|successor: &NodeId| targets.contains(successor))
        })
        .or_else(|| targets.iter().copied().min())
}

fn body_absorbing_return_tails<V: FlowView>(
    view: &V,
    header: NodeId,
    body: &BTreeSet<NodeId>,
) -> Option<BTreeSet<NodeId>> {
    let targets: Vec<NodeId> = flow_exit_targets(view, body);
    if targets.len() < 2 {
        return None;
    }
    let preds: Vec<Vec<NodeId>> = flow_predecessors(view);
    let tails: Vec<(NodeId, Option<BTreeSet<NodeId>>)> = targets
        .iter()
        .map(|target: &NodeId| (*target, private_return_tail(view, body, &preds, *target)))
        .collect();
    let blocked: Vec<NodeId> = tails
        .iter()
        .filter(|(_, tail): &&(NodeId, Option<BTreeSet<NodeId>>)| tail.is_none())
        .map(|(target, _): &(NodeId, Option<BTreeSet<NodeId>>)| *target)
        .collect();
    let keep: NodeId = match blocked.as_slice() {
        [] => preferred_follow(view, header, body, &targets)?,
        [single] => *single,
        _ => return None,
    };
    let mut extended: BTreeSet<NodeId> = body.clone();
    for (target, tail) in &tails {
        if *target == keep {
            continue;
        }
        let tail: &BTreeSet<NodeId> = tail.as_ref()?;
        extended.extend(tail.iter().copied());
    }
    if extended.len() == body.len() || extended.contains(&keep) {
        return None;
    }
    (flow_exit_targets(view, &extended) == vec![keep]).then_some(extended)
}

pub fn loop_body_absorbing_return_tails(
    cfg: &Cfg,
    header: NodeId,
    body: &BTreeSet<NodeId>,
) -> Option<BTreeSet<NodeId>> {
    let view: CfgFlow<'_> = CfgFlow {
        cfg,
        live: reachable(cfg),
    };
    body_absorbing_return_tails(&view, header, body)
}

pub fn strongly_connected_components(cfg: &Cfg) -> Vec<Vec<NodeId>> {
    let count: usize = cfg.len();
    let reach: Vec<bool> = reachable(cfg);
    let mut index_of: Vec<u32> = vec![u32::MAX; count];
    let mut lowlink: Vec<u32> = vec![0; count];
    let mut on_stack: Vec<bool> = vec![false; count];
    let mut tarjan_stack: Vec<NodeId> = Vec::new();
    let mut call: Vec<(NodeId, Vec<NodeId>, usize)> = Vec::new();
    let mut next_index: u32 = 0;
    let mut result: Vec<Vec<NodeId>> = Vec::new();
    for start in 0..count as NodeId {
        if !reach[start as usize] || index_of[start as usize] != u32::MAX {
            continue;
        }
        index_of[start as usize] = next_index;
        lowlink[start as usize] = next_index;
        next_index += 1;
        tarjan_stack.push(start);
        on_stack[start as usize] = true;
        call.push((start, cfg.successors(start), 0));
        while !call.is_empty() {
            let top: usize = call.len() - 1;
            let v: NodeId = call[top].0;
            if call[top].2 < call[top].1.len() {
                let w: NodeId = call[top].1[call[top].2];
                call[top].2 += 1;
                if !reach[w as usize] {
                    continue;
                }
                if index_of[w as usize] == u32::MAX {
                    index_of[w as usize] = next_index;
                    lowlink[w as usize] = next_index;
                    next_index += 1;
                    tarjan_stack.push(w);
                    on_stack[w as usize] = true;
                    let succ_w: Vec<NodeId> = cfg.successors(w);
                    call.push((w, succ_w, 0));
                } else if on_stack[w as usize] {
                    lowlink[v as usize] = lowlink[v as usize].min(index_of[w as usize]);
                }
            } else {
                call.pop();
                if let Some((parent, _, _)) = call.last() {
                    let p: usize = *parent as usize;
                    lowlink[p] = lowlink[p].min(lowlink[v as usize]);
                }
                if lowlink[v as usize] == index_of[v as usize] {
                    let mut component: Vec<NodeId> = Vec::new();
                    while let Some(node) = tarjan_stack.pop() {
                        on_stack[node as usize] = false;
                        component.push(node);
                        if node == v {
                            break;
                        }
                    }
                    component.sort_unstable();
                    result.push(component);
                }
            }
        }
    }
    result
}

#[derive(Debug, Clone)]
pub struct IrreducibleEntry {
    pub members: BTreeSet<NodeId>,
    pub entries: Vec<NodeId>,
    pub external_edges: Vec<(NodeId, NodeId)>,
}

pub type CloneMap = BTreeMap<NodeId, NodeId>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CnsBudget {
    pub max_cloned_blocks: usize,
    pub max_iterations: usize,
}

impl CnsBudget {
    pub fn tight_for(cfg: &Cfg) -> Self {
        let regions: Vec<IrreducibleEntry> = multi_entry_irreducible_sccs(cfg);
        let mut members: BTreeSet<NodeId> = BTreeSet::new();
        let mut secondary_entries: usize = 0;
        for region in regions {
            members.extend(region.members);
            secondary_entries += region.entries.len().saturating_sub(1);
        }
        Self {
            max_cloned_blocks: members.len().min(64),
            max_iterations: secondary_entries.saturating_add(4),
        }
    }
}

pub fn multi_entry_irreducible_sccs(cfg: &Cfg) -> Vec<IrreducibleEntry> {
    if !loop_forest(cfg).irreducible {
        return Vec::new();
    }
    let preds: Vec<Vec<NodeId>> = predecessors(cfg);
    let mut out: Vec<IrreducibleEntry> = Vec::new();
    for component in strongly_connected_components(cfg) {
        let members: BTreeSet<NodeId> = component.iter().copied().collect();
        let is_cycle: bool = component.len() > 1
            || (component.len() == 1 && cfg.successors(component[0]).contains(&component[0]));
        if !is_cycle {
            continue;
        }
        let mut entries: Vec<NodeId> = Vec::new();
        let mut external_edges: Vec<(NodeId, NodeId)> = Vec::new();
        for &node in &component {
            let mut is_entry: bool = node == cfg.entry;
            for &pred in &preds[node as usize] {
                if !members.contains(&pred) {
                    external_edges.push((pred, node));
                    is_entry = true;
                }
            }
            if is_entry {
                entries.push(node);
            }
        }
        entries.sort_unstable();
        if entries.len() >= 2 {
            out.push(IrreducibleEntry {
                members,
                entries,
                external_edges,
            });
        }
    }
    out
}

fn is_dfs_ancestor(discover: &[u32], finish: &[u32], ancestor: NodeId, node: NodeId) -> bool {
    discover[ancestor as usize] != u32::MAX
        && discover[node as usize] != u32::MAX
        && discover[ancestor as usize] <= discover[node as usize]
        && finish[node as usize] <= finish[ancestor as usize]
}

fn choose_primary_header(cfg: &Cfg, region: &IrreducibleEntry) -> Option<NodeId> {
    let dom: Dominators = dominators(cfg);
    let (discover, finish): (Vec<u32>, Vec<u32>) = dfs_intervals(cfg);
    let mut chosen: Option<(NodeId, usize, usize)> = None;
    for &entry in &region.entries {
        let mut targets_retreating_edge: bool = false;
        for &source in &region.members {
            for target in cfg.successors(source) {
                if target == entry
                    && (is_dfs_ancestor(&discover, &finish, entry, source)
                        || dom.dominates(entry, source))
                {
                    targets_retreating_edge = true;
                }
            }
        }
        if !targets_retreating_edge {
            continue;
        }
        let external_predecessors: usize = region
            .external_edges
            .iter()
            .filter(|(_, target): &&(NodeId, NodeId)| *target == entry)
            .count();
        let dominated_members: usize = region
            .members
            .iter()
            .filter(|member: &&NodeId| dom.dominates(entry, **member))
            .count();
        let replace: bool = match chosen {
            None => true,
            Some((best, best_external, best_dominated)) => {
                external_predecessors > best_external
                    || (external_predecessors == best_external
                        && (dominated_members > best_dominated
                            || (dominated_members == best_dominated && entry < best)))
            }
        };
        if replace {
            chosen = Some((entry, external_predecessors, dominated_members));
        }
    }
    chosen.map(|(entry, _, _): (NodeId, usize, usize)| entry)
}

fn clone_reachable_without_header(
    cfg: &Cfg,
    members: &BTreeSet<NodeId>,
    entry: NodeId,
    primary: NodeId,
) -> BTreeSet<NodeId> {
    let mut clones: BTreeSet<NodeId> = BTreeSet::new();
    let mut stack: Vec<NodeId> = vec![entry];
    while let Some(node) = stack.pop() {
        if node == primary || !members.contains(&node) || !clones.insert(node) {
            continue;
        }
        for successor in cfg.successors(node) {
            if successor != primary && members.contains(&successor) && !clones.contains(&successor)
            {
                stack.push(successor);
            }
        }
    }
    clones
}

fn retarget_terminator(term: &mut Terminator, from: NodeId, to: NodeId) {
    match term {
        Terminator::Return | Terminator::Unreachable => {}
        Terminator::Goto(target) => {
            if *target == from {
                *target = to;
            }
        }
        Terminator::Branch {
            taken, not_taken, ..
        } => {
            if *taken == from {
                *taken = to;
            }
            if *not_taken == from {
                *not_taken = to;
            }
        }
        Terminator::Switch { cases, default, .. } => {
            for (_, target) in cases {
                if *target == from {
                    *target = to;
                }
            }
            if *default == Some(from) {
                *default = Some(to);
            }
        }
    }
}

fn clone_secondary_entry(
    cfg: &mut Cfg,
    members: &BTreeSet<NodeId>,
    entry: NodeId,
    primary: NodeId,
    clone_map: &mut CloneMap,
    cloned_blocks: &mut usize,
    budget: CnsBudget,
) -> bool {
    let clone_set: BTreeSet<NodeId> = clone_reachable_without_header(cfg, members, entry, primary);
    if clone_set.is_empty()
        || clone_set.len() > budget.max_cloned_blocks.saturating_sub(*cloned_blocks)
    {
        return false;
    }
    let base: NodeId = cfg.nodes.len() as NodeId;
    let mut remap: BTreeMap<NodeId, NodeId> = BTreeMap::new();
    for (offset, node) in clone_set.iter().copied().enumerate() {
        remap.insert(node, base + offset as NodeId);
    }
    let Some(&clone_entry): Option<&NodeId> = remap.get(&entry) else {
        return false;
    };
    let mut new_nodes: Vec<CfgNode> = Vec::with_capacity(clone_set.len());
    for node in clone_set.iter().copied() {
        let mut cloned: CfgNode = cfg.nodes[node as usize].clone();
        for (&from, &to) in &remap {
            retarget_terminator(&mut cloned.term, from, to);
        }
        let origin: NodeId = match clone_map.get(&node) {
            Some(&mapped) => mapped,
            None => node,
        };
        let Some(&clone): Option<&NodeId> = remap.get(&node) else {
            return false;
        };
        clone_map.insert(clone, origin);
        new_nodes.push(cloned);
    }
    let preds: Vec<Vec<NodeId>> = predecessors(cfg);
    let external_predecessors: Vec<NodeId> = preds[entry as usize]
        .iter()
        .copied()
        .filter(|pred: &NodeId| !members.contains(pred))
        .collect();
    cfg.nodes.extend(new_nodes);
    for predecessor in external_predecessors {
        retarget_terminator(
            &mut cfg.nodes[predecessor as usize].term,
            entry,
            clone_entry,
        );
    }
    if cfg.entry == entry {
        cfg.entry = clone_entry;
    }
    *cloned_blocks += clone_set.len();
    true
}

pub fn make_reducible(cfg: &Cfg, budget: CnsBudget) -> Option<(Cfg, CloneMap)> {
    let mut transformed: Cfg = cfg.clone();
    let mut clone_map: CloneMap = BTreeMap::new();
    let mut cloned_blocks: usize = 0;
    let mut iterations: usize = 0;
    while iterations < budget.max_iterations {
        let regions: Vec<IrreducibleEntry> = multi_entry_irreducible_sccs(&transformed);
        if regions.is_empty() {
            return Some((transformed, clone_map));
        }
        let region: Option<&IrreducibleEntry> = regions
            .iter()
            .min_by_key(|candidate: &&IrreducibleEntry| candidate.members.iter().next().copied());
        let region: &IrreducibleEntry = region?;
        let primary: NodeId = choose_primary_header(&transformed, region)?;
        let secondary_entries: Vec<NodeId> = region
            .entries
            .iter()
            .copied()
            .filter(|entry: &NodeId| *entry != primary)
            .collect();
        if secondary_entries.is_empty() {
            return None;
        }
        for entry in secondary_entries {
            if !clone_secondary_entry(
                &mut transformed,
                &region.members,
                entry,
                primary,
                &mut clone_map,
                &mut cloned_blocks,
                budget,
            ) {
                return None;
            }
        }
        iterations += 1;
    }
    if multi_entry_irreducible_sccs(&transformed).is_empty() {
        Some((transformed, clone_map))
    } else {
        None
    }
}

fn mapped_clone_origin(
    node: NodeId,
    original_len: usize,
    transformed_len: usize,
    clone_map: &CloneMap,
    residual: &BTreeMap<NodeId, NodeId>,
) -> Option<NodeId> {
    let mut current: NodeId = node;
    let mut hops: usize = 0;
    while let Some(&target) = residual.get(&current) {
        current = target;
        hops += 1;
        if hops > transformed_len {
            return None;
        }
    }
    if (current as usize) < original_len {
        if clone_map.contains_key(&current) {
            return None;
        }
        return Some(current);
    }
    let origin: NodeId = clone_map.get(&current).copied()?;
    if (origin as usize) >= original_len {
        return None;
    }
    Some(origin)
}

fn terminator_matches_original_under_quotient(
    original: &Terminator,
    transformed: &Terminator,
    original_len: usize,
    transformed_len: usize,
    clone_map: &CloneMap,
    residual: &BTreeMap<NodeId, NodeId>,
) -> bool {
    let mapped = |target: NodeId| -> Option<NodeId> {
        mapped_clone_origin(target, original_len, transformed_len, clone_map, residual)
    };
    match (original, transformed) {
        (Terminator::Return, Terminator::Return)
        | (Terminator::Unreachable, Terminator::Unreachable) => true,
        (Terminator::Goto(expected), Terminator::Goto(actual)) => {
            mapped(*actual) == Some(*expected)
        }
        (
            Terminator::Branch {
                atom: expected_atom,
                taken: expected_taken,
                not_taken: expected_not_taken,
            },
            Terminator::Branch {
                atom: actual_atom,
                taken: actual_taken,
                not_taken: actual_not_taken,
            },
        ) => {
            let taken_matches: bool = mapped(*actual_taken)
                .is_some_and(|mapped_taken: NodeId| mapped_taken == *expected_taken);
            let not_taken_matches: bool = mapped(*actual_not_taken)
                .is_some_and(|mapped_not_taken: NodeId| mapped_not_taken == *expected_not_taken);
            expected_atom == actual_atom && taken_matches && not_taken_matches
        }
        (
            Terminator::Switch {
                atom: expected_atom,
                cases: expected_cases,
                default: expected_default,
            },
            Terminator::Switch {
                atom: actual_atom,
                cases: actual_cases,
                default: actual_default,
            },
        ) => {
            expected_atom == actual_atom
                && expected_cases.len() == actual_cases.len()
                && expected_cases.iter().zip(actual_cases).all(
                    |((expected_value, expected_target), (actual_value, actual_target)): (
                        &(i64, NodeId),
                        &(i64, NodeId),
                    )| {
                        let target_matches: bool = mapped(*actual_target)
                            .is_some_and(|mapped_target: NodeId| mapped_target == *expected_target);
                        expected_value == actual_value && target_matches
                    },
                )
                && match (expected_default, actual_default) {
                    (None, None) => true,
                    (Some(expected), Some(actual)) => mapped(*actual) == Some(*expected),
                    _ => false,
                }
        }
        _ => false,
    }
}

pub fn relowered_matches_original_modulo_clones(
    original: &Cfg,
    transformed: &Cfg,
    clone_map: &CloneMap,
    residual: &BTreeMap<NodeId, NodeId>,
) -> bool {
    let original_len: usize = original.len();
    let transformed_len: usize = transformed.len();
    if transformed_len < original_len {
        return false;
    }
    for (&clone, &origin) in clone_map {
        if (clone as usize) < original_len
            || (clone as usize) >= transformed_len
            || (origin as usize) >= original_len
        {
            return false;
        }
    }
    let transformed_reachable: Vec<bool> = reachable(transformed);
    let original_reachable: Vec<bool> = reachable(original);
    if mapped_clone_origin(
        transformed.entry,
        original_len,
        transformed_len,
        clone_map,
        residual,
    ) != Some(original.entry)
    {
        return false;
    }
    let mut transformed_origins: BTreeSet<NodeId> = BTreeSet::new();
    let mut realized_edges: BTreeSet<(NodeId, NodeId)> = BTreeSet::new();
    for node in 0..transformed_len as NodeId {
        if !transformed_reachable[node as usize] {
            continue;
        }
        if residual.contains_key(&node) {
            continue;
        }
        let Some(origin): Option<NodeId> =
            mapped_clone_origin(node, original_len, transformed_len, clone_map, residual)
        else {
            return false;
        };
        transformed_origins.insert(origin);
        let Some(original_node): Option<&CfgNode> = original.nodes.get(origin as usize) else {
            return false;
        };
        let Some(transformed_node): Option<&CfgNode> = transformed.nodes.get(node as usize) else {
            return false;
        };
        if original_node.pure != transformed_node.pure
            || !terminator_matches_original_under_quotient(
                &original_node.term,
                &transformed_node.term,
                original_len,
                transformed_len,
                clone_map,
                residual,
            )
        {
            return false;
        }
        for successor in transformed.successors(node) {
            let Some(mapped_successor): Option<NodeId> = mapped_clone_origin(
                successor,
                original_len,
                transformed_len,
                clone_map,
                residual,
            ) else {
                return false;
            };
            if !original.successors(origin).contains(&mapped_successor) {
                return false;
            }
            realized_edges.insert((origin, mapped_successor));
        }
    }
    for node in 0..original_len as NodeId {
        if original_reachable[node as usize] && !transformed_origins.contains(&node) {
            return false;
        }
        if original_reachable[node as usize] {
            for successor in original.successors(node) {
                if !realized_edges.contains(&(node, successor)) {
                    return false;
                }
            }
        }
    }
    for region in multi_entry_irreducible_sccs(original) {
        let Some(primary): Option<NodeId> = choose_primary_header(original, &region) else {
            return false;
        };
        for (predecessor, secondary) in region.external_edges {
            if secondary == primary {
                continue;
            }
            let Some(transformed_node): Option<&CfgNode> =
                transformed.nodes.get(predecessor as usize)
            else {
                return false;
            };
            if !term_successors(&transformed_node.term)
                .into_iter()
                .any(|target: NodeId| clone_map.get(&target).copied() == Some(secondary))
            {
                return false;
            }
        }
        if original.entry != primary
            && region.entries.contains(&original.entry)
            && clone_map.get(&transformed.entry).copied() != Some(original.entry)
        {
            return false;
        }
    }
    true
}

pub fn relowered_matches_original(
    original: &Cfg,
    rendered: &Cfg,
    residual: &BTreeMap<NodeId, NodeId>,
) -> bool {
    let n: usize = original.len();
    if rendered.len() < n {
        return false;
    }
    let reach: Vec<bool> = reachable(original);
    for node in 0..n as NodeId {
        if !reach[node as usize] {
            continue;
        }
        let mut effective: BTreeSet<NodeId> = BTreeSet::new();
        for succ in rendered.successors(node) {
            let mut cur: NodeId = succ;
            let mut hops: usize = 0;
            while let Some(&target) = residual.get(&cur) {
                cur = target;
                hops += 1;
                if hops > rendered.len() {
                    return false;
                }
            }
            if (cur as usize) >= n {
                return false;
            }
            effective.insert(cur);
        }
        let expected: BTreeSet<NodeId> = original.successors(node).into_iter().collect();
        if effective != expected {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Cond {
    Leaf(Atom),
    NotLeaf(Atom),
    And(CondId, CondId),
    Or(CondId, CondId),
}

#[derive(Debug, Clone, Default)]
pub struct CondPool {
    nodes: Vec<Cond>,
    index: BTreeMap<Cond, CondId>,
}

impl CondPool {
    fn intern(&mut self, cond: Cond) -> CondId {
        if let Some(id) = self.index.get(&cond) {
            return *id;
        }
        let id: CondId = self.nodes.len() as CondId;
        self.nodes.push(cond);
        self.index.insert(cond, id);
        id
    }

    fn leaf(&mut self, atom: Atom) -> CondId {
        self.intern(Cond::Leaf(atom))
    }

    fn not(&mut self, cond: CondId) -> CondId {
        match self.nodes[cond as usize] {
            Cond::Leaf(a) => self.intern(Cond::NotLeaf(a)),
            Cond::NotLeaf(a) => self.intern(Cond::Leaf(a)),
            Cond::And(x, y) => {
                let nx: CondId = self.not(x);
                let ny: CondId = self.not(y);
                self.intern(Cond::Or(nx, ny))
            }
            Cond::Or(x, y) => {
                let nx: CondId = self.not(x);
                let ny: CondId = self.not(y);
                self.intern(Cond::And(nx, ny))
            }
        }
    }

    fn and(&mut self, x: CondId, y: CondId) -> CondId {
        self.intern(Cond::And(x, y))
    }

    fn or(&mut self, x: CondId, y: CondId) -> CondId {
        self.intern(Cond::Or(x, y))
    }

    pub fn nodes(&self) -> &[Cond] {
        &self.nodes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    Block,
    IfThen,
    IfThenElse,
    While,
    DoWhile,
    Switch,
    NaturalLoop,
    SelfLoop,
    Proper,
    Irreducible,
}

#[derive(Debug, Clone)]
pub struct Region {
    pub kind: RegionKind,
    pub entry: NodeId,
    pub cond: Option<CondId>,
    pub scrutinee: Option<Atom>,
    pub children: Vec<RegionId>,
    pub exits: Vec<NodeId>,
    pub head: Option<RegionId>,
}

#[derive(Debug, Clone)]
pub struct StructureResult {
    pub root: Option<RegionId>,
    pub regions: Vec<Region>,
    pub conds: CondPool,
    pub irreducible: bool,
    pub clone_map: CloneMap,
}

impl StructureResult {
    pub const fn is_complete(&self) -> bool {
        self.root.is_some() && !self.irreducible
    }

    pub fn root_kind(&self) -> Option<RegionKind> {
        self.root.map(|r: RegionId| self.regions[r as usize].kind)
    }
}

#[derive(Debug, Clone)]
pub struct CnsOutcome {
    pub cfg: Cfg,
    pub result: StructureResult,
}

#[derive(Debug, Clone)]
enum AbFlow {
    Seq(Option<NodeId>),
    Cond {
        cond: CondId,
        taken: NodeId,
        not_taken: NodeId,
    },
    Switch {
        atom: Atom,
        cases: Vec<(i64, NodeId)>,
        default: Option<NodeId>,
    },
    Region(Vec<NodeId>),
}

struct Collapse {
    region_of: Vec<RegionId>,
    flow: Vec<AbFlow>,
    pure: Vec<bool>,
    returns: Vec<bool>,
    alive: Vec<bool>,
    entry: NodeId,
    regions: Vec<Region>,
    conds: CondPool,
    irreducible: bool,
}

impl FlowView for Collapse {
    fn flow_node_count(&self) -> usize {
        self.flow.len()
    }

    fn flow_is_live(&self, node: NodeId) -> bool {
        self.alive.get(node as usize).copied().unwrap_or(false)
    }

    fn flow_successors(&self, node: NodeId) -> Vec<NodeId> {
        self.successors(node)
    }

    fn flow_returns(&self, node: NodeId) -> bool {
        self.is_exit_sink(node) && self.returns.get(node as usize).copied().unwrap_or(false)
    }
}

pub fn structure(cfg: &Cfg) -> StructureResult {
    let forest: LoopForest = loop_forest(cfg);
    let mut collapse: Collapse = Collapse::new(cfg);
    collapse.run();
    let mut result: StructureResult = collapse.finish();
    if forest.irreducible {
        result.irreducible = true;
    }
    result
}

pub fn structure_with_cns(cfg: &Cfg, budget: CnsBudget) -> Option<CnsOutcome> {
    let unchanged: StructureResult = structure(cfg);
    if unchanged.is_complete() {
        return Some(CnsOutcome {
            cfg: cfg.clone(),
            result: unchanged,
        });
    }
    let (transformed, clone_map): (Cfg, CloneMap) = make_reducible(cfg, budget)?;
    let mut result: StructureResult = structure(&transformed);
    if !result.is_complete()
        || !relowered_matches_original_modulo_clones(
            cfg,
            &transformed,
            &clone_map,
            &BTreeMap::new(),
        )
    {
        return None;
    }
    result.clone_map = clone_map;
    Some(CnsOutcome {
        cfg: transformed,
        result,
    })
}

impl Collapse {
    fn new(cfg: &Cfg) -> Self {
        let count: usize = cfg.len();
        let reach: Vec<bool> = reachable(cfg);
        let mut conds: CondPool = CondPool::default();
        let mut regions: Vec<Region> = Vec::with_capacity(count);
        let mut region_of: Vec<RegionId> = vec![0; count];
        let mut flow: Vec<AbFlow> = Vec::with_capacity(count);
        let pure: Vec<bool> = cfg.nodes.iter().map(|n: &CfgNode| n.pure).collect();
        let returns: Vec<bool> = cfg
            .nodes
            .iter()
            .map(|n: &CfgNode| !matches!(n.term, Terminator::Unreachable))
            .collect();
        for (idx, node) in cfg.nodes.iter().enumerate() {
            let (kind_flow, exits): (AbFlow, Vec<NodeId>) = match &node.term {
                Terminator::Return | Terminator::Unreachable => (AbFlow::Seq(None), Vec::new()),
                Terminator::Goto(t) => (AbFlow::Seq(Some(*t)), vec![*t]),
                Terminator::Branch {
                    atom,
                    taken,
                    not_taken,
                } => {
                    let cond: CondId = conds.leaf(*atom);
                    (
                        AbFlow::Cond {
                            cond,
                            taken: *taken,
                            not_taken: *not_taken,
                        },
                        term_successors(&node.term),
                    )
                }
                Terminator::Switch {
                    atom,
                    cases,
                    default,
                } => (
                    AbFlow::Switch {
                        atom: *atom,
                        cases: cases.clone(),
                        default: *default,
                    },
                    term_successors(&node.term),
                ),
            };
            region_of[idx] = regions.len() as RegionId;
            regions.push(Region {
                kind: RegionKind::Block,
                entry: idx as NodeId,
                cond: None,
                scrutinee: None,
                children: Vec::new(),
                exits,
                head: None,
            });
            flow.push(kind_flow);
        }
        Self {
            region_of,
            flow,
            pure,
            returns,
            alive: reach,
            entry: cfg.entry,
            regions,
            conds,
            irreducible: false,
        }
    }

    fn successors(&self, node: NodeId) -> Vec<NodeId> {
        match &self.flow[node as usize] {
            AbFlow::Seq(None) => Vec::new(),
            AbFlow::Seq(Some(s)) => vec![*s],
            AbFlow::Cond {
                taken, not_taken, ..
            } => {
                if taken == not_taken {
                    vec![*taken]
                } else {
                    vec![*taken, *not_taken]
                }
            }
            AbFlow::Switch { cases, default, .. } => {
                let mut out: Vec<NodeId> = Vec::new();
                for (_, t) in cases {
                    if !out.contains(t) {
                        out.push(*t);
                    }
                }
                if let Some(d) = default
                    && !out.contains(d)
                {
                    out.push(*d);
                }
                out
            }
            AbFlow::Region(v) => v.clone(),
        }
    }

    fn single_succ(&self, node: NodeId) -> Option<NodeId> {
        match &self.flow[node as usize] {
            AbFlow::Seq(Some(s)) => Some(*s),
            AbFlow::Region(v) if v.len() == 1 => Some(v[0]),
            _ => None,
        }
    }

    fn is_exit_sink(&self, node: NodeId) -> bool {
        matches!(&self.flow[node as usize], AbFlow::Seq(None))
            || matches!(&self.flow[node as usize], AbFlow::Region(v) if v.is_empty())
    }

    fn absorb_returns(&mut self, node: NodeId, folded: NodeId) {
        self.returns[node as usize] = self.returns[node as usize] && self.returns[folded as usize];
    }

    fn alive_nodes(&self) -> Vec<NodeId> {
        (0..self.alive.len() as NodeId)
            .filter(|n: &NodeId| self.alive[*n as usize])
            .collect()
    }

    fn preds(&self) -> Vec<Vec<NodeId>> {
        let count: usize = self.flow.len();
        let mut preds: Vec<Vec<NodeId>> = vec![Vec::new(); count];
        for from in self.alive_nodes() {
            for s in self.successors(from) {
                if self.alive[s as usize] && !preds[s as usize].contains(&from) {
                    preds[s as usize].push(from);
                }
            }
        }
        preds
    }

    fn postorder(&self) -> Vec<NodeId> {
        let count: usize = self.flow.len();
        let mut visited: Vec<bool> = vec![false; count];
        let mut order: Vec<NodeId> = Vec::new();
        let mut stack: Vec<(NodeId, Vec<NodeId>, usize)> = Vec::new();
        if !self.alive[self.entry as usize] {
            return order;
        }
        visited[self.entry as usize] = true;
        stack.push((self.entry, self.successors(self.entry), 0));
        while let Some((node, succs, idx)) = stack.last_mut() {
            if *idx < succs.len() {
                let child: NodeId = succs[*idx];
                *idx += 1;
                if self.alive[child as usize] && !visited[child as usize] {
                    visited[child as usize] = true;
                    let child_succs: Vec<NodeId> = self.successors(child);
                    stack.push((child, child_succs, 0));
                }
            } else {
                order.push(*node);
                stack.pop();
            }
        }
        order
    }

    fn run(&mut self) {
        loop {
            while self.reduce_one_acyclic() {}
            if self.reduce_one_cyclic() {
                continue;
            }
            break;
        }
        if self.irreducible {
            return;
        }
        if self.alive_nodes().len() > 1 {
            if self.has_live_cycle() {
                self.irreducible = true;
            } else {
                self.reduce_proper();
            }
        }
    }

    fn reduce_one_acyclic(&mut self) -> bool {
        let preds: Vec<Vec<NodeId>> = self.preds();
        let headers: BTreeSet<NodeId> = self.loop_boundary();
        for node in self.postorder() {
            if self.try_block(node, &preds, &headers) {
                return true;
            }
        }
        for node in self.postorder() {
            if self.try_short_circuit(node, &preds, &headers) {
                return true;
            }
        }
        for node in self.postorder() {
            if self.try_if_then_else(node, &preds, &headers)
                || self.try_if_then(node, &preds, &headers)
                || self.try_switch(node, &preds, &headers)
            {
                return true;
            }
        }
        false
    }

    fn try_block(
        &mut self,
        node: NodeId,
        preds: &[Vec<NodeId>],
        headers: &BTreeSet<NodeId>,
    ) -> bool {
        let Some(succ): Option<NodeId> = self.single_succ(node) else {
            return false;
        };
        if succ == node || succ == self.entry || headers.contains(&succ) {
            return false;
        }
        if preds[succ as usize].as_slice() != [node] {
            return false;
        }
        if self.successors(succ).contains(&node) {
            return false;
        }
        let child_a: RegionId = self.region_of[node as usize];
        let child_b: RegionId = self.region_of[succ as usize];
        let mut children: Vec<RegionId> = self.block_children(child_a);
        children.extend(self.block_children(child_b));
        let exits: Vec<NodeId> = self.successors(succ);
        let region: RegionId = self.push_region(Region {
            kind: RegionKind::Block,
            entry: self.regions[child_a as usize].entry,
            cond: None,
            scrutinee: None,
            children,
            exits,
            head: None,
        });
        self.flow[node as usize] = self.flow[succ as usize].clone();
        self.pure[node as usize] = self.pure[node as usize] && self.pure[succ as usize];
        self.returns[node as usize] = self.returns[succ as usize];
        self.region_of[node as usize] = region;
        self.alive[succ as usize] = false;
        true
    }

    fn block_children(&self, region: RegionId) -> Vec<RegionId> {
        if self.regions[region as usize].kind == RegionKind::Block
            && !self.regions[region as usize].children.is_empty()
        {
            self.regions[region as usize].children.clone()
        } else {
            vec![region]
        }
    }

    fn try_if_then_else(
        &mut self,
        node: NodeId,
        preds: &[Vec<NodeId>],
        headers: &BTreeSet<NodeId>,
    ) -> bool {
        if headers.contains(&node) {
            return false;
        }
        let AbFlow::Cond {
            cond,
            taken,
            not_taken,
        } = self.flow[node as usize]
        else {
            return false;
        };
        if taken == not_taken {
            return false;
        }
        if headers.contains(&taken) || headers.contains(&not_taken) {
            return false;
        }
        if preds[taken as usize].as_slice() != [node]
            || preds[not_taken as usize].as_slice() != [node]
        {
            return false;
        }
        if !self.is_simple_branchless(taken) || !self.is_simple_branchless(not_taken) {
            return false;
        }
        let then_exit: Option<NodeId> = self.single_succ(taken);
        let else_exit: Option<NodeId> = self.single_succ(not_taken);
        let mut targets: Vec<NodeId> = Vec::new();
        if let Some(t) = then_exit {
            targets.push(t);
        }
        if let Some(e) = else_exit
            && !targets.contains(&e)
        {
            targets.push(e);
        }
        if targets.len() > 1 {
            return false;
        }
        if targets.first() == Some(&node) {
            return false;
        }
        let then_region: RegionId = self.region_of[taken as usize];
        let else_region: RegionId = self.region_of[not_taken as usize];
        let head: RegionId = self.region_of[node as usize];
        let join: Option<NodeId> = targets.first().copied();
        let region: RegionId = self.push_region(Region {
            kind: RegionKind::IfThenElse,
            entry: self.regions[head as usize].entry,
            cond: Some(cond),
            scrutinee: None,
            children: vec![then_region, else_region],
            exits: targets,
            head: Some(head),
        });
        self.flow[node as usize] = AbFlow::Seq(join);
        self.absorb_returns(node, taken);
        self.absorb_returns(node, not_taken);
        self.region_of[node as usize] = region;
        self.alive[taken as usize] = false;
        self.alive[not_taken as usize] = false;
        true
    }

    fn try_if_then(
        &mut self,
        node: NodeId,
        preds: &[Vec<NodeId>],
        headers: &BTreeSet<NodeId>,
    ) -> bool {
        if headers.contains(&node) {
            return false;
        }
        let AbFlow::Cond {
            cond,
            taken,
            not_taken,
        } = self.flow[node as usize]
        else {
            return false;
        };
        if taken == not_taken {
            return false;
        }
        if let Some(region) = self.if_then_arm(node, cond, taken, not_taken, false, preds, headers)
        {
            self.region_of[node as usize] = region;
            self.flow[node as usize] = AbFlow::Seq(Some(not_taken));
            self.absorb_returns(node, taken);
            self.alive[taken as usize] = false;
            return true;
        }
        if let Some(region) = self.if_then_arm(node, cond, not_taken, taken, true, preds, headers) {
            self.region_of[node as usize] = region;
            self.flow[node as usize] = AbFlow::Seq(Some(taken));
            self.absorb_returns(node, not_taken);
            self.alive[not_taken as usize] = false;
            return true;
        }
        false
    }

    fn if_then_arm(
        &mut self,
        node: NodeId,
        cond: CondId,
        arm: NodeId,
        cont: NodeId,
        negate: bool,
        preds: &[Vec<NodeId>],
        headers: &BTreeSet<NodeId>,
    ) -> Option<RegionId> {
        if headers.contains(&arm) {
            return None;
        }
        if preds[arm as usize].as_slice() != [node] {
            return None;
        }
        if !self.is_simple_branchless(arm) {
            return None;
        }
        let arm_to_cont: bool = self.single_succ(arm) == Some(cont);
        let arm_returns: bool = self.is_exit_sink(arm);
        if !arm_to_cont && !arm_returns {
            return None;
        }
        let cond_id: CondId = if negate { self.conds.not(cond) } else { cond };
        let arm_region: RegionId = self.region_of[arm as usize];
        let head: RegionId = self.region_of[node as usize];
        Some(self.push_region(Region {
            kind: RegionKind::IfThen,
            entry: self.regions[head as usize].entry,
            cond: Some(cond_id),
            scrutinee: None,
            children: vec![arm_region],
            exits: vec![cont],
            head: Some(head),
        }))
    }

    fn try_short_circuit(
        &mut self,
        node: NodeId,
        preds: &[Vec<NodeId>],
        headers: &BTreeSet<NodeId>,
    ) -> bool {
        if headers.contains(&node) {
            return false;
        }
        let AbFlow::Cond {
            cond: cond_p,
            taken,
            not_taken,
        } = self.flow[node as usize]
        else {
            return false;
        };
        if taken == not_taken {
            return false;
        }
        if let AbFlow::Cond {
            cond: cond_q,
            taken: ta,
            not_taken: fa,
        } = self.flow[not_taken as usize]
            && !headers.contains(&not_taken)
            && preds[not_taken as usize].as_slice() == [node]
            && self.pure[not_taken as usize]
            && ta == taken
            && fa != node
        {
            let fused: CondId = self.conds.or(cond_p, cond_q);
            self.fuse_short_circuit(node, not_taken, fused, taken, fa);
            return true;
        }
        if let AbFlow::Cond {
            cond: cond_q,
            taken: ta,
            not_taken: fa,
        } = self.flow[taken as usize]
            && !headers.contains(&taken)
            && preds[taken as usize].as_slice() == [node]
            && self.pure[taken as usize]
            && fa == not_taken
            && ta != node
        {
            let fused: CondId = self.conds.and(cond_p, cond_q);
            self.fuse_short_circuit(node, taken, fused, ta, not_taken);
            return true;
        }
        false
    }

    fn fuse_short_circuit(
        &mut self,
        node: NodeId,
        second: NodeId,
        fused: CondId,
        taken: NodeId,
        not_taken: NodeId,
    ) {
        let region_a: RegionId = self.region_of[node as usize];
        let region_b: RegionId = self.region_of[second as usize];
        let mut children: Vec<RegionId> = self.block_children(region_a);
        children.extend(self.block_children(region_b));
        let region: RegionId = self.push_region(Region {
            kind: RegionKind::Block,
            entry: self.regions[region_a as usize].entry,
            cond: None,
            scrutinee: None,
            children,
            exits: vec![taken, not_taken],
            head: None,
        });
        self.region_of[node as usize] = region;
        self.pure[node as usize] = self.pure[node as usize] && self.pure[second as usize];
        self.absorb_returns(node, second);
        self.flow[node as usize] = AbFlow::Cond {
            cond: fused,
            taken,
            not_taken,
        };
        self.alive[second as usize] = false;
    }

    fn try_switch(
        &mut self,
        node: NodeId,
        preds: &[Vec<NodeId>],
        headers: &BTreeSet<NodeId>,
    ) -> bool {
        if headers.contains(&node) {
            return false;
        }
        let AbFlow::Switch {
            atom,
            cases,
            default,
        } = self.flow[node as usize].clone()
        else {
            return false;
        };
        let mut targets: Vec<NodeId> = Vec::new();
        for (_, t) in &cases {
            if !targets.contains(t) {
                targets.push(*t);
            }
        }
        if let Some(d) = default
            && !targets.contains(&d)
        {
            targets.push(d);
        }
        let mut bodies: Vec<NodeId> = Vec::new();
        let mut join: Option<NodeId> = None;
        for &t in &targets {
            if preds[t as usize].as_slice() == [node]
                && self.is_simple_branchless(t)
                && !headers.contains(&t)
            {
                bodies.push(t);
                if let Some(exit) = self.single_succ(t) {
                    match join {
                        None => join = Some(exit),
                        Some(j) if j == exit => {}
                        Some(_) => return false,
                    }
                }
            } else {
                match join {
                    None => join = Some(t),
                    Some(j) if j == t => {}
                    Some(_) => return false,
                }
            }
        }
        if bodies.is_empty() {
            return false;
        }
        if join == Some(node) {
            return false;
        }
        let mut children: Vec<RegionId> = vec![self.region_of[node as usize]];
        for &b in &bodies {
            children.push(self.region_of[b as usize]);
        }
        let exits: Vec<NodeId> = join.into_iter().collect();
        let region: RegionId = self.push_region(Region {
            kind: RegionKind::Switch,
            entry: self.regions[self.region_of[node as usize] as usize].entry,
            cond: None,
            scrutinee: Some(atom),
            children,
            exits,
            head: None,
        });
        self.flow[node as usize] = AbFlow::Seq(join);
        self.region_of[node as usize] = region;
        for &b in &bodies {
            self.absorb_returns(node, b);
            self.alive[b as usize] = false;
        }
        true
    }

    fn is_simple_branchless(&self, node: NodeId) -> bool {
        matches!(
            &self.flow[node as usize],
            AbFlow::Seq(_) | AbFlow::Region(_)
        )
    }

    fn abstract_dominators(&self) -> Dominators {
        let succ: Vec<Vec<NodeId>> = (0..self.flow.len() as NodeId)
            .map(|n: NodeId| {
                if self.alive[n as usize] {
                    self.successors(n)
                } else {
                    Vec::new()
                }
            })
            .collect();
        let graph: AdjGraph = AdjGraph::new(self.entry, succ);
        Dominators::compute(&graph)
    }

    fn back_edges(&self, dom: &Dominators) -> Vec<(NodeId, NodeId)> {
        let mut edges: Vec<(NodeId, NodeId)> = Vec::new();
        for u in self.alive_nodes() {
            for v in self.successors(u) {
                if self.alive[v as usize] && dom.dominates(v, u) {
                    edges.push((u, v));
                }
            }
        }
        edges
    }

    fn natural_loop_body(&self, header: NodeId, latches: &[NodeId]) -> BTreeSet<NodeId> {
        let preds: Vec<Vec<NodeId>> = self.preds();
        disrobe_core::dominators::natural_loop_body(
            header,
            latches,
            |node: NodeId, emit: &mut dyn FnMut(NodeId)| {
                for &pred in &preds[node as usize] {
                    emit(pred);
                }
            },
        )
    }

    fn loop_boundary(&self) -> BTreeSet<NodeId> {
        let dom: Dominators = self.abstract_dominators();
        let mut boundary: BTreeSet<NodeId> = BTreeSet::new();
        for (u, v) in self.back_edges(&dom) {
            boundary.insert(u);
            boundary.insert(v);
        }
        boundary
    }

    fn reduce_one_cyclic(&mut self) -> bool {
        let dom: Dominators = self.abstract_dominators();
        let back: Vec<(NodeId, NodeId)> = self.back_edges(&dom);
        if back.is_empty() {
            if self.has_live_cycle() {
                self.irreducible = true;
            }
            return false;
        }
        let mut headers: Vec<NodeId> = Vec::new();
        for &(_, v) in &back {
            if !headers.contains(&v) {
                headers.push(v);
            }
        }
        let header_set: BTreeSet<NodeId> = headers.iter().copied().collect();
        let mut chosen: Option<(NodeId, BTreeSet<NodeId>)> = None;
        for &header in &headers {
            let latches: Vec<NodeId> = back
                .iter()
                .filter(|(_, v): &&(NodeId, NodeId)| *v == header)
                .map(|(u, _): &(NodeId, NodeId)| *u)
                .collect();
            let body: BTreeSet<NodeId> = self.natural_loop_body(header, &latches);
            let innermost: bool = !body
                .iter()
                .any(|n: &NodeId| *n != header && header_set.contains(n));
            let smaller: bool = chosen
                .as_ref()
                .is_none_or(|(_, b): &(NodeId, BTreeSet<NodeId>)| body.len() < b.len());
            if innermost && smaller {
                chosen = Some((header, body));
            }
        }
        let Some((header, body)): Option<(NodeId, BTreeSet<NodeId>)> = chosen else {
            self.irreducible = true;
            return false;
        };
        let body: BTreeSet<NodeId> =
            body_absorbing_return_tails(self, header, &body).unwrap_or(body);
        let component: Vec<NodeId> = body.into_iter().collect();
        self.collapse_loop(&component, header);
        true
    }

    fn collapse_loop(&mut self, component: &[NodeId], header: NodeId) {
        let member: BTreeSet<NodeId> = component.iter().copied().collect();
        let mut exits: Vec<NodeId> = Vec::new();
        for &node in component {
            for s in self.successors(node) {
                if !member.contains(&s) && !exits.contains(&s) {
                    exits.push(s);
                }
            }
        }
        let (kind, cond): (RegionKind, Option<CondId>) = self.classify_loop(component, header);
        let mut children: Vec<RegionId> = vec![self.region_of[header as usize]];
        for &node in component {
            if node != header {
                children.push(self.region_of[node as usize]);
            }
        }
        let region: RegionId = self.push_region(Region {
            kind,
            entry: self.regions[self.region_of[header as usize] as usize].entry,
            cond,
            scrutinee: None,
            children,
            exits: exits.clone(),
            head: None,
        });
        self.flow[header as usize] = match exits.len() {
            0 => AbFlow::Seq(None),
            1 => AbFlow::Seq(Some(exits[0])),
            _ => AbFlow::Region(exits),
        };
        self.region_of[header as usize] = region;
        for &node in component {
            if node != header {
                self.absorb_returns(header, node);
                self.alive[node as usize] = false;
            }
        }
    }

    fn classify_loop(&self, component: &[NodeId], header: NodeId) -> (RegionKind, Option<CondId>) {
        let member: BTreeSet<NodeId> = component.iter().copied().collect();
        if component.len() == 1 {
            return (RegionKind::SelfLoop, None);
        }
        if component.len() == 2 {
            let other: NodeId = component
                .iter()
                .copied()
                .find(|&n: &NodeId| n != header)
                .unwrap_or(header);
            if let AbFlow::Cond {
                cond,
                taken,
                not_taken,
            } = self.flow[header as usize]
            {
                let taken_in: bool = member.contains(&taken);
                let not_taken_in: bool = member.contains(&not_taken);
                if taken_in ^ not_taken_in {
                    return (RegionKind::While, Some(cond));
                }
            }
            if let AbFlow::Cond {
                cond,
                taken,
                not_taken,
            } = self.flow[other as usize]
                && self.single_succ(header) == Some(other)
            {
                let back_taken: bool = taken == header;
                let back_not_taken: bool = not_taken == header;
                if back_taken ^ back_not_taken {
                    return (RegionKind::DoWhile, Some(cond));
                }
            }
        }
        (RegionKind::NaturalLoop, None)
    }

    fn has_live_cycle(&self) -> bool {
        self.sccs().into_iter().any(|c: Vec<NodeId>| {
            c.len() > 1 || (c.len() == 1 && self.successors(c[0]).contains(&c[0]))
        })
    }

    fn reduce_proper(&mut self) {
        let live: Vec<NodeId> = self.alive_nodes();
        let mut exits: Vec<NodeId> = Vec::new();
        let member: BTreeSet<NodeId> = live.iter().copied().collect();
        for &node in &live {
            for s in self.successors(node) {
                if !member.contains(&s) && !exits.contains(&s) {
                    exits.push(s);
                }
            }
        }
        let mut children: Vec<RegionId> = vec![self.region_of[self.entry as usize]];
        for &node in &live {
            if node != self.entry {
                children.push(self.region_of[node as usize]);
            }
        }
        let region: RegionId = self.push_region(Region {
            kind: RegionKind::Proper,
            entry: self.regions[self.region_of[self.entry as usize] as usize].entry,
            cond: None,
            scrutinee: None,
            children,
            exits: exits.clone(),
            head: None,
        });
        self.flow[self.entry as usize] = match exits.len() {
            0 => AbFlow::Seq(None),
            1 => AbFlow::Seq(Some(exits[0])),
            _ => AbFlow::Region(exits),
        };
        self.region_of[self.entry as usize] = region;
        for &node in &live {
            if node != self.entry {
                self.absorb_returns(self.entry, node);
                self.alive[node as usize] = false;
            }
        }
    }

    fn sccs(&self) -> Vec<Vec<NodeId>> {
        let order: Vec<NodeId> = self.postorder();
        let mut rgraph: Vec<Vec<NodeId>> = vec![Vec::new(); self.flow.len()];
        for &node in &order {
            for s in self.successors(node) {
                if self.alive[s as usize] {
                    rgraph[s as usize].push(node);
                }
            }
        }
        let mut assigned: Vec<bool> = vec![false; self.flow.len()];
        let mut components: Vec<Vec<NodeId>> = Vec::new();
        for &root in order.iter().rev() {
            if assigned[root as usize] {
                continue;
            }
            let mut component: Vec<NodeId> = Vec::new();
            let mut stack: Vec<NodeId> = vec![root];
            assigned[root as usize] = true;
            while let Some(node) = stack.pop() {
                component.push(node);
                for &pred in &rgraph[node as usize] {
                    if !assigned[pred as usize] {
                        assigned[pred as usize] = true;
                        stack.push(pred);
                    }
                }
            }
            component.sort_unstable();
            components.push(component);
        }
        components
    }

    fn push_region(&mut self, region: Region) -> RegionId {
        let id: RegionId = self.regions.len() as RegionId;
        self.regions.push(region);
        id
    }

    fn finish(mut self) -> StructureResult {
        let live: Vec<NodeId> = self.alive_nodes();
        if self.irreducible || live.len() != 1 {
            self.irreducible = true;
            let mut children: Vec<RegionId> = live
                .iter()
                .map(|n: &NodeId| self.region_of[*n as usize])
                .collect();
            if children.is_empty() {
                children.push(self.region_of[self.entry as usize]);
            }
            let region: RegionId = self.push_region(Region {
                kind: RegionKind::Irreducible,
                entry: self.entry,
                cond: None,
                scrutinee: None,
                children,
                exits: Vec::new(),
                head: None,
            });
            return StructureResult {
                root: Some(region),
                regions: self.regions,
                conds: self.conds,
                irreducible: true,
                clone_map: BTreeMap::new(),
            };
        }
        let root: RegionId = self.region_of[live[0] as usize];
        StructureResult {
            root: Some(root),
            regions: self.regions,
            conds: self.conds,
            irreducible: false,
            clone_map: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngExt as _, SeedableRng as _};

    fn goto(t: NodeId) -> CfgNode {
        CfgNode {
            term: Terminator::Goto(t),
            pure: true,
        }
    }

    fn ret() -> CfgNode {
        CfgNode {
            term: Terminator::Return,
            pure: true,
        }
    }

    fn br(atom: Atom, taken: NodeId, not_taken: NodeId) -> CfgNode {
        CfgNode {
            term: Terminator::Branch {
                atom,
                taken,
                not_taken,
            },
            pure: true,
        }
    }

    #[test]
    fn linear_chain_collapses_to_block() {
        let cfg: Cfg = Cfg::new(0, vec![goto(1), goto(2), ret()]).unwrap();
        let result: StructureResult = structure(&cfg);
        assert!(result.is_complete());
        assert_eq!(result.root_kind(), Some(RegionKind::Block));
    }

    #[test]
    fn if_then_collapses() {
        let cfg: Cfg = Cfg::new(0, vec![br(0, 1, 2), goto(2), ret()]).unwrap();
        let result: StructureResult = structure(&cfg);
        assert!(result.is_complete(), "{result:?}");
        assert_eq!(result.root_kind(), Some(RegionKind::Block));
        assert!(
            result
                .regions
                .iter()
                .any(|r: &Region| r.kind == RegionKind::IfThen)
        );
    }

    #[test]
    fn if_then_else_collapses() {
        let cfg: Cfg = Cfg::new(0, vec![br(0, 1, 2), goto(3), goto(3), ret()]).unwrap();
        let result: StructureResult = structure(&cfg);
        assert!(result.is_complete(), "{result:?}");
        let ite: &Region = result
            .regions
            .iter()
            .find(|r: &&Region| r.kind == RegionKind::IfThenElse)
            .expect("if-then-else region");
        assert!(ite.cond.is_some(), "if-then-else must carry a condition");
        assert_eq!(ite.exits, vec![3], "both arms join at node 3");
    }

    #[test]
    fn multi_return_chain_completes() {
        let cfg: Cfg = Cfg::new(0, vec![br(0, 1, 2), ret(), br(1, 3, 4), ret(), ret()]).unwrap();
        let result: StructureResult = structure(&cfg);
        assert!(result.is_complete(), "{result:?}");
    }

    #[test]
    fn pre_tested_while_collapses() {
        let cfg: Cfg = Cfg::new(0, vec![goto(1), br(0, 2, 3), goto(1), ret()]).unwrap();
        let result: StructureResult = structure(&cfg);
        assert!(result.is_complete(), "{result:?}");
        assert!(
            result
                .regions
                .iter()
                .any(|r: &Region| r.kind == RegionKind::While),
            "{result:?}"
        );
    }

    #[test]
    fn post_tested_do_while_collapses() {
        let cfg: Cfg = Cfg::new(0, vec![goto(1), goto(2), br(0, 1, 3), ret()]).unwrap();
        let result: StructureResult = structure(&cfg);
        assert!(result.is_complete(), "{result:?}");
        assert!(
            result
                .regions
                .iter()
                .any(|r: &Region| r.kind == RegionKind::DoWhile),
            "{result:?}"
        );
    }

    #[test]
    fn self_loop_collapses() {
        let self_cfg: Cfg = Cfg::new(0, vec![br(0, 0, 1), ret()]).unwrap();
        let result: StructureResult = structure(&self_cfg);
        assert!(result.is_complete(), "{result:?}");
        assert!(
            result
                .regions
                .iter()
                .any(|r: &Region| r.kind == RegionKind::SelfLoop)
        );
    }

    #[test]
    fn short_circuit_or_fuses_to_or_cond() {
        let cfg: Cfg = Cfg::new(0, vec![br(0, 3, 1), br(1, 3, 2), goto(3), ret()]).unwrap();
        let result: StructureResult = structure(&cfg);
        assert!(result.is_complete(), "{result:?}");
        assert!(
            result
                .conds
                .nodes()
                .iter()
                .any(|c: &Cond| matches!(c, Cond::Or(_, _))),
            "expected a fused OR condition: {result:?}"
        );
    }

    #[test]
    fn short_circuit_and_fuses_to_and_cond() {
        let cfg: Cfg = Cfg::new(0, vec![br(0, 1, 3), br(1, 2, 3), goto(3), ret()]).unwrap();
        let result: StructureResult = structure(&cfg);
        assert!(result.is_complete(), "{result:?}");
        assert!(
            result
                .conds
                .nodes()
                .iter()
                .any(|c: &Cond| matches!(c, Cond::And(_, _))),
            "expected a fused AND condition: {result:?}"
        );
    }

    #[test]
    fn impure_second_predicate_is_not_fused() {
        let mut nodes: Vec<CfgNode> = vec![br(0, 3, 1), br(1, 3, 2), goto(3), ret()];
        nodes[1].pure = false;
        let cfg: Cfg = Cfg::new(0, nodes).unwrap();
        let result: StructureResult = structure(&cfg);
        assert!(result.is_complete(), "{result:?}");
        assert!(
            !result
                .conds
                .nodes()
                .iter()
                .any(|c: &Cond| matches!(c, Cond::Or(_, _))),
            "an impure second predicate must not be short-circuit fused: {result:?}"
        );
    }

    #[test]
    fn switch_region_collapses() {
        let switch: CfgNode = CfgNode {
            term: Terminator::Switch {
                atom: 0,
                cases: vec![(0, 1), (1, 2), (2, 3)],
                default: Some(4),
            },
            pure: true,
        };
        let cfg: Cfg = Cfg::new(0, vec![switch, ret(), ret(), ret(), ret()]).unwrap();
        let result: StructureResult = structure(&cfg);
        assert!(result.is_complete(), "{result:?}");
        assert_eq!(result.root_kind(), Some(RegionKind::Switch));
        let root: &Region = &result.regions[result.root.unwrap() as usize];
        assert_eq!(root.scrutinee, Some(0));
        assert_eq!(root.entry, 0);
        assert!(root.exits.is_empty(), "every case returns: {result:?}");
    }

    #[test]
    fn nested_loop_collapses_completely() {
        let cfg: Cfg =
            Cfg::new(0, vec![goto(1), br(0, 2, 4), br(1, 3, 1), goto(2), ret()]).unwrap();
        let result: StructureResult = structure(&cfg);
        assert!(result.is_complete(), "{result:?}");
        let loop_regions: usize = result
            .regions
            .iter()
            .filter(|r: &&Region| {
                matches!(
                    r.kind,
                    RegionKind::While | RegionKind::DoWhile | RegionKind::NaturalLoop
                )
            })
            .count();
        assert!(loop_regions >= 2, "expected two nested loops: {result:?}");
    }

    #[test]
    fn irreducible_two_entry_cycle_is_rejected() {
        let cfg: Cfg = Cfg::new(0, vec![br(0, 1, 2), goto(2), br(1, 1, 3), ret()]).unwrap();
        let result: StructureResult = structure(&cfg);
        assert!(!result.is_complete(), "{result:?}");
        assert!(result.irreducible);
        assert!(loop_forest(&cfg).irreducible);
    }

    #[test]
    fn scc_finds_the_two_entry_body_cycle() {
        let cfg: Cfg = Cfg::new(0, vec![br(0, 1, 2), goto(2), br(1, 1, 3), ret()]).unwrap();
        let cyclic: Vec<Vec<NodeId>> = strongly_connected_components(&cfg)
            .into_iter()
            .filter(|c: &Vec<NodeId>| c.len() > 1)
            .collect();
        assert_eq!(cyclic, vec![vec![1, 2]], "{cyclic:?}");
    }

    #[test]
    fn multi_entry_scc_reports_both_entries_and_external_edges() {
        let cfg: Cfg = Cfg::new(0, vec![br(0, 1, 2), goto(2), br(1, 1, 3), ret()]).unwrap();
        let sccs: Vec<IrreducibleEntry> = multi_entry_irreducible_sccs(&cfg);
        assert_eq!(sccs.len(), 1, "{sccs:?}");
        assert_eq!(sccs[0].entries, vec![1, 2]);
        assert!(sccs[0].external_edges.contains(&(0, 1)));
        assert!(sccs[0].external_edges.contains(&(0, 2)));
    }

    #[test]
    fn reducible_graph_has_no_multi_entry_scc() {
        let cfg: Cfg = Cfg::new(0, vec![goto(1), br(0, 2, 3), goto(1), ret()]).unwrap();
        assert!(multi_entry_irreducible_sccs(&cfg).is_empty());
    }

    #[test]
    fn bisimulation_guard_accepts_identity() {
        let cfg: Cfg = Cfg::new(0, vec![goto(1), br(0, 2, 3), goto(1), ret()]).unwrap();
        let empty: BTreeMap<NodeId, NodeId> = BTreeMap::new();
        assert!(relowered_matches_original(&cfg, &cfg, &empty));
    }

    #[test]
    fn bisimulation_guard_collapses_residual_goto_stub() {
        let original: Cfg = Cfg::new(0, vec![br(0, 1, 2), goto(2), br(1, 1, 3), ret()]).unwrap();
        let rendered: Cfg =
            Cfg::new(0, vec![br(0, 1, 4), goto(2), br(1, 1, 3), ret(), ret()]).unwrap();
        let residual: BTreeMap<NodeId, NodeId> = BTreeMap::from([(4, 2)]);
        assert!(relowered_matches_original(&original, &rendered, &residual));
    }

    #[test]
    fn bisimulation_guard_rejects_wrong_residual_target() {
        let original: Cfg = Cfg::new(0, vec![br(0, 1, 2), goto(2), br(1, 1, 3), ret()]).unwrap();
        let rendered: Cfg =
            Cfg::new(0, vec![br(0, 1, 4), goto(2), br(1, 1, 3), ret(), ret()]).unwrap();
        let residual: BTreeMap<NodeId, NodeId> = BTreeMap::from([(4, 3)]);
        assert!(!relowered_matches_original(&original, &rendered, &residual));
    }

    #[test]
    fn bisimulation_guard_rejects_dropped_edge() {
        let original: Cfg = Cfg::new(0, vec![br(0, 1, 2), goto(2), br(1, 1, 3), ret()]).unwrap();
        let rendered: Cfg = Cfg::new(0, vec![goto(1), goto(2), br(1, 1, 3), ret()]).unwrap();
        let empty: BTreeMap<NodeId, NodeId> = BTreeMap::new();
        assert!(!relowered_matches_original(&original, &rendered, &empty));
    }

    #[test]
    fn cond_pool_double_negation_and_de_morgan() {
        let mut pool: CondPool = CondPool::default();
        let a: CondId = pool.leaf(0);
        let b: CondId = pool.leaf(1);
        let not_a: CondId = pool.not(a);
        let not_not_a: CondId = pool.not(not_a);
        assert_eq!(not_not_a, a, "double negation must cancel");
        let and_ab: CondId = pool.and(a, b);
        let not_and: CondId = pool.not(and_ab);
        assert!(matches!(pool.nodes()[not_and as usize], Cond::Or(_, _)));
        let dup: CondId = pool.and(a, b);
        assert_eq!(dup, and_ab, "hash-consing must dedup identical trees");
    }

    #[test]
    fn post_dominators_route_multiple_returns_to_exit() {
        let cfg: Cfg = Cfg::new(0, vec![br(0, 1, 2), ret(), ret()]).unwrap();
        let pdom: PostDominators = PostDominators::compute(&cfg);
        assert_eq!(pdom.immediate_post_dominator(1), Some(pdom.exit()));
        assert_eq!(pdom.immediate_post_dominator(2), Some(pdom.exit()));
        assert_eq!(pdom.immediate_post_dominator(0), Some(pdom.exit()));
    }

    #[test]
    fn noreturn_call_routes_to_exit_and_structures() {
        let abort: CfgNode = CfgNode {
            term: Terminator::Unreachable,
            pure: false,
        };
        let cfg: Cfg = Cfg::new(0, vec![br(0, 1, 2), abort, ret()]).unwrap();
        let pdom: PostDominators = PostDominators::compute(&cfg);
        assert_eq!(pdom.immediate_post_dominator(1), Some(pdom.exit()));
        let result: StructureResult = structure(&cfg);
        assert!(
            result.is_complete(),
            "an if-guarded noreturn call must structure: {result:?}"
        );
    }

    #[test]
    fn post_dominators_diamond_join() {
        let cfg: Cfg = Cfg::new(0, vec![br(0, 1, 2), goto(3), goto(3), ret()]).unwrap();
        let pdom: PostDominators = PostDominators::compute(&cfg);
        assert_eq!(pdom.immediate_post_dominator(0), Some(3));
        assert!(pdom.post_dominates(3, 0));
        assert!(!pdom.post_dominates(1, 0));
    }

    #[test]
    fn loop_forest_reducible_single_loop() {
        let cfg: Cfg = Cfg::new(0, vec![goto(1), br(0, 2, 3), goto(1), ret()]).unwrap();
        let forest: LoopForest = loop_forest(&cfg);
        assert!(!forest.irreducible);
        assert_eq!(forest.loops.len(), 1);
        assert_eq!(forest.loops[0].header, 1);
        assert_eq!(forest.loops[0].latches, vec![2]);
        assert!(forest.loops[0].body.contains(&2));
    }

    #[test]
    fn loop_forest_nesting_parent_is_set() {
        let cfg: Cfg =
            Cfg::new(0, vec![goto(1), br(0, 2, 4), br(1, 3, 1), goto(2), ret()]).unwrap();
        let forest: LoopForest = loop_forest(&cfg);
        assert!(!forest.irreducible);
        assert_eq!(forest.loops.len(), 2);
        assert!(
            forest
                .loops
                .iter()
                .any(|l: &NaturalLoop| l.parent.is_some())
        );
    }

    fn random_reducible(rng: &mut StdRng, count: usize) -> Cfg {
        let mut nodes: Vec<CfgNode> = Vec::with_capacity(count);
        for i in 0..count {
            if i + 1 >= count {
                nodes.push(ret());
                continue;
            }
            let roll: u32 = rng.random::<u32>() % 3;
            if roll == 0 {
                nodes.push(goto(i as NodeId + 1));
            } else {
                let span: u32 = (count - i - 1) as u32;
                let taken: NodeId = i as NodeId + 1 + (rng.random::<u32>() % span.max(1));
                let taken: NodeId = taken.min(count as NodeId - 1);
                nodes.push(br(i as Atom, taken, i as NodeId + 1));
            }
        }
        Cfg::new(0, nodes).unwrap()
    }

    #[test]
    fn random_reducible_graphs_always_complete() {
        let mut rng: StdRng = StdRng::seed_from_u64(0x5EED_1234);
        for _ in 0..500 {
            let count: usize = 2 + (rng.random::<u32>() % 10) as usize;
            let cfg: Cfg = random_reducible(&mut rng, count);
            let forest: LoopForest = loop_forest(&cfg);
            assert!(
                !forest.irreducible,
                "generator must stay reducible: {cfg:?}"
            );
            let result: StructureResult = structure(&cfg);
            assert!(
                result.is_complete(),
                "reducible acyclic-forward graph must fully structure: {cfg:?} -> {result:?}"
            );
            assert!(!result.irreducible);
        }
    }

    #[test]
    fn engine_irreducibility_matches_loop_forest() {
        let mut rng: StdRng = StdRng::seed_from_u64(0xC0FF_EE22);
        for _ in 0..800 {
            let count: usize = 2 + (rng.random::<u32>() % 8) as usize;
            let mut nodes: Vec<CfgNode> = Vec::with_capacity(count);
            for i in 0..count {
                let pick: u32 = rng.random::<u32>() % 4;
                let node: CfgNode = match pick {
                    0 => ret(),
                    1 => goto((rng.random::<u32>() % count as u32) as NodeId),
                    _ => {
                        let taken: NodeId = (rng.random::<u32>() % count as u32) as NodeId;
                        let not_taken: NodeId = (rng.random::<u32>() % count as u32) as NodeId;
                        br(i as Atom, taken, not_taken)
                    }
                };
                nodes.push(node);
            }
            let cfg: Cfg = Cfg::new(0, nodes).unwrap();
            let forest: LoopForest = loop_forest(&cfg);
            let result: StructureResult = structure(&cfg);
            if forest.irreducible {
                assert!(
                    result.irreducible,
                    "loop forest says irreducible but engine structured it: {cfg:?} -> {result:?}"
                );
            } else {
                assert!(
                    result.is_complete(),
                    "reducible graph must structure completely: {cfg:?} -> {result:?}"
                );
            }
        }
    }

    fn cns_two_entry_cfg() -> Cfg {
        Cfg::new(0, vec![br(0, 1, 2), goto(2), br(1, 1, 3), ret()]).unwrap()
    }

    #[test]
    fn cns_two_entry_scc_becomes_reducible_and_structures() {
        let original: Cfg = cns_two_entry_cfg();
        let budget: CnsBudget = CnsBudget::tight_for(&original);
        let (reduced, clones): (Cfg, CloneMap) =
            make_reducible(&original, budget).expect("two-entry CNS result");
        assert!(!loop_forest(&reduced).irreducible, "{reduced:?}");
        assert!(relowered_matches_original_modulo_clones(
            &original,
            &reduced,
            &clones,
            &BTreeMap::new()
        ));
        let structured: CnsOutcome =
            structure_with_cns(&original, budget).expect("two-entry CNS structure");
        assert!(structured.result.is_complete(), "{structured:?}");
        assert_eq!(structured.result.clone_map, clones);
    }

    #[test]
    fn cns_three_entry_scc_abstains_when_clones_exceed_policy_cap() {
        let cfg: Cfg = Cfg::new(
            0,
            vec![
                br(0, 1, 4),
                br(1, 2, 3),
                br(2, 3, 1),
                br(3, 2, 1),
                br(4, 2, 3),
                ret(),
            ],
        )
        .unwrap();
        let budget: CnsBudget = CnsBudget::tight_for(&cfg);
        assert_eq!(budget.max_cloned_blocks, 3);
        assert!(make_reducible(&cfg, budget).is_none());
    }

    #[test]
    fn clone_quotient_guard_rejects_nonidentical_clone_mapping() {
        let original: Cfg = cns_two_entry_cfg();
        let budget: CnsBudget = CnsBudget::tight_for(&original);
        let (reduced, mut clones): (Cfg, CloneMap) =
            make_reducible(&original, budget).expect("CNS result");
        let clone: NodeId = *clones.keys().next().expect("clone id");
        clones.insert(clone, 1);
        assert!(!relowered_matches_original_modulo_clones(
            &original,
            &reduced,
            &clones,
            &BTreeMap::new()
        ));
    }

    #[test]
    fn clone_quotient_guard_rejects_dropped_original_edge() {
        let original: Cfg = cns_two_entry_cfg();
        let budget: CnsBudget = CnsBudget::tight_for(&original);
        let (mut reduced, clones): (Cfg, CloneMap) =
            make_reducible(&original, budget).expect("CNS result");
        reduced.nodes[0].term = Terminator::Goto(1);
        assert!(!relowered_matches_original_modulo_clones(
            &original,
            &reduced,
            &clones,
            &BTreeMap::new()
        ));
    }

    #[test]
    fn clone_quotient_guard_rejects_tampered_clone_body() {
        let original: Cfg = cns_two_entry_cfg();
        let budget: CnsBudget = CnsBudget::tight_for(&original);
        let (mut reduced, clones): (Cfg, CloneMap) =
            make_reducible(&original, budget).expect("CNS result");
        let clone: NodeId = *clones.keys().next().expect("clone id");
        reduced.nodes[clone as usize].pure = false;
        assert!(!relowered_matches_original_modulo_clones(
            &original,
            &reduced,
            &clones,
            &BTreeMap::new()
        ));
    }

    #[test]
    fn cns_reducible_cfg_preserves_structure_result_bytes() {
        let cfg: Cfg = Cfg::new(0, vec![goto(1), br(0, 2, 3), goto(1), ret()]).unwrap();
        let before: String = format!("{:?}", structure(&cfg));
        let budget: CnsBudget = CnsBudget::tight_for(&cfg);
        let outcome: CnsOutcome = structure_with_cns(&cfg, budget).expect("reducible outcome");
        let after: String = format!("{:?}", outcome.result);
        assert_eq!(after, before);
        assert!(outcome.result.clone_map.is_empty());
        assert_eq!(outcome.cfg.nodes, cfg.nodes);
    }
}
