use std::collections::{BTreeMap, BTreeSet};

use disrobe_core::{AdjGraph, DiGraph, Dominators, immediate_post_dominators};

pub(crate) type NodeId = u32;
pub(crate) type RegionId = u32;
pub(crate) type Atom = u32;
pub(crate) type CondId = u32;

/// A block terminator in the structuring CFG; `Return`/`Unreachable` route to the unified exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Terminator {
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

/// One CFG node: its terminator plus whether its body is side-effect free (fusable as a short-circuit predicate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CfgNode {
    pub(crate) term: Terminator,
    pub(crate) pure: bool,
}

/// Reason a [`Cfg`] failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CfgError {
    EmptyGraph,
    EntryOutOfRange,
    TargetOutOfRange,
}

/// A single-entry control-flow graph over dense `u32` node ids.
#[derive(Debug, Clone)]
pub(crate) struct Cfg {
    entry: NodeId,
    nodes: Vec<CfgNode>,
}

impl Cfg {
    /// Build and validate a CFG; every branch/switch target and the entry must be in range.
    pub(crate) fn new(entry: NodeId, nodes: Vec<CfgNode>) -> Result<Self, CfgError> {
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

    /// Number of nodes.
    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
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

/// Dominator tree of `cfg` (Cooper-Harvey-Kennedy, reused from `disrobe-core`).
pub(crate) fn dominators(cfg: &Cfg) -> Dominators {
    let graph: CfgGraph<'_> = CfgGraph { cfg };
    Dominators::compute(&graph)
}

/// Immediate post-dominators over `cfg` with a single synthetic exit that every return and noreturn routes to.
#[derive(Debug, Clone)]
pub(crate) struct PostDominators {
    ipdom: Vec<Option<NodeId>>,
    exit: NodeId,
}

impl PostDominators {
    /// Compute post-dominators; the synthetic exit is node id `cfg.len()`.
    pub(crate) fn compute(cfg: &Cfg) -> Self {
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

    /// Immediate post-dominator of `node`, or `None` when it cannot reach the exit.
    pub(crate) fn immediate_post_dominator(&self, node: NodeId) -> Option<NodeId> {
        self.ipdom.get(node as usize).copied().flatten()
    }

    /// The synthetic exit node id.
    pub(crate) fn exit(&self) -> NodeId {
        self.exit
    }

    /// Whether `a` post-dominates `b` (every path from `b` to exit passes through `a`).
    pub(crate) fn post_dominates(&self, a: NodeId, b: NodeId) -> bool {
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

/// One natural loop: its header, the latch edges back to it, and its body node set.
#[derive(Debug, Clone)]
pub(crate) struct NaturalLoop {
    pub(crate) header: NodeId,
    pub(crate) latches: Vec<NodeId>,
    pub(crate) body: BTreeSet<NodeId>,
    pub(crate) parent: Option<usize>,
}

/// The loop nesting forest of a CFG plus an explicit irreducibility verdict.
#[derive(Debug, Clone)]
pub(crate) struct LoopForest {
    pub(crate) loops: Vec<NaturalLoop>,
    pub(crate) irreducible: bool,
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

/// Compute the loop nesting forest and irreducibility verdict of `cfg`.
pub(crate) fn loop_forest(cfg: &Cfg) -> LoopForest {
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

/// A hash-consed, negation-normal-form condition over opaque predicate atoms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Cond {
    Leaf(Atom),
    NotLeaf(Atom),
    And(CondId, CondId),
    Or(CondId, CondId),
}

/// Interning pool that keeps every [`Cond`] in NNF and structurally unique.
#[derive(Debug, Clone, Default)]
pub(crate) struct CondPool {
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

    /// The interned conditions, indexable by [`CondId`].
    pub(crate) fn nodes(&self) -> &[Cond] {
        &self.nodes
    }
}

/// The structural class of a recovered region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegionKind {
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

/// One node in the recovered region tree.
#[derive(Debug, Clone)]
pub(crate) struct Region {
    pub(crate) kind: RegionKind,
    pub(crate) entry: NodeId,
    pub(crate) cond: Option<CondId>,
    pub(crate) scrutinee: Option<Atom>,
    pub(crate) children: Vec<RegionId>,
    pub(crate) exits: Vec<NodeId>,
    pub(crate) head: Option<RegionId>,
}

/// The outcome of running structural analysis over a CFG.
#[derive(Debug, Clone)]
pub(crate) struct StructureResult {
    pub(crate) root: Option<RegionId>,
    pub(crate) regions: Vec<Region>,
    pub(crate) conds: CondPool,
    pub(crate) irreducible: bool,
}

impl StructureResult {
    /// Whether the CFG collapsed to a single region with no irreducible residue.
    pub(crate) fn is_complete(&self) -> bool {
        self.root.is_some() && !self.irreducible
    }

    /// The kind of the root region, if any.
    pub(crate) fn root_kind(&self) -> Option<RegionKind> {
        self.root.map(|r: RegionId| self.regions[r as usize].kind)
    }
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
    alive: Vec<bool>,
    entry: NodeId,
    regions: Vec<Region>,
    conds: CondPool,
    irreducible: bool,
}

/// Run schema-based structural analysis over `cfg`, collapsing it to a region tree.
pub(crate) fn structure(cfg: &Cfg) -> StructureResult {
    let forest: LoopForest = loop_forest(cfg);
    let mut collapse: Collapse = Collapse::new(cfg);
    collapse.run();
    let mut result: StructureResult = collapse.finish();
    if forest.irreducible {
        result.irreducible = true;
    }
    result
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
            self.alive[taken as usize] = false;
            return true;
        }
        if let Some(region) = self.if_then_arm(node, cond, not_taken, taken, true, preds, headers) {
            self.region_of[node as usize] = region;
            self.flow[node as usize] = AbFlow::Seq(Some(taken));
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
        let mut body: BTreeSet<NodeId> = BTreeSet::from([header]);
        let mut stack: Vec<NodeId> = Vec::new();
        for &latch in latches {
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
        body
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
            };
        }
        let root: RegionId = self.region_of[live[0] as usize];
        StructureResult {
            root: Some(root),
            regions: self.regions,
            conds: self.conds,
            irreducible: false,
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
}
