use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{BlockKind, NirBlock, NirFunction, NirInstr, NirOp, ValueOp, basic_blocks};

use super::explore::SymexecBudget;
use super::interp::{Interp, parse_immediate};
use super::solver::{Feasible, Guard, SymSolver};
use super::state::State;
use super::value::{BitWidth, Sym};
use crate::jumptable::{JumpTableResolution, SuccessorKind};

const MIN_CASES: usize = 3;
const MIN_INDEGREE: usize = 3;
const MAX_CFF_BLOCKS: usize = 4_096;
const MAX_REGION_NODES: u32 = 512;
const SLICE_DEPTH: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeGuard {
    Direct,
    Branch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevirtEdge {
    pub from: u64,
    pub to: u64,
    pub guard: EdgeGuard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockRole {
    Resolved,
    Terminal,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradeReason {
    NextStateNotConstant,
    NextStateOutsideCaseMap,
    StateVarNotAssigned,
    RegionUnbounded,
    SolverUnknown,
    FellIntoCase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevirtNote {
    pub block: u64,
    pub reason: DegradeReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredCfg {
    pub entry: u64,
    pub state_var: String,
    pub cases: Vec<u64>,
    pub edges: Vec<DevirtEdge>,
    pub scaffolding: Vec<u64>,
    pub roles: BTreeMap<u64, BlockRole>,
    pub notes: Vec<DevirtNote>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryViolation {
    EdgeFromUnknownBlock { from: u64, to: u64 },
    EdgeToUnknownBlock { from: u64, to: u64 },
    EdgeFromUnresolvedBlock { from: u64, to: u64 },
    EdgeIntoScaffolding { from: u64, to: u64 },
    ResolvedBlockHasNoEdge { block: u64 },
    TerminalBlockHasEdge { block: u64 },
    EntryNotACase { entry: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CffAbstain {
    NotFlattened,
    DispatcherNotFound,
    StateVarNotUnique,
    CaseMapTooSmall,
    InitialStateUnknown,
    Budget,
    TooManyBlocks,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CffOutcome {
    Recovered(RecoveredCfg),
    Abstain(CffAbstain),
}

impl CffOutcome {
    #[must_use]
    pub const fn is_abstain(&self) -> bool {
        matches!(self, Self::Abstain(_))
    }

    #[must_use]
    pub const fn recovered(&self) -> Option<&RecoveredCfg> {
        match self {
            Self::Recovered(cfg) => Some(cfg),
            Self::Abstain(_) => None,
        }
    }
}

impl RecoveredCfg {
    #[must_use]
    pub fn edge_set(&self) -> BTreeSet<(u64, u64)> {
        self.edges
            .iter()
            .map(|edge: &DevirtEdge| (edge.from, edge.to))
            .collect()
    }

    #[must_use]
    pub fn successors(&self, block: u64) -> Vec<u64> {
        self.edges
            .iter()
            .filter(|edge: &&DevirtEdge| edge.from == block)
            .map(|edge: &DevirtEdge| edge.to)
            .collect()
    }

    pub fn canary(&self) -> Result<(), CanaryViolation> {
        let cases: BTreeSet<u64> = self.cases.iter().copied().collect();
        let scaffold: BTreeSet<u64> = self.scaffolding.iter().copied().collect();
        if !cases.contains(&self.entry) {
            return Err(CanaryViolation::EntryNotACase { entry: self.entry });
        }
        for edge in &self.edges {
            if !cases.contains(&edge.from) {
                return Err(CanaryViolation::EdgeFromUnknownBlock {
                    from: edge.from,
                    to: edge.to,
                });
            }
            if !cases.contains(&edge.to) {
                return Err(CanaryViolation::EdgeToUnknownBlock {
                    from: edge.from,
                    to: edge.to,
                });
            }
            if scaffold.contains(&edge.to) {
                return Err(CanaryViolation::EdgeIntoScaffolding {
                    from: edge.from,
                    to: edge.to,
                });
            }
            if self.roles.get(&edge.from) != Some(&BlockRole::Resolved) {
                return Err(CanaryViolation::EdgeFromUnresolvedBlock {
                    from: edge.from,
                    to: edge.to,
                });
            }
        }
        for (&block, role) in &self.roles {
            let outgoing: usize = self
                .edges
                .iter()
                .filter(|e: &&DevirtEdge| e.from == block)
                .count();
            match role {
                BlockRole::Resolved if outgoing == 0 => {
                    return Err(CanaryViolation::ResolvedBlockHasNoEdge { block });
                }
                BlockRole::Terminal if outgoing != 0 => {
                    return Err(CanaryViolation::TerminalBlockHasEdge { block });
                }
                BlockRole::Resolved | BlockRole::Terminal | BlockRole::Unresolved => {}
            }
        }
        Ok(())
    }
}

#[must_use]
pub fn devirtualize(function: &NirFunction) -> CffOutcome {
    devirtualize_with(function, SymexecBudget::bounded_default())
}

#[must_use]
pub fn devirtualize_with(function: &NirFunction, budget: SymexecBudget) -> CffOutcome {
    let blocks_list: Vec<NirBlock> = basic_blocks(function);
    if blocks_list.is_empty() {
        return CffOutcome::Abstain(CffAbstain::NotFlattened);
    }
    if blocks_list.len() > MAX_CFF_BLOCKS {
        return CffOutcome::Abstain(CffAbstain::TooManyBlocks);
    }
    let blocks: BTreeMap<u64, NirBlock> = blocks_list
        .into_iter()
        .map(|block: NirBlock| (block.start, block))
        .collect();
    let entry_block: u64 = if blocks.contains_key(&function.address) {
        function.address
    } else {
        match blocks.keys().next() {
            Some(first) => *first,
            None => return CffOutcome::Abstain(CffAbstain::NotFlattened),
        }
    };
    let plan: Plan = match detect(&blocks, entry_block) {
        Ok(plan) => plan,
        Err(reason) => return CffOutcome::Abstain(reason),
    };
    build(&blocks, &plan, budget)
}

#[must_use]
pub fn devirtualize_table_dispatch(
    function: &NirFunction,
    state_var: &str,
    sv_width_bytes: u32,
    dispatcher_head: u64,
    resolution: &JumpTableResolution,
    budget: SymexecBudget,
) -> CffOutcome {
    let blocks_list: Vec<NirBlock> = basic_blocks(function);
    if blocks_list.is_empty() {
        return CffOutcome::Abstain(CffAbstain::NotFlattened);
    }
    if blocks_list.len() > MAX_CFF_BLOCKS {
        return CffOutcome::Abstain(CffAbstain::TooManyBlocks);
    }
    let Some(sv_width): Option<BitWidth> = BitWidth::from_bytes(sv_width_bytes) else {
        return CffOutcome::Abstain(CffAbstain::NotFlattened);
    };
    let blocks: BTreeMap<u64, NirBlock> = blocks_list
        .into_iter()
        .map(|block: NirBlock| (block.start, block))
        .collect();
    let entry_block: u64 = if blocks.contains_key(&function.address) {
        function.address
    } else {
        match blocks.keys().next() {
            Some(first) => *first,
            None => return CffOutcome::Abstain(CffAbstain::NotFlattened),
        }
    };
    let mut casemap: BTreeMap<u64, u64> = BTreeMap::new();
    for successor in resolution.successors() {
        if successor.kind == SuccessorKind::Case && blocks.contains_key(&successor.target) {
            casemap.insert(successor.case_value, successor.target);
        }
    }
    if casemap.len() < MIN_CASES {
        return CffOutcome::Abstain(CffAbstain::CaseMapTooSmall);
    }
    let mut scaffolding: BTreeSet<u64> = BTreeSet::new();
    scaffolding.insert(dispatcher_head);
    if !casemap.values().any(|target: &u64| *target == entry_block) {
        scaffolding.insert(entry_block);
    }
    let plan: Plan = Plan {
        head: dispatcher_head,
        entry_block,
        state_var: state_var.trim().to_owned(),
        sv_width,
        casemap,
        scaffolding,
    };
    build(&blocks, &plan, budget)
}

#[derive(Debug, Clone)]
struct Plan {
    head: u64,
    entry_block: u64,
    state_var: String,
    sv_width: BitWidth,
    casemap: BTreeMap<u64, u64>,
    scaffolding: BTreeSet<u64>,
}

fn build(blocks: &BTreeMap<u64, NirBlock>, plan: &Plan, budget: SymexecBudget) -> CffOutcome {
    let case_heads: BTreeSet<u64> = plan.casemap.values().copied().collect();
    let mut solver: SymSolver = SymSolver::new(budget.solver());
    let Some(entry_real): Option<u64> =
        solve_initial(&mut solver, blocks, plan, &case_heads, budget)
    else {
        return CffOutcome::Abstain(CffAbstain::InitialStateUnknown);
    };
    let mut edges: Vec<DevirtEdge> = Vec::new();
    let mut roles: BTreeMap<u64, BlockRole> = BTreeMap::new();
    let mut notes: Vec<DevirtNote> = Vec::new();
    for (&case_value, &block) in &plan.casemap {
        if solver.cumulative_exhausted() {
            return CffOutcome::Abstain(CffAbstain::Budget);
        }
        match resolve_block(
            &mut solver,
            blocks,
            plan,
            &case_heads,
            case_value,
            block,
            budget,
        ) {
            BlockResolution::Resolved { targets } => {
                let guard: EdgeGuard = if targets.len() > 1 {
                    EdgeGuard::Branch
                } else {
                    EdgeGuard::Direct
                };
                roles.insert(block, BlockRole::Resolved);
                for to in targets {
                    edges.push(DevirtEdge {
                        from: block,
                        to,
                        guard,
                    });
                }
            }
            BlockResolution::Terminal => {
                roles.insert(block, BlockRole::Terminal);
            }
            BlockResolution::Degrade(reason) => {
                roles.insert(block, BlockRole::Unresolved);
                notes.push(DevirtNote { block, reason });
            }
        }
    }
    edges.sort_by_key(|edge: &DevirtEdge| (edge.from, edge.to));
    edges.dedup_by(|a: &mut DevirtEdge, b: &mut DevirtEdge| a.from == b.from && a.to == b.to);
    let mut cases: Vec<u64> = plan.casemap.values().copied().collect();
    cases.sort_unstable();
    cases.dedup();
    let mut scaffolding: Vec<u64> = plan.scaffolding.iter().copied().collect();
    scaffolding.sort_unstable();
    CffOutcome::Recovered(RecoveredCfg {
        entry: entry_real,
        state_var: plan.state_var.clone(),
        cases,
        edges,
        scaffolding,
        roles,
        notes,
    })
}

#[derive(Debug)]
enum BlockResolution {
    Resolved { targets: Vec<u64> },
    Terminal,
    Degrade(DegradeReason),
}

fn solve_initial(
    solver: &mut SymSolver,
    blocks: &BTreeMap<u64, NirBlock>,
    plan: &Plan,
    case_heads: &BTreeSet<u64>,
    budget: SymexecBudget,
) -> Option<u64> {
    let mut walker: RegionWalker<'_> = RegionWalker::new(
        solver,
        blocks,
        plan.head,
        plan.entry_block,
        case_heads,
        &plan.state_var,
        plan.sv_width,
        budget,
    );
    walker.run(plan.entry_block, None);
    if walker.abstain.is_some() {
        return None;
    }
    let mut constants: BTreeSet<u64> = BTreeSet::new();
    for end in &walker.ends {
        if end.terminal {
            continue;
        }
        let value: u64 = end.sv?;
        constants.insert(value);
    }
    let mut iter = constants.into_iter();
    let first: u64 = iter.next()?;
    if iter.next().is_some() {
        return None;
    }
    plan.casemap.get(&first).copied()
}

fn resolve_block(
    solver: &mut SymSolver,
    blocks: &BTreeMap<u64, NirBlock>,
    plan: &Plan,
    case_heads: &BTreeSet<u64>,
    case_value: u64,
    block: u64,
    budget: SymexecBudget,
) -> BlockResolution {
    let mut walker: RegionWalker<'_> = RegionWalker::new(
        solver,
        blocks,
        plan.head,
        block,
        case_heads,
        &plan.state_var,
        plan.sv_width,
        budget,
    );
    walker.run(block, Some(case_value));
    if let Some(reason) = walker.abstain {
        return BlockResolution::Degrade(reason);
    }
    let back: Vec<&PathEnd> = walker
        .ends
        .iter()
        .filter(|end: &&PathEnd| !end.terminal)
        .collect();
    if back.is_empty() {
        return BlockResolution::Terminal;
    }
    if back.iter().any(|end: &&PathEnd| !end.wrote) {
        return BlockResolution::Degrade(DegradeReason::StateVarNotAssigned);
    }
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    for end in &back {
        let Some(value): Option<u64> = end.sv else {
            return BlockResolution::Degrade(DegradeReason::NextStateNotConstant);
        };
        let Some(&target): Option<&u64> = plan.casemap.get(&value) else {
            return BlockResolution::Degrade(DegradeReason::NextStateOutsideCaseMap);
        };
        targets.insert(target);
    }
    BlockResolution::Resolved {
        targets: targets.into_iter().collect(),
    }
}

#[derive(Debug)]
struct PathEnd {
    sv: Option<u64>,
    wrote: bool,
    terminal: bool,
}

struct RegionWalker<'a> {
    solver: &'a mut SymSolver,
    blocks: &'a BTreeMap<u64, NirBlock>,
    stop: u64,
    start: u64,
    case_heads: &'a BTreeSet<u64>,
    state_var: &'a str,
    sv_width: BitWidth,
    budget: SymexecBudget,
    nodes: u32,
    abstain: Option<DegradeReason>,
    ends: Vec<PathEnd>,
}

impl std::fmt::Debug for RegionWalker<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegionWalker")
            .field("stop", &self.stop)
            .field("start", &self.start)
            .field("nodes", &self.nodes)
            .field("abstain", &self.abstain)
            .finish_non_exhaustive()
    }
}

impl<'a> RegionWalker<'a> {
    #[allow(
        clippy::too_many_arguments,
        reason = "one solver, one graph, and the immutable region parameters; bundling them into a context struct would only relocate the same fields"
    )]
    const fn new(
        solver: &'a mut SymSolver,
        blocks: &'a BTreeMap<u64, NirBlock>,
        stop: u64,
        start: u64,
        case_heads: &'a BTreeSet<u64>,
        state_var: &'a str,
        sv_width: BitWidth,
        budget: SymexecBudget,
    ) -> Self {
        Self {
            solver,
            blocks,
            stop,
            start,
            case_heads,
            state_var,
            sv_width,
            budget,
            nodes: 0,
            abstain: None,
            ends: Vec::new(),
        }
    }

    fn run(&mut self, start: u64, seed: Option<u64>) {
        let mut state: State = State::entry(start, self.budget.memory_ceiling);
        if let Some(value) = seed {
            state.env.insert(
                self.state_var.to_owned(),
                Sym::constant(self.sv_width, value),
            );
        }
        let mut worklist: Vec<(State, bool)> = vec![(state, false)];
        while let Some((mut state, wrote)) = worklist.pop() {
            if self.abstain.is_some() {
                return;
            }
            self.nodes = self.nodes.saturating_add(1);
            if self.nodes > MAX_REGION_NODES {
                self.abstain = Some(DegradeReason::RegionUnbounded);
                return;
            }
            let Some(block): Option<NirBlock> = self.blocks.get(&state.block).cloned() else {
                continue;
            };
            let mut wrote: bool = wrote;
            for instr in &block.instructions {
                if dest_is(instr, self.state_var) {
                    wrote = true;
                }
                Interp::new(self.solver).step(&mut state, instr);
            }
            self.transition(&block, &state, wrote, &mut worklist);
        }
    }

    fn transition(
        &mut self,
        block: &NirBlock,
        state: &State,
        wrote: bool,
        worklist: &mut Vec<(State, bool)>,
    ) {
        if block.successors.is_empty() {
            self.ends.push(PathEnd {
                sv: None,
                wrote,
                terminal: true,
            });
            return;
        }
        let terminator: Option<&NirInstr> = block.instructions.last();
        if block.kind == BlockKind::Conditional
            && block.successors.len() == 2
            && let Some(instr) = terminator
            && let Some(taken) = instr.direct_target()
            && block.successors.contains(&taken)
            && let Some(fallthrough) = block.successors.iter().copied().find(|s: &u64| *s != taken)
        {
            self.fork(state, instr, taken, fallthrough, wrote, worklist);
            return;
        }
        for successor in &block.successors {
            let child: State = state.fork(*successor);
            self.enqueue(child, wrote, worklist);
        }
    }

    fn fork(
        &mut self,
        state: &State,
        terminator: &NirInstr,
        taken: u64,
        fallthrough: u64,
        wrote: bool,
        worklist: &mut Vec<(State, bool)>,
    ) {
        if self.solver.cumulative_exhausted() {
            self.abstain = Some(DegradeReason::SolverUnknown);
            return;
        }
        let mut probe: State = state.clone();
        let condition: Sym = match terminator.operands.first() {
            Some(name) => Interp::new(self.solver).eval_operand(&mut probe, name, BitWidth::BYTE),
            None => self.solver.fresh_havoc(BitWidth::BYTE),
        };
        let nonzero: Guard = self.solver.nonzero_guard(condition);
        let zero: Guard = self.solver.zero_guard(condition);
        let taken_feasible: Feasible = self.solver.feasible(&probe.path, nonzero);
        let fallthrough_feasible: Feasible = self.solver.feasible(&probe.path, zero);
        if taken_feasible == Feasible::Unknown || fallthrough_feasible == Feasible::Unknown {
            self.abstain = Some(DegradeReason::SolverUnknown);
            return;
        }
        self.arm(taken, &probe, nonzero, taken_feasible, wrote, worklist);
        self.arm(
            fallthrough,
            &probe,
            zero,
            fallthrough_feasible,
            wrote,
            worklist,
        );
    }

    fn arm(
        &mut self,
        target: u64,
        base: &State,
        guard: Guard,
        feasible: Feasible,
        wrote: bool,
        worklist: &mut Vec<(State, bool)>,
    ) {
        match feasible {
            Feasible::Sat => {
                let mut child: State = base.fork(target);
                if let Guard::Term(term) = guard {
                    child.path.push(term);
                }
                self.enqueue(child, wrote, worklist);
            }
            Feasible::Unsat => {}
            Feasible::Unknown => {
                self.abstain = Some(DegradeReason::SolverUnknown);
            }
        }
    }

    fn enqueue(&mut self, child: State, wrote: bool, worklist: &mut Vec<(State, bool)>) {
        if child.block == self.stop {
            let sv: Option<u64> = child
                .env
                .get(self.state_var)
                .and_then(|value: &Sym| value.const_value());
            self.ends.push(PathEnd {
                sv,
                wrote,
                terminal: false,
            });
            return;
        }
        if child.block != self.start && self.case_heads.contains(&child.block) {
            self.abstain = Some(DegradeReason::FellIntoCase);
            return;
        }
        let count: u32 = child
            .loop_counts
            .get(&child.block)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        if count > self.budget.loop_cap {
            self.abstain = Some(DegradeReason::RegionUnbounded);
            return;
        }
        let mut child: State = child;
        child.loop_counts.insert(child.block, count);
        worklist.push((child, wrote));
    }
}

fn detect(blocks: &BTreeMap<u64, NirBlock>, entry_block: u64) -> Result<Plan, CffAbstain> {
    let mut indegree: BTreeMap<u64, usize> = blocks.keys().map(|start: &u64| (*start, 0)).collect();
    for block in blocks.values() {
        for successor in &block.successors {
            if let Some(count) = indegree.get_mut(successor) {
                *count = count.saturating_add(1);
            }
        }
    }
    let mut head: Option<(u64, usize)> = None;
    for (&start, block) in blocks {
        if classify_compare(block).is_none() {
            continue;
        }
        let degree: usize = indegree.get(&start).copied().unwrap_or(0);
        if degree < MIN_INDEGREE {
            continue;
        }
        match head {
            Some((_, best)) if best >= degree => {}
            Some(_) | None => head = Some((start, degree)),
        }
    }
    let Some((head, _)): Option<(u64, usize)> = head else {
        return Err(CffAbstain::DispatcherNotFound);
    };
    let chain: ChainResult = follow_chain(blocks, head)?;
    if chain.casemap.len() < MIN_CASES {
        return Err(CffAbstain::CaseMapTooSmall);
    }
    let writing: usize = chain
        .casemap
        .values()
        .filter(|target: &&u64| {
            region_writes_sv(blocks, **target, head, &chain.case_heads, &chain.state_var)
        })
        .count();
    if writing < 2 || writing.saturating_mul(2) < chain.casemap.len() {
        return Err(CffAbstain::NotFlattened);
    }
    let mut scaffolding: BTreeSet<u64> = chain.blocks.clone();
    if !chain.case_heads.contains(&entry_block) {
        scaffolding.insert(entry_block);
    }
    Ok(Plan {
        head,
        entry_block,
        state_var: chain.state_var,
        sv_width: chain.sv_width,
        casemap: chain.casemap,
        scaffolding,
    })
}

#[derive(Debug)]
struct ChainResult {
    state_var: String,
    sv_width: BitWidth,
    casemap: BTreeMap<u64, u64>,
    case_heads: BTreeSet<u64>,
    blocks: BTreeSet<u64>,
}

fn follow_chain(blocks: &BTreeMap<u64, NirBlock>, head: u64) -> Result<ChainResult, CffAbstain> {
    let mut casemap: BTreeMap<u64, u64> = BTreeMap::new();
    let mut chain_blocks: BTreeSet<u64> = BTreeSet::new();
    let mut sv_root: Option<String> = None;
    let mut sv_width: Option<BitWidth> = None;
    let mut cursor: u64 = head;
    for _ in 0..blocks.len().saturating_add(1) {
        if !chain_blocks.insert(cursor) {
            break;
        }
        let Some(block): Option<&NirBlock> = blocks.get(&cursor) else {
            break;
        };
        let Some(info): Option<CompareInfo> = classify_compare(block) else {
            chain_blocks.remove(&cursor);
            break;
        };
        match &sv_root {
            Some(root) if *root != info.sv_root => return Err(CffAbstain::StateVarNotUnique),
            Some(_) => {}
            None => {
                sv_root = Some(info.sv_root.clone());
                sv_width = Some(info.width);
            }
        }
        if casemap.insert(info.c, info.case_target).is_some() {
            break;
        }
        cursor = info.continue_target;
        if chain_blocks.contains(&cursor) {
            break;
        }
    }
    let (Some(state_var), Some(width)): (Option<String>, Option<BitWidth>) = (sv_root, sv_width)
    else {
        return Err(CffAbstain::DispatcherNotFound);
    };
    let case_heads: BTreeSet<u64> = casemap.values().copied().collect();
    Ok(ChainResult {
        state_var,
        sv_width: width,
        casemap,
        case_heads,
        blocks: chain_blocks,
    })
}

#[derive(Debug)]
struct CompareInfo {
    sv_root: String,
    c: u64,
    case_target: u64,
    continue_target: u64,
    width: BitWidth,
}

fn classify_compare(block: &NirBlock) -> Option<CompareInfo> {
    let terminator: &NirInstr = block.instructions.last()?;
    let NirOp::CondBranch {
        target: Some(taken),
    } = &terminator.op
    else {
        return None;
    };
    let taken: u64 = *taken;
    if !block.successors.contains(&taken) {
        return None;
    }
    let cond: &str = terminator.operands.first()?.trim();
    let defs: BTreeMap<&str, &NirInstr> = block_defs(block);
    let (equal, lhs, rhs, width): (bool, String, String, BitWidth) = trace_compare(&defs, cond)?;
    let continue_target: u64 = block
        .successors
        .iter()
        .copied()
        .find(|s: &u64| *s != taken)?;
    let (constant, variable): (u64, String) = split_const(&lhs, &rhs, width)?;
    let sv_root: String = slice_root(&defs, &variable)?;
    let (case_target, next): (u64, u64) = if equal {
        (taken, continue_target)
    } else {
        (continue_target, taken)
    };
    Some(CompareInfo {
        sv_root,
        c: constant,
        case_target,
        continue_target: next,
        width,
    })
}

fn block_defs(block: &NirBlock) -> BTreeMap<&str, &NirInstr> {
    let mut defs: BTreeMap<&str, &NirInstr> = BTreeMap::new();
    for instr in &block.instructions {
        if let Some(name) = dest_name(instr) {
            defs.insert(name, instr);
        }
    }
    defs
}

fn trace_compare(
    defs: &BTreeMap<&str, &NirInstr>,
    name: &str,
) -> Option<(bool, String, String, BitWidth)> {
    let mut cursor: String = name.trim().to_owned();
    for _ in 0..SLICE_DEPTH {
        let instr: &&NirInstr = defs.get(cursor.as_str())?;
        match &instr.op {
            NirOp::Value {
                op: ValueOp::IntEqual,
                inputs,
                input_sizes,
                ..
            } if inputs.len() == 2 => {
                let width: BitWidth = input_sizes
                    .first()
                    .copied()
                    .and_then(BitWidth::from_bytes)
                    .unwrap_or(BitWidth::QWORD);
                return Some((true, inputs[0].clone(), inputs[1].clone(), width));
            }
            NirOp::Value {
                op: ValueOp::IntNotEqual,
                inputs,
                input_sizes,
                ..
            } if inputs.len() == 2 => {
                let width: BitWidth = input_sizes
                    .first()
                    .copied()
                    .and_then(BitWidth::from_bytes)
                    .unwrap_or(BitWidth::QWORD);
                return Some((false, inputs[0].clone(), inputs[1].clone(), width));
            }
            NirOp::Copy { src, .. } => src.trim().clone_into(&mut cursor),
            NirOp::Value {
                op: ValueOp::BoolNegate,
                inputs,
                ..
            } if inputs.len() == 1 => {
                let (equal, lhs, rhs, width): (bool, String, String, BitWidth) =
                    trace_compare(defs, inputs[0].trim())?;
                return Some((!equal, lhs, rhs, width));
            }
            _ => return None,
        }
    }
    None
}

fn split_const(lhs: &str, rhs: &str, width: BitWidth) -> Option<(u64, String)> {
    let lhs_const: Option<u64> = parse_immediate(lhs.trim(), width);
    let rhs_const: Option<u64> = parse_immediate(rhs.trim(), width);
    match (lhs_const, rhs_const) {
        (Some(_), Some(_)) | (None, None) => None,
        (Some(value), None) => Some((value, rhs.trim().to_owned())),
        (None, Some(value)) => Some((value, lhs.trim().to_owned())),
    }
}

fn slice_root(defs: &BTreeMap<&str, &NirInstr>, name: &str) -> Option<String> {
    let mut cursor: String = name.trim().to_owned();
    for _ in 0..SLICE_DEPTH {
        if parse_immediate(&cursor, BitWidth::QWORD).is_some() {
            return None;
        }
        let Some(instr): Option<&&NirInstr> = defs.get(cursor.as_str()) else {
            return Some(cursor);
        };
        match &instr.op {
            NirOp::Copy { src, .. } | NirOp::Subpiece { src, .. } => {
                src.trim().clone_into(&mut cursor);
            }
            NirOp::Value {
                op: ValueOp::IntZext | ValueOp::IntSext,
                inputs,
                ..
            } if inputs.len() == 1 => inputs[0].trim().clone_into(&mut cursor),
            NirOp::RawLoad { .. } | NirOp::Load => return None,
            _ => return Some(cursor),
        }
    }
    None
}

fn region_writes_sv(
    blocks: &BTreeMap<u64, NirBlock>,
    start: u64,
    stop: u64,
    case_heads: &BTreeSet<u64>,
    state_var: &str,
) -> bool {
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut stack: Vec<u64> = vec![start];
    while let Some(current) = stack.pop() {
        if current == stop || !seen.insert(current) {
            continue;
        }
        if current != start && case_heads.contains(&current) {
            continue;
        }
        let Some(block): Option<&NirBlock> = blocks.get(&current) else {
            continue;
        };
        if block
            .instructions
            .iter()
            .any(|instr: &NirInstr| dest_is(instr, state_var))
        {
            return true;
        }
        for successor in &block.successors {
            stack.push(*successor);
        }
    }
    false
}

fn dest_is(instr: &NirInstr, name: &str) -> bool {
    dest_name(instr).is_some_and(|dest: &str| dest == name.trim())
}

fn dest_name(instr: &NirInstr) -> Option<&str> {
    match &instr.op {
        NirOp::Deposit { cell, .. } => Some(cell.trim()),
        NirOp::Const
        | NirOp::BinOp { .. }
        | NirOp::Load
        | NirOp::Phi
        | NirOp::Copy { .. }
        | NirOp::Subpiece { .. }
        | NirOp::Value { .. }
        | NirOp::Piece { .. }
        | NirOp::RawLoad { .. } => instr.operands.first().map(|name: &String| name.trim()),
        NirOp::Nop
        | NirOp::Store
        | NirOp::RawStore { .. }
        | NirOp::Call { .. }
        | NirOp::IndirectCall
        | NirOp::ExternCall { .. }
        | NirOp::NoReturnCall { .. }
        | NirOp::TailCall { .. }
        | NirOp::CallOther { .. }
        | NirOp::Branch { .. }
        | NirOp::CondBranch { .. }
        | NirOp::Return
        | NirOp::Interrupt
        | NirOp::Unmodeled { .. } => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use disrobe_nir::{SourceLang, SourceRef};

    use super::*;
    use crate::{
        Endian, EntryKind, IndexBound, IndirectSite, JumpTableResolution, PathConstraint, Perms,
        Section, SectionMap, TableForm, resolve_jump_table,
    };

    fn raw(address: u64, op: NirOp, operands: &[&str]) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: String::new(),
            operands: operands
                .iter()
                .map(|item: &&str| (*item).to_owned())
                .collect(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    fn cmp_eq(address: u64, dest: &str, var: &str, constant: &str) -> NirInstr {
        raw(
            address,
            NirOp::Value {
                op: ValueOp::IntEqual,
                inputs: vec![var.to_owned(), constant.to_owned()],
                input_sizes: vec![4, 4],
                size: 1,
            },
            &[dest],
        )
    }

    fn set_state(address: u64, sv: &str, value: &str) -> NirInstr {
        raw(
            address,
            NirOp::Copy {
                src: value.to_owned(),
                size: 4,
            },
            &[sv],
        )
    }

    fn function(instructions: Vec<NirInstr>, end: u64) -> NirFunction {
        NirFunction {
            name: "flat".to_owned(),
            address: 0x0,
            end,
            is_export: false,
            instructions,
            source: SourceRef::new(SourceLang::NativeX86, 0x0),
        }
    }

    fn straight_flattened() -> NirFunction {
        function(
            vec![
                set_state(0x00, "sv", "0"),
                raw(0x04, NirOp::Branch { target: Some(0x10) }, &[]),
                cmp_eq(0x10, "e0", "sv", "0"),
                raw(0x14, NirOp::CondBranch { target: Some(0x40) }, &["e0"]),
                cmp_eq(0x18, "e1", "sv", "1"),
                raw(0x1c, NirOp::CondBranch { target: Some(0x50) }, &["e1"]),
                cmp_eq(0x20, "e2", "sv", "2"),
                raw(0x24, NirOp::CondBranch { target: Some(0x60) }, &["e2"]),
                raw(0x28, NirOp::Return, &[]),
                set_state(0x40, "sv", "1"),
                raw(0x44, NirOp::Branch { target: Some(0x10) }, &[]),
                set_state(0x50, "sv", "2"),
                raw(0x54, NirOp::Branch { target: Some(0x10) }, &[]),
                raw(0x60, NirOp::Return, &[]),
            ],
            0x64,
        )
    }

    #[test]
    fn straight_chain_recovers_the_known_original_edges() {
        let outcome: CffOutcome = devirtualize(&straight_flattened());
        let CffOutcome::Recovered(cfg) = outcome else {
            panic!("a three-case flattened function must devirtualize: {outcome:?}");
        };
        assert_eq!(cfg.entry, 0x40);
        assert_eq!(cfg.state_var, "sv");
        assert_eq!(
            cfg.edge_set(),
            BTreeSet::from([(0x40, 0x50), (0x50, 0x60)]),
            "recovered edges must match the hand-verified original chain 0x40 -> 0x50 -> 0x60"
        );
        assert_eq!(cfg.roles.get(&0x60), Some(&BlockRole::Terminal));
        assert!(
            cfg.canary().is_ok(),
            "well-formed recovery passes the canary"
        );
        assert!(cfg.notes.is_empty());
    }

    #[test]
    fn canary_rejects_a_dropped_edge() {
        let CffOutcome::Recovered(mut cfg) = devirtualize(&straight_flattened()) else {
            panic!("expected recovery");
        };
        cfg.edges.retain(|edge: &DevirtEdge| edge.from != 0x40);
        assert_eq!(
            cfg.canary(),
            Err(CanaryViolation::ResolvedBlockHasNoEdge { block: 0x40 }),
            "dropping the only edge of a resolved block must be caught"
        );
    }

    #[test]
    fn canary_rejects_an_invented_edge() {
        let CffOutcome::Recovered(mut cfg) = devirtualize(&straight_flattened()) else {
            panic!("expected recovery");
        };
        cfg.edges.push(DevirtEdge {
            from: 0x40,
            to: 0x999,
            guard: EdgeGuard::Direct,
        });
        assert_eq!(
            cfg.canary(),
            Err(CanaryViolation::EdgeToUnknownBlock {
                from: 0x40,
                to: 0x999,
            }),
            "an edge to a fabricated block outside the case map must be caught"
        );
    }

    #[test]
    fn ordinary_switch_is_not_treated_as_flattened() {
        let switch: NirFunction = function(
            vec![
                cmp_eq(0x00, "e0", "x", "0"),
                raw(0x04, NirOp::CondBranch { target: Some(0x40) }, &["e0"]),
                cmp_eq(0x08, "e1", "x", "1"),
                raw(0x0c, NirOp::CondBranch { target: Some(0x50) }, &["e1"]),
                cmp_eq(0x10, "e2", "x", "2"),
                raw(0x14, NirOp::CondBranch { target: Some(0x60) }, &["e2"]),
                raw(0x18, NirOp::Return, &[]),
                raw(0x40, NirOp::Return, &[]),
                raw(0x50, NirOp::Return, &[]),
                raw(0x60, NirOp::Return, &[]),
            ],
            0x64,
        );
        let outcome: CffOutcome = devirtualize(&switch);
        assert!(
            outcome.is_abstain(),
            "a plain switch has in-degree-one arms and no state-var writeback: {outcome:?}"
        );
    }

    fn cmp_data(address: u64, dest: &str, lhs: &str, rhs: &str) -> NirInstr {
        raw(
            address,
            NirOp::Value {
                op: ValueOp::IntEqual,
                inputs: vec![lhs.to_owned(), rhs.to_owned()],
                input_sizes: vec![4, 4],
                size: 1,
            },
            &[dest],
        )
    }

    fn dispatch_head() -> Vec<NirInstr> {
        vec![
            cmp_eq(0x10, "e0", "sv", "0"),
            raw(0x14, NirOp::CondBranch { target: Some(0x40) }, &["e0"]),
            cmp_eq(0x18, "e1", "sv", "1"),
            raw(0x1c, NirOp::CondBranch { target: Some(0x50) }, &["e1"]),
            cmp_eq(0x20, "e2", "sv", "2"),
            raw(0x24, NirOp::CondBranch { target: Some(0x60) }, &["e2"]),
            raw(0x28, NirOp::Return, &[]),
        ]
    }

    #[test]
    fn select_next_state_recovers_two_conditional_edges() {
        let mut instrs: Vec<NirInstr> = vec![
            set_state(0x00, "sv", "0"),
            raw(0x04, NirOp::Branch { target: Some(0x10) }, &[]),
        ];
        instrs.extend(dispatch_head());
        instrs.extend(vec![
            cmp_data(0x40, "c", "a", "b"),
            raw(0x44, NirOp::CondBranch { target: Some(0x4c) }, &["c"]),
            set_state(0x48, "sv", "1"),
            raw(0x4a, NirOp::Branch { target: Some(0x10) }, &[]),
            set_state(0x4c, "sv", "2"),
            raw(0x4e, NirOp::Branch { target: Some(0x10) }, &[]),
            set_state(0x50, "sv", "2"),
            raw(0x54, NirOp::Branch { target: Some(0x10) }, &[]),
            raw(0x60, NirOp::Return, &[]),
        ]);
        let CffOutcome::Recovered(cfg) = devirtualize(&function(instrs, 0x64)) else {
            panic!("select-of-constants next state must devirtualize");
        };
        assert_eq!(cfg.entry, 0x40);
        assert_eq!(
            cfg.edge_set(),
            BTreeSet::from([(0x40, 0x50), (0x40, 0x60), (0x50, 0x60)]),
            "state 0 forks to states 1 and 2; state 1 flows to state 2"
        );
        assert!(
            cfg.edges
                .iter()
                .filter(|edge: &&DevirtEdge| edge.from == 0x40)
                .all(|edge: &DevirtEdge| edge.guard == EdgeGuard::Branch),
            "the two exits of the forking block are conditional edges"
        );
        assert!(cfg.canary().is_ok());
        assert!(cfg.notes.is_empty());
    }

    #[test]
    fn loop_flattening_recovers_the_self_edge() {
        let mut instrs: Vec<NirInstr> = vec![
            set_state(0x00, "sv", "0"),
            raw(0x04, NirOp::Branch { target: Some(0x10) }, &[]),
        ];
        instrs.extend(dispatch_head());
        instrs.extend(vec![
            set_state(0x40, "sv", "1"),
            raw(0x44, NirOp::Branch { target: Some(0x10) }, &[]),
            cmp_data(0x50, "c", "a", "b"),
            raw(0x54, NirOp::CondBranch { target: Some(0x5c) }, &["c"]),
            set_state(0x58, "sv", "2"),
            raw(0x5a, NirOp::Branch { target: Some(0x10) }, &[]),
            set_state(0x5c, "sv", "1"),
            raw(0x5e, NirOp::Branch { target: Some(0x10) }, &[]),
            raw(0x60, NirOp::Return, &[]),
        ]);
        let CffOutcome::Recovered(cfg) = devirtualize(&function(instrs, 0x64)) else {
            panic!("a state that maps back to an earlier block must recover its loop");
        };
        assert_eq!(cfg.entry, 0x40);
        assert_eq!(
            cfg.edge_set(),
            BTreeSet::from([(0x40, 0x50), (0x50, 0x50), (0x50, 0x60)]),
            "state 1 loops to itself while the condition holds, else exits to state 2"
        );
        assert!(cfg.canary().is_ok());
    }

    #[test]
    fn runtime_next_state_degrades_without_dropping_the_rest() {
        let mut instrs: Vec<NirInstr> = vec![
            set_state(0x00, "sv", "0"),
            raw(0x04, NirOp::Branch { target: Some(0x10) }, &[]),
        ];
        instrs.extend(dispatch_head());
        instrs.extend(vec![
            set_state(0x40, "sv", "1"),
            raw(0x44, NirOp::Branch { target: Some(0x10) }, &[]),
            raw(
                0x50,
                NirOp::RawLoad {
                    addr: "p".to_owned(),
                    size: 4,
                },
                &["sv"],
            ),
            raw(0x54, NirOp::Branch { target: Some(0x10) }, &[]),
            raw(0x60, NirOp::Return, &[]),
        ]);
        let CffOutcome::Recovered(cfg) = devirtualize(&function(instrs, 0x64)) else {
            panic!("a runtime-computed next state must still yield partial recovery");
        };
        assert_eq!(
            cfg.edge_set(),
            BTreeSet::from([(0x40, 0x50)]),
            "the resolvable backbone survives even though state 1 is opaque"
        );
        assert_eq!(cfg.roles.get(&0x50), Some(&BlockRole::Unresolved));
        assert_eq!(
            cfg.notes,
            vec![DevirtNote {
                block: 0x50,
                reason: DegradeReason::NextStateNotConstant,
            }],
            "the opaque block is reported, never silently dropped"
        );
        assert!(cfg.canary().is_ok());
    }

    #[test]
    fn state_var_clobbered_after_the_write_degrades() {
        let mut instrs: Vec<NirInstr> = vec![
            set_state(0x00, "sv", "0"),
            raw(0x04, NirOp::Branch { target: Some(0x10) }, &[]),
        ];
        instrs.extend(dispatch_head());
        instrs.extend(vec![
            set_state(0x40, "sv", "1"),
            raw(0x44, NirOp::Branch { target: Some(0x10) }, &[]),
            set_state(0x50, "sv", "2"),
            raw(
                0x54,
                NirOp::Call {
                    target: Some(0x9000),
                },
                &[],
            ),
            raw(0x58, NirOp::Branch { target: Some(0x10) }, &[]),
            raw(0x60, NirOp::Return, &[]),
        ]);
        let CffOutcome::Recovered(cfg) = devirtualize(&function(instrs, 0x64)) else {
            panic!("a clobbered state var must degrade, not fabricate an edge");
        };
        assert_eq!(cfg.roles.get(&0x50), Some(&BlockRole::Unresolved));
        assert!(
            cfg.notes.contains(&DevirtNote {
                block: 0x50,
                reason: DegradeReason::NextStateNotConstant,
            }),
            "a call clobbers the state var after its constant write: {:?}",
            cfg.notes
        );
        assert!(
            !cfg.edge_set()
                .iter()
                .any(|(from, _): &(u64, u64)| *from == 0x50),
            "no next-state edge may be invented for the clobbered block"
        );
        assert!(cfg.canary().is_ok());
    }

    fn le64(values: &[u64]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value: &u64| value.to_le_bytes())
            .collect()
    }

    #[test]
    fn jump_table_dispatch_composes_with_the_inc2_resolver() {
        let table_base: u64 = 0x4000;
        let targets: [u64; 3] = [0x1100, 0x1140, 0x1180];
        let starts: BTreeSet<u64> = targets.iter().copied().collect();
        let code: Section =
            Section::new(0x1000, vec![0x90; 0x400], Perms::code(), false).with_insn_starts(starts);
        let rodata: Section = Section::new(table_base, le64(&targets), Perms::ro(), true);
        let sections: SectionMap = SectionMap::new(vec![code, rodata]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base,
                stride: 8,
                entry_bytes: 8,
                endian: Endian::Little,
                entry: EntryKind::AbsolutePointer,
                case_base: 0,
            },
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(2)]),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        assert!(!resolution.is_abstain(), "the dispatch table must resolve");

        let flat: NirFunction = NirFunction {
            name: "table_flat".to_owned(),
            address: 0x1000,
            end: 0x1184,
            is_export: false,
            instructions: vec![
                set_state(0x1000, "sv", "0"),
                raw(
                    0x1004,
                    NirOp::Branch {
                        target: Some(0x1010),
                    },
                    &[],
                ),
                raw(0x1010, NirOp::Branch { target: None }, &[]),
                set_state(0x1100, "sv", "1"),
                raw(
                    0x1104,
                    NirOp::Branch {
                        target: Some(0x1010),
                    },
                    &[],
                ),
                set_state(0x1140, "sv", "2"),
                raw(
                    0x1144,
                    NirOp::Branch {
                        target: Some(0x1010),
                    },
                    &[],
                ),
                raw(0x1180, NirOp::Return, &[]),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x1000),
        };
        let outcome: CffOutcome = devirtualize_table_dispatch(
            &flat,
            "sv",
            4,
            0x1010,
            &resolution,
            SymexecBudget::bounded_default(),
        );
        let CffOutcome::Recovered(cfg) = outcome else {
            panic!("the jump-table dispatcher case map must drive devirtualization: {outcome:?}");
        };
        assert_eq!(cfg.entry, 0x1100);
        assert_eq!(
            cfg.edge_set(),
            BTreeSet::from([(0x1100, 0x1140), (0x1140, 0x1180)]),
            "the recovered chain matches the known original block order"
        );
        assert_eq!(cfg.roles.get(&0x1180), Some(&BlockRole::Terminal));
        assert!(cfg.canary().is_ok());
    }

    #[test]
    fn canary_rejects_an_edge_out_of_a_terminal_block() {
        let CffOutcome::Recovered(mut cfg) = devirtualize(&straight_flattened()) else {
            panic!("expected recovery");
        };
        cfg.edges.push(DevirtEdge {
            from: 0x60,
            to: 0x40,
            guard: EdgeGuard::Direct,
        });
        assert_eq!(
            cfg.canary(),
            Err(CanaryViolation::EdgeFromUnresolvedBlock {
                from: 0x60,
                to: 0x40,
            }),
            "a terminal block that suddenly sprouts a next-state edge must be caught"
        );
    }
}
