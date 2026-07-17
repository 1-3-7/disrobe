use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{BlockKind, NirBlock, NirFunction, NirInstr, basic_blocks};

use super::cheap::{CheapResolution, cheap_initial, cheap_resolve_block};
use super::detect::{MAX_CFF_BLOCKS, MIN_CASES, Plan, SvWidth, detect};
use super::types::{
    BlockRole, CffAbstain, CffOutcome, DegradeReason, DevirtEdge, DevirtNote, EdgeGuard,
    RecoveredCfg,
};
use crate::jumptable::{JumpTableResolution, SuccessorKind};
use crate::symexec::explore::SymexecBudget;
use crate::symexec::interp::Interp;
use crate::symexec::solver::{Feasible, Guard, SymSolver};
use crate::symexec::state::State;
use crate::symexec::value::{BitWidth, Sym};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CffTrace {
    pub cheap_blocks: usize,
    pub solver_blocks: usize,
    pub solver_invoked: bool,
}

#[must_use]
pub fn devirtualize(function: &NirFunction) -> CffOutcome {
    devirtualize_with(function, SymexecBudget::bounded_default())
}

#[must_use]
pub fn devirtualize_with(function: &NirFunction, budget: SymexecBudget) -> CffOutcome {
    devirtualize_traced(function, budget).0
}

#[must_use]
pub fn devirtualize_traced(
    function: &NirFunction,
    budget: SymexecBudget,
) -> (CffOutcome, CffTrace) {
    let blocks_list: Vec<NirBlock> = basic_blocks(function);
    if blocks_list.is_empty() {
        return (
            CffOutcome::Abstain(CffAbstain::NotFlattened),
            CffTrace::default(),
        );
    }
    if blocks_list.len() > MAX_CFF_BLOCKS {
        return (
            CffOutcome::Abstain(CffAbstain::TooManyBlocks),
            CffTrace::default(),
        );
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
            None => {
                return (
                    CffOutcome::Abstain(CffAbstain::NotFlattened),
                    CffTrace::default(),
                );
            }
        }
    };
    let plan: Plan = match detect(&blocks, entry_block) {
        Ok(plan) => plan,
        Err(reason) => return (CffOutcome::Abstain(reason), CffTrace::default()),
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
    let Some(sv_width): Option<SvWidth> = SvWidth::from_bytes(sv_width_bytes) else {
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
    build(&blocks, &plan, budget).0
}

fn build(
    blocks: &BTreeMap<u64, NirBlock>,
    plan: &Plan,
    budget: SymexecBudget,
) -> (CffOutcome, CffTrace) {
    let case_heads: BTreeSet<u64> = plan.casemap.values().copied().collect();
    let mut trace: CffTrace = CffTrace::default();
    let mut solver: Option<SymSolver> = None;
    let entry_real: u64 = if let Some(entry) =
        cheap_initial(blocks, plan, &case_heads, budget.loop_cap)
    {
        trace.cheap_blocks = trace.cheap_blocks.saturating_add(1);
        entry
    } else {
        let engine: &mut SymSolver = solver.get_or_insert_with(|| SymSolver::new(budget.solver()));
        trace.solver_invoked = true;
        let Some(entry): Option<u64> = solve_initial(engine, blocks, plan, &case_heads, budget)
        else {
            return (CffOutcome::Abstain(CffAbstain::InitialStateUnknown), trace);
        };
        trace.solver_blocks = trace.solver_blocks.saturating_add(1);
        entry
    };
    let mut edges: Vec<DevirtEdge> = Vec::new();
    let mut roles: BTreeMap<u64, BlockRole> = BTreeMap::new();
    let mut notes: Vec<DevirtNote> = Vec::new();
    for (&case_value, &block) in &plan.casemap {
        let resolution: BlockResolution = match cheap_resolve_block(
            blocks,
            plan,
            &case_heads,
            case_value,
            block,
            budget.loop_cap,
        ) {
            CheapResolution::Resolved { targets } => {
                trace.cheap_blocks = trace.cheap_blocks.saturating_add(1);
                BlockResolution::Resolved { targets }
            }
            CheapResolution::Terminal => {
                trace.cheap_blocks = trace.cheap_blocks.saturating_add(1);
                BlockResolution::Terminal
            }
            CheapResolution::Degrade(reason) => {
                trace.cheap_blocks = trace.cheap_blocks.saturating_add(1);
                BlockResolution::Degrade(reason)
            }
            CheapResolution::NeedsSolver => {
                let engine: &mut SymSolver =
                    solver.get_or_insert_with(|| SymSolver::new(budget.solver()));
                trace.solver_invoked = true;
                if engine.cumulative_exhausted() {
                    return (CffOutcome::Abstain(CffAbstain::Budget), trace);
                }
                trace.solver_blocks = trace.solver_blocks.saturating_add(1);
                resolve_block(engine, blocks, plan, &case_heads, case_value, block, budget)
            }
        };
        match resolution {
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
    (
        CffOutcome::Recovered(RecoveredCfg {
            entry: entry_real,
            state_var: plan.state_var.clone(),
            cases,
            edges,
            scaffolding,
            roles,
            notes,
        }),
        trace,
    )
}

#[derive(Debug)]
enum BlockResolution {
    Resolved { targets: Vec<u64> },
    Terminal,
    Degrade(DegradeReason),
}

fn plan_width(plan: &Plan) -> BitWidth {
    BitWidth::new(plan.sv_width.bits() as u16).unwrap_or(BitWidth::QWORD)
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
        plan_width(plan),
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
        plan_width(plan),
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
            if self.nodes > super::detect::MAX_REGION_NODES {
                self.abstain = Some(DegradeReason::RegionUnbounded);
                return;
            }
            let Some(block): Option<NirBlock> = self.blocks.get(&state.block).cloned() else {
                continue;
            };
            let mut wrote: bool = wrote;
            for instr in &block.instructions {
                if super::detect::dest_is(instr, self.state_var) {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use disrobe_nir::{NirFunction, NirInstr, NirOp, SourceLang, SourceRef, ValueOp};

    use super::*;
    use crate::cff::CanaryViolation;
    use crate::jumptable::{
        Endian, EntryKind, IndexBound, IndirectSite, PathConstraint, Perms, Section, SectionMap,
        TableForm, resolve_jump_table,
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
        let (outcome, trace): (CffOutcome, CffTrace) =
            devirtualize_traced(&straight_flattened(), SymexecBudget::bounded_default());
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
        assert!(
            !trace.solver_invoked,
            "a constant state-chain resolves entirely on the cheap tier: {trace:?}"
        );
        assert_eq!(trace.solver_blocks, 0);
    }

    #[test]
    fn cheap_chain_matches_the_solver_backed_recovery() {
        let (cheap, trace): (CffOutcome, CffTrace) =
            devirtualize_traced(&straight_flattened(), SymexecBudget::bounded_default());
        let solver_only: CffOutcome =
            solver_only_devirtualize(&straight_flattened(), SymexecBudget::bounded_default());
        assert!(!trace.solver_invoked);
        assert_eq!(
            cheap, solver_only,
            "the cheap tier and the solver path must agree on the recovered graph"
        );
    }

    fn solver_only_devirtualize(function: &NirFunction, budget: SymexecBudget) -> CffOutcome {
        let blocks_list: Vec<NirBlock> = basic_blocks(function);
        let blocks: BTreeMap<u64, NirBlock> = blocks_list
            .into_iter()
            .map(|block: NirBlock| (block.start, block))
            .collect();
        let entry_block: u64 = if blocks.contains_key(&function.address) {
            function.address
        } else {
            *blocks.keys().next().expect("non-empty")
        };
        let plan: Plan = detect(&blocks, entry_block).expect("detected");
        let case_heads: BTreeSet<u64> = plan.casemap.values().copied().collect();
        let mut solver: SymSolver = SymSolver::new(budget.solver());
        let entry_real: u64 = solve_initial(&mut solver, &blocks, &plan, &case_heads, budget)
            .expect("solver resolves the initial state");
        let mut edges: Vec<DevirtEdge> = Vec::new();
        let mut roles: BTreeMap<u64, BlockRole> = BTreeMap::new();
        let mut notes: Vec<DevirtNote> = Vec::new();
        for (&case_value, &block) in &plan.casemap {
            match resolve_block(
                &mut solver,
                &blocks,
                &plan,
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

    fn value_op(
        address: u64,
        op: ValueOp,
        dest: &str,
        inputs: &[&str],
        out_bytes: u32,
    ) -> NirInstr {
        raw(
            address,
            NirOp::Value {
                op,
                inputs: inputs
                    .iter()
                    .map(|item: &&str| (*item).to_owned())
                    .collect(),
                input_sizes: inputs.iter().map(|_| 4_u32).collect(),
                size: out_bytes,
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
        let (outcome, trace): (CffOutcome, CffTrace) =
            devirtualize_traced(&function(instrs, 0x64), SymexecBudget::bounded_default());
        let CffOutcome::Recovered(cfg) = outcome else {
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
        assert!(
            !trace.solver_invoked,
            "a conditional-state diamond over free inputs resolves without the solver: {trace:?}"
        );
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
        let (outcome, trace): (CffOutcome, CffTrace) =
            devirtualize_traced(&function(instrs, 0x64), SymexecBudget::bounded_default());
        let CffOutcome::Recovered(cfg) = outcome else {
            panic!("a state that maps back to an earlier block must recover its loop");
        };
        assert_eq!(cfg.entry, 0x40);
        assert_eq!(
            cfg.edge_set(),
            BTreeSet::from([(0x40, 0x50), (0x50, 0x50), (0x50, 0x60)]),
            "state 1 loops to itself while the condition holds, else exits to state 2"
        );
        assert!(cfg.canary().is_ok());
        assert!(!trace.solver_invoked, "the diamond loop resolves cheaply");
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

    #[test]
    fn opaque_internal_branch_falls_back_to_the_solver_and_agrees() {
        let mut instrs: Vec<NirInstr> = vec![
            set_state(0x00, "sv", "0"),
            raw(0x04, NirOp::Branch { target: Some(0x10) }, &[]),
        ];
        instrs.extend(dispatch_head());
        instrs.extend(vec![
            value_op(0x40, ValueOp::IntOr, "t", &["x", "1"], 4),
            value_op(0x42, ValueOp::IntNotEqual, "c", &["t", "0"], 1),
            raw(0x44, NirOp::CondBranch { target: Some(0x4c) }, &["c"]),
            set_state(0x48, "sv", "1"),
            raw(0x4a, NirOp::Branch { target: Some(0x10) }, &[]),
            set_state(0x4c, "sv", "2"),
            raw(0x4e, NirOp::Branch { target: Some(0x10) }, &[]),
            set_state(0x50, "sv", "2"),
            raw(0x54, NirOp::Branch { target: Some(0x10) }, &[]),
            raw(0x60, NirOp::Return, &[]),
        ]);
        let flat: NirFunction = function(instrs, 0x64);
        let (outcome, trace): (CffOutcome, CffTrace) =
            devirtualize_traced(&flat, SymexecBudget::bounded_default());
        let CffOutcome::Recovered(cfg) = outcome else {
            panic!("an opaque-predicate diamond must still deflatten via the solver");
        };
        assert!(
            trace.solver_invoked && trace.solver_blocks >= 1,
            "(x | 1) != 0 is not a provably two-valued equality of free inputs, so the block defers: {trace:?}"
        );
        assert_eq!(
            cfg.edge_set(),
            BTreeSet::from([(0x40, 0x60), (0x50, 0x60)]),
            "(x | 1) is never zero, so the solver keeps only the live arm to state 2"
        );
        assert!(cfg.canary().is_ok());
        assert_eq!(
            outcome_edges(&solver_only_devirtualize(
                &flat,
                SymexecBudget::bounded_default()
            )),
            cfg.edge_set(),
            "the mixed cheap/solver result matches a pure solver run"
        );
    }

    fn outcome_edges(outcome: &CffOutcome) -> BTreeSet<(u64, u64)> {
        match outcome {
            CffOutcome::Recovered(cfg) => cfg.edge_set(),
            CffOutcome::Abstain(_) => BTreeSet::new(),
        }
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
