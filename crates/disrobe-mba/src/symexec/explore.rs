use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use disrobe_nir::{BlockKind, NirBlock, NirFunction, NirInstr, basic_blocks};

use super::interp::Interp;
use super::solver::{Feasible, Guard, SolverBudget, SymSolver};
use super::state::State;
use super::value::{BitWidth, Sym};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymexecBudget {
    pub max_blocks: usize,
    pub max_states: u64,
    pub max_paths: u64,
    pub max_retired: u64,
    pub loop_cap: u32,
    pub memory_ceiling: usize,
    pub solver_query_timeout: Duration,
    pub solver_max_conflicts: u64,
    pub solver_max_decisions: u64,
    pub solver_cumulative: Duration,
    pub solver_max_queries: u64,
}

impl SymexecBudget {
    #[must_use]
    pub const fn bounded_default() -> Self {
        Self {
            max_blocks: 4_096,
            max_states: 20_000,
            max_paths: 8_192,
            max_retired: 200_000,
            loop_cap: 8,
            memory_ceiling: 4_096,
            solver_query_timeout: Duration::from_millis(250),
            solver_max_conflicts: 20_000,
            solver_max_decisions: 100_000,
            solver_cumulative: Duration::from_secs(5),
            solver_max_queries: 4_096,
        }
    }

    pub(crate) const fn solver(self) -> SolverBudget {
        SolverBudget {
            per_query_timeout: self.solver_query_timeout,
            max_conflicts: self.solver_max_conflicts,
            max_decisions: self.solver_max_decisions,
            cumulative: self.solver_cumulative,
            max_queries: self.solver_max_queries,
        }
    }
}

impl Default for SymexecBudget {
    fn default() -> Self {
        Self::bounded_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbstainReason {
    StateCap,
    PathCap,
    RetiredCap,
    LoopCap,
    SolverBudget,
    SolverUnknown,
    TooManyBlocks,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) live: BTreeSet<(u64, u64)>,
    pub(crate) dead: BTreeSet<(u64, u64)>,
    pub(crate) abstain: Option<AbstainReason>,
}

#[derive(Debug)]
pub(crate) struct Explore {
    blocks: BTreeMap<u64, NirBlock>,
    solver: SymSolver,
    budget: SymexecBudget,
    live: BTreeSet<(u64, u64)>,
    dead: BTreeSet<(u64, u64)>,
    states_seen: u64,
    paths: u64,
    retired: u64,
    abstain: Option<AbstainReason>,
}

impl Explore {
    pub(crate) fn run(function: &NirFunction, budget: SymexecBudget) -> Outcome {
        let blocks_list: Vec<NirBlock> = basic_blocks(function);
        if blocks_list.is_empty() {
            return Outcome {
                live: BTreeSet::new(),
                dead: BTreeSet::new(),
                abstain: None,
            };
        }
        if blocks_list.len() > budget.max_blocks {
            return Outcome {
                live: BTreeSet::new(),
                dead: BTreeSet::new(),
                abstain: Some(AbstainReason::TooManyBlocks),
            };
        }
        let entry: u64 = function.address;
        let blocks: BTreeMap<u64, NirBlock> = blocks_list
            .into_iter()
            .map(|block: NirBlock| (block.start, block))
            .collect();
        let entry: u64 = if blocks.contains_key(&entry) {
            entry
        } else {
            blocks.keys().next().copied().unwrap_or(entry)
        };
        let mut engine: Self = Self {
            blocks,
            solver: SymSolver::new(budget.solver()),
            budget,
            live: BTreeSet::new(),
            dead: BTreeSet::new(),
            states_seen: 0,
            paths: 0,
            retired: 0,
            abstain: None,
        };
        engine.explore(entry);
        Outcome {
            live: engine.live,
            dead: engine.dead,
            abstain: engine.abstain,
        }
    }

    fn explore(&mut self, entry: u64) {
        let mut worklist: Vec<State> = vec![State::entry(entry, self.budget.memory_ceiling)];
        while let Some(mut state) = worklist.pop() {
            if self.abstain.is_some() {
                return;
            }
            self.states_seen = self.states_seen.saturating_add(1);
            if self.states_seen > self.budget.max_states {
                self.abstain = Some(AbstainReason::StateCap);
                return;
            }
            let Some(block): Option<NirBlock> = self.blocks.get(&state.block).cloned() else {
                continue;
            };
            if self.execute_block(&mut state, &block).is_none() {
                return;
            }
            self.transition(&state, &block, &mut worklist);
        }
    }

    fn execute_block(&mut self, state: &mut State, block: &NirBlock) -> Option<()> {
        for instr in &block.instructions {
            self.retired = self.retired.saturating_add(1);
            if self.retired > self.budget.max_retired {
                self.abstain = Some(AbstainReason::RetiredCap);
                return None;
            }
            Interp::new(&mut self.solver).step(state, instr);
        }
        Some(())
    }

    fn transition(&mut self, state: &State, block: &NirBlock, worklist: &mut Vec<State>) {
        if block.successors.is_empty() {
            self.paths = self.paths.saturating_add(1);
            if self.paths > self.budget.max_paths {
                self.abstain = Some(AbstainReason::PathCap);
            }
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
            self.branch(state, block.start, instr, taken, fallthrough, worklist);
            return;
        }
        for successor in &block.successors {
            self.live.insert((block.start, *successor));
            let child: State = state.fork(*successor);
            self.enqueue(child, worklist);
        }
    }

    fn branch(
        &mut self,
        state: &State,
        source: u64,
        terminator: &NirInstr,
        taken: u64,
        fallthrough: u64,
        worklist: &mut Vec<State>,
    ) {
        if self.solver.cumulative_exhausted() {
            self.abstain = Some(AbstainReason::SolverBudget);
            return;
        }
        let mut probe: State = state.clone();
        let condition: Sym = match terminator.operands.first() {
            Some(name) => {
                Interp::new(&mut self.solver).eval_operand(&mut probe, name, BitWidth::BYTE)
            }
            None => self.solver.fresh_havoc(BitWidth::BYTE),
        };
        let nonzero: Guard = self.solver.nonzero_guard(condition);
        let zero: Guard = self.solver.zero_guard(condition);
        let taken_feasible: Feasible = self.solver.feasible(&probe.path, nonzero);
        let fallthrough_feasible: Feasible = self.solver.feasible(&probe.path, zero);
        if taken_feasible == Feasible::Unknown || fallthrough_feasible == Feasible::Unknown {
            self.abstain = Some(AbstainReason::SolverUnknown);
            return;
        }
        self.arm(&probe, source, taken, nonzero, taken_feasible, worklist);
        self.arm(
            &probe,
            source,
            fallthrough,
            zero,
            fallthrough_feasible,
            worklist,
        );
    }

    fn arm(
        &mut self,
        state: &State,
        source: u64,
        target: u64,
        guard: Guard,
        feasible: Feasible,
        worklist: &mut Vec<State>,
    ) {
        match feasible {
            Feasible::Sat => {
                self.live.insert((source, target));
                let mut child: State = state.fork(target);
                if let Guard::Term(term) = guard {
                    child.path.push(term);
                }
                self.enqueue(child, worklist);
            }
            Feasible::Unsat => {
                self.dead.insert((source, target));
            }
            Feasible::Unknown => {
                self.abstain = Some(AbstainReason::SolverUnknown);
            }
        }
    }

    fn enqueue(&mut self, mut child: State, worklist: &mut Vec<State>) {
        let count: u32 = child
            .loop_counts
            .get(&child.block)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        if count > self.budget.loop_cap {
            self.abstain = Some(AbstainReason::LoopCap);
            return;
        }
        child.loop_counts.insert(child.block, count);
        worklist.push(child);
    }
}
