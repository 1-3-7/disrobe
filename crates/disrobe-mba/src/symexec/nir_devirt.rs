use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use disrobe_nir::{NirBlock, NirFunction, NirOp, basic_blocks};

use super::cff::{BlockRole, CffOutcome, RecoveredCfg, devirtualize_with};
use super::explore::{AbstainReason, SymexecBudget};
use super::opaque::{CfgEdit, Resolution, analyze_opaque_with};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevirtStatus {
    Full,
    Partial,
    None,
}

impl DevirtStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldedBranch {
    pub block: u64,
    pub kept: u64,
    pub dropped: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevirtAbstain {
    OpaqueBudget(AbstainReason),
    RewriteRejected,
}

impl DevirtAbstain {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OpaqueBudget(reason) => match reason {
                AbstainReason::StateCap => "opaque-budget-state-cap",
                AbstainReason::PathCap => "opaque-budget-path-cap",
                AbstainReason::RetiredCap => "opaque-budget-step-cap",
                AbstainReason::LoopCap => "opaque-budget-loop-cap",
                AbstainReason::SolverBudget => "opaque-budget-solver",
                AbstainReason::SolverUnknown => "opaque-solver-unknown",
                AbstainReason::TooManyBlocks => "opaque-too-many-blocks",
            },
            Self::RewriteRejected => "rewrite-rejected-not-superset",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CffSummary {
    pub detected: bool,
    pub certified_full: bool,
    pub cases: usize,
    pub resolved: usize,
    pub unresolved: usize,
}

impl CffSummary {
    const fn none() -> Self {
        Self {
            detected: false,
            certified_full: false,
            cases: 0,
            resolved: 0,
            unresolved: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NirDevirtReport {
    pub status: DevirtStatus,
    pub folded: Vec<FoldedBranch>,
    pub cff: CffSummary,
    pub abstain: Option<DevirtAbstain>,
}

#[derive(Debug, Clone)]
pub struct NirDevirtOutcome {
    pub function: NirFunction,
    pub report: NirDevirtReport,
}

#[derive(Debug, Clone, Copy)]
pub struct BinaryBudget {
    deadline: Option<Instant>,
}

impl BinaryBudget {
    #[must_use]
    pub fn new(total: Duration) -> Self {
        Self {
            deadline: Instant::now().checked_add(total),
        }
    }

    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.deadline
            .is_some_and(|deadline: Instant| Instant::now() >= deadline)
    }
}

#[must_use]
pub fn devirtualize_nir(function: &NirFunction) -> NirDevirtOutcome {
    devirtualize_nir_with(function, SymexecBudget::bounded_default())
}

#[must_use]
pub fn devirtualize_nir_with(function: &NirFunction, budget: SymexecBudget) -> NirDevirtOutcome {
    let cff: CffSummary = detect_cff(function, budget);
    let (folded_function, folded, abstain): (
        NirFunction,
        Vec<FoldedBranch>,
        Option<DevirtAbstain>,
    ) = fold_opaque(function, budget);
    let status: DevirtStatus = classify(&folded, cff);
    NirDevirtOutcome {
        function: folded_function,
        report: NirDevirtReport {
            status,
            folded,
            cff,
            abstain,
        },
    }
}

const fn classify(folded: &[FoldedBranch], cff: CffSummary) -> DevirtStatus {
    if cff.detected {
        return DevirtStatus::Partial;
    }
    if folded.is_empty() {
        DevirtStatus::None
    } else {
        DevirtStatus::Full
    }
}

fn detect_cff(function: &NirFunction, budget: SymexecBudget) -> CffSummary {
    match devirtualize_with(function, budget) {
        CffOutcome::Recovered(cfg) => summarize_cff(&cfg),
        CffOutcome::Abstain(_) => CffSummary::none(),
    }
}

fn summarize_cff(cfg: &RecoveredCfg) -> CffSummary {
    let resolved: usize = cfg
        .roles
        .values()
        .filter(|role: &&BlockRole| matches!(role, BlockRole::Resolved))
        .count();
    let unresolved: usize = cfg
        .roles
        .values()
        .filter(|role: &&BlockRole| matches!(role, BlockRole::Unresolved))
        .count();
    let certified_full: bool = cfg.notes.is_empty() && unresolved == 0 && cfg.canary().is_ok();
    CffSummary {
        detected: true,
        certified_full,
        cases: cfg.cases.len(),
        resolved,
        unresolved,
    }
}

fn fold_opaque(
    function: &NirFunction,
    budget: SymexecBudget,
) -> (NirFunction, Vec<FoldedBranch>, Option<DevirtAbstain>) {
    let resolution: Resolution = analyze_opaque_with(function, budget);
    let edits: Vec<CfgEdit> = match resolution {
        Resolution::Resolved { edits } => edits,
        Resolution::Abstain(reason) => {
            return (
                function.clone(),
                Vec::new(),
                Some(DevirtAbstain::OpaqueBudget(reason)),
            );
        }
    };
    if edits.is_empty() {
        return (function.clone(), Vec::new(), None);
    }
    let blocks: Vec<NirBlock> = basic_blocks(function);
    let mut by_block: BTreeMap<u64, (u64, u64, u64)> = BTreeMap::new();
    let mut conflict: BTreeSet<u64> = BTreeSet::new();
    for edit in &edits {
        let Some(block): Option<&NirBlock> = blocks
            .iter()
            .find(|block: &&NirBlock| block.start == edit.from)
        else {
            continue;
        };
        let Some(terminator): Option<&disrobe_nir::NirInstr> = block.instructions.last() else {
            continue;
        };
        if !matches!(terminator.op, NirOp::CondBranch { .. }) {
            continue;
        }
        if block.successors.len() != 2 || !block.successors.contains(&edit.to) {
            continue;
        }
        let Some(live): Option<u64> = block
            .successors
            .iter()
            .copied()
            .find(|successor: &u64| *successor != edit.to)
        else {
            continue;
        };
        if by_block
            .insert(edit.from, (terminator.address, live, edit.to))
            .is_some()
        {
            conflict.insert(edit.from);
        }
    }
    for block_start in &conflict {
        by_block.remove(block_start);
    }
    if by_block.is_empty() {
        return (function.clone(), Vec::new(), None);
    }
    let rewrite_by_addr: BTreeMap<u64, u64> = by_block
        .values()
        .map(|(address, live, _dropped): &(u64, u64, u64)| (*address, *live))
        .collect();
    let mut candidate: NirFunction = function.clone();
    for instr in &mut candidate.instructions {
        if let Some(&live) = rewrite_by_addr.get(&instr.address) {
            instr.op = NirOp::Branch { target: Some(live) };
            instr.operands.clear();
        }
    }
    let old_edges: BTreeSet<(u64, u64)> = edge_set(function);
    let new_edges: BTreeSet<(u64, u64)> = edge_set(&candidate);
    if !new_edges.is_subset(&old_edges) {
        return (
            function.clone(),
            Vec::new(),
            Some(DevirtAbstain::RewriteRejected),
        );
    }
    let mut folded: Vec<FoldedBranch> = by_block
        .iter()
        .map(
            |(from, (_address, live, dropped)): (&u64, &(u64, u64, u64))| FoldedBranch {
                block: *from,
                kept: *live,
                dropped: *dropped,
            },
        )
        .collect();
    folded.sort_by_key(|branch: &FoldedBranch| branch.block);
    (candidate, folded, None)
}

fn edge_set(function: &NirFunction) -> BTreeSet<(u64, u64)> {
    basic_blocks(function)
        .into_iter()
        .flat_map(|block: NirBlock| {
            block
                .successors
                .into_iter()
                .map(move |successor: u64| (block.start, successor))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use std::time::Duration;

    use disrobe_nir::{NirInstr, NirOp, SourceLang, SourceRef, ValueOp};

    use super::*;

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

    fn value(
        address: u64,
        op: ValueOp,
        dest: &str,
        inputs: &[&str],
        sizes: &[u32],
        size: u32,
    ) -> NirInstr {
        raw(
            address,
            NirOp::Value {
                op,
                inputs: inputs
                    .iter()
                    .map(|item: &&str| (*item).to_owned())
                    .collect(),
                input_sizes: sizes.to_vec(),
                size,
            },
            &[dest],
        )
    }

    fn function(address: u64, end: u64, instructions: Vec<NirInstr>) -> NirFunction {
        NirFunction {
            name: "fixture".to_owned(),
            address,
            end,
            is_export: false,
            instructions,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    fn opaque_or_one() -> NirFunction {
        function(
            0x0,
            0x8,
            vec![
                value(0x0, ValueOp::IntOr, "t0", &["x", "1"], &[1, 1], 1),
                raw(0x2, NirOp::CondBranch { target: Some(0x6) }, &["t0"]),
                raw(0x4, NirOp::Return, &[]),
                raw(0x6, NirOp::Return, &[]),
            ],
        )
    }

    #[test]
    fn opaque_dead_arm_is_folded_to_the_live_successor() {
        let original: NirFunction = opaque_or_one();
        let outcome: NirDevirtOutcome = devirtualize_nir(&original);
        assert_eq!(outcome.report.status, DevirtStatus::Full);
        assert_eq!(
            outcome.report.folded,
            vec![FoldedBranch {
                block: 0x0,
                kept: 0x6,
                dropped: 0x4,
            }],
            "(x | 1) is never zero, so the fallthrough arm to 0x4 is dead and 0x6 survives"
        );
        assert!(outcome.report.abstain.is_none());

        let old_edges: BTreeSet<(u64, u64)> = edge_set(&original);
        let new_edges: BTreeSet<(u64, u64)> = edge_set(&outcome.function);
        assert!(
            new_edges.is_subset(&old_edges),
            "the rewrite may only remove edges, never invent one"
        );
        assert!(
            !new_edges.contains(&(0x0, 0x4)),
            "the proven-dead edge must be gone"
        );
        assert!(
            new_edges.contains(&(0x0, 0x6)),
            "the live edge must be preserved"
        );
        let terminator: &NirInstr = outcome
            .function
            .instructions
            .iter()
            .find(|instr: &&NirInstr| instr.address == 0x2)
            .expect("terminator survives");
        assert_eq!(terminator.op, NirOp::Branch { target: Some(0x6) });
    }

    #[test]
    fn budget_starved_solver_returns_the_original_untouched() {
        let fixture: NirFunction = function(
            0x0,
            0xe,
            vec![
                value(0x0, ValueOp::IntMult, "sq", &["a", "a"], &[4, 4], 4),
                value(0x2, ValueOp::IntAdd, "p", &["sq", "a"], &[4, 4], 4),
                value(0x4, ValueOp::IntAnd, "lo", &["p", "1"], &[4, 4], 4),
                value(0x6, ValueOp::IntEqual, "c", &["lo", "1"], &[4, 4], 1),
                raw(0x8, NirOp::CondBranch { target: Some(0xc) }, &["c"]),
                raw(0xa, NirOp::Return, &[]),
                raw(0xc, NirOp::Return, &[]),
            ],
        );
        let starved: SymexecBudget = SymexecBudget {
            solver_query_timeout: Duration::from_nanos(1),
            solver_max_conflicts: 0,
            solver_max_decisions: 0,
            ..SymexecBudget::bounded_default()
        };
        let outcome: NirDevirtOutcome = devirtualize_nir_with(&fixture, starved);
        assert_eq!(
            outcome.function, fixture,
            "an unproven case must return the original function verbatim"
        );
        assert!(outcome.report.folded.is_empty());
        assert_eq!(
            outcome.report.abstain,
            Some(DevirtAbstain::OpaqueBudget(AbstainReason::SolverUnknown))
        );
        assert_eq!(outcome.report.status, DevirtStatus::None);
    }

    #[test]
    fn data_dependent_compare_leaves_the_function_unchanged() {
        let fixture: NirFunction = function(
            0x0,
            0x8,
            vec![
                value(0x0, ValueOp::IntLess, "t0", &["a", "b"], &[1, 1], 1),
                raw(0x2, NirOp::CondBranch { target: Some(0x6) }, &["t0"]),
                raw(0x4, NirOp::Return, &[]),
                raw(0x6, NirOp::Return, &[]),
            ],
        );
        let outcome: NirDevirtOutcome = devirtualize_nir(&fixture);
        assert_eq!(outcome.function, fixture);
        assert!(outcome.report.folded.is_empty());
        assert!(outcome.report.abstain.is_none());
        assert_eq!(outcome.report.status, DevirtStatus::None);
    }

    #[test]
    fn exhausted_binary_budget_reports_exhaustion() {
        let budget: BinaryBudget = BinaryBudget::new(Duration::ZERO);
        assert!(budget.exhausted());
        let open: BinaryBudget = BinaryBudget::new(Duration::from_hours(1));
        assert!(!open.exhausted());
    }
}
