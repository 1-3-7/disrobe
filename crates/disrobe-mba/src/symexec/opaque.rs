use disrobe_nir::NirFunction;

use super::explore::{AbstainReason, Explore, Outcome, SymexecBudget};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneReason {
    ProvenUnsatArm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfgEdit {
    pub from: u64,
    pub to: u64,
    pub reason: PruneReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    Resolved { edits: Vec<CfgEdit> },
    Abstain(AbstainReason),
}

impl Resolution {
    #[must_use]
    pub fn dropped_edges(&self) -> &[CfgEdit] {
        match self {
            Self::Resolved { edits } => edits,
            Self::Abstain(_) => &[],
        }
    }

    #[must_use]
    pub const fn is_abstain(&self) -> bool {
        matches!(self, Self::Abstain(_))
    }
}

#[must_use]
pub fn analyze_opaque(function: &NirFunction) -> Resolution {
    analyze_opaque_with(function, SymexecBudget::bounded_default())
}

#[must_use]
pub fn analyze_opaque_with(function: &NirFunction, budget: SymexecBudget) -> Resolution {
    let outcome: Outcome = Explore::run(function, budget);
    if let Some(reason) = outcome.abstain {
        return Resolution::Abstain(reason);
    }
    let edits: Vec<CfgEdit> = outcome
        .dead
        .difference(&outcome.live)
        .map(|&(from, to): &(u64, u64)| CfgEdit {
            from,
            to,
            reason: PruneReason::ProvenUnsatArm,
        })
        .collect();
    Resolution::Resolved { edits }
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

    #[test]
    fn opaque_or_one_prunes_exactly_the_known_dead_arm() {
        let fixture: NirFunction = function(
            0x0,
            0x8,
            vec![
                value(0x0, ValueOp::IntOr, "t0", &["x", "1"], &[1, 1], 1),
                raw(0x2, NirOp::CondBranch { target: Some(0x6) }, &["t0"]),
                raw(0x4, NirOp::Return, &[]),
                raw(0x6, NirOp::Return, &[]),
            ],
        );
        let resolution: Resolution = analyze_opaque(&fixture);
        assert_eq!(
            resolution,
            Resolution::Resolved {
                edits: vec![CfgEdit {
                    from: 0x0,
                    to: 0x4,
                    reason: PruneReason::ProvenUnsatArm,
                }],
            },
            "the (x | 1) == 0 fallthrough arm is provably dead; the nonzero arm survives"
        );
    }

    #[test]
    fn canary_data_dependent_compare_prunes_nothing() {
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
        let resolution: Resolution = analyze_opaque(&fixture);
        assert_eq!(resolution, Resolution::Resolved { edits: Vec::new() });
        assert!(resolution.dropped_edges().is_empty());
    }

    #[test]
    fn canary_switch_chain_prunes_nothing() {
        let fixture: NirFunction = function(
            0x0,
            0x12,
            vec![
                value(0x0, ValueOp::IntEqual, "c0", &["s", "1"], &[1, 1], 1),
                raw(0x2, NirOp::CondBranch { target: Some(0x10) }, &["c0"]),
                value(0x4, ValueOp::IntEqual, "c1", &["s", "2"], &[1, 1], 1),
                raw(0x6, NirOp::CondBranch { target: Some(0x10) }, &["c1"]),
                raw(0x8, NirOp::Return, &[]),
                raw(0x10, NirOp::Return, &[]),
            ],
        );
        let resolution: Resolution = analyze_opaque(&fixture);
        assert!(resolution.dropped_edges().is_empty());
        assert!(!resolution.is_abstain());
    }

    #[test]
    fn canary_bounded_loop_guard_prunes_nothing() {
        let fixture: NirFunction = function(
            0x0,
            0xc,
            vec![
                raw(
                    0x0,
                    NirOp::Copy {
                        src: "0".to_owned(),
                        size: 1,
                    },
                    &["i"],
                ),
                value(0x2, ValueOp::IntLessEqual, "ge", &["3", "i"], &[1, 1], 1),
                raw(0x4, NirOp::CondBranch { target: Some(0xa) }, &["ge"]),
                value(0x6, ValueOp::IntAdd, "i", &["i", "1"], &[1, 1], 1),
                raw(0x8, NirOp::Branch { target: Some(0x2) }, &[]),
                raw(0xa, NirOp::Return, &[]),
            ],
        );
        let resolution: Resolution = analyze_opaque(&fixture);
        assert!(
            resolution.dropped_edges().is_empty(),
            "both loop edges are taken across iterations; neither is dead: {resolution:?}"
        );
        assert!(!resolution.is_abstain());
    }

    #[test]
    fn hostile_unbounded_loop_abstains_without_pruning() {
        let fixture: NirFunction = function(
            0x0,
            0xa,
            vec![
                value(0x0, ValueOp::IntLessEqual, "ge", &["n", "i"], &[1, 1], 1),
                raw(0x2, NirOp::CondBranch { target: Some(0x8) }, &["ge"]),
                value(0x4, ValueOp::IntAdd, "i", &["i", "1"], &[1, 1], 1),
                raw(0x6, NirOp::Branch { target: Some(0x0) }, &[]),
                raw(0x8, NirOp::Return, &[]),
            ],
        );
        let resolution: Resolution = analyze_opaque(&fixture);
        assert!(
            resolution.is_abstain(),
            "unbounded symbolic loop must abstain: {resolution:?}"
        );
        assert!(resolution.dropped_edges().is_empty());
    }

    #[test]
    fn solver_unknown_abstains_rather_than_guessing() {
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
        let resolution: Resolution = analyze_opaque_with(&fixture, starved);
        assert_eq!(
            resolution,
            Resolution::Abstain(AbstainReason::SolverUnknown)
        );
        assert!(resolution.dropped_edges().is_empty());
    }
}
