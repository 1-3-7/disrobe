#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

pub mod bitwise_synth;
#[cfg(any(feature = "smt-verify", test))]
pub mod boolean;
#[cfg(feature = "cfg-recovery")]
pub mod cff;
pub mod egraph;
pub mod enum_synth;
pub mod expr;
pub mod finite_diff;
pub mod jumptable;
pub mod linear_mba;
pub mod linear_solver;
pub mod mixed_mba;
pub mod opaque;
pub mod perm_poly;
pub mod poly_mba;
pub mod poly_oracle;
pub mod rewrite;
pub mod rules;
pub mod simplify;
#[cfg(feature = "smt-solver")]
pub mod smt;
pub mod smtlib;
#[cfg(feature = "smt-solver")]
pub mod symexec;
#[cfg(feature = "smt-verify")]
pub mod synth;
#[cfg(feature = "smt-verify")]
pub mod verify;

pub use bitwise_synth::{MAX_BITWISE_SYNTH_VARS, synthesize_bitwise_masked};
#[cfg(feature = "cfg-recovery")]
pub use cff::{
    BlockRole, CanaryViolation, CffAbstain, CffOutcome, DegradeReason, DevirtEdge, DevirtNote,
    EdgeGuard, RecoveredCfg, devirtualize_cheap,
};
#[cfg(feature = "smt-solver")]
pub use cff::{
    CffTrace, devirtualize, devirtualize_table_dispatch, devirtualize_traced, devirtualize_with,
};
pub use expr::{BinOp, Expr, UnOp, Width, equivalent_exhaustive, equivalent_exhaustive_runnable};
pub use finite_diff::{
    MAX_CERTIFICATE_DEGREE, composition_is_identity, induces_zero_function,
    polynomial_is_zero_function,
};
pub use jumptable::{
    Endian, EntryKind, IndexBound, IndirectSite, JumpTableAbstain, JumpTableResolution,
    PathConstraint, Perms, Provenance, RejectCause, ResolveTier, Section, SectionMap, Successor,
    SuccessorKind, TableForm, resolve_jump_table_vsa,
};
#[cfg(feature = "smt-solver")]
pub use jumptable::{resolve_jump_table, resolve_jump_table_with};
pub use linear_mba::synthesize_linear_basis;
pub use linear_solver::{
    MAX_SOLVER_VARS, columns_equal_mod_width, is_column_faithful, solve_linear_mba, truth_column,
};
pub use mixed_mba::{
    MAX_MIXED_MBA_NODES, MAX_MIXED_MBA_VARS, MAX_MIXED_MBA_WORK, MixedRefusal, MixedSimplification,
    simplify_mixed, simplify_mixed_detailed,
};
pub use opaque::{BranchFold, CmpOp, OpaqueVerdict, Predicate, classify, fold_branch};
pub use perm_poly::{PermutationPolynomial, recover_inverse};
pub use poly_mba::{MAX_POLY_MBA_VARS, solve_polynomial_mba};
pub use rewrite::canonicalize;
pub use rules::{
    ApplyError, Binary, Condition, LoadError, MBA_PEEPHOLE_RULES, Pattern, Rule, RuleHit, RuleSet,
    Template, Unary, apply_root, load_str, mba_peephole_rule_pack_id, mba_peephole_rules,
    rewrite_fixpoint,
};
pub use simplify::{
    PredicateSimplification, Simplification, Verification, simplify, simplify_predicate,
};
#[cfg(feature = "smt-solver")]
pub use smt::{SmtBudget, SmtVerdict, check_unsat};
pub use smtlib::{equivalence_query, tautology_refutation_query};
#[cfg(feature = "smt-solver")]
pub use symexec::{
    AbstainReason, BinaryBudget, CffSummary, CfgEdit, DevirtAbstain, DevirtStatus, FoldedBranch,
    NirDevirtOutcome, NirDevirtReport, PruneReason, Resolution, SymexecBudget, analyze_opaque,
    analyze_opaque_with, devirtualize_nir, devirtualize_nir_with,
};
#[cfg(feature = "smt-verify")]
pub use synth::{SynthConfig, synthesize, synthesize_with};
#[cfg(feature = "smt-verify")]
pub use verify::{
    Equivalence, EquivalenceInput, verify_equivalent, verify_equivalent_budgeted,
    verify_predicate_equivalent_budgeted,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub const fn version() -> &'static str {
    VERSION
}
