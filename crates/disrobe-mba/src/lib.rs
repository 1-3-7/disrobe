#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

pub mod bitwise_synth;
pub mod boolean;
pub mod egraph;
pub mod enum_synth;
pub mod expr;
pub mod finite_diff;
pub mod linear_mba;
pub mod linear_solver;
pub mod mixed_mba;
pub mod opaque;
pub mod perm_poly;
pub mod poly_mba;
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
pub use expr::{BinOp, Expr, UnOp, Width, equivalent_exhaustive, equivalent_exhaustive_runnable};
pub use finite_diff::{
    MAX_CERTIFICATE_DEGREE, composition_is_identity, induces_zero_function,
    polynomial_is_zero_function,
};
pub use linear_mba::synthesize_linear_basis;
pub use linear_solver::{
    MAX_SOLVER_VARS, columns_equal_mod_width, is_column_faithful, solve_linear_mba, truth_column,
};
pub use mixed_mba::{MAX_MIXED_MBA_VARS, simplify_mixed};
pub use opaque::{BranchFold, CmpOp, OpaqueVerdict, Predicate, classify, fold_branch};
pub use perm_poly::{PermutationPolynomial, recover_inverse};
pub use poly_mba::{MAX_POLY_MBA_VARS, solve_polynomial_mba};
pub use rewrite::canonicalize;
pub use rules::{
    ApplyError, Binary, Condition, LoadError, MBA_PEEPHOLE_RULES, Pattern, Rule, RuleHit, RuleSet,
    Template, Unary, apply_root, load_str, mba_peephole_rules, rewrite_fixpoint,
};
pub use simplify::{
    PredicateSimplification, Simplification, Verification, simplify, simplify_predicate,
};
#[cfg(feature = "smt-solver")]
pub use smt::{SmtBudget, SmtVerdict, check_unsat};
pub use smtlib::{equivalence_query, tautology_refutation_query};
#[cfg(feature = "smt-solver")]
pub use symexec::{
    AbstainReason, BlockRole, CanaryViolation, CffAbstain, CffOutcome, CfgEdit, DegradeReason,
    DevirtEdge, DevirtNote, EdgeGuard, Endian, EntryKind, IndexBound, IndirectSite,
    JumpTableAbstain, JumpTableResolution, PathConstraint, Perms, Provenance, PruneReason,
    RecoveredCfg, RejectCause, Resolution, Section, SectionMap, Successor, SuccessorKind,
    SymexecBudget, TableForm, analyze_opaque, analyze_opaque_with, devirtualize,
    devirtualize_table_dispatch, devirtualize_with, resolve_jump_table, resolve_jump_table_with,
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
