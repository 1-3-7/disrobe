#![forbid(unsafe_code)]
#![doc = "Bounded symbolic anti-analysis primitives shared across disrobe passes."]
#![doc = ""]
#![doc = "Two frontend-agnostic analyses over fixed-width bitvector expressions:"]
#![doc = ""]
#![doc = "- [`simplify`]: a mixed-boolean-arithmetic (MBA) simplifier that returns a"]
#![doc = "  linear MBA expression to its canonical arithmetic form (for example"]
#![doc = "  `(x ^ y) + 2*(x & y)` becomes `x + y`). Every emitted rewrite is checked"]
#![doc = "  for equivalence by exhaustive bitvector evaluation, exact column identity,"]
#![doc = "  or bounded bit-blast equivalence."]
#![doc = "- [`opaque`]: a symbolic opaque-predicate prover that classifies a predicate"]
#![doc = "  as always-true, always-false, or genuinely data-dependent by exhaustive"]
#![doc = "  small-domain evaluation, then folds the dead branch away."]
#![doc = ""]
#![doc = "Soundness rests on three independent oracles, picked by what the query"]
#![doc = "allows: exhaustive bitvector enumeration (complete up to 16-bit operands and"]
#![doc = "three free variables); a [`linear_solver`] that proves a linear-MBA rewrite over"]
#![doc = "Z/2^n exactly by truth-table column identity, which holds at W16/W32/W64 and for"]
#![doc = "more variables than enumeration can reach; and a BDD bit-blasting"]
#![doc = "[`verify`]ier enabled by default through the `smt-verify` feature. A rewrite that none of these can"]
#![doc = "prove is left untouched rather than emitted on heuristic confidence."]
#![doc = ""]
#![doc = "[`bitwise_synth`] recovers a minimal partial-mask form for multi-variable pure"]
#![doc = "bitwise functions (for example `(x & y) & 0xF0 | (x ^ y) & 0x0F`), which the"]
#![doc = "linear-MBA grammar excludes because it forbids non-trivial mask constants. It reads"]
#![doc = "each output bit's boolean function, groups bit positions by that function, and emits"]
#![doc = "one masked term per distinct function; the result is proven by the same oracles."]

pub mod bitwise_synth;
pub mod expr;
pub mod linear_mba;
pub mod linear_solver;
pub mod opaque;
pub mod rewrite;
pub mod rules;
pub mod simplify;
#[cfg(feature = "smt-solver")]
pub mod smt;
#[cfg(feature = "smt-verify")]
pub mod verify;

pub use bitwise_synth::{MAX_BITWISE_SYNTH_VARS, synthesize_bitwise_masked};
pub use expr::{BinOp, Expr, UnOp, Width, equivalent_exhaustive, equivalent_exhaustive_runnable};
pub use linear_mba::synthesize_linear_basis;
pub use linear_solver::{
    MAX_SOLVER_VARS, columns_equal_mod_width, is_column_faithful, solve_linear_mba, truth_column,
};
pub use opaque::{BranchFold, CmpOp, OpaqueVerdict, Predicate, classify, fold_branch};
pub use rewrite::canonicalize;
pub use rules::{
    ApplyError, Binary, Condition, LoadError, MBA_PEEPHOLE_RULES, Pattern, Rule, RuleHit, RuleSet,
    Template, Unary, apply_root, load_str, mba_peephole_rules, rewrite_fixpoint,
};
pub use simplify::{Simplification, Verification, simplify};
#[cfg(feature = "smt-solver")]
pub use smt::{SmtBudget, SmtVerdict, check_unsat};
#[cfg(feature = "smt-verify")]
pub use verify::{Equivalence, verify_equivalent, verify_equivalent_budgeted};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub const fn version() -> &'static str {
    VERSION
}
