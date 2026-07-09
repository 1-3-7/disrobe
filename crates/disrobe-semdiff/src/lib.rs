#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

mod diff;
mod structural;

pub use diff::{ChangeKind, FunctionChange, SemanticDiff, diff};
pub use structural::{
    Indeterminate, MAX_FUNCTIONS_PER_MODULE, MAX_PROPAGATION_ROUNDS, MatchTier,
    StructuralMatchReport, StructuralPair, structural_match,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
