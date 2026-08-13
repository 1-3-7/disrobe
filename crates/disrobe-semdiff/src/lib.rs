#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

mod diff;
mod lineage;
mod structural;
mod summary;

pub use diff::{ChangeKind, FunctionChange, SemanticDiff, diff};
pub use lineage::{
    LineageMember, LineageReport, LineageVariant, MAX_LINEAGE_VARIANTS, VariantFamily,
    variant_lineage,
};
pub use structural::{
    Indeterminate, MAX_FUNCTIONS_PER_MODULE, MAX_PROPAGATION_ROUNDS, MatchTier,
    StructuralMatchReport, StructuralPair, structural_match,
};
pub use summary::{
    MAX_ADDRESS_PEEL_STEPS, MAX_SUMMARY_BLOCKS, MAX_SUMMARY_DEPTH, MAX_SUMMARY_INSTRUCTIONS,
    MAX_SUMMARY_MEMORY_CELLS, MAX_SUMMARY_NODES, MAX_SUMMARY_OUTPUTS, MIN_SUMMARY_OPERATIONS,
    SummaryDecline, SymbolicSummary, symbolic_summary,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
