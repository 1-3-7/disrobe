#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is the correct visibility for the crate-internal summary, arena, and call-graph helpers shared across private submodules; redundant_pub_crate (nursery) and the workspace unreachable_pub lint cannot both hold for a private submodule, matching the crate-level allow already shipped across the workspace"
)]

mod abi;
mod callgraph;
mod config;
mod engine;
mod pe_facts;
mod pointers;
mod report;
mod summary;
mod thunks;

pub use callgraph::{
    CALL_EDGE_TARGET_CAP, CallEdge, CallEdgeBuildError, CallEdgeEvidence, CallEdgeLabel,
    NonEmptyCallTargets,
};
pub use config::TaintConfig;
pub use engine::{
    analyze, analyze_with_call_edges, analyze_with_constant_pointers, analyze_with_import_thunks,
};
pub use pe_facts::{MAX_CONSTANT_POINTER_SLOTS, PeFacts, PeFactsError, pe_facts};
pub use pointers::ConstantPointers;
pub use report::{TaintFinding, TaintReport, TaintStep, UnresolvedCall, UnresolvedCallKind};
pub use thunks::ImportThunks;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
