#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is the right visibility for the crate-internal value-graph and optimizer helpers; redundant_pub_crate (nursery) and the workspace unreachable_pub lint cannot both hold for a private submodule, matching the crate-level allow already shipped across the workspace"
)]

mod capability;
mod cfg;
mod dfg;
#[cfg(feature = "llm-metadata")]
mod llm;
mod llvmir;
mod optimize;
mod symexec;
mod valuegraph;

pub use capability::{CapabilitySummary, CapabilityTag, capability_summary};
pub use cfg::{CfgBlock, CfgFunction, CfgSummary, cfg_summary};
pub use dfg::{DataEdge, DfgFunction, DfgSummary, dfg_summary};
#[cfg(feature = "llm-metadata")]
pub use llm::{IrSummaryEmitter, METADATA_CAPABILITY};
pub use llvmir::{
    LlvmEmitError, LlvmModule, emit_llvm_function, emit_optimized_llvm_function, llvm_int_ty,
};
pub use symexec::{BranchFact, Location, NirSummary, summarize_function};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
