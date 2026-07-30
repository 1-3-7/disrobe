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
mod report;
mod summary;

pub use config::TaintConfig;
pub use engine::analyze;
pub use report::{TaintFinding, TaintReport, TaintStep, UnresolvedCall, UnresolvedCallKind};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
