#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is the right visibility for these crate-internal symbolic-execution helpers; redundant_pub_crate (nursery) and the workspace unreachable_pub lint cannot both hold for a private submodule, matching the crate-level allow already shipped across the workspace"
)]

pub(crate) mod cff;
pub(crate) mod explore;
pub(crate) mod interp;
pub(crate) mod jumptable;
pub(crate) mod memory;
pub(crate) mod nir_devirt;
pub(crate) mod opaque;
pub(crate) mod solver;
pub(crate) mod solver_cert;
pub(crate) mod state;
pub(crate) mod value;

pub use cff::{
    BlockRole, CanaryViolation, CffAbstain, CffOutcome, DegradeReason, DevirtEdge, DevirtNote,
    EdgeGuard, RecoveredCfg, devirtualize, devirtualize_table_dispatch, devirtualize_with,
};
pub use explore::{AbstainReason, SymexecBudget};
pub use jumptable::{
    Endian, EntryKind, IndexBound, IndirectSite, JumpTableAbstain, JumpTableResolution,
    PathConstraint, Perms, Provenance, RejectCause, Section, SectionMap, Successor, SuccessorKind,
    TableForm, resolve_jump_table, resolve_jump_table_with,
};
pub use nir_devirt::{
    BinaryBudget, CffSummary, DevirtAbstain, DevirtStatus, FoldedBranch, NirDevirtOutcome,
    NirDevirtReport, devirtualize_nir, devirtualize_nir_with,
};
pub use opaque::{CfgEdit, PruneReason, Resolution, analyze_opaque, analyze_opaque_with};
