#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is the right visibility for these crate-internal symbolic-execution helpers; redundant_pub_crate (nursery) and the workspace unreachable_pub lint cannot both hold for a private submodule, matching the crate-level allow already shipped across the workspace"
)]

pub(crate) mod explore;
pub(crate) mod jumptable;
pub(crate) mod memory;
pub(crate) mod opaque;
pub(crate) mod solver;
pub(crate) mod state;
pub(crate) mod value;

pub use explore::{AbstainReason, SymexecBudget};
pub use jumptable::{
    Endian, EntryKind, IndexBound, IndirectSite, JumpTableAbstain, JumpTableResolution,
    PathConstraint, Perms, Provenance, RejectCause, Section, SectionMap, Successor, SuccessorKind,
    TableForm, resolve_jump_table, resolve_jump_table_with,
};
pub use opaque::{CfgEdit, PruneReason, Resolution, analyze_opaque, analyze_opaque_with};
