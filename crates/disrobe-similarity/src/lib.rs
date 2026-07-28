#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![deny(clippy::float_arithmetic)]

mod constant;
mod features;
mod fingerprint;
mod matcher;
mod structure;

pub use constant::{SMALL_INTEGER_CEILING, is_discriminating_constant};
pub use features::{AnchorStrength, DataReference, FunctionFeatures, FunctionId, anchor_strength};
pub use fingerprint::ControlFlowFingerprint;
pub use matcher::{
    CallRelation, FunctionVerdict, MAXIMUM_PROPAGATION_HOPS, MatchReport, MatchStage,
    UnmatchedCause, Verdict, match_functions,
};
pub use structure::{
    BasicBlock, ControlFlowGraph, INSTRUCTION_CATEGORY_COUNT, InstructionCategory, InstructionMix,
    MINIMUM_DISTINGUISHING_BLOCKS, StructuralKey,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
