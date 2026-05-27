//! Chain-detect state machine.
//!
//! Implements `disrobe.chain/v1` -- a trait + registry + precedence comparator,
//! a work-queue driver, and a serde `chain.json` model. The wire schema is
//! published at `schemas/chain.v1.json`.
//!
//! The module is gated behind the `chain` cargo feature so that crates
//! which do not need the driver pay zero compile cost.

pub mod chain_json;
pub mod detection;
pub mod detector;
pub mod precedence;
pub mod registry;
pub mod spec;
pub mod state_machine;

pub use chain_json::{
    ChainDocument, ChainInputDoc, ChainSpecDoc, ChainStats, DetectorPickDoc, NodeDoc,
    OutputKindDoc, SCHEMA_VERSION, Topology,
};
pub use detection::{
    ArtifactRef, ChildHandle, ConfidenceBand, DetectContext, DetectVerdict, Detection, OutputKind,
    PassRunOutcome,
};
pub use detector::{Detector, Pass};
pub use precedence::{
    FAMILY_CONTAINER, FAMILY_INTERPRETER_BYTECODE, FAMILY_NATIVE_FORMAT, FAMILY_OBFUSCATOR_WRAPPER,
    FAMILY_PACKER_ARCHIVE, FAMILY_SOURCE, FAMILY_UNKNOWN, compare, family_precedence,
};
pub use registry::{DetectorPick, PassRegistry};
pub use spec::{ChainSpec, ChainSpecError, PassToken, SpecCursor, SpecKind};
pub use state_machine::{ChainConfig, ChainDriver, ChainPlan, Node, NodeId, Verdict, WorkItem};
