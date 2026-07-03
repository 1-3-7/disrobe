pub mod chain_json;
pub mod detection;
pub mod detector;
pub mod ecosystem;
pub mod obfuscator_catalog;
pub mod precedence;
pub mod recovery;
pub mod registry;
pub mod spec;
pub mod state_machine;

pub use chain_json::{
    ChainDocument, ChainInputDoc, ChainSpecDoc, ChainStats, DetectorPickDoc, NodeDoc,
    OutputKindDoc, SCHEMA_VERSION, Topology, VerdictDoc,
};
pub use detection::{
    ArtifactRef, ChildArtifact, ChildHandle, ConfidenceBand, DetectContext, DetectVerdict,
    Detection, OutputKind, PassRunOutcome,
};
pub use detector::{Detector, Pass};
pub use ecosystem::{Ecosystem, ecosystem_for};
pub use obfuscator_catalog::{CatalogEntry, DetectorOutput, ObfuscatorCatalog, SupportQuality};
pub use precedence::{
    FAMILY_CONTAINER, FAMILY_INTERPRETER_BYTECODE, FAMILY_NATIVE_FORMAT, FAMILY_OBFUSCATOR_WRAPPER,
    FAMILY_PACKER_ARCHIVE, FAMILY_SOURCE, FAMILY_UNKNOWN, compare, family_precedence,
};
pub use recovery::{
    ChainPassRecovery, ChainRecoveryReport, RECOVERY_SCHEMA_VERSION, RecoveryInputDoc,
    RecoveryStatus, status_from_node, tier_from_node,
};
pub use registry::{DetectorPick, PassRegistry};
pub use spec::{ChainSpec, ChainSpecError, PassToken, SpecCursor, SpecKind};
pub use state_machine::{
    ChainConfig, ChainDriver, ChainPlan, ExtractedArtifact, Node, NodeId, Verdict, WorkItem,
};
