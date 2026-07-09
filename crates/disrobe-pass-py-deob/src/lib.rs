#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(clippy::redundant_pub_crate)]
pub mod ast_eval;
mod auto_route;
#[cfg(feature = "chain")]
pub mod chain_detector;
mod cipher;
mod codec;
mod constant_fold;
mod dead_branch;
pub(crate) mod debug;
mod detect;
mod error;
pub mod format_wire;
mod fstring_recover;
mod hyperion_v2v3;
mod junk_fn;
mod layered_peel;
#[cfg(feature = "llm-metadata")]
pub mod llm;
pub mod marshal;
pub mod obfuscators;
pub mod pass;
mod peel;
mod provenance_header;
mod pyrandom;
mod shuffled_base64;
mod source_cleanup;
mod unrename;

pub use auto_route::{
    AutoDeobOutcome, RouteKind, SupportedObfuscator, auto_deobfuscate, looks_obfuscated,
    supported_families, supported_obfuscators, unidentified_guidance,
};
pub use cipher::{CipherKind, KeyFinding, KeyProvenance};
pub use detect::{Detection, Family, detect};
pub use error::{Error, Result};
pub use format_wire::format_python;
pub use hyperion_v2v3::{
    CodeObjectSummary as HyperionCodeObjectSummary, HyperionPeelStep, HyperionV2V3Detection,
    HyperionV2V3PeelResult, HyperionVariant, InnerDecodeResult as HyperionInnerDecodeResult,
    InnerStage as HyperionInnerStage, InnerStageKind as HyperionInnerStageKind,
    PEEL_ALL_DEFAULT_ITERS as PEEL_ALL_HYPERION_DEFAULT_ITERS,
    decode_inner as decode_hyperion_v2v3_inner,
    decode_inner_with_version as decode_hyperion_v2v3_inner_with_version,
    detect as detect_hyperion_v2v3, peel_all_layers as peel_hyperion_v2v3_all_layers,
    peel_one_layer as peel_hyperion_v2v3_layer,
};
pub use layered_peel::{LayerStep, LayeredPeel, PeelBudget, WallReason};
#[cfg(feature = "llm-metadata")]
pub use llm::{METADATA_CAPABILITY as PY_DEOB_METADATA_CAPABILITY, PyDeobLlmInput};
pub use marshal::{
    MarshalLayer, MarshalRecovery, detect_marshal, recover_marshal as recover_marshal_source,
};
pub use obfuscators::pyc_zipper::{PycZipperPass, recover_pyc as recover_pyc_zipper};
pub use obfuscators::{
    DetectReport as ObfuscatorDetectReport, Obfuscator, ObfuscatorPass,
    PeelOutcome as ObfuscatorPeelOutcome, Quality as ObfuscatorQuality, iter_passes,
};
pub use pass::PyDeobLegacyPass;
pub use peel::{ObfuscatorPeelSummary, PeelResult, PeelStep, peel, peel_with_pyver};
pub use provenance_header::{python_deobfuscated_header, render_deobfuscated_with_header};
pub use source_cleanup::{CleanupStats, cleanup_source};
pub use unrename::UnrenameStats;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
