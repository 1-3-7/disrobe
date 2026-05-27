#![forbid(unsafe_code)]
#![allow(clippy::redundant_pub_crate)]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

mod bcc_lift;
#[cfg(feature = "chain")]
pub mod chain_detector;
mod descriptor_cache;
mod detect;
mod dynamic_hook;
mod error;
pub mod format_wire;
mod inner_cipher;
mod key;
#[cfg(feature = "llm-metadata")]
pub mod llm;
mod mix_string;
mod nine_pro;
mod pass;
mod provenance;
mod provenance_header;
mod runtime;
mod sourcedefender_cross;
pub mod static_unpack;
mod unpack;
mod v3v4v5;
mod v6v7;
mod v8v9;
mod wrap;

pub use bcc_lift::{BccLiftOutput, FunctionId, PseudoCFunction, lift_bcc_native};
pub use descriptor_cache::{DescriptorCache, DescriptorCacheConfig, DescriptorCacheStats};
pub use detect::{
    Detection, DetectionConfidence, ProtectionKind, PyarmorVersion, detect_from_wrapper,
};
pub use dynamic_hook::{
    CaptureGroups, CaptureLimitation, CaptureManifest, CaptureManifestEntry, CaptureSource,
    DynamicHookOptions, DynamicHookResult, InterpreterSpec, run_dynamic_hook,
    run_dynamic_hook_with_target,
};
pub use error::{Error, Result};
pub use format_wire::format_python;
pub use inner_cipher::{
    DecryptionStats, PyarmorCoDescriptor, PyarmorModuleState, PyarmorTrailer, decrypt_module,
    decrypt_module_with_cache, parse_plaintext_xor_procedure,
};
#[cfg(feature = "llm-metadata")]
pub use llm::{METADATA_CAPABILITY as PYARMOR_METADATA_CAPABILITY, PyarmorLlmInput, RecoveredKey};
pub use nine_pro::{NineProBindMode, NineProDetection, detect_nine_pro};
pub use pass::{
    PASS_INPUT_PATH_CAP, PassInput, PyarmorPass, UnpackSummary, decode_pass_input,
    encode_pass_output,
};
pub use provenance::{ProvenanceRegion, ProvenanceStage, PyarmorProvenance};
pub use provenance_header::{
    python_disasm_header, python_unpacked_header, render_disasm_with_header,
    render_unpacked_with_header,
};
pub use sourcedefender_cross::{
    CrossoverFinding, SourcedefenderCrossKind, detect_sourcedefender_cross,
};
pub use static_unpack::{
    DecryptStatus as StaticDecryptStatus, HeaderMetadata as StaticHeaderMetadata,
    InnerCipherStats as StaticInnerCipherStats, LlmMetadata as StaticLlmMetadata, MutualInfoHint,
    RuntimeInfoSummary as StaticRuntimeInfoSummary, UnpackConfig as StaticUnpackConfig,
    UnpackOutput as StaticUnpackOutput, WrapperMagic, recover_with_mutual_info_hint, unpack_static,
    unpack_static_with_config,
};
pub use unpack::{
    DynamicHookSummary, ModeOverride, TargetPyVersion, UnpackOptions, UnpackOutput,
    UserCodeCandidate, unpack_wrapper_text, unpack_wrapper_text_with_options,
};
pub use v3v4v5::LegacyDecryptedPayload;
pub use v8v9::{BccArch, BccBlob};
