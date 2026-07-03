#![forbid(unsafe_code)]
#![allow(clippy::redundant_pub_crate)]
use std::fs;
use std::io::Read as _;
use std::path::Path;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const MAX_RUNTIME_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CAPTURE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JSON_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RUNTIME_DIR_ENTRIES: usize = 4096;

fn read_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata: fs::Metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        )
        .into());
    }
    if metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} is {} bytes; cap is {} bytes",
                path.display(),
                metadata.len(),
                max_bytes
            ),
        )
        .into());
    }
    let file: fs::File = fs::File::open(path)?;
    let mut reader: std::io::Take<fs::File> = file.take(max_bytes.saturating_add(1));
    let capacity: usize = usize::try_from(metadata.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} length does not fit usize", path.display()),
        )
    })?;
    let mut bytes: Vec<u8> = Vec::with_capacity(capacity);
    reader.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |len: u64| len > max_bytes) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} grew past {} bytes while reading",
                path.display(),
                max_bytes
            ),
        )
        .into());
    }
    Ok(bytes)
}

mod bcc_lift;
#[cfg(feature = "chain")]
pub mod chain_detector;
mod debug;
mod descriptor_cache;
mod detect;
mod dynamic_hook;
mod error;
pub mod format_wire;
mod inner_cipher;
mod key;
mod key_class;
#[cfg(feature = "llm-metadata")]
pub mod llm;
mod mix_string;
mod mode_class;
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

pub use bcc_lift::{
    BccLiftOutput, FunctionId, PseudoCFunction, lift_bcc_code_region, lift_bcc_native,
};
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
pub use key_class::{
    HeaderModeFlags, RuntimeKeyClass, RuntimeKeyClassification, SerialClassification, SerialKind,
    classify_runtime_key, classify_serial, decode_mode_flags, map_format_version,
};
#[cfg(feature = "llm-metadata")]
pub use llm::{METADATA_CAPABILITY as PYARMOR_METADATA_CAPABILITY, PyarmorLlmInput, RecoveredKey};
pub use mode_class::{
    BootstrapImport, ModeClassification, RecoveryDisposition, ScriptType, classify_modes,
};
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
    InnerCipherStats as StaticInnerCipherStats, LlmMetadata as StaticLlmMetadata,
    RuntimeInfoSummary as StaticRuntimeInfoSummary, UnpackConfig as StaticUnpackConfig,
    UnpackOutput as StaticUnpackOutput, WrapperMagic, unpack_static, unpack_static_with_config,
};
pub use unpack::{
    DynamicHookSummary, ModeOverride, TargetPyVersion, UnpackOptions, UnpackOutput,
    UserCodeCandidate, unpack_wrapper_text, unpack_wrapper_text_with_options,
};
pub use v3v4v5::{LegacyAnalysis, LegacyFormat};
pub use v8v9::{BccArch, BccBlob};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_file(name: &str) -> std::path::PathBuf {
        let seq: u64 = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "disrobe_pyarmor_{name}_{}_{}",
            std::process::id(),
            seq
        ))
    }

    #[test]
    fn bounded_file_read_accepts_file_within_cap() {
        let path: std::path::PathBuf = temp_file("within_cap");
        std::fs::write(&path, b"abcd").expect("write temp file");
        let bytes: Vec<u8> = read_file_bounded(&path, 4).expect("read under cap");
        assert_eq!(bytes, b"abcd");
        std::fs::remove_file(&path).expect("remove temp file");
    }

    #[test]
    fn bounded_file_read_rejects_file_over_cap() {
        let path: std::path::PathBuf = temp_file("over_cap");
        std::fs::write(&path, b"abcd").expect("write temp file");
        let err: Error = read_file_bounded(&path, 3).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
        std::fs::remove_file(&path).expect("remove temp file");
    }
}
