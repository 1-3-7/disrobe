use crate::detect::Detection;
use crate::error::{Error, Result};
use crate::static_unpack::runtime::RuntimeInfoSummary;
use crate::static_unpack::{DecryptStatus, InnerCipherStats, UnpackConfig, VersionedOutcome};

pub(crate) fn run(
    bytes: &[u8],
    detection: &Detection,
    runtime: Option<&RuntimeInfoSummary>,
    cfg: &UnpackConfig,
) -> Result<VersionedOutcome> {
    if cfg.strict && runtime.is_none() {
        return Err(Error::RuntimeNotFound {
            searched: vec!["<runtime not supplied to unpack_static_with_config>".to_owned()],
        });
    }
    let _ = bytes;
    let _ = detection;
    Ok(VersionedOutcome {
        plaintext: Vec::new(),
        original_bytecode: None,
        bcc_blobs: Vec::new(),
        encrypted_funcs_recovered: 0,
        inner_cipher_stats: InnerCipherStats::empty(),
        status: DecryptStatus::DetectOnly,
        diagnostics: vec![
            "DR-PYARM-STATIC: v6 in-memory decrypt requires runtime bytes; supply UnpackConfig.runtime_bytes or use unpack_wrapper_text_with_options for file-based flow"
                .to_owned(),
        ],
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::detect::{DetectionConfidence, ProtectionKind, PyarmorVersion};

    fn dummy_detection() -> Detection {
        Detection {
            version: PyarmorVersion::V6,
            protection: ProtectionKind::Standard,
            serial: None,
            python_major: Some(3),
            python_minor: Some(7),
            pyc_magic: Some(0x0d42),
            payload_offset_in_payload: 16,
            payload_size_in_payload: 0,
            iv: None,
            raw_header: Vec::new(),
            confidence: DetectionConfidence::High,
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn detect_only_when_no_runtime() {
        let outcome: VersionedOutcome =
            run(&[], &dummy_detection(), None, &UnpackConfig::default()).unwrap();
        assert_eq!(outcome.status, DecryptStatus::DetectOnly);
    }

    #[test]
    fn strict_without_runtime_errors() {
        let cfg: UnpackConfig = UnpackConfig {
            strict: true,
            ..UnpackConfig::default()
        };
        let err: Error = run(&[], &dummy_detection(), None, &cfg).unwrap_err();
        assert!(matches!(err, Error::RuntimeNotFound { .. }));
    }
}
