use crate::detect::{Detection, DetectionConfidence, PyarmorVersion};
use crate::error::{Error, Result};

const PYARMOR_HEADER_MAGIC: &[u8; 8] = b"PYARMOR\x00";
const PYARMOR_HEADER_LEN: usize = 64;
const HEADER_DATA_OFFSET_FIELD: usize = 0x1C;
const HEADER_DATA_SIZE_FIELD: usize = 0x20;
const HEADER_KEY_REGION: core::ops::Range<usize> = 36..64;
const MIN_STREAM_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyFormat {
    BareCiphertext,
    PyarmorHeader,
}

impl LegacyFormat {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BareCiphertext => {
                "bare-ciphertext (PyArmor 3.x/4.x mode-8: no header, raw AES-128-CTR blob)"
            }
            Self::PyarmorHeader => {
                "PYARMOR\\0 header (PyArmor 5.x: 64-byte header, zeroed key region)"
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LegacyAnalysis {
    pub version: PyarmorVersion,
    pub format: LegacyFormat,
    pub ciphertext_offset: usize,
    pub ciphertext_len: usize,
    pub stream_len_plausible: bool,
    pub key_region_present: bool,
    pub confidence: DetectionConfidence,
    pub wall_reason: String,
    pub diagnostics: Vec<String>,
}

impl LegacyAnalysis {
    #[inline]
    #[must_use]
    #[allow(
        clippy::unused_self,
        reason = "intentional invariant: legacy v3/v4/v5 code objects are never statically recoverable (AES-CTR key RSA-wrapped in capsule, absent from artifact); method form documents this at every call site"
    )]
    pub const fn is_statically_recoverable(&self) -> bool {
        false
    }
}

pub(crate) fn analyze_legacy(payload: &[u8], detection: &Detection) -> Result<LegacyAnalysis> {
    if payload.is_empty() {
        return Err(Error::HeaderTruncated { need: 1, got: 0 });
    }
    let version: PyarmorVersion = detection.version;

    let has_pyarmor_header: bool =
        payload.len() >= PYARMOR_HEADER_LEN && &payload[..8] == PYARMOR_HEADER_MAGIC;

    let (format, ciphertext_offset, ciphertext_len, key_region_present): (
        LegacyFormat,
        usize,
        usize,
        bool,
    ) = if has_pyarmor_header {
        let data_offset: usize = read_u32_le(payload, HEADER_DATA_OFFSET_FIELD) as usize;
        let data_size: usize = read_u32_le(payload, HEADER_DATA_SIZE_FIELD) as usize;
        let offset: usize = if data_offset >= PYARMOR_HEADER_LEN && data_offset <= payload.len() {
            data_offset
        } else {
            PYARMOR_HEADER_LEN
        };
        let size: usize = if data_size > 0 {
            let Some(end): Option<usize> = offset.checked_add(data_size) else {
                return Err(Error::HeaderTruncated {
                    need: usize::MAX,
                    got: payload.len(),
                });
            };
            if end > payload.len() {
                return Err(Error::HeaderTruncated {
                    need: end,
                    got: payload.len(),
                });
            }
            data_size
        } else {
            payload.len().saturating_sub(offset)
        };
        let key_region_nonzero: bool = payload
            .get(HEADER_KEY_REGION)
            .is_some_and(|region: &[u8]| region.iter().any(|&b: &u8| b != 0));
        (
            LegacyFormat::PyarmorHeader,
            offset,
            size,
            key_region_nonzero,
        )
    } else {
        (LegacyFormat::BareCiphertext, 0, payload.len(), false)
    };

    let stream_len_plausible: bool = ciphertext_len >= MIN_STREAM_LEN;

    let wall_reason: String = format!(
        "PyArmor {version:?} {fmt}: code-object bytecode is AES-128-CTR encrypted (stream cipher; ciphertext is not block-aligned, key fixed per-capsule and deterministic across builds). The decryption key is RSA-wrapped inside the capsule (product.key / pyshield.key / pyshield.lic) and is recoverable only with the obfuscator's secret RSA private key, which is never distributed alongside obfuscated scripts. The runtime derives the key in the closed-source _pytransform native extension at import time, decrypting each code object transiently under __armor_enter__. The static artifact therefore lacks the key material entirely: this is an information-theoretic wall, not a missing implementation. Recovery requires the original capsule's private key or a runtime dump under the matching Python build.",
        fmt = format.label()
    );

    let mut diagnostics: Vec<String> = vec![
        format!(
            "DR-PYARM-LEGACY: {version:?} static analysis: format={}, ciphertext_offset={ciphertext_offset}, ciphertext_len={ciphertext_len}, stream_len_plausible={stream_len_plausible}",
            format.label()
        ),
        "DR-PYARM-LEGACY: cipher identified as AES-128-CTR; key RSA-wrapped in capsule, absent from distributed artifact".to_owned(),
    ];
    if has_pyarmor_header && !key_region_present {
        diagnostics.push(
            "DR-PYARM-LEGACY: header key region [36..64] is all-zero (PyArmor 5.x stores wrapped key in pytransform.key, not inline)".to_owned(),
        );
    }
    diagnostics.extend(detection.diagnostics.iter().cloned());

    Ok(LegacyAnalysis {
        version,
        format,
        ciphertext_offset,
        ciphertext_len,
        stream_len_plausible,
        key_region_present,
        confidence: detection.confidence,
        wall_reason,
        diagnostics,
    })
}

#[inline]
fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    buf.get(offset..offset + 4)
        .map_or(0, |s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::detect::ProtectionKind;

    fn detection(version: PyarmorVersion) -> Detection {
        Detection {
            version,
            protection: ProtectionKind::Standard,
            serial: None,
            python_major: Some(3),
            python_minor: Some(7),
            pyc_magic: None,
            payload_offset_in_payload: 0,
            payload_size_in_payload: 0,
            iv: None,
            raw_header: Vec::new(),
            confidence: DetectionConfidence::Low,
            diagnostics: Vec::new(),
        }
    }

    fn real_v5_header() -> Vec<u8> {
        let mut p: Vec<u8> = vec![0u8; PYARMOR_HEADER_LEN];
        p[..8].copy_from_slice(PYARMOR_HEADER_MAGIC);
        p[9] = 3;
        p[10] = 7;
        p[12..16].copy_from_slice(&[0x42, 0x0d, 0x0d, 0x0a]);
        p[HEADER_DATA_OFFSET_FIELD..HEADER_DATA_OFFSET_FIELD + 4]
            .copy_from_slice(&0x40u32.to_le_bytes());
        p[HEADER_DATA_SIZE_FIELD..HEADER_DATA_SIZE_FIELD + 4]
            .copy_from_slice(&0x20u32.to_le_bytes());
        p.extend_from_slice(&[0x11u8; 0x20]);
        p
    }

    #[test]
    fn empty_payload_is_truncated() {
        let err: Error = analyze_legacy(&[], &detection(PyarmorVersion::V3)).unwrap_err();
        assert!(matches!(err, Error::HeaderTruncated { need: 1, got: 0 }));
    }

    #[test]
    fn bare_ciphertext_v3_is_no_header() {
        let payload: Vec<u8> = vec![0xe5u8; 96];
        let a: LegacyAnalysis = analyze_legacy(&payload, &detection(PyarmorVersion::V3)).unwrap();
        assert_eq!(a.format, LegacyFormat::BareCiphertext);
        assert_eq!(a.ciphertext_offset, 0);
        assert_eq!(a.ciphertext_len, 96);
        assert!(a.stream_len_plausible);
        assert!(!a.key_region_present);
        assert!(!a.is_statically_recoverable());
    }

    #[test]
    fn pyarmor_header_v5_parses_offset_size_and_zero_key_region() {
        let payload: Vec<u8> = real_v5_header();
        let a: LegacyAnalysis = analyze_legacy(&payload, &detection(PyarmorVersion::V5)).unwrap();
        assert_eq!(a.format, LegacyFormat::PyarmorHeader);
        assert_eq!(a.ciphertext_offset, 0x40);
        assert_eq!(a.ciphertext_len, 0x20);
        assert!(
            !a.key_region_present,
            "real PyArmor 5.x zeroes header bytes [36..64]; key lives in pytransform.key"
        );
    }

    #[test]
    fn pyarmor_header_rejects_declared_data_size_past_payload() {
        let mut payload: Vec<u8> = real_v5_header();
        payload[HEADER_DATA_SIZE_FIELD..HEADER_DATA_SIZE_FIELD + 4]
            .copy_from_slice(&0x200u32.to_le_bytes());
        let err: Error = analyze_legacy(&payload, &detection(PyarmorVersion::V5)).unwrap_err();
        assert!(matches!(
            err,
            Error::HeaderTruncated {
                need: 0x240,
                got: 0x60
            }
        ));
    }

    #[test]
    fn pyarmor_header_with_inline_key_region_is_flagged_present() {
        let mut payload: Vec<u8> = real_v5_header();
        for b in &mut payload[HEADER_KEY_REGION] {
            *b = 0xab;
        }
        let a: LegacyAnalysis = analyze_legacy(&payload, &detection(PyarmorVersion::V5)).unwrap();
        assert!(a.key_region_present);
    }

    #[test]
    fn pyarmor_header_v5_detects_zeroed_key_region() {
        let mut payload: Vec<u8> = real_v5_header();
        for b in &mut payload[HEADER_KEY_REGION] {
            *b = 0;
        }
        let a: LegacyAnalysis = analyze_legacy(&payload, &detection(PyarmorVersion::V5)).unwrap();
        assert!(!a.key_region_present);
        assert!(
            a.diagnostics
                .iter()
                .any(|d: &String| d.contains("all-zero"))
        );
    }

    #[test]
    fn wall_reason_names_aes_ctr_and_rsa_wrapped_key() {
        let payload: Vec<u8> = vec![0xe5u8; 64];
        let a: LegacyAnalysis = analyze_legacy(&payload, &detection(PyarmorVersion::V4)).unwrap();
        assert!(a.wall_reason.contains("AES-128-CTR"));
        assert!(a.wall_reason.contains("RSA-wrapped"));
        assert!(a.wall_reason.contains("information-theoretic"));
    }

    #[test]
    fn analysis_is_never_statically_recoverable() {
        for v in [PyarmorVersion::V3, PyarmorVersion::V4, PyarmorVersion::V5] {
            let payload: Vec<u8> = vec![0x22u8; 80];
            let a: LegacyAnalysis = analyze_legacy(&payload, &detection(v)).unwrap();
            assert!(!a.is_statically_recoverable());
        }
    }
}
