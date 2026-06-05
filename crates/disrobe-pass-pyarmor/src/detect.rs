use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyarmorVersion {
    V3,
    V4,
    V5,
    V6,
    V7,
    V8,
    V9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionKind {
    Standard,
    SuperMode,
    Bcc,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub version: PyarmorVersion,
    pub protection: ProtectionKind,
    pub serial: Option<String>,
    pub python_major: Option<u8>,
    pub python_minor: Option<u8>,
    pub pyc_magic: Option<u16>,
    pub payload_offset_in_payload: usize,
    pub payload_size_in_payload: usize,
    pub iv: Option<Vec<u8>>,
    pub raw_header: Vec<u8>,
    pub confidence: DetectionConfidence,
    pub diagnostics: Vec<String>,
}

const V8_V9_PREFIX: &[u8; 2] = b"PY";
const V6_V7_PREFIX: &[u8; 7] = b"PYARMOR";
const LEGACY_MODE_V3_DES: u8 = 0x01;
const LEGACY_MODE_V4_MIXED: u8 = 0x02;
const LEGACY_MODE_V5_AES: u8 = 0x05;

fn detect(payload: &[u8]) -> Result<Detection> {
    if payload.len() >= 8
        && &payload[..2] == V8_V9_PREFIX
        && payload[2..8].iter().all(u8::is_ascii_digit)
    {
        return parse_v8v9(payload);
    }
    if payload.len() >= 8 && &payload[..7] == V6_V7_PREFIX && payload[7] == 0 {
        return parse_v6v7(payload);
    }
    if let Some(det) = try_parse_legacy(payload) {
        return Ok(det);
    }
    Err(Error::NotPyarmor)
}

fn try_parse_legacy(payload: &[u8]) -> Option<Detection> {
    if payload.is_empty() {
        return None;
    }
    let mode_byte: u8 = payload[0];
    let version: PyarmorVersion = match mode_byte {
        LEGACY_MODE_V3_DES => PyarmorVersion::V3,
        LEGACY_MODE_V4_MIXED => PyarmorVersion::V4,
        LEGACY_MODE_V5_AES => PyarmorVersion::V5,
        _ => return None,
    };
    if payload.len() < 16 {
        return None;
    }
    let header_window: &[u8] = &payload[..payload.len().min(64)];
    let diagnostic: String = format!(
        "DR-PYARM-INFO: detected probable PyArmor {version:?} wrapper (legacy mode byte 0x{mode_byte:02x}); no real-world sample corpus available; decryption not implemented for legacy DES/early-AES era"
    );
    Some(Detection {
        version,
        protection: ProtectionKind::Standard,
        serial: None,
        python_major: None,
        python_minor: None,
        pyc_magic: None,
        payload_offset_in_payload: 1,
        payload_size_in_payload: payload.len().saturating_sub(1),
        iv: None,
        raw_header: header_window.to_vec(),
        confidence: DetectionConfidence::Low,
        diagnostics: vec![diagnostic],
    })
}

fn parse_v8v9(payload: &[u8]) -> Result<Detection> {
    if payload.len() < 64 {
        return Err(Error::HeaderTruncated {
            need: 64,
            got: payload.len(),
        });
    }
    let serial: String = core::str::from_utf8(&payload[2..8])
        .unwrap_or("000000")
        .to_owned();
    let (version, confidence): (PyarmorVersion, DetectionConfidence) = match serial.as_bytes() {
        s if s.starts_with(b"008") => (PyarmorVersion::V8, DetectionConfidence::High),
        s if s.starts_with(b"009") => (PyarmorVersion::V9, DetectionConfidence::High),
        _ => (PyarmorVersion::V9, DetectionConfidence::Medium),
    };
    let python_major: u8 = payload[9];
    let python_minor: u8 = payload[10];
    let pyc_magic: u16 = u16::from_le_bytes([payload[12], payload[13]]);
    let protection: ProtectionKind = match payload[20] {
        0x08 => ProtectionKind::Standard,
        0x09 => ProtectionKind::Bcc,
        _ => ProtectionKind::Unknown,
    };

    let ciphertext_offset: usize =
        u32::from_le_bytes([payload[28], payload[29], payload[30], payload[31]]) as usize;
    let ciphertext_size: usize =
        u32::from_le_bytes([payload[32], payload[33], payload[34], payload[35]]) as usize;

    let mut iv: Vec<u8> = Vec::with_capacity(12);
    iv.extend_from_slice(&payload[36..40]);
    iv.extend_from_slice(&payload[44..52]);

    Ok(Detection {
        version,
        protection,
        serial: Some(serial),
        python_major: Some(python_major),
        python_minor: Some(python_minor),
        pyc_magic: Some(pyc_magic),
        payload_offset_in_payload: ciphertext_offset,
        payload_size_in_payload: ciphertext_size,
        iv: Some(iv),
        raw_header: payload[..64.min(payload.len())].to_vec(),
        confidence,
        diagnostics: Vec::new(),
    })
}

fn parse_v6v7(payload: &[u8]) -> Result<Detection> {
    if payload.len() < 20 {
        return Err(Error::HeaderTruncated {
            need: 20,
            got: payload.len(),
        });
    }
    let python_major: u8 = payload[9];
    let python_minor: u8 = payload[10];
    let pyc_magic: u16 = u16::from_le_bytes([payload[12], payload[13]]);

    let version: PyarmorVersion = if python_minor >= 8 {
        PyarmorVersion::V7
    } else {
        PyarmorVersion::V6
    };

    Ok(Detection {
        version,
        protection: ProtectionKind::Standard,
        serial: None,
        python_major: Some(python_major),
        python_minor: Some(python_minor),
        pyc_magic: Some(pyc_magic),
        payload_offset_in_payload: 16,
        payload_size_in_payload: payload.len().saturating_sub(16),
        iv: None,
        raw_header: payload[..20.min(payload.len())].to_vec(),
        confidence: DetectionConfidence::High,
        diagnostics: Vec::new(),
    })
}

pub fn detect_from_wrapper(wrapper_text: &str) -> Result<(Detection, Vec<u8>)> {
    let payload: Vec<u8> = extract_payload_literal(wrapper_text)?;
    let mut det: Detection = detect(&payload)?;
    if has_super_mode_invocation(wrapper_text) {
        det.protection = ProtectionKind::SuperMode;
        det.diagnostics.push(
            "DR-PYARM-INFO: super-mode wrapper detected (calls pyarmor(...) without leading underscores)"
                .to_owned(),
        );
    }
    if wrapper_text.contains("__pyarmor__")
        && matches!(
            det.version,
            PyarmorVersion::V3 | PyarmorVersion::V4 | PyarmorVersion::V5
        )
    {
        det.diagnostics
            .push("DR-PYARM-INFO: legacy __pyarmor__(...) call site found".to_owned());
    }
    Ok((det, payload))
}

fn has_super_mode_invocation(text: &str) -> bool {
    text.split_inclusive('\n').any(|line| {
        let trimmed: &str = line.trim_start();
        trimmed.starts_with("pyarmor(")
            && !trimmed.starts_with("pyarmor_runtime")
            && !trimmed.starts_with("pyarmor_data")
    })
}

fn extract_payload_literal(text: &str) -> Result<Vec<u8>> {
    let start: Option<usize> = text.find("b'").or_else(|| text.find("b\""));
    let start: usize = start.ok_or(Error::PayloadLiteralMissing)?;
    let opener: u8 = text.as_bytes()[start + 1];
    let body_start: usize = start + 2;

    let bytes: &[u8] = text.as_bytes();
    let mut end: usize = body_start;
    while end < bytes.len() {
        if bytes[end] == opener && bytes[end - 1] != b'\\' {
            break;
        }
        end += 1;
    }
    if end == bytes.len() {
        return Err(Error::PayloadLiteralMissing);
    }
    decode_python_bytes(&text[body_start..end])
}

fn decode_python_bytes(s: &str) -> Result<Vec<u8>> {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        if i + 1 >= bytes.len() {
            return Err(Error::HexDecode(i));
        }
        let escape: u8 = bytes[i + 1];
        match escape {
            b'x' => {
                if i + 3 >= bytes.len() {
                    return Err(Error::HexDecode(i));
                }
                let high: u8 = hex_nibble(bytes[i + 2]).ok_or(Error::HexDecode(i))?;
                let low: u8 = hex_nibble(bytes[i + 3]).ok_or(Error::HexDecode(i))?;
                out.push((high << 4) | low);
                i += 4;
            }
            b'n' => {
                out.push(b'\n');
                i += 2;
            }
            b'r' => {
                out.push(b'\r');
                i += 2;
            }
            b't' => {
                out.push(b'\t');
                i += 2;
            }
            b'\\' => {
                out.push(b'\\');
                i += 2;
            }
            b'\'' => {
                out.push(b'\'');
                i += 2;
            }
            b'"' => {
                out.push(b'"');
                i += 2;
            }
            b'0' => {
                out.push(0);
                i += 2;
            }
            b'a' => {
                out.push(7);
                i += 2;
            }
            b'b' => {
                out.push(8);
                i += 2;
            }
            b'f' => {
                out.push(12);
                i += 2;
            }
            b'v' => {
                out.push(11);
                i += 2;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_v8_header() {
        let mut payload: Vec<u8> = vec![0u8; 64];
        payload[..8].copy_from_slice(b"PY008106");
        payload[9] = 3;
        payload[10] = 12;
        payload[20] = 0x08;
        let det: Detection = detect(&payload).unwrap();
        assert_eq!(det.version, PyarmorVersion::V8);
        assert_eq!(det.protection, ProtectionKind::Standard);
        assert_eq!(det.serial.as_deref(), Some("008106"));
        assert_eq!(det.python_major, Some(3));
        assert_eq!(det.python_minor, Some(12));
    }

    #[test]
    fn detect_v9_bcc_header() {
        let mut payload: Vec<u8> = vec![0u8; 64];
        payload[..8].copy_from_slice(b"PY009070");
        payload[9] = 3;
        payload[10] = 13;
        payload[20] = 0x09;
        let det: Detection = detect(&payload).unwrap();
        assert_eq!(det.version, PyarmorVersion::V9);
        assert_eq!(det.protection, ProtectionKind::Bcc);
    }

    #[test]
    fn detect_v6_header() {
        let mut payload: Vec<u8> = vec![0u8; 24];
        payload[..8].copy_from_slice(b"PYARMOR\0");
        payload[9] = 3;
        payload[10] = 9;
        let det: Detection = detect(&payload).unwrap();
        assert_eq!(det.version, PyarmorVersion::V7);
        assert_eq!(det.python_minor, Some(9));
    }

    #[test]
    fn detect_nonpyarmor() {
        let err: Error = detect(b"random garbage bytes \x00\x01\x02").unwrap_err();
        assert!(matches!(err, Error::NotPyarmor));
    }

    #[test]
    fn extract_payload_from_wrapper() {
        let text: &str = r"
from pyarmor_runtime_000000 import __pyarmor__
__pyarmor__(__name__, __file__, b'PY000000\x00\x03\x0e\x00')
";
        let bytes: Vec<u8> = extract_payload_literal(text).unwrap();
        assert_eq!(&bytes[..2], b"PY");
        assert_eq!(&bytes[..8], b"PY000000");
        assert_eq!(bytes[9], 3);
        assert_eq!(bytes[10], 14);
    }

    #[test]
    fn detect_legacy_v3_mode_byte() {
        let mut payload: Vec<u8> = vec![0u8; 32];
        payload[0] = LEGACY_MODE_V3_DES;
        let det: Detection = detect(&payload).unwrap();
        assert_eq!(det.version, PyarmorVersion::V3);
        assert_eq!(det.confidence, DetectionConfidence::Low);
        assert!(!det.diagnostics.is_empty());
        assert!(det.diagnostics[0].contains("V3"));
    }

    #[test]
    fn detect_legacy_v4_mode_byte() {
        let mut payload: Vec<u8> = vec![0u8; 32];
        payload[0] = LEGACY_MODE_V4_MIXED;
        let det: Detection = detect(&payload).unwrap();
        assert_eq!(det.version, PyarmorVersion::V4);
        assert_eq!(det.confidence, DetectionConfidence::Low);
    }

    #[test]
    fn detect_legacy_v5_mode_byte() {
        let mut payload: Vec<u8> = vec![0u8; 32];
        payload[0] = LEGACY_MODE_V5_AES;
        let det: Detection = detect(&payload).unwrap();
        assert_eq!(det.version, PyarmorVersion::V5);
        assert_eq!(det.confidence, DetectionConfidence::Low);
        assert!(det.diagnostics.iter().any(|d| d.contains("DES/early-AES")));
    }

    #[test]
    fn detect_v6_v7_v8_confidence_is_high() {
        let mut p: Vec<u8> = vec![0u8; 64];
        p[..8].copy_from_slice(b"PY008106");
        p[9] = 3;
        p[10] = 12;
        p[20] = 0x08;
        let det: Detection = detect(&p).unwrap();
        assert_eq!(det.confidence, DetectionConfidence::High);
    }

    #[test]
    fn super_mode_invocation_is_flagged() {
        let mut payload: Vec<u8> = vec![0u8; 64];
        payload[..8].copy_from_slice(b"PY008106");
        payload[9] = 3;
        payload[10] = 9;
        payload[20] = 0x08;
        let escaped: String =
            payload
                .iter()
                .fold(String::with_capacity(payload.len() * 4), |mut s, b| {
                    use core::fmt::Write as _;
                    let _ = write!(s, "\\x{b:02x}");
                    s
                });
        let text: String = format!(
            "from pyarmor_runtime_000000 import pyarmor\npyarmor(__name__, __file__, b'{escaped}')\n"
        );
        let (det, _): (Detection, Vec<u8>) = detect_from_wrapper(&text).unwrap();
        assert_eq!(det.protection, ProtectionKind::SuperMode);
        assert!(det.diagnostics.iter().any(|d| d.contains("super-mode")));
    }

    #[test]
    fn pyarmor_runtime_import_not_misclassified_as_super() {
        let mut payload: Vec<u8> = vec![0u8; 64];
        payload[..8].copy_from_slice(b"PY008106");
        payload[9] = 3;
        payload[10] = 9;
        payload[20] = 0x08;
        let escaped: String =
            payload
                .iter()
                .fold(String::with_capacity(payload.len() * 4), |mut s, b| {
                    use core::fmt::Write as _;
                    let _ = write!(s, "\\x{b:02x}");
                    s
                });
        let text: String = format!(
            "from pyarmor_runtime_000000 import __pyarmor__\n__pyarmor__(__name__, __file__, b'{escaped}')\n"
        );
        let (det, _): (Detection, Vec<u8>) = detect_from_wrapper(&text).unwrap();
        assert_eq!(det.protection, ProtectionKind::Standard);
    }

    #[test]
    fn legacy_too_short_returns_not_pyarmor() {
        let payload: Vec<u8> = vec![LEGACY_MODE_V3_DES, 0, 0];
        let err: Error = detect(&payload).unwrap_err();
        assert!(matches!(err, Error::NotPyarmor));
    }
}
