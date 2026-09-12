use crate::detect::{
    Detection, DetectionConfidence, ProtectionKind, PyarmorVersion, detect_from_wrapper,
};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperMagic {
    Py8Or9,
    PyArmor6Or7,
    LegacyV3,
    LegacyV4,
    LegacyV5,
}

impl WrapperMagic {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Py8Or9 => "PY (v8/v9, AES-CTR initial=2)",
            Self::PyArmor6Or7 => "PYARMOR (v6/v7, AES-CTR initial=2)",
            Self::LegacyV3 => "legacy v3 (AES-128-CTR, RSA-wrapped key, static wall)",
            Self::LegacyV4 => "legacy v4 (AES-128-CTR, RSA-wrapped key, static wall)",
            Self::LegacyV5 => "legacy v5 (AES-128-CTR, RSA-wrapped key, static wall)",
        }
    }
}

pub fn sniff(bytes: &[u8]) -> Result<WrapperMagic> {
    if bytes.len() >= 8 && &bytes[..2] == b"PY" && bytes[2..8].iter().all(u8::is_ascii_digit) {
        return Ok(WrapperMagic::Py8Or9);
    }
    if bytes.len() >= 8 && &bytes[..7] == b"PYARMOR" && bytes[7] == 0 {
        return Ok(WrapperMagic::PyArmor6Or7);
    }
    if let Some(first) = bytes.first() {
        match *first {
            0x01 => return Ok(WrapperMagic::LegacyV3),
            0x02 => return Ok(WrapperMagic::LegacyV4),
            0x05 => return Ok(WrapperMagic::LegacyV5),
            _ => {}
        }
    }
    Err(Error::NotPyarmor)
}

pub(crate) fn detect_payload(bytes: &[u8]) -> Result<Detection> {
    if bytes.len() >= 8 && &bytes[..2] == b"PY" && bytes[2..8].iter().all(u8::is_ascii_digit) {
        return parse_v8v9_facts(bytes);
    }
    if bytes.len() >= 8 && &bytes[..7] == b"PYARMOR" && bytes[7] == 0 {
        return parse_v6v7_facts(bytes);
    }
    if let Some(first) = bytes.first() {
        match *first {
            0x01 => {
                return Ok(legacy_facts(bytes, PyarmorVersion::V3, *first));
            }
            0x02 => {
                return Ok(legacy_facts(bytes, PyarmorVersion::V4, *first));
            }
            0x05 => {
                return Ok(legacy_facts(bytes, PyarmorVersion::V5, *first));
            }
            _ => {}
        }
    }
    Err(Error::NotPyarmor)
}

pub fn detect_from_wrapper_text(text: &str) -> Result<(Detection, Vec<u8>)> {
    detect_from_wrapper(text)
}

fn parse_v8v9_facts(payload: &[u8]) -> Result<Detection> {
    if payload.len() < 64 {
        return Err(Error::HeaderTruncated {
            need: 64,
            got: payload.len(),
        });
    }
    let serial: String = core::str::from_utf8(&payload[2..8])
        .unwrap_or("000000")
        .to_owned();
    let (version, confidence): (PyarmorVersion, DetectionConfidence) =
        crate::detect::classify_version_from_serial(&serial);
    let python_major: u8 = payload[9];
    let python_minor: u8 = payload[10];
    let pyc_magic: u16 = u16::from_le_bytes([payload[12], payload[13]]);
    let protection: ProtectionKind = match payload[20] {
        0x08 => ProtectionKind::Standard,
        0x09 => ProtectionKind::Bcc,
        _ => ProtectionKind::Unknown,
    };
    let cipher_offset: usize =
        u32::from_le_bytes([payload[28], payload[29], payload[30], payload[31]]) as usize;
    let cipher_size: usize =
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
        payload_offset_in_payload: cipher_offset,
        payload_size_in_payload: cipher_size,
        iv: Some(iv),
        raw_header: payload[..64.min(payload.len())].to_vec(),
        confidence,
        diagnostics: Vec::new(),
    })
}

fn parse_v6v7_facts(payload: &[u8]) -> Result<Detection> {
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

fn legacy_facts(payload: &[u8], version: PyarmorVersion, lead_byte: u8) -> Detection {
    let header_window: &[u8] = &payload[..payload.len().min(64)];
    Detection {
        version,
        protection: ProtectionKind::Standard,
        serial: None,
        python_major: None,
        python_minor: None,
        pyc_magic: None,
        payload_offset_in_payload: 0,
        payload_size_in_payload: payload.len(),
        iv: None,
        raw_header: header_window.to_vec(),
        confidence: DetectionConfidence::Low,
        diagnostics: vec![format!(
            "DR-PYARM-INFO: legacy {version:?} wrapper (leading byte 0x{lead_byte:02x}); AES-128-CTR code object, key RSA-wrapped in capsule (static decryption is an information-theoretic wall)"
        )],
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sniff_v8() {
        let bytes: &[u8] = b"PY008106\x00\x00\x00";
        assert_eq!(sniff(bytes).unwrap(), WrapperMagic::Py8Or9);
    }

    #[test]
    fn sniff_v9() {
        let bytes: &[u8] = b"PY009070\x00\x00\x00";
        assert_eq!(sniff(bytes).unwrap(), WrapperMagic::Py8Or9);
    }

    #[test]
    fn sniff_v6v7() {
        let bytes: &[u8] = b"PYARMOR\x00\x00\x00";
        assert_eq!(sniff(bytes).unwrap(), WrapperMagic::PyArmor6Or7);
    }

    #[test]
    fn sniff_legacy_v3() {
        let bytes: &[u8] = &[0x01u8, 0u8, 0u8, 0u8];
        assert_eq!(sniff(bytes).unwrap(), WrapperMagic::LegacyV3);
    }

    #[test]
    fn sniff_garbage() {
        let bytes: &[u8] = &[0xffu8, 0xff, 0xff, 0xff];
        assert!(sniff(bytes).is_err());
    }

    #[test]
    fn detect_payload_v8() {
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes[..8].copy_from_slice(b"PY008106");
        bytes[9] = 3;
        bytes[10] = 12;
        bytes[20] = 0x08;
        let det: Detection = detect_payload(&bytes).unwrap();
        assert_eq!(det.version, PyarmorVersion::V8);
        assert_eq!(det.python_major, Some(3));
        assert_eq!(det.python_minor, Some(12));
    }

    #[test]
    fn detect_payload_v9_bcc() {
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes[..8].copy_from_slice(b"PY009070");
        bytes[9] = 3;
        bytes[10] = 13;
        bytes[20] = 0x09;
        let det: Detection = detect_payload(&bytes).unwrap();
        assert_eq!(det.version, PyarmorVersion::V9);
        assert_eq!(det.protection, ProtectionKind::Bcc);
    }
}
