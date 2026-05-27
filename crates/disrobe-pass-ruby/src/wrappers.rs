use serde::{Deserialize, Serialize};

use crate::detect::{OCRA_MARKER, RUBY2EXE_MARKER};
use crate::error::{Result, RubyError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WrapperKind {
    Ruby2Exe,
    Ocra,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrapperExtract {
    pub kind: WrapperKind,
    pub marker_offset: u32,
    pub embedded_payload_offset: u32,
    pub embedded_payload_len: u32,
    pub container_format: String,
}

pub(crate) fn extract(bytes: &[u8]) -> Result<WrapperExtract> {
    let (kind, marker_offset): (WrapperKind, usize) =
        if let Some(o) = find_window(bytes, RUBY2EXE_MARKER) {
            (WrapperKind::Ruby2Exe, o)
        } else if let Some(o) = find_window(bytes, OCRA_MARKER) {
            (WrapperKind::Ocra, o)
        } else {
            return Err(RubyError::Ruby2ExeNoSignature);
        };
    let container: &str = if bytes.starts_with(b"MZ") {
        "pe"
    } else if bytes.starts_with(b"\x7FELF") {
        "elf"
    } else {
        "unknown"
    };
    let payload_offset: usize = marker_offset.saturating_add(match kind {
        WrapperKind::Ruby2Exe => RUBY2EXE_MARKER.len(),
        WrapperKind::Ocra => OCRA_MARKER.len(),
    });
    let payload_len: usize = bytes.len().saturating_sub(payload_offset);
    Ok(WrapperExtract {
        kind,
        marker_offset: u32::try_from(marker_offset).unwrap_or(u32::MAX),
        embedded_payload_offset: u32::try_from(payload_offset).unwrap_or(u32::MAX),
        embedded_payload_len: u32::try_from(payload_len).unwrap_or(u32::MAX),
        container_format: container.to_owned(),
    })
}

#[inline]
fn find_window(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ruby2exe() {
        let mut bytes: Vec<u8> = b"MZ".to_vec();
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(RUBY2EXE_MARKER);
        bytes.extend_from_slice(b"payload-bytes-here");
        let w: WrapperExtract = extract(&bytes).expect("extract");
        assert_eq!(w.kind, WrapperKind::Ruby2Exe);
        assert_eq!(w.embedded_payload_len, 18);
        assert_eq!(w.container_format, "pe");
    }

    #[test]
    fn extracts_ocra() {
        let mut bytes: Vec<u8> = b"MZ".to_vec();
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(OCRA_MARKER);
        bytes.extend_from_slice(b"payload");
        let w: WrapperExtract = extract(&bytes).expect("extract");
        assert_eq!(w.kind, WrapperKind::Ocra);
        assert_eq!(w.embedded_payload_len, 7);
    }

    #[test]
    fn rejects_no_signature() {
        let err: RubyError = extract(b"MZ\x00\x00\x00").expect_err("none");
        assert!(matches!(err, RubyError::Ruby2ExeNoSignature));
    }
}
