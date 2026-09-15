use memchr::memmem;

use crate::error::{Error, Result};
use crate::protectors::{ProtectorDetection, ProtectorFamily, extract_envelope_strings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZendGuardEra {
    Zend2,
    Zend3,
    Zend4,
}

impl ZendGuardEra {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Zend2 => "zend-2",
            Self::Zend3 => "zend-3",
            Self::Zend4 => "zend-4",
        }
    }
}

const ERA_MARKERS: &[(&[u8], ZendGuardEra)] = &[
    (b"<?php @Zend;\n2", ZendGuardEra::Zend2),
    (b"<?php @Zend;\n3", ZendGuardEra::Zend3),
    (b"<?php @Zend;\n4", ZendGuardEra::Zend4),
];

const LOADER_MARKERS: &[&[u8]] = &[b"Zend Optimizer", b"Zend Guard Loader", b"@Zend;"];

const ENVELOPE_STRING_MIN: usize = 5;

pub fn detect(bytes: &[u8]) -> Option<(ZendGuardEra, usize, usize)> {
    ERA_MARKERS
        .iter()
        .filter_map(|(needle, era): &(&[u8], ZendGuardEra)| {
            memmem::find(bytes, needle).map(|idx: usize| (*era, idx, needle.len()))
        })
        .min_by_key(|(_, idx, _): &(ZendGuardEra, usize, usize)| *idx)
}

pub fn detect_loader_only(bytes: &[u8]) -> Option<usize> {
    LOADER_MARKERS
        .iter()
        .filter_map(|needle: &&[u8]| memmem::find(bytes, needle))
        .min()
}

pub fn analyze(bytes: &[u8]) -> Result<ProtectorDetection> {
    let (label, marker_offset, marker_len, confident): (String, usize, usize, bool) =
        if let Some((era, idx, len)) = detect(bytes) {
            (era.label().to_string(), idx, len, true)
        } else if let Some(idx) = detect_loader_only(bytes) {
            ("loader-banner".to_string(), idx, 0, false)
        } else {
            return Err(Error::ZendGuardBadHeader("no Zend Guard marker"));
        };

    let header_start: usize = marker_offset + marker_len;
    let payload_offset: Option<usize> = if header_start < bytes.len() {
        Some(header_start)
    } else {
        None
    };
    let payload_len: usize = payload_offset.map_or(0, |off: usize| bytes.len() - off);
    let recovered_strings: Vec<String> = extract_envelope_strings(
        payload_offset.map_or(&bytes[marker_offset..], |off: usize| &bytes[off..]),
        ENVELOPE_STRING_MIN,
    );

    let mut detection: ProtectorDetection =
        ProtectorDetection::new(ProtectorFamily::ZendGuard, label, marker_offset, confident);
    detection.payload_offset = payload_offset;
    detection.payload_len = payload_len;
    detection.recovered_strings = recovered_strings;
    detection.apply_static_recovery(bytes);
    Ok(detection)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_zend3_marker() {
        let blob: &[u8] = b"<?php @Zend;\n3140\nopaque-encrypted-opcodes";
        let (era, _idx, _len): (ZendGuardEra, usize, usize) = detect(blob).expect("era");
        assert_eq!(era, ZendGuardEra::Zend3);
    }

    #[test]
    fn analyze_is_detect_only() {
        let mut blob: Vec<u8> = b"<?php @Zend;\n4".to_vec();
        blob.extend_from_slice(b"0030encrypted zend opcode stream behind loader");
        let detection: ProtectorDetection = analyze(&blob).expect("analyze");
        assert_eq!(detection.family, ProtectorFamily::ZendGuard);
        assert_eq!(detection.version_label, "zend-4");
        assert!(detection.wall_reason.contains("Zend Optimizer"));
    }

    #[test]
    fn loader_banner_is_low_confidence() {
        let blob: &[u8] = b"<?php /* requires Zend Guard Loader v6 */";
        let detection: ProtectorDetection = analyze(blob).expect("analyze");
        assert!(!detection.confident);
        assert_eq!(detection.version_label, "loader-banner");
    }

    #[test]
    fn missing_marker_is_error() {
        assert!(analyze(b"<?php echo 'not zend';").is_err());
    }
}
