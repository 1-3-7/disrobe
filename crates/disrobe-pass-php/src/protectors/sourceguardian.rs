use memchr::memmem;

use crate::error::{Error, Result};
use crate::protectors::{ProtectorDetection, ProtectorFamily, extract_envelope_strings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceGuardianEra {
    Legacy,
    Modern,
}

impl SourceGuardianEra {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Legacy => "sg-legacy",
            Self::Modern => "sg-modern",
        }
    }
}

const LEGACY_MARKERS: &[&[u8]] = &[
    b"<?php\n//SGV1",
    b"<?php\n//SGV2",
    b"<?php //SGV1",
    b"<?php //SGV2",
];

const MODERN_MARKERS: &[&[u8]] = &[
    b"<?php @SourceGuardian;",
    b"// PHP SourceGuardian Loader v",
    b"<?php\n//SourceGuardian",
    b"sg_load(",
];

const ENVELOPE_STRING_MIN: usize = 5;

pub fn detect(bytes: &[u8]) -> Option<(SourceGuardianEra, usize)> {
    let legacy: Option<(SourceGuardianEra, usize)> = LEGACY_MARKERS
        .iter()
        .filter_map(|needle: &&[u8]| {
            memmem::find(bytes, needle).map(|idx: usize| (SourceGuardianEra::Legacy, idx))
        })
        .min_by_key(|(_, idx): &(SourceGuardianEra, usize)| *idx);
    let modern: Option<(SourceGuardianEra, usize)> = MODERN_MARKERS
        .iter()
        .filter_map(|needle: &&[u8]| {
            memmem::find(bytes, needle).map(|idx: usize| (SourceGuardianEra::Modern, idx))
        })
        .min_by_key(|(_, idx): &(SourceGuardianEra, usize)| *idx);
    match (legacy, modern) {
        (Some(l), Some(m)) => Some(if l.1 <= m.1 { l } else { m }),
        (Some(l), None) => Some(l),
        (None, Some(m)) => Some(m),
        (None, None) => None,
    }
}

pub fn analyze(bytes: &[u8]) -> Result<ProtectorDetection> {
    let Some((era, marker_offset)): Option<(SourceGuardianEra, usize)> = detect(bytes) else {
        return Err(Error::SourceGuardianBadHeader("no SG marker"));
    };
    let payload_offset: Option<usize> = bytes[marker_offset..]
        .iter()
        .position(|&b: &u8| b == b'\n')
        .map(|p: usize| marker_offset + p + 1)
        .filter(|off: &usize| *off < bytes.len());
    let payload_len: usize = payload_offset.map_or(0, |off: usize| bytes.len() - off);
    let recovered_strings: Vec<String> = extract_envelope_strings(
        payload_offset.map_or(&bytes[marker_offset..], |off: usize| &bytes[off..]),
        ENVELOPE_STRING_MIN,
    );

    let mut detection: ProtectorDetection = ProtectorDetection::new(
        ProtectorFamily::SourceGuardian,
        era.label().to_string(),
        marker_offset,
        true,
    );
    detection.payload_offset = payload_offset;
    detection.payload_len = payload_len;
    detection.recovered_strings = recovered_strings;
    Ok(detection)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_legacy_sgv_banner() {
        let blob: &[u8] = b"<?php //SGV1\nencrypted-payload\n";
        let (era, _off): (SourceGuardianEra, usize) = detect(blob).expect("era");
        assert_eq!(era, SourceGuardianEra::Legacy);
    }

    #[test]
    fn analyze_modern_is_detect_only() {
        let mut blob: Vec<u8> = b"<?php @SourceGuardian;\n".to_vec();
        blob.extend_from_slice(b"opaque encrypted opcode stream behind the ixed loader");
        let detection: ProtectorDetection = analyze(&blob).expect("analyze");
        assert_eq!(detection.family, ProtectorFamily::SourceGuardian);
        assert_eq!(detection.version_label, "sg-modern");
        assert!(detection.wall_reason.contains("ixed"));
    }

    #[test]
    fn missing_marker_is_error() {
        assert!(analyze(b"<?php echo 'not sg';").is_err());
    }
}
