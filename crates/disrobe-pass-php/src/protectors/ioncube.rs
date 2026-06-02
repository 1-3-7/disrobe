use memchr::memmem;

use crate::error::{Error, Result};
use crate::protectors::{ProtectorDetection, ProtectorFamily, extract_envelope_strings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IonCubeEra {
    V4Legacy,
    V6,
    V9,
    V10,
    V11Plus,
}

impl IonCubeEra {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::V4Legacy => "v4-legacy",
            Self::V6 => "v6",
            Self::V9 => "v9",
            Self::V10 => "v10",
            Self::V11Plus => "v11+",
        }
    }
}

const ERA_MARKERS: &[(&[u8], IonCubeEra)] = &[
    (b"//00400", IonCubeEra::V4Legacy),
    (b"//0046", IonCubeEra::V6),
    (b"//004F", IonCubeEra::V9),
    (b"//0080", IonCubeEra::V10),
    (b"//00A0", IonCubeEra::V11Plus),
];

const LOADER_MARKERS: &[&[u8]] = &[b"ioncube_loader", b"ioncube_event_handler", b"The file <b>"];

const ENVELOPE_STRING_MIN: usize = 5;

pub fn detect(bytes: &[u8]) -> Option<(IonCubeEra, usize)> {
    ERA_MARKERS
        .iter()
        .filter_map(|(needle, era): &(&[u8], IonCubeEra)| {
            memmem::find(bytes, needle).map(|idx: usize| (*era, idx))
        })
        .min_by_key(|(_, idx): &(IonCubeEra, usize)| *idx)
}

pub fn detect_loader_only(bytes: &[u8]) -> Option<usize> {
    LOADER_MARKERS
        .iter()
        .filter_map(|needle: &&[u8]| memmem::find(bytes, needle))
        .min()
}

pub fn analyze(bytes: &[u8]) -> Result<ProtectorDetection> {
    let (marker_offset, confident, label): (usize, bool, String) =
        if let Some((era, idx)) = detect(bytes) {
            (idx, true, era.label().to_string())
        } else if let Some(idx) = detect_loader_only(bytes) {
            (idx, false, "loader-call".to_string())
        } else {
            return Err(Error::IonCubeBadHeader("no ionCube marker"));
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

    let mut detection: ProtectorDetection =
        ProtectorDetection::new(ProtectorFamily::IonCube, label, marker_offset, confident);
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
    fn detects_v6_era_marker() {
        let blob: &[u8] = b"<?php //0046\nopaque-encrypted-opcode-bytes-here\n";
        let (era, off): (IonCubeEra, usize) = detect(blob).expect("era");
        assert_eq!(era, IonCubeEra::V6);
        assert!(off > 0);
    }

    #[test]
    fn analyze_is_honest_detect_only_no_source() {
        let mut blob: Vec<u8> = b"<?php //004F\n".to_vec();
        blob.extend_from_slice(b"encrypted Zend opcode payload that we cannot decrypt");
        let detection: ProtectorDetection = analyze(&blob).expect("analyze");
        assert_eq!(detection.family, ProtectorFamily::IonCube);
        assert_eq!(detection.version_label, "v9");
        assert!(detection.confident);
        assert!(detection.payload_offset.is_some());
        assert!(detection.wall_reason.contains("native loader"));
        assert!(
            detection
                .recovered_strings
                .iter()
                .any(|s: &String| s.contains("opcode"))
        );
    }

    #[test]
    fn loader_call_is_low_confidence() {
        let blob: &[u8] = b"<?php if(!extension_loaded('ioncube_loader')){die();}";
        let detection: ProtectorDetection = analyze(blob).expect("analyze");
        assert!(!detection.confident);
        assert_eq!(detection.version_label, "loader-call");
    }

    #[test]
    fn missing_marker_is_error() {
        assert!(analyze(b"<?php echo 'clear text';").is_err());
    }
}
