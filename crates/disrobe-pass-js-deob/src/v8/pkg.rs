use serde::{Deserialize, Serialize};

const PKG_PRELUDE_MARKER: &[u8] = b"PAYLOAD_POSITION";
const PKG_LEGACY_MARKER: &[u8] = b"this[\"_PAYLOAD_POSITION_\"]";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkgLocation {
    pub payload_offset: u64,
    pub payload_size: u64,
    pub marker_offset: u64,
    pub legacy: bool,
}

#[must_use]
pub fn detect_pkg_payload(bytes: &[u8]) -> Option<PkgLocation> {
    let (marker_off, legacy): (usize, bool) = find_marker(bytes)?;
    let suffix: &[u8] = &bytes[bytes.len().saturating_sub(32)..];
    if suffix.len() < 16 {
        return None;
    }
    let payload_size: u64 = u64::from_le_bytes([
        suffix[suffix.len() - 16],
        suffix[suffix.len() - 15],
        suffix[suffix.len() - 14],
        suffix[suffix.len() - 13],
        suffix[suffix.len() - 12],
        suffix[suffix.len() - 11],
        suffix[suffix.len() - 10],
        suffix[suffix.len() - 9],
    ]);
    let payload_offset_raw: u64 = u64::from_le_bytes([
        suffix[suffix.len() - 8],
        suffix[suffix.len() - 7],
        suffix[suffix.len() - 6],
        suffix[suffix.len() - 5],
        suffix[suffix.len() - 4],
        suffix[suffix.len() - 3],
        suffix[suffix.len() - 2],
        suffix[suffix.len() - 1],
    ]);
    let total_len: u64 = bytes.len() as u64;
    let payload_offset: u64 = if payload_offset_raw < total_len {
        payload_offset_raw
    } else {
        total_len.saturating_sub(payload_size).saturating_sub(16)
    };
    Some(PkgLocation {
        payload_offset,
        payload_size,
        marker_offset: marker_off as u64,
        legacy,
    })
}

fn find_marker(bytes: &[u8]) -> Option<(usize, bool)> {
    if let Some(i) = find_subslice(bytes, PKG_LEGACY_MARKER) {
        return Some((i, true));
    }
    find_subslice(bytes, PKG_PRELUDE_MARKER).map(|i: usize| (i, false))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_pkg(payload: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; 1024];
        let marker: &[u8] = PKG_PRELUDE_MARKER;
        let marker_off: usize = 200;
        out[marker_off..marker_off + marker.len()].copy_from_slice(marker);
        let payload_off: u64 = 512;
        let payload_size: u64 = payload.len() as u64;
        let payload_off_usize: usize = usize::try_from(payload_off).unwrap();
        out[payload_off_usize..payload_off_usize + payload.len()].copy_from_slice(payload);
        out.extend_from_slice(&payload_size.to_le_bytes());
        out.extend_from_slice(&payload_off.to_le_bytes());
        out
    }

    #[test]
    fn detects_pkg_payload_marker_and_suffix() {
        let payload: &[u8] = b"module.exports = function () { return 42; };";
        let bytes: Vec<u8> = synth_pkg(payload);
        let loc: PkgLocation = detect_pkg_payload(&bytes).expect("pkg location");
        assert!(!loc.legacy);
        assert_eq!(loc.payload_size, payload.len() as u64);
        assert_eq!(loc.payload_offset, 512);
        assert_eq!(loc.marker_offset, 200);
    }

    #[test]
    fn legacy_marker_detection_flag_set() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        let marker: &[u8] = PKG_LEGACY_MARKER;
        bytes[100..100 + marker.len()].copy_from_slice(marker);
        bytes.extend_from_slice(&8u64.to_le_bytes());
        bytes.extend_from_slice(&200u64.to_le_bytes());
        let loc: PkgLocation = detect_pkg_payload(&bytes).expect("pkg");
        assert!(loc.legacy);
    }

    #[test]
    fn returns_none_when_no_marker() {
        assert!(detect_pkg_payload(&[0u8; 1024]).is_none());
    }
}
