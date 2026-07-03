use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NineProBindMode {
    None,
    HardwareBound,
    LicenseFileBound,
    NetworkBound,
    ExpirationBound,
    MultiBound,
    Unknown,
}

impl NineProBindMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HardwareBound => "hardware",
            Self::LicenseFileBound => "license-file",
            Self::NetworkBound => "network",
            Self::ExpirationBound => "expiration",
            Self::MultiBound => "multi",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NineProDetection {
    pub is_nine_pro: bool,
    pub bind_mode: NineProBindMode,
    pub bind_flags: u32,
    pub restrict_byte: u8,
    pub expiration_ts: Option<u64>,
    pub bind_markers_found: Vec<String>,
}

const HEADER_RESTRICT_OFFSET: usize = 24;
const HEADER_BIND_FLAGS_OFFSET: usize = 52;
const HEADER_EXPIRATION_OFFSET: usize = 60;
const BIND_FLAG_HARDWARE: u32 = 0x0000_0001;
const BIND_FLAG_LICENSE_FILE: u32 = 0x0000_0002;
const BIND_FLAG_NETWORK: u32 = 0x0000_0004;
const BIND_FLAG_EXPIRATION: u32 = 0x0000_0008;
const NINE_PRO_RESTRICT_SENTINEL: u8 = 0x80;

const PRO_MARKER_STRINGS: &[&[u8]] = &[
    b"__pyarmor_bind__",
    b"__pyarmor_dev__",
    b"__pyarmor_hwid__",
    b"__pyarmor_machine__",
    b"pyarmor.license.lic",
    b"pyarmor.bind.lic",
    b"pyarmor-restrict-mode",
];

pub fn detect_nine_pro(payload: &[u8]) -> NineProDetection {
    if payload.len() < 64 {
        return empty();
    }
    if &payload[..2] != b"PY" || !payload[2..8].iter().all(u8::is_ascii_digit) {
        return empty();
    }
    let serial: &[u8] = &payload[2..8];
    let is_nine_series: bool = serial.starts_with(b"009");

    let restrict_byte: u8 = payload[HEADER_RESTRICT_OFFSET];
    let bind_flags: u32 = u32::from_le_bytes([
        payload[HEADER_BIND_FLAGS_OFFSET],
        payload[HEADER_BIND_FLAGS_OFFSET + 1],
        payload[HEADER_BIND_FLAGS_OFFSET + 2],
        payload[HEADER_BIND_FLAGS_OFFSET + 3],
    ]);

    let expiration_ts: Option<u64> = if bind_flags & BIND_FLAG_EXPIRATION != 0
        && payload.len() >= HEADER_EXPIRATION_OFFSET + 4
    {
        let raw: u32 = u32::from_le_bytes([
            payload[HEADER_EXPIRATION_OFFSET],
            payload[HEADER_EXPIRATION_OFFSET + 1],
            payload[HEADER_EXPIRATION_OFFSET + 2],
            payload[HEADER_EXPIRATION_OFFSET + 3],
        ]);
        if raw == 0 { None } else { Some(u64::from(raw)) }
    } else {
        None
    };

    let bind_markers_found: Vec<String> = scan_pro_markers(payload);
    let header_indicates_pro: bool =
        is_nine_series && (restrict_byte & NINE_PRO_RESTRICT_SENTINEL != 0 || bind_flags != 0);
    let is_nine_pro: bool = header_indicates_pro || !bind_markers_found.is_empty();

    let bind_mode: NineProBindMode = classify(bind_flags, &bind_markers_found, is_nine_pro);

    NineProDetection {
        is_nine_pro,
        bind_mode,
        bind_flags,
        restrict_byte,
        expiration_ts,
        bind_markers_found,
    }
}

const fn empty() -> NineProDetection {
    NineProDetection {
        is_nine_pro: false,
        bind_mode: NineProBindMode::None,
        bind_flags: 0,
        restrict_byte: 0,
        expiration_ts: None,
        bind_markers_found: Vec::new(),
    }
}

fn classify(flags: u32, markers: &[String], is_pro: bool) -> NineProBindMode {
    if !is_pro {
        return NineProBindMode::None;
    }
    let bits: u32 = flags
        & (BIND_FLAG_HARDWARE | BIND_FLAG_LICENSE_FILE | BIND_FLAG_NETWORK | BIND_FLAG_EXPIRATION);
    let count: u32 = bits.count_ones();
    match (count, bits) {
        (0, _) => {
            if markers
                .iter()
                .any(|m| m.contains("bind") || m.contains("hwid"))
            {
                NineProBindMode::HardwareBound
            } else {
                NineProBindMode::Unknown
            }
        }
        (1, BIND_FLAG_HARDWARE) => NineProBindMode::HardwareBound,
        (1, BIND_FLAG_LICENSE_FILE) => NineProBindMode::LicenseFileBound,
        (1, BIND_FLAG_NETWORK) => NineProBindMode::NetworkBound,
        (1, BIND_FLAG_EXPIRATION) => NineProBindMode::ExpirationBound,
        _ => NineProBindMode::MultiBound,
    }
}

fn scan_pro_markers(payload: &[u8]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let head_window_end: usize = payload.len().min(64 * 1024);
    let head: &[u8] = &payload[..head_window_end];
    for marker in PRO_MARKER_STRINGS {
        if find_subslice(head, marker).is_some()
            && let Ok(s) = core::str::from_utf8(marker)
        {
            found.push(s.to_owned());
        }
    }
    found
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn header_with(restrict: u8, flags: u32, exp: u32) -> Vec<u8> {
        let mut p: Vec<u8> = vec![0u8; 64];
        p[..8].copy_from_slice(b"PY009070");
        p[9] = 3;
        p[10] = 14;
        p[20] = 0x08;
        p[HEADER_RESTRICT_OFFSET] = restrict;
        p[HEADER_BIND_FLAGS_OFFSET..HEADER_BIND_FLAGS_OFFSET + 4]
            .copy_from_slice(&flags.to_le_bytes());
        if exp != 0 {
            let len_needed: usize = HEADER_EXPIRATION_OFFSET + 4;
            if p.len() < len_needed {
                p.resize(len_needed, 0);
            }
            p[HEADER_EXPIRATION_OFFSET..HEADER_EXPIRATION_OFFSET + 4]
                .copy_from_slice(&exp.to_le_bytes());
        }
        p
    }

    #[test]
    fn non_v9_returns_not_pro() {
        let mut p: Vec<u8> = vec![0u8; 64];
        p[..8].copy_from_slice(b"PY008106");
        let det: NineProDetection = detect_nine_pro(&p);
        assert!(!det.is_nine_pro);
        assert_eq!(det.bind_mode, NineProBindMode::None);
    }

    #[test]
    fn hardware_bound_header_classified() {
        let p: Vec<u8> = header_with(0x80, BIND_FLAG_HARDWARE, 0);
        let det: NineProDetection = detect_nine_pro(&p);
        assert!(det.is_nine_pro);
        assert_eq!(det.bind_mode, NineProBindMode::HardwareBound);
        assert_eq!(det.bind_flags, BIND_FLAG_HARDWARE);
    }

    #[test]
    fn expiration_header_includes_timestamp() {
        let mut p: Vec<u8> = header_with(0x80, BIND_FLAG_EXPIRATION, 0x6500_0000);
        if p.len() < 64 {
            p.resize(64, 0);
        }
        let det: NineProDetection = detect_nine_pro(&p);
        assert_eq!(det.bind_mode, NineProBindMode::ExpirationBound);
        assert_eq!(det.expiration_ts, Some(0x6500_0000));
    }

    #[test]
    fn multi_bind_flags_classified_as_multi() {
        let p: Vec<u8> = header_with(0x80, BIND_FLAG_HARDWARE | BIND_FLAG_NETWORK, 0);
        let det: NineProDetection = detect_nine_pro(&p);
        assert_eq!(det.bind_mode, NineProBindMode::MultiBound);
    }

    #[test]
    fn marker_string_alone_signals_pro() {
        let mut p: Vec<u8> = vec![0u8; 1024];
        p[..8].copy_from_slice(b"PY009070");
        let marker: &[u8; 16] = b"__pyarmor_bind__";
        p[256..256 + marker.len()].copy_from_slice(marker);
        let det: NineProDetection = detect_nine_pro(&p);
        assert!(det.is_nine_pro);
        assert!(
            det.bind_markers_found
                .iter()
                .any(|m| m == "__pyarmor_bind__")
        );
    }

    #[test]
    fn truncated_payload_is_safe() {
        let det: NineProDetection = detect_nine_pro(b"PY009");
        assert!(!det.is_nine_pro);
        assert_eq!(det.bind_mode, NineProBindMode::None);
    }
}
