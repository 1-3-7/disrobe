use disrobe_core::byte_search;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NineProBindMode {
    #[default]
    None,
    HardwareBound,
    LicenseFileBound,
    Unknown,
}

impl NineProBindMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HardwareBound => "hardware",
            Self::LicenseFileBound => "license-file",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NineProDetection {
    pub is_nine_pro: bool,
    pub bind_mode: NineProBindMode,
    pub bind_markers_found: Vec<String>,
}

const PRO_MARKER_STRINGS: &[&[u8]] = &[
    b"__pyarmor_bind__",
    b"__pyarmor_dev__",
    b"__pyarmor_hwid__",
    b"__pyarmor_machine__",
    b"pyarmor.license.lic",
    b"pyarmor.bind.lic",
    b"pyarmor-restrict-mode",
];

const MARKER_WINDOW: usize = 64 * 1024;

pub fn detect_nine_pro(payload: &[u8]) -> NineProDetection {
    let bind_markers_found: Vec<String> = scan_pro_markers(payload);
    let is_nine_pro: bool = !bind_markers_found.is_empty();
    NineProDetection {
        is_nine_pro,
        bind_mode: classify(&bind_markers_found),
        bind_markers_found,
    }
}

fn classify(markers: &[String]) -> NineProBindMode {
    if markers.is_empty() {
        NineProBindMode::None
    } else if markers
        .iter()
        .any(|m: &String| m.contains("hwid") || m.contains("machine") || m == "__pyarmor_bind__")
    {
        NineProBindMode::HardwareBound
    } else if markers
        .iter()
        .any(|m: &String| matches!(m.as_str(), "pyarmor.license.lic" | "pyarmor.bind.lic"))
    {
        NineProBindMode::LicenseFileBound
    } else {
        NineProBindMode::Unknown
    }
}

fn scan_pro_markers(payload: &[u8]) -> Vec<String> {
    let head: &[u8] = &payload[..payload.len().min(MARKER_WINDOW)];
    PRO_MARKER_STRINGS
        .iter()
        .filter(|marker: &&&[u8]| byte_search::contains(head, marker))
        .filter_map(|marker: &&[u8]| core::str::from_utf8(marker).ok())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn default_build_header(serial: [u8; 6]) -> Vec<u8> {
        let mut p: Vec<u8> = vec![0u8; 128];
        p[..2].copy_from_slice(b"PY");
        p[2..8].copy_from_slice(&serial);
        p[9] = 3;
        p[10] = 12;
        p[16] = 0x80;
        p[18] = 0x01;
        p[20] = 0x08;
        p[24] = 0x04;
        p[28] = 0x40;
        p[36] = 0x12;
        p[37] = 0x09;
        p[38] = 0x04;
        p[52..56].copy_from_slice(&[0x96, 0x88, 0xf1, 0x32]);
        p
    }

    #[test]
    fn a_licence_serial_and_nonce_bytes_are_not_pro_evidence() {
        let det: NineProDetection = detect_nine_pro(&default_build_header(*b"009070"));
        assert_eq!(det, NineProDetection::default());
    }

    #[test]
    fn a_hardware_marker_signals_a_bound_pro_build() {
        let mut p: Vec<u8> = default_build_header(*b"000000");
        p.extend_from_slice(b"__pyarmor_hwid__");
        let det: NineProDetection = detect_nine_pro(&p);
        assert!(det.is_nine_pro);
        assert_eq!(det.bind_mode, NineProBindMode::HardwareBound);
        assert_eq!(det.bind_markers_found, vec!["__pyarmor_hwid__".to_owned()]);
    }

    #[test]
    fn a_licence_file_marker_is_a_licence_file_binding() {
        let mut p: Vec<u8> = default_build_header(*b"000000");
        p.extend_from_slice(b"pyarmor.license.lic");
        assert_eq!(
            detect_nine_pro(&p).bind_mode,
            NineProBindMode::LicenseFileBound
        );
    }

    #[test]
    fn a_marker_past_the_window_is_not_read() {
        let mut p: Vec<u8> = vec![0u8; MARKER_WINDOW];
        p.extend_from_slice(b"__pyarmor_bind__");
        assert!(!detect_nine_pro(&p).is_nine_pro);
    }

    #[test]
    fn truncated_payload_is_safe() {
        assert_eq!(detect_nine_pro(b"PY009"), NineProDetection::default());
    }
}
