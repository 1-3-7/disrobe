//! Nuitka build detection from binary contents.

use std::path::Path;

use crate::error::{Error, Result};
use crate::onefile_locator::{LocatedOnefile, locate_onefile_payload};
use crate::util::find_subslice;

/// Strings present in a real Nuitka 4.1.1 `--standalone` exe and `--module` pyd.
const NUITKA_SIGNATURES: &[&[u8]] = &[
    b"__nuitka_version__",
    b"nuitka_module_loader",
    b"nuitka_distribution",
    b"nuitka_resource_reader",
    b"nuitka_empty_function",
    b"Nuitka_Err_NormalizeException",
    b"__compiled__",
];

/// Env-var names baked into the onefile bootstrap C (`OnefileBootstrap.c`).
const ONEFILE_BOOTSTRAP_SIGNATURES: &[&[u8]] = &[
    b"NUITKA_ONEFILE_PARENT",
    b"NUITKA_ONEFILE_START",
    b"NUITKA_ONEFILE_TIME_US",
    b"NUITKA_ONEFILE_RANDOM",
    b"NUITKA_ONEFILE_DIRECTORY",
];

const WHEEL_SIGNATURES: &[&[u8]] = &[
    b".dist-info/METADATA",
    b".dist-info/RECORD",
    b".dist-info/WHEEL",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NuitkaFlavor {
    Standalone,
    OnefileUncompressed,
    OnefileZstd,
    Wheel,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NuitkaVersion {
    pub raw: Option<String>,
    pub python_major: Option<u8>,
    pub python_minor: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WheelMarker {
    pub has_metadata: bool,
    pub has_record: bool,
    pub has_wheel: bool,
}

impl WheelMarker {
    #[inline]
    #[must_use]
    pub const fn is_wheel(self) -> bool {
        self.has_metadata && self.has_record && self.has_wheel
    }
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub flavor: NuitkaFlavor,
    pub hits: Vec<String>,
    pub version: NuitkaVersion,
    pub onefile_payload_offset: Option<usize>,
    pub onefile_payload_compressed: bool,
    pub wheel_marker: WheelMarker,
}

pub fn detect_in_file(path: &Path) -> Result<Detection> {
    let bytes: Vec<u8> = std::fs::read(path)?;
    detect_in_bytes(&bytes)
}

pub fn detect_in_bytes(bytes: &[u8]) -> Result<Detection> {
    let mut hits: Vec<String> =
        Vec::with_capacity(NUITKA_SIGNATURES.len() + ONEFILE_BOOTSTRAP_SIGNATURES.len());
    for sig in NUITKA_SIGNATURES.iter().chain(ONEFILE_BOOTSTRAP_SIGNATURES) {
        if find_subslice(bytes, sig).is_some()
            && let Ok(text) = core::str::from_utf8(sig)
        {
            hits.push(text.to_owned());
        }
    }

    let located: Option<LocatedOnefile> = locate_onefile_payload(bytes);
    let (onefile_offset, onefile_compressed): (Option<usize>, bool) =
        located.map_or((None, false), |loc| (Some(loc.offset), loc.compressed));
    let wheel_marker: WheelMarker = locate_wheel(bytes);

    let flavor: NuitkaFlavor = match (onefile_offset, onefile_compressed, wheel_marker.is_wheel()) {
        (Some(_), true, _) => NuitkaFlavor::OnefileZstd,
        (Some(_), false, _) => NuitkaFlavor::OnefileUncompressed,
        (None, _, true) => NuitkaFlavor::Wheel,
        _ => NuitkaFlavor::Standalone,
    };

    if hits.is_empty() && onefile_offset.is_none() && !wheel_marker.is_wheel() {
        return Err(Error::NotNuitka);
    }

    let version: NuitkaVersion = parse_version(bytes);

    Ok(Detection {
        flavor,
        hits,
        version,
        onefile_payload_offset: onefile_offset,
        onefile_payload_compressed: onefile_compressed,
        wheel_marker,
    })
}

fn locate_wheel(bytes: &[u8]) -> WheelMarker {
    WheelMarker {
        has_metadata: find_subslice(bytes, WHEEL_SIGNATURES[0]).is_some(),
        has_record: find_subslice(bytes, WHEEL_SIGNATURES[1]).is_some(),
        has_wheel: find_subslice(bytes, WHEEL_SIGNATURES[2]).is_some(),
    }
}

fn parse_version(bytes: &[u8]) -> NuitkaVersion {
    let raw: Option<String> = find_after_marker(bytes, b"NUITKA_VERSION", 64);
    let py_pair: Option<(u8, u8)> = find_python_version_strings(bytes);
    NuitkaVersion {
        raw,
        python_major: py_pair.map(|(maj, _)| maj),
        python_minor: py_pair.map(|(_, min)| min),
    }
}

fn find_python_version_strings(bytes: &[u8]) -> Option<(u8, u8)> {
    for major in [3u8, 2u8] {
        for minor in (0u8..=20u8).rev() {
            let dll_form: String = format!("python{major}{minor}.dll");
            if find_subslice(bytes, dll_form.as_bytes()).is_some() {
                return Some((major, minor));
            }
            let so_form: String = format!("libpython{major}.{minor}.so");
            if find_subslice(bytes, so_form.as_bytes()).is_some() {
                return Some((major, minor));
            }
            let dylib_form: String = format!("libpython{major}.{minor}.dylib");
            if find_subslice(bytes, dylib_form.as_bytes()).is_some() {
                return Some((major, minor));
            }
        }
    }
    None
}

fn find_after_marker(bytes: &[u8], marker: &[u8], read_len: usize) -> Option<String> {
    let idx: usize = find_subslice(bytes, marker)?;
    let start: usize = idx + marker.len();
    let end: usize = (start + read_len).min(bytes.len());
    let slice: &[u8] = &bytes[start..end];
    let printable: Vec<u8> = slice
        .iter()
        .take_while(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'.' || b == b'_' || b == b'-')
        .copied()
        .collect();
    if printable.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&printable).into_owned())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn kax_payload(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out: Vec<u8> = b"KAX".to_vec();
        for (name, data) in entries {
            for unit in name.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out.extend_from_slice(&[0u8, 0u8]);
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            out.extend_from_slice(data);
        }
        out.extend_from_slice(&[0u8, 0u8]);
        out
    }

    #[test]
    fn empty_input_is_not_nuitka() {
        let Err(err): Result<Detection> = detect_in_bytes(b"") else {
            panic!("empty input must error");
        };
        assert!(matches!(err, Error::NotNuitka));
    }

    #[test]
    fn detects_standalone_runtime_marker() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        bytes[100..119].copy_from_slice(b"nuitka_distribution");
        bytes[300..312].copy_from_slice(b"__compiled__");
        let det: Detection = detect_in_bytes(&bytes).expect("standalone marker present");
        assert_eq!(det.flavor, NuitkaFlavor::Standalone);
        assert!(det.hits.iter().any(|s| s == "nuitka_distribution"));
        assert!(det.hits.iter().any(|s| s == "__compiled__"));
    }

    #[test]
    fn detects_onefile_zstd_via_bootstrap_and_validated_payload() {
        let inner: Vec<u8> = kax_payload(&[("hello.exe", b"MZ\x90\x00body")]);
        let compressed: Vec<u8> = zstd::stream::encode_all(&inner[3..], 19).expect("zstd");
        let mut bytes: Vec<u8> = b"MZ\x90\x00".to_vec();
        bytes.extend_from_slice(b"NUITKA_ONEFILE_PARENT\0NUITKA_ONEFILE_START\0");
        bytes.extend_from_slice(b"KAY");
        bytes.extend_from_slice(&compressed);
        let det: Detection = detect_in_bytes(&bytes).expect("onefile zstd");
        assert_eq!(det.flavor, NuitkaFlavor::OnefileZstd);
        assert!(det.onefile_payload_compressed);
        assert!(det.onefile_payload_offset.is_some());
        assert!(det.hits.iter().any(|s| s == "NUITKA_ONEFILE_PARENT"));
    }

    #[test]
    fn detects_onefile_uncompressed_via_validated_payload() {
        let inner: Vec<u8> = kax_payload(&[("hello.exe", b"MZ\x90\x00body")]);
        let mut bytes: Vec<u8> = b"MZ\x90\x00".to_vec();
        bytes.extend_from_slice(b"NUITKA_ONEFILE_DIRECTORY\0");
        bytes.extend_from_slice(&inner);
        let det: Detection = detect_in_bytes(&bytes).expect("onefile stored");
        assert_eq!(det.flavor, NuitkaFlavor::OnefileUncompressed);
        assert!(!det.onefile_payload_compressed);
    }

    #[test]
    fn bare_ka_xy_without_validation_is_not_onefile() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[500..503].copy_from_slice(b"KAY");
        bytes[504..520].copy_from_slice(&[0xAB; 16]);
        bytes[1000..1019].copy_from_slice(b"nuitka_distribution");
        let det: Detection = detect_in_bytes(&bytes).expect("standalone, not onefile");
        assert_eq!(det.onefile_payload_offset, None);
        assert_eq!(det.flavor, NuitkaFlavor::Standalone);
    }

    #[test]
    fn detects_wheel_when_all_three_dist_info_markers_present() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[100..119].copy_from_slice(b".dist-info/METADATA");
        bytes[400..417].copy_from_slice(b".dist-info/RECORD");
        bytes[800..816].copy_from_slice(b".dist-info/WHEEL");
        bytes[1500..1512].copy_from_slice(b"__compiled__");
        let det: Detection = detect_in_bytes(&bytes).expect("wheel + nuitka markers");
        assert_eq!(det.flavor, NuitkaFlavor::Wheel);
        assert!(det.wheel_marker.is_wheel());
    }

    #[test]
    fn random_garbage_input_is_not_nuitka() {
        let bytes: Vec<u8> = (0..2048u32)
            .map(|i| (i.wrapping_mul(31) & 0xFF) as u8)
            .collect();
        let result: Result<Detection> = detect_in_bytes(&bytes);
        if let Ok(det) = result {
            assert!(det.hits.is_empty() || det.onefile_payload_offset.is_some());
        }
    }
}
