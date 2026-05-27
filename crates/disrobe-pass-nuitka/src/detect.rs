use std::path::Path;

use crate::error::{Error, Result};
use crate::util::find_subslice;

const NUITKA_SIGNATURES: &[&[u8]] = &[
    b"Nuitka_FunctionObject",
    b"Nuitka_GeneratorObject",
    b"Nuitka_CellObject",
    b"loadConstantsBlob",
    b"createGlobalConstants",
    b"NUITKA_CONSTANT_BLOB_TAG_",
    b"MAKE_FUNCTION_",
    b"impl___main__",
];

const WHEEL_SIGNATURES: &[&[u8]] = &[
    b".dist-info/METADATA",
    b".dist-info/RECORD",
    b".dist-info/WHEEL",
];

const ONEFILE_MAGIC_PREFIX: &[u8; 2] = b"KA";

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
    let mut hits: Vec<String> = Vec::with_capacity(NUITKA_SIGNATURES.len());
    for sig in NUITKA_SIGNATURES {
        if find_subslice(bytes, sig).is_some()
            && let Ok(s) = core::str::from_utf8(sig)
        {
            hits.push(s.to_owned());
        }
    }

    let (onefile_offset, onefile_compressed): (Option<usize>, bool) = locate_onefile(bytes);
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

fn locate_onefile(bytes: &[u8]) -> (Option<usize>, bool) {
    let mut cursor: usize = 0usize;
    while let Some(idx) = find_subslice_after(bytes, ONEFILE_MAGIC_PREFIX, cursor) {
        if idx + 3 > bytes.len() {
            break;
        }
        let third: u8 = bytes[idx + 2];
        match third {
            b'X' => return (Some(idx), false),
            b'Y' => return (Some(idx), true),
            _ => cursor = idx + 2,
        }
    }
    (None, false)
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

fn find_subslice_after(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if start >= haystack.len() {
        return None;
    }
    find_subslice(&haystack[start..], needle).map(|i| i + start)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_not_nuitka() {
        let Err(err): Result<Detection> = detect_in_bytes(b"") else {
            panic!("empty input must error");
        };
        assert!(matches!(err, Error::NotNuitka));
    }

    #[test]
    fn detects_load_constants_blob_marker() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        bytes[100..117].copy_from_slice(b"loadConstantsBlob");
        let det: Detection = detect_in_bytes(&bytes).expect("synthetic marker present");
        assert_eq!(det.flavor, NuitkaFlavor::Standalone);
        assert!(det.hits.iter().any(|s| s == "loadConstantsBlob"));
    }

    #[test]
    fn detects_onefile_zstd() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        bytes[200..203].copy_from_slice(b"KAY");
        let det: Detection = detect_in_bytes(&bytes).expect("KAY synthetic must detect");
        assert_eq!(det.flavor, NuitkaFlavor::OnefileZstd);
        assert_eq!(det.onefile_payload_offset, Some(200));
        assert!(det.onefile_payload_compressed);
    }

    #[test]
    fn detects_onefile_uncompressed() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        bytes[300..303].copy_from_slice(b"KAX");
        let det: Detection = detect_in_bytes(&bytes).expect("KAX synthetic must detect");
        assert_eq!(det.flavor, NuitkaFlavor::OnefileUncompressed);
        assert!(!det.onefile_payload_compressed);
    }

    #[test]
    fn detects_wheel_when_all_three_dist_info_markers_present() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[100..119].copy_from_slice(b".dist-info/METADATA");
        bytes[400..417].copy_from_slice(b".dist-info/RECORD");
        bytes[800..816].copy_from_slice(b".dist-info/WHEEL");
        bytes[1500..1517].copy_from_slice(b"loadConstantsBlob");
        let det: Detection = detect_in_bytes(&bytes).expect("wheel + nuitka markers");
        assert_eq!(det.flavor, NuitkaFlavor::Wheel);
        assert!(det.wheel_marker.is_wheel());
    }

    #[test]
    fn wheel_partial_marker_does_not_flip_flavor() {
        let mut bytes: Vec<u8> = vec![0u8; 2048];
        bytes[100..119].copy_from_slice(b".dist-info/METADATA");
        bytes[1500..1517].copy_from_slice(b"loadConstantsBlob");
        let det: Detection = detect_in_bytes(&bytes).expect("partial wheel + nuitka markers");
        assert_eq!(det.flavor, NuitkaFlavor::Standalone);
        assert!(!det.wheel_marker.is_wheel());
        assert!(det.wheel_marker.has_metadata);
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

    #[test]
    fn onefile_zstd_wins_over_wheel_marker() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[50..53].copy_from_slice(b"KAY");
        bytes[200..219].copy_from_slice(b".dist-info/METADATA");
        bytes[600..617].copy_from_slice(b".dist-info/RECORD");
        bytes[1000..1016].copy_from_slice(b".dist-info/WHEEL");
        let det: Detection = detect_in_bytes(&bytes).expect("onefile wins over wheel");
        assert_eq!(det.flavor, NuitkaFlavor::OnefileZstd);
    }
}
