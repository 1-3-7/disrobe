use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::error::{Error, Result};
use crate::polyglot::looks_like_pickle;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelFormat {
    BarePickle,
    PyTorchZip,
    PyTorchLegacyTar,
    PyTorchStackedPickle,
    NumpyNpy,
    NumpyNpz,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedPickle {
    pub path: String,
    pub offset: usize,
    pub length: usize,
    pub protocol: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlReport {
    pub format: ModelFormat,
    pub framing: Option<String>,
    pub embedded: Vec<EmbeddedPickle>,
}

#[must_use]
pub fn detect(bytes: &[u8]) -> ModelFormat {
    if bytes.starts_with(b"PK\x03\x04") {
        return ModelFormat::PyTorchZip;
    }
    if is_npy(bytes) {
        return ModelFormat::NumpyNpy;
    }
    if is_npz(bytes) {
        return ModelFormat::NumpyNpz;
    }
    if is_legacy_tar(bytes) {
        return ModelFormat::PyTorchLegacyTar;
    }
    if looks_like_pickle(bytes) {
        return ModelFormat::BarePickle;
    }
    ModelFormat::Unknown
}

pub fn extract(bytes: &[u8]) -> Result<MlReport> {
    let format: ModelFormat = detect(bytes);
    match format {
        ModelFormat::PyTorchZip | ModelFormat::NumpyNpz => extract_zip(bytes, format),
        ModelFormat::PyTorchLegacyTar => extract_tar(bytes),
        ModelFormat::BarePickle => Ok(MlReport {
            format,
            framing: Some("raw pickle stream".to_string()),
            embedded: vec![EmbeddedPickle {
                path: "<root>".to_string(),
                offset: 0,
                length: bytes.len(),
                protocol: protocol_of(bytes),
            }],
        }),
        ModelFormat::NumpyNpy => Ok(MlReport {
            format,
            framing: Some(numpy_object_array_note(bytes)),
            embedded: numpy_npy_embedded(bytes),
        }),
        ModelFormat::PyTorchStackedPickle | ModelFormat::Unknown => Ok(MlReport {
            format,
            framing: None,
            embedded: scan_for_embedded(bytes),
        }),
    }
}

fn extract_zip(bytes: &[u8], format: ModelFormat) -> Result<MlReport> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)
        .map_err(|e: zip::result::ZipError| Error::Container(e.to_string()))?;
    let mut embedded: Vec<EmbeddedPickle> = Vec::new();
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e: zip::result::ZipError| Error::Container(e.to_string()))?;
        let name: String = file.name().to_string();
        let is_pickle_entry: bool = name.ends_with(".pkl")
            || name.ends_with("data.pkl")
            || name.ends_with("/data")
            || name.ends_with("constants.pkl")
            || name.ends_with("attributes.pkl");
        let mut buf: Vec<u8> = Vec::new();
        if file.read_to_end(&mut buf).is_err() {
            continue;
        }
        if is_pickle_entry || looks_like_pickle(&buf) {
            embedded.push(EmbeddedPickle {
                path: name,
                offset: 0,
                length: buf.len(),
                protocol: protocol_of(&buf),
            });
        }
    }
    Ok(MlReport {
        format,
        framing: Some("ZIP container (PyTorch >=1.6 / TorchScript / .npz)".to_string()),
        embedded,
    })
}

fn extract_tar(bytes: &[u8]) -> Result<MlReport> {
    let mut archive: tar::Archive<&[u8]> = tar::Archive::new(bytes);
    let mut embedded: Vec<EmbeddedPickle> = Vec::new();
    let entries = archive
        .entries()
        .map_err(|e: std::io::Error| Error::Container(e.to_string()))?;
    for entry in entries {
        let mut e = entry.map_err(|err: std::io::Error| Error::Container(err.to_string()))?;
        let path: String = e.path().map_or_else(
            |_| "<unknown>".to_string(),
            |p| p.to_string_lossy().into_owned(),
        );
        let mut buf: Vec<u8> = Vec::new();
        if e.read_to_end(&mut buf).is_err() {
            continue;
        }
        if path == "pickle" || looks_like_pickle(&buf) {
            embedded.push(EmbeddedPickle {
                path,
                offset: 0,
                length: buf.len(),
                protocol: protocol_of(&buf),
            });
        }
    }
    Ok(MlReport {
        format: ModelFormat::PyTorchLegacyTar,
        framing: Some("legacy PyTorch tar (v0.1.1)".to_string()),
        embedded,
    })
}

fn scan_for_embedded(bytes: &[u8]) -> Vec<EmbeddedPickle> {
    let mut out: Vec<EmbeddedPickle> = Vec::new();
    let mut i: usize = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == 0x80
            && bytes[i + 1] <= 5
            && let Some(end) = find_stop(&bytes[i..])
        {
            out.push(EmbeddedPickle {
                path: format!("<stacked@{i}>"),
                offset: i,
                length: end + 1,
                protocol: Some(bytes[i + 1]),
            });
            i += end + 1;
            continue;
        }
        i += 1;
    }
    out
}

fn find_stop(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|&b: &u8| b == b'.')
}

const NPY_HEADER_SCAN: usize = 256;

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

fn is_npy_object_array(bytes: &[u8]) -> bool {
    let header: &[u8] = &bytes[..bytes.len().min(NPY_HEADER_SCAN)];
    contains_subslice(header, b"'O'")
        || contains_subslice(header, b"|O")
        || contains_subslice(header, b"dtype('O')")
}

fn numpy_npy_embedded(bytes: &[u8]) -> Vec<EmbeddedPickle> {
    if is_npy_object_array(bytes) {
        scan_for_embedded(bytes)
    } else {
        Vec::new()
    }
}

fn numpy_object_array_note(bytes: &[u8]) -> String {
    if is_npy_object_array(bytes) {
        "numpy .npy object array - body is a pickle stream".to_string()
    } else {
        ".npy non-object array (no embedded pickle)".to_string()
    }
}

#[inline]
fn protocol_of(bytes: &[u8]) -> Option<u8> {
    if bytes.len() >= 2 && bytes[0] == 0x80 {
        Some(bytes[1])
    } else if looks_like_pickle(bytes) {
        Some(0)
    } else {
        None
    }
}

fn is_npy(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x93, b'N', b'U', b'M', b'P', b'Y'])
}

fn is_npz(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"PK\x03\x04") {
        return false;
    }
    bytes.windows(4).take(8192).any(|w: &[u8]| w == b".npy")
}

fn is_legacy_tar(bytes: &[u8]) -> bool {
    bytes.len() >= 265 && &bytes[257..262] == b"ustar"
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bare_pickle_detected() {
        assert_eq!(detect(b"\x80\x02N."), ModelFormat::BarePickle);
    }

    #[test]
    fn npy_magic_detected() {
        let bytes: &[u8] = &[0x93, b'N', b'U', b'M', b'P', b'Y', 1, 0];
        assert_eq!(detect(bytes), ModelFormat::NumpyNpy);
    }

    #[test]
    fn bare_pickle_extract_reports_protocol() {
        let r: MlReport = extract(b"\x80\x04N.").expect("extract");
        assert_eq!(r.format, ModelFormat::BarePickle);
        assert_eq!(r.embedded[0].protocol, Some(4));
    }

    #[test]
    fn stacked_scan_finds_two() {
        let bytes: &[u8] = b"\x80\x02N.\x80\x02K\x01.";
        let found: Vec<EmbeddedPickle> = scan_for_embedded(bytes);
        assert_eq!(found.len(), 2);
    }

    fn npy_with_descr(descr: &[u8], body: &[u8]) -> Vec<u8> {
        let dict: Vec<u8> = {
            let mut d: Vec<u8> = Vec::new();
            d.extend_from_slice(b"{'descr': '");
            d.extend_from_slice(descr);
            d.extend_from_slice(b"', 'fortran_order': False, 'shape': (1,), }");
            d
        };
        let prelude: usize = 10 + dict.len() + 1;
        let pad: usize = (64 - prelude % 64) % 64;
        let header_len: u16 = (dict.len() + pad + 1) as u16;
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&[0x93, b'N', b'U', b'M', b'P', b'Y', 1, 0]);
        out.extend_from_slice(&header_len.to_le_bytes());
        out.extend_from_slice(&dict);
        out.resize(out.len() + pad, b' ');
        out.push(b'\n');
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn npy_object_array_extracts_embedded_pickle() {
        let body: &[u8] = b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00}\x94.";
        let bytes: Vec<u8> = npy_with_descr(b"|O", body);
        assert_eq!(detect(&bytes), ModelFormat::NumpyNpy);
        let report: MlReport = extract(&bytes).expect("extract");
        assert!(
            report
                .framing
                .as_deref()
                .unwrap_or("")
                .contains("object array"),
            "object-array framing missing: {:?}",
            report.framing
        );
        assert!(
            !report.embedded.is_empty(),
            "object-array .npy yielded no embedded pickle"
        );
        assert_eq!(report.embedded[0].protocol, Some(4));
    }

    #[test]
    fn npy_float_array_has_no_embedded_pickle() {
        let body: &[u8] = &[0u8; 8];
        let bytes: Vec<u8> = npy_with_descr(b"<f8", body);
        assert_eq!(detect(&bytes), ModelFormat::NumpyNpy);
        let report: MlReport = extract(&bytes).expect("extract");
        assert!(
            report.embedded.is_empty(),
            "float .npy false-positive embedded pickle"
        );
    }
}
