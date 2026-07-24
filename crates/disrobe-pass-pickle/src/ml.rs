use std::io::{Cursor, Read};

use disrobe_core::byte_search;
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::error::{Error, Result};
use crate::polyglot::looks_like_pickle;

const MODEL_ARCHIVE_ENTRY_MAX: usize = 4096;
const MODEL_ENTRY_BYTES_MAX: usize = 64 * 1024 * 1024;
const MODEL_ENTRY_BYTES_MAX_U64: u64 = 64 * 1024 * 1024;
const MODEL_TOTAL_BYTES_MAX: usize = 256 * 1024 * 1024;

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
    let format: ModelFormat = if bytes.starts_with(b"PK\x03\x04") {
        ModelFormat::PyTorchZip
    } else if is_npy(bytes) {
        ModelFormat::NumpyNpy
    } else if is_npz(bytes) {
        ModelFormat::NumpyNpz
    } else if is_legacy_tar(bytes) {
        ModelFormat::PyTorchLegacyTar
    } else if looks_like_pickle(bytes) {
        ModelFormat::BarePickle
    } else {
        ModelFormat::Unknown
    };
    crate::debug::dbg_kv("model-format", || format!("detected {format:?}"));
    format
}

pub fn extract(bytes: &[u8]) -> Result<MlReport> {
    crate::debug::dbg_section("pickle model-file extraction");
    crate::debug::dbg_kv("input-len", || bytes.len().to_string());
    crate::debug::dbg_hex("input-magic", bytes, 8);
    let format: ModelFormat = detect(bytes);
    let report: Result<MlReport> = match format {
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
    };
    if let Ok(r) = &report {
        crate::debug::dbg_kv("model-extracted", || {
            format!(
                "format={:?} framing={:?} embedded_pickles={}",
                r.format,
                r.framing,
                r.embedded.len()
            )
        });
    }
    report
}

fn extract_zip(bytes: &[u8], format: ModelFormat) -> Result<MlReport> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)
        .map_err(|e: zip::result::ZipError| Error::Container(e.to_string()))?;
    enforce_archive_entry_count(archive.len())?;
    let mut embedded: Vec<EmbeddedPickle> = Vec::new();
    let mut total_read: usize = 0;
    for i in 0..archive.len() {
        let mut file: zip::read::ZipFile<'_> = archive
            .by_index(i)
            .map_err(|e: zip::result::ZipError| Error::Container(e.to_string()))?;
        let name: String = file.name().to_string();
        enforce_entry_size(&name, file.size())?;
        let is_pickle_entry: bool = name.ends_with(".pkl")
            || name.ends_with("data.pkl")
            || name.ends_with("/data")
            || name.ends_with("constants.pkl")
            || name.ends_with("attributes.pkl");
        let buf: Vec<u8> = read_entry_to_limit(&mut file, &name)?;
        charge_payload_budget(&mut total_read, buf.len(), &name)?;
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
    let entries: tar::Entries<'_, &[u8]> = archive
        .entries()
        .map_err(|e: std::io::Error| Error::Container(e.to_string()))?;
    let mut entry_count: usize = 0;
    let mut total_read: usize = 0;
    for entry in entries {
        entry_count = entry_count.checked_add(1).ok_or(Error::ArchiveEntryCount {
            count: usize::MAX,
            limit: MODEL_ARCHIVE_ENTRY_MAX,
        })?;
        enforce_archive_entry_count(entry_count)?;
        let mut e: tar::Entry<'_, &[u8]> =
            entry.map_err(|err: std::io::Error| Error::Container(err.to_string()))?;
        let path: String = e.path().map_or_else(
            |_| "<unknown>".to_string(),
            |p| p.to_string_lossy().into_owned(),
        );
        enforce_entry_size(&path, e.size())?;
        let buf: Vec<u8> = read_entry_to_limit(&mut e, &path)?;
        charge_payload_budget(&mut total_read, buf.len(), &path)?;
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

fn enforce_archive_entry_count(count: usize) -> Result<()> {
    if count > MODEL_ARCHIVE_ENTRY_MAX {
        return Err(Error::ArchiveEntryCount {
            count,
            limit: MODEL_ARCHIVE_ENTRY_MAX,
        });
    }
    Ok(())
}

fn enforce_entry_size(path: &str, declared: u64) -> Result<()> {
    let limit: u64 = MODEL_ENTRY_BYTES_MAX_U64;
    if declared > limit {
        return Err(Error::ArchiveEntryTooLarge {
            path: path.to_string(),
            declared,
            limit,
        });
    }
    Ok(())
}

fn read_entry_to_limit<R: Read + ?Sized>(reader: &mut R, path: &str) -> Result<Vec<u8>> {
    let limit: u64 = MODEL_ENTRY_BYTES_MAX_U64;
    let mut buf: Vec<u8> = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(Error::Io)?;
    if buf.len() > MODEL_ENTRY_BYTES_MAX {
        return Err(Error::ArchiveEntryTooLarge {
            path: path.to_string(),
            declared: MODEL_ENTRY_BYTES_MAX_U64.saturating_add(1),
            limit,
        });
    }
    Ok(buf)
}

fn charge_payload_budget(total: &mut usize, amount: usize, path: &str) -> Result<()> {
    let next: usize = total
        .checked_add(amount)
        .ok_or_else(|| Error::ArchivePayloadBudget {
            path: path.to_string(),
            total: usize::MAX,
            limit: MODEL_TOTAL_BYTES_MAX,
        })?;
    if next > MODEL_TOTAL_BYTES_MAX {
        return Err(Error::ArchivePayloadBudget {
            path: path.to_string(),
            total: next,
            limit: MODEL_TOTAL_BYTES_MAX,
        });
    }
    *total = next;
    Ok(())
}

fn scan_for_embedded(bytes: &[u8]) -> Vec<EmbeddedPickle> {
    let mut out: Vec<EmbeddedPickle> = Vec::new();
    let mut i: usize = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == 0x80 && bytes[i + 1] <= 5 {
            let Some(end): Option<usize> = find_stop(&bytes[i..]) else {
                break;
            };
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

fn is_npy_object_array(bytes: &[u8]) -> bool {
    let header: &[u8] = &bytes[..bytes.len().min(NPY_HEADER_SCAN)];
    byte_search::contains(header, b"'O'")
        || byte_search::contains(header, b"|O")
        || byte_search::contains(header, b"dtype('O')")
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

    #[test]
    fn stacked_scan_marker_flood_without_stop_stays_bounded() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(b"\x80\x04]\x94.");
        for _ in 0..200_000 {
            bytes.push(0x80);
            bytes.push(0x00);
        }
        let start: std::time::Instant = std::time::Instant::now();
        let found: Vec<EmbeddedPickle> = scan_for_embedded(&bytes);
        let elapsed: std::time::Duration = start.elapsed();
        assert_eq!(found.len(), 1, "only the leading valid pickle is embedded");
        assert_eq!(found[0].offset, 0);
        assert_eq!(found[0].length, 5);
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "a stop-less marker flood must not scan quadratically, took {elapsed:?}"
        );
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

    fn oversized_tar() -> Vec<u8> {
        let mut header: [u8; 512] = [0; 512];
        header[..6].copy_from_slice(b"pickle");
        let declared: usize = MODEL_ENTRY_BYTES_MAX + 1;
        let size_field: String = format!("{declared:011o}\0");
        header[124..136].copy_from_slice(size_field.as_bytes());
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].fill(b' ');
        let checksum: u32 = header.iter().map(|byte: &u8| u32::from(*byte)).sum();
        let checksum_field: String = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_field.as_bytes());
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&header);
        out.extend_from_slice(&[0; 1024]);
        out
    }

    #[test]
    fn tar_declared_entry_over_limit_errors() {
        let bytes: Vec<u8> = oversized_tar();
        let err: Error = extract(&bytes).expect_err("oversized tar member must fail");
        assert!(matches!(err, Error::ArchiveEntryTooLarge { .. }));
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
    fn npy_header_probe_is_defined_for_empty_needle_and_empty_input() {
        let header: &[u8] = b"\x93NUMPY\x01\x00{'descr': '|O', 'shape': (1,), }";
        assert!(!byte_search::contains(header, b""));
        assert!(!byte_search::contains(b"", b""));
        assert_eq!(byte_search::find(header, b""), None);
        assert!(!is_npy_object_array(b""));
        assert!(is_npy_object_array(header));
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
