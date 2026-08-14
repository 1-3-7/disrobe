use std::io::{Cursor, Read};

use disrobe_core::byte_search;
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::disasm::{StreamEnd, StreamProbe, disassemble, probe_stream};
use crate::error::{Error, Result};
use crate::opcode::max_proto;
use crate::polyglot::looks_like_pickle;
use crate::vm::{PickleValue, VmTrace, execute};

const MODEL_ARCHIVE_ENTRY_MAX: usize = 4096;
const MODEL_ENTRY_BYTES_MAX: usize = 64 * 1024 * 1024;
const MODEL_ENTRY_BYTES_MAX_U64: u64 = 64 * 1024 * 1024;
const MODEL_TOTAL_BYTES_MAX: usize = 256 * 1024 * 1024;
const STACKED_MEMBER_MAX: usize = 4096;
const STACKED_MEMBER_MIN: usize = 2;
const ANCHOR_OPCODE_BUDGET: usize = 1 << 16;
const SCAN_OPCODES_PER_BYTE: usize = 2;
const SCAN_OPCODE_FLOOR: usize = 1 << 16;
const TORCH_LEGACY_MEMBERS: usize = 5;
const TORCH_MAGIC_NUMBER_DECIMAL: &str = "119547037146038801333356";
const TORCH_MAGIC_NUMBER_HEX: &str = "0x1950a86a20f9469cfc6c";
const TORCH_LEGACY_MEMBER_NAMES: [&str; TORCH_LEGACY_MEMBERS] = [
    "<magic>",
    "<protocol_version>",
    "<sys_info>",
    "<module>",
    "<storage_keys>",
];

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
    let format: ModelFormat = if is_npz(bytes) {
        ModelFormat::NumpyNpz
    } else if bytes.starts_with(b"PK\x03\x04") {
        ModelFormat::PyTorchZip
    } else if is_npy(bytes) {
        ModelFormat::NumpyNpy
    } else if is_legacy_tar(bytes) {
        ModelFormat::PyTorchLegacyTar
    } else if stacked_layout(bytes).members.len() >= STACKED_MEMBER_MIN {
        ModelFormat::PyTorchStackedPickle
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
        ModelFormat::BarePickle => {
            let member: Option<StreamEnd> = probe_stream(bytes, scan_budget(bytes.len())).end;
            Ok(MlReport {
                format,
                framing: Some(bare_pickle_framing(bytes.len(), member)),
                embedded: vec![EmbeddedPickle {
                    path: "<root>".to_string(),
                    offset: 0,
                    length: member.map_or(bytes.len(), |end: StreamEnd| end.len),
                    protocol: member
                        .map_or_else(|| protocol_of(bytes), |end: StreamEnd| Some(end.protocol)),
                }],
            })
        }
        ModelFormat::NumpyNpy => Ok(MlReport {
            format,
            framing: Some(numpy_object_array_note(bytes)),
            embedded: numpy_npy_embedded(bytes),
        }),
        ModelFormat::PyTorchStackedPickle => {
            let layout: StackedLayout = stacked_layout(bytes);
            Ok(MlReport {
                format,
                framing: Some(stacked_framing(&layout)),
                embedded: layout.members,
            })
        }
        ModelFormat::Unknown => Ok(MlReport {
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

#[derive(Debug, Clone)]
struct StackedLayout {
    members: Vec<EmbeddedPickle>,
    trailing: usize,
    torch_legacy: bool,
}

const fn scan_budget(len: usize) -> usize {
    len.saturating_mul(SCAN_OPCODES_PER_BYTE)
        .saturating_add(SCAN_OPCODE_FLOOR)
}

fn stacked_layout(bytes: &[u8]) -> StackedLayout {
    let mut spans: Vec<StreamEnd> = Vec::new();
    let mut budget: usize = scan_budget(bytes.len());
    let mut pos: usize = 0;
    let mut torch_legacy: bool = false;
    let mut limit: usize = STACKED_MEMBER_MAX;
    while spans.len() < limit && pos < bytes.len() && budget > 0 {
        let probe: StreamProbe = probe_stream(&bytes[pos..], budget);
        budget = budget.saturating_sub(probe.opcodes.max(1));
        let Some(end): Option<StreamEnd> = probe.end else {
            break;
        };
        if spans.is_empty() && is_torch_magic(&bytes[pos..pos.saturating_add(end.len)]) {
            torch_legacy = true;
            limit = TORCH_LEGACY_MEMBERS;
        }
        spans.push(end);
        pos = pos.saturating_add(end.len);
    }
    let named: bool = torch_legacy && spans.len() == TORCH_LEGACY_MEMBERS;
    let mut members: Vec<EmbeddedPickle> = Vec::with_capacity(spans.len());
    let mut offset: usize = 0;
    for (index, span) in spans.iter().enumerate() {
        members.push(EmbeddedPickle {
            path: match TORCH_LEGACY_MEMBER_NAMES.get(index) {
                Some(name) if named => (*name).to_owned(),
                _ => format!("<stacked@{offset}>"),
            },
            offset,
            length: span.len,
            protocol: Some(span.protocol),
        });
        offset = offset.saturating_add(span.len);
    }
    StackedLayout {
        members,
        trailing: bytes.len().saturating_sub(offset),
        torch_legacy,
    }
}

const TORCH_MAGIC_MEMBER_MAX: usize = 64;

fn is_torch_magic(member: &[u8]) -> bool {
    if member.len() > TORCH_MAGIC_MEMBER_MAX {
        return false;
    }
    let Ok(dis): Result<crate::disasm::Disassembly> = disassemble(member) else {
        return false;
    };
    let Ok(trace): Result<VmTrace> = execute(&dis) else {
        return false;
    };
    matches!(&trace.result, PickleValue::BigInt(value) if value == TORCH_MAGIC_NUMBER_DECIMAL)
}

fn stacked_framing(layout: &StackedLayout) -> String {
    if layout.torch_legacy {
        format!(
            "legacy torch.save container: {} stacked pickle streams (magic number {}) + {} \
             trailing bytes of storage payload",
            layout.members.len(),
            TORCH_MAGIC_NUMBER_HEX,
            layout.trailing
        )
    } else {
        format!(
            "stacked pickle container: {} successive streams + {} trailing bytes",
            layout.members.len(),
            layout.trailing
        )
    }
}

fn bare_pickle_framing(len: usize, member: Option<StreamEnd>) -> String {
    match member {
        Some(end) if end.len < len => format!(
            "raw pickle stream: {} bytes of opcodes + {} trailing bytes",
            end.len,
            len - end.len
        ),
        _ => "raw pickle stream".to_string(),
    }
}

fn scan_for_embedded(bytes: &[u8]) -> Vec<EmbeddedPickle> {
    let mut out: Vec<EmbeddedPickle> = Vec::new();
    let mut budget: usize = scan_budget(bytes.len());
    let mut i: usize = 0;
    while i + 1 < bytes.len() && out.len() < STACKED_MEMBER_MAX && budget > 0 {
        if bytes[i] == 0x80 && bytes[i + 1] <= max_proto() {
            let probe: StreamProbe = probe_stream(&bytes[i..], budget.min(ANCHOR_OPCODE_BUDGET));
            budget = budget.saturating_sub(probe.opcodes.max(1));
            if let Some(end) = probe.end {
                out.push(EmbeddedPickle {
                    path: format!("<stacked@{i}>"),
                    offset: i,
                    length: end.len,
                    protocol: Some(end.protocol),
                });
                i = i.saturating_add(end.len);
                continue;
            }
        }
        i = i.saturating_add(1);
    }
    out
}

const NPY_HEADER_SCAN: usize = 256;

fn npy_body_offset(bytes: &[u8]) -> Option<usize> {
    if !is_npy(bytes) {
        return None;
    }
    let major: u8 = *bytes.get(6)?;
    let declared: usize = match major {
        1 => usize::from(u16::from_le_bytes([*bytes.get(8)?, *bytes.get(9)?])),
        2 | 3 => u32::from_le_bytes([
            *bytes.get(8)?,
            *bytes.get(9)?,
            *bytes.get(10)?,
            *bytes.get(11)?,
        ]) as usize,
        _ => return None,
    };
    let prefix: usize = if major == 1 { 10 } else { 12 };
    let body: usize = prefix.checked_add(declared)?;
    (body <= bytes.len()).then_some(body)
}

fn npy_header(bytes: &[u8]) -> &[u8] {
    let end: usize = npy_body_offset(bytes).unwrap_or(NPY_HEADER_SCAN);
    &bytes[..bytes.len().min(end)]
}

fn is_npy_object_array(bytes: &[u8]) -> bool {
    let header: &[u8] = npy_header(bytes);
    byte_search::contains(header, b"'O'")
        || byte_search::contains(header, b"|O")
        || byte_search::contains(header, b"dtype('O')")
}

fn numpy_npy_embedded(bytes: &[u8]) -> Vec<EmbeddedPickle> {
    if !is_npy_object_array(bytes) {
        return Vec::new();
    }
    let Some(body): Option<usize> = npy_body_offset(bytes) else {
        return scan_for_embedded(bytes);
    };
    let tail: &[u8] = &bytes[body..];
    let Some(end): Option<StreamEnd> = probe_stream(tail, scan_budget(tail.len())).end else {
        return scan_for_embedded(bytes);
    };
    vec![EmbeddedPickle {
        path: "<array-body>".to_string(),
        offset: body,
        length: end.len,
        protocol: Some(end.protocol),
    }]
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
    match bytes {
        [0x80, declared, ..] if *declared <= max_proto() => Some(*declared),
        _ if looks_like_pickle(bytes) => Some(0),
        _ => None,
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
        let body: &[u8] = b"\x80\x04\x95\n\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x01a\x94K\x01s.";
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
        assert_eq!(
            report.embedded[0].length,
            body.len(),
            "the array body is one whole pickle stream"
        );
        assert_eq!(report.embedded[0].offset, bytes.len() - body.len());
    }

    #[test]
    fn an_over_declared_frame_is_not_reported_as_an_embedded_pickle() {
        let body: &[u8] = b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00}\x94.";
        assert!(
            disassemble(body).is_err(),
            "the frame declares five bytes and three follow, so this is not a pickle at all"
        );
        let bytes: Vec<u8> = npy_with_descr(b"|O", body);
        let report: MlReport = extract(&bytes).expect("extract");
        assert!(
            report.embedded.is_empty(),
            "a stream the disassembler rejects must not be listed as an embedded pickle: {:?}",
            report.embedded
        );
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
    fn two_successive_streams_are_a_stacked_container() {
        let bytes: &[u8] = b"\x80\x02N.\x80\x02K\x01.";
        assert_eq!(detect(bytes), ModelFormat::PyTorchStackedPickle);
        let report: MlReport = extract(bytes).expect("extract");
        assert_eq!(report.embedded.len(), 2);
        assert_eq!(report.embedded[1].offset, 4);
        assert_eq!(report.embedded[1].length, 5);
        assert_eq!(
            report.framing.as_deref(),
            Some("stacked pickle container: 2 successive streams + 0 trailing bytes")
        );
    }

    #[test]
    fn a_truncated_last_member_is_trailing_data_not_a_member() {
        let bytes: &[u8] = b"\x80\x02N.\x80\x02K\x01.\x80\x02K";
        let layout: StackedLayout = stacked_layout(bytes);
        assert_eq!(layout.members.len(), 2);
        assert_eq!(layout.trailing, 3);
        assert!(!layout.torch_legacy);
    }

    #[test]
    fn a_flood_of_tiny_streams_stops_at_the_member_ceiling() {
        let mut bytes: Vec<u8> = Vec::new();
        for _ in 0..STACKED_MEMBER_MAX + 64 {
            bytes.extend_from_slice(b"\x80\x02N.");
        }
        let start: std::time::Instant = std::time::Instant::now();
        let layout: StackedLayout = stacked_layout(&bytes);
        assert_eq!(layout.members.len(), STACKED_MEMBER_MAX);
        assert_eq!(layout.trailing, 64 * 4);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "a stream flood must stay bounded"
        );
    }

    fn zip_naming(entry: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = b"PK\x03\x04".to_vec();
        out.extend_from_slice(&[0x14, 0x00]);
        out.extend_from_slice(&[0x00, 0x00]);
        out.extend_from_slice(&[0x00, 0x00]);
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&(entry.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0x00, 0x00]);
        out.extend_from_slice(entry);
        out
    }

    #[test]
    fn a_torch_zip_stays_a_torch_zip_after_the_npz_probe_runs_first() {
        let bytes: Vec<u8> = zip_naming(b"archive/data.pkl");
        assert_eq!(detect(&bytes), ModelFormat::PyTorchZip);
        let torchscript: Vec<u8> = zip_naming(b"model/constants.pkl");
        assert_eq!(detect(&torchscript), ModelFormat::PyTorchZip);
    }

    #[test]
    fn an_npz_archive_is_not_reported_as_a_torch_zip() {
        let bytes: Vec<u8> = zip_naming(b"arr_0.npy");
        assert_eq!(detect(&bytes), ModelFormat::NumpyNpz);
    }

    #[test]
    fn a_declared_protocol_above_the_opcode_table_is_not_a_protocol() {
        assert_eq!(protocol_of(&[0x80, 0xff, b'.']), None);
        assert_eq!(protocol_of(b"\x80\x05N."), Some(5));
        assert_eq!(protocol_of(b"N."), Some(0));
    }

    #[test]
    fn npy_body_offset_follows_the_declared_header_length() {
        let body: &[u8] = b"\x80\x04}\x94.";
        let bytes: Vec<u8> = npy_with_descr(b"|O", body);
        assert_eq!(npy_body_offset(&bytes), Some(bytes.len() - body.len()));
        assert_eq!(npy_body_offset(b"\x93NUMPY\x01\x00"), None);
        assert_eq!(npy_body_offset(b"not-an-npy"), None);
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
