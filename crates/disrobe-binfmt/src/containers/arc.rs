use std::collections::BTreeSet;

use crate::error::{Error, Result};

pub const ARC_MARKER: u8 = 0x1A;
const FNLEN: usize = 13;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcEntry {
    pub name: String,
    pub method: u8,
    pub compressed_size: u32,
    pub original_size: u32,
    pub crc16: u16,
    pub data_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcArchive {
    pub entries: Vec<ArcEntry>,
}

#[must_use]
pub fn detect_arc(bytes: &[u8]) -> bool {
    if bytes.len() < 2 + FNLEN + 4 || bytes[0] != ARC_MARKER {
        return false;
    }
    let method: u8 = bytes[1] & 0x7f;
    if !(1..=11).contains(&method) {
        return false;
    }
    let name: &[u8] = &bytes[2..2 + FNLEN];
    let nul: usize = name
        .iter()
        .position(|&b: &u8| b == 0)
        .map_or(FNLEN, |value: usize| value);
    nul > 0 && name[..nul].iter().all(|&b: &u8| (0x20..0x7f).contains(&b))
}

pub fn parse_arc(bytes: &[u8]) -> Result<ArcArchive> {
    parse_arc_with_entry_limit(bytes, crate::quota::DEFAULT_MAX_ENTRIES)
}

pub(crate) fn parse_arc_with_entry_limit(bytes: &[u8], max_entries: usize) -> Result<ArcArchive> {
    if bytes.first() != Some(&ARC_MARKER) {
        return Err(Error::Arc("arc: missing 0x1a archive marker".to_owned()));
    }
    let mut cursor: usize = 0;
    let mut entries: Vec<ArcEntry> = Vec::new();
    let mut terminated: bool = false;
    while cursor + 2 <= bytes.len() {
        if bytes[cursor] != ARC_MARKER {
            return Err(Error::Arc(format!(
                "arc: expected 0x1a marker at offset {cursor}, found 0x{:02x}",
                bytes[cursor]
            )));
        }
        let raw_method: u8 = bytes[cursor + 1];
        let method: u8 = raw_method & 0x7f;
        if method == 0 {
            terminated = true;
            break;
        }
        let name_start: usize = cursor + 2;
        let name_end: usize = name_start + FNLEN;
        let name_bytes: &[u8] = bytes
            .get(name_start..name_end)
            .ok_or_else(|| Error::Arc("arc: truncated name field".to_owned()))?;
        let name: String = cstr(name_bytes);
        let comp_off: usize = name_end;
        let compressed_size: u32 = read_u32(bytes, comp_off)?;
        let crc_off: usize = comp_off + 4 + 2 + 2;
        let crc16: u16 = read_u16(bytes, crc_off)?;
        let has_orig: bool = method != 1;
        let (original_size, header_end): (u32, usize) = if has_orig {
            (read_u32(bytes, crc_off + 2)?, crc_off + 2 + 4)
        } else {
            (compressed_size, crc_off + 2)
        };
        let data_offset: usize = if raw_method & 0x80 == 0 {
            header_end
        } else {
            header_end
                .checked_add(12)
                .ok_or_else(|| Error::Arc("arc: Spark header size overflow".to_owned()))?
        };
        let data_end: usize = data_offset
            .checked_add(compressed_size as usize)
            .ok_or_else(|| Error::Arc("arc: data size overflow".to_owned()))?;
        if data_end > bytes.len() {
            return Err(Error::Arc(format!(
                "arc: entry `{name}` data runs past end of archive"
            )));
        }
        if entries.len() >= max_entries {
            return Err(Error::QuotaExceeded {
                entry: name,
                reason: format!("ARC entry count exceeds cap {max_entries}"),
            });
        }
        entries.push(ArcEntry {
            name,
            method,
            compressed_size,
            original_size,
            crc16,
            data_offset,
        });
        cursor = data_end;
    }
    if entries.is_empty() {
        return Err(Error::Arc("arc: no entries before end marker".to_owned()));
    }
    if !terminated {
        return Err(Error::Arc("arc: missing end marker".to_owned()));
    }
    Ok(ArcArchive { entries })
}

pub(crate) fn admit_output_path(paths: &mut BTreeSet<String>, name: &str) -> Result<()> {
    let key: String = name.to_ascii_lowercase();
    let has_ancestor: bool = key
        .match_indices('/')
        .any(|(index, _): (usize, &str)| paths.contains(&key[..index]));
    let descendant_prefix: String = format!("{key}/");
    let has_descendant: bool = paths
        .range(descendant_prefix.clone()..)
        .next()
        .is_some_and(|candidate: &String| candidate.starts_with(&descendant_prefix));
    if paths.contains(&key) || has_ancestor || has_descendant {
        return Err(Error::Arc(format!(
            "arc: normalized output path collision at `{name}`"
        )));
    }
    paths.insert(key);
    Ok(())
}

#[must_use]
pub const fn entry_is_stored(entry: &ArcEntry) -> bool {
    entry.method == 1 || entry.method == 2
}

pub(crate) fn preflight_entry_quota(
    entry: &ArcEntry,
    quota: crate::quota::ExtractionQuota,
) -> Result<()> {
    let mut guard: crate::quota::QuotaGuard =
        crate::quota::QuotaGuard::new(crate::quota::ExtractionQuota {
            max_entries: 1,
            max_total_uncompressed: quota.max_per_entry_uncompressed,
            max_per_entry_uncompressed: quota.max_per_entry_uncompressed,
            max_per_entry_ratio: quota.max_per_entry_ratio,
            max_aggregate_ratio: u64::MAX,
        });
    guard.admit_entry(
        &entry.name,
        u64::from(entry.original_size),
        u64::from(entry.compressed_size),
    )
}

fn entry_raw<'a>(bytes: &'a [u8], entry: &ArcEntry) -> Result<&'a [u8]> {
    let end: usize = entry
        .data_offset
        .checked_add(entry.compressed_size as usize)
        .ok_or_else(|| Error::Arc(format!("arc: entry `{}` data range overflow", entry.name)))?;
    bytes
        .get(entry.data_offset..end)
        .ok_or_else(|| Error::Arc(format!("arc: entry `{}` data out of bounds", entry.name)))
}

pub fn entry_bytes(bytes: &[u8], entry: &ArcEntry, max_out: u64) -> Result<Vec<u8>> {
    let raw: &[u8] = entry_raw(bytes, entry)?;
    let cap: usize = usize::try_from(max_out).map_or(usize::MAX, |value: usize| value);
    let expected: usize = usize::try_from(entry.original_size).map_err(|_| {
        Error::Arc(format!(
            "arc: entry `{}` original size does not fit this platform",
            entry.name
        ))
    })?;
    if expected > cap {
        return Err(Error::Arc(format!(
            "arc: entry `{}` output exceeds cap",
            entry.name
        )));
    }
    let decoded: Vec<u8> = match entry.method {
        1 | 2 => raw.to_vec(),
        3 => crate::containers::arc_codec::un_rle(raw, cap)?,
        4 => crate::containers::arc_codec::un_squeeze(raw, cap)?,
        5 => crate::containers::arc_codec::un_crunch_fixed(raw, false, cap)?,
        6 | 7 => {
            let intermediate_cap: usize = expected.checked_mul(2).ok_or_else(|| {
                Error::Arc(format!(
                    "arc: entry `{}` intermediate size overflow",
                    entry.name
                ))
            })?;
            let intermediate: Vec<u8> = crate::containers::arc_codec::un_crunch_fixed(
                raw,
                entry.method == 7,
                intermediate_cap,
            )?;
            crate::containers::arc_codec::un_rle(&intermediate, cap)?
        }
        8 => crate::containers::arc_codec::un_crunch(raw, expected)?,
        9 => crate::containers::arc_codec::un_squash(raw, expected)?,
        other => {
            return Err(Error::Arc(format!(
                "arc: entry `{}` uses compression method {other}, which is not decodable in-tree",
                entry.name
            )));
        }
    };
    if decoded.len() != expected {
        return Err(Error::Arc(format!(
            "arc: entry `{}` decoded to {} bytes, header declares {}",
            entry.name,
            decoded.len(),
            entry.original_size
        )));
    }
    let actual_crc: u16 = crate::containers::lzh::crc16_arc(&decoded);
    if actual_crc != entry.crc16 {
        return Err(Error::Arc(format!(
            "arc: entry `{}` CRC mismatch: header {:04x}, decoded {:04x}",
            entry.name, entry.crc16, actual_crc
        )));
    }
    Ok(decoded)
}

fn cstr(field: &[u8]) -> String {
    let end: usize = field
        .iter()
        .position(|&b: &u8| b == 0)
        .map_or(field.len(), |value: usize| value);
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16> {
    disrobe_bytes::read_u16_le_at(bytes, at)
        .map_err(|_| Error::Arc("arc: truncated u16".to_owned()))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    disrobe_bytes::read_u32_le_at(bytes, at)
        .map_err(|_| Error::Arc("arc: truncated u32".to_owned()))
}

#[cfg(test)]
pub(crate) fn build_entry(method: u8, name: &str, data: &[u8], orig: u32) -> Vec<u8> {
    let mut out: Vec<u8> = vec![ARC_MARKER, method];
    let mut name_field: [u8; FNLEN] = [0u8; FNLEN];
    let nb: &[u8] = name.as_bytes();
    name_field[..nb.len()].copy_from_slice(nb);
    out.extend_from_slice(&name_field);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crate::containers::lzh::crc16_arc(data).to_le_bytes());
    if method != 1 {
        out.extend_from_slice(&orig.to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
pub(crate) fn synth_stored_arc(name: &str, body: &[u8]) -> Option<Vec<u8>> {
    if name.len() >= FNLEN {
        return None;
    }
    let mut blob: Vec<u8> = build_entry(2, name, body, u32::try_from(body.len()).ok()?);
    blob.push(ARC_MARKER);
    blob.push(0);
    Some(blob)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_recognizes_stored_arc() {
        let e: Vec<u8> = build_entry(2, "readme.txt", b"hello arc world", 15);
        assert!(detect_arc(&e));
        assert!(!detect_arc(b"PK\x03\x04 not arc"));
    }

    #[test]
    fn parses_stored_member_byte_exact() {
        let payload: &[u8] = b"stored arc member bytes, method 2";
        let mut blob: Vec<u8> = build_entry(2, "data.txt", payload, payload.len() as u32);
        blob.push(ARC_MARKER);
        blob.push(0);
        let archive: ArcArchive = parse_arc(&blob).expect("parse arc");
        assert_eq!(archive.entries.len(), 1);
        let entry: &ArcEntry = &archive.entries[0];
        assert_eq!(entry.name, "data.txt");
        assert!(entry_is_stored(entry));
        assert_eq!(entry_bytes(&blob, entry, 1 << 20).expect("bytes"), payload);
    }

    fn build_entry_compressed(method: u8, name: &str, comp: &[u8], decoded: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = vec![ARC_MARKER, method];
        let mut name_field: [u8; FNLEN] = [0u8; FNLEN];
        let nb: &[u8] = name.as_bytes();
        name_field[..nb.len()].copy_from_slice(nb);
        out.extend_from_slice(&name_field);
        out.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crate::containers::lzh::crc16_arc(decoded).to_le_bytes());
        out.extend_from_slice(&(decoded.len() as u32).to_le_bytes());
        out.extend_from_slice(comp);
        out
    }

    fn rle_encode_for_test(input: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i < input.len() {
            let byte: u8 = input[i];
            let mut run: usize = 1;
            while i + run < input.len() && input[i + run] == byte && run < 255 {
                run += 1;
            }
            if byte == 0x90 {
                for _ in 0..run {
                    out.push(0x90);
                    out.push(0);
                }
            } else if run >= 4 {
                out.push(byte);
                out.push(0x90);
                out.push(run as u8);
            } else {
                out.push(byte);
                i += 1;
                continue;
            }
            i += run;
        }
        out
    }

    #[test]
    fn method3_rle_round_trips_through_entry_bytes() {
        let payload: Vec<u8> = {
            let mut v: Vec<u8> = b"header".to_vec();
            v.extend(std::iter::repeat_n(b'=', 40));
            v.extend_from_slice(b"footer");
            v
        };
        let comp: Vec<u8> = rle_encode_for_test(&payload);
        let mut blob: Vec<u8> = build_entry_compressed(3, "rle.txt", &comp, &payload);
        blob.push(ARC_MARKER);
        blob.push(0);
        let archive: ArcArchive = parse_arc(&blob).expect("parse arc");
        let decoded: Vec<u8> =
            entry_bytes(&blob, &archive.entries[0], 1 << 20).expect("decode method 3");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn fixed_lzw_methods_decode_reference_wires_through_arc_entries() {
        const METHOD_FIVE: &[u8] = &[
            0x0a, 0x50, 0x82, 0xd6, 0x69, 0x8b, 0x98, 0xb3, 0x77, 0x37, 0x70,
        ];
        const METHOD_SIX: &[u8] = &[
            0x0a, 0x54, 0xff, 0x10, 0x00, 0x82, 0x5a, 0x00, 0xc4, 0x5a, 0x03, 0x13, 0x6d, 0x45,
            0xa0,
        ];
        const METHOD_SEVEN: &[u8] = &[
            0x84, 0x03, 0xaf, 0xb8, 0x43, 0x21, 0x93, 0x4e, 0x02, 0x93, 0x4e, 0xd0, 0x50, 0x69,
            0x34,
        ];
        let cases: [(u8, &str, &[u8], &[u8]); 3] = [
            (5, "method5.bin", METHOD_FIVE, b"ABABABAABABABA"),
            (6, "method6.bin", METHOD_SIX, b"AAAAABBBBBCCCCCAAAAABBBBB"),
            (7, "method7.bin", METHOD_SEVEN, b"AAAAABBBBBCCCCCAAAAABBBBB"),
        ];
        for (method, name, compressed, expected) in cases {
            let mut blob: Vec<u8> = build_entry_compressed(method, name, compressed, expected);
            blob.extend_from_slice(&[ARC_MARKER, 0]);
            let archive: ArcArchive = parse_arc(&blob).expect("parse fixed LZW ARC entry");
            let decoded: Vec<u8> =
                entry_bytes(&blob, &archive.entries[0], 1 << 20).expect("decode fixed LZW ARC");
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn fixed_lzw_accepts_an_empty_member_and_preflights_the_ratio_boundary() {
        let mut blob: Vec<u8> = build_entry_compressed(5, "empty.bin", &[], &[]);
        blob.extend_from_slice(&[ARC_MARKER, 0]);
        let archive: ArcArchive = parse_arc(&blob).expect("parse empty fixed LZW ARC entry");
        let decoded: Vec<u8> =
            entry_bytes(&blob, &archive.entries[0], 0).expect("decode empty fixed LZW ARC");
        assert!(decoded.is_empty());

        let entry: ArcEntry = ArcEntry {
            name: "ratio.bin".to_owned(),
            method: 5,
            compressed_size: 1,
            original_size: 100,
            crc16: 0,
            data_offset: 0,
        };
        let exact: crate::quota::ExtractionQuota = crate::quota::ExtractionQuota {
            max_per_entry_uncompressed: 100,
            max_per_entry_ratio: 100,
            ..crate::quota::ExtractionQuota::default_safe()
        };
        preflight_entry_quota(&entry, exact).expect("admit exact ARC ratio boundary");
        let below: crate::quota::ExtractionQuota = crate::quota::ExtractionQuota {
            max_per_entry_ratio: 99,
            ..exact
        };
        assert!(matches!(
            preflight_entry_quota(&entry, below),
            Err(Error::QuotaExceeded { .. })
        ));
    }

    #[test]
    fn unsupported_method_errors() {
        let payload: &[u8] = b"\x01\x02\x03 unsupported arc variant";
        let mut blob: Vec<u8> = build_entry_compressed(10, "old.dat", payload, &[0; 16]);
        blob.extend_from_slice(&[ARC_MARKER, 0]);
        let archive: ArcArchive = parse_arc(&blob).expect("parse arc");
        assert!(entry_bytes(&blob, &archive.entries[0], 1 << 20).is_err());
    }

    #[test]
    fn decoded_member_with_a_mismatched_crc_is_rejected() {
        let payload: &[u8] = b"crc protected arc member";
        let mut blob: Vec<u8> = build_entry(2, "crc.txt", payload, payload.len() as u32);
        blob[23..25].copy_from_slice(&0x1234_u16.to_le_bytes());
        blob.extend_from_slice(&[ARC_MARKER, 0]);
        let archive: ArcArchive = parse_arc(&blob).expect("parse arc");
        let decoded: Result<Vec<u8>> = entry_bytes(&blob, &archive.entries[0], 1 << 20);
        assert!(matches!(decoded, Err(Error::Arc(message)) if message.contains("CRC")));
    }

    #[test]
    fn parser_enforces_the_entry_limit_before_retaining_another_member() {
        let mut blob: Vec<u8> = build_entry(2, "one.txt", b"one", 3);
        blob.extend_from_slice(&build_entry(2, "two.txt", b"two", 3));
        blob.extend_from_slice(&[ARC_MARKER, 0]);
        let parsed: Result<ArcArchive> = parse_arc_with_entry_limit(&blob, 1);
        assert!(matches!(parsed, Err(Error::QuotaExceeded { .. })));
    }

    #[test]
    fn parser_rejects_an_archive_without_the_end_marker() {
        let blob: Vec<u8> = build_entry(2, "one.txt", b"one", 3);
        let parsed: Result<ArcArchive> = parse_arc(&blob);
        assert!(matches!(parsed, Err(Error::Arc(message)) if message.contains("end marker")));
    }
}
