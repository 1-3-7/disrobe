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
    let method: u8 = bytes[1];
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
    if bytes.first() != Some(&ARC_MARKER) {
        return Err(Error::Arc("arc: missing 0x1a archive marker".to_owned()));
    }
    let mut cursor: usize = 0;
    let mut entries: Vec<ArcEntry> = Vec::new();
    while cursor + 2 <= bytes.len() {
        if bytes[cursor] != ARC_MARKER {
            return Err(Error::Arc(format!(
                "arc: expected 0x1a marker at offset {cursor}, found 0x{:02x}",
                bytes[cursor]
            )));
        }
        let method: u8 = bytes[cursor + 1];
        if method == 0 {
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
        let data_offset: usize = header_end;
        let data_end: usize = data_offset
            .checked_add(compressed_size as usize)
            .ok_or_else(|| Error::Arc("arc: data size overflow".to_owned()))?;
        if data_end > bytes.len() {
            return Err(Error::Arc(format!(
                "arc: entry `{name}` data runs past end of archive"
            )));
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
    Ok(ArcArchive { entries })
}

#[must_use]
pub const fn entry_is_stored(entry: &ArcEntry) -> bool {
    entry.method == 1 || entry.method == 2
}

fn entry_raw<'a>(bytes: &'a [u8], entry: &ArcEntry) -> Result<&'a [u8]> {
    bytes
        .get(entry.data_offset..entry.data_offset + entry.compressed_size as usize)
        .ok_or_else(|| Error::Arc(format!("arc: entry `{}` data out of bounds", entry.name)))
}

pub fn entry_bytes(bytes: &[u8], entry: &ArcEntry, max_out: u64) -> Result<Vec<u8>> {
    let raw: &[u8] = entry_raw(bytes, entry)?;
    let cap: usize = usize::try_from(max_out).map_or(usize::MAX, |value: usize| value);
    let decoded: Vec<u8> = match entry.method {
        1 | 2 => raw.to_vec(),
        3 => crate::containers::arc_codec::un_rle(raw, cap)?,
        4 => crate::containers::arc_codec::un_squeeze(raw, cap)?,
        8 => crate::containers::arc_codec::un_crunch(raw, cap)?,
        9 => crate::containers::arc_codec::un_squash(raw, cap)?,
        other => {
            return Err(Error::Arc(format!(
                "arc: entry `{}` uses compression method {other}, which is not decodable in-tree",
                entry.name
            )));
        }
    };
    if entry.method != 1 && decoded.len() as u64 != u64::from(entry.original_size) {
        return Err(Error::Arc(format!(
            "arc: entry `{}` decoded to {} bytes, header declares {}",
            entry.name,
            decoded.len(),
            entry.original_size
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
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_entry(method: u8, name: &str, data: &[u8], orig: u32) -> Vec<u8> {
        let mut out: Vec<u8> = vec![ARC_MARKER, method];
        let mut name_field: [u8; FNLEN] = [0u8; FNLEN];
        let nb: &[u8] = name.as_bytes();
        name_field[..nb.len()].copy_from_slice(nb);
        out.extend_from_slice(&name_field);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        if method != 1 {
            out.extend_from_slice(&orig.to_le_bytes());
        }
        out.extend_from_slice(data);
        out
    }

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

    fn build_entry_compressed(method: u8, name: &str, comp: &[u8], orig: u32) -> Vec<u8> {
        let mut out: Vec<u8> = vec![ARC_MARKER, method];
        let mut name_field: [u8; FNLEN] = [0u8; FNLEN];
        let nb: &[u8] = name.as_bytes();
        name_field[..nb.len()].copy_from_slice(nb);
        out.extend_from_slice(&name_field);
        out.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&orig.to_le_bytes());
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
        let mut blob: Vec<u8> = build_entry_compressed(3, "rle.txt", &comp, payload.len() as u32);
        blob.push(ARC_MARKER);
        blob.push(0);
        let archive: ArcArchive = parse_arc(&blob).expect("parse arc");
        let decoded: Vec<u8> =
            entry_bytes(&blob, &archive.entries[0], 1 << 20).expect("decode method 3");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn unsupported_method_errors() {
        let payload: &[u8] = b"\x01\x02\x03 old crunch variant";
        let blob: Vec<u8> = build_entry_compressed(5, "old.dat", payload, 4096);
        let archive: ArcArchive = parse_arc(&blob).expect("parse arc");
        assert!(entry_bytes(&blob, &archive.entries[0], 1 << 20).is_err());
    }
}
