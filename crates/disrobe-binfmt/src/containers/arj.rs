use crate::error::{Error, Result};

pub const ARJ_MAGIC: &[u8; 2] = &[0x60, 0xEA];

const FIRST_HDR_SIZE: usize = 30;
const FLAG_GARBLE: u8 = 0x01;
const OFS_HOST_OS: usize = 7;
const OFS_FLAGS: usize = 8;
const OFS_METHOD: usize = 9;
const OFS_FILE_TYPE: usize = 10;
const OFS_COMPRESSED: usize = 16;
const OFS_ORIGINAL: usize = 20;
const OFS_CRC: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArjEntry {
    pub name: String,
    pub method: u8,
    pub host_os: u8,
    pub is_directory: bool,
    pub encrypted: bool,
    pub compressed_size: u32,
    pub original_size: u32,
    pub crc32: u32,
    pub data_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArjArchive {
    pub name: String,
    pub entries: Vec<ArjEntry>,
}

#[must_use]
pub fn detect_arj(bytes: &[u8]) -> bool {
    bytes.len() > 4 && bytes.starts_with(ARJ_MAGIC) && {
        let basic: u16 = u16::from_le_bytes([bytes[2], bytes[3]]);
        (FIRST_HDR_SIZE as u16..=2600).contains(&basic)
    }
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16> {
    let s: &[u8] = bytes
        .get(at..at + 2)
        .ok_or_else(|| Error::Arj("arj: truncated u16".to_owned()))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    let s: &[u8] = bytes
        .get(at..at + 4)
        .ok_or_else(|| Error::Arj("arj: truncated u32".to_owned()))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn skip_block(bytes: &[u8], at: usize) -> Result<(Vec<u8>, usize)> {
    let basic_size: usize = read_u16(bytes, at + 2)? as usize;
    if basic_size == 0 {
        return Ok((Vec::new(), at + 4));
    }
    let block_start: usize = at + 4;
    let block_end: usize = block_start
        .checked_add(basic_size)
        .ok_or_else(|| Error::Arj("arj: basic header size overflow".to_owned()))?;
    let block: &[u8] = bytes
        .get(block_start..block_end)
        .ok_or_else(|| Error::Arj("arj: basic header runs past end".to_owned()))?;
    let mut cursor: usize = block_end + 4;
    loop {
        let ext_size: usize = read_u16(bytes, cursor)? as usize;
        cursor += 2;
        if ext_size == 0 {
            break;
        }
        cursor = cursor
            .checked_add(ext_size + 4)
            .ok_or_else(|| Error::Arj("arj: extended header overflow".to_owned()))?;
        if cursor > bytes.len() {
            return Err(Error::Arj("arj: extended header past end".to_owned()));
        }
    }
    Ok((block.to_vec(), cursor))
}

pub fn parse_arj(bytes: &[u8]) -> Result<ArjArchive> {
    if !detect_arj(bytes) {
        return Err(Error::Arj("arj: missing 0x60 0xEA header id".to_owned()));
    }
    let (main_block, mut cursor): (Vec<u8>, usize) = skip_block(bytes, 0)?;
    let archive_name: String = first_cstr(&main_block, FIRST_HDR_SIZE);

    let mut entries: Vec<ArjEntry> = Vec::new();
    while cursor + 4 <= bytes.len() {
        if &bytes[cursor..cursor + 2] != ARJ_MAGIC {
            break;
        }
        let basic_size: usize = read_u16(bytes, cursor + 2)? as usize;
        if basic_size == 0 {
            break;
        }
        let (block, after_headers): (Vec<u8>, usize) = skip_block(bytes, cursor)?;
        let method: u8 = *block
            .get(OFS_METHOD)
            .ok_or_else(|| Error::Arj("arj: missing method byte".to_owned()))?;
        let host_os: u8 = block.get(OFS_HOST_OS).copied().map_or(0, |value: u8| value);
        let flags: u8 = block.get(OFS_FLAGS).copied().map_or(0, |value: u8| value);
        let file_type: u8 = block
            .get(OFS_FILE_TYPE)
            .copied()
            .map_or(0, |value: u8| value);
        let compressed_size: u32 = read_u32(&block, OFS_COMPRESSED)?;
        let original_size: u32 = read_u32(&block, OFS_ORIGINAL)?;
        let crc32: u32 = read_u32(&block, OFS_CRC)?;
        let name: String = first_cstr(&block, FIRST_HDR_SIZE);
        let data_offset: usize = after_headers;
        let data_end: usize = data_offset
            .checked_add(compressed_size as usize)
            .ok_or_else(|| Error::Arj("arj: compressed data overflow".to_owned()))?;
        if data_end > bytes.len() {
            return Err(Error::Arj(format!(
                "arj: entry `{name}` data runs past end of archive"
            )));
        }
        entries.push(ArjEntry {
            name,
            method,
            host_os,
            is_directory: file_type == 3,
            encrypted: flags & FLAG_GARBLE != 0,
            compressed_size,
            original_size,
            crc32,
            data_offset,
        });
        cursor = data_end;
    }
    Ok(ArjArchive {
        name: archive_name,
        entries,
    })
}

fn first_cstr(block: &[u8], at: usize) -> String {
    let tail: &[u8] = block.get(at..).map_or(&[] as &[u8], |value: &[u8]| value);
    let end: usize = tail
        .iter()
        .position(|&b: &u8| b == 0)
        .map_or(tail.len(), |value: usize| value);
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

#[must_use]
pub const fn entry_is_stored(entry: &ArjEntry) -> bool {
    entry.method == 0
}

fn entry_raw<'a>(bytes: &'a [u8], entry: &ArjEntry) -> Result<&'a [u8]> {
    bytes
        .get(entry.data_offset..entry.data_offset + entry.compressed_size as usize)
        .ok_or_else(|| Error::Arj(format!("arj: entry `{}` data out of bounds", entry.name)))
}

pub fn entry_bytes(bytes: &[u8], entry: &ArjEntry, max_out: u64) -> Result<Vec<u8>> {
    if entry.encrypted {
        return Err(Error::Arj(format!(
            "arj: entry `{}` is password-garbled (no key in archive)",
            entry.name
        )));
    }
    let raw: &[u8] = entry_raw(bytes, entry)?;
    let expected: usize = entry.original_size as usize;
    match entry.method {
        0 => Ok(raw.to_vec()),
        1..=3 => {
            if u64::from(entry.original_size) > max_out {
                return Err(Error::Arj(format!(
                    "arj: entry `{}` declares {} decompressed bytes, exceeding the per-entry extraction cap {max_out}",
                    entry.name, entry.original_size
                )));
            }
            crate::containers::lha_huff::decode(ARJ_LZ_PARAMS, raw, expected).map_err(|e: Error| {
                Error::Arj(format!(
                    "arj: entry `{}` method {}: {e}",
                    entry.name, entry.method
                ))
            })
        }
        4 => Err(Error::Arj(format!(
            "arj: entry `{}` uses method 4 (decode_f fast lzss); its bitstream differs from methods 1-3 and is not decoded in-tree",
            entry.name
        ))),
        other => Err(Error::Arj(format!(
            "arj: entry `{}` uses unknown method {other}",
            entry.name
        ))),
    }
}

const ARJ_LZ_PARAMS: crate::containers::lha_huff::LhaParams =
    crate::containers::lha_huff::LhaParams {
        history_bits: 16,
        offset_bits: 5,
    };

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_block(fields: &[u8], name: &str, data: &[u8]) -> Vec<u8> {
        let mut basic: Vec<u8> = Vec::new();
        basic.push(FIRST_HDR_SIZE as u8);
        basic.extend_from_slice(fields);
        while basic.len() < FIRST_HDR_SIZE {
            basic.push(0);
        }
        basic.extend_from_slice(name.as_bytes());
        basic.push(0);
        basic.push(0);

        let mut out: Vec<u8> = ARJ_MAGIC.to_vec();
        out.extend_from_slice(&(basic.len() as u16).to_le_bytes());
        out.extend_from_slice(&basic);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    fn file_fields(method: u8, file_type: u8, comp: u32, orig: u32) -> Vec<u8> {
        let mut f: Vec<u8> = vec![0u8; FIRST_HDR_SIZE - 1];
        f[OFS_HOST_OS - 1] = 2;
        f[OFS_METHOD - 1] = method;
        f[OFS_FILE_TYPE - 1] = file_type;
        f[(OFS_COMPRESSED - 1)..(OFS_COMPRESSED - 1 + 4)].copy_from_slice(&comp.to_le_bytes());
        f[(OFS_ORIGINAL - 1)..(OFS_ORIGINAL - 1 + 4)].copy_from_slice(&orig.to_le_bytes());
        f
    }

    #[test]
    fn detect_matches_header_id() {
        let mut bytes: Vec<u8> = ARJ_MAGIC.to_vec();
        bytes.extend_from_slice(&40u16.to_le_bytes());
        bytes.extend([0u8; 64]);
        assert!(detect_arj(&bytes));
        assert!(!detect_arj(b"PK\x03\x04"));
    }

    #[test]
    fn parses_stored_entry_byte_exact() {
        let payload: &[u8] = b"stored arj member, verbatim bytes here";
        let mut blob: Vec<u8> = build_block(&[], "main", &[]);
        blob.extend(build_block(
            &file_fields(0, 0, payload.len() as u32, payload.len() as u32),
            "hello.txt",
            payload,
        ));
        blob.extend_from_slice(ARJ_MAGIC);
        blob.extend_from_slice(&0u16.to_le_bytes());
        let archive: ArjArchive = parse_arj(&blob).expect("parse arj");
        assert_eq!(archive.entries.len(), 1);
        let entry: &ArjEntry = &archive.entries[0];
        assert_eq!(entry.name, "hello.txt");
        assert!(entry_is_stored(entry));
        assert_eq!(
            entry_bytes(&blob, entry, u64::MAX).expect("bytes"),
            payload.to_vec()
        );
    }

    #[test]
    fn method4_is_documented_as_undecoded() {
        let payload: &[u8] = b"\x01\x02\x03 lz-coded";
        let mut blob: Vec<u8> = build_block(&[], "main", &[]);
        blob.extend(build_block(
            &file_fields(4, 0, payload.len() as u32, 999),
            "big.bin",
            payload,
        ));
        let archive: ArjArchive = parse_arj(&blob).expect("parse arj");
        let entry: &ArjEntry = &archive.entries[0];
        assert!(!entry_is_stored(entry));
        assert!(entry_bytes(&blob, entry, u64::MAX).is_err());
    }

    #[test]
    fn method1_routes_to_huffman_lzss_decoder() {
        let mut blob: Vec<u8> = build_block(&[], "main", &[]);
        blob.extend(build_block(
            &file_fields(1, 0, 4, 64),
            "lz.bin",
            &[0x00, 0x00, 0x00, 0x00],
        ));
        let archive: ArjArchive = parse_arj(&blob).expect("parse arj");
        let entry: &ArjEntry = &archive.entries[0];
        assert_eq!(entry.method, 1);
        let result: Result<Vec<u8>> = entry_bytes(&blob, entry, u64::MAX);
        assert!(
            matches!(&result, Err(Error::Arj(msg)) if msg.contains("method 1")),
            "method 1 must route through the lzss decoder and report decode failure on garbage input"
        );
    }
}
