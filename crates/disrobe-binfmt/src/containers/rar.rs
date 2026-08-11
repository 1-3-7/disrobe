use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use disrobe_bytes::ByteReader;

const RAR5_SIGNATURE: &[u8; 8] = &[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];
const RAR4_SIGNATURE: &[u8; 7] = &[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];

const HEAD_FILE: u64 = 2;
const HEAD_ENDARC: u64 = 5;
const FILE_FLAG_DIRECTORY: u64 = 0x0001;
const HEADER_FLAG_EXTRA: u64 = 0x0001;
const HEADER_FLAG_DATA: u64 = 0x0002;
const RAR5_METHOD_MASK: u64 = 0x0380;
const RAR5_METHOD_SHIFT: u32 = 7;
const RAR5_VERSION_MASK: u64 = 0x003f;
const MAX_ENTRIES: usize = 1_000_000;

const RAR4_FILE_HEAD: u8 = 0x74;
const RAR4_ENDARC_HEAD: u8 = 0x7b;
const RAR4_FLAG_ADD_SIZE: u16 = 0x8000;
const RAR4_FLAG_DIRECTORY: u16 = 0xe0;
const RAR4_LHD_LARGE: u16 = 0x0100;
const RAR4_LHD_UNICODE: u16 = 0x0200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RarMethod {
    Store,
    Compressed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarEntry {
    pub name: String,
    pub data_offset: u64,
    pub packed_size: u64,
    pub unpacked_size: u64,
    pub method: RarMethod,
    pub method_byte: u8,
    pub compression_version: u8,
    pub is_dir: bool,
}

impl RarEntry {
    #[must_use]
    pub const fn method_label(&self) -> &'static str {
        match self.method_byte {
            0x30 => "store",
            0x31 => "fastest",
            0x32 => "fast",
            0x33 => "normal",
            0x34 => "good",
            0x35 => "best",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarArchive {
    pub version: u8,
    pub entries: Vec<RarEntry>,
}

fn read_rar5_vint(reader: &mut ByteReader<'_>) -> Option<u64> {
    reader.read_uleb128().ok()
}

#[must_use]
pub fn detect_rar(bytes: &[u8]) -> bool {
    bytes.starts_with(RAR5_SIGNATURE) || bytes.starts_with(RAR4_SIGNATURE)
}

pub fn parse_rar(bytes: &[u8]) -> Result<RarArchive> {
    if bytes.starts_with(RAR5_SIGNATURE) {
        parse_rar5(bytes)
    } else if bytes.starts_with(RAR4_SIGNATURE) {
        parse_rar4(bytes)
    } else {
        Err(Error::Decompression(
            "input is neither a RAR4 nor a RAR5 archive (encrypted-header archives are not parsed in-tree)"
                .to_owned(),
        ))
    }
}

pub fn parse_rar5(bytes: &[u8]) -> Result<RarArchive> {
    if !bytes.starts_with(RAR5_SIGNATURE) {
        return Err(Error::Decompression(
            "rar5 signature not found (rar4 and encrypted-header archives use a different parser)"
                .to_owned(),
        ));
    }
    let mut pos: usize = RAR5_SIGNATURE.len();
    let mut entries: Vec<RarEntry> = Vec::new();

    while pos < bytes.len() {
        if entries.len() > MAX_ENTRIES {
            return Err(Error::Decompression(
                "rar entry count exceeds sanity bound".to_owned(),
            ));
        }
        let block_start: usize = pos;
        let mut cur: ByteReader<'_> = ByteReader::new(bytes);
        if cur.seek(pos).is_err() {
            break;
        }
        let Some(_crc): Option<u32> = cur.read_u32_le().ok() else {
            break;
        };
        let Some(header_size): Option<u64> = read_rar5_vint(&mut cur) else {
            break;
        };
        let header_body_start: usize = cur.position();
        let header_end: usize = match header_body_start.checked_add(header_size as usize) {
            Some(e) if e <= bytes.len() => e,
            _ => break,
        };
        let Some(header_type): Option<u64> = read_rar5_vint(&mut cur) else {
            break;
        };
        let Some(header_flags): Option<u64> = read_rar5_vint(&mut cur) else {
            break;
        };

        if header_flags & HEADER_FLAG_EXTRA != 0 {
            let Some(_extra): Option<u64> = read_rar5_vint(&mut cur) else {
                break;
            };
        }
        let data_size: u64 = if header_flags & HEADER_FLAG_DATA != 0 {
            match read_rar5_vint(&mut cur) {
                Some(v) => v,
                None => break,
            }
        } else {
            0
        };

        if header_type == HEAD_ENDARC {
            break;
        }

        if header_type == HEAD_FILE
            && let Some(entry) = parse_rar5_file_block(&mut cur, header_end, data_size)
        {
            entries.push(entry);
        }

        let data_start: usize = header_end;
        pos = match data_start.checked_add(data_size as usize) {
            Some(p) if p > block_start => p,
            _ => break,
        };
    }

    Ok(RarArchive {
        version: 5,
        entries,
    })
}

fn parse_rar5_file_block(
    cur: &mut ByteReader<'_>,
    header_end: usize,
    data_size: u64,
) -> Option<RarEntry> {
    let file_flags: u64 = read_rar5_vint(cur)?;
    let unpacked_size: u64 = read_rar5_vint(cur)?;
    let _attributes: u64 = read_rar5_vint(cur)?;
    if file_flags & 0x0002 != 0 {
        let _mtime: u32 = cur.read_u32_le().ok()?;
    }
    if file_flags & 0x0004 != 0 {
        let _data_crc: u32 = cur.read_u32_le().ok()?;
    }
    let compression_info: u64 = read_rar5_vint(cur)?;
    let _host_os: u64 = read_rar5_vint(cur)?;
    let name_length: u64 = read_rar5_vint(cur)?;
    let name_bytes: &[u8] = cur.read_bytes(name_length as usize).ok()?;
    let name: String = String::from_utf8_lossy(name_bytes).replace('\\', "/");

    let is_dir: bool = file_flags & FILE_FLAG_DIRECTORY != 0;
    let method_bits: u64 = (compression_info & RAR5_METHOD_MASK) >> RAR5_METHOD_SHIFT;
    let raw_version: u8 = (compression_info & RAR5_VERSION_MASK) as u8;
    let compression_version: u8 = 50 + raw_version;
    let method: RarMethod = if method_bits == 0 {
        RarMethod::Store
    } else {
        RarMethod::Compressed
    };
    let method_byte: u8 = 0x30 + (method_bits as u8).min(5);

    Some(RarEntry {
        name,
        data_offset: header_end as u64,
        packed_size: data_size,
        unpacked_size,
        method,
        method_byte,
        compression_version,
        is_dir,
    })
}

pub fn parse_rar4(bytes: &[u8]) -> Result<RarArchive> {
    if !bytes.starts_with(RAR4_SIGNATURE) {
        return Err(Error::Decompression("rar4 signature not found".to_owned()));
    }
    let mut pos: usize = RAR4_SIGNATURE.len();
    let mut entries: Vec<RarEntry> = Vec::new();

    while pos + 7 <= bytes.len() {
        if entries.len() > MAX_ENTRIES {
            return Err(Error::Decompression(
                "rar entry count exceeds sanity bound".to_owned(),
            ));
        }
        let block_start: usize = pos;
        let head_type: u8 = bytes[pos + 2];
        let head_flags: u16 = u16::from_le_bytes([bytes[pos + 3], bytes[pos + 4]]);
        let head_size: u16 = u16::from_le_bytes([bytes[pos + 5], bytes[pos + 6]]);
        if head_size < 7 {
            break;
        }
        let header_end: usize = match block_start.checked_add(head_size as usize) {
            Some(e) if e <= bytes.len() => e,
            _ => break,
        };

        let add_size: u64 = if head_flags & RAR4_FLAG_ADD_SIZE != 0 {
            let slice: Option<&[u8]> = bytes.get(pos + 7..pos + 11);
            match slice {
                Some(s) => u64::from(u32::from_le_bytes([s[0], s[1], s[2], s[3]])),
                None => break,
            }
        } else {
            0
        };

        if head_type == RAR4_ENDARC_HEAD {
            break;
        }

        if head_type == RAR4_FILE_HEAD
            && let Some(entry) = parse_rar4_file_block(bytes, block_start, header_end, head_flags)
        {
            entries.push(entry);
        }

        pos = match header_end.checked_add(add_size as usize) {
            Some(p) if p > block_start => p,
            _ => break,
        };
    }

    Ok(RarArchive {
        version: 4,
        entries,
    })
}

fn parse_rar4_file_block(
    bytes: &[u8],
    block_start: usize,
    header_end: usize,
    head_flags: u16,
) -> Option<RarEntry> {
    let pack_size_lo: u32 = u32::from_le_bytes([
        *bytes.get(block_start + 7)?,
        *bytes.get(block_start + 8)?,
        *bytes.get(block_start + 9)?,
        *bytes.get(block_start + 10)?,
    ]);
    let unp_size_lo: u32 = u32::from_le_bytes([
        *bytes.get(block_start + 11)?,
        *bytes.get(block_start + 12)?,
        *bytes.get(block_start + 13)?,
        *bytes.get(block_start + 14)?,
    ]);
    let _host_os: u8 = *bytes.get(block_start + 15)?;
    let _file_crc: u32 = u32::from_le_bytes([
        *bytes.get(block_start + 16)?,
        *bytes.get(block_start + 17)?,
        *bytes.get(block_start + 18)?,
        *bytes.get(block_start + 19)?,
    ]);
    let _ftime: u32 = u32::from_le_bytes([
        *bytes.get(block_start + 20)?,
        *bytes.get(block_start + 21)?,
        *bytes.get(block_start + 22)?,
        *bytes.get(block_start + 23)?,
    ]);
    let unp_version: u8 = *bytes.get(block_start + 24)?;
    let method_byte: u8 = *bytes.get(block_start + 25)?;
    let name_size: u16 =
        u16::from_le_bytes([*bytes.get(block_start + 26)?, *bytes.get(block_start + 27)?]);
    let _attr: u32 = u32::from_le_bytes([
        *bytes.get(block_start + 28)?,
        *bytes.get(block_start + 29)?,
        *bytes.get(block_start + 30)?,
        *bytes.get(block_start + 31)?,
    ]);

    let mut field_off: usize = block_start + 32;
    let (pack_size, unp_size): (u64, u64) = if head_flags & RAR4_LHD_LARGE != 0 {
        let high_pack: u32 = u32::from_le_bytes([
            *bytes.get(field_off)?,
            *bytes.get(field_off + 1)?,
            *bytes.get(field_off + 2)?,
            *bytes.get(field_off + 3)?,
        ]);
        let high_unp: u32 = u32::from_le_bytes([
            *bytes.get(field_off + 4)?,
            *bytes.get(field_off + 5)?,
            *bytes.get(field_off + 6)?,
            *bytes.get(field_off + 7)?,
        ]);
        field_off += 8;
        (
            (u64::from(high_pack) << 32) | u64::from(pack_size_lo),
            (u64::from(high_unp) << 32) | u64::from(unp_size_lo),
        )
    } else {
        (u64::from(pack_size_lo), u64::from(unp_size_lo))
    };

    let name_bytes: &[u8] = bytes.get(field_off..field_off + name_size as usize)?;
    let name: String = decode_rar4_name(name_bytes, head_flags & RAR4_LHD_UNICODE != 0);

    let is_dir: bool = (head_flags & RAR4_FLAG_DIRECTORY) == RAR4_FLAG_DIRECTORY;
    let method: RarMethod = if method_byte == 0x30 {
        RarMethod::Store
    } else {
        RarMethod::Compressed
    };

    Some(RarEntry {
        name,
        data_offset: header_end as u64,
        packed_size: pack_size,
        unpacked_size: unp_size,
        method,
        method_byte,
        compression_version: unp_version,
        is_dir,
    })
}

fn decode_rar4_name(name_bytes: &[u8], unicode_flag: bool) -> String {
    if !unicode_flag {
        return String::from_utf8_lossy(name_bytes).replace('\\', "/");
    }
    let nul: Option<usize> = name_bytes.iter().position(|&b: &u8| b == 0);
    match nul {
        Some(idx) if idx + 1 < name_bytes.len() => {
            let ascii_part: &[u8] = &name_bytes[..idx];
            let encoded: &[u8] = &name_bytes[idx + 1..];
            decode_rar4_unicode(ascii_part, encoded)
                .unwrap_or_else(|| String::from_utf8_lossy(ascii_part).into_owned())
                .replace('\\', "/")
        }
        _ => String::from_utf8_lossy(name_bytes).replace('\\', "/"),
    }
}

fn decode_rar4_unicode(ascii: &[u8], encoded: &[u8]) -> Option<String> {
    let high_byte: u8 = *encoded.first()?;
    let mut units: Vec<u16> = Vec::new();
    let mut enc_pos: usize = 1;
    let mut flag_bits: u8 = 0;
    let mut flags: u8 = 0;
    let mut name_pos: usize = 0;
    while enc_pos < encoded.len() {
        if flag_bits == 0 {
            flags = encoded[enc_pos];
            enc_pos += 1;
            flag_bits = 8;
        }
        flag_bits -= 2;
        match (flags >> flag_bits) & 0x3 {
            0 => {
                let low: u8 = *encoded.get(enc_pos)?;
                enc_pos += 1;
                units.push(u16::from(low));
                name_pos += 1;
            }
            1 => {
                let low: u8 = *encoded.get(enc_pos)?;
                enc_pos += 1;
                units.push(u16::from(low) | (u16::from(high_byte) << 8));
                name_pos += 1;
            }
            2 => {
                let lo: u8 = *encoded.get(enc_pos)?;
                let hi: u8 = *encoded.get(enc_pos + 1)?;
                enc_pos += 2;
                units.push(u16::from(lo) | (u16::from(hi) << 8));
                name_pos += 1;
            }
            _ => {
                let length: u8 = *encoded.get(enc_pos)?;
                enc_pos += 1;
                let count: usize = (length & 0x7f) as usize + 2;
                if length & 0x80 != 0 {
                    let correction: u8 = *encoded.get(enc_pos)?;
                    enc_pos += 1;
                    for _ in 0..count {
                        let base: u8 = *ascii.get(name_pos)?;
                        units.push(
                            u16::from(base.wrapping_add(correction)) | (u16::from(high_byte) << 8),
                        );
                        name_pos += 1;
                    }
                } else {
                    for _ in 0..count {
                        let base: u8 = *ascii.get(name_pos)?;
                        units.push(u16::from(base));
                        name_pos += 1;
                    }
                }
            }
        }
    }
    Some(String::from_utf16_lossy(&units))
}

pub fn file_data<'a>(bytes: &'a [u8], entry: &RarEntry) -> Result<&'a [u8]> {
    if entry.method != RarMethod::Store {
        return Err(Error::Decompression(format!(
            "rar entry `{}` uses the rar `{}` compression method (rar {} LZ); call entry_bytes to decode it (file_data returns only the verbatim stored slice)",
            entry.name,
            entry.method_label(),
            if entry.compression_version >= 50 {
                "5.0"
            } else {
                "2.9/3.x"
            }
        )));
    }
    packed_slice(bytes, entry)
}

fn packed_slice<'a>(bytes: &'a [u8], entry: &RarEntry) -> Result<&'a [u8]> {
    let start: usize = entry.data_offset as usize;
    let end: usize = start
        .checked_add(entry.packed_size as usize)
        .ok_or_else(|| Error::Decompression("rar file range overflow".to_owned()))?;
    bytes
        .get(start..end)
        .ok_or_else(|| Error::Decompression(format!("rar entry `{}` out of bounds", entry.name)))
}

pub fn entry_bytes(bytes: &[u8], entry: &RarEntry, cap: u64) -> Result<Vec<u8>> {
    let packed: &[u8] = packed_slice(bytes, entry)?;
    if entry.method == RarMethod::Store {
        return Ok(packed.to_vec());
    }
    if entry.compression_version >= 50 {
        return crate::containers::rar_unpack5::unpack5(packed, entry.unpacked_size, cap);
    }
    if entry.compression_version >= 29 {
        return crate::containers::rar_unpack3::unpack3(packed, entry.unpacked_size, cap);
    }
    Err(Error::Decompression(format!(
        "rar entry `{}` uses rar {} lz (method `{}`); only rar 2.9/3.x and rar 5.0 lz are decoded in-tree",
        entry.name,
        entry.compression_version,
        entry.method_label()
    )))
}

#[cfg(test)]
fn write_vint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte: u8 = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[cfg(test)]
pub(crate) fn build_test_rar5_store(name: &str, body: &[u8]) -> Vec<u8> {
    let mut header_body: Vec<u8> = Vec::new();
    write_vint(&mut header_body, HEAD_FILE);
    write_vint(&mut header_body, HEADER_FLAG_DATA);
    write_vint(&mut header_body, body.len() as u64);
    write_vint(&mut header_body, 0);
    write_vint(&mut header_body, body.len() as u64);
    write_vint(&mut header_body, 0);
    write_vint(&mut header_body, 0);
    write_vint(&mut header_body, 0);
    write_vint(&mut header_body, name.len() as u64);
    header_body.extend_from_slice(name.as_bytes());

    let mut block: Vec<u8> = Vec::new();
    block.extend_from_slice(&0u32.to_le_bytes());
    write_vint(&mut block, header_body.len() as u64);
    block.extend_from_slice(&header_body);
    block.extend_from_slice(body);

    let mut end_body: Vec<u8> = Vec::new();
    write_vint(&mut end_body, HEAD_ENDARC);
    write_vint(&mut end_body, 0);
    write_vint(&mut end_body, 0);
    let mut end_block: Vec<u8> = Vec::new();
    end_block.extend_from_slice(&0u32.to_le_bytes());
    write_vint(&mut end_block, end_body.len() as u64);
    end_block.extend_from_slice(&end_body);

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(RAR5_SIGNATURE);
    let mut main_body: Vec<u8> = Vec::new();
    write_vint(&mut main_body, 1);
    write_vint(&mut main_body, 0);
    write_vint(&mut main_body, 0);
    out.extend_from_slice(&0u32.to_le_bytes());
    write_vint(&mut out, main_body.len() as u64);
    out.extend_from_slice(&main_body);
    out.extend_from_slice(&block);
    out.extend_from_slice(&end_block);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_rar5_store(name: &str, body: &[u8]) -> Vec<u8> {
        build_test_rar5_store(name, body)
    }

    #[test]
    fn detects_and_extracts_stored_rar5() {
        let body: &[u8] = b"recovered stored rar payload bytes";
        let image: Vec<u8> = build_rar5_store("docs/notes.txt", body);
        assert!(detect_rar(&image));
        let archive: RarArchive = parse_rar(&image).expect("parse rar5");
        assert_eq!(archive.version, 5);
        assert_eq!(archive.entries.len(), 1);
        let entry: &RarEntry = &archive.entries[0];
        assert_eq!(entry.name, "docs/notes.txt");
        assert_eq!(entry.method, RarMethod::Store);
        let data: &[u8] = file_data(&image, entry).expect("data");
        assert_eq!(data, body);
    }

    fn build_rar4_store(name: &str, body: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(RAR4_SIGNATURE);
        let mut main: Vec<u8> = vec![0x00, 0x00, 0x73, 0x00, 0x00, 0x0d, 0x00];
        main.extend_from_slice(&[0u8; 6]);
        out.extend_from_slice(&main);

        let name_bytes: &[u8] = name.as_bytes();
        let head_size: u16 = (32 + name_bytes.len()) as u16;
        let mut file: Vec<u8> = Vec::new();
        file.extend_from_slice(&[0x00, 0x00]);
        file.push(RAR4_FILE_HEAD);
        file.extend_from_slice(&RAR4_FLAG_ADD_SIZE.to_le_bytes());
        file.extend_from_slice(&head_size.to_le_bytes());
        file.extend_from_slice(&(body.len() as u32).to_le_bytes());
        file.extend_from_slice(&(body.len() as u32).to_le_bytes());
        file.push(0x02);
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.push(20);
        file.push(0x30);
        file.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        file.extend_from_slice(&0x20u32.to_le_bytes());
        file.extend_from_slice(name_bytes);
        out.extend_from_slice(&file);
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn detects_and_extracts_stored_rar4() {
        let body: &[u8] = b"rar4 stored payload bytes recovered verbatim";
        let image: Vec<u8> = build_rar4_store("hello.txt", body);
        assert!(detect_rar(&image));
        let archive: RarArchive = parse_rar(&image).expect("parse rar4");
        assert_eq!(archive.version, 4);
        assert_eq!(archive.entries.len(), 1);
        let entry: &RarEntry = &archive.entries[0];
        assert_eq!(entry.name, "hello.txt");
        assert_eq!(entry.method, RarMethod::Store);
        assert_eq!(entry.method_byte, 0x30);
        assert_eq!(entry.unpacked_size, body.len() as u64);
        let data: &[u8] = file_data(&image, entry).expect("data");
        assert_eq!(data, body);
    }

    #[test]
    fn rejects_non_rar() {
        assert!(!detect_rar(&[0u8; 16]));
        assert!(parse_rar(&[0u8; 16]).is_err());
    }

    #[test]
    fn rar5_vint_rejects_tenth_group_overflow() {
        let bytes: [u8; 10] = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        let mut reader: ByteReader<'_> = ByteReader::new(&bytes);
        assert_eq!(read_rar5_vint(&mut reader), None);
    }

    #[test]
    fn compressed_entry_reports_named_method_gap() {
        let entry: RarEntry = RarEntry {
            name: "x".to_owned(),
            data_offset: 0,
            packed_size: 0,
            unpacked_size: 0,
            method: RarMethod::Compressed,
            method_byte: 0x33,
            compression_version: 29,
            is_dir: false,
        };
        let err: Error = file_data(&[0u8; 8], &entry).unwrap_err();
        let msg: String = format!("{err}");
        assert!(msg.contains("normal"), "must name the method: {msg}");
    }

    #[test]
    fn truncated_rar_does_not_panic() {
        let full: Vec<u8> = build_rar5_store("a.bin", b"alpha-bravo-charlie");
        for cut in (8..full.len()).step_by(3) {
            let _ = parse_rar5(&full[..cut]);
        }
        let full4: Vec<u8> = build_rar4_store("a.bin", b"alpha-bravo-charlie");
        for cut in (7..full4.len()).step_by(3) {
            let _ = parse_rar4(&full4[..cut]);
        }
    }
}
