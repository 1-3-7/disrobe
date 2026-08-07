use std::io::Read;

use crate::containers::lha_dyn::{self, DynMethod};
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LzhFile {
    pub path: String,
    pub method: String,
    pub original_size: u64,
    pub is_directory: bool,
    pub decoder_supported: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LzhArchive {
    pub files: Vec<LzhFile>,
    pub notes: Vec<String>,
}

const LZH_METHOD_OFFSET: usize = 2;
const LZH_METHOD_LEN: usize = 5;

#[must_use]
pub fn detect_lzh(bytes: &[u8]) -> bool {
    if bytes.len() < LZH_METHOD_OFFSET + LZH_METHOD_LEN {
        return false;
    }
    let tag: &[u8] = &bytes[LZH_METHOD_OFFSET..LZH_METHOD_OFFSET + LZH_METHOD_LEN];
    matches!(
        tag,
        b"-lh0-"
            | b"-lh1-"
            | b"-lh2-"
            | b"-lh3-"
            | b"-lh4-"
            | b"-lh5-"
            | b"-lh6-"
            | b"-lh7-"
            | b"-lhd-"
            | b"-lhx-"
            | b"-lz4-"
            | b"-lz5-"
            | b"-lzs-"
            | b"-pm0-"
            | b"-pm1-"
            | b"-pm2-"
    )
}

struct LzhMember<'a> {
    method: [u8; 5],
    name: String,
    original_size: u64,
    is_directory: bool,
    header: &'a [u8],
    body: &'a [u8],
}

const fn dyn_method(method: [u8; 5]) -> Option<DynMethod> {
    match &method {
        b"-lh2-" => Some(DynMethod::Lh2),
        b"-lh3-" => Some(DynMethod::Lh3),
        _ => None,
    }
}

fn walk_members(bytes: &[u8]) -> Result<Vec<LzhMember<'_>>> {
    let mut members: Vec<LzhMember<'_>> = Vec::new();
    let mut pos: usize = 0;
    while pos < bytes.len() {
        let header_len: usize = bytes[pos] as usize;
        if header_len == 0 {
            break;
        }
        let level: u8 = *bytes
            .get(pos + 20)
            .ok_or_else(|| Error::Lzh("lzh: truncated base header".to_owned()))?;
        let mut method: [u8; 5] = [0; 5];
        method.copy_from_slice(
            bytes
                .get(pos + 2..pos + 7)
                .ok_or_else(|| Error::Lzh("lzh: truncated method tag".to_owned()))?,
        );
        let compressed_size: u64 = u64::from(read_u32(bytes, pos + 7)?);
        let original_size: u64 = u64::from(read_u32(bytes, pos + 11)?);

        let (header_end, body_len): (usize, u64) = match level {
            0 => (pos + 2 + header_len, compressed_size),
            1 => {
                let base_end: usize = pos + 2 + header_len;
                let first_ext_len: usize = usize::from(read_u16(bytes, base_end - 2)?);
                let ext_end: usize = skip_ext_headers(bytes, base_end, first_ext_len)?;
                let ext_total: u64 = (ext_end - base_end) as u64;
                let body_len: u64 = compressed_size.saturating_sub(ext_total);
                (ext_end, body_len)
            }
            2 => {
                let word_len: usize = usize::from(read_u16(bytes, pos)?);
                if word_len < 2 {
                    return Err(Error::Lzh("lzh: invalid level-2 header size".to_owned()));
                }
                (pos + word_len, compressed_size)
            }
            _ => return Err(Error::Lzh(format!("lzh: unsupported header level {level}"))),
        };

        let name: String = parse_name(bytes, pos, level, header_len);
        let is_directory: bool = &method == b"-lhd-";

        let body_start: usize = header_end;
        let body_end: usize = body_start
            .checked_add(usize::try_from(body_len).map_or(usize::MAX, |value: usize| value))
            .ok_or_else(|| Error::Lzh("lzh: body length overflow".to_owned()))?;
        if body_end > bytes.len() || body_start > bytes.len() {
            return Err(Error::Lzh("lzh: member body runs past end".to_owned()));
        }
        let header: &[u8] = &bytes[pos..body_start];
        let body: &[u8] = &bytes[body_start..body_end];
        members.push(LzhMember {
            method,
            name,
            original_size,
            is_directory,
            header,
            body,
        });
        pos = body_end;
    }
    if members.is_empty() {
        return Err(Error::Lzh("lzh: archive contains no members".to_owned()));
    }
    Ok(members)
}

fn parse_name(bytes: &[u8], pos: usize, level: u8, header_len: usize) -> String {
    if level >= 2 {
        return String::new();
    }
    let name_len: usize = usize::from(bytes.get(pos + 21).copied().map_or(0, |value: u8| value));
    let start: usize = pos + 22;
    let available: usize = (pos + 2 + header_len).min(bytes.len());
    let end: usize = (start + name_len).min(available);
    if start >= end {
        return String::new();
    }
    bytes
        .get(start..end)
        .map_or_else(String::new, |raw: &[u8]| {
            String::from_utf8_lossy(raw).into_owned()
        })
}

fn skip_ext_headers(bytes: &[u8], start: usize, first_len: usize) -> Result<usize> {
    let mut cursor: usize = start;
    let mut next_len: usize = first_len;
    while next_len != 0 {
        if next_len < 2 {
            return Err(Error::Lzh("lzh: malformed extended header".to_owned()));
        }
        let end: usize = cursor
            .checked_add(next_len)
            .ok_or_else(|| Error::Lzh("lzh: extended header overflow".to_owned()))?;
        if end > bytes.len() {
            return Err(Error::Lzh("lzh: extended header runs past end".to_owned()));
        }
        next_len = usize::from(read_u16(bytes, end - 2)?);
        cursor = end;
    }
    Ok(cursor)
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16> {
    disrobe_bytes::read_u16_le_at(bytes, at)
        .map_err(|_| Error::Lzh("lzh: truncated u16 field".to_owned()))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    disrobe_bytes::read_u32_le_at(bytes, at)
        .map_err(|_| Error::Lzh("lzh: truncated u32 field".to_owned()))
}

fn decode_via_delharc(
    member: &LzhMember<'_>,
    max_output: u64,
) -> std::result::Result<Vec<u8>, (bool, String)> {
    let mut archive: Vec<u8> = Vec::with_capacity(member.header.len() + member.body.len() + 1);
    archive.extend_from_slice(member.header);
    archive.extend_from_slice(member.body);
    archive.push(0);
    let mut reader: delharc::LhaDecodeReader<&[u8]> =
        delharc::LhaDecodeReader::new(archive.as_slice()).map_err(|e| (false, e.to_string()))?;
    if !reader.is_decoder_supported() {
        return Err((false, "method not supported by in-tree decoder".to_owned()));
    }
    let mut data: Vec<u8> = Vec::new();
    let read: usize = reader
        .by_ref()
        .take(max_output.saturating_add(1u64))
        .read_to_end(&mut data)
        .map_err(|e| (true, e.to_string()))?;
    let read_u64: u64 =
        u64::try_from(read).map_err(|_| (true, "decoded member length exceeds u64".to_owned()))?;
    if read_u64 > max_output {
        return Err((
            true,
            format!("decoded member exceeds declared size {max_output}"),
        ));
    }
    Ok(data)
}

pub fn parse_lzh(bytes: &[u8], max_total: u64) -> Result<LzhArchive> {
    let members: Vec<LzhMember<'_>> = walk_members(bytes)?;
    let mut files: Vec<LzhFile> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut total: u64 = 0;
    for member in &members {
        let method: String = String::from_utf8_lossy(&member.method).into_owned();
        let path: String = member.name.clone();
        if member.is_directory {
            files.push(LzhFile {
                path,
                method,
                original_size: member.original_size,
                is_directory: true,
                decoder_supported: false,
                data: Vec::new(),
            });
            continue;
        }
        total = total.saturating_add(member.original_size);
        if total > max_total {
            return Err(Error::Lzh(format!(
                "lzh: decompressed size exceeds quota ({total} > {max_total})"
            )));
        }
        let (data, supported): (Vec<u8>, bool) = if let Some(dm) = dyn_method(member.method) {
            match lha_dyn::decode(dm, member.body, member.original_size) {
                Ok(d) => (d, true),
                Err(e) => {
                    notes.push(format!("lzh `{path}`: {method} decode: {e}"));
                    (Vec::new(), false)
                }
            }
        } else {
            match decode_via_delharc(member, member.original_size) {
                Ok(d) => (d, true),
                Err((true, e)) => {
                    notes.push(format!("lzh `{path}`: decode: {e}"));
                    (Vec::new(), false)
                }
                Err((false, _)) => {
                    notes.push(format!(
                        "lzh `{path}`: compression method `{method}` not decodable in-tree (carve-only)"
                    ));
                    (Vec::new(), false)
                }
            }
        };
        files.push(LzhFile {
            path,
            method,
            original_size: member.original_size,
            is_directory: false,
            decoder_supported: supported,
            data,
        });
    }
    Ok(LzhArchive { files, notes })
}

#[cfg(test)]
pub(crate) fn lha_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
pub(crate) fn build_stored_lzh(name: &str, body: &[u8]) -> Option<Vec<u8>> {
    let name_len: u8 = u8::try_from(name.len()).ok()?;
    let size: u32 = u32::try_from(body.len()).ok()?;
    let header_len: u8 = u8::try_from(22usize.checked_add(name.len())?).ok()?;
    let mut out: Vec<u8> = Vec::with_capacity(usize::from(header_len) + 2 + body.len() + 1);
    out.push(header_len);
    out.push(0);
    out.extend_from_slice(b"-lh0-");
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.push(0x20);
    out.push(0);
    out.push(name_len);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&lha_crc16(body).to_le_bytes());
    out[1] = out[2..]
        .iter()
        .fold(0u8, |acc: u8, &b: &u8| acc.wrapping_add(b));
    out.extend_from_slice(body);
    out.push(0);
    Some(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_recognizes_lh5_at_offset_two() {
        let mut bytes: Vec<u8> = vec![0x20, 0x00];
        bytes.extend_from_slice(b"-lh5-");
        bytes.extend([0u8; 16]);
        assert!(detect_lzh(&bytes));
    }

    #[test]
    fn detect_recognizes_lh2_and_lh3() {
        for tag in [b"-lh2-", b"-lh3-"] {
            let mut bytes: Vec<u8> = vec![0x20, 0x00];
            bytes.extend_from_slice(tag);
            bytes.extend([0u8; 16]);
            assert!(detect_lzh(&bytes));
        }
    }

    #[test]
    fn detect_rejects_unrelated() {
        assert!(!detect_lzh(b"PK\x03\x04 not an lzh"));
    }

    #[test]
    fn parse_lzh_decodes_lh2_member_to_known_crc() {
        let archive: &[u8] = include_bytes!("../../tests/fixtures/lzh/lh2.lzh");
        let parsed: LzhArchive = parse_lzh(archive, 64 * 1024 * 1024).expect("parse lh2");
        let file: &LzhFile = parsed.files.first().expect("one member");
        assert_eq!(file.method, "-lh2-");
        assert!(file.decoder_supported);
        assert_eq!(file.data.len() as u64, file.original_size);
        assert_eq!(lha_crc16(&file.data), 0xd157);
    }

    #[test]
    fn parse_lzh_decodes_lh3_member() {
        let archive: &[u8] = include_bytes!("../../tests/fixtures/lzh/lh3.lzh");
        let parsed: LzhArchive = parse_lzh(archive, 64 * 1024 * 1024).expect("parse lh3");
        let file: &LzhFile = parsed.files.first().expect("one member");
        assert_eq!(file.method, "-lh3-");
        assert!(file.decoder_supported);
        let lh2: &[u8] = include_bytes!("../../tests/fixtures/lzh/lh2.lzh");
        let lh2_parsed: LzhArchive = parse_lzh(lh2, 64 * 1024 * 1024).expect("parse lh2");
        assert_eq!(file.data, lh2_parsed.files[0].data);
    }

    #[test]
    fn parse_lzh_decodes_lh5_via_delharc_path() {
        let archive: &[u8] = include_bytes!("../../tests/fixtures/lzh/lh5_222.lzh");
        let parsed: LzhArchive = parse_lzh(archive, 64 * 1024 * 1024).expect("parse lh5");
        let file: &LzhFile = parsed
            .files
            .iter()
            .find(|f| !f.is_directory)
            .expect("member");
        assert_eq!(file.method, "-lh5-");
        assert!(file.decoder_supported);
        assert_eq!(file.data.len() as u64, file.original_size);
    }

    #[test]
    fn delharc_fallback_rejects_output_past_declared_size() {
        let archive: &[u8] = include_bytes!("../../tests/fixtures/lzh/lh5_222.lzh");
        let members: Vec<LzhMember<'_>> = walk_members(archive).expect("walk lh5");
        let err: (bool, String) =
            decode_via_delharc(&members[0], 1u64).expect_err("one-byte cap must fail");
        assert!(err.0);
        assert!(err.1.contains("declared size"));
    }
}
