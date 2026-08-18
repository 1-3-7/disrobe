use std::io::{Cursor, Read};

use crate::containers::lha_dyn::{self, DynMethod};
use crate::containers::pmarc::{self, PmMethod};
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LzhFile {
    pub path: String,
    pub method: String,
    pub header_level: u8,
    pub compressed_size: u64,
    pub original_size: u64,
    pub unix_permissions: Option<u16>,
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
    header_level: u8,
    name: String,
    compressed_size: u64,
    original_size: u64,
    file_crc: u16,
    unix_permissions: Option<u16>,
    is_directory: bool,
    encoded: &'a [u8],
    body: &'a [u8],
}

const MAX_LZH_HEADER_BYTES: usize = 1024 * 1024;
const MAX_LZH_MEMBERS: usize = 65_535;

const fn dyn_method(method: [u8; 5]) -> Option<DynMethod> {
    match &method {
        b"-lh2-" => Some(DynMethod::Lh2),
        b"-lh3-" => Some(DynMethod::Lh3),
        _ => None,
    }
}

const fn pm_method(method: [u8; 5]) -> Option<PmMethod> {
    match &method {
        b"-pm1-" => Some(PmMethod::Pm1),
        b"-pm2-" => Some(PmMethod::Pm2),
        _ => None,
    }
}

fn walk_members(bytes: &[u8], max_entries: usize) -> Result<Vec<LzhMember<'_>>> {
    let mut members: Vec<LzhMember<'_>> = Vec::new();
    let mut pos: usize = 0;
    while pos < bytes.len() {
        let member_cap: usize = max_entries.min(MAX_LZH_MEMBERS);
        if members.len() >= member_cap {
            return Err(Error::Lzh(format!(
                "lzh: member count exceeds cap {member_cap}"
            )));
        }
        let Some(header_end): Option<usize> = preflight_header(bytes, pos)? else {
            break;
        };
        let mut cursor: Cursor<&[u8]> = Cursor::new(&bytes[pos..header_end]);
        let header: delharc::LhaHeader = delharc::LhaHeader::read(&mut cursor)
            .map_err(|error| Error::Lzh(format!("lzh: invalid header: {error}")))?
            .ok_or_else(|| Error::Lzh("lzh: missing member header".to_owned()))?;
        let consumed: usize = usize::try_from(cursor.position())
            .map_err(|_| Error::Lzh("lzh: header position exceeds usize".to_owned()))?;
        if consumed != header_end - pos {
            return Err(Error::Lzh("lzh: header extent mismatch".to_owned()));
        }
        if is_multidisc(&header) {
            return Err(Error::Lzh(
                "lzh: member requires another archive volume".to_owned(),
            ));
        }
        let method: [u8; 5] = header.compression;
        let compressed_size: u64 = header.compressed_size;
        let original_size: u64 = header.original_size;
        let body_len: u64 = compressed_size;
        let resolved_name: String = resolve_member_name(&header)?;
        let unix_permissions: Option<u16> = resolve_unix_permissions(&header)?;
        let is_directory: bool = lhd_is_directory(&header, unix_permissions, &resolved_name)?;

        let body_start: usize = header_end;
        let body_len_usize: usize = usize::try_from(body_len)
            .map_err(|_| Error::Lzh("lzh: body length exceeds usize".to_owned()))?;
        let body_end: usize = body_start
            .checked_add(body_len_usize)
            .ok_or_else(|| Error::Lzh("lzh: body length overflow".to_owned()))?;
        if body_end > bytes.len() || body_start > bytes.len() {
            return Err(Error::Lzh("lzh: member body runs past end".to_owned()));
        }
        let encoded: &[u8] = &bytes[pos..body_end];
        let body: &[u8] = &bytes[body_start..body_end];
        members.push(LzhMember {
            method,
            header_level: header.level,
            name: resolved_name,
            compressed_size,
            original_size,
            file_crc: header.file_crc,
            unix_permissions,
            is_directory,
            encoded,
            body,
        });
        pos = body_end;
    }
    if members.is_empty() {
        return Err(Error::Lzh("lzh: archive contains no members".to_owned()));
    }
    Ok(members)
}

fn is_multidisc(header: &delharc::LhaHeader) -> bool {
    header
        .iter_extra()
        .any(|extra: &[u8]| extra.first() == Some(&0x39))
}

fn lhd_is_directory(
    header: &delharc::LhaHeader,
    unix_permissions: Option<u16>,
    name: &str,
) -> Result<bool> {
    if header.compression != *b"-lhd-" {
        return Ok(false);
    }
    let file_type: u16 = unix_permissions.map_or(0, |mode: u16| mode & 0o170_000);
    if file_type == 0o120_000 || name.contains('|') {
        return Err(Error::Lzh(format!(
            "lzh: symbolic link member `{name}` is not extracted"
        )));
    }
    if header.compressed_size != 0 || header.original_size != 0 {
        return Err(Error::Lzh(format!(
            "lzh: nonempty LHD member `{name}` cannot be proven to be a directory"
        )));
    }
    if !matches!(file_type, 0 | 0o040_000) {
        return Err(Error::Lzh(format!(
            "lzh: LHD member `{name}` has unsupported Unix file type {file_type:#07o}"
        )));
    }
    Ok(true)
}

fn resolve_unix_permissions(header: &delharc::LhaHeader) -> Result<Option<u16>> {
    let mut permissions: Option<u16> = None;
    for extra in header.iter_extra() {
        let Some((&kind, data)): Option<(&u8, &[u8])> = extra.split_first() else {
            return Err(Error::Lzh("lzh: empty extended header".to_owned()));
        };
        if kind != 0x50 {
            continue;
        }
        let raw: [u8; 2] = data
            .try_into()
            .map_err(|_| Error::Lzh("lzh: malformed Unix permissions header".to_owned()))?;
        if permissions.replace(u16::from_le_bytes(raw)).is_some() {
            return Err(Error::Lzh(
                "lzh: duplicate Unix permissions header".to_owned(),
            ));
        }
    }
    Ok(permissions)
}

fn resolve_member_name(header: &delharc::LhaHeader) -> Result<String> {
    let mut byte_filename: Option<&[u8]> = None;
    let mut byte_directory: Option<&[u8]> = None;
    let mut unicode_filename: Option<&[u8]> = None;
    let mut unicode_directory: Option<&[u8]> = None;
    let mut codepage: Option<u32> = None;
    for extra in header.iter_extra() {
        let Some((&kind, data)): Option<(&u8, &[u8])> = extra.split_first() else {
            return Err(Error::Lzh("lzh: empty extended header".to_owned()));
        };
        let slot: Option<&mut Option<&[u8]>> = match kind {
            0x01 => Some(&mut byte_filename),
            0x02 => Some(&mut byte_directory),
            0x44 => Some(&mut unicode_filename),
            0x45 => Some(&mut unicode_directory),
            _ => None,
        };
        if let Some(slot) = slot
            && slot.replace(data).is_some()
        {
            return Err(Error::Lzh(format!(
                "lzh: duplicate name extended header {kind:#04x}"
            )));
        }
        if kind == 0x46 {
            if codepage.is_some() || data.len() != 4 {
                return Err(Error::Lzh("lzh: malformed codepage header".to_owned()));
            }
            let raw: [u8; 4] = data
                .try_into()
                .map_err(|_| Error::Lzh("lzh: malformed codepage header".to_owned()))?;
            codepage = Some(u32::from_le_bytes(raw));
        }
    }
    let filename: String = match (unicode_filename, byte_filename) {
        (Some(raw), _) if !raw.is_empty() => decode_utf16_component(raw, false)?,
        (None, Some(raw)) if !raw.is_empty() => decode_legacy_component(raw, codepage, false)?,
        (Some(_), _) | (None, Some(_)) if header.is_directory() => String::new(),
        (Some(_), _) | (None, Some(_)) => {
            return Err(Error::Lzh(
                "lzh: regular member has an empty path".to_owned(),
            ));
        }
        (None, None) if header.is_directory() && header.filename.is_empty() => String::new(),
        (None, None) => decode_legacy_base(&header.filename, codepage)?,
    };
    let directory: String = if let Some(raw) = unicode_directory {
        decode_utf16_component(raw, true)?
    } else if let Some(raw) = byte_directory {
        decode_legacy_component(raw, codepage, true)?
    } else {
        String::new()
    };
    if filename.is_empty() && !header.is_directory() {
        return Err(Error::Lzh(
            "lzh: regular member has an empty path".to_owned(),
        ));
    }
    let path: String = if directory.is_empty() {
        filename
    } else if filename.is_empty() {
        directory
    } else {
        format!("{directory}/{filename}")
    };
    Ok(path)
}

fn decode_utf16_component(raw: &[u8], directory: bool) -> Result<String> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(Error::Lzh("lzh: malformed UTF-16 name".to_owned()));
    }
    let mut words: Vec<u16> = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let word: u16 = u16::from_le_bytes([pair[0], pair[1]]);
        if word == 0 {
            return Err(Error::Lzh("lzh: name contains an embedded NUL".to_owned()));
        }
        words.push(word);
    }
    decode_utf16_words(&words, directory)
}

fn decode_utf16_words(words: &[u16], directory: bool) -> Result<String> {
    let components: &[u16] = if directory {
        let Some((&0xffff, components)): Option<(&u16, &[u16])> = words.split_last() else {
            return Err(Error::Lzh(
                "lzh: UTF-16 directory lacks its trailing separator".to_owned(),
            ));
        };
        components
    } else {
        words
    };
    let mut path: String = String::new();
    for (index, component) in components.split(|word: &u16| *word == 0xffff).enumerate() {
        if component.is_empty() {
            return Err(Error::Lzh(
                "lzh: UTF-16 path has an empty component".to_owned(),
            ));
        }
        let decoded: String = String::from_utf16(component)
            .map_err(|_| Error::Lzh("lzh: malformed UTF-16 name".to_owned()))?;
        if decoded.contains(['/', '\\']) {
            return Err(Error::Lzh(
                "lzh: UTF-16 path contains a non-LHA separator".to_owned(),
            ));
        }
        if index != 0 {
            path.push('/');
        }
        path.push_str(&decoded);
    }
    Ok(path)
}

fn decode_legacy_component(raw: &[u8], codepage: Option<u32>, directory: bool) -> Result<String> {
    let components: &[u8] = if directory {
        let Some((&0xff, components)): Option<(&u8, &[u8])> = raw.split_last() else {
            return Err(Error::Lzh(
                "lzh: byte directory lacks its trailing separator".to_owned(),
            ));
        };
        components
    } else {
        raw
    };
    let mut path: String = String::new();
    for (index, component) in components.split(|byte: &u8| *byte == 0xff).enumerate() {
        if component.is_empty() {
            return Err(Error::Lzh(
                "lzh: byte path has an empty component".to_owned(),
            ));
        }
        let decoded: String = decode_codepage(component, codepage)?;
        if decoded.contains(['/', '\\']) {
            return Err(Error::Lzh(
                "lzh: byte path contains a non-LHA separator".to_owned(),
            ));
        }
        if index != 0 {
            path.push('/');
        }
        path.push_str(&decoded);
    }
    Ok(path)
}

fn decode_legacy_base(raw: &[u8], codepage: Option<u32>) -> Result<String> {
    if let Some(codepage) = codepage {
        if let Some(encoding) = encoding_for_codepage(codepage) {
            let decoded: String = encoding
                .decode_without_bom_handling_and_without_replacement(raw)
                .map(|value: std::borrow::Cow<'_, str>| value.into_owned())
                .ok_or_else(|| Error::Lzh(format!("lzh: malformed codepage {codepage} name")))?;
            return Ok(normalize_decoded_base(&decoded));
        }
    } else if raw.is_ascii() {
        let decoded: &str = std::str::from_utf8(raw)
            .map_err(|_| Error::Lzh("lzh: malformed ASCII name".to_owned()))?;
        return Ok(normalize_decoded_base(decoded));
    }
    let mut path: String = String::new();
    for (index, component) in raw.split(|byte: &u8| *byte == 0xff).enumerate() {
        if component.is_empty() {
            return Err(Error::Lzh(
                "lzh: byte path has an empty component".to_owned(),
            ));
        }
        let decoded: String = percent_encode_legacy(component);
        if index != 0 {
            path.push('/');
        }
        path.push_str(&decoded);
    }
    Ok(path)
}

fn normalize_decoded_base(decoded: &str) -> String {
    decoded.replace('\\', "/")
}

fn decode_codepage(raw: &[u8], codepage: Option<u32>) -> Result<String> {
    let Some(codepage) = codepage else {
        return Ok(percent_encode_legacy(raw));
    };
    let Some(encoding) = encoding_for_codepage(codepage) else {
        return Ok(percent_encode_legacy(raw));
    };
    encoding
        .decode_without_bom_handling_and_without_replacement(raw)
        .map(|decoded: std::borrow::Cow<'_, str>| decoded.into_owned())
        .ok_or_else(|| Error::Lzh(format!("lzh: malformed codepage {codepage} name")))
}

fn encoding_for_codepage(codepage: u32) -> Option<&'static encoding_rs::Encoding> {
    let label: String = match codepage {
        65001 => Some("utf-8".to_owned()),
        932 => Some("shift_jis".to_owned()),
        936 => Some("gbk".to_owned()),
        949 => Some("euc-kr".to_owned()),
        950 => Some("big5".to_owned()),
        866 => Some("ibm866".to_owned()),
        20866 => Some("koi8-r".to_owned()),
        21866 => Some("koi8-u".to_owned()),
        1250..=1258 => Some(format!("windows-{codepage}")),
        _ => None,
    }?;
    encoding_rs::Encoding::for_label(label.as_bytes())
}

fn percent_encode_legacy(raw: &[u8]) -> String {
    let mut encoded: String = String::with_capacity(raw.len());
    for &byte in raw {
        if byte == 0 {
            encoded.push('\0');
        } else if byte.is_ascii_graphic() && !matches!(byte, b'%' | b'/' | b'\\') {
            encoded.push(char::from(byte));
        } else if byte == b' ' {
            encoded.push(' ');
        } else {
            use std::fmt::Write as _;
            let _: std::fmt::Result = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn preflight_header(bytes: &[u8], pos: usize) -> Result<Option<usize>> {
    let Some(&header_len): Option<&u8> = bytes.get(pos) else {
        return Ok(None);
    };
    if header_len == 0 {
        return Ok(None);
    }
    let level_offset: usize = pos
        .checked_add(20)
        .ok_or_else(|| Error::Lzh("lzh: header offset overflow".to_owned()))?;
    let level: u8 = *bytes
        .get(level_offset)
        .ok_or_else(|| Error::Lzh("lzh: truncated base header".to_owned()))?;
    let header_end: usize = match level {
        0 => pos
            .checked_add(usize::from(header_len) + 2)
            .ok_or_else(|| Error::Lzh("lzh: header length overflow".to_owned()))?,
        1 => {
            let base_end: usize = pos
                .checked_add(usize::from(header_len) + 2)
                .ok_or_else(|| Error::Lzh("lzh: header length overflow".to_owned()))?;
            let first_len_at: usize = base_end
                .checked_sub(2)
                .ok_or_else(|| Error::Lzh("lzh: level-1 header underflow".to_owned()))?;
            let first_len: usize = usize::from(read_u16(bytes, first_len_at)?);
            skip_ext_headers(bytes, pos, base_end, first_len, 2, bytes.len())?
        }
        2 => {
            let extent: usize = usize::from(read_u16(bytes, pos)?);
            let end: usize = pos
                .checked_add(extent)
                .ok_or_else(|| Error::Lzh("lzh: header length overflow".to_owned()))?;
            if extent < 26 {
                return Err(Error::Lzh("lzh: level-2 header is too short".to_owned()));
            }
            let first_len_at: usize = pos
                .checked_add(24)
                .ok_or_else(|| Error::Lzh("lzh: header position overflow".to_owned()))?;
            let extra_start: usize = pos
                .checked_add(26)
                .ok_or_else(|| Error::Lzh("lzh: header position overflow".to_owned()))?;
            let first_len: usize = usize::from(read_u16(bytes, first_len_at)?);
            let _: usize = skip_ext_headers(bytes, pos, extra_start, first_len, 2, end)?;
            end
        }
        3 => {
            let checksum_at: usize = pos
                .checked_add(1)
                .ok_or_else(|| Error::Lzh("lzh: header position overflow".to_owned()))?;
            if header_len != 4 || bytes.get(checksum_at) != Some(&0) {
                return Err(Error::Lzh(
                    "lzh: invalid level-3 fixed-width marker".to_owned(),
                ));
            }
            let extent_at: usize = pos
                .checked_add(24)
                .ok_or_else(|| Error::Lzh("lzh: header position overflow".to_owned()))?;
            let first_len_at: usize = pos
                .checked_add(28)
                .ok_or_else(|| Error::Lzh("lzh: header position overflow".to_owned()))?;
            let extra_start: usize = pos
                .checked_add(32)
                .ok_or_else(|| Error::Lzh("lzh: header position overflow".to_owned()))?;
            let extent: usize = usize::try_from(read_u32(bytes, extent_at)?)
                .map_err(|_| Error::Lzh("lzh: header length exceeds usize".to_owned()))?;
            let end: usize = pos
                .checked_add(extent)
                .ok_or_else(|| Error::Lzh("lzh: header length overflow".to_owned()))?;
            if extent < 32 {
                return Err(Error::Lzh("lzh: level-3 header is too short".to_owned()));
            }
            let first_len: usize = usize::try_from(read_u32(bytes, first_len_at)?)
                .map_err(|_| Error::Lzh("lzh: extended header exceeds usize".to_owned()))?;
            let _: usize = skip_ext_headers(bytes, pos, extra_start, first_len, 4, end)?;
            end
        }
        _ => return Err(Error::Lzh(format!("lzh: unsupported header level {level}"))),
    };
    let extent: usize = header_end
        .checked_sub(pos)
        .ok_or_else(|| Error::Lzh("lzh: header extent underflow".to_owned()))?;
    if extent > MAX_LZH_HEADER_BYTES {
        return Err(Error::Lzh(format!(
            "lzh: header extent {extent} exceeds cap {MAX_LZH_HEADER_BYTES}"
        )));
    }
    if extent < 2 || header_end > bytes.len() {
        return Err(Error::Lzh("lzh: header runs past end".to_owned()));
    }
    Ok(Some(header_end))
}

fn skip_ext_headers(
    bytes: &[u8],
    member_start: usize,
    start: usize,
    first_len: usize,
    length_bytes: usize,
    declared_end: usize,
) -> Result<usize> {
    let mut cursor: usize = start;
    let mut next_len: usize = first_len;
    while next_len != 0 {
        if next_len <= length_bytes {
            return Err(Error::Lzh("lzh: malformed extended header".to_owned()));
        }
        let end: usize = cursor
            .checked_add(next_len)
            .ok_or_else(|| Error::Lzh("lzh: extended header overflow".to_owned()))?;
        let extent: usize = end
            .checked_sub(member_start)
            .ok_or_else(|| Error::Lzh("lzh: extended header underflow".to_owned()))?;
        if extent > MAX_LZH_HEADER_BYTES {
            return Err(Error::Lzh(format!(
                "lzh: header extent {extent} exceeds cap {MAX_LZH_HEADER_BYTES}"
            )));
        }
        if end > declared_end || end > bytes.len() || end < length_bytes {
            return Err(Error::Lzh("lzh: extended header runs past end".to_owned()));
        }
        let next_len_at: usize = end
            .checked_sub(length_bytes)
            .ok_or_else(|| Error::Lzh("lzh: extended header underflow".to_owned()))?;
        next_len = match length_bytes {
            2 => usize::from(read_u16(bytes, next_len_at)?),
            4 => usize::try_from(read_u32(bytes, next_len_at)?)
                .map_err(|_| Error::Lzh("lzh: extended header exceeds usize".to_owned()))?,
            _ => return Err(Error::Lzh("lzh: invalid extended header width".to_owned())),
        };
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
    let mut reader: delharc::LhaDecodeReader<&[u8]> =
        delharc::LhaDecodeReader::new(member.encoded).map_err(|e| (false, e.to_string()))?;
    if !reader.is_decoder_supported() {
        return Err((false, "method not supported by in-tree decoder".to_owned()));
    }
    let mut data: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(max_output));
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
    reader
        .crc_check()
        .map_err(|error| (true, error.to_string()))?;
    let remaining: &[u8] = reader
        .take_inner()
        .ok_or_else(|| (true, "decoder input is unavailable".to_owned()))?;
    if !remaining.is_empty() {
        return Err((
            true,
            format!("decoder left {} compressed byte(s) unread", remaining.len()),
        ));
    }
    Ok(data)
}

pub(crate) fn parse_lzh_with_quota(
    bytes: &[u8],
    quota: crate::quota::ExtractionQuota,
) -> Result<LzhArchive> {
    let members: Vec<LzhMember<'_>> = walk_members(bytes, quota.max_entries)?;
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut safe_paths: Vec<Option<String>> = Vec::with_capacity(members.len());
    let mut notes: Vec<String> = Vec::new();
    for member in &members {
        match crate::quota::sanitize_entry_path(&member.name) {
            Ok(path) => {
                if !member.is_directory {
                    let collision_key: String = path.to_ascii_lowercase();
                    if !names.insert(collision_key) {
                        return Err(Error::Lzh(format!(
                            "lzh: duplicate normalized output path `{path}`"
                        )));
                    }
                }
                safe_paths.push(Some(path));
            }
            Err(error) => {
                notes.push(format!("lzh-slip: {error}"));
                safe_paths.push(None);
            }
        }
    }
    let mut files: Vec<LzhFile> = Vec::new();
    let mut guard: crate::quota::QuotaGuard = crate::quota::QuotaGuard::new(quota);
    for (member, safe_path) in members.iter().zip(safe_paths) {
        let Some(path): Option<String> = safe_path else {
            continue;
        };
        let method: String = String::from_utf8_lossy(&member.method).into_owned();
        if member.is_directory {
            files.push(LzhFile {
                path,
                method,
                header_level: member.header_level,
                compressed_size: member.compressed_size,
                original_size: member.original_size,
                unix_permissions: member.unix_permissions,
                is_directory: true,
                decoder_supported: false,
                data: Vec::new(),
            });
            continue;
        }
        guard.admit_entry(&path, member.original_size, member.compressed_size)?;
        let (data, supported): (Vec<u8>, bool) = if let Some(dm) = dyn_method(member.method) {
            let max_output: u64 = quota
                .max_per_entry_uncompressed
                .min(quota.max_total_uncompressed);
            match lha_dyn::decode_bounded(dm, member.body, member.original_size, max_output) {
                Ok(d) => (d, true),
                Err(error) => {
                    return Err(Error::Lzh(format!(
                        "lzh `{path}`: {method} decode failed: {error}"
                    )));
                }
            }
        } else if let Some(pm) = pm_method(member.method) {
            let max_output: u64 = quota
                .max_per_entry_uncompressed
                .min(quota.max_total_uncompressed);
            match pmarc::decode_bounded(pm, member.body, member.original_size, max_output) {
                Ok(decoded) => {
                    let unread_bytes: u64 = decoded.unread_bits / 8;
                    if unread_bytes != 0 {
                        notes.push(format!(
                            "lzh `{path}`: {method} member declares {} compressed byte(s) but the decoder consumed {}",
                            member.compressed_size,
                            member.compressed_size.saturating_sub(unread_bytes)
                        ));
                    }
                    (decoded.data, true)
                }
                Err(error) => {
                    return Err(Error::Lzh(format!(
                        "lzh `{path}`: {method} decode failed: {error}"
                    )));
                }
            }
        } else {
            match decode_via_delharc(member, member.original_size) {
                Ok(d) => (d, true),
                Err((true, error)) => {
                    return Err(Error::Lzh(format!("lzh `{path}`: decode failed: {error}")));
                }
                Err((false, _)) => {
                    notes.push(format!(
                        "lzh `{path}`: compression method `{method}` is deferred and the member was omitted"
                    ));
                    (Vec::new(), false)
                }
            }
        };
        if supported {
            let decoded_size: u64 = u64::try_from(data.len())
                .map_err(|_| Error::Lzh("lzh: decoded size exceeds u64".to_owned()))?;
            if decoded_size != member.original_size {
                return Err(Error::Lzh(format!(
                    "lzh `{path}`: decoded size {decoded_size} differs from declared size {}",
                    member.original_size
                )));
            }
            let decoded_crc: u16 = crc16_arc(&data);
            if decoded_crc != member.file_crc {
                return Err(Error::Lzh(format!(
                    "lzh `{path}`: decoded CRC {decoded_crc:04x} differs from declared CRC {:04x}",
                    member.file_crc
                )));
            }
        }
        files.push(LzhFile {
            path,
            method,
            header_level: member.header_level,
            compressed_size: member.compressed_size,
            original_size: member.original_size,
            unix_permissions: member.unix_permissions,
            is_directory: false,
            decoder_supported: supported,
            data,
        });
    }
    Ok(LzhArchive { files, notes })
}

pub fn parse_lzh(bytes: &[u8], max_total: u64) -> Result<LzhArchive> {
    parse_lzh_with_quota(
        bytes,
        crate::quota::ExtractionQuota {
            max_entries: MAX_LZH_MEMBERS,
            max_total_uncompressed: max_total,
            max_per_entry_uncompressed: max_total,
            max_per_entry_ratio: u64::MAX,
            max_aggregate_ratio: u64::MAX,
        },
    )
}

pub(crate) fn crc16_arc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
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
    out.extend_from_slice(&crc16_arc(body).to_le_bytes());
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

    fn header_with_extra(headers: Vec<(u8, Vec<u8>)>) -> delharc::LhaHeader {
        let lengths: Vec<u16> = headers
            .iter()
            .map(|(_kind, data): &(u8, Vec<u8>)| {
                u16::try_from(data.len() + 3).expect("bounded test header")
            })
            .collect();
        let mut extra_headers: Vec<u8> = Vec::new();
        for (index, (kind, data)) in headers.into_iter().enumerate() {
            extra_headers.push(kind);
            extra_headers.extend_from_slice(&data);
            let next: u16 = lengths.get(index + 1).copied().unwrap_or(0);
            extra_headers.extend_from_slice(&next.to_le_bytes());
        }
        delharc::LhaHeader {
            level: 2,
            compression: *b"-lh0-",
            filename: b"base.txt".to_vec().into_boxed_slice(),
            first_header_len: u32::from(lengths.first().copied().unwrap_or(0)),
            extra_headers: extra_headers.into_boxed_slice(),
            ..delharc::LhaHeader::default()
        }
    }

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
        assert_eq!(crc16_arc(&file.data), 0xd157);
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
        let members: Vec<LzhMember<'_>> = walk_members(archive, MAX_LZH_MEMBERS).expect("walk lh5");
        let err: (bool, String) =
            decode_via_delharc(&members[0], 1u64).expect_err("one-byte cap must fail");
        assert!(err.0);
        assert!(err.1.contains("declared size"));
    }

    #[test]
    fn multidisc_extended_header_refuses_the_missing_volume() {
        let archive: &[u8] = include_bytes!("../../tests/fixtures/lzh/level3/h3_lfn.lzh");
        let mut split: Vec<u8> = archive.to_vec();
        split[39] = 0x39;
        split[33..35].fill(0);
        let crc: u16 = crc16_arc(&split[..82]);
        split[33..35].copy_from_slice(&crc.to_le_bytes());
        let error: Error = parse_lzh(&split, 1024).expect_err("require another archive volume");
        assert!(
            error
                .to_string()
                .contains("requires another archive volume")
        );
    }

    #[test]
    fn level3_chain_and_64_bit_size_metadata_are_bounded_before_decode() {
        let archive: &[u8] = include_bytes!("../../tests/fixtures/lzh/level3/h3_lfn.lzh");

        let mut invalid_width: Vec<u8> = archive.to_vec();
        invalid_width[0] = 2;
        let error: Error = parse_lzh(&invalid_width, 1024).expect_err("reject level-3 width");
        assert!(error.to_string().contains("fixed-width marker"));

        let mut unterminated: Vec<u8> = archive.to_vec();
        unterminated[78..82].copy_from_slice(&5u32.to_le_bytes());
        let error: Error = parse_lzh(&unterminated, 1024).expect_err("reject unterminated chain");
        assert!(error.to_string().contains("extended header runs past end"));

        let mut overflowing: Vec<u8> = archive.to_vec();
        overflowing[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        let error: Error = parse_lzh(&overflowing, 1024).expect_err("reject overflowing chain");
        assert!(error.to_string().contains("header extent"));

        let mut oversized: Vec<u8> = archive.to_vec();
        oversized[61] = 0x42;
        oversized[62..70].copy_from_slice(&14u64.to_le_bytes());
        oversized[70..78].copy_from_slice(&(1u64 << 40).to_le_bytes());
        oversized[33..35].fill(0);
        let crc: u16 = crc16_arc(&oversized[..82]);
        oversized[33..35].copy_from_slice(&crc.to_le_bytes());
        let error: Error = parse_lzh(&oversized, 1024).expect_err("reject 64-bit size quota");
        assert!(error.to_string().contains("per-entry cap 1024"));

        let mut duplicate_crc: Vec<u8> = archive.to_vec();
        duplicate_crc[61] = 0x00;
        let error: Error =
            parse_lzh(&duplicate_crc, 1024).expect_err("reject duplicate common CRC");
        assert!(error.to_string().contains("double common CRC-16"));
    }

    #[test]
    fn level3_chain_uses_the_full_32_bit_link_width() {
        let extent: usize = 65_540;
        let mut bytes: Vec<u8> = vec![0; extent];
        bytes[extent - 4..].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            skip_ext_headers(&bytes, 0, 0, extent, 4, extent).expect("walk 32-bit chain"),
            extent
        );
    }

    #[test]
    fn unicode_and_codepage_name_extensions_are_resolved_strictly() {
        let unicode_directory: Vec<u8> = "資料"
            .encode_utf16()
            .chain(std::iter::once(0xffff))
            .flat_map(u16::to_le_bytes)
            .collect();
        let unicode_filename: Vec<u8> = "結果.txt"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            decode_utf16_component(&unicode_directory, true).expect("unicode directory"),
            "資料"
        );
        assert_eq!(
            decode_utf16_component(&unicode_filename, false).expect("unicode filename"),
            "結果.txt"
        );
        assert_eq!(
            decode_codepage(&[0x83, 0x65, 0x83, 0x58, 0x83, 0x67], Some(932)).expect("shift jis"),
            "テスト"
        );
        assert_eq!(
            decode_legacy_base(&[0x95, 0x5c, b'.', b't', b'x', b't'], Some(932))
                .expect("shift jis trail byte"),
            "表.txt"
        );
        assert_eq!(
            decode_legacy_base(&[0x95, 0x5c, b'.', b't', b'x', b't'], None)
                .expect("reversible undeclared name"),
            "%95%5C.txt"
        );
        assert_eq!(
            decode_codepage(&[0x80, b'%', b'.'], Some(437)).expect("unsupported page"),
            "%80%25."
        );
        let header: delharc::LhaHeader = header_with_extra(vec![
            (0x01, b"legacy.txt".to_vec()),
            (0x02, b"legacy\xff".to_vec()),
            (0x46, 932u32.to_le_bytes().to_vec()),
            (0x44, unicode_filename),
            (0x45, unicode_directory),
        ]);
        assert_eq!(
            resolve_member_name(&header).expect("resolved path"),
            "資料/結果.txt"
        );
    }

    #[test]
    fn unix_permissions_are_exact_and_duplicate_or_malformed_values_refuse() {
        let executable: delharc::LhaHeader = header_with_extra(vec![(0x50, vec![0xed, 0x81])]);
        assert_eq!(
            resolve_unix_permissions(&executable).expect("Unix permissions"),
            Some(0o100_755)
        );
        let malformed: delharc::LhaHeader = header_with_extra(vec![(0x50, vec![0xed])]);
        assert!(resolve_unix_permissions(&malformed).is_err());
        let duplicate: delharc::LhaHeader =
            header_with_extra(vec![(0x50, vec![0xa4, 0x81]), (0x50, vec![0xed, 0x81])]);
        assert!(resolve_unix_permissions(&duplicate).is_err());
    }

    #[test]
    fn malformed_unicode_name_extensions_refuse() {
        for raw in [
            vec![0x41],
            vec![0, 0],
            vec![0x00, 0xd8],
            vec![0x41, 0, 0xff, 0xff],
        ] {
            assert!(decode_utf16_component(&raw, false).is_err());
        }
        assert!(decode_utf16_component(&[0x41, 0], true).is_err());
    }
}
