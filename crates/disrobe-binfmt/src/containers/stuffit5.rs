use std::collections::BTreeMap;

use super::stuffit::{crc16_ibm, decode_bounded};
use crate::error::{Error, Result};

const SIT5_SIGNATURE: &[u8; 16] = b"StuffIt (c)1997-";
const SIT5_ENTRY_ID: u32 = 0xa5a5_a5a5;
const SIT5_ARCHIVE_VERSION: u8 = 5;
const ARCHIVE_HEADER_LEN: usize = 100;
const ENTRY_FIXED_LEN: usize = 48;
const ARCHIVE_FLAG_14_BYTES: u8 = 0x10;
const ARCHIVE_FLAG_COMMENT: u8 = 0x20;
const ENTRY_FLAG_DIRECTORY: u8 = 0x40;
const ENTRY_FLAG_ENCRYPTED: u8 = 0x20;
const ENTRY_FLAG_RESOURCE_FORK: u16 = 0x0001;
const DIRECTORY_SENTINEL: u32 = 0xffff_ffff;
const METHOD_STORED: u8 = 0;
const METHOD_ARSENIC: u8 = 15;
const METHOD_MASK: u8 = 0x0f;
const MAX_ENTRIES: usize = 65_535;
const MAX_PATH_BYTES: usize = 4096;
const MAX_FOLDER_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sit5Compression {
    Stored,
    Arsenic,
}

#[derive(Debug, Clone)]
pub struct Sit5Fork {
    pub compression: Sit5Compression,
    pub uncompressed_len: u32,
    pub compressed_len: u32,
    pub expected_crc: u16,
    pub data_offset: usize,
}

#[derive(Debug, Clone)]
pub struct Sit5Entry {
    pub path: String,
    pub resource: Option<Sit5Fork>,
    pub data: Option<Sit5Fork>,
}

#[derive(Debug, Clone)]
pub struct Sit5Archive {
    pub entries: Vec<Sit5Entry>,
}

fn sit5_error(message: impl Into<String>) -> Error {
    Error::StuffIt(message.into())
}

fn rd_u8(bytes: &[u8], offset: usize) -> Result<u8> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| sit5_error("stuffit 5: truncated u8"))
}

fn rd_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    disrobe_bytes::read_u16_be_at(bytes, offset).map_err(|_| sit5_error("stuffit 5: truncated u16"))
}

fn rd_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    disrobe_bytes::read_u32_be_at(bytes, offset).map_err(|_| sit5_error("stuffit 5: truncated u32"))
}

fn compression(method: u8) -> Result<Sit5Compression> {
    match method & METHOD_MASK {
        METHOD_STORED => Ok(Sit5Compression::Stored),
        METHOD_ARSENIC => Ok(Sit5Compression::Arsenic),
        other => Err(sit5_error(format!(
            "stuffit 5: unsupported compression method {other}"
        ))),
    }
}

fn decode_name(raw: &[u8]) -> Result<String> {
    if raw.is_empty() {
        return Err(sit5_error("stuffit 5: entry name is empty"));
    }
    let decoded: String = encoding_rs::MACINTOSH
        .decode_without_bom_handling(raw)
        .0
        .into_owned();
    if decoded.contains('\0') {
        return Err(sit5_error("stuffit 5: entry name contains a null byte"));
    }
    if decoded == "." || decoded == ".." {
        return Err(sit5_error(format!(
            "stuffit 5: entry name `{decoded}` traverses the output root"
        )));
    }
    Ok(decoded)
}

fn join_path(parent: Option<&String>, name: &str) -> Result<String> {
    let joined: String = match parent {
        Some(base) if !base.is_empty() => format!("{base}/{name}"),
        _ => name.to_owned(),
    };
    if joined.len() > MAX_PATH_BYTES {
        return Err(sit5_error("stuffit 5: entry path exceeds the length limit"));
    }
    Ok(joined)
}

struct EntryHeader {
    entry_flags: u8,
    header_size: usize,
    data_offset_in_header: u32,
    name: String,
    data_length: u32,
    data_compressed_len: u32,
    data_crc: u16,
    data_method: Option<u8>,
    resource: Option<(u32, u32, u16, u8)>,
    payload_start: usize,
}

fn parse_entry_header(bytes: &[u8], pos: usize) -> Result<EntryHeader> {
    let fixed_end: usize = pos
        .checked_add(ENTRY_FIXED_LEN)
        .ok_or_else(|| sit5_error("stuffit 5: entry header range overflow"))?;
    if fixed_end > bytes.len() {
        return Err(sit5_error("stuffit 5: truncated entry header"));
    }
    if rd_u32(bytes, pos)? != SIT5_ENTRY_ID {
        return Err(sit5_error(format!(
            "stuffit 5: entry at offset {pos} is missing the a5a5a5a5 marker"
        )));
    }
    let entry_version: u8 = rd_u8(bytes, pos + 4)?;
    let header_size: usize = usize::from(rd_u16(bytes, pos + 6)?);
    if header_size < ENTRY_FIXED_LEN {
        return Err(sit5_error(format!(
            "stuffit 5: entry header size {header_size} is below the {ENTRY_FIXED_LEN}-byte minimum"
        )));
    }
    let header_end: usize = pos
        .checked_add(header_size)
        .ok_or_else(|| sit5_error("stuffit 5: entry header range overflow"))?;
    if header_end > bytes.len() {
        return Err(sit5_error("stuffit 5: entry header runs past the archive"));
    }
    let entry_flags: u8 = rd_u8(bytes, pos + 9)?;
    let data_offset_in_header: u32 = rd_u32(bytes, pos + 26)?;
    let name_length: usize = usize::from(rd_u16(bytes, pos + 30)?);
    let stored_header_crc: u16 = rd_u16(bytes, pos + 32)?;
    let data_length: u32 = rd_u32(bytes, pos + 34)?;
    let data_compressed_len: u32 = rd_u32(bytes, pos + 38)?;
    let data_crc: u16 = rd_u16(bytes, pos + 42)?;

    let mut header_copy: Vec<u8> = bytes[pos..header_end].to_vec();
    header_copy[32] = 0;
    header_copy[33] = 0;
    if crc16_ibm(&header_copy) != stored_header_crc {
        return Err(sit5_error(format!(
            "stuffit 5: entry at offset {pos} has a header CRC mismatch"
        )));
    }

    let encrypted: bool = entry_flags & ENTRY_FLAG_ENCRYPTED != 0;
    let mut cursor: usize = pos + 46;
    let mut data_method: Option<u8> = None;
    if entry_flags & ENTRY_FLAG_DIRECTORY == 0 {
        data_method = Some(rd_u8(bytes, cursor)?);
        let pass_len: usize = usize::from(rd_u8(bytes, cursor + 1)?);
        cursor += 2;
        if encrypted && data_length != 0 {
            return Err(sit5_error(
                "stuffit 5: encrypted entries require a password and key derivation metadata",
            ));
        }
        if pass_len != 0 {
            return Err(sit5_error(
                "stuffit 5: entry carries key material without the encrypted flag",
            ));
        }
    } else {
        cursor += 2;
    }

    let name_end: usize = cursor
        .checked_add(name_length)
        .ok_or_else(|| sit5_error("stuffit 5: entry name range overflow"))?;
    if name_end > header_end {
        return Err(sit5_error("stuffit 5: entry name runs past its header"));
    }
    let name: String = decode_name(&bytes[cursor..name_end])?;
    cursor = name_end;

    if cursor < header_end {
        let comment_size: usize = usize::from(rd_u16(bytes, cursor)?);
        cursor = cursor
            .checked_add(4)
            .and_then(|next: usize| next.checked_add(comment_size))
            .ok_or_else(|| sit5_error("stuffit 5: entry comment range overflow"))?;
        if cursor > header_end {
            return Err(sit5_error("stuffit 5: entry comment runs past its header"));
        }
    }

    let fork_flags: u16 = rd_u16(bytes, cursor)?;
    cursor = cursor
        .checked_add(if entry_version == 1 { 36 } else { 32 })
        .ok_or_else(|| sit5_error("stuffit 5: entry metadata range overflow"))?;

    let resource: Option<(u32, u32, u16, u8)> = if fork_flags & ENTRY_FLAG_RESOURCE_FORK == 0 {
        None
    } else {
        let resource_length: u32 = rd_u32(bytes, cursor)?;
        let resource_compressed_len: u32 = rd_u32(bytes, cursor + 4)?;
        let resource_crc: u16 = rd_u16(bytes, cursor + 8)?;
        let resource_method: u8 = rd_u8(bytes, cursor + 12)?;
        let pass_len: usize = usize::from(rd_u8(bytes, cursor + 13)?);
        cursor += 14;
        if encrypted && resource_length != 0 {
            return Err(sit5_error(
                "stuffit 5: encrypted entries require a password and key derivation metadata",
            ));
        }
        if pass_len != 0 {
            return Err(sit5_error(
                "stuffit 5: entry carries key material without the encrypted flag",
            ));
        }
        Some((
            resource_length,
            resource_compressed_len,
            resource_crc,
            resource_method,
        ))
    };

    Ok(EntryHeader {
        entry_flags,
        header_size,
        data_offset_in_header,
        name,
        data_length,
        data_compressed_len,
        data_crc,
        data_method,
        resource,
        payload_start: cursor,
    })
}

pub fn parse_sit5(bytes: &[u8]) -> Result<Sit5Archive> {
    let header: &[u8] = bytes
        .get(..ARCHIVE_HEADER_LEN)
        .ok_or_else(|| sit5_error("stuffit 5: truncated archive header"))?;
    if !header.starts_with(SIT5_SIGNATURE) {
        return Err(sit5_error("stuffit 5: missing StuffIt 5 signature"));
    }
    let version: u8 = rd_u8(header, 82)?;
    if version != SIT5_ARCHIVE_VERSION {
        return Err(sit5_error(format!(
            "stuffit 5: archive version {version} is not the supported version {SIT5_ARCHIVE_VERSION}"
        )));
    }
    let archive_flags: u8 = rd_u8(header, 83)?;
    let total_len: usize = usize::try_from(rd_u32(header, 84)?)
        .map_err(|_| sit5_error("stuffit 5: archive length exceeds address space"))?;
    if total_len > bytes.len() {
        return Err(sit5_error(format!(
            "stuffit 5: declared archive length {total_len} exceeds input length {}",
            bytes.len()
        )));
    }
    let declared_entries: usize = usize::from(rd_u16(header, 92)?);
    let first_offset: usize = usize::try_from(rd_u32(header, 94)?)
        .map_err(|_| sit5_error("stuffit 5: first entry offset exceeds address space"))?;
    if first_offset < ARCHIVE_HEADER_LEN || first_offset > bytes.len() {
        return Err(sit5_error(format!(
            "stuffit 5: first entry offset {first_offset} is outside the archive"
        )));
    }
    if archive_flags & (ARCHIVE_FLAG_14_BYTES | ARCHIVE_FLAG_COMMENT) != archive_flags
        && archive_flags != 0
    {
        return Err(sit5_error(format!(
            "stuffit 5: unsupported archive flags {archive_flags:#04x}"
        )));
    }

    let limit: usize = total_len.max(first_offset);
    let mut entries: Vec<Sit5Entry> = Vec::new();
    let mut directories: BTreeMap<u32, String> = BTreeMap::new();
    let mut cursor: usize = first_offset;
    let mut visited: usize = 0;
    let mut depth_guard: usize = 0;

    while cursor < limit && visited < MAX_ENTRIES {
        let entry_offset: u32 =
            u32::try_from(cursor).map_err(|_| sit5_error("stuffit 5: entry offset exceeds u32"))?;
        let entry: EntryHeader = parse_entry_header(bytes, cursor)?;
        visited += 1;

        let parent: Option<&String> = directories.get(&entry.data_offset_in_header);
        if entry.data_offset_in_header != 0 && parent.is_none() {
            return Err(sit5_error(format!(
                "stuffit 5: entry at offset {cursor} names a parent directory that has not been seen"
            )));
        }
        let path: String = join_path(parent, &entry.name)?;

        if entry.entry_flags & ENTRY_FLAG_DIRECTORY != 0 {
            if entry.data_length == DIRECTORY_SENTINEL {
                cursor = entry.payload_start;
                continue;
            }
            depth_guard += 1;
            if depth_guard > MAX_FOLDER_DEPTH {
                return Err(sit5_error("stuffit 5: folder depth limit exceeded"));
            }
            if directories.insert(entry_offset, path).is_some() {
                return Err(sit5_error(format!(
                    "stuffit 5: two directory entries share offset {entry_offset}"
                )));
            }
            cursor = entry.payload_start;
            continue;
        }

        let resource_compressed_len: u32 = entry.resource.as_ref().map_or(0, |fork| fork.1);
        let resource_fork: Option<Sit5Fork> = match entry.resource {
            Some((length, compressed, crc, method)) if length != 0 => Some(Sit5Fork {
                compression: compression(method)?,
                uncompressed_len: length,
                compressed_len: compressed,
                expected_crc: crc,
                data_offset: entry.payload_start,
            }),
            _ => None,
        };
        let data_start: usize = entry
            .payload_start
            .checked_add(
                usize::try_from(resource_compressed_len)
                    .map_err(|_| sit5_error("stuffit 5: resource length exceeds address space"))?,
            )
            .ok_or_else(|| sit5_error("stuffit 5: fork range overflow"))?;
        let data_fork: Option<Sit5Fork> = match entry.data_method {
            Some(method) if entry.data_length != 0 => Some(Sit5Fork {
                compression: compression(method)?,
                uncompressed_len: entry.data_length,
                compressed_len: entry.data_compressed_len,
                expected_crc: entry.data_crc,
                data_offset: data_start,
            }),
            _ => None,
        };

        let next: usize = data_start
            .checked_add(
                usize::try_from(entry.data_compressed_len)
                    .map_err(|_| sit5_error("stuffit 5: data length exceeds address space"))?,
            )
            .ok_or_else(|| sit5_error("stuffit 5: fork range overflow"))?;
        if next > bytes.len() {
            return Err(sit5_error("stuffit 5: fork data runs past the archive"));
        }

        entries.push(Sit5Entry {
            path,
            resource: resource_fork,
            data: data_fork,
        });
        if next <= cursor {
            return Err(sit5_error("stuffit 5: entry walk failed to advance"));
        }
        cursor = next;
        let _ = entry.header_size;
    }

    if entries.is_empty() {
        return Err(sit5_error(
            "stuffit 5: archive declares no recoverable files",
        ));
    }
    if visited > MAX_ENTRIES {
        return Err(sit5_error("stuffit 5: entry limit exceeded"));
    }
    let _ = declared_entries;
    Ok(Sit5Archive { entries })
}

#[cfg(test)]
pub(crate) fn build_test_sit5(name: &str, body: &[u8]) -> Option<Vec<u8>> {
    let encoded: &[u8] = name.as_bytes();
    if encoded.is_empty() || encoded.len() > u16::MAX as usize || encoded.contains(&0) {
        return None;
    }

    let name_len: usize = encoded.len();
    let header_size: usize = 48 + name_len;
    let metadata_len: usize = 32;
    let entry_offset: usize = ARCHIVE_HEADER_LEN;
    let total: usize = entry_offset + header_size + metadata_len + body.len();

    let mut out: Vec<u8> = Vec::with_capacity(total);
    out.extend_from_slice(SIT5_SIGNATURE);
    out.resize(82, b' ');
    out.push(SIT5_ARCHIVE_VERSION);
    out.push(0);
    out.extend_from_slice(&u32::try_from(total).ok()?.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&u32::try_from(entry_offset).ok()?.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());

    let mut entry: Vec<u8> = Vec::with_capacity(header_size);
    entry.extend_from_slice(&SIT5_ENTRY_ID.to_be_bytes());
    entry.push(2);
    entry.push(0);
    entry.extend_from_slice(&u16::try_from(header_size).ok()?.to_be_bytes());
    entry.push(0);
    entry.push(0);
    entry.extend_from_slice(&0u32.to_be_bytes());
    entry.extend_from_slice(&0u32.to_be_bytes());
    entry.extend_from_slice(&0u32.to_be_bytes());
    entry.extend_from_slice(&0u32.to_be_bytes());
    entry.extend_from_slice(&0u32.to_be_bytes());
    entry.extend_from_slice(&u16::try_from(name_len).ok()?.to_be_bytes());
    entry.extend_from_slice(&0u16.to_be_bytes());
    entry.extend_from_slice(&u32::try_from(body.len()).ok()?.to_be_bytes());
    entry.extend_from_slice(&u32::try_from(body.len()).ok()?.to_be_bytes());
    entry.extend_from_slice(&crc16_ibm(body).to_be_bytes());
    entry.extend_from_slice(&0u16.to_be_bytes());
    entry.push(METHOD_STORED);
    entry.push(0);
    entry.extend_from_slice(encoded);
    let header_crc: u16 = crc16_ibm(&entry);
    entry[32..34].copy_from_slice(&header_crc.to_be_bytes());

    out.extend_from_slice(&entry);
    out.extend_from_slice(&0u16.to_be_bytes());
    out.resize(entry_offset + header_size + metadata_len, 0);
    out.extend_from_slice(body);
    Some(out)
}

pub fn fork_bytes_bounded(bytes: &[u8], fork: &Sit5Fork, max_output: usize) -> Result<Vec<u8>> {
    let length: usize = usize::try_from(fork.compressed_len)
        .map_err(|_| sit5_error("stuffit 5: compressed length exceeds address space"))?;
    let end: usize = fork
        .data_offset
        .checked_add(length)
        .ok_or_else(|| sit5_error("stuffit 5: fork range overflow"))?;
    let raw: &[u8] = bytes
        .get(fork.data_offset..end)
        .ok_or_else(|| sit5_error("stuffit 5: fork data out of bounds"))?;
    let expected_len: usize = usize::try_from(fork.uncompressed_len)
        .map_err(|_| sit5_error("stuffit 5: uncompressed length exceeds address space"))?;

    match fork.compression {
        Sit5Compression::Stored => {
            if fork.compressed_len != fork.uncompressed_len {
                return Err(sit5_error("stuffit 5: stored fork length mismatch"));
            }
            if expected_len > max_output {
                return Err(sit5_error(format!(
                    "stuffit 5: decoded fork length {expected_len} exceeds cap {max_output}"
                )));
            }
            let output: Vec<u8> = raw.to_vec();
            let actual_crc: u16 = crc16_ibm(&output);
            if actual_crc != fork.expected_crc {
                return Err(sit5_error(format!(
                    "stuffit 5: fork CRC mismatch: expected {:04x}, got {actual_crc:04x}",
                    fork.expected_crc
                )));
            }
            Ok(output)
        }
        Sit5Compression::Arsenic => {
            let mut decoder: compcol::arsenic::Decoder =
                <compcol::arsenic::Arsenic as compcol::Algorithm>::decoder_with(());
            let (output, _consumed): (Vec<u8>, usize) =
                decode_bounded(&mut decoder, raw, expected_len, max_output, "method 15")?;
            Ok(output)
        }
    }
}
