use crate::error::{Error, Result};
use flate2::read::{DeflateDecoder, GzDecoder};
use memchr::memmem;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;

pub const PHAR_HALT_SENTINEL: &[u8] = b"__HALT_COMPILER();";
pub const PHAR_SIG_TRAILER: &[u8] = b"GBMB";
pub const PHAR_MANIFEST_ENTRY_CAP: u32 = 1 << 20;
pub const PHAR_ALIAS_CAP: u32 = 1 << 14;
pub const PHAR_META_CAP: u32 = 1 << 22;
pub const PHAR_ENTRY_NAME_CAP: u32 = 1 << 12;
pub const PHAR_PAYLOAD_CAP: u32 = 1 << 30;

const FLAG_COMPRESSED_GZ: u32 = 0x0000_1000;
const FLAG_COMPRESSED_BZ: u32 = 0x0000_2000;

pub const PHAR_DECOMPRESS_CAP: usize = 256 * 1024 * 1024;
const PHAR_DECOMPRESS_INITIAL_CAP: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PharCompression {
    None,
    Deflate,
    Bzip2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PharEntry {
    pub name: String,
    pub uncompressed_size: u32,
    pub stored_size: u32,
    pub timestamp: u32,
    pub crc32: u32,
    pub flags: u32,
    pub compression: PharCompression,
    pub data_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PharArchive {
    pub manifest_offset: usize,
    pub api_version: u16,
    pub global_flags: u32,
    pub alias: Vec<u8>,
    pub metadata: Vec<u8>,
    pub entries: BTreeMap<String, PharEntry>,
}

pub fn parse(bytes: &[u8]) -> Result<PharArchive> {
    if bytes.len() < 4 {
        return Err(Error::PharTooSmall(bytes.len()));
    }
    let Some(halt_idx): Option<usize> = memmem::find(bytes, PHAR_HALT_SENTINEL) else {
        return Err(Error::PharNoHaltSentinel);
    };
    let mut cursor: usize = halt_idx + PHAR_HALT_SENTINEL.len();
    skip_until_after_halt(bytes, &mut cursor);

    let manifest_offset: usize = cursor;
    let manifest_len: usize = read_u32_le(bytes, &mut cursor)? as usize;
    let entry_count: u32 = read_u32_le(bytes, &mut cursor)?;
    if entry_count > PHAR_MANIFEST_ENTRY_CAP {
        return Err(Error::PharManifestTooLarge {
            count: entry_count,
            cap: PHAR_MANIFEST_ENTRY_CAP,
        });
    }
    let api_version: u16 = read_u16_be(bytes, &mut cursor)?;
    let global_flags: u32 = read_u32_le(bytes, &mut cursor)?;
    let alias_len: u32 = read_u32_le(bytes, &mut cursor)?;
    if alias_len > PHAR_ALIAS_CAP {
        return Err(Error::PharAliasOversize(alias_len));
    }
    let alias: Vec<u8> = take_bytes(bytes, &mut cursor, alias_len as usize)?.to_vec();
    let metadata_len: u32 = read_u32_le(bytes, &mut cursor)?;
    if metadata_len > PHAR_META_CAP {
        return Err(Error::PharManifestTruncated {
            offset: cursor,
            need: metadata_len as usize,
        });
    }
    let metadata: Vec<u8> = take_bytes(bytes, &mut cursor, metadata_len as usize)?.to_vec();

    let mut entries_meta: Vec<PharEntryMeta> = Vec::with_capacity(entry_count as usize);
    for _ in 0..entry_count {
        entries_meta.push(read_entry_meta(bytes, &mut cursor)?);
    }

    let manifest_end: usize = manifest_offset
        .checked_add(4)
        .and_then(|n: usize| n.checked_add(manifest_len))
        .ok_or(Error::PharManifestTruncated {
            offset: manifest_offset,
            need: manifest_len,
        })?;
    if manifest_end > bytes.len() {
        return Err(Error::PharManifestTruncated {
            offset: manifest_offset,
            need: manifest_end - bytes.len(),
        });
    }

    let mut data_cursor: usize = manifest_end;
    let mut entries: BTreeMap<String, PharEntry> = BTreeMap::new();
    for meta in entries_meta {
        if data_cursor.checked_add(meta.stored_size as usize).is_none()
            || data_cursor + meta.stored_size as usize > bytes.len()
        {
            return Err(Error::PharEntryPayloadTruncated {
                name: meta.name.clone(),
                need: meta.stored_size,
                got: bytes.len().saturating_sub(data_cursor),
            });
        }
        let compression: PharCompression = decode_compression(&meta)?;
        let entry: PharEntry = PharEntry {
            name: meta.name.clone(),
            uncompressed_size: meta.uncompressed_size,
            stored_size: meta.stored_size,
            timestamp: meta.timestamp,
            crc32: meta.crc32,
            flags: meta.flags,
            compression,
            data_offset: data_cursor,
        };
        data_cursor += meta.stored_size as usize;
        entries.insert(meta.name, entry);
    }

    Ok(PharArchive {
        manifest_offset,
        api_version,
        global_flags,
        alias,
        metadata,
        entries,
    })
}

pub fn extract_entry(archive: &PharArchive, bytes: &[u8], name: &str) -> Result<Vec<u8>> {
    let Some(entry): Option<&PharEntry> = archive.entries.get(name) else {
        return Err(Error::PharEntryPayloadTruncated {
            name: name.to_string(),
            need: 0,
            got: 0,
        });
    };
    let end: usize = entry.data_offset + entry.stored_size as usize;
    let stored: &[u8] = &bytes[entry.data_offset..end];
    match entry.compression {
        PharCompression::None => Ok(stored.to_vec()),
        PharCompression::Deflate => decompress_deflate(stored, name, entry.uncompressed_size),
        PharCompression::Bzip2 => Err(Error::PharUnsupportedCompression {
            name: name.to_string(),
            bits: FLAG_COMPRESSED_BZ,
        }),
    }
}

fn decompress_deflate(stored: &[u8], name: &str, expected: u32) -> Result<Vec<u8>> {
    let initial: usize =
        (expected as usize).clamp(PHAR_DECOMPRESS_INITIAL_CAP, PHAR_DECOMPRESS_CAP);
    if let Some(out) = try_bounded(GzDecoder::new(stored), initial, name)?
        && !out.is_empty()
    {
        return Ok(out);
    }
    try_bounded(DeflateDecoder::new(stored), initial, name)?.map_or_else(
        || {
            Err(Error::PharDecompressFailed {
                name: name.to_string(),
                reason: "raw deflate stream invalid".to_string(),
            })
        },
        Ok,
    )
}

fn try_bounded<R: Read>(mut dec: R, initial_cap: usize, name: &str) -> Result<Option<Vec<u8>>> {
    let cap_plus_one: u64 = PHAR_DECOMPRESS_CAP as u64 + 1;
    let mut out: Vec<u8> = Vec::with_capacity(initial_cap);
    match Read::take(&mut dec, cap_plus_one).read_to_end(&mut out) {
        Ok(read) if read as u64 > PHAR_DECOMPRESS_CAP as u64 => Err(Error::PharDecompressBomb {
            name: name.to_string(),
            cap: PHAR_DECOMPRESS_CAP,
        }),
        Ok(_) => Ok(Some(out)),
        Err(_) => Ok(None),
    }
}

fn decode_compression(meta: &PharEntryMeta) -> Result<PharCompression> {
    let bits: u32 = meta.flags;
    let masked: u32 = bits & 0x0000_f000;
    match masked {
        0 => Ok(PharCompression::None),
        FLAG_COMPRESSED_GZ => Ok(PharCompression::Deflate),
        FLAG_COMPRESSED_BZ => Ok(PharCompression::Bzip2),
        _ => Err(Error::PharUnsupportedCompression {
            name: meta.name.clone(),
            bits,
        }),
    }
}

#[derive(Debug)]
struct PharEntryMeta {
    name: String,
    uncompressed_size: u32,
    timestamp: u32,
    stored_size: u32,
    crc32: u32,
    flags: u32,
}

fn read_entry_meta(bytes: &[u8], cursor: &mut usize) -> Result<PharEntryMeta> {
    let name_len: u32 = read_u32_le(bytes, cursor)?;
    if name_len > PHAR_ENTRY_NAME_CAP {
        return Err(Error::PharManifestTruncated {
            offset: *cursor,
            need: name_len as usize,
        });
    }
    let name_bytes: &[u8] = take_bytes(bytes, cursor, name_len as usize)?;
    let name: String = String::from_utf8_lossy(name_bytes).into_owned();
    let uncompressed_size: u32 = read_u32_le(bytes, cursor)?;
    let timestamp: u32 = read_u32_le(bytes, cursor)?;
    let stored_size: u32 = read_u32_le(bytes, cursor)?;
    if stored_size > PHAR_PAYLOAD_CAP {
        return Err(Error::PharEntryPayloadTruncated {
            name,
            need: stored_size,
            got: 0,
        });
    }
    let crc32: u32 = read_u32_le(bytes, cursor)?;
    let flags: u32 = read_u32_le(bytes, cursor)?;
    let entry_meta_len: u32 = read_u32_le(bytes, cursor)?;
    if entry_meta_len > PHAR_META_CAP {
        return Err(Error::PharManifestTruncated {
            offset: *cursor,
            need: entry_meta_len as usize,
        });
    }
    take_bytes(bytes, cursor, entry_meta_len as usize)?;
    Ok(PharEntryMeta {
        name,
        uncompressed_size,
        timestamp,
        stored_size,
        crc32,
        flags,
    })
}

fn read_u32_le(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let end: usize = cursor.checked_add(4).ok_or(Error::PharManifestTruncated {
        offset: *cursor,
        need: 4,
    })?;
    if end > bytes.len() {
        return Err(Error::PharManifestTruncated {
            offset: *cursor,
            need: end - bytes.len(),
        });
    }
    let raw: [u8; 4] = [
        bytes[*cursor],
        bytes[*cursor + 1],
        bytes[*cursor + 2],
        bytes[*cursor + 3],
    ];
    *cursor = end;
    Ok(u32::from_le_bytes(raw))
}

fn read_u16_be(bytes: &[u8], cursor: &mut usize) -> Result<u16> {
    let end: usize = cursor.checked_add(2).ok_or(Error::PharManifestTruncated {
        offset: *cursor,
        need: 2,
    })?;
    if end > bytes.len() {
        return Err(Error::PharManifestTruncated {
            offset: *cursor,
            need: end - bytes.len(),
        });
    }
    let raw: [u8; 2] = [bytes[*cursor], bytes[*cursor + 1]];
    *cursor = end;
    Ok(u16::from_be_bytes(raw))
}

fn take_bytes<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end: usize = cursor
        .checked_add(len)
        .ok_or(Error::PharManifestTruncated {
            offset: *cursor,
            need: len,
        })?;
    if end > bytes.len() {
        return Err(Error::PharManifestTruncated {
            offset: *cursor,
            need: end - bytes.len(),
        });
    }
    let slice: &'a [u8] = &bytes[*cursor..end];
    *cursor = end;
    Ok(slice)
}

fn skip_until_after_halt(bytes: &[u8], cursor: &mut usize) {
    while *cursor < bytes.len() && (bytes[*cursor] == b' ' || bytes[*cursor] == b'\t') {
        *cursor += 1;
    }
    if bytes.get(*cursor).copied() == Some(b'?') && bytes.get(*cursor + 1).copied() == Some(b'>') {
        *cursor += 2;
    }
    if bytes.get(*cursor).copied() == Some(b'\r') {
        *cursor += 1;
    }
    if bytes.get(*cursor).copied() == Some(b'\n') {
        *cursor += 1;
    }
}
