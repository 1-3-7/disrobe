use crate::debug::{dbg_kv, dbg_line, dbg_section};
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
pub const PHAR_MAX_EXPANSION_RATIO: usize = 100;
pub const PHAR_MIN_DECOMPRESS_ALLOWANCE: usize = 64 * 1024;
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
    dbg_section("php phar");
    dbg_kv("phar-input-len", || bytes.len().to_string());
    if bytes.len() < 4 {
        return Err(Error::PharTooSmall(bytes.len()));
    }
    let Some(halt_idx): Option<usize> = memmem::find(bytes, PHAR_HALT_SENTINEL) else {
        return Err(Error::PharNoHaltSentinel);
    };
    dbg_kv("phar-halt-offset", || format!("0x{halt_idx:x}"));
    let mut cursor: usize = halt_idx + PHAR_HALT_SENTINEL.len();
    skip_until_after_halt(bytes, &mut cursor);

    let manifest_offset: usize = cursor;
    dbg_kv("phar-manifest-offset", || format!("0x{manifest_offset:x}"));
    let manifest_len: usize = read_u32_le(bytes, &mut cursor)? as usize;
    let manifest_end: usize = manifest_offset
        .checked_add(4)
        .and_then(|n: usize| n.checked_add(manifest_len))
        .ok_or(Error::PharManifestTruncated {
            offset: manifest_offset,
            need: manifest_len,
        })?;
    ensure_manifest_range(cursor, 4, manifest_end)?;
    let entry_count: u32 = read_u32_le(bytes, &mut cursor)?;
    dbg_kv("phar-manifest-len", || manifest_len.to_string());
    dbg_kv("phar-entry-count", || entry_count.to_string());
    if entry_count > PHAR_MANIFEST_ENTRY_CAP {
        return Err(Error::PharManifestTooLarge {
            count: entry_count,
            cap: PHAR_MANIFEST_ENTRY_CAP,
        });
    }
    if manifest_end > bytes.len() {
        return Err(Error::PharManifestTruncated {
            offset: manifest_offset,
            need: manifest_end - bytes.len(),
        });
    }
    let api_version: u16 = read_u16_be_within(bytes, &mut cursor, manifest_end)?;
    let global_flags: u32 = read_u32_le_within(bytes, &mut cursor, manifest_end)?;
    dbg_kv("phar-api-version", || format!("0x{api_version:04x}"));
    dbg_kv("phar-global-flags", || format!("0x{global_flags:08x}"));
    let alias_len: u32 = read_u32_le_within(bytes, &mut cursor, manifest_end)?;
    if alias_len > PHAR_ALIAS_CAP {
        return Err(Error::PharAliasOversize(alias_len));
    }
    let alias: &[u8] = take_bytes_within(bytes, &mut cursor, alias_len as usize, manifest_end)?;
    let metadata_len: u32 = read_u32_le_within(bytes, &mut cursor, manifest_end)?;
    if metadata_len > PHAR_META_CAP {
        return Err(Error::PharManifestTruncated {
            offset: cursor,
            need: metadata_len as usize,
        });
    }
    let metadata: &[u8] =
        take_bytes_within(bytes, &mut cursor, metadata_len as usize, manifest_end)?;
    let entries_offset: usize = cursor;
    validate_manifest_entries(bytes, &mut cursor, manifest_end, entry_count)?;
    cursor = entries_offset;
    preflight_entries(bytes, &mut cursor, manifest_end, entry_count)?;
    cursor = entries_offset;

    let mut data_cursor: usize = manifest_end;
    let mut entries: BTreeMap<String, PharEntry> = BTreeMap::new();
    for _ in 0..entry_count {
        let meta: PharEntryMeta = read_entry_meta(bytes, &mut cursor, manifest_end)?;
        let stored_size: usize = meta.stored_size as usize;
        let Some(payload_end): Option<usize> = data_cursor.checked_add(stored_size) else {
            return Err(Error::PharEntryPayloadTruncated {
                name: meta.name.clone(),
                need: meta.stored_size,
                got: bytes.len().saturating_sub(data_cursor),
            });
        };
        if payload_end > bytes.len() {
            return Err(Error::PharEntryPayloadTruncated {
                name: meta.name.clone(),
                need: meta.stored_size,
                got: bytes.len().saturating_sub(data_cursor),
            });
        }
        let compression: PharCompression = decode_compression(&meta.name, meta.flags)?;
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
        dbg_kv("phar-entry", || {
            format!(
                "{} compression={:?} stored={} uncompressed={} at 0x{:x}",
                entry.name,
                entry.compression,
                entry.stored_size,
                entry.uncompressed_size,
                entry.data_offset
            )
        });
        data_cursor = payload_end;
        entries.insert(meta.name, entry);
    }

    dbg_kv("phar-entries-parsed", || entries.len().to_string());
    Ok(PharArchive {
        manifest_offset,
        api_version,
        global_flags,
        alias: alias.to_vec(),
        metadata: metadata.to_vec(),
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
    let stored_size: usize = entry.stored_size as usize;
    let got: usize = bytes.len().saturating_sub(entry.data_offset);
    let end: usize = entry.data_offset.checked_add(stored_size).ok_or_else(|| {
        Error::PharEntryPayloadTruncated {
            name: name.to_string(),
            need: entry.stored_size,
            got,
        }
    })?;
    let stored: &[u8] =
        bytes
            .get(entry.data_offset..end)
            .ok_or_else(|| Error::PharEntryPayloadTruncated {
                name: name.to_string(),
                need: entry.stored_size,
                got,
            })?;
    dbg_line(|| {
        format!(
            "phar extract '{name}': {:?} stored={} expected-uncompressed={}",
            entry.compression, entry.stored_size, entry.uncompressed_size
        )
    });
    match entry.compression {
        PharCompression::None => Ok(stored.to_vec()),
        PharCompression::Deflate => {
            let expected: usize = declared_output_len(entry, name, stored.len())?;
            decompress_deflate(stored, name, expected)
        }
        PharCompression::Bzip2 => {
            let expected: usize = declared_output_len(entry, name, stored.len())?;
            decompress_bzip2(stored, name, expected)
        }
    }
}

#[must_use]
pub const fn decompress_ceiling(stored_len: usize) -> usize {
    let proportional: usize = match stored_len.checked_mul(PHAR_MAX_EXPANSION_RATIO) {
        Some(scaled) => scaled,
        None => PHAR_DECOMPRESS_CAP,
    };
    let allowed: usize = if proportional > PHAR_MIN_DECOMPRESS_ALLOWANCE {
        proportional
    } else {
        PHAR_MIN_DECOMPRESS_ALLOWANCE
    };
    if allowed > PHAR_DECOMPRESS_CAP {
        PHAR_DECOMPRESS_CAP
    } else {
        allowed
    }
}

fn declared_output_len(entry: &PharEntry, name: &str, stored_len: usize) -> Result<usize> {
    let declared: usize = declared_output_len_from_parts(
        name,
        entry.uncompressed_size,
        entry.stored_size,
        stored_len,
    )?;
    let ceiling: usize = decompress_ceiling(stored_len);
    dbg_kv("phar-decompress-budget", || {
        format!("{name} declared={declared} ceiling={ceiling}")
    });
    Ok(declared)
}

fn declared_output_len_from_parts(
    name: &str,
    declared_size: u32,
    stored_size: u32,
    stored_len: usize,
) -> Result<usize> {
    let ceiling: usize = decompress_ceiling(stored_len);
    let declared: usize = declared_size as usize;
    if declared > ceiling {
        return Err(Error::PharDeclaredSizeImplausible {
            name: name.to_string(),
            declared: declared_size,
            stored: stored_size,
            ceiling,
        });
    }
    Ok(declared)
}

fn short_stream(name: &str, expected: usize, produced: usize) -> Error {
    Error::PharDecompressFailed {
        name: name.to_string(),
        reason: format!("declared {expected} uncompressed bytes, stream yielded {produced}"),
    }
}

fn decompress_bzip2(stored: &[u8], name: &str, expected: usize) -> Result<Vec<u8>> {
    let initial: usize = expected.min(PHAR_DECOMPRESS_INITIAL_CAP);
    let decoder: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(stored);
    try_bounded(decoder, initial, name, expected)?.map_or_else(
        || {
            Err(Error::PharDecompressFailed {
                name: name.to_string(),
                reason: "bzip2 stream invalid".to_string(),
            })
        },
        |out: Vec<u8>| exactly_declared(out, name, expected),
    )
}

fn decompress_deflate(stored: &[u8], name: &str, expected: usize) -> Result<Vec<u8>> {
    let initial: usize = expected.min(PHAR_DECOMPRESS_INITIAL_CAP);
    if let Some(out) = try_bounded(GzDecoder::new(stored), initial, name, expected)? {
        if out.len() == expected {
            return Ok(out);
        }
        if !out.is_empty() {
            return Err(short_stream(name, expected, out.len()));
        }
    }
    try_bounded(DeflateDecoder::new(stored), initial, name, expected)?.map_or_else(
        || {
            Err(Error::PharDecompressFailed {
                name: name.to_string(),
                reason: "raw deflate stream invalid".to_string(),
            })
        },
        |out: Vec<u8>| exactly_declared(out, name, expected),
    )
}

fn exactly_declared(out: Vec<u8>, name: &str, expected: usize) -> Result<Vec<u8>> {
    if out.len() == expected {
        return Ok(out);
    }
    Err(short_stream(name, expected, out.len()))
}

fn try_bounded<R: Read>(
    mut dec: R,
    initial_cap: usize,
    name: &str,
    cap: usize,
) -> Result<Option<Vec<u8>>> {
    let mut out: Vec<u8> = Vec::with_capacity(initial_cap.min(cap));
    let mut buffer: [u8; 8192] = [0; 8192];
    loop {
        let remaining: usize = cap.saturating_sub(out.len());
        let read_len: usize = if remaining == 0 {
            1
        } else {
            remaining.min(buffer.len())
        };
        let read: usize = match dec.read(&mut buffer[..read_len]) {
            Ok(0) => return Ok(Some(out)),
            Ok(read) => read,
            Err(_) => return Ok(None),
        };
        if read > remaining {
            return Err(Error::PharDecompressBomb {
                name: name.to_string(),
                cap,
            });
        }
        if out.try_reserve_exact(read).is_err() {
            return Ok(None);
        }
        out.extend_from_slice(&buffer[..read]);
    }
}

fn validate_manifest_entries(
    bytes: &[u8],
    cursor: &mut usize,
    manifest_end: usize,
    entry_count: u32,
) -> Result<()> {
    for _ in 0..entry_count {
        let name_len: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        if name_len > PHAR_ENTRY_NAME_CAP {
            return Err(Error::PharManifestTruncated {
                offset: *cursor,
                need: name_len as usize,
            });
        }
        take_bytes_within(bytes, cursor, name_len as usize, manifest_end)?;
        let _uncompressed_size: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        let _timestamp: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        let _stored_size: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        let _crc32: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        let _flags: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        let entry_meta_len: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        if entry_meta_len > PHAR_META_CAP {
            return Err(Error::PharManifestTruncated {
                offset: *cursor,
                need: entry_meta_len as usize,
            });
        }
        take_bytes_within(bytes, cursor, entry_meta_len as usize, manifest_end)?;
    }
    Ok(())
}

fn preflight_entries(
    bytes: &[u8],
    cursor: &mut usize,
    manifest_end: usize,
    entry_count: u32,
) -> Result<()> {
    let mut payload_cursor: usize = manifest_end;
    let mut total_output: usize = 0;
    for _ in 0..entry_count {
        let name_len: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        if name_len > PHAR_ENTRY_NAME_CAP {
            return Err(Error::PharManifestTruncated {
                offset: *cursor,
                need: name_len as usize,
            });
        }
        let name_bytes: &[u8] = take_bytes_within(bytes, cursor, name_len as usize, manifest_end)?;
        let name: std::borrow::Cow<'_, str> = String::from_utf8_lossy(name_bytes);
        let uncompressed_size: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        let _timestamp: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        let stored_size: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        if stored_size > PHAR_PAYLOAD_CAP {
            return Err(Error::PharEntryPayloadTruncated {
                name: name.into_owned(),
                need: stored_size,
                got: 0,
            });
        }
        let stored_len: usize = stored_size as usize;
        let payload_end: usize = payload_cursor.checked_add(stored_len).ok_or_else(|| {
            Error::PharEntryPayloadTruncated {
                name: name.to_string(),
                need: stored_size,
                got: bytes.len().saturating_sub(payload_cursor),
            }
        })?;
        if payload_end > bytes.len() {
            return Err(Error::PharEntryPayloadTruncated {
                name: name.into_owned(),
                need: stored_size,
                got: bytes.len().saturating_sub(payload_cursor),
            });
        }
        payload_cursor = payload_end;
        let _crc32: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        let flags: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        let entry_meta_len: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
        if entry_meta_len > PHAR_META_CAP {
            return Err(Error::PharManifestTruncated {
                offset: *cursor,
                need: entry_meta_len as usize,
            });
        }
        take_bytes_within(bytes, cursor, entry_meta_len as usize, manifest_end)?;
        let compression: PharCompression = decode_compression(name.as_ref(), flags)?;
        let entry_output: usize = match compression {
            PharCompression::None => stored_len,
            PharCompression::Deflate | PharCompression::Bzip2 => declared_output_len_from_parts(
                name.as_ref(),
                uncompressed_size,
                stored_size,
                stored_len,
            )?,
        };
        let Some(projected_output): Option<usize> = total_output.checked_add(entry_output) else {
            return Err(Error::PharArchiveQuotaExceeded {
                declared: usize::MAX,
                cap: PHAR_DECOMPRESS_CAP,
            });
        };
        if projected_output > PHAR_DECOMPRESS_CAP {
            return Err(Error::PharArchiveQuotaExceeded {
                declared: projected_output,
                cap: PHAR_DECOMPRESS_CAP,
            });
        }
        total_output = projected_output;
    }
    Ok(())
}

fn decode_compression(name: &str, bits: u32) -> Result<PharCompression> {
    let masked: u32 = bits & 0x0000_f000;
    match masked {
        0 => Ok(PharCompression::None),
        FLAG_COMPRESSED_GZ => Ok(PharCompression::Deflate),
        FLAG_COMPRESSED_BZ => Ok(PharCompression::Bzip2),
        _ => Err(Error::PharUnsupportedCompression {
            name: name.to_string(),
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

fn read_entry_meta(bytes: &[u8], cursor: &mut usize, manifest_end: usize) -> Result<PharEntryMeta> {
    let name_len: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
    if name_len > PHAR_ENTRY_NAME_CAP {
        return Err(Error::PharManifestTruncated {
            offset: *cursor,
            need: name_len as usize,
        });
    }
    let name_bytes: &[u8] = take_bytes_within(bytes, cursor, name_len as usize, manifest_end)?;
    let name: String = String::from_utf8_lossy(name_bytes).into_owned();
    let uncompressed_size: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
    let timestamp: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
    let stored_size: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
    if stored_size > PHAR_PAYLOAD_CAP {
        return Err(Error::PharEntryPayloadTruncated {
            name,
            need: stored_size,
            got: 0,
        });
    }
    let crc32: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
    let flags: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
    let entry_meta_len: u32 = read_u32_le_within(bytes, cursor, manifest_end)?;
    if entry_meta_len > PHAR_META_CAP {
        return Err(Error::PharManifestTruncated {
            offset: *cursor,
            need: entry_meta_len as usize,
        });
    }
    take_bytes_within(bytes, cursor, entry_meta_len as usize, manifest_end)?;
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

fn read_u32_le_within(bytes: &[u8], cursor: &mut usize, manifest_end: usize) -> Result<u32> {
    ensure_manifest_range(*cursor, 4, manifest_end)?;
    read_u32_le(bytes, cursor)
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

fn read_u16_be_within(bytes: &[u8], cursor: &mut usize, manifest_end: usize) -> Result<u16> {
    ensure_manifest_range(*cursor, 2, manifest_end)?;
    read_u16_be(bytes, cursor)
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

fn take_bytes_within<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
    manifest_end: usize,
) -> Result<&'a [u8]> {
    ensure_manifest_range(*cursor, len, manifest_end)?;
    take_bytes(bytes, cursor, len)
}

fn ensure_manifest_range(cursor: usize, len: usize, manifest_end: usize) -> Result<()> {
    let end: usize = cursor
        .checked_add(len)
        .ok_or(Error::PharManifestTruncated {
            offset: cursor,
            need: len,
        })?;
    if end > manifest_end {
        return Err(Error::PharManifestTruncated {
            offset: cursor,
            need: end - manifest_end,
        });
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{Error, try_bounded};

    #[test]
    fn bounded_reader_rejects_output_past_supplied_cap() {
        let source: Cursor<&[u8]> = Cursor::new(b"abcd");
        let result: Result<Option<Vec<u8>>, Error> = try_bounded(source, 2, "payload", 3);
        assert!(matches!(
            result,
            Err(Error::PharDecompressBomb { name, cap }) if name == "payload" && cap == 3
        ));
    }
}
