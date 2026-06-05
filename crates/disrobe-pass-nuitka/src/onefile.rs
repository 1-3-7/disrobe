//! Nuitka `--onefile` payload extraction.

use std::io::Read;

use crate::error::{Error, Result};

/// Hard ceiling on a single contained file.
const MAX_ENTRY_SIZE: u64 = 8 * 1024 * 1024 * 1024;

/// Hard ceiling on the number of entries in one payload.
const MAX_ENTRY_COUNT: usize = 1 << 20;

/// Decompression-bomb guard: max expansion factor over compressed size.
const MAX_DECOMPRESSION_RATIO: u64 = 1024;

/// Absolute ceiling on decompressed payload size.
const MAX_DECOMPRESSED_ABS: u64 = 16 * 1024 * 1024 * 1024;

/// Longest filename (in bytes) accepted before declaring the stream malformed.
const MAX_FILENAME_BYTES: usize = 4096;

/// Little-endian zstd frame magic (`0xFD2FB528`).
const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Filename character width used by the writer per host OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilenameEncoding {
    /// Windows builds: UTF-16LE, 2-byte code units, 2-byte NUL terminator.
    Utf16Le,
    /// POSIX builds: UTF-8, 1-byte units, 1-byte NUL terminator.
    Utf8,
}

/// A single file recovered from a onefile payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnefileEntry {
    /// Path relative to the payload root, separators as the build emitted them.
    pub filename: String,
    /// Declared (and verified-present) byte length of the file data.
    pub size: u64,
    /// Offset of the file data within the decompressed entry stream.
    pub data_offset: usize,
    /// The recovered file bytes.
    pub data: Vec<u8>,
    /// POSIX permission/flags byte when present (POSIX builds), else `None`.
    pub permissions: Option<u8>,
    /// CRC32 when the build embedded per-file checksums (cached mode), else `None`.
    pub crc32: Option<u32>,
    /// Symlink target for POSIX symlink entries (`flags & 2`), else `None`.
    pub symlink_target: Option<String>,
}

/// Outcome of decoding a onefile payload.
#[derive(Debug)]
pub struct OnefilePayload {
    /// Whether the payload body was zstd-compressed (`KAY`).
    pub compressed: bool,
    /// Filename encoding inferred from a clean walk.
    pub encoding: FilenameEncoding,
    /// Whether per-file CRC32 checksums were present (cached mode).
    pub has_checksums: bool,
    /// The recovered entries, in payload order.
    pub entries: Vec<OnefileEntry>,
    /// Length in bytes of the decompressed entry stream.
    pub payload_size: usize,
}

/// Decode a Nuitka `--onefile` payload that begins at `payload_offset` within `image`.
pub fn extract_onefile(image: &[u8], payload_offset: usize) -> Result<OnefilePayload> {
    let header_end: usize = payload_offset
        .checked_add(3)
        .ok_or(Error::EntryTruncated(payload_offset))?;
    if header_end > image.len() {
        return Err(Error::EntryTruncated(payload_offset));
    }
    let magic: [u8; 3] = [
        image[payload_offset],
        image[payload_offset + 1],
        image[payload_offset + 2],
    ];
    if magic[0] != b'K' || magic[1] != b'A' {
        return Err(Error::BadOnefileMagic(magic));
    }
    let compressed: bool = match magic[2] {
        b'X' => false,
        b'Y' => true,
        _ => return Err(Error::BadOnefileMagic(magic)),
    };

    let body: &[u8] = &image[header_end..];
    let stream: Vec<u8> = if compressed {
        decompress_payload(body)?
    } else {
        body.to_vec()
    };

    let walk: WalkOutcome = walk_payload(&stream)?;

    Ok(OnefilePayload {
        compressed,
        encoding: walk.encoding,
        has_checksums: walk.has_checksums,
        entries: walk.entries,
        payload_size: walk.consumed,
    })
}

/// Decode the (possibly multi-frame) zstd entry stream.
fn decompress_payload(body: &[u8]) -> Result<Vec<u8>> {
    let cap: u64 = (body.len() as u64)
        .saturating_mul(MAX_DECOMPRESSION_RATIO)
        .min(MAX_DECOMPRESSED_ABS);
    let mut out: Vec<u8> = Vec::new();
    let mut rest: &[u8] = body;

    if !starts_zstd_frame(rest) {
        return Err(Error::Zstd(
            "payload marked compressed but does not begin with a zstd frame".to_owned(),
        ));
    }

    while starts_zstd_frame(rest) {
        let decoder: zstd::stream::read::Decoder<'_, std::io::BufReader<&[u8]>> =
            zstd::stream::read::Decoder::new(rest).map_err(|e| Error::Zstd(format!("{e}")))?;
        let mut frame: zstd::stream::read::Decoder<'_, std::io::BufReader<&[u8]>> =
            decoder.single_frame();

        let before: usize = out.len();
        let budget: u64 = cap.saturating_sub(out.len() as u64).saturating_add(1);
        let mut limited: std::io::Take<
            &mut zstd::stream::read::Decoder<'_, std::io::BufReader<&[u8]>>,
        > = Read::take(&mut frame, budget);
        limited
            .read_to_end(&mut out)
            .map_err(|e| Error::Zstd(format!("{e}")))?;
        if out.len() as u64 > cap {
            return Err(Error::Zstd(format!(
                "decompressed payload exceeds bomb cap of {cap} bytes"
            )));
        }

        let mut reader: std::io::BufReader<&[u8]> = frame.finish();
        let buffered: usize = std::io::BufRead::fill_buf(&mut reader)
            .map_err(|e| Error::Zstd(format!("{e}")))?
            .len();
        let consumed: usize = rest.len().saturating_sub(buffered);
        if consumed == 0 && out.len() == before {
            return Err(Error::Zstd(
                "zstd frame made no progress (truncated stream)".to_owned(),
            ));
        }
        rest = &rest[consumed..];
    }

    Ok(out)
}

/// Whether `bytes` begins a regular or skippable zstd frame.
#[inline]
fn starts_zstd_frame(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let head: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
    head == ZSTD_FRAME_MAGIC
        || (head[0] & 0xF0 == 0x50 && head[1] == 0x2A && head[2] == 0x4D && head[3] == 0x18)
}

struct WalkOutcome {
    entries: Vec<OnefileEntry>,
    encoding: FilenameEncoding,
    has_checksums: bool,
    consumed: usize,
}

/// Walk the decompressed entry stream, selecting the layout that consumes it cleanly.
fn walk_payload(stream: &[u8]) -> Result<WalkOutcome> {
    let candidates: [(FilenameEncoding, bool); 4] = [
        (FilenameEncoding::Utf16Le, false),
        (FilenameEncoding::Utf16Le, true),
        (FilenameEncoding::Utf8, false),
        (FilenameEncoding::Utf8, true),
    ];

    let mut last_err: Error = Error::EmptyPayload;
    for (encoding, has_checksums) in candidates {
        match try_walk(stream, encoding, has_checksums) {
            Ok((entries, consumed)) if consumed == stream.len() => {
                return Ok(WalkOutcome {
                    entries,
                    encoding,
                    has_checksums,
                    consumed,
                });
            }
            Ok(_) => last_err = Error::EntryTruncated(stream.len()),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Attempt one layout, returning the entries and the number of bytes consumed.
fn try_walk(
    stream: &[u8],
    encoding: FilenameEncoding,
    has_checksums: bool,
) -> Result<(Vec<OnefileEntry>, usize)> {
    let mut entries: Vec<OnefileEntry> = Vec::new();
    let mut cursor: usize = 0usize;

    loop {
        if cursor == stream.len() {
            break;
        }
        let (filename, name_end): (String, usize) =
            read_name(stream, cursor, encoding).ok_or(Error::EntryTruncated(cursor))?;
        cursor = name_end;
        if filename.is_empty() {
            break;
        }
        if entries.len() >= MAX_ENTRY_COUNT {
            return Err(Error::EntryTruncated(cursor));
        }

        let mut permissions: Option<u8> = None;
        if matches!(encoding, FilenameEncoding::Utf8) {
            let &flags: &u8 = stream.get(cursor).ok_or(Error::EntryTruncated(cursor))?;
            cursor += 1;
            permissions = Some(flags);
            if flags & 2 != 0 {
                let (target, target_end): (String, usize) =
                    read_name(stream, cursor, encoding).ok_or(Error::EntryTruncated(cursor))?;
                cursor = target_end;
                entries.push(OnefileEntry {
                    filename,
                    size: 0,
                    data_offset: cursor,
                    data: Vec::new(),
                    permissions,
                    crc32: None,
                    symlink_target: Some(target),
                });
                continue;
            }
        }

        let size: u64 = read_u64_le(stream, cursor).ok_or(Error::EntryTruncated(cursor))?;
        cursor += 8;
        if size > MAX_ENTRY_SIZE {
            return Err(Error::EntryTruncated(cursor));
        }

        let crc32: Option<u32> = if has_checksums {
            let value: u32 = read_u32_le(stream, cursor).ok_or(Error::EntryTruncated(cursor))?;
            cursor += 4;
            Some(value)
        } else {
            None
        };

        let size_usize: usize = usize::try_from(size).map_err(|_| Error::EntryTruncated(cursor))?;
        let data_offset: usize = cursor;
        let end: usize = cursor
            .checked_add(size_usize)
            .ok_or(Error::EntryTruncated(cursor))?;
        if end > stream.len() {
            return Err(Error::EntryTruncated(cursor));
        }
        let data: Vec<u8> = stream[data_offset..end].to_vec();
        cursor = end;

        entries.push(OnefileEntry {
            filename,
            size,
            data_offset,
            data,
            permissions,
            crc32,
            symlink_target: None,
        });
    }

    Ok((entries, cursor))
}

/// Read a NUL-terminated filename in the given encoding, returning it and the cursor past the terminator.
fn read_name(stream: &[u8], start: usize, encoding: FilenameEncoding) -> Option<(String, usize)> {
    match encoding {
        FilenameEncoding::Utf16Le => read_name_utf16le(stream, start),
        FilenameEncoding::Utf8 => read_name_utf8(stream, start),
    }
}

fn read_name_utf16le(stream: &[u8], start: usize) -> Option<(String, usize)> {
    let mut cursor: usize = start;
    let mut units: Vec<u16> = Vec::new();
    loop {
        let unit: u16 = read_u16_le(stream, cursor)?;
        cursor += 2;
        if unit == 0 {
            break;
        }
        if !is_plausible_path_unit(unit) {
            return None;
        }
        if units.len() * 2 >= MAX_FILENAME_BYTES {
            return None;
        }
        units.push(unit);
    }
    let name: String = String::from_utf16(&units).ok()?;
    Some((name, cursor))
}

fn read_name_utf8(stream: &[u8], start: usize) -> Option<(String, usize)> {
    let rel: usize = stream.get(start..)?.iter().position(|&b| b == 0)?;
    if rel > MAX_FILENAME_BYTES {
        return None;
    }
    let raw: &[u8] = stream.get(start..start + rel)?;
    if !raw.iter().all(|&b| is_plausible_path_byte(b)) {
        return None;
    }
    let name: &str = core::str::from_utf8(raw).ok()?;
    Some((name.to_owned(), start + rel + 1))
}

#[inline]
const fn is_plausible_path_unit(unit: u16) -> bool {
    match unit {
        0x20..=0x7E => {
            unit != b'?' as u16
                && unit != b'*' as u16
                && unit != b'<' as u16
                && unit != b'>' as u16
                && unit != b'|' as u16
                && unit != b'"' as u16
        }
        _ => unit >= 0xA0,
    }
}

#[inline]
const fn is_plausible_path_byte(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7E | 0x80..=0xFF)
        && !matches!(byte, b'?' | b'*' | b'<' | b'>' | b'|' | b'"')
}

#[inline]
fn read_u16_le(stream: &[u8], at: usize) -> Option<u16> {
    let bytes: &[u8] = stream.get(at..at + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[inline]
fn read_u32_le(stream: &[u8], at: usize) -> Option<u32> {
    let bytes: &[u8] = stream.get(at..at + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[inline]
fn read_u64_le(stream: &[u8], at: usize) -> Option<u64> {
    let bytes: &[u8] = stream.get(at..at + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Build an uncompressed Windows-layout (`KAX`, UTF-16LE, no checksum) payload.
    fn build_kax_win(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out: Vec<u8> = b"KAX".to_vec();
        for (name, data) in entries {
            for unit in name.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out.extend_from_slice(&[0u8, 0u8]);
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            out.extend_from_slice(data);
        }
        out.extend_from_slice(&[0u8, 0u8]);
        out
    }

    /// Cached-mode Windows layout: like [`build_kax_win`] but with a `u32` CRC32 per entry.
    fn build_kax_win_crc(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut out: Vec<u8> = b"KAX".to_vec();
        for (name, data, crc) in entries {
            for unit in name.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out.extend_from_slice(&[0u8, 0u8]);
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(data);
        }
        out.extend_from_slice(&[0u8, 0u8]);
        out
    }

    /// POSIX layout: `KAX`, UTF-8 names, 1-byte flags, no checksum.
    fn build_kax_posix(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut out: Vec<u8> = b"KAX".to_vec();
        for (name, flags, data) in entries {
            out.extend_from_slice(name.as_bytes());
            out.push(0u8);
            out.push(*flags);
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            out.extend_from_slice(data);
        }
        out.push(0u8);
        out
    }

    #[test]
    fn missing_magic_errors() {
        let bytes: Vec<u8> = vec![0u8; 1024];
        let Err(err): Result<OnefilePayload> = extract_onefile(&bytes, 0) else {
            panic!("zero bytes must trigger bad-magic");
        };
        assert!(matches!(err, Error::BadOnefileMagic(_)));
    }

    #[test]
    fn empty_kax_is_empty_archive() {
        let bytes: Vec<u8> = build_kax_win(&[]);
        let payload: OnefilePayload = extract_onefile(&bytes, 0).expect("empty KAX");
        assert!(!payload.compressed);
        assert!(payload.entries.is_empty());
        assert_eq!(payload.encoding, FilenameEncoding::Utf16Le);
    }

    #[test]
    fn windows_no_checksum_round_trips() {
        let bytes: Vec<u8> =
            build_kax_win(&[("hello.exe", b"MZ\x90\x00data"), ("_wmi.pyd", b"MZxx")]);
        let payload: OnefilePayload = extract_onefile(&bytes, 0).expect("win kax");
        assert_eq!(payload.encoding, FilenameEncoding::Utf16Le);
        assert!(!payload.has_checksums);
        assert_eq!(payload.entries.len(), 2);
        assert_eq!(payload.entries[0].filename, "hello.exe");
        assert_eq!(payload.entries[0].data, b"MZ\x90\x00data");
        assert_eq!(payload.entries[1].filename, "_wmi.pyd");
        assert_eq!(payload.entries[1].crc32, None);
    }

    #[test]
    fn windows_with_checksum_round_trips() {
        let bytes: Vec<u8> = build_kax_win_crc(&[
            ("a.dll", b"MZ____", 0xDEAD_BEEF),
            ("b.pyd", b"MZ__", 0x0000_0001),
        ]);
        let payload: OnefilePayload = extract_onefile(&bytes, 0).expect("win crc kax");
        assert!(payload.has_checksums);
        assert_eq!(payload.entries[0].crc32, Some(0xDEAD_BEEF));
        assert_eq!(payload.entries[0].data, b"MZ____");
        assert_eq!(payload.entries[1].crc32, Some(0x0000_0001));
    }

    #[test]
    fn posix_flags_round_trip() {
        let bytes: Vec<u8> = build_kax_posix(&[
            ("bin/app", 1u8, b"\x7fELFdata"),
            ("lib/x.so", 0u8, b"\x7fELF"),
        ]);
        let payload: OnefilePayload = extract_onefile(&bytes, 0).expect("posix kax");
        assert_eq!(payload.encoding, FilenameEncoding::Utf8);
        assert_eq!(payload.entries[0].filename, "bin/app");
        assert_eq!(payload.entries[0].permissions, Some(1u8));
        assert_eq!(payload.entries[0].data, b"\x7fELFdata");
        assert_eq!(payload.entries[1].permissions, Some(0u8));
    }

    #[test]
    fn truncated_size_field_errors() {
        let mut bytes: Vec<u8> = b"KAX".to_vec();
        for unit in "oops".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0u8, 0u8, 0u8]);
        let Err(err): Result<OnefilePayload> = extract_onefile(&bytes, 0) else {
            panic!("truncated payload must error");
        };
        assert!(matches!(
            err,
            Error::EntryTruncated(_) | Error::EmptyPayload
        ));
    }

    #[test]
    fn declared_size_overrun_errors() {
        let mut bytes: Vec<u8> = b"KAX".to_vec();
        for unit in "big.bin".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0u8, 0u8]);
        bytes.extend_from_slice(&100_000u64.to_le_bytes());
        bytes.push(0u8);
        let Err(err): Result<OnefilePayload> = extract_onefile(&bytes, 0) else {
            panic!("overlong declared size must error");
        };
        assert!(matches!(
            err,
            Error::EntryTruncated(_) | Error::EmptyPayload
        ));
    }

    #[test]
    fn compressed_kay_round_trips() {
        let inner: Vec<u8> = build_kax_win(&[("mod.pyc", b"\xee\x0c\r\nmarshalbytes")]);
        let stream: &[u8] = &inner[3..];
        let compressed: Vec<u8> = zstd::stream::encode_all(stream, 19).expect("zstd encode");
        let mut payload: Vec<u8> = b"KAY".to_vec();
        payload.extend_from_slice(&compressed);
        let decoded: OnefilePayload = extract_onefile(&payload, 0).expect("kay round trip");
        assert!(decoded.compressed);
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].filename, "mod.pyc");
        assert_eq!(decoded.entries[0].data, b"\xee\x0c\r\nmarshalbytes");
    }

    #[test]
    fn multi_frame_zstd_concatenation_decodes() {
        let inner: Vec<u8> = build_kax_win(&[("a.bin", b"AAAAAAAA"), ("b.bin", b"BBBBBBBB")]);
        let stream: &[u8] = &inner[3..];
        let mid: usize = stream.len() / 2;
        let mut compressed: Vec<u8> =
            zstd::stream::encode_all(&stream[..mid], 19).expect("frame 1");
        let frame2: Vec<u8> = zstd::stream::encode_all(&stream[mid..], 19).expect("frame 2");
        compressed.extend_from_slice(&frame2);
        let mut payload: Vec<u8> = b"KAY".to_vec();
        payload.extend_from_slice(&compressed);
        let decoded: OnefilePayload = extract_onefile(&payload, 0).expect("multi-frame");
        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.entries[0].data, b"AAAAAAAA");
        assert_eq!(decoded.entries[1].data, b"BBBBBBBB");
    }
}
