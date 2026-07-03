use std::io::Read;

use crate::error::{Error, Result};

const MAX_ENTRY_SIZE: u64 = 512 * 1024 * 1024;

const MAX_ENTRY_COUNT: usize = 1 << 20;

const MAX_DECOMPRESSION_RATIO: u64 = 1024;

const MAX_DECOMPRESSED_ABS: u64 = 512 * 1024 * 1024;

const MAX_FILENAME_BYTES: usize = 4096;

const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilenameEncoding {
    Utf16Le,

    Utf8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnefileEntry {
    pub filename: String,

    pub size: u64,

    pub data_offset: usize,

    pub data: Vec<u8>,

    pub permissions: Option<u8>,

    pub crc32: Option<u32>,

    pub symlink_target: Option<String>,
}

#[derive(Debug)]
pub struct OnefilePayload {
    pub compressed: bool,

    pub encoding: FilenameEncoding,

    pub has_checksums: bool,

    pub entries: Vec<OnefileEntry>,

    pub payload_size: usize,
}

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
    crate::util::dbg_line(&format!(
        "extract_onefile: offset={payload_offset} magic={magic:?} compressed={compressed} body_len={}",
        body.len()
    ));
    let decompressed: Option<Vec<u8>> = if compressed {
        Some(decompress_payload(body)?)
    } else {
        None
    };
    let stream: &[u8] = decompressed.as_deref().unwrap_or(body);
    crate::util::dbg_line(&format!("extract_onefile: stream_len={}", stream.len()));
    crate::util::dbg_hex("extract_onefile: stream head", stream, 256);

    let walk: WalkOutcome = walk_payload(stream)?;

    Ok(OnefilePayload {
        compressed,
        encoding: walk.encoding,
        has_checksums: walk.has_checksums,
        entries: walk.entries,
        payload_size: walk.consumed,
    })
}

#[derive(Debug)]
pub struct StreamedEntry<'a> {
    pub filename: String,
    pub size: u64,
    pub permissions: Option<u8>,
    pub crc32: Option<u32>,
    pub symlink_target: Option<String>,
    pub data: &'a [u8],
}

#[derive(Debug)]
pub struct StreamedPayload {
    pub compressed: bool,
    pub encoding: FilenameEncoding,
    pub has_checksums: bool,
    pub entry_count: usize,
}

/// Walk a Nuitka onefile payload and hand each entry to `sink` as a borrowed slice of the decoded
/// stream, never collecting an owned `data: Vec<u8>` per entry.
///
/// The decoded stream is held once (callers writing each entry to disk in `sink` keep peak memory
/// at roughly the stream plus the input image, not the doubled copy `extract_onefile` builds). The
/// `sink` returning `Err` aborts the walk with that error.
pub fn extract_onefile_streaming(
    image: &[u8],
    payload_offset: usize,
    sink: &mut dyn FnMut(&StreamedEntry<'_>) -> std::io::Result<()>,
) -> Result<StreamedPayload> {
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
    if !compressed {
        let (encoding, has_checksums): (FilenameEncoding, bool) = detect_walk_params(body)?;
        let entry_count: usize = stream_entries(body, encoding, has_checksums, sink)?;
        return Ok(StreamedPayload {
            compressed,
            encoding,
            has_checksums,
            entry_count,
        });
    }

    let mut reader: ZstdConcatReader<'_> = ZstdConcatReader::new(body)?;
    let (encoding, has_checksums, prefix): (FilenameEncoding, bool, Vec<u8>) =
        detect_walk_params_streaming(&mut reader)?;
    let entry_count: usize =
        stream_entries_read(prefix, &mut reader, encoding, has_checksums, sink)?;

    Ok(StreamedPayload {
        compressed,
        encoding,
        has_checksums,
        entry_count,
    })
}

const STREAM_DETECT_PREFIX: usize = 256 * 1024;
const STREAM_COPY_CHUNK: usize = 1 << 20;

struct ZstdConcatReader<'a> {
    rest: &'a [u8],
    frame: Option<zstd::stream::read::Decoder<'a, std::io::BufReader<&'a [u8]>>>,
    produced: u64,
    cap: u64,
}

impl<'a> ZstdConcatReader<'a> {
    fn new(body: &'a [u8]) -> Result<Self> {
        if !starts_zstd_frame(body) {
            return Err(Error::Zstd(
                "payload marked compressed but does not begin with a zstd frame".to_owned(),
            ));
        }
        let cap: u64 = (body.len() as u64)
            .saturating_mul(MAX_DECOMPRESSION_RATIO)
            .min(MAX_DECOMPRESSED_ABS);
        Ok(Self {
            rest: body,
            frame: None,
            produced: 0,
            cap,
        })
    }
}

impl std::io::Read for ZstdConcatReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.frame.is_none() {
                if !starts_zstd_frame(self.rest) {
                    return Ok(0);
                }
                let decoder: zstd::stream::read::Decoder<'_, std::io::BufReader<&[u8]>> =
                    zstd::stream::read::Decoder::new(self.rest)
                        .map_err(|e| std::io::Error::other(format!("{e}")))?;
                self.frame = Some(decoder.single_frame());
            }
            let Some(frame): Option<
                &mut zstd::stream::read::Decoder<'_, std::io::BufReader<&[u8]>>,
            > = self.frame.as_mut() else {
                return Ok(0);
            };
            let n: usize = frame.read(buf)?;
            if n > 0 {
                self.produced = self.produced.saturating_add(n as u64);
                if self.produced > self.cap {
                    return Err(std::io::Error::other(format!(
                        "decompressed payload exceeds bomb cap of {} bytes",
                        self.cap
                    )));
                }
                return Ok(n);
            }
            let Some(frame): Option<zstd::stream::read::Decoder<'_, std::io::BufReader<&[u8]>>> =
                self.frame.take()
            else {
                return Ok(0);
            };
            let mut inner: std::io::BufReader<&[u8]> = frame.finish();
            let buffered: usize = std::io::BufRead::fill_buf(&mut inner)?.len();
            let consumed: usize = self.rest.len().saturating_sub(buffered);
            if consumed == 0 {
                return Ok(0);
            }
            self.rest = &self.rest[consumed..];
        }
    }
}

fn detect_walk_params_streaming(
    reader: &mut dyn std::io::Read,
) -> Result<(FilenameEncoding, bool, Vec<u8>)> {
    let mut prefix: Vec<u8> = Vec::with_capacity(STREAM_DETECT_PREFIX);
    let mut chunk: [u8; 8192] = [0u8; 8192];
    while prefix.len() < STREAM_DETECT_PREFIX {
        let n: usize = reader
            .read(&mut chunk)
            .map_err(|e| Error::Zstd(format!("{e}")))?;
        if n == 0 {
            break;
        }
        prefix.extend_from_slice(&chunk[..n]);
    }
    let candidates: [(FilenameEncoding, bool); 4] = [
        (FilenameEncoding::Utf16Le, false),
        (FilenameEncoding::Utf16Le, true),
        (FilenameEncoding::Utf8, false),
        (FilenameEncoding::Utf8, true),
    ];
    for (encoding, has_checksums) in candidates {
        if first_entry_plausible(&prefix, encoding, has_checksums) {
            return Ok((encoding, has_checksums, prefix));
        }
    }
    Err(Error::EmptyPayload)
}

fn first_entry_plausible(prefix: &[u8], encoding: FilenameEncoding, has_checksums: bool) -> bool {
    let Some((name, mut cursor)): Option<(String, usize)> = read_name(prefix, 0, encoding) else {
        return false;
    };
    if name.is_empty() {
        return false;
    }
    if matches!(encoding, FilenameEncoding::Utf8) {
        let Some(&flags): Option<&u8> = prefix.get(cursor) else {
            return false;
        };
        cursor += 1;
        if flags & 2 != 0 {
            return read_name(prefix, cursor, encoding).is_some();
        }
    }
    let Some(size): Option<u64> = read_u64_le(prefix, cursor) else {
        return false;
    };
    cursor += 8;
    if size > MAX_ENTRY_SIZE {
        return false;
    }
    if has_checksums && read_u32_le(prefix, cursor).is_none() {
        return false;
    }
    true
}

fn stream_entries_read(
    prefix: Vec<u8>,
    reader: &mut dyn std::io::Read,
    encoding: FilenameEncoding,
    has_checksums: bool,
    sink: &mut dyn FnMut(&StreamedEntry<'_>) -> std::io::Result<()>,
) -> Result<usize> {
    let mut src: PrefixThenReader<'_> = PrefixThenReader::new(prefix, reader);
    let mut head: Vec<u8> = Vec::with_capacity(4096);
    let mut data: Vec<u8> = Vec::new();
    let mut count: usize = 0;

    loop {
        head.clear();
        let Some((filename, _name_consumed)): Option<(String, usize)> =
            read_name_from(&mut src, &mut head, encoding)?
        else {
            break;
        };
        if filename.is_empty() {
            break;
        }
        if count >= MAX_ENTRY_COUNT {
            return Err(Error::EntryTruncated(count));
        }

        let mut permissions: Option<u8> = None;
        if matches!(encoding, FilenameEncoding::Utf8) {
            let flags: u8 = src.read_u8()?.ok_or(Error::EntryTruncated(count))?;
            permissions = Some(flags);
            if flags & 2 != 0 {
                head.clear();
                let (target, _consumed): (String, usize) =
                    read_name_from(&mut src, &mut head, encoding)?
                        .ok_or(Error::EntryTruncated(count))?;
                sink(&StreamedEntry {
                    filename,
                    size: 0,
                    permissions,
                    crc32: None,
                    symlink_target: Some(target),
                    data: &[],
                })
                .map_err(Error::Io)?;
                count += 1;
                continue;
            }
        }

        let size: u64 = src.read_u64_le()?.ok_or(Error::EntryTruncated(count))?;
        if size > MAX_ENTRY_SIZE {
            return Err(Error::EntryTruncated(count));
        }
        let crc32: Option<u32> = if has_checksums {
            Some(src.read_u32_le()?.ok_or(Error::EntryTruncated(count))?)
        } else {
            None
        };
        let size_usize: usize = usize::try_from(size).map_err(|_| Error::EntryTruncated(count))?;
        data.clear();
        src.read_exact_into(&mut data, size_usize)?;
        sink(&StreamedEntry {
            filename,
            size,
            permissions,
            crc32,
            symlink_target: None,
            data: &data,
        })
        .map_err(Error::Io)?;
        count += 1;
    }
    Ok(count)
}

struct PrefixThenReader<'a> {
    prefix: Vec<u8>,
    pos: usize,
    reader: &'a mut dyn std::io::Read,
}

impl<'a> PrefixThenReader<'a> {
    fn new(prefix: Vec<u8>, reader: &'a mut dyn std::io::Read) -> Self {
        Self {
            prefix,
            pos: 0,
            reader,
        }
    }

    fn read_byte(&mut self) -> Result<Option<u8>> {
        if self.pos < self.prefix.len() {
            let b: u8 = self.prefix[self.pos];
            self.pos += 1;
            return Ok(Some(b));
        }
        let mut one: [u8; 1] = [0u8; 1];
        let n: usize = self
            .reader
            .read(&mut one)
            .map_err(|e| Error::Zstd(format!("{e}")))?;
        if n == 0 { Ok(None) } else { Ok(Some(one[0])) }
    }

    fn read_u8(&mut self) -> Result<Option<u8>> {
        self.read_byte()
    }

    fn read_u16_le(&mut self) -> Result<Option<u16>> {
        let Some(a): Option<u8> = self.read_byte()? else {
            return Ok(None);
        };
        let Some(b): Option<u8> = self.read_byte()? else {
            return Ok(None);
        };
        Ok(Some(u16::from_le_bytes([a, b])))
    }

    fn read_u32_le(&mut self) -> Result<Option<u32>> {
        let mut buf: [u8; 4] = [0u8; 4];
        for slot in &mut buf {
            let Some(b): Option<u8> = self.read_byte()? else {
                return Ok(None);
            };
            *slot = b;
        }
        Ok(Some(u32::from_le_bytes(buf)))
    }

    fn read_u64_le(&mut self) -> Result<Option<u64>> {
        let mut buf: [u8; 8] = [0u8; 8];
        for slot in &mut buf {
            let Some(b): Option<u8> = self.read_byte()? else {
                return Ok(None);
            };
            *slot = b;
        }
        Ok(Some(u64::from_le_bytes(buf)))
    }

    fn read_exact_into(&mut self, out: &mut Vec<u8>, len: usize) -> Result<()> {
        let from_prefix: usize = (self.prefix.len() - self.pos).min(len);
        out.extend_from_slice(&self.prefix[self.pos..self.pos + from_prefix]);
        self.pos += from_prefix;
        let mut remaining: usize = len - from_prefix;
        let mut chunk: Vec<u8> = vec![0u8; STREAM_COPY_CHUNK.min(remaining.max(1))];
        while remaining > 0 {
            let want: usize = remaining.min(chunk.len());
            let n: usize = self
                .reader
                .read(&mut chunk[..want])
                .map_err(|e| Error::Zstd(format!("{e}")))?;
            if n == 0 {
                return Err(Error::EntryTruncated(out.len()));
            }
            out.extend_from_slice(&chunk[..n]);
            remaining -= n;
        }
        Ok(())
    }
}

fn read_name_from(
    src: &mut PrefixThenReader<'_>,
    head: &mut Vec<u8>,
    encoding: FilenameEncoding,
) -> Result<Option<(String, usize)>> {
    match encoding {
        FilenameEncoding::Utf16Le => {
            let mut units: Vec<u16> = Vec::new();
            loop {
                let Some(unit): Option<u16> = src.read_u16_le()? else {
                    return Ok(None);
                };
                if unit == 0 {
                    break;
                }
                if !is_plausible_path_unit(unit) || units.len() * 2 >= MAX_FILENAME_BYTES {
                    return Err(Error::EntryTruncated(units.len()));
                }
                units.push(unit);
            }
            let name: String =
                String::from_utf16(&units).map_err(|_| Error::EntryTruncated(units.len()))?;
            Ok(Some((name, units.len())))
        }
        FilenameEncoding::Utf8 => {
            loop {
                let Some(b): Option<u8> = src.read_byte()? else {
                    return Ok(None);
                };
                if b == 0 {
                    break;
                }
                if !is_plausible_path_byte(b) || head.len() >= MAX_FILENAME_BYTES {
                    return Err(Error::EntryTruncated(head.len()));
                }
                head.push(b);
            }
            let name: String = core::str::from_utf8(head)
                .map_err(|_| Error::EntryTruncated(head.len()))?
                .to_owned();
            Ok(Some((name, head.len())))
        }
    }
}

fn detect_walk_params(stream: &[u8]) -> Result<(FilenameEncoding, bool)> {
    let candidates: [(FilenameEncoding, bool); 4] = [
        (FilenameEncoding::Utf16Le, false),
        (FilenameEncoding::Utf16Le, true),
        (FilenameEncoding::Utf8, false),
        (FilenameEncoding::Utf8, true),
    ];
    let mut last_err: Error = Error::EmptyPayload;
    for (encoding, has_checksums) in candidates {
        match count_walk(stream, encoding, has_checksums) {
            Ok((entries, consumed, terminated, data_total)) => {
                let exact: bool = consumed == stream.len();
                let trailer_ok: bool = terminated && entries > 0 && data_total > 0;
                if exact || trailer_ok {
                    return Ok((encoding, has_checksums));
                }
                last_err = Error::EntryTruncated(stream.len());
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn count_walk(
    stream: &[u8],
    encoding: FilenameEncoding,
    has_checksums: bool,
) -> Result<(usize, usize, bool, u64)> {
    let mut entries: usize = 0;
    let mut data_total: u64 = 0;
    let mut cursor: usize = 0usize;
    let mut terminated: bool = false;
    loop {
        if cursor == stream.len() {
            break;
        }
        let (filename, name_end): (String, usize) =
            read_name(stream, cursor, encoding).ok_or(Error::EntryTruncated(cursor))?;
        cursor = name_end;
        if filename.is_empty() {
            terminated = true;
            break;
        }
        if entries >= MAX_ENTRY_COUNT {
            return Err(Error::EntryTruncated(cursor));
        }
        if matches!(encoding, FilenameEncoding::Utf8) {
            let &flags: &u8 = stream.get(cursor).ok_or(Error::EntryTruncated(cursor))?;
            cursor += 1;
            if flags & 2 != 0 {
                let (_target, target_end): (String, usize) =
                    read_name(stream, cursor, encoding).ok_or(Error::EntryTruncated(cursor))?;
                cursor = target_end;
                entries += 1;
                continue;
            }
        }
        let size: u64 = read_u64_le(stream, cursor).ok_or(Error::EntryTruncated(cursor))?;
        cursor += 8;
        if size > MAX_ENTRY_SIZE {
            return Err(Error::EntryTruncated(cursor));
        }
        if has_checksums {
            let _value: u32 = read_u32_le(stream, cursor).ok_or(Error::EntryTruncated(cursor))?;
            cursor += 4;
        }
        let size_usize: usize = usize::try_from(size).map_err(|_| Error::EntryTruncated(cursor))?;
        let end: usize = cursor
            .checked_add(size_usize)
            .ok_or(Error::EntryTruncated(cursor))?;
        if end > stream.len() {
            return Err(Error::EntryTruncated(cursor));
        }
        data_total = data_total.saturating_add(size);
        entries += 1;
        cursor = end;
    }
    Ok((entries, cursor, terminated, data_total))
}

fn stream_entries(
    stream: &[u8],
    encoding: FilenameEncoding,
    has_checksums: bool,
    sink: &mut dyn FnMut(&StreamedEntry<'_>) -> std::io::Result<()>,
) -> Result<usize> {
    let mut cursor: usize = 0usize;
    let mut count: usize = 0;
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

        let mut permissions: Option<u8> = None;
        if matches!(encoding, FilenameEncoding::Utf8) {
            let &flags: &u8 = stream.get(cursor).ok_or(Error::EntryTruncated(cursor))?;
            cursor += 1;
            permissions = Some(flags);
            if flags & 2 != 0 {
                let (target, target_end): (String, usize) =
                    read_name(stream, cursor, encoding).ok_or(Error::EntryTruncated(cursor))?;
                cursor = target_end;
                sink(&StreamedEntry {
                    filename,
                    size: 0,
                    permissions,
                    crc32: None,
                    symlink_target: Some(target),
                    data: &[],
                })?;
                count += 1;
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
        let end: usize = cursor
            .checked_add(size_usize)
            .ok_or(Error::EntryTruncated(cursor))?;
        if end > stream.len() {
            return Err(Error::EntryTruncated(cursor));
        }
        sink(&StreamedEntry {
            filename,
            size,
            permissions,
            crc32,
            symlink_target: None,
            data: &stream[cursor..end],
        })?;
        count += 1;
        cursor = end;
    }
    Ok(count)
}

pub(crate) fn validates_at(image: &[u8], offset: usize) -> Option<bool> {
    let magic_end: usize = offset.checked_add(3)?;
    let magic: &[u8] = image.get(offset..magic_end)?;
    if magic[0] != b'K' || magic[1] != b'A' {
        return None;
    }
    let body: &[u8] = image.get(magic_end..)?;
    match magic[2] {
        b'Y' if starts_zstd_frame(body) => Some(true),
        b'X' if uncompressed_first_entry_plausible(body) => Some(false),
        _ => None,
    }
}

fn uncompressed_first_entry_plausible(body: &[u8]) -> bool {
    if matches!(body, [0, 0, ..] | [0]) {
        return true;
    }
    for encoding in [FilenameEncoding::Utf16Le, FilenameEncoding::Utf8] {
        let Some((name, name_end)): Option<(String, usize)> = read_name(body, 0, encoding) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let Some(size_at): Option<usize> = (match encoding {
            FilenameEncoding::Utf8 => name_end.checked_add(1),
            FilenameEncoding::Utf16Le => Some(name_end),
        }) else {
            continue;
        };
        let Some(size): Option<u64> = read_u64_le(body, size_at) else {
            continue;
        };
        let Some(end): Option<u64> = (size_at as u64)
            .checked_add(8)
            .and_then(|start: u64| start.checked_add(size))
        else {
            continue;
        };
        let fits: bool = end <= body.len() as u64;
        if size <= MAX_ENTRY_SIZE && fits {
            return true;
        }
    }
    false
}

fn decompress_payload(body: &[u8]) -> Result<Vec<u8>> {
    let cap: u64 = (body.len() as u64)
        .saturating_mul(MAX_DECOMPRESSION_RATIO)
        .min(MAX_DECOMPRESSED_ABS);
    decompress_payload_with_cap(body, cap)
}

fn decompress_payload_with_cap(body: &[u8], cap: u64) -> Result<Vec<u8>> {
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
            Ok((entries, consumed, terminated)) => {
                let data_total: usize = entries.iter().map(|e: &OnefileEntry| e.data.len()).sum();
                let exact: bool = consumed == stream.len();
                let trailer_ok: bool = terminated && !entries.is_empty() && data_total > 0;
                crate::util::dbg_line(&format!(
                    "walk candidate encoding={encoding:?} crc={has_checksums}: entries={} consumed={consumed}/{} terminated={terminated} data_total={data_total} exact={exact} trailer_ok={trailer_ok}",
                    entries.len(),
                    stream.len()
                ));
                if exact || trailer_ok {
                    return Ok(WalkOutcome {
                        entries,
                        encoding,
                        has_checksums,
                        consumed,
                    });
                }
                last_err = Error::EntryTruncated(stream.len());
            }
            Err(e) => {
                crate::util::dbg_line(&format!(
                    "walk candidate encoding={encoding:?} crc={has_checksums}: ERR {e:?}"
                ));
                last_err = e;
            }
        }
    }
    Err(last_err)
}

fn try_walk(
    stream: &[u8],
    encoding: FilenameEncoding,
    has_checksums: bool,
) -> Result<(Vec<OnefileEntry>, usize, bool)> {
    let mut entries: Vec<OnefileEntry> = Vec::new();
    let mut cursor: usize = 0usize;
    let mut terminated: bool = false;

    loop {
        if cursor == stream.len() {
            break;
        }
        let (filename, name_end): (String, usize) =
            read_name(stream, cursor, encoding).ok_or(Error::EntryTruncated(cursor))?;
        cursor = name_end;
        if filename.is_empty() {
            terminated = true;
            break;
        }
        if entries.is_empty() {
            crate::util::dbg_line(&format!(
                "try_walk[{encoding:?},crc={has_checksums}]: name_end={cursor}"
            ));
            crate::util::dbg_guarded("try_walk: first name", &filename);
            crate::util::dbg_hex(
                "try_walk: 40 bytes at first name_end (size-field region)",
                stream.get(cursor..).unwrap_or_default(),
                40,
            );
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

    Ok((entries, cursor, terminated))
}

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
    let end: usize = start.checked_add(rel)?;
    let raw: &[u8] = stream.get(start..end)?;
    if !raw.iter().all(|&b| is_plausible_path_byte(b)) {
        return None;
    }
    let name: &str = core::str::from_utf8(raw).ok()?;
    Some((name.to_owned(), end.checked_add(1)?))
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
    let end: usize = at.checked_add(2)?;
    let bytes: &[u8] = stream.get(at..end)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[inline]
fn read_u32_le(stream: &[u8], at: usize) -> Option<u32> {
    let end: usize = at.checked_add(4)?;
    let bytes: &[u8] = stream.get(at..end)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[inline]
fn read_u64_le(stream: &[u8], at: usize) -> Option<u64> {
    let end: usize = at.checked_add(8)?;
    let bytes: &[u8] = stream.get(at..end)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

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
    fn validation_offset_overflow_returns_none() {
        assert_eq!(validates_at(&[], usize::MAX), None);
    }

    #[test]
    fn integer_read_offset_overflow_returns_none() {
        assert_eq!(read_u16_le(&[], usize::MAX), None);
        assert_eq!(read_u32_le(&[], usize::MAX), None);
        assert_eq!(read_u64_le(&[], usize::MAX), None);
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
    fn uncompressed_payload_with_trailing_trailer_extracts() {
        let mut bytes: Vec<u8> = build_kax_win(&[
            ("main.dll", b"MZ\x90\x00the-real-payload-bytes"),
            ("python314.dll", b"MZsecond-module-data"),
        ]);
        bytes.extend_from_slice(&[0u8; 4096]);
        bytes.extend_from_slice(&0x00cc_a940u64.to_le_bytes());
        let payload: OnefilePayload =
            extract_onefile(&bytes, 0).expect("kax with onefile trailer must extract");
        assert_eq!(payload.entries.len(), 2);
        assert_eq!(payload.entries[0].filename, "main.dll");
        assert_eq!(payload.entries[0].data, b"MZ\x90\x00the-real-payload-bytes");
        assert_eq!(payload.entries[1].filename, "python314.dll");
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
    fn streaming_declared_size_overrun_errors_before_sink() {
        let mut bytes: Vec<u8> = b"KAX".to_vec();
        for unit in "big.bin".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0u8, 0u8]);
        bytes.extend_from_slice(&MAX_ENTRY_SIZE.to_le_bytes());
        let mut called: bool = false;
        let Err(err): Result<StreamedPayload> =
            extract_onefile_streaming(&bytes, 0, &mut |_e: &StreamedEntry<'_>| {
                called = true;
                Ok(())
            })
        else {
            panic!("streaming overlong declared size must error");
        };
        assert!(!called);
        assert!(matches!(
            err,
            Error::EntryTruncated(_) | Error::EmptyPayload
        ));
    }

    #[test]
    fn oversized_streaming_entry_errors_before_sink() {
        let mut bytes: Vec<u8> = b"KAX".to_vec();
        for unit in "too-big.bin".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0u8, 0u8]);
        bytes.extend_from_slice(&(MAX_ENTRY_SIZE + 1).to_le_bytes());
        let mut called: bool = false;
        let Err(err): Result<StreamedPayload> =
            extract_onefile_streaming(&bytes, 0, &mut |_e: &StreamedEntry<'_>| {
                called = true;
                Ok(())
            })
        else {
            panic!("oversized entry must error");
        };
        assert!(!called);
        assert!(matches!(
            err,
            Error::EntryTruncated(_) | Error::EmptyPayload
        ));
    }

    #[test]
    fn compressed_payload_over_cap_errors() {
        let raw: Vec<u8> = vec![b'A'; 128];
        let compressed: Vec<u8> = zstd::stream::encode_all(raw.as_slice(), 1).expect("zstd");
        let Err(err): Result<Vec<u8>> = decompress_payload_with_cap(&compressed, 16) else {
            panic!("over-cap decompression must error");
        };
        assert!(matches!(err, Error::Zstd(_)));
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

    fn collect_streamed(payload: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut got: Vec<(String, Vec<u8>)> = Vec::new();
        extract_onefile_streaming(payload, 0, &mut |e: &StreamedEntry<'_>| {
            got.push((e.filename.clone(), e.data.to_vec()));
            Ok(())
        })
        .expect("streaming walk");
        got
    }

    #[test]
    fn streaming_matches_full_extract_uncompressed() {
        let bytes: Vec<u8> = build_kax_win(&[
            ("main.dll", b"MZ\x90\x00the-real-payload-bytes"),
            ("python314.dll", b"MZsecond-module-data"),
        ]);
        let full: OnefilePayload = extract_onefile(&bytes, 0).expect("full");
        let streamed: Vec<(String, Vec<u8>)> = collect_streamed(&bytes);
        let expected: Vec<(String, Vec<u8>)> = full
            .entries
            .iter()
            .map(|e: &OnefileEntry| (e.filename.clone(), e.data.clone()))
            .collect();
        assert_eq!(streamed, expected);
    }

    #[test]
    fn streaming_matches_full_extract_zstd() {
        let inner: Vec<u8> = build_kax_win(&[
            ("a.pyd", b"\x7fELFmodule-a-bytes"),
            ("b.pyd", b"MZmodule-b-bytes-longer"),
        ]);
        let compressed: Vec<u8> = zstd::stream::encode_all(&inner[3..], 19).expect("zstd");
        let mut payload: Vec<u8> = b"KAY".to_vec();
        payload.extend_from_slice(&compressed);
        let full: OnefilePayload = extract_onefile(&payload, 0).expect("full");
        let streamed: Vec<(String, Vec<u8>)> = collect_streamed(&payload);
        let expected: Vec<(String, Vec<u8>)> = full
            .entries
            .iter()
            .map(|e: &OnefileEntry| (e.filename.clone(), e.data.clone()))
            .collect();
        assert_eq!(streamed, expected);
        assert!(!expected.is_empty());
    }
}
