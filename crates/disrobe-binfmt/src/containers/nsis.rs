use std::io::Read as _;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const NSIS_FIRSTHEADER_MAGIC: [u8; 16] = [
    0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's', b't',
];

const FIRSTHEADER_LEN: usize = 28;
const FLAGS_LEN: usize = 4;
const CRC_LEN: usize = 4;
const FH_FLAGS_NO_CRC: u32 = 4;
const COMPRESSED_FLAG: u32 = 0x8000_0000;
const SIZE_MASK: u32 = 0x7FFF_FFFF;
const BLOCK_COUNT: usize = 8;
const BLOCK_ENTRIES: usize = 2;
const BLOCK_STRINGS: usize = 3;
const BLOCK_LANGTABLES: usize = 4;
const ENTRY_LEN: usize = 28;
const ENTRY_PARAM_COUNT: usize = 6;
const EW_EXTRACTFILE: u32 = 20;
const NS_VAR_CODE: u16 = 1;
const NS_SHELL_CODE: u16 = 2;
const NS_LANG_CODE: u16 = 3;
const LEADING_EMPTY_UTF16_STRING: [u8; 2] = [0, 0];

const MAX_HEADER_BYTES: usize = 64 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_SOLID_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000_000;
const LZMA_PROPS_LEN: usize = 5;
const LZMA_PROPS_LIMIT: u8 = 9 * 5 * 5;
const LZMA_MIN_DICT: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsisHeader {
    pub offset: u64,
    pub flags: u32,
    pub siginfo: u32,
    pub header_size: u32,
    pub archive_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NsisCompression {
    Stored,
    Deflate,
    Lzma,
    Bzip2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsisBlock {
    pub offset: u32,
    pub num: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsisFileEntry {
    pub name: String,
    pub position: u32,
    pub mtime_low: u32,
    pub mtime_high: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsisArchive {
    pub header: NsisHeader,
    pub compression: NsisCompression,
    pub solid: bool,
    pub unicode: bool,
    pub data_region_offset: u64,
    pub files: Vec<NsisFileEntry>,
}

pub fn detect_nsis(bytes: &[u8]) -> Option<NsisHeader> {
    bytes
        .windows(NSIS_FIRSTHEADER_MAGIC.len())
        .enumerate()
        .find_map(|(i, w): (usize, &[u8])| {
            if w == NSIS_FIRSTHEADER_MAGIC {
                read_firstheader(bytes, i)
            } else {
                None
            }
        })
}

fn read_firstheader(bytes: &[u8], offset: usize) -> Option<NsisHeader> {
    if offset < 4 || offset + FIRSTHEADER_LEN > bytes.len() {
        return None;
    }
    let flags: u32 = read_u32(bytes, offset - 4)?;
    let siginfo: u32 = read_u32(bytes, offset)?;
    let header_size: u32 = read_u32(bytes, offset + 16)?;
    let archive_size: u32 = read_u32(bytes, offset + 20)?;
    Some(NsisHeader {
        offset: offset as u64,
        flags,
        siginfo,
        header_size,
        archive_size,
    })
}

pub fn parse_nsis(bytes: &[u8]) -> Result<NsisHeader> {
    detect_nsis(bytes).ok_or_else(|| {
        Error::Decompression(
            "nsis first-header signature `NullsoftInst` not found in input".to_owned(),
        )
    })
}

pub fn parse_nsis_archive(bytes: &[u8]) -> Result<NsisArchive> {
    let header: NsisHeader = parse_nsis(bytes)?;
    let (data_start, compressed_region): (usize, &[u8]) = data_region(bytes, &header)?;
    let header_size: usize = usize::try_from(header.header_size)
        .map_err(|_e: std::num::TryFromIntError| nsis_err("header_size exceeds usize"))?;
    if header_size == 0 || header_size > MAX_HEADER_BYTES {
        return Err(nsis_err("nsis header_size is zero or implausibly large"));
    }

    let (compression, solid, header_consumed, header_bytes): (
        NsisCompression,
        bool,
        usize,
        Vec<u8>,
    ) = decode_first_block(compressed_region, header_size)?;

    let data_region_offset: u64 = (data_start as u64)
        .checked_add(header_consumed as u64)
        .ok_or_else(|| nsis_err("data region offset overflow"))?;

    let (unicode, files): (bool, Vec<NsisFileEntry>) = parse_entries(&header_bytes)?;

    Ok(NsisArchive {
        header,
        compression,
        solid,
        unicode,
        data_region_offset,
        files,
    })
}

fn data_region<'a>(bytes: &'a [u8], header: &NsisHeader) -> Result<(usize, &'a [u8])> {
    let first_header: usize = usize::try_from(header.offset)
        .ok()
        .and_then(|siginfo: usize| siginfo.checked_sub(FLAGS_LEN))
        .ok_or_else(|| nsis_err("nsis first-header offset out of range"))?;
    let data_start: usize = first_header
        .checked_add(FIRSTHEADER_LEN)
        .ok_or_else(|| nsis_err("nsis first-header offset overflow"))?;
    let crc_len: usize = if header.flags & FH_FLAGS_NO_CRC == 0 {
        CRC_LEN
    } else {
        0
    };
    let data_len: usize = usize::try_from(header.archive_size)
        .ok()
        .and_then(|archive: usize| archive.checked_sub(FIRSTHEADER_LEN + crc_len))
        .ok_or_else(|| nsis_err("nsis archive size is smaller than its first header"))?;
    let data_end: usize = data_start
        .checked_add(data_len)
        .map_or(bytes.len(), |end: usize| end.min(bytes.len()));
    let region: &[u8] = bytes
        .get(data_start..data_end)
        .ok_or_else(|| nsis_err("nsis data region out of bounds"))?;
    Ok((data_start, region))
}

fn decode_first_block(
    region: &[u8],
    header_size: usize,
) -> Result<(NsisCompression, bool, usize, Vec<u8>)> {
    if let Some((size_word, payload)) = peek_block(region) {
        let declared: usize = (size_word & SIZE_MASK) as usize;
        let is_compressed: bool = size_word & COMPRESSED_FLAG != 0;
        if !is_compressed && declared == header_size && payload.len() >= header_size {
            return Ok((
                NsisCompression::Stored,
                false,
                4 + header_size,
                payload[..header_size].to_vec(),
            ));
        }
        if is_compressed
            && declared > 0
            && declared <= region.len()
            && let Some(slice) = payload.get(..declared)
            && let Ok((method, out)) = try_methods(slice, header_size)
            && out.len() == header_size
        {
            return Ok((method, false, 4 + declared, out));
        }
    }

    let with_length_word: usize = header_size
        .checked_add(4)
        .ok_or_else(|| nsis_err("nsis header size overflows"))?;
    let (method, out, consumed): (NsisCompression, Vec<u8>, usize) =
        try_methods_streaming(region, with_length_word)?;
    let header_bytes: Vec<u8> = extract_streamed_header(&out, header_size)?;
    Ok((method, true, consumed, header_bytes))
}

fn extract_streamed_header(out: &[u8], header_size: usize) -> Result<Vec<u8>> {
    let leading_size_word: bool =
        read_u32(out, 0).is_some_and(|word: u32| (word & SIZE_MASK) as usize == header_size);
    let start: usize = if leading_size_word && out.len() >= header_size + 4 {
        4
    } else {
        0
    };
    out.get(start..start + header_size)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| nsis_err("decompressed nsis header shorter than header_size"))
}

fn peek_block(region: &[u8]) -> Option<(u32, &[u8])> {
    let size_word: u32 = read_u32(region, 0)?;
    let payload: &[u8] = region.get(4..)?;
    Some((size_word, payload))
}

fn try_methods(slice: &[u8], expected: usize) -> Result<(NsisCompression, Vec<u8>)> {
    if let Ok(out) = inflate_raw(slice, expected) {
        return Ok((NsisCompression::Deflate, out));
    }
    if let Ok(out) = lzma_decode(slice, expected as u64) {
        return Ok((NsisCompression::Lzma, out));
    }
    if let Ok(out) = bzip2_decode(slice, expected as u64) {
        return Ok((NsisCompression::Bzip2, out));
    }
    Err(nsis_err(
        "no supported nsis compression method decoded block",
    ))
}

fn try_methods_streaming(
    region: &[u8],
    expected: usize,
) -> Result<(NsisCompression, Vec<u8>, usize)> {
    if let Ok((out, consumed)) = inflate_raw_counting(region, expected) {
        return Ok((NsisCompression::Deflate, out, consumed));
    }
    if let Ok(out) = lzma_decode_prefix(region, expected) {
        return Ok((NsisCompression::Lzma, out, region.len()));
    }
    if is_nsis_bzip2_framed(region)
        && let Ok(out) = super::nsis_bzip2::decompress_prefix(region, expected)
        && out.len() >= expected
    {
        return Ok((NsisCompression::Bzip2, out, region.len()));
    }
    if let Ok(out) = bzip2_decode(region, expected as u64) {
        return Ok((NsisCompression::Bzip2, out, region.len()));
    }
    Err(nsis_err(
        "no supported nsis compression method decoded header",
    ))
}

fn parse_entries(header: &[u8]) -> Result<(bool, Vec<NsisFileEntry>)> {
    let blocks: [NsisBlock; BLOCK_COUNT] = read_block_table(header)?;
    let entries: NsisBlock = blocks[BLOCK_ENTRIES];
    let strings_start: usize = blocks[BLOCK_STRINGS].offset as usize;
    let strings_end: usize = (blocks[BLOCK_LANGTABLES].offset as usize).max(strings_start);
    let string_block: &[u8] = header
        .get(strings_start..strings_end.min(header.len()))
        .map_or(&[] as &[u8], |value: &[u8]| value);
    let unicode: bool = string_block.starts_with(&LEADING_EMPTY_UTF16_STRING);

    let entry_count: usize = entries.num as usize;
    if entry_count > MAX_ENTRIES {
        return Err(nsis_err("nsis entry count exceeds sanity bound"));
    }
    let table_start: usize = entries.offset as usize;
    let mut out: Vec<NsisFileEntry> = Vec::new();
    for i in 0..entry_count {
        let base: usize = match table_start.checked_add(i * ENTRY_LEN) {
            Some(b) => b,
            None => break,
        };
        let opcode: u32 = match read_u32(header, base) {
            Some(v) => v,
            None => break,
        };
        if opcode != EW_EXTRACTFILE {
            continue;
        }
        let mut params: [u32; ENTRY_PARAM_COUNT] = [0u32; ENTRY_PARAM_COUNT];
        let mut ok: bool = true;
        for (j, slot) in params.iter_mut().enumerate() {
            if let Some(v) = read_u32(header, base + 4 + j * 4) {
                *slot = v;
            } else {
                ok = false;
                break;
            }
        }
        if !ok {
            break;
        }
        let name_index: u32 = params[1];
        let position: u32 = params[2];
        let name: String = decode_nsis_string(string_block, name_index, unicode);
        if name.is_empty() {
            continue;
        }
        out.push(NsisFileEntry {
            name,
            position,
            mtime_low: params[3],
            mtime_high: params[4],
        });
    }
    Ok((unicode, out))
}

fn read_block_table(header: &[u8]) -> Result<[NsisBlock; BLOCK_COUNT]> {
    let mut blocks: [NsisBlock; BLOCK_COUNT] = [NsisBlock { offset: 0, num: 0 }; BLOCK_COUNT];
    for (i, block) in blocks.iter_mut().enumerate() {
        let base: usize = 4 + i * 8;
        let offset: u32 =
            read_u32(header, base).ok_or_else(|| nsis_err("nsis block table truncated"))?;
        let num: u32 =
            read_u32(header, base + 4).ok_or_else(|| nsis_err("nsis block table truncated"))?;
        *block = NsisBlock { offset, num };
    }
    Ok(blocks)
}

fn decode_nsis_string(block: &[u8], char_index: u32, unicode: bool) -> String {
    if unicode {
        decode_unicode_string(block, char_index)
    } else {
        decode_ansi_string(block, char_index)
    }
}

fn decode_unicode_string(block: &[u8], char_index: u32) -> String {
    let start: usize = (char_index as usize).saturating_mul(2);
    let mut out: String = String::new();
    let mut pos: usize = start;
    while pos + 1 < block.len() {
        let w: u16 = u16::from(block[pos]) | (u16::from(block[pos + 1]) << 8);
        if w == 0 {
            break;
        }
        if w == NS_VAR_CODE || w == NS_SHELL_CODE || w == NS_LANG_CODE {
            let next: u16 = if pos + 3 < block.len() {
                u16::from(block[pos + 2]) | (u16::from(block[pos + 3]) << 8)
            } else {
                0
            };
            push_special(&mut out, w, u32::from(next & 0x7FFF));
            pos += 4;
            continue;
        }
        push_wchar(&mut out, w);
        pos += 2;
    }
    out
}

fn decode_ansi_string(block: &[u8], byte_index: u32) -> String {
    let start: usize = byte_index as usize;
    let mut out: String = String::new();
    let mut pos: usize = start;
    while pos < block.len() {
        let c: u8 = block[pos];
        if c == 0 {
            break;
        }
        if c == NS_VAR_CODE as u8 || c == NS_SHELL_CODE as u8 || c == NS_LANG_CODE as u8 {
            let b0: u8 = block.get(pos + 1).copied().map_or(0, |value: u8| value);
            let b1: u8 = block.get(pos + 2).copied().map_or(0, |value: u8| value);
            let param: u32 = u32::from(b0 & 0x7F) | (u32::from(b1 & 0x7F) << 7);
            push_special(&mut out, u16::from(c), param);
            pos += 3;
            continue;
        }
        out.push(char::from(c));
        pos += 1;
    }
    out
}

fn push_wchar(out: &mut String, w: u16) {
    match char::from_u32(u32::from(w)) {
        Some(c) => out.push(c),
        None => out.push('_'),
    }
}

fn push_special(out: &mut String, kind: u16, param: u32) {
    match kind {
        NS_SHELL_CODE => out.push_str(shell_folder_name(param)),
        NS_VAR_CODE => {
            out.push_str("$VAR");
            out.push_str(&param.to_string());
        }
        _ => {
            out.push_str("$LANG");
            out.push_str(&param.to_string());
        }
    }
}

const fn shell_folder_name(param: u32) -> &'static str {
    match param & 0xFF {
        0x07 | 0x16 => "$STARTMENU",
        0x0B | 0x18 => "$DESKTOP",
        0x10 | 0x1C => "$LOCALAPPDATA",
        0x1A | 0x23 => "$APPDATA",
        0x26 | 0x2A => "$PROGRAMFILES",
        0x28 | 0x2B => "$PROGRAMFILES64",
        0x29 => "$COMMONFILES",
        0x2C => "$COMMONFILES64",
        0x25 => "$SYSDIR",
        _ => "$SHELL",
    }
}

pub fn decompress_file(
    bytes: &[u8],
    archive: &NsisArchive,
    entry: &NsisFileEntry,
    cap: u64,
) -> Result<Vec<u8>> {
    let abs: usize = (archive.data_region_offset as usize)
        .checked_add(entry.position as usize)
        .ok_or_else(|| nsis_err("file position overflow"))?;
    let chunk: &[u8] = bytes
        .get(abs..)
        .ok_or_else(|| nsis_err("file position past end of input"))?;
    let size_word: u32 = read_u32(chunk, 0).ok_or_else(|| nsis_err("file size word truncated"))?;
    let is_compressed: bool = size_word & COMPRESSED_FLAG != 0;
    let declared: usize = (size_word & SIZE_MASK) as usize;
    let payload: &[u8] = chunk
        .get(4..4 + declared.min(chunk.len().saturating_sub(4)))
        .ok_or_else(|| nsis_err("file payload truncated"))?;
    let limit: u64 = cap.min(MAX_FILE_BYTES);
    if !is_compressed {
        if payload.len() as u64 > limit {
            return Err(nsis_err("stored nsis file exceeds size cap"));
        }
        return Ok(payload.to_vec());
    }
    match archive.compression {
        NsisCompression::Stored => Ok(payload.to_vec()),
        NsisCompression::Deflate => inflate_raw_capped(payload, limit),
        NsisCompression::Lzma => lzma_decode(payload, limit),
        NsisCompression::Bzip2 => bzip2_decode(payload, limit),
    }
}

fn inflate_raw(input: &[u8], expected: usize) -> Result<Vec<u8>> {
    let mut decoder: flate2::read::DeflateDecoder<&[u8]> = flate2::read::DeflateDecoder::new(input);
    let mut out: Vec<u8> = Vec::with_capacity(expected.min(MAX_HEADER_BYTES));
    decoder
        .by_ref()
        .take(expected as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| nsis_err_owned(format!("raw deflate failed: {e}")))?;
    Ok(out)
}

fn inflate_raw_counting(input: &[u8], expected: usize) -> Result<(Vec<u8>, usize)> {
    let mut decoder: flate2::read::DeflateDecoder<&[u8]> = flate2::read::DeflateDecoder::new(input);
    let mut out: Vec<u8> = Vec::with_capacity(expected.min(MAX_HEADER_BYTES));
    decoder
        .by_ref()
        .take(expected as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| nsis_err_owned(format!("raw deflate failed: {e}")))?;
    let consumed: usize = decoder.total_in() as usize;
    Ok((out, consumed))
}

fn inflate_raw_capped(input: &[u8], cap: u64) -> Result<Vec<u8>> {
    let mut decoder: flate2::read::DeflateDecoder<&[u8]> = flate2::read::DeflateDecoder::new(input);
    let mut out: Vec<u8> = Vec::new();
    let read: u64 = std::io::copy(&mut decoder.by_ref().take(cap + 1), &mut out)
        .map_err(|e: std::io::Error| nsis_err_owned(format!("raw deflate failed: {e}")))?;
    if read > cap {
        return Err(nsis_err("deflate output exceeds size cap"));
    }
    Ok(out)
}

fn lzma_decode(input: &[u8], cap: u64) -> Result<Vec<u8>> {
    if input.len() < LZMA_PROPS_LEN {
        return Err(nsis_err("nsis lzma stream too short for props"));
    }
    let options: lzma_rs::decompress::Options = lzma_rs::decompress::Options {
        unpacked_size: lzma_rs::decompress::UnpackedSize::UseProvided(None),
        memlimit: Some(usize::try_from(cap).map_or(usize::MAX, |limit: usize| limit)),
        allow_incomplete: false,
    };
    let mut reader: &[u8] = input;
    let mut sink: CappedSink = CappedSink {
        out: Vec::new(),
        cap,
    };
    lzma_rs::lzma_decompress_with_options(&mut reader, &mut sink, &options).map_err(
        |e: lzma_rs::error::Error| nsis_err_owned(format!("nsis lzma decode failed: {e}")),
    )?;
    Ok(sink.out)
}

fn lzma_decode_prefix(input: &[u8], want: usize) -> Result<Vec<u8>> {
    let props: u8 = *input
        .first()
        .ok_or_else(|| nsis_err("nsis lzma stream too short for props"))?;
    if props >= LZMA_PROPS_LIMIT {
        return Err(nsis_err("nsis lzma props byte out of range"));
    }
    let declared_dict: u32 =
        read_u32(input, 1).ok_or_else(|| nsis_err("nsis lzma stream too short for props"))?;
    let want_dict: u32 = u32::try_from(want).map_or(u32::MAX, |size: u32| size);
    let mut options: liblzma::stream::LzmaOptions =
        liblzma::stream::LzmaOptions::new_preset(0).map_err(lzma_stream_err)?;
    options
        .dict_size(declared_dict.min(want_dict).max(LZMA_MIN_DICT))
        .literal_context_bits(u32::from(props % 9))
        .literal_position_bits(u32::from(props / 9 % 5))
        .position_bits(u32::from(props / 45));
    let mut filters: liblzma::stream::Filters = liblzma::stream::Filters::new();
    filters.lzma1(&options);
    let mut stream: liblzma::stream::Stream =
        liblzma::stream::Stream::new_raw_decoder(&filters).map_err(lzma_stream_err)?;
    let data: &[u8] = input.get(LZMA_PROPS_LEN..).map_or(&[], |rest: &[u8]| rest);
    let mut out: Vec<u8> = Vec::with_capacity(want);
    while out.len() < want {
        let consumed: usize = usize::try_from(stream.total_in()).map_or(data.len(), |n: usize| n);
        let rest: &[u8] = data.get(consumed..).map_or(&[], |tail: &[u8]| tail);
        let produced: usize = out.len();
        let status: liblzma::stream::Status = stream
            .process_vec(rest, &mut out, liblzma::stream::Action::Run)
            .map_err(lzma_stream_err)?;
        let stalled: bool = out.len() == produced && stream.total_in() == consumed as u64;
        if status == liblzma::stream::Status::StreamEnd || stalled {
            break;
        }
    }
    if out.len() < want {
        return Err(nsis_err("nsis lzma stream ends before the header does"));
    }
    out.truncate(want);
    Ok(out)
}

fn lzma_stream_err(e: liblzma::stream::Error) -> Error {
    nsis_err_owned(format!("nsis lzma decode failed: {e}"))
}

struct CappedSink {
    out: Vec<u8>,
    cap: u64,
}

impl std::io::Write for CappedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let total: u64 = (self.out.len() as u64).saturating_add(buf.len() as u64);
        if total > self.cap {
            return Err(std::io::Error::other(format!(
                "nsis output exceeds its {} byte cap",
                self.cap
            )));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bzip2_decode(input: &[u8], cap: u64) -> Result<Vec<u8>> {
    if is_nsis_bzip2_framed(input) {
        let limit: u64 = cap.min(MAX_FILE_BYTES);
        return super::nsis_bzip2::decompress(input, limit)
            .map_err(|e: Error| nsis_err_owned(format!("nsis bzip2 decode failed: {e}")));
    }
    let mut decoder: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(input);
    let mut out: Vec<u8> = Vec::new();
    let read: u64 = std::io::copy(
        &mut decoder.by_ref().take(cap.min(MAX_FILE_BYTES) + 1),
        &mut out,
    )
    .map_err(|e: std::io::Error| nsis_err_owned(format!("nsis bzip2 decode failed: {e}")))?;
    if read > cap.min(MAX_FILE_BYTES) {
        return Err(nsis_err("bzip2 output exceeds size cap"));
    }
    Ok(out)
}

fn is_nsis_bzip2_framed(input: &[u8]) -> bool {
    !input.starts_with(b"BZh") && matches!(input.first(), Some(&(0x31 | 0x17)))
}

pub fn decode_solid_region(bytes: &[u8], archive: &NsisArchive, cap: u64) -> Result<Vec<u8>> {
    let (_, region): (usize, &[u8]) = data_region(bytes, &archive.header)?;
    let limit: u64 = cap.clamp(1, MAX_SOLID_BYTES);
    let mut full: Vec<u8> = match archive.compression {
        NsisCompression::Stored => {
            if region.len() as u64 > limit {
                return Err(nsis_err("stored solid region exceeds cap"));
            }
            Ok(region.to_vec())
        }
        NsisCompression::Deflate => inflate_raw_capped(region, limit),
        NsisCompression::Lzma => lzma_decode(region, limit),
        NsisCompression::Bzip2 => bzip2_decode(region, limit),
    }?;
    let header_size: usize = archive.header.header_size as usize;
    let header_block_len: usize = solid_header_block_len(&full, header_size);
    if full.len() < header_block_len {
        return Err(nsis_err("solid stream shorter than header block"));
    }
    Ok(full.split_off(header_block_len))
}

fn solid_header_block_len(full: &[u8], header_size: usize) -> usize {
    if let Some(prefix) = read_u32(full, 0)
        && (prefix & SIZE_MASK) as usize == header_size
        && full.len() >= header_size + 4
    {
        return header_size + 4;
    }
    header_size
}

pub fn slice_solid_file(solid: &[u8], entry: &NsisFileEntry, cap: u64) -> Result<Vec<u8>> {
    let pos: usize = entry.position as usize;
    let size_word: u32 =
        read_u32(solid, pos).ok_or_else(|| nsis_err("solid file size word out of bounds"))?;
    let declared: usize = (size_word & SIZE_MASK) as usize;
    let data_start: usize = pos
        .checked_add(4)
        .ok_or_else(|| nsis_err("solid file offset overflow"))?;
    let data_end: usize = data_start
        .checked_add(declared)
        .ok_or_else(|| nsis_err("solid file length overflow"))?;
    if declared as u64 > cap.min(MAX_FILE_BYTES) {
        return Err(nsis_err("solid file exceeds size cap"));
    }
    solid
        .get(data_start..data_end)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| nsis_err("solid file slice out of bounds"))
}

#[inline]
fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    disrobe_bytes::read_u32_le_at(bytes, at).ok()
}

#[inline]
fn nsis_err(msg: &'static str) -> Error {
    Error::Nsis(msg.to_owned())
}

#[inline]
const fn nsis_err_owned(msg: String) -> Error {
    Error::Nsis(msg)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) fn build_test_nsis(file_name: &str, file_body: &[u8]) -> Vec<u8> {
    use std::io::Write as _;

    fn put_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn raw_deflate(input: &[u8]) -> Vec<u8> {
        let mut enc: flate2::write::DeflateEncoder<Vec<u8>> =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(input).expect("deflate write");
        enc.finish().expect("deflate finish")
    }
    let mut strings: Vec<u8> = vec![0u8, 0u8];
    for u in file_name.encode_utf16() {
        strings.extend_from_slice(&u.to_le_bytes());
    }
    strings.extend_from_slice(&[0u8, 0u8]);
    let entries_offset: u32 = 4 + (BLOCK_COUNT as u32) * 8;
    let entries_len: u32 = ENTRY_LEN as u32;
    let strings_offset: u32 = entries_offset + entries_len;
    let langtables_offset: u32 = strings_offset + strings.len() as u32;
    let mut hdr: Vec<u8> = Vec::new();
    put_u32(&mut hdr, 0);
    let blocks: [(u32, u32); BLOCK_COUNT] = [
        (0, 0),
        (0, 0),
        (entries_offset, 1),
        (strings_offset, 0),
        (langtables_offset, 0),
        (0, 0),
        (0, 0),
        (0, 0),
    ];
    for (off, num) in blocks {
        put_u32(&mut hdr, off);
        put_u32(&mut hdr, num);
    }
    put_u32(&mut hdr, EW_EXTRACTFILE);
    put_u32(&mut hdr, 0);
    put_u32(&mut hdr, 1);
    put_u32(&mut hdr, 0);
    put_u32(&mut hdr, 0);
    put_u32(&mut hdr, 0);
    put_u32(&mut hdr, 0);
    hdr.extend_from_slice(&strings);

    let header_size: u32 = hdr.len() as u32;
    let header_comp: Vec<u8> = raw_deflate(&hdr);
    let file_comp: Vec<u8> = raw_deflate(file_body);
    let mut data_region: Vec<u8> = Vec::new();
    put_u32(&mut data_region, COMPRESSED_FLAG | file_comp.len() as u32);
    data_region.extend_from_slice(&file_comp);
    let mut archive: Vec<u8> = Vec::new();
    put_u32(&mut archive, COMPRESSED_FLAG | header_comp.len() as u32);
    archive.extend_from_slice(&header_comp);
    archive.extend_from_slice(&data_region);
    let archive_size: u32 = (FIRSTHEADER_LEN + archive.len() + CRC_LEN) as u32;
    let mut out: Vec<u8> = vec![0u8; 256];
    put_u32(&mut out, 0);
    out.extend_from_slice(&NSIS_FIRSTHEADER_MAGIC);
    put_u32(&mut out, header_size);
    put_u32(&mut out, archive_size);
    out.extend_from_slice(&archive);
    out.extend_from_slice(&[0u8; CRC_LEN]);
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) fn build_test_nsis_solid(file_name: &str, file_body: &[u8]) -> Vec<u8> {
    use std::io::Write as _;

    fn put_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn raw_deflate(input: &[u8]) -> Vec<u8> {
        let mut enc: flate2::write::DeflateEncoder<Vec<u8>> =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(input).expect("deflate write");
        enc.finish().expect("deflate finish")
    }
    let mut strings: Vec<u8> = vec![0u8, 0u8];
    for u in file_name.encode_utf16() {
        strings.extend_from_slice(&u.to_le_bytes());
    }
    strings.extend_from_slice(&[0u8, 0u8]);
    let entries_offset: u32 = 4 + (BLOCK_COUNT as u32) * 8;
    let strings_offset: u32 = entries_offset + ENTRY_LEN as u32;
    let langtables_offset: u32 = strings_offset + strings.len() as u32;
    let mut hdr: Vec<u8> = Vec::new();
    put_u32(&mut hdr, 0);
    let blocks: [(u32, u32); BLOCK_COUNT] = [
        (0, 0),
        (0, 0),
        (entries_offset, 1),
        (strings_offset, 0),
        (langtables_offset, 0),
        (0, 0),
        (0, 0),
        (0, 0),
    ];
    for (off, num) in blocks {
        put_u32(&mut hdr, off);
        put_u32(&mut hdr, num);
    }
    put_u32(&mut hdr, EW_EXTRACTFILE);
    put_u32(&mut hdr, 0);
    put_u32(&mut hdr, 1);
    put_u32(&mut hdr, 0);
    put_u32(&mut hdr, 0);
    put_u32(&mut hdr, 0);
    put_u32(&mut hdr, 0);
    hdr.extend_from_slice(&strings);
    let header_size: u32 = hdr.len() as u32;

    let mut plain: Vec<u8> = Vec::new();
    put_u32(&mut plain, header_size);
    plain.extend_from_slice(&hdr);
    put_u32(&mut plain, file_body.len() as u32);
    plain.extend_from_slice(file_body);
    let solid_comp: Vec<u8> = raw_deflate(&plain);
    let archive_size: u32 = (FIRSTHEADER_LEN + solid_comp.len() + CRC_LEN) as u32;

    let mut out: Vec<u8> = vec![0u8; 256];
    put_u32(&mut out, 0);
    out.extend_from_slice(&NSIS_FIRSTHEADER_MAGIC);
    put_u32(&mut out, header_size);
    put_u32(&mut out, archive_size);
    out.extend_from_slice(&solid_comp);
    out.extend_from_slice(&[0u8; CRC_LEN]);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_pe_with_nsis(header_size: u32, archive_size: u32) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        let offset: usize = 512;
        let flags: u32 = 0;
        bytes[offset - 4..offset].copy_from_slice(&flags.to_le_bytes());
        bytes[offset..offset + 16].copy_from_slice(&NSIS_FIRSTHEADER_MAGIC);
        bytes[offset + 16..offset + 20].copy_from_slice(&header_size.to_le_bytes());
        bytes[offset + 20..offset + 24].copy_from_slice(&archive_size.to_le_bytes());
        bytes
    }

    #[test]
    fn detects_signature_in_pe_tail() {
        let bytes: Vec<u8> = synth_pe_with_nsis(0x1234, 0x10_000);
        let header: NsisHeader = parse_nsis(&bytes).expect("nsis header");
        assert_eq!(header.offset, 512);
        assert_eq!(header.header_size, 0x1234);
        assert_eq!(header.archive_size, 0x10_000);
    }

    #[test]
    fn rejects_non_nsis() {
        let bytes: Vec<u8> = vec![0u8; 512];
        let err: Error = parse_nsis(&bytes).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }

    fn build_nsis(file_name: &str, file_body: &[u8]) -> Vec<u8> {
        build_test_nsis(file_name, file_body)
    }

    #[test]
    fn extracts_single_deflate_file() {
        let body: &[u8] =
            b"the quick brown fox jumps over the lazy dog, repeated repeated repeated";
        let bytes: Vec<u8> = build_nsis("$VAR4\\hello.txt", body);
        let archive: NsisArchive = parse_nsis_archive(&bytes).expect("parse archive");
        assert!(archive.unicode);
        assert_eq!(archive.compression, NsisCompression::Deflate);
        assert_eq!(archive.files.len(), 1);
        let entry: &NsisFileEntry = &archive.files[0];
        assert_eq!(entry.name, "$VAR4\\hello.txt");
        assert!(!archive.solid);
        let recovered: Vec<u8> =
            decompress_file(&bytes, &archive, entry, u64::MAX).expect("decode");
        assert_eq!(recovered, body);
    }

    #[test]
    fn extracts_single_solid_deflate_file() {
        let body: &[u8] =
            b"solid-mode payload bytes that ride one continuous deflate stream after the header";
        let bytes: Vec<u8> = build_test_nsis_solid("app\\solid.bin", body);
        let archive: NsisArchive = parse_nsis_archive(&bytes).expect("parse solid archive");
        assert!(
            archive.solid,
            "single-stream archive must be detected as solid"
        );
        assert_eq!(archive.files.len(), 1);
        let solid: Vec<u8> =
            decode_solid_region(&bytes, &archive, u64::MAX).expect("decode solid region");
        let recovered: Vec<u8> =
            slice_solid_file(&solid, &archive.files[0], u64::MAX).expect("slice solid file");
        assert_eq!(recovered, body);
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let body: &[u8] = b"payload payload payload payload payload";
        let full: Vec<u8> = build_nsis("a.bin", body);
        for cut in (32..full.len()).step_by(7) {
            let partial: &[u8] = &full[..cut];
            let _ = parse_nsis_archive(partial);
        }
    }

    #[test]
    fn garbage_nsis_shaped_input_no_panic() {
        let mut bytes: Vec<u8> = vec![0u8; 2048];
        let off: usize = 512;
        bytes[off - 4..off].copy_from_slice(&0u32.to_le_bytes());
        bytes[off..off + 16].copy_from_slice(&NSIS_FIRSTHEADER_MAGIC);
        bytes[off + 16..off + 20].copy_from_slice(&4096u32.to_le_bytes());
        bytes[off + 20..off + 24].copy_from_slice(&1024u32.to_le_bytes());
        for (i, b) in bytes.iter_mut().enumerate().skip(off + 28) {
            *b = (i % 251) as u8;
        }
        let err: Result<NsisArchive> = parse_nsis_archive(&bytes);
        assert!(err.is_err());
    }

    #[test]
    fn bad_method_when_header_undecodable() {
        let mut bytes: Vec<u8> = vec![0u8; 600];
        let off: usize = 512;
        bytes[off..off + 16].copy_from_slice(&NSIS_FIRSTHEADER_MAGIC);
        bytes[off + 16..off + 20].copy_from_slice(&64u32.to_le_bytes());
        bytes[off + 20..off + 24].copy_from_slice(&40u32.to_le_bytes());
        let r: Result<NsisArchive> = parse_nsis_archive(&bytes);
        assert!(r.is_err());
    }
}
