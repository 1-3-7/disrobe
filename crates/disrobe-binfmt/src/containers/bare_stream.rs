use std::io::Read;

use crate::error::{Error, Result};

pub const LZIP_MAGIC: &[u8; 5] = b"LZIP\x01";
pub const LZ4_FRAME_MAGIC: &[u8; 4] = &[0x04, 0x22, 0x4d, 0x18];
pub const LZ4_LEGACY_MAGIC: &[u8; 4] = &[0x02, 0x21, 0x4c, 0x18];
pub const LZ4_SKIPPABLE_LOW: u32 = 0x184d_2a50;
pub const LZ4_SKIPPABLE_HIGH: u32 = 0x184d_2a5f;
pub const COMPRESS_MAGIC: &[u8; 2] = &[0x1f, 0x9d];
pub const GZIP_MAGIC: &[u8; 2] = &[0x1f, 0x8b];
pub const BZIP2_MAGIC: &[u8; 3] = b"BZh";
pub const ZSTD_MAGIC: &[u8; 4] = &[0x28, 0xb5, 0x2f, 0xfd];
pub const LZMA_ALONE_PROPS_MAX: u8 = 225;

const LZ4_LEGACY_MAX_BLOCK: usize = 8 * 1024 * 1024;
const COMPRESS_MAX_CODE_BITS: u8 = 16;
const COMPRESS_MIN_CODE_BITS: u8 = 9;

#[must_use]
pub fn zlib_header_is_valid(bytes: &[u8]) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    let cmf: u8 = bytes[0];
    let flg: u8 = bytes[1];
    let compression_method: u8 = cmf & 0x0f;
    let compression_info: u8 = cmf >> 4;
    if compression_method != 8 || compression_info > 7 {
        return false;
    }
    let check: u16 = (u16::from(cmf) << 8) | u16::from(flg);
    check.is_multiple_of(31)
}

#[must_use]
pub fn detect_zlib(bytes: &[u8]) -> bool {
    if !zlib_header_is_valid(bytes) {
        return false;
    }
    inflate_zlib_verified(bytes, 4 * 1024 * 1024).is_ok()
}

pub fn inflate_zlib_verified(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    if !zlib_header_is_valid(bytes) {
        return Err(Error::Decompression(
            "zlib: header fails CM/CINFO/FCHECK validation".to_owned(),
        ));
    }
    let limit: u64 = cap.saturating_add(1);
    let mut out: Vec<u8> = Vec::new();
    let mut decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(bytes);
    let read: u64 = std::io::copy(&mut (&mut decoder).take(limit), &mut out)
        .map_err(|e: std::io::Error| Error::Decompression(format!("zlib: inflate failed: {e}")))?;
    if read > cap {
        return Err(Error::QuotaExceeded {
            entry: "stream.zlib".to_owned(),
            reason: format!("decompressed stream exceeds bomb cap {cap}"),
        });
    }
    let consumed: u64 = decoder.total_in();
    let consumed_usize: usize =
        usize::try_from(consumed).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("zlib: input overflow".to_owned())
        })?;
    let trailer_start: usize = consumed_usize.checked_sub(4).ok_or_else(|| {
        Error::Decompression("zlib: stream too short to hold adler32 trailer".to_owned())
    })?;
    let trailer: &[u8] = bytes
        .get(trailer_start..consumed_usize)
        .ok_or_else(|| Error::Decompression("zlib: adler32 trailer out of range".to_owned()))?;
    let stored: u32 = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let computed: u32 = adler32(&out);
    if stored != computed {
        return Err(Error::Decompression(format!(
            "zlib: adler32 mismatch (stored {stored:#010x}, computed {computed:#010x})"
        )));
    }
    Ok(out)
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }
    (b << 16) | a
}

#[must_use]
pub fn detect_lzip(bytes: &[u8]) -> bool {
    bytes.starts_with(LZIP_MAGIC)
}

pub fn decompress_lzip(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    if !detect_lzip(bytes) {
        return Err(Error::Decompression(
            "lzip: missing LZIP\\x01 magic".to_owned(),
        ));
    }
    let limit: u64 = cap.saturating_add(1);
    let mut out: Vec<u8> = Vec::new();
    let decoder: liblzma::read::XzDecoder<&[u8]> =
        liblzma::read::XzDecoder::new_stream(bytes, lzip_stream()?);
    let read: u64 = std::io::copy(&mut decoder.take(limit), &mut out)
        .map_err(|e: std::io::Error| Error::Decompression(format!("lzip: decode failed: {e}")))?;
    if read > cap {
        return Err(Error::QuotaExceeded {
            entry: "stream.lz".to_owned(),
            reason: format!("decompressed stream exceeds bomb cap {cap}"),
        });
    }
    Ok(out)
}

fn lzip_stream() -> Result<liblzma::stream::Stream> {
    liblzma::stream::Stream::new_lzip_decoder(u64::MAX, 0)
        .map_err(|e: liblzma::stream::Error| Error::Decompression(format!("lzip: {e}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lz4Layout {
    Frame,
    Legacy,
    Skippable,
}

#[must_use]
pub fn detect_lz4(bytes: &[u8]) -> Option<Lz4Layout> {
    if bytes.len() < 4 {
        return None;
    }
    if bytes.starts_with(LZ4_FRAME_MAGIC) {
        return Some(Lz4Layout::Frame);
    }
    if bytes.starts_with(LZ4_LEGACY_MAGIC) {
        return Some(Lz4Layout::Legacy);
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if (LZ4_SKIPPABLE_LOW..=LZ4_SKIPPABLE_HIGH).contains(&magic) {
        return Some(Lz4Layout::Skippable);
    }
    None
}

pub fn decompress_lz4(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    match detect_lz4(bytes) {
        Some(Lz4Layout::Frame) => decompress_lz4_frame(bytes, cap),
        Some(Lz4Layout::Legacy) => decompress_lz4_legacy(bytes, cap),
        Some(Lz4Layout::Skippable) => decompress_lz4_skippable_chain(bytes, cap),
        None => Err(Error::Decompression(
            "lz4: input matches no frame/legacy/skippable magic".to_owned(),
        )),
    }
}

fn decompress_lz4_frame(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    let limit: u64 = cap.saturating_add(1);
    let mut out: Vec<u8> = Vec::new();
    let mut decoder: lz4_flex::frame::FrameDecoder<&[u8]> =
        lz4_flex::frame::FrameDecoder::new(bytes);
    let read: u64 =
        std::io::copy(&mut (&mut decoder).take(limit), &mut out).map_err(|e: std::io::Error| {
            Error::Decompression(format!("lz4: frame decode failed: {e}"))
        })?;
    if read > cap {
        return Err(Error::QuotaExceeded {
            entry: "stream.lz4".to_owned(),
            reason: format!("decompressed stream exceeds bomb cap {cap}"),
        });
    }
    Ok(out)
}

fn decompress_lz4_skippable_chain(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut offset: usize = 0;
    while offset + 4 <= bytes.len() {
        let magic: u32 = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        if (LZ4_SKIPPABLE_LOW..=LZ4_SKIPPABLE_HIGH).contains(&magic) {
            let size_field: &[u8] = bytes.get(offset + 4..offset + 8).ok_or_else(|| {
                Error::Decompression("lz4: truncated skippable frame size".to_owned())
            })?;
            let frame_len: usize =
                u32::from_le_bytes([size_field[0], size_field[1], size_field[2], size_field[3]])
                    as usize;
            offset = offset
                .checked_add(8)
                .and_then(|o: usize| o.checked_add(frame_len))
                .ok_or_else(|| Error::Decompression("lz4: skippable frame overflow".to_owned()))?;
            if offset > bytes.len() {
                return Err(Error::Decompression(
                    "lz4: skippable frame body past end of input".to_owned(),
                ));
            }
            continue;
        }
        let remaining: &[u8] = &bytes[offset..];
        match detect_lz4(remaining) {
            Some(Lz4Layout::Frame) => {
                out.extend(decompress_lz4_frame(remaining, cap)?);
            }
            Some(Lz4Layout::Legacy) => {
                out.extend(decompress_lz4_legacy(remaining, cap)?);
            }
            _ => break,
        }
        if out.len() as u64 > cap {
            return Err(Error::QuotaExceeded {
                entry: "stream.lz4".to_owned(),
                reason: format!("decompressed stream exceeds bomb cap {cap}"),
            });
        }
        break;
    }
    Ok(out)
}

fn decompress_lz4_legacy(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut offset: usize = LZ4_LEGACY_MAGIC.len();
    while offset + 4 <= bytes.len() {
        let block_size: usize = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        let next_magic: bool = detect_lz4(&bytes[offset.saturating_sub(4)..])
            == Some(Lz4Layout::Frame)
            || bytes[offset.saturating_sub(4)..].starts_with(LZ4_LEGACY_MAGIC);
        if next_magic {
            break;
        }
        let block_end: usize = offset
            .checked_add(block_size)
            .ok_or_else(|| Error::Decompression("lz4: legacy block size overflow".to_owned()))?;
        let block: &[u8] = bytes.get(offset..block_end).ok_or_else(|| {
            Error::Decompression("lz4: legacy block past end of input".to_owned())
        })?;
        let decoded: Vec<u8> =
            crate::containers::lz4_block::decompress_bounded(block, LZ4_LEGACY_MAX_BLOCK)?;
        out.extend_from_slice(&decoded);
        if out.len() as u64 > cap {
            return Err(Error::QuotaExceeded {
                entry: "stream.lz4".to_owned(),
                reason: format!("decompressed stream exceeds bomb cap {cap}"),
            });
        }
        offset = block_end;
    }
    if out.is_empty() {
        return Err(Error::Decompression(
            "lz4: legacy frame produced no output".to_owned(),
        ));
    }
    Ok(out)
}

#[must_use]
pub fn detect_compress(bytes: &[u8]) -> bool {
    if !bytes.starts_with(COMPRESS_MAGIC) || bytes.len() < 3 {
        return false;
    }
    let flags: u8 = bytes[2];
    let max_bits: u8 = flags & 0x1f;
    (COMPRESS_MIN_CODE_BITS..=COMPRESS_MAX_CODE_BITS).contains(&max_bits)
}

pub fn decompress_compress(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    if !detect_compress(bytes) {
        return Err(Error::Decompression(
            "compress(.Z): missing 0x1f9d magic or invalid max-code-bits".to_owned(),
        ));
    }
    let flags: u8 = bytes[2];
    let max_bits: u32 = u32::from(flags & 0x1f);
    let block_mode: bool = flags & 0x80 != 0;
    if !(9..=16).contains(&max_bits) {
        return Err(Error::Decompression(format!(
            "compress(.Z): max code width {max_bits} outside 9..=16"
        )));
    }
    lzw_unix_decompress(&bytes[3..], max_bits, block_mode, cap)
}

const COMPRESS_CLEAR_CODE: u32 = 256;
const COMPRESS_FIRST_FREE: u32 = 257;

fn lzw_unix_decompress(
    payload: &[u8],
    max_bits: u32,
    block_mode: bool,
    cap: u64,
) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let max_entries: u32 = 1u32 << max_bits;
    let first_free: u32 = if block_mode {
        COMPRESS_FIRST_FREE
    } else {
        COMPRESS_CLEAR_CODE
    };
    let mut prefix: Vec<u32> = vec![0u32; max_entries as usize];
    let mut suffix: Vec<u8> = vec![0u8; max_entries as usize];
    for code in 0..256u32 {
        suffix[code as usize] = code as u8;
    }
    let mut stack: Vec<u8> = Vec::with_capacity(max_entries as usize);
    let mut code_size: u32 = 9;
    let mut next_code: u32 = first_free;
    let mut previous: Option<u32> = None;
    let mut bit_pos: usize = 0;
    let mut region_start: usize = 0;
    let total_bits: usize = payload.len() * 8;

    loop {
        if next_code > max_code_for(code_size) && code_size < max_bits {
            bit_pos = group_align(bit_pos, region_start, code_size);
            region_start = bit_pos;
            code_size += 1;
        }
        if bit_pos + (code_size as usize) > total_bits {
            break;
        }
        let code: u32 = read_lsb_code(payload, bit_pos, code_size);
        bit_pos += code_size as usize;

        if block_mode && code == COMPRESS_CLEAR_CODE {
            bit_pos = group_align(bit_pos, region_start, code_size);
            region_start = bit_pos;
            next_code = first_free;
            code_size = 9;
            previous = None;
            continue;
        }

        let deferred_first: bool = code >= next_code;
        if deferred_first && (code != next_code || previous.is_none()) {
            return Err(Error::Decompression(format!(
                "compress(.Z): invalid code {code} (next={next_code})"
            )));
        }
        let walk_from: u32 = if deferred_first {
            match previous {
                Some(prev) => prev,
                None => {
                    return Err(Error::Decompression(
                        "compress(.Z): deferred code with no predecessor".to_owned(),
                    ));
                }
            }
        } else {
            code
        };

        let first_byte: u8 = emit_chain(walk_from, &prefix, &suffix, &mut stack);
        while let Some(byte) = stack.pop() {
            out.push(byte);
        }
        if deferred_first {
            out.push(first_byte);
        }
        if out.len() as u64 > cap {
            return Err(Error::QuotaExceeded {
                entry: "stream.Z".to_owned(),
                reason: format!("decompressed stream exceeds bomb cap {cap}"),
            });
        }

        if let Some(prev) = previous
            && next_code < max_entries
        {
            prefix[next_code as usize] = prev;
            suffix[next_code as usize] = first_byte;
            next_code += 1;
        }
        previous = Some(code);
    }
    Ok(out)
}

const fn max_code_for(code_size: u32) -> u32 {
    (1u32 << code_size) - 1
}

const fn group_align(bit_pos: usize, region_start: usize, code_size: u32) -> usize {
    let group_bits: usize = (code_size as usize) << 3;
    let consumed: usize = bit_pos - region_start;
    let remainder: usize = consumed % group_bits;
    if remainder == 0 {
        bit_pos
    } else {
        bit_pos + (group_bits - remainder)
    }
}

fn emit_chain(start: u32, prefix: &[u32], suffix: &[u8], stack: &mut Vec<u8>) -> u8 {
    let mut code: u32 = start;
    while code >= COMPRESS_CLEAR_CODE {
        stack.push(suffix[code as usize]);
        code = prefix[code as usize];
    }
    let first: u8 = suffix[code as usize];
    stack.push(first);
    first
}

fn read_lsb_code(payload: &[u8], bit_pos: usize, code_size: u32) -> u32 {
    let mut value: u32 = 0;
    for i in 0..code_size as usize {
        let absolute: usize = bit_pos + i;
        let byte: usize = absolute / 8;
        let bit: usize = absolute % 8;
        if (payload[byte] >> bit) & 1 != 0 {
            value |= 1u32 << i;
        }
    }
    value
}

#[derive(Debug, Clone)]
pub struct GzipMember {
    pub original_name: Option<String>,
    pub data: Vec<u8>,
    pub compressed_len: usize,
}

#[must_use]
pub fn detect_gzip(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes.starts_with(GZIP_MAGIC) && bytes[2] == 0x08
}

pub fn decompress_gzip_members(bytes: &[u8], cap: u64) -> Result<Vec<GzipMember>> {
    if !detect_gzip(bytes) {
        return Err(Error::Decompression(
            "gzip: missing 0x1f8b deflate magic".to_owned(),
        ));
    }
    let mut members: Vec<GzipMember> = Vec::new();
    let mut offset: usize = 0;
    let mut total: u64 = 0;
    while offset < bytes.len() {
        if !bytes[offset..].starts_with(GZIP_MAGIC) {
            break;
        }
        let remaining: &[u8] = &bytes[offset..];
        let original_name: Option<String> = parse_gzip_name(remaining);
        let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(remaining);
        let mut decoder: flate2::bufread::GzDecoder<&mut std::io::Cursor<&[u8]>> =
            flate2::bufread::GzDecoder::new(&mut cursor);
        let mut data: Vec<u8> = Vec::new();
        let member_cap: u64 = cap.saturating_sub(total).saturating_add(1);
        let read: u64 = std::io::copy(&mut (&mut decoder).take(member_cap), &mut data).map_err(
            |e: std::io::Error| Error::Decompression(format!("gzip: inflate failed: {e}")),
        )?;
        total = total.saturating_add(read);
        if total > cap {
            return Err(Error::QuotaExceeded {
                entry: "stream.gz".to_owned(),
                reason: format!("decompressed stream exceeds bomb cap {cap}"),
            });
        }
        let consumed: usize =
            usize::try_from(cursor.position()).map_err(|_e: std::num::TryFromIntError| {
                Error::Decompression("gzip: input overflow".to_owned())
            })?;
        if consumed == 0 {
            return Err(Error::Decompression(
                "gzip: member consumed zero input (malformed stream)".to_owned(),
            ));
        }
        members.push(GzipMember {
            original_name,
            data,
            compressed_len: consumed,
        });
        offset = offset
            .checked_add(consumed)
            .ok_or_else(|| Error::Decompression("gzip: member offset overflow".to_owned()))?;
    }
    if members.is_empty() {
        return Err(Error::Decompression("gzip: no members decoded".to_owned()));
    }
    Ok(members)
}

fn parse_gzip_name(member: &[u8]) -> Option<String> {
    if member.len() < 10 {
        return None;
    }
    let flg: u8 = member[3];
    if flg & 0x08 == 0 {
        return None;
    }
    let mut cursor: usize = 10;
    if flg & 0x04 != 0 {
        let xlen: usize = usize::from(u16::from_le_bytes([
            *member.get(cursor)?,
            *member.get(cursor + 1)?,
        ]));
        cursor = cursor.checked_add(2)?.checked_add(xlen)?;
    }
    let start: usize = cursor;
    while cursor < member.len() && member[cursor] != 0 {
        cursor += 1;
    }
    if cursor >= member.len() {
        return None;
    }
    let raw: &[u8] = member.get(start..cursor)?;
    Some(String::from_utf8_lossy(raw).into_owned())
}

#[must_use]
pub fn detect_bzip2(bytes: &[u8]) -> bool {
    if !bytes.starts_with(BZIP2_MAGIC) || bytes.len() < 4 {
        return false;
    }
    matches!(bytes[3], b'1'..=b'9')
}

pub fn decompress_bzip2(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    if !detect_bzip2(bytes) {
        return Err(Error::Decompression(
            "bzip2: missing BZh[1-9] magic".to_owned(),
        ));
    }
    let limit: u64 = cap.saturating_add(1);
    let mut out: Vec<u8> = Vec::new();
    let decoder: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(bytes);
    let read: u64 = std::io::copy(&mut decoder.take(limit), &mut out)
        .map_err(|e: std::io::Error| Error::Decompression(format!("bzip2: decode failed: {e}")))?;
    if read > cap {
        return Err(Error::QuotaExceeded {
            entry: "stream.bz2".to_owned(),
            reason: format!("decompressed stream exceeds bomb cap {cap}"),
        });
    }
    Ok(out)
}

#[must_use]
pub fn detect_zstd(bytes: &[u8]) -> bool {
    bytes.starts_with(ZSTD_MAGIC)
}

pub fn decompress_zstd(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    if !detect_zstd(bytes) {
        return Err(Error::Decompression(
            "zstd: missing 0x28b52ffd magic".to_owned(),
        ));
    }
    let limit: u64 = cap.saturating_add(1);
    let mut out: Vec<u8> = Vec::new();
    let decoder: zstd::stream::read::Decoder<'static, std::io::BufReader<&[u8]>> =
        zstd::stream::read::Decoder::new(bytes)
            .map_err(|e: std::io::Error| Error::Decompression(format!("zstd: {e}")))?;
    let read: u64 = std::io::copy(&mut decoder.take(limit), &mut out)
        .map_err(|e: std::io::Error| Error::Decompression(format!("zstd: decode failed: {e}")))?;
    if read > cap {
        return Err(Error::QuotaExceeded {
            entry: "stream.zst".to_owned(),
            reason: format!("decompressed stream exceeds bomb cap {cap}"),
        });
    }
    Ok(out)
}

#[must_use]
pub fn lzma_alone_header_is_valid(bytes: &[u8]) -> bool {
    if bytes.len() < 13 {
        return false;
    }
    let props: u8 = bytes[0];
    if props > LZMA_ALONE_PROPS_MAX {
        return false;
    }
    let dict_size: u32 = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    if dict_size < (1u32 << 12) {
        return false;
    }
    let uncompressed: u64 = u64::from_le_bytes([
        bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
    ]);
    uncompressed == u64::MAX || uncompressed < (1u64 << 56)
}

#[must_use]
pub fn detect_lzma_alone(bytes: &[u8]) -> bool {
    if !lzma_alone_header_is_valid(bytes) {
        return false;
    }
    let declared: u64 = u64::from_le_bytes([
        bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
    ]);
    if declared == u64::MAX || declared == 0 {
        return false;
    }
    let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(bytes);
    let mut sink: Vec<u8> = Vec::new();
    let options: lzma_rs::decompress::Options = lzma_rs::decompress::Options {
        memlimit: Some(256 * 1024 * 1024),
        ..Default::default()
    };
    match lzma_rs::lzma_decompress_with_options(&mut reader, &mut sink, &options) {
        Ok(()) => sink.len() as u64 == declared,
        Err(_) => false,
    }
}

struct CapWriter {
    inner: Vec<u8>,
    cap: u64,
    overflowed: bool,
}

impl std::io::Write for CapWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.inner.len() as u64 + buf.len() as u64 > self.cap {
            self.overflowed = true;
            return Err(std::io::Error::other("lzma-alone output exceeds bomb cap"));
        }
        self.inner.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn decompress_lzma_alone(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    if !lzma_alone_header_is_valid(bytes) {
        return Err(Error::Decompression(
            "lzma-alone: header is not a valid 13-byte lzma-alone prelude".to_owned(),
        ));
    }
    let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(bytes);
    let mut sink: CapWriter = CapWriter {
        inner: Vec::new(),
        cap,
        overflowed: false,
    };
    let options: lzma_rs::decompress::Options = lzma_rs::decompress::Options {
        memlimit: Some(512 * 1024 * 1024),
        ..Default::default()
    };
    match lzma_rs::lzma_decompress_with_options(&mut reader, &mut sink, &options) {
        Ok(()) => Ok(sink.inner),
        Err(e) => {
            if sink.overflowed {
                Err(Error::QuotaExceeded {
                    entry: "stream.lzma".to_owned(),
                    reason: format!("decompressed stream exceeds bomb cap {cap}"),
                })
            } else {
                Err(Error::Decompression(format!("lzma-alone decode: {e}")))
            }
        }
    }
}

const BROTLI_READER_BUFFER: usize = 4096;
const LZNT1_CHUNK_SIGNATURE: u16 = 0x3000;
const LZNT1_COMPRESSED_FLAG: u16 = 0x8000;
const LZNT1_CHUNK_SIZE_MASK: u16 = 0x0fff;
const OUTPUT_ORACLE_MIN_LEN: usize = 16;

fn output_independently_validates(out: &[u8]) -> bool {
    if out.len() < OUTPUT_ORACLE_MIN_LEN {
        return false;
    }
    has_nested_container_magic(out) || has_known_artifact_header(out) || is_mostly_printable(out)
}

fn has_nested_container_magic(out: &[u8]) -> bool {
    detect_gzip(out)
        || detect_bzip2(out)
        || detect_zstd(out)
        || detect_zlib(out)
        || detect_lzip(out)
        || detect_compress(out)
        || detect_lz4(out).is_some()
        || out.starts_with(b"\xfd7zXZ\x00")
        || out.starts_with(b"PK\x03\x04")
        || out.starts_with(b"PK\x05\x06")
        || out.starts_with(b"7z\xbc\xaf\x27\x1c")
        || out.starts_with(b"Rar!\x1a\x07")
        || out.starts_with(b"ustar")
}

fn has_known_artifact_header(out: &[u8]) -> bool {
    out.starts_with(b"\x7fELF")
        || out.starts_with(b"MZ")
        || out.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || out.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || out.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || out.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || out.starts_with(b"\x89PNG\r\n\x1a\n")
        || out.starts_with(b"%PDF-")
        || out.starts_with(b"dex\n")
        || has_marshal_pyc_header(out)
}

fn has_marshal_pyc_header(out: &[u8]) -> bool {
    if out.len() < 16 {
        return false;
    }
    if out[2] != 0x0d || out[3] != 0x0a {
        return false;
    }
    let magic_lo: u16 = u16::from_le_bytes([out[0], out[1]]);
    if !(0x0a00..=0x0fff).contains(&magic_lo) {
        return false;
    }
    matches!(
        out[16],
        b'c' | b'd' | b's' | b'(' | b'{' | b'[' | b')' | b'N' | b'T' | b'F' | b'z' | b'Z' | b'i'
    )
}

fn is_mostly_printable(out: &[u8]) -> bool {
    let sample: &[u8] = if out.len() > 65_536 {
        &out[..65_536]
    } else {
        out
    };
    let printable: usize = sample
        .iter()
        .filter(|&&b: &&u8| matches!(b, 0x09 | 0x0a | 0x0d | 0x20..=0x7e))
        .count();
    printable * 100 >= sample.len() * 95
}

pub fn decompress_brotli(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    let limit: u64 = cap.saturating_add(1);
    let mut out: Vec<u8> = Vec::new();
    let mut decoder: brotli::Decompressor<&[u8]> =
        brotli::Decompressor::new(bytes, BROTLI_READER_BUFFER);
    let read: u64 = std::io::copy(&mut (&mut decoder).take(limit), &mut out)
        .map_err(|e: std::io::Error| Error::Decompression(format!("brotli: decode failed: {e}")))?;
    if read > cap {
        return Err(Error::QuotaExceeded {
            entry: "stream.br".to_owned(),
            reason: format!("decompressed stream exceeds bomb cap {cap}"),
        });
    }
    if out.is_empty() {
        return Err(Error::Decompression(
            "brotli: stream produced no output".to_owned(),
        ));
    }
    Ok(out)
}

#[must_use]
pub fn detect_brotli(bytes: &[u8]) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    decompress_brotli(bytes, 16 * 1024 * 1024)
        .is_ok_and(|out: Vec<u8>| output_independently_validates(&out))
}

#[must_use]
pub fn try_decompress_brotli_oracle(bytes: &[u8], cap: u64) -> Option<Vec<u8>> {
    match decompress_brotli(bytes, cap) {
        Ok(out) if output_independently_validates(&out) => Some(out),
        _ => None,
    }
}

pub fn decompress_lznt1(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut offset: usize = 0;
    while offset < bytes.len() {
        if offset + 2 > bytes.len() {
            break;
        }
        let header: u16 = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        if header == 0 {
            break;
        }
        let body_len: usize = usize::from(header & LZNT1_CHUNK_SIZE_MASK) + 1;
        let compressed: bool = header & LZNT1_COMPRESSED_FLAG != 0;
        if header & 0x7000 != LZNT1_CHUNK_SIGNATURE {
            return Err(Error::Decompression(format!(
                "lznt1: chunk signature {:#06x} not 0x3000",
                header & 0x7000
            )));
        }
        let body_start: usize = offset + 2;
        let body_end: usize = body_start
            .checked_add(body_len)
            .ok_or_else(|| Error::Decompression("lznt1: chunk length overflow".to_owned()))?;
        let body: &[u8] = bytes.get(body_start..body_end).ok_or_else(|| {
            Error::Decompression("lznt1: chunk body past end of input".to_owned())
        })?;
        let chunk_origin: usize = out.len();
        if compressed {
            decompress_lznt1_chunk(body, chunk_origin, &mut out)?;
        } else {
            out.extend_from_slice(body);
        }
        if out.len() as u64 > cap {
            return Err(Error::QuotaExceeded {
                entry: "stream.lznt1".to_owned(),
                reason: format!("decompressed stream exceeds bomb cap {cap}"),
            });
        }
        offset = body_end;
    }
    if out.is_empty() {
        return Err(Error::Decompression("lznt1: produced no output".to_owned()));
    }
    Ok(out)
}

fn decompress_lznt1_chunk(body: &[u8], chunk_origin: usize, out: &mut Vec<u8>) -> Result<()> {
    let mut cursor: usize = 0;
    while cursor < body.len() {
        let flags: u8 = body[cursor];
        cursor += 1;
        for bit in 0..8u8 {
            if cursor >= body.len() {
                return Ok(());
            }
            if flags & (1u8 << bit) == 0 {
                out.push(body[cursor]);
                cursor += 1;
                continue;
            }
            let token: u16 = u16::from_le_bytes([
                body[cursor],
                *body.get(cursor + 1).ok_or_else(|| {
                    Error::Decompression("lznt1: truncated back-reference token".to_owned())
                })?,
            ]);
            cursor += 2;
            let produced: usize = out.len() - chunk_origin;
            if produced == 0 {
                return Err(Error::Decompression(
                    "lznt1: back-reference at chunk start".to_owned(),
                ));
            }
            let (length, displacement): (usize, usize) = lznt1_split_token(token, produced);
            let source_start: usize = chunk_origin
                .checked_add(produced)
                .and_then(|p: usize| p.checked_sub(displacement))
                .ok_or_else(|| {
                    Error::Decompression("lznt1: back-reference underflow".to_owned())
                })?;
            if source_start < chunk_origin {
                return Err(Error::Decompression(
                    "lznt1: back-reference points before chunk".to_owned(),
                ));
            }
            for i in 0..length {
                let byte: u8 = out[source_start + i];
                out.push(byte);
            }
        }
    }
    Ok(())
}

fn lznt1_split_token(token: u16, produced: usize) -> (usize, usize) {
    let mut position: usize = produced - 1;
    let mut length_mask: u16 = 0x0fff;
    let mut length_bits: u32 = 12;
    while position >= 0x10 {
        length_mask >>= 1;
        length_bits -= 1;
        position >>= 1;
    }
    let displacement: usize = usize::from(token >> length_bits) + 1;
    let length: usize = usize::from(token & length_mask) + 3;
    (length, displacement)
}

#[must_use]
pub fn detect_lznt1(bytes: &[u8]) -> bool {
    if bytes.len() < 3 {
        return false;
    }
    let header: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
    if header & 0x7000 != LZNT1_CHUNK_SIGNATURE {
        return false;
    }
    decompress_lznt1(bytes, 16 * 1024 * 1024)
        .is_ok_and(|out: Vec<u8>| output_independently_validates(&out))
}

#[must_use]
pub fn try_decompress_lznt1_oracle(bytes: &[u8], cap: u64) -> Option<Vec<u8>> {
    if bytes.len() < 2 {
        return None;
    }
    let header: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
    if header & 0x7000 != LZNT1_CHUNK_SIGNATURE {
        return None;
    }
    match decompress_lznt1(bytes, cap) {
        Ok(out) if output_independently_validates(&out) => Some(out),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn zlib_header_validation_accepts_real_headers() {
        assert!(zlib_header_is_valid(&[0x78, 0x01]));
        assert!(zlib_header_is_valid(&[0x78, 0x9c]));
        assert!(zlib_header_is_valid(&[0x78, 0xda]));
    }

    #[test]
    fn zlib_header_validation_rejects_non_zlib() {
        assert!(!zlib_header_is_valid(&[0x78, 0x00]));
        assert!(!zlib_header_is_valid(&[0x1f, 0x8b]));
        assert!(!zlib_header_is_valid(&[0x78]));
    }

    #[test]
    fn zlib_round_trip_with_adler_check() {
        use std::io::Write as _;
        let payload: Vec<u8> = b"the quick brown fox jumps over the lazy dog".repeat(4);
        let mut encoder: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&payload).expect("encode");
        let compressed: Vec<u8> = encoder.finish().expect("finish");
        assert_eq!(compressed[0], 0x78);
        let decoded: Vec<u8> = inflate_zlib_verified(&compressed, 1 << 20).expect("inflate");
        assert_eq!(decoded, payload);
        assert!(detect_zlib(&compressed));
    }

    #[test]
    fn zlib_rejects_payload_that_merely_starts_0x78() {
        let mut bytes: Vec<u8> = vec![0x78, 0x9c];
        bytes.extend(std::iter::repeat_n(0xffu8, 64));
        assert!(!detect_zlib(&bytes));
    }

    #[test]
    fn lz4_magic_dispatch() {
        assert_eq!(
            detect_lz4(&[0x04, 0x22, 0x4d, 0x18]),
            Some(Lz4Layout::Frame)
        );
        assert_eq!(
            detect_lz4(&[0x02, 0x21, 0x4c, 0x18]),
            Some(Lz4Layout::Legacy)
        );
        assert_eq!(
            detect_lz4(&[0x50, 0x2a, 0x4d, 0x18]),
            Some(Lz4Layout::Skippable)
        );
        assert_eq!(detect_lz4(&[0x00, 0x00, 0x00, 0x00]), None);
    }

    #[test]
    fn lz4_frame_round_trip() {
        let payload: Vec<u8> = (0..5000u32).map(|i: u32| (i % 251) as u8).collect();
        let mut compressed: Vec<u8> = Vec::new();
        {
            use std::io::Write as _;
            let mut encoder: lz4_flex::frame::FrameEncoder<&mut Vec<u8>> =
                lz4_flex::frame::FrameEncoder::new(&mut compressed);
            encoder.write_all(&payload).expect("encode");
            encoder.finish().expect("finish");
        }
        let decoded: Vec<u8> = decompress_lz4(&compressed, 1 << 20).expect("decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn gzip_member_name_parsing() {
        let mut member: Vec<u8> = vec![0x1f, 0x8b, 0x08, 0x08, 0, 0, 0, 0, 0, 0xff];
        member.extend_from_slice(b"original.txt\x00");
        let name: Option<String> = parse_gzip_name(&member);
        assert_eq!(name.as_deref(), Some("original.txt"));
    }

    #[test]
    fn bzip2_magic_validation() {
        assert!(detect_bzip2(b"BZh9"));
        assert!(detect_bzip2(b"BZh1"));
        assert!(!detect_bzip2(b"BZh0"));
        assert!(!detect_bzip2(b"BZx9"));
    }

    #[test]
    fn lzma_alone_header_validation() {
        let mut header: Vec<u8> = vec![0x5d];
        header.extend_from_slice(&(1u32 << 23).to_le_bytes());
        header.extend_from_slice(&42u64.to_le_bytes());
        assert!(lzma_alone_header_is_valid(&header));
        let mut bad: Vec<u8> = vec![0xff];
        bad.extend(std::iter::repeat_n(0u8, 12));
        assert!(!lzma_alone_header_is_valid(&bad));
        let mz: Vec<u8> = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff".to_vec();
        assert!(!detect_lzma_alone(&mz));
    }

    #[test]
    fn compress_magic_validation() {
        assert!(detect_compress(&[0x1f, 0x9d, 0x90]));
        assert!(!detect_compress(&[0x1f, 0x9d, 0x00]));
        assert!(!detect_compress(&[0x1f, 0x8b, 0x90]));
    }

    #[test]
    fn lzma_alone_round_trip() {
        let payload: Vec<u8> = b"the quick brown fox jumps over the lazy dog\n".repeat(8);
        let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(payload.as_slice());
        let mut compressed: Vec<u8> = Vec::new();
        lzma_rs::lzma_compress(&mut reader, &mut compressed).expect("compress");
        let decoded: Vec<u8> = decompress_lzma_alone(&compressed, 1 << 20).expect("decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn lzma_alone_respects_cap() {
        let payload: Vec<u8> = vec![0x41u8; 4096];
        let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(payload.as_slice());
        let mut compressed: Vec<u8> = Vec::new();
        lzma_rs::lzma_compress(&mut reader, &mut compressed).expect("compress");
        let err: Error = decompress_lzma_alone(&compressed, 16).expect_err("cap");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn lzma_alone_rejects_bad_header() {
        let err: Error = decompress_lzma_alone(b"not-lzma-at-all!!", 1 << 20).expect_err("bad");
        assert!(matches!(err, Error::Decompression(_)));
    }

    fn brotli_compress(payload: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut compressed: Vec<u8> = Vec::new();
        {
            let mut encoder: brotli::CompressorWriter<&mut Vec<u8>> =
                brotli::CompressorWriter::new(&mut compressed, 4096, 9, 22);
            encoder.write_all(payload).expect("brotli encode");
            encoder.flush().expect("brotli flush");
        }
        compressed
    }

    #[test]
    fn brotli_round_trip_printable_oracle() {
        let payload: Vec<u8> =
            b"the quick brown fox jumps over the lazy dog, repeatedly and verbosely.\n".repeat(64);
        let compressed: Vec<u8> = brotli_compress(&payload);
        let decoded: Vec<u8> = decompress_brotli(&compressed, 1 << 20).expect("brotli decode");
        assert_eq!(decoded, payload);
        assert!(detect_brotli(&compressed));
        assert_eq!(
            try_decompress_brotli_oracle(&compressed, 1 << 20).as_deref(),
            Some(payload.as_slice())
        );
    }

    #[test]
    fn brotli_round_trip_nested_gzip_oracle() {
        use std::io::Write as _;
        let inner: Vec<u8> = b"nested payload that lives under gzip then brotli\n".repeat(32);
        let mut gz: Vec<u8> = Vec::new();
        {
            let mut encoder: flate2::write::GzEncoder<&mut Vec<u8>> =
                flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            encoder.write_all(&inner).expect("gzip encode");
            encoder.finish().expect("gzip finish");
        }
        assert!(detect_gzip(&gz));
        let compressed: Vec<u8> = brotli_compress(&gz);
        let decoded: Vec<u8> = decompress_brotli(&compressed, 1 << 20).expect("brotli decode");
        assert_eq!(decoded, gz);
        assert!(detect_brotli(&compressed));
    }

    #[test]
    fn brotli_respects_cap() {
        let payload: Vec<u8> = vec![0x41u8; 1 << 16];
        let compressed: Vec<u8> = brotli_compress(&payload);
        let err: Error = decompress_brotli(&compressed, 64).expect_err("cap");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn brotli_rejects_non_brotli_garbage() {
        let garbage: Vec<u8> = (0..4096u32)
            .map(|i: u32| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        assert!(!detect_brotli(&garbage));
        assert!(try_decompress_brotli_oracle(&garbage, 1 << 20).is_none());
    }

    fn lznt1_uncompressed_chunk(payload: &[u8]) -> Vec<u8> {
        assert!(!payload.is_empty() && payload.len() <= 4096);
        let header: u16 = LZNT1_CHUNK_SIGNATURE | ((payload.len() as u16) - 1);
        let mut out: Vec<u8> = header.to_le_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn lznt1_uncompressed_chunk_round_trip() {
        let payload: &[u8] = b"plain uncompressed chunk text content well over sixteen bytes";
        let stream: Vec<u8> = lznt1_uncompressed_chunk(payload);
        let decoded: Vec<u8> = decompress_lznt1(&stream, 1 << 20).expect("lznt1 decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn lznt1_compressed_back_reference_reference_vector() {
        let mut chunk_body: Vec<u8> = Vec::new();
        chunk_body.push(0b0000_0010);
        chunk_body.push(b'A');
        let token: u16 = (30u16 - 3) & 0x0fff;
        chunk_body.extend_from_slice(&token.to_le_bytes());
        let header: u16 =
            LZNT1_CHUNK_SIGNATURE | LZNT1_COMPRESSED_FLAG | ((chunk_body.len() as u16) - 1);
        let mut stream: Vec<u8> = header.to_le_bytes().to_vec();
        stream.extend_from_slice(&chunk_body);
        let expected: Vec<u8> = vec![b'A'; 31];
        let decoded: Vec<u8> = decompress_lznt1(&stream, 1 << 20).expect("lznt1 decode");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn lznt1_compressed_via_reference_encoder() {
        let payload: Vec<u8> = b"ABCABCABCABCABCABC#####ABCABCABCABC#####ABCABCABCABC".to_vec();
        let stream: Vec<u8> = reference_lznt1_compress(&payload);
        let decoded: Vec<u8> = decompress_lznt1(&stream, 1 << 20).expect("lznt1 decode");
        assert_eq!(decoded, payload);
        assert!(detect_lznt1(&stream));
        assert_eq!(
            try_decompress_lznt1_oracle(&stream, 1 << 20).as_deref(),
            Some(payload.as_slice())
        );
    }

    #[test]
    fn lznt1_token_split_matches_reference() {
        for produced in [1usize, 0x10, 0x11, 0x20, 0x100, 0x800, 0xfff] {
            let (length, displacement): (usize, usize) = lznt1_split_token(0xffff, produced);
            let (rl, rd): (usize, usize) = reference_split(0xffff, produced);
            assert_eq!((length, displacement), (rl, rd), "produced={produced}");
        }
    }

    #[test]
    fn lznt1_respects_cap() {
        let payload: Vec<u8> = vec![0x42u8; 4096];
        let stream: Vec<u8> = reference_lznt1_compress(&payload);
        let err: Error = decompress_lznt1(&stream, 16).expect_err("cap");
        assert!(matches!(err, Error::QuotaExceeded { .. }));
    }

    #[test]
    fn lznt1_rejects_bad_signature() {
        let mut stream: Vec<u8> = vec![0x00, 0x40];
        stream.extend(std::iter::repeat_n(0x41u8, 32));
        assert!(!detect_lznt1(&stream));
        assert!(try_decompress_lznt1_oracle(&stream, 1 << 20).is_none());
    }

    fn reference_split(token: u16, produced: usize) -> (usize, usize) {
        let mut pos: usize = produced - 1;
        let mut l_mask: u16 = 0xfff;
        let mut o_shift: u32 = 12;
        while pos >= 0x10 {
            l_mask >>= 1;
            o_shift -= 1;
            pos >>= 1;
        }
        let length: usize = usize::from(token & l_mask) + 3;
        let offset: usize = usize::from(token >> o_shift) + 1;
        (length, offset)
    }

    fn reference_lznt1_compress(payload: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for chunk in payload.chunks(4096) {
            let compressed: Vec<u8> = reference_compress_chunk(chunk);
            if compressed.len() < chunk.len() {
                let header: u16 =
                    LZNT1_CHUNK_SIGNATURE | LZNT1_COMPRESSED_FLAG | ((compressed.len() as u16) - 1);
                out.extend_from_slice(&header.to_le_bytes());
                out.extend_from_slice(&compressed);
            } else {
                let header: u16 = LZNT1_CHUNK_SIGNATURE | ((chunk.len() as u16) - 1);
                out.extend_from_slice(&header.to_le_bytes());
                out.extend_from_slice(chunk);
            }
        }
        out
    }

    fn reference_compress_chunk(chunk: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut pos: usize = 0;
        while pos < chunk.len() {
            let group_start: usize = out.len();
            out.push(0u8);
            let mut flags: u8 = 0;
            for bit in 0..8u8 {
                if pos >= chunk.len() {
                    break;
                }
                let (best_len, best_off): (usize, usize) = reference_find_match(chunk, pos);
                if best_len >= 3 {
                    let (_, max_bits): (u16, u32) = reference_masks(pos);
                    let token: u16 = (((best_off - 1) as u16) << max_bits)
                        | (((best_len - 3) as u16) & ((1u16 << max_bits) - 1));
                    out.extend_from_slice(&token.to_le_bytes());
                    flags |= 1u8 << bit;
                    pos += best_len;
                } else {
                    out.push(chunk[pos]);
                    pos += 1;
                }
            }
            out[group_start] = flags;
        }
        out
    }

    fn reference_masks(produced: usize) -> (u16, u32) {
        let mut p: usize = produced - 1;
        let mut l_mask: u16 = 0xfff;
        let mut o_shift: u32 = 12;
        while p >= 0x10 {
            l_mask >>= 1;
            o_shift -= 1;
            p >>= 1;
        }
        (l_mask, o_shift)
    }

    fn reference_find_match(chunk: &[u8], pos: usize) -> (usize, usize) {
        if pos == 0 {
            return (0, 0);
        }
        let (l_mask, _): (u16, u32) = reference_masks(pos);
        let max_len: usize = (usize::from(l_mask) + 3).min(chunk.len() - pos);
        let max_off: usize = pos;
        let mut best_len: usize = 0;
        let mut best_off: usize = 0;
        for off in 1..=max_off {
            let mut len: usize = 0;
            while len < max_len && chunk[pos + len] == chunk[pos - off + (len % off)] {
                len += 1;
            }
            if len > best_len {
                best_len = len;
                best_off = off;
            }
        }
        (best_len, best_off)
    }
}
