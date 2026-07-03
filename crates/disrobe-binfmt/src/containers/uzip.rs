use std::io::{Read, Write};

use crate::error::{Error, Result};

const MAGIC_LEN: usize = 128;
const OFS_COMPR: usize = 0x0b;
const OFS_VERSN: usize = 0x0c;
const MAGIC_START: &[u8] = b"#!/bin/sh\n";

const COMP_LIBZ: u8 = b'V';
const COMP_LIBZ_DDP: u8 = b'v';
const COMP_LZMA: u8 = b'L';
const COMP_LZMA_DDP: u8 = b'l';
const COMP_ZSTD: u8 = b'Z';
const COMP_ZSTD_DDP: u8 = b'z';
const MAX_UZIP_PREALLOC: usize = 64 * 1024 * 1024;
const MAX_UZIP_PREALLOC_U64: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UzipCompressor {
    Zlib,
    Lzma,
    Zstd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UzipImage {
    pub compressor: UzipCompressor,
    pub version: u8,
    pub block_size: u32,
    pub block_count: u32,
    pub image: Vec<u8>,
}

#[must_use]
pub fn detect_uzip(bytes: &[u8]) -> bool {
    bytes.len() > MAGIC_LEN + 8
        && bytes.starts_with(MAGIC_START)
        && compressor_from(bytes.get(OFS_COMPR).copied().map_or(0, |value: u8| value)).is_some()
}

const fn compressor_from(byte: u8) -> Option<UzipCompressor> {
    match byte {
        COMP_LIBZ | COMP_LIBZ_DDP => Some(UzipCompressor::Zlib),
        COMP_LZMA | COMP_LZMA_DDP => Some(UzipCompressor::Lzma),
        COMP_ZSTD | COMP_ZSTD_DDP => Some(UzipCompressor::Zstd),
        _ => None,
    }
}

pub fn parse_uzip(bytes: &[u8], max_total: u64) -> Result<UzipImage> {
    if !bytes.starts_with(MAGIC_START) {
        return Err(Error::Uzip(
            "uzip: missing #!/bin/sh cloop preamble".to_owned(),
        ));
    }
    let compr_byte: u8 = *bytes
        .get(OFS_COMPR)
        .ok_or_else(|| Error::Uzip("uzip: truncated magic".to_owned()))?;
    let compressor: UzipCompressor = compressor_from(compr_byte)
        .ok_or_else(|| Error::Uzip(format!("uzip: unknown compressor byte 0x{compr_byte:02x}")))?;
    let version: u8 = *bytes
        .get(OFS_VERSN)
        .ok_or_else(|| Error::Uzip("uzip: truncated version field".to_owned()))?;

    let blksz: u32 = read_be_u32(bytes, MAGIC_LEN)?;
    let nblocks: u32 = read_be_u32(bytes, MAGIC_LEN + 4)?;
    if blksz == 0 || nblocks == 0 {
        return Err(Error::Uzip(format!(
            "uzip: implausible blksz={blksz} nblocks={nblocks}"
        )));
    }
    let toc_start: usize = MAGIC_LEN + 8;
    let block_count: usize = usize::try_from(nblocks)
        .map_err(|_| Error::Uzip("uzip: block count overflow".to_owned()))?;
    let toc_entries: usize = block_count
        .checked_add(1)
        .ok_or_else(|| Error::Uzip("uzip: TOC entry count overflow".to_owned()))?;
    let toc_end: usize = toc_start
        .checked_add(toc_entries.checked_mul(8).ok_or_else(toc_overflow)?)
        .ok_or_else(toc_overflow)?;
    if toc_end > bytes.len() {
        return Err(Error::Uzip(format!(
            "uzip: TOC of {toc_entries} offsets runs past end of image"
        )));
    }
    let mut offsets: Vec<u64> = Vec::with_capacity(toc_entries);
    for i in 0..toc_entries {
        let at: usize = toc_start + i * 8;
        offsets.push(read_be_u64(bytes, at)?);
    }

    let total_uncompressed: u64 = u64::from(blksz) * u64::from(nblocks);
    if total_uncompressed > max_total {
        return Err(Error::Uzip(format!(
            "uzip: image size {total_uncompressed} exceeds quota {max_total}"
        )));
    }

    let prealloc_u64: u64 = total_uncompressed.min(MAX_UZIP_PREALLOC_U64);
    let prealloc: usize = usize::try_from(prealloc_u64)
        .map_err(|_| Error::Uzip("uzip: image capacity overflow".to_owned()))?;
    let mut image: Vec<u8> = Vec::with_capacity(prealloc);
    for i in 0..block_count {
        let start: u64 = offsets[i];
        let end: u64 = offsets[i + 1];
        if end < start {
            return Err(Error::Uzip(format!(
                "uzip: TOC offset {i} not monotonic ({start} > {end})"
            )));
        }
        let start_us: usize =
            usize::try_from(start).map_err(|_| Error::Uzip("uzip: offset overflow".to_owned()))?;
        let end_us: usize =
            usize::try_from(end).map_err(|_| Error::Uzip("uzip: offset overflow".to_owned()))?;
        if end_us > bytes.len() {
            return Err(Error::Uzip(format!(
                "uzip: block {i} ends at {end_us} past image length {}",
                bytes.len()
            )));
        }
        let block: &[u8] = &bytes[start_us..end_us];
        let want: usize = usize::try_from(blksz)
            .map_err(|_| Error::Uzip("uzip: block size overflow".to_owned()))?;
        if block.is_empty() {
            image.extend(std::iter::repeat_n(0u8, want));
            continue;
        }
        let decoded: Vec<u8> = decode_block(compressor, block, want)?;
        image.extend_from_slice(&decoded);
    }
    Ok(UzipImage {
        compressor,
        version,
        block_size: blksz,
        block_count: nblocks,
        image,
    })
}

fn decode_block(compressor: UzipCompressor, block: &[u8], want: usize) -> Result<Vec<u8>> {
    match compressor {
        UzipCompressor::Zlib => {
            let decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(block);
            read_block_to_exact(decoder, want, "zlib")
        }
        UzipCompressor::Lzma => {
            let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(block);
            let mut writer: BoundedVecWriter = BoundedVecWriter::new(want);
            lzma_rs::lzma_decompress(&mut cursor, &mut writer)
                .map_err(|e| Error::Uzip(format!("uzip: lzma block decode failed: {e}")))?;
            writer.finish_exact("lzma")
        }
        UzipCompressor::Zstd => {
            let decoder: zstd::stream::read::Decoder<'_, std::io::BufReader<&[u8]>> =
                zstd::stream::read::Decoder::new(block)
                    .map_err(|e| Error::Uzip(format!("uzip: zstd init failed: {e}")))?;
            read_block_to_exact(decoder, want, "zstd")
        }
    }
}

fn read_block_to_exact<R: Read>(reader: R, want: usize, label: &'static str) -> Result<Vec<u8>> {
    let limit: u64 = u64::try_from(want)
        .map_err(|_| Error::Uzip(format!("uzip: {label} block size overflow")))?
        .checked_add(1)
        .ok_or_else(|| Error::Uzip(format!("uzip: {label} block read limit overflow")))?;
    let capacity: usize = want.min(MAX_UZIP_PREALLOC);
    let mut out: Vec<u8> = Vec::with_capacity(capacity);
    let mut limited: std::io::Take<R> = reader.take(limit);
    limited
        .read_to_end(&mut out)
        .map_err(|e| Error::Uzip(format!("uzip: {label} block decode failed: {e}")))?;
    if out.len() != want {
        return Err(Error::Uzip(format!(
            "uzip: {label} block decoded to {} bytes, expected {want}",
            out.len()
        )));
    }
    Ok(out)
}

struct BoundedVecWriter {
    out: Vec<u8>,
    cap: usize,
}

impl BoundedVecWriter {
    fn new(cap: usize) -> Self {
        Self {
            out: Vec::with_capacity(cap.min(MAX_UZIP_PREALLOC)),
            cap,
        }
    }

    fn finish_exact(self, label: &'static str) -> Result<Vec<u8>> {
        if self.out.len() != self.cap {
            return Err(Error::Uzip(format!(
                "uzip: {label} block decoded to {} bytes, expected {}",
                self.out.len(),
                self.cap
            )));
        }
        Ok(self.out)
    }
}

impl Write for BoundedVecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let remaining: usize = self.cap.saturating_sub(self.out.len());
        if buf.len() > remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "uzip block exceeds declared size",
            ));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn read_be_u32(bytes: &[u8], at: usize) -> Result<u32> {
    let s: &[u8] = bytes
        .get(at..at + 4)
        .ok_or_else(|| Error::Uzip("uzip: truncated u32".to_owned()))?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_be_u64(bytes: &[u8], at: usize) -> Result<u64> {
    let s: &[u8] = bytes
        .get(at..at + 8)
        .ok_or_else(|| Error::Uzip("uzip: truncated u64".to_owned()))?;
    Ok(u64::from_be_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

fn toc_overflow() -> Error {
    Error::Uzip("uzip: TOC size overflow".to_owned())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn zlib_block(payload: &[u8]) -> Vec<u8> {
        let mut enc: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(payload).expect("zlib write");
        enc.finish().expect("zlib finish")
    }

    fn build_cloop_zlib(block_size: u32, blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut magic: Vec<u8> = vec![0u8; MAGIC_LEN];
        magic[..MAGIC_START.len()].copy_from_slice(MAGIC_START);
        magic[OFS_COMPR] = COMP_LIBZ;
        magic[OFS_VERSN] = b'2';
        let compressed: Vec<Vec<u8>> = blocks.iter().map(|b| zlib_block(b)).collect();
        let nblocks: u32 = compressed.len() as u32;
        let toc_start: u64 = (MAGIC_LEN + 8 + (compressed.len() + 1) * 8) as u64;
        let mut offsets: Vec<u64> = Vec::with_capacity(compressed.len() + 1);
        let mut cursor: u64 = toc_start;
        for c in &compressed {
            offsets.push(cursor);
            cursor += c.len() as u64;
        }
        offsets.push(cursor);
        let mut out: Vec<u8> = magic;
        out.extend_from_slice(&block_size.to_be_bytes());
        out.extend_from_slice(&nblocks.to_be_bytes());
        for off in &offsets {
            out.extend_from_slice(&off.to_be_bytes());
        }
        for c in &compressed {
            out.extend_from_slice(c);
        }
        out
    }

    #[test]
    fn detect_recognizes_cloop_v2() {
        let img: Vec<u8> = build_cloop_zlib(16, &[vec![0xAAu8; 16]]);
        assert!(detect_uzip(&img));
        assert!(!detect_uzip(b"#!/bin/sh\n echo not uzip"));
    }

    #[test]
    fn reconstructs_zlib_blocks_byte_exact() {
        let block_size: u32 = 32;
        let mut b0: Vec<u8> = b"FreeBSD UZIP block zero contents".to_vec();
        b0.resize(block_size as usize, 0);
        let mut b1: Vec<u8> = b"second cloop block, distinct bytes".to_vec();
        b1.resize(block_size as usize, 0);
        let img: Vec<u8> = build_cloop_zlib(block_size, &[b0.clone(), b1.clone()]);
        let parsed: UzipImage = parse_uzip(&img, 1 << 20).expect("parse uzip");
        assert_eq!(parsed.compressor, UzipCompressor::Zlib);
        assert_eq!(parsed.block_size, block_size);
        assert_eq!(parsed.block_count, 2);
        let mut want: Vec<u8> = b0;
        want.extend_from_slice(&b1);
        assert_eq!(parsed.image, want);
    }

    #[test]
    fn rejects_block_that_inflates_past_declared_size() {
        let img: Vec<u8> = build_cloop_zlib(4, &[b"ABCDE".to_vec()]);
        let err: Error = parse_uzip(&img, 1 << 20).expect_err("oversized block must reject");
        assert!(matches!(err, Error::Uzip(message) if message.contains("decoded")));
    }
}
