use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::quota::bounded_prealloc;

pub const SPARSE_MAGIC: u32 = 0xed26_ff3a;
const SPARSE_HEADER_LEN: usize = 28;
const CHUNK_HEADER_LEN: usize = 12;

const CHUNK_TYPE_RAW: u16 = 0xCAC1;
const CHUNK_TYPE_FILL: u16 = 0xCAC2;
const CHUNK_TYPE_DONT_CARE: u16 = 0xCAC3;
const CHUNK_TYPE_CRC32: u16 = 0xCAC4;

const MAX_RAW_IMAGE: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseHeader {
    pub major_version: u16,
    pub minor_version: u16,
    pub file_hdr_sz: u16,
    pub chunk_hdr_sz: u16,
    pub block_size: u32,
    pub total_blocks: u32,
    pub total_chunks: u32,
    pub image_checksum: u32,
}

fn rd_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn rd_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[must_use]
pub fn detect_sparse(bytes: &[u8]) -> Option<SparseHeader> {
    if bytes.len() < SPARSE_HEADER_LEN {
        return None;
    }
    if rd_u32(bytes, 0) != SPARSE_MAGIC {
        return None;
    }
    let major_version: u16 = rd_u16(bytes, 4);
    if major_version != 1 {
        return None;
    }
    Some(SparseHeader {
        major_version,
        minor_version: rd_u16(bytes, 6),
        file_hdr_sz: rd_u16(bytes, 8),
        chunk_hdr_sz: rd_u16(bytes, 10),
        block_size: rd_u32(bytes, 12),
        total_blocks: rd_u32(bytes, 16),
        total_chunks: rd_u32(bytes, 20),
        image_checksum: rd_u32(bytes, 24),
    })
}

pub fn unsparse(bytes: &[u8], max_total: u64) -> Result<Vec<u8>> {
    let header: SparseHeader = detect_sparse(bytes)
        .ok_or_else(|| Error::Sparse("android sparse magic 0xed26ff3a not found".to_owned()))?;
    let block_size: usize = usize::try_from(header.block_size)
        .map_err(|_| Error::Sparse("block size overflows usize".to_owned()))?;
    if block_size == 0 || !block_size.is_multiple_of(4) {
        return Err(Error::Sparse(format!(
            "invalid block size {block_size} (must be a non-zero multiple of 4)"
        )));
    }
    let expected_total: u64 = u64::from(header.total_blocks) * u64::from(header.block_size);
    let ceiling: u64 = max_total.min(MAX_RAW_IMAGE);
    if expected_total > ceiling {
        return Err(Error::Sparse(format!(
            "raw image would be {expected_total} bytes, exceeds the {ceiling} byte budget"
        )));
    }
    let declared_file_hdr_sz: usize = usize::from(header.file_hdr_sz);
    let file_hdr_sz: usize = if declared_file_hdr_sz >= SPARSE_HEADER_LEN {
        declared_file_hdr_sz
    } else {
        SPARSE_HEADER_LEN
    };
    let declared_chunk_hdr_sz: usize = usize::from(header.chunk_hdr_sz);
    let chunk_hdr_sz: usize = if declared_chunk_hdr_sz >= CHUNK_HEADER_LEN {
        declared_chunk_hdr_sz
    } else {
        CHUNK_HEADER_LEN
    };

    let mut out: Vec<u8> = Vec::with_capacity(bounded_prealloc(expected_total));
    let mut pos: usize = file_hdr_sz;
    for chunk_index in 0..header.total_chunks {
        let fixed_header_end: usize = pos
            .checked_add(CHUNK_HEADER_LEN)
            .ok_or_else(|| Error::Sparse("chunk fixed header offset overflow".to_owned()))?;
        let hdr: &[u8] = bytes.get(pos..fixed_header_end).ok_or_else(|| {
            Error::Sparse(format!("chunk {chunk_index} header at {pos} out of bounds"))
        })?;
        let chunk_type: u16 = rd_u16(hdr, 0);
        let chunk_blocks: u32 = rd_u32(hdr, 4);
        let total_sz: u32 = rd_u32(hdr, 8);
        let payload_start: usize = pos
            .checked_add(chunk_hdr_sz)
            .ok_or_else(|| Error::Sparse("chunk header offset overflow".to_owned()))?;
        let total_sz_usize: usize = usize::try_from(total_sz)
            .map_err(|_| Error::Sparse("chunk size overflows usize".to_owned()))?;
        if total_sz_usize < chunk_hdr_sz {
            return Err(Error::Sparse(format!(
                "chunk {chunk_index} total size {total_sz_usize} smaller than header {chunk_hdr_sz}"
            )));
        }
        let payload_len: usize = total_sz_usize - chunk_hdr_sz;
        let out_len_u64: u64 = u64::from(chunk_blocks)
            .checked_mul(u64::from(header.block_size))
            .ok_or_else(|| Error::Sparse("chunk output length overflow".to_owned()))?;
        let out_len: usize = usize::try_from(out_len_u64)
            .map_err(|_| Error::Sparse("chunk output length overflows usize".to_owned()))?;
        let new_out_len: u64 = u64::try_from(out.len())
            .map_err(|_| Error::Sparse("expanded output length overflows u64".to_owned()))?
            .checked_add(out_len_u64)
            .ok_or_else(|| Error::Sparse("expanded output length overflow".to_owned()))?;
        if new_out_len > MAX_RAW_IMAGE || new_out_len > expected_total {
            return Err(Error::Sparse(format!(
                "expanded output {new_out_len} exceeds declared total {expected_total}"
            )));
        }
        match chunk_type {
            CHUNK_TYPE_RAW => {
                let data: &[u8] = bytes
                    .get(payload_start..payload_start + payload_len)
                    .ok_or_else(|| {
                        Error::Sparse(format!("raw chunk {chunk_index} payload out of bounds"))
                    })?;
                if data.len() != out_len {
                    return Err(Error::Sparse(format!(
                        "raw chunk {chunk_index} payload {} != expected {out_len}",
                        data.len()
                    )));
                }
                out.extend_from_slice(data);
            }
            CHUNK_TYPE_FILL => {
                let fill: &[u8] = bytes.get(payload_start..payload_start + 4).ok_or_else(|| {
                    Error::Sparse(format!("fill chunk {chunk_index} value out of bounds"))
                })?;
                let pattern: [u8; 4] = [fill[0], fill[1], fill[2], fill[3]];
                let words: usize = out_len / 4;
                out.reserve(out_len);
                for _ in 0..words {
                    out.extend_from_slice(&pattern);
                }
            }
            CHUNK_TYPE_DONT_CARE => {
                out.extend(std::iter::repeat_n(0u8, out_len));
            }
            CHUNK_TYPE_CRC32 => {}
            other => {
                return Err(Error::Sparse(format!(
                    "chunk {chunk_index} has unknown type 0x{other:04x}"
                )));
            }
        }
        pos = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| Error::Sparse("chunk cursor overflow".to_owned()))?;
    }
    let observed_total: u64 = u64::try_from(out.len())
        .map_err(|_| Error::Sparse("expanded output length overflows u64".to_owned()))?;
    if observed_total != expected_total {
        return Err(Error::Sparse(format!(
            "expanded output {observed_total} does not match declared total {expected_total}"
        )));
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const BLOCK: usize = 4096;

    #[test]
    fn a_tiny_image_declaring_a_huge_total_is_refused_against_the_caller_budget() {
        const DECLARED_BLOCKS: u32 = 262_144;
        const CALLER_BUDGET: u64 = 64 * 1024 * 1024;
        let declared_total: u64 = u64::from(DECLARED_BLOCKS) * BLOCK as u64;
        assert!(
            declared_total < MAX_RAW_IMAGE && declared_total > CALLER_BUDGET,
            "the declared total must sit under the private cap and over the caller budget, \
             otherwise the private cap alone would refuse it and this test proves nothing"
        );
        let mut img: Vec<u8> = Vec::new();
        write_sparse_header(&mut img, DECLARED_BLOCKS, 1);
        img.extend_from_slice(&CHUNK_TYPE_DONT_CARE.to_le_bytes());
        img.extend_from_slice(&0u16.to_le_bytes());
        img.extend_from_slice(&DECLARED_BLOCKS.to_le_bytes());
        img.extend_from_slice(&(CHUNK_HEADER_LEN as u32).to_le_bytes());
        assert!(
            img.len() < 128,
            "the point of this test is that a tiny input drives the allocation, got {}",
            img.len()
        );
        let error: Error = unsparse(&img, 64 * 1024 * 1024)
            .expect_err("a declared total past the caller budget must be refused");
        let text: String = format!("{error}");
        assert!(
            text.contains("budget"),
            "the refusal must name the budget it exceeded, got {text}"
        );
    }

    fn write_sparse_header(out: &mut Vec<u8>, total_blocks: u32, total_chunks: u32) {
        out.extend_from_slice(&SPARSE_MAGIC.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(SPARSE_HEADER_LEN as u16).to_le_bytes());
        out.extend_from_slice(&(CHUNK_HEADER_LEN as u16).to_le_bytes());
        out.extend_from_slice(&(BLOCK as u32).to_le_bytes());
        out.extend_from_slice(&total_blocks.to_le_bytes());
        out.extend_from_slice(&total_chunks.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
    }

    fn chunk_raw(out: &mut Vec<u8>, blocks: u32, data: &[u8]) {
        out.extend_from_slice(&CHUNK_TYPE_RAW.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&blocks.to_le_bytes());
        out.extend_from_slice(&((CHUNK_HEADER_LEN + data.len()) as u32).to_le_bytes());
        out.extend_from_slice(data);
    }

    fn chunk_fill(out: &mut Vec<u8>, blocks: u32, pattern: [u8; 4]) {
        out.extend_from_slice(&CHUNK_TYPE_FILL.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&blocks.to_le_bytes());
        out.extend_from_slice(&((CHUNK_HEADER_LEN + 4) as u32).to_le_bytes());
        out.extend_from_slice(&pattern);
    }

    fn chunk_dont_care(out: &mut Vec<u8>, blocks: u32) {
        out.extend_from_slice(&CHUNK_TYPE_DONT_CARE.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&blocks.to_le_bytes());
        out.extend_from_slice(&(CHUNK_HEADER_LEN as u32).to_le_bytes());
    }

    fn build_reference_raw() -> Vec<u8> {
        let mut raw: Vec<u8> = Vec::new();
        raw.extend((0..BLOCK).map(|i| (i % 256) as u8));
        raw.extend(std::iter::repeat_n(0xABu8, BLOCK));
        raw.extend(std::iter::repeat_n(0x00u8, BLOCK));
        raw.extend((0..BLOCK).map(|i| ((i * 7) % 256) as u8));
        raw
    }

    #[test]
    fn detects_sparse_magic() {
        let mut img: Vec<u8> = Vec::new();
        write_sparse_header(&mut img, 4, 0);
        let header: SparseHeader = detect_sparse(&img).expect("sparse header");
        assert_eq!(header.block_size, BLOCK as u32);
        assert_eq!(header.total_blocks, 4);
    }

    #[test]
    fn rejects_non_sparse() {
        assert!(detect_sparse(&[0u8; 64]).is_none());
        assert!(detect_sparse(&[0u8; 4]).is_none());
    }

    #[test]
    fn unsparse_reconstructs_reference_raw_byte_exact() {
        let raw: Vec<u8> = build_reference_raw();
        let block0: &[u8] = &raw[0..BLOCK];
        let block3: &[u8] = &raw[3 * BLOCK..4 * BLOCK];

        let mut img: Vec<u8> = Vec::new();
        write_sparse_header(&mut img, 4, 4);
        chunk_raw(&mut img, 1, block0);
        chunk_fill(&mut img, 1, [0xAB, 0xAB, 0xAB, 0xAB]);
        chunk_dont_care(&mut img, 1);
        chunk_raw(&mut img, 1, block3);

        let recovered: Vec<u8> = unsparse(&img, u64::MAX).expect("unsparse");
        assert_eq!(recovered.len(), raw.len());
        assert_eq!(recovered, raw);
    }

    #[test]
    fn unsparse_then_detect_inner_ext4() {
        let mut inner: Vec<u8> = vec![0u8; 2 * BLOCK];
        inner[0x438] = 0x53;
        inner[0x439] = 0xEF;
        let mut img: Vec<u8> = Vec::new();
        write_sparse_header(&mut img, 2, 1);
        chunk_raw(&mut img, 2, &inner);
        let recovered: Vec<u8> = unsparse(&img, u64::MAX).expect("unsparse");
        assert_eq!(recovered, inner);
        assert_eq!(recovered[0x438], 0x53);
        assert_eq!(recovered[0x439], 0xEF);
    }

    #[test]
    fn extract_to_writes_unsparsed_image() {
        let raw: Vec<u8> = build_reference_raw();
        let mut img: Vec<u8> = Vec::new();
        write_sparse_header(&mut img, 4, 1);
        chunk_raw(&mut img, 4, &raw);
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-sparse-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::AndroidSparse, &img, &dir)
                .expect("sparse extract");
        assert_eq!(result.kind, crate::container::ContainerKind::AndroidSparse);
        let written: Vec<u8> = std::fs::read(dir.join("unsparse.img")).expect("raw image");
        assert_eq!(written, raw);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_chunk_output_beyond_declared_total() {
        let mut img: Vec<u8> = Vec::new();
        write_sparse_header(&mut img, 1, 1);
        chunk_dont_care(&mut img, 2);
        let err: Error =
            unsparse(&img, u64::MAX).expect_err("chunk output must not outrun total_blocks");
        assert!(matches!(err, Error::Sparse(message) if message.contains("declared total")));
    }
}
