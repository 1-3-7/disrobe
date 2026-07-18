use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const EROFS_SUPER_OFFSET: usize = 1024;
const EROFS_MAGIC: u32 = 0xE0F5_E1E2;
const EROFS_ISLOTBITS: u32 = 5;

const EROFS_INODE_FLAT_PLAIN: u16 = 0;
const EROFS_INODE_COMPRESSED_FULL: u16 = 1;
const EROFS_INODE_FLAT_INLINE: u16 = 2;
const EROFS_INODE_COMPRESSED_COMPACT: u16 = 3;
const EROFS_INODE_CHUNK_BASED: u16 = 4;

const EROFS_INODE_LAYOUT_COMPACT: u16 = 0;
const EROFS_INODE_LAYOUT_EXTENDED: u16 = 1;

const S_IFMT: u16 = 0o170_000;
const S_IFREG: u16 = 0o100_000;
const S_IFDIR: u16 = 0o040_000;
const S_IFLNK: u16 = 0o120_000;

const MAX_FILES: usize = 500_000;
const MAX_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErofsSuperblock {
    pub blkszbits: u8,
    pub block_size: u32,
    pub root_nid: u16,
    pub inos: u64,
    pub meta_blkaddr: u32,
}

#[derive(Debug, Clone)]
pub struct ErofsFile {
    pub path: String,
    pub data: Vec<u8>,
    pub is_executable: bool,
    pub is_symlink: bool,
}

#[derive(Debug, Clone)]
pub struct ErofsWalk {
    pub superblock: ErofsSuperblock,
    pub files: Vec<ErofsFile>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct ErofsInode {
    format: u16,
    mode: u16,
    size: u64,
    raw_blkaddr: u32,
    inode_slot_end: usize,
}

fn rd_u16(b: &[u8], at: usize) -> Option<u16> {
    disrobe_bytes::read_u16_le_at(b, at).ok()
}

fn rd_u32(b: &[u8], at: usize) -> Option<u32> {
    disrobe_bytes::read_u32_le_at(b, at).ok()
}

fn rd_u64(b: &[u8], at: usize) -> Option<u64> {
    disrobe_bytes::read_u64_le_at(b, at).ok()
}

#[must_use]
pub fn detect_erofs(bytes: &[u8]) -> Option<ErofsSuperblock> {
    if bytes.len() < EROFS_SUPER_OFFSET + 128 {
        return None;
    }
    if rd_u32(bytes, EROFS_SUPER_OFFSET)? != EROFS_MAGIC {
        return None;
    }
    let blkszbits: u8 = bytes[EROFS_SUPER_OFFSET + 12];
    if !(9..=16).contains(&blkszbits) {
        return None;
    }
    let root_nid: u16 = rd_u16(bytes, EROFS_SUPER_OFFSET + 16)?;
    let inos: u64 = rd_u64(bytes, EROFS_SUPER_OFFSET + 24)?;
    let meta_blkaddr: u32 = rd_u32(bytes, EROFS_SUPER_OFFSET + 36)?;
    Some(ErofsSuperblock {
        blkszbits,
        block_size: 1u32 << blkszbits,
        root_nid,
        inos,
        meta_blkaddr,
    })
}

const fn inode_offset(sb: &ErofsSuperblock, nid: u64) -> usize {
    let meta_base: usize = sb.meta_blkaddr as usize * sb.block_size as usize;
    meta_base + (nid as usize) * (1usize << EROFS_ISLOTBITS)
}

fn read_inode(bytes: &[u8], sb: &ErofsSuperblock, nid: u64) -> Result<ErofsInode> {
    let base: usize = inode_offset(sb, nid);
    let format: u16 = rd_u16(bytes, base)
        .ok_or_else(|| Error::Erofs(format!("inode nid {nid} format out of bounds")))?;
    let layout: u16 = (format >> 1) & 0x7;
    let version: u16 = format & 0x1;
    match version {
        EROFS_INODE_LAYOUT_EXTENDED => {
            let mode: u16 = rd_u16(bytes, base + 8)
                .ok_or_else(|| Error::Erofs("extended inode mode oob".to_owned()))?;
            let size: u64 = rd_u64(bytes, base + 16)
                .ok_or_else(|| Error::Erofs("extended inode size oob".to_owned()))?;
            let raw_blkaddr: u32 = rd_u32(bytes, base + 28)
                .ok_or_else(|| Error::Erofs("extended inode blkaddr oob".to_owned()))?;
            Ok(ErofsInode {
                format: layout,
                mode,
                size,
                raw_blkaddr,
                inode_slot_end: base + 64,
            })
        }
        EROFS_INODE_LAYOUT_COMPACT => {
            let mode: u16 = rd_u16(bytes, base + 4)
                .ok_or_else(|| Error::Erofs("compact inode mode oob".to_owned()))?;
            let size: u64 = u64::from(
                rd_u32(bytes, base + 8)
                    .ok_or_else(|| Error::Erofs("compact inode size oob".to_owned()))?,
            );
            let raw_blkaddr: u32 = rd_u32(bytes, base + 16)
                .ok_or_else(|| Error::Erofs("compact inode blkaddr oob".to_owned()))?;
            Ok(ErofsInode {
                format: layout,
                mode,
                size,
                raw_blkaddr,
                inode_slot_end: base + 32,
            })
        }
        other => Err(Error::Erofs(format!(
            "inode nid {nid} unknown version {other}"
        ))),
    }
}

fn inode_data(
    bytes: &[u8],
    sb: &ErofsSuperblock,
    inode: &ErofsInode,
    notes: &mut Vec<String>,
    path: &str,
) -> Result<Vec<u8>> {
    let size: usize = inode.size as usize;
    if size == 0 {
        return Ok(Vec::new());
    }
    match inode.format {
        EROFS_INODE_FLAT_PLAIN => {
            let start: usize = inode.raw_blkaddr as usize * sb.block_size as usize;
            let slice: &[u8] = bytes
                .get(start..start + size)
                .ok_or_else(|| Error::Erofs(format!("flat-plain data for `{path}` oob")))?;
            Ok(slice.to_vec())
        }
        EROFS_INODE_FLAT_INLINE => {
            let block_size: usize = sb.block_size as usize;
            let tail_len: usize = size % block_size;
            let head_blocks: usize = size / block_size;
            let mut out: Vec<u8> = Vec::with_capacity(size.min(bytes.len()));
            let block_start: usize = inode.raw_blkaddr as usize * block_size;
            for i in 0..head_blocks {
                let s: usize = block_start + i * block_size;
                let slice: &[u8] = bytes
                    .get(s..s + block_size)
                    .ok_or_else(|| Error::Erofs(format!("flat-inline block for `{path}` oob")))?;
                out.extend_from_slice(slice);
            }
            if tail_len > 0 {
                let inline_start: usize = align_up(inode.inode_slot_end, 1);
                let slice: &[u8] = bytes
                    .get(inline_start..inline_start + tail_len)
                    .ok_or_else(|| Error::Erofs(format!("flat-inline tail for `{path}` oob")))?;
                out.extend_from_slice(slice);
            }
            Ok(out)
        }
        EROFS_INODE_COMPRESSED_FULL => compressed_full_data(bytes, sb, inode, notes, path),
        EROFS_INODE_COMPRESSED_COMPACT => Err(Error::Erofs(format!(
            "erofs `{path}` uses the compact (2/4-byte packed) compression index, which is not decoded in-tree"
        ))),
        EROFS_INODE_CHUNK_BASED => chunk_based_data(bytes, sb, inode, path),
        other => Err(Error::Erofs(format!(
            "inode `{path}` has unknown data layout {other}"
        ))),
    }
}

const EROFS_CHUNK_FORMAT_BLKBITS_MASK: u16 = 0x001f;
const EROFS_CHUNK_FORMAT_INDEXES: u16 = 0x0020;
const EROFS_NULL_ADDR: u32 = 0xFFFF_FFFF;

fn chunk_based_data(
    bytes: &[u8],
    sb: &ErofsSuperblock,
    inode: &ErofsInode,
    path: &str,
) -> Result<Vec<u8>> {
    let size: usize = inode.size as usize;
    let block_size: usize = sb.block_size as usize;
    let chunk_format: u16 = (inode.raw_blkaddr & 0xFFFF) as u16;
    let chunkbits: u32 =
        sb.blkszbits as u32 + u32::from(chunk_format & EROFS_CHUNK_FORMAT_BLKBITS_MASK);
    let chunk_size: usize = 1usize << chunkbits;
    let is_indexes: bool = chunk_format & EROFS_CHUNK_FORMAT_INDEXES != 0;
    let chunk_count: usize = size.div_ceil(chunk_size);
    let entry_size: usize = if is_indexes { 8 } else { 4 };
    let table_start: usize = inode.inode_slot_end;
    let mut out: Vec<u8> = Vec::with_capacity(size.min(bytes.len()));
    for index in 0..chunk_count {
        let entry_off: usize = table_start + index * entry_size;
        let blkaddr: u32 = if is_indexes {
            rd_u32(bytes, entry_off + 4)
                .ok_or_else(|| Error::Erofs(format!("chunk index for `{path}` oob")))?
        } else {
            rd_u32(bytes, entry_off)
                .ok_or_else(|| Error::Erofs(format!("chunk addr for `{path}` oob")))?
        };
        let this_chunk: usize = chunk_size.min(size - out.len());
        if blkaddr == EROFS_NULL_ADDR {
            out.extend(std::iter::repeat_n(0u8, this_chunk));
        } else {
            let start: usize = blkaddr as usize * block_size;
            let slice: &[u8] = bytes
                .get(start..start + this_chunk)
                .ok_or_else(|| Error::Erofs(format!("chunk data for `{path}` oob")))?;
            out.extend_from_slice(slice);
        }
    }
    out.truncate(size);
    Ok(out)
}

const Z_EROFS_ALGO_LZ4: u8 = 0;
const Z_EROFS_ALGO_LZMA: u8 = 1;
const Z_EROFS_ALGO_DEFLATE: u8 = 2;
const Z_EROFS_ALGO_ZSTD: u8 = 3;

const Z_EROFS_LCLUSTER_TYPE_PLAIN: u16 = 0;
const Z_EROFS_LCLUSTER_TYPE_NONHEAD: u16 = 2;

fn compressed_full_data(
    bytes: &[u8],
    sb: &ErofsSuperblock,
    inode: &ErofsInode,
    notes: &mut Vec<String>,
    path: &str,
) -> Result<Vec<u8>> {
    let header_off: usize = inode.inode_slot_end;
    let advise: u16 =
        rd_u16(bytes, header_off + 4).ok_or_else(|| Error::Erofs("z map header oob".to_owned()))?;
    let algo_byte: u8 = *bytes
        .get(header_off + 6)
        .ok_or_else(|| Error::Erofs("z map algorithm oob".to_owned()))?;
    let clusterbits_byte: u8 = *bytes
        .get(header_off + 7)
        .ok_or_else(|| Error::Erofs("z map clusterbits oob".to_owned()))?;
    let algorithm: u8 = algo_byte & 0x0f;
    let _ = advise;
    let lclusterbits: u32 = sb.blkszbits as u32 + u32::from(clusterbits_byte & 0x0f);
    let lcluster_size: usize = 1usize << lclusterbits;
    let block_size: usize = sb.block_size as usize;
    let size: usize = inode.size as usize;
    let index_base: usize = header_off + 8;
    let lcluster_count: usize = size.div_ceil(lcluster_size);

    let mut out: Vec<u8> = Vec::with_capacity(size.min(bytes.len()));
    let mut logical: usize = 0;
    while logical < lcluster_count {
        let entry_off: usize = index_base + logical * 8;
        let di_advise: u16 = rd_u16(bytes, entry_off)
            .ok_or_else(|| Error::Erofs(format!("lcluster advise for `{path}` oob")))?;
        let lcluster_type: u16 = di_advise & 0x3;
        if lcluster_type == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
            logical += 1;
            continue;
        }
        let blkaddr: u32 = rd_u32(bytes, entry_off + 4)
            .ok_or_else(|| Error::Erofs(format!("lcluster blkaddr for `{path}` oob")))?;
        let mut span: usize = 1;
        while logical + span < lcluster_count {
            let next_off: usize = index_base + (logical + span) * 8;
            let next_advise: u16 = rd_u16(bytes, next_off)
                .ok_or_else(|| Error::Erofs(format!("lcluster scan for `{path}` oob")))?;
            if next_advise & 0x3 == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                span += 1;
            } else {
                break;
            }
        }
        let logical_remaining: usize = size - out.len();
        let want: usize = (span * lcluster_size).min(logical_remaining);
        let pcluster_start: usize = blkaddr as usize * block_size;
        if lcluster_type == Z_EROFS_LCLUSTER_TYPE_PLAIN {
            let slice: &[u8] = bytes
                .get(pcluster_start..pcluster_start + want)
                .ok_or_else(|| Error::Erofs(format!("plain pcluster for `{path}` oob")))?;
            out.extend_from_slice(slice);
        } else {
            let pcluster_len: usize =
                (span * lcluster_size).min(bytes.len().saturating_sub(pcluster_start));
            let comp: &[u8] = bytes
                .get(pcluster_start..pcluster_start + pcluster_len)
                .ok_or_else(|| Error::Erofs(format!("compressed pcluster for `{path}` oob")))?;
            let decoded: Vec<u8> = decode_pcluster(algorithm, comp, want, path)?;
            out.extend_from_slice(&decoded[..want.min(decoded.len())]);
        }
        logical += span;
    }
    if out.len() < size {
        notes.push(format!(
            "erofs `{path}`: decoded {} of {size} bytes from the full compression index",
            out.len()
        ));
    }
    out.truncate(size);
    Ok(out)
}

fn decode_pcluster(algorithm: u8, comp: &[u8], want: usize, path: &str) -> Result<Vec<u8>> {
    match algorithm {
        Z_EROFS_ALGO_LZ4 => crate::containers::lz4_block::decompress_stop_at(comp, want),
        Z_EROFS_ALGO_DEFLATE => decode_deflate(comp, want),
        Z_EROFS_ALGO_ZSTD => decode_zstd(comp, want, path),
        Z_EROFS_ALGO_LZMA => Err(Error::Erofs(format!(
            "erofs `{path}` uses microlzma physical clusters, which need a microlzma decoder not exposed by the in-tree xz binding"
        ))),
        other => Err(Error::Erofs(format!(
            "erofs `{path}` unknown compression algorithm {other}"
        ))),
    }
}

fn decode_deflate(comp: &[u8], want: usize) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let decoder: flate2::read::DeflateDecoder<&[u8]> = flate2::read::DeflateDecoder::new(comp);
    let mut out: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(want as u64));
    decoder
        .take(want as u64)
        .read_to_end(&mut out)
        .map_err(|e| Error::Erofs(format!("erofs deflate pcluster: {e}")))?;
    Ok(out)
}

fn decode_zstd(comp: &[u8], want: usize, path: &str) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let mut out: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(want as u64));
    let decoder: zstd::stream::read::Decoder<'static, std::io::BufReader<&[u8]>> =
        zstd::stream::read::Decoder::new(comp)
            .map_err(|e: std::io::Error| Error::Erofs(format!("erofs `{path}` zstd init: {e}")))?;
    decoder
        .take(want as u64)
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| Error::Erofs(format!("erofs `{path}` zstd pcluster: {e}")))?;
    Ok(out)
}

const fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        return value;
    }
    value.div_ceil(align) * align
}

fn read_directory(
    bytes: &[u8],
    sb: &ErofsSuperblock,
    inode: &ErofsInode,
    notes: &mut Vec<String>,
    path: &str,
) -> Result<Vec<(u64, String, u8)>> {
    let dir_data: Vec<u8> = inode_data(bytes, sb, inode, notes, path)?;
    let block_size: usize = sb.block_size as usize;
    let mut entries: Vec<(u64, String, u8)> = Vec::new();
    let mut block_off: usize = 0;
    while block_off < dir_data.len() {
        let block_end: usize = (block_off + block_size).min(dir_data.len());
        let block: &[u8] = &dir_data[block_off..block_end];
        parse_dir_block(block, &mut entries);
        block_off += block_size;
    }
    Ok(entries)
}

fn parse_dir_block(block: &[u8], entries: &mut Vec<(u64, String, u8)>) {
    if block.len() < 12 {
        return;
    }
    let first_nameoff: usize = u16::from_le_bytes([block[8], block[9]]) as usize;
    if first_nameoff < 12 || first_nameoff > block.len() {
        return;
    }
    let count: usize = first_nameoff / 12;
    for i in 0..count {
        let rec: usize = i * 12;
        let nid: u64 = u64::from_le_bytes([
            block[rec],
            block[rec + 1],
            block[rec + 2],
            block[rec + 3],
            block[rec + 4],
            block[rec + 5],
            block[rec + 6],
            block[rec + 7],
        ]);
        let nameoff: usize = u16::from_le_bytes([block[rec + 8], block[rec + 9]]) as usize;
        let file_type: u8 = block[rec + 10];
        let name_end: usize = if i + 1 < count {
            u16::from_le_bytes([block[rec + 12 + 8], block[rec + 12 + 9]]) as usize
        } else {
            block
                .iter()
                .skip(nameoff)
                .position(|&b| b == 0)
                .map_or(block.len(), |z| nameoff + z)
        };
        if nameoff > block.len() || name_end > block.len() || nameoff > name_end {
            continue;
        }
        let name: String = String::from_utf8_lossy(&block[nameoff..name_end]).into_owned();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        entries.push((nid, name, file_type));
    }
}

pub fn walk_erofs(bytes: &[u8], max_total: u64) -> Result<ErofsWalk> {
    let sb: ErofsSuperblock = detect_erofs(bytes)
        .ok_or_else(|| Error::Erofs("erofs superblock magic not found".to_owned()))?;
    let mut notes: Vec<String> = Vec::new();
    let mut files: Vec<ErofsFile> = Vec::new();
    let mut total: u64 = 0;
    let mut stack: Vec<(u64, String, usize)> = vec![(u64::from(sb.root_nid), String::new(), 0)];
    let mut visited: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    while let Some((nid, prefix, depth)) = stack.pop() {
        if depth > MAX_DEPTH || files.len() > MAX_FILES || !visited.insert(nid) {
            continue;
        }
        let inode: ErofsInode = read_inode(bytes, &sb, nid)?;
        let kind: u16 = inode.mode & S_IFMT;
        if kind == S_IFDIR {
            let entries: Vec<(u64, String, u8)> =
                read_directory(bytes, &sb, &inode, &mut notes, &prefix)?;
            for (child_nid, name, _ft) in entries.into_iter().rev() {
                let child_path: String = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                stack.push((child_nid, child_path, depth + 1));
            }
        } else if kind == S_IFREG {
            let data: Vec<u8> = inode_data(bytes, &sb, &inode, &mut notes, &prefix)?;
            total = total.saturating_add(data.len() as u64);
            if total > max_total {
                return Err(Error::Erofs(format!("walk exceeds total cap {max_total}")));
            }
            files.push(ErofsFile {
                path: prefix,
                is_executable: inode.mode & 0o111 != 0,
                data,
                is_symlink: false,
            });
        } else if kind == S_IFLNK {
            let data: Vec<u8> = inode_data(bytes, &sb, &inode, &mut notes, &prefix)?;
            files.push(ErofsFile {
                path: prefix,
                data,
                is_executable: false,
                is_symlink: true,
            });
        }
    }
    Ok(ErofsWalk {
        superblock: sb,
        files,
        notes,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const BLK_BITS: u8 = 12;
    const BLK: usize = 4096;
    const EROFS_FT_DIR: u8 = 2;

    struct ErofsBuilder {
        image: Vec<u8>,
        meta_block: usize,
        next_data_block: usize,
        next_nid: u64,
    }

    impl ErofsBuilder {
        fn new(total_blocks: usize, meta_block: usize, first_data_block: usize) -> Self {
            Self {
                image: vec![0u8; total_blocks * BLK],
                meta_block,
                next_data_block: first_data_block,
                next_nid: 0,
            }
        }

        fn meta_base(&self) -> usize {
            self.meta_block * BLK
        }

        fn alloc_data_block(&mut self, n: usize) -> u32 {
            let blk: usize = self.next_data_block;
            self.next_data_block += n;
            blk as u32
        }

        fn write_super(&mut self, root_nid: u16) {
            let base: usize = EROFS_SUPER_OFFSET;
            self.image[base..base + 4].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
            self.image[base + 12] = BLK_BITS;
            self.image[base + 16..base + 18].copy_from_slice(&root_nid.to_le_bytes());
            self.image[base + 24..base + 32].copy_from_slice(&8u64.to_le_bytes());
            self.image[base + 36..base + 40]
                .copy_from_slice(&(self.meta_block as u32).to_le_bytes());
        }

        fn write_compact_inode_flat_plain(&mut self, mode: u16, size: u32, blkaddr: u32) -> u64 {
            let nid: u64 = self.next_nid;
            let off: usize = self.meta_base() + (nid as usize) * 32;
            let format: u16 = (EROFS_INODE_FLAT_PLAIN << 1) | EROFS_INODE_LAYOUT_COMPACT;
            self.image[off..off + 2].copy_from_slice(&format.to_le_bytes());
            self.image[off + 4..off + 6].copy_from_slice(&mode.to_le_bytes());
            self.image[off + 8..off + 12].copy_from_slice(&size.to_le_bytes());
            self.image[off + 16..off + 20].copy_from_slice(&blkaddr.to_le_bytes());
            self.next_nid += 1;
            nid
        }

        fn write_compact_inode_inline(
            &mut self,
            mode: u16,
            size: u32,
            head_blkaddr: u32,
            tail: &[u8],
        ) -> u64 {
            let nid: u64 = self.next_nid;
            let off: usize = self.meta_base() + (nid as usize) * 32;
            let format: u16 = (EROFS_INODE_FLAT_INLINE << 1) | EROFS_INODE_LAYOUT_COMPACT;
            self.image[off..off + 2].copy_from_slice(&format.to_le_bytes());
            self.image[off + 4..off + 6].copy_from_slice(&mode.to_le_bytes());
            self.image[off + 8..off + 12].copy_from_slice(&size.to_le_bytes());
            self.image[off + 16..off + 20].copy_from_slice(&head_blkaddr.to_le_bytes());
            let inline_off: usize = off + 32;
            self.image[inline_off..inline_off + tail.len()].copy_from_slice(tail);
            self.next_nid += 1 + (tail.len().div_ceil(32)) as u64;
            nid
        }

        fn write_chunk_based_inode(
            &mut self,
            mode: u16,
            size: u32,
            chunk_format: u16,
            chunk_addrs: &[u32],
        ) -> u64 {
            let nid: u64 = self.next_nid;
            let off: usize = self.meta_base() + (nid as usize) * 32;
            let format: u16 = (EROFS_INODE_CHUNK_BASED << 1) | EROFS_INODE_LAYOUT_COMPACT;
            self.image[off..off + 2].copy_from_slice(&format.to_le_bytes());
            self.image[off + 4..off + 6].copy_from_slice(&mode.to_le_bytes());
            self.image[off + 8..off + 12].copy_from_slice(&size.to_le_bytes());
            self.image[off + 16..off + 18].copy_from_slice(&chunk_format.to_le_bytes());
            let inline_off: usize = off + 32;
            for (i, addr) in chunk_addrs.iter().enumerate() {
                let slot: usize = inline_off + i * 4;
                self.image[slot..slot + 4].copy_from_slice(&addr.to_le_bytes());
            }
            self.next_nid += 1 + (chunk_addrs.len() * 4).div_ceil(32) as u64;
            nid
        }

        fn write_compressed_full_inode(
            &mut self,
            mode: u16,
            size: u32,
            algorithm: u8,
            clusterbits_delta: u8,
            lclusters: &[(u16, u32)],
        ) -> u64 {
            let nid: u64 = self.next_nid;
            let off: usize = self.meta_base() + (nid as usize) * 32;
            let format: u16 = (EROFS_INODE_COMPRESSED_FULL << 1) | EROFS_INODE_LAYOUT_COMPACT;
            self.image[off..off + 2].copy_from_slice(&format.to_le_bytes());
            self.image[off + 4..off + 6].copy_from_slice(&mode.to_le_bytes());
            self.image[off + 8..off + 12].copy_from_slice(&size.to_le_bytes());
            let header_off: usize = off + 32;
            self.image[header_off + 6] = algorithm & 0x0f;
            self.image[header_off + 7] = clusterbits_delta & 0x0f;
            let index_off: usize = header_off + 8;
            for (i, (di_advise, blkaddr)) in lclusters.iter().enumerate() {
                let slot: usize = index_off + i * 8;
                self.image[slot..slot + 2].copy_from_slice(&di_advise.to_le_bytes());
                self.image[slot + 4..slot + 8].copy_from_slice(&blkaddr.to_le_bytes());
            }
            let inline_bytes: usize = 8 + lclusters.len() * 8;
            self.next_nid += 1 + inline_bytes.div_ceil(32) as u64;
            nid
        }

        fn put_block(&mut self, blkaddr: u32, data: &[u8]) {
            let off: usize = blkaddr as usize * BLK;
            self.image[off..off + data.len()].copy_from_slice(data);
        }

        fn put_dir_block(&mut self, blkaddr: u32, entries: &[(u64, &str, u8)]) {
            let mut names: Vec<u8> = Vec::new();
            let header_len: usize = entries.len() * 12;
            let mut name_offsets: Vec<u16> = Vec::new();
            for (_, name, _) in entries {
                name_offsets.push((header_len + names.len()) as u16);
                names.extend_from_slice(name.as_bytes());
            }
            let mut block: Vec<u8> = Vec::new();
            for (i, (nid, _, ft)) in entries.iter().enumerate() {
                block.extend_from_slice(&nid.to_le_bytes());
                block.extend_from_slice(&name_offsets[i].to_le_bytes());
                block.push(*ft);
                block.push(0);
            }
            block.extend_from_slice(&names);
            self.put_block(blkaddr, &block);
        }
    }

    fn build_reference_erofs() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let body_plain: Vec<u8> = (0..BLK as u32).map(|i| (i % 256) as u8).collect();
        let body_inline: Vec<u8> = b"erofs inline tail content byte exact 1234567890".to_vec();
        let nested: Vec<u8> = b"erofs nested directory file payload".to_vec();

        let mut b: ErofsBuilder = ErofsBuilder::new(16, 2, 6);

        let plain_blk: u32 = b.alloc_data_block(1);
        b.put_block(plain_blk, &body_plain);
        let inline_head: u32 = 0;

        let nested_blk: u32 = b.alloc_data_block(1);
        b.put_block(nested_blk, &nested);

        let root_dir_blk: u32 = b.alloc_data_block(1);
        let sub_dir_blk: u32 = b.alloc_data_block(1);

        let root_nid: u64 = b.write_compact_inode_inline(S_IFDIR | 0o755, 0, 0, &[]);
        let plain_nid: u64 =
            b.write_compact_inode_flat_plain(S_IFREG | 0o644, body_plain.len() as u32, plain_blk);
        let inline_nid: u64 = b.write_compact_inode_inline(
            S_IFREG | 0o755,
            body_inline.len() as u32,
            inline_head,
            &body_inline,
        );
        let sub_nid: u64 = b.write_compact_inode_inline(S_IFDIR | 0o755, 0, 0, &[]);
        let nested_nid: u64 =
            b.write_compact_inode_flat_plain(S_IFREG | 0o644, nested.len() as u32, nested_blk);

        let root_inode_off: usize = b.meta_base() + (root_nid as usize) * 32;
        b.image[root_inode_off + 16..root_inode_off + 20]
            .copy_from_slice(&root_dir_blk.to_le_bytes());
        let root_size: u32 = (3 * 12 + "..".len() + ".".len() + "sub".len()) as u32;
        let _ = root_size;

        let sub_inode_off: usize = b.meta_base() + (sub_nid as usize) * 32;
        b.image[sub_inode_off + 16..sub_inode_off + 20].copy_from_slice(&sub_dir_blk.to_le_bytes());

        b.put_dir_block(
            root_dir_blk,
            &[
                (root_nid, ".", EROFS_FT_DIR),
                (root_nid, "..", EROFS_FT_DIR),
                (plain_nid, "plain.bin", 1),
                (inline_nid, "inline.txt", 1),
                (sub_nid, "sub", EROFS_FT_DIR),
            ],
        );
        let root_dir_size: u32 = block_dir_size(&[
            (".", 12),
            ("..", 12),
            ("plain.bin", 12),
            ("inline.txt", 12),
            ("sub", 12),
        ]);
        set_inode_inline_dir(&mut b, root_nid, root_dir_blk, root_dir_size);

        b.put_dir_block(
            sub_dir_blk,
            &[
                (sub_nid, ".", EROFS_FT_DIR),
                (root_nid, "..", EROFS_FT_DIR),
                (nested_nid, "deep.dat", 1),
            ],
        );
        let sub_dir_size: u32 = block_dir_size(&[(".", 12), ("..", 12), ("deep.dat", 12)]);
        set_inode_inline_dir(&mut b, sub_nid, sub_dir_blk, sub_dir_size);

        b.write_super(root_nid as u16);
        (b.image.clone(), body_plain, body_inline, nested)
    }

    fn block_dir_size(entries: &[(&str, usize)]) -> u32 {
        let header: usize = entries.len() * 12;
        let names: usize = entries.iter().map(|(n, _)| n.len()).sum::<usize>();
        (header + names) as u32
    }

    fn set_inode_inline_dir(b: &mut ErofsBuilder, nid: u64, blkaddr: u32, size: u32) {
        let off: usize = b.meta_base() + (nid as usize) * 32;
        let format: u16 = (EROFS_INODE_FLAT_PLAIN << 1) | EROFS_INODE_LAYOUT_COMPACT;
        b.image[off..off + 2].copy_from_slice(&format.to_le_bytes());
        b.image[off + 8..off + 12].copy_from_slice(&size.to_le_bytes());
        b.image[off + 16..off + 20].copy_from_slice(&blkaddr.to_le_bytes());
    }

    #[test]
    fn detects_erofs_magic() {
        let (image, _, _, _): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = build_reference_erofs();
        let sb: ErofsSuperblock = detect_erofs(&image).expect("erofs superblock");
        assert_eq!(sb.block_size, BLK as u32);
    }

    #[test]
    fn rejects_non_erofs() {
        assert!(detect_erofs(&[0u8; 2048]).is_none());
    }

    #[test]
    fn walks_flat_plain_and_inline_byte_exact() {
        let (image, body_plain, body_inline, nested): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
            build_reference_erofs();
        let walk: ErofsWalk = walk_erofs(&image, 64 * 1024 * 1024).expect("walk erofs");
        let plain: &ErofsFile = walk
            .files
            .iter()
            .find(|f| f.path == "plain.bin")
            .expect("plain");
        assert_eq!(plain.data, body_plain, "flat-plain bytes");
        let inline: &ErofsFile = walk
            .files
            .iter()
            .find(|f| f.path == "inline.txt")
            .expect("inline");
        assert_eq!(inline.data, body_inline, "flat-inline tail bytes");
        assert!(inline.is_executable);
        let deep: &ErofsFile = walk
            .files
            .iter()
            .find(|f| f.path == "sub/deep.dat")
            .expect("deep");
        assert_eq!(deep.data, nested, "nested file bytes");
    }

    #[test]
    fn extract_to_writes_erofs_files() {
        let (image, body_plain, _, _): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
            build_reference_erofs();
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-erofs-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::Erofs, &image, &dir)
                .expect("erofs extract");
        assert_eq!(result.kind, crate::container::ContainerKind::Erofs);
        assert_eq!(
            std::fs::read(dir.join("plain.bin")).expect("plain"),
            body_plain
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn lz4_literal_block(input: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let len: usize = input.len();
        let token: u8 = if len >= 0x0F { 0xF0 } else { (len as u8) << 4 };
        out.push(token);
        if len >= 0x0F {
            let mut remaining: usize = len - 0x0F;
            while remaining >= 0xFF {
                out.push(0xFF);
                remaining -= 0xFF;
            }
            out.push(remaining as u8);
        }
        out.extend_from_slice(input);
        out
    }

    fn build_single_file_erofs<F>(make_inode: F) -> Vec<u8>
    where
        F: FnOnce(&mut ErofsBuilder) -> (u64, u32),
    {
        let mut b: ErofsBuilder = ErofsBuilder::new(24, 2, 6);
        let root_dir_blk: u32 = b.alloc_data_block(1);
        let root_nid: u64 = b.write_compact_inode_flat_plain(S_IFDIR | 0o755, 0, root_dir_blk);
        let (file_nid, _size): (u64, u32) = make_inode(&mut b);
        b.put_dir_block(
            root_dir_blk,
            &[
                (root_nid, ".", EROFS_FT_DIR),
                (root_nid, "..", EROFS_FT_DIR),
                (file_nid, "file.bin", 1),
            ],
        );
        let root_dir_size: u32 = {
            let header: usize = 3 * 12;
            let names: usize = ".".len() + "..".len() + "file.bin".len();
            (header + names) as u32
        };
        let root_off: usize = b.meta_base() + (root_nid as usize) * 32;
        b.image[root_off + 8..root_off + 12].copy_from_slice(&root_dir_size.to_le_bytes());
        b.write_super(root_nid as u16);
        b.image
    }

    #[test]
    fn chunk_based_file_reconstructs_byte_exact() {
        let chunk0: Vec<u8> = (0..BLK as u32).map(|i| (i % 251) as u8).collect();
        let chunk2: Vec<u8> = (0..BLK as u32).map(|i| ((i * 7) % 251) as u8).collect();
        let size: u32 = (BLK * 3) as u32;
        let c0: Vec<u8> = chunk0.clone();
        let c2: Vec<u8> = chunk2.clone();
        let image: Vec<u8> = build_single_file_erofs(move |b: &mut ErofsBuilder| {
            let blk0: u32 = b.alloc_data_block(1);
            b.put_block(blk0, &c0);
            let blk2: u32 = b.alloc_data_block(1);
            b.put_block(blk2, &c2);
            let nid: u64 =
                b.write_chunk_based_inode(S_IFREG | 0o644, size, 0, &[blk0, EROFS_NULL_ADDR, blk2]);
            (nid, size)
        });
        let walk: ErofsWalk = walk_erofs(&image, 64 * 1024 * 1024).expect("walk");
        let file: &ErofsFile = walk
            .files
            .iter()
            .find(|f| f.path == "file.bin")
            .expect("file");
        let mut expected: Vec<u8> = chunk0;
        expected.extend(std::iter::repeat_n(0u8, BLK));
        expected.extend_from_slice(&chunk2);
        assert_eq!(
            file.data, expected,
            "chunk-based reconstruction with a hole"
        );
    }

    #[test]
    fn compressed_full_lz4_single_head_cluster() {
        let payload: Vec<u8> =
            b"erofs lz4 head pcluster decoded from one literal lz4 block, last cluster".to_vec();
        let size: u32 = payload.len() as u32;
        let head_blk_lit: Vec<u8> = lz4_literal_block(&payload);
        let image: Vec<u8> = build_single_file_erofs(move |b: &mut ErofsBuilder| {
            let head_blk: u32 = b.alloc_data_block(1);
            b.put_block(head_blk, &head_blk_lit);
            let advise_head: u16 = 1;
            let nid: u64 = b.write_compressed_full_inode(
                S_IFREG | 0o644,
                size,
                Z_EROFS_ALGO_LZ4,
                0,
                &[(advise_head, head_blk)],
            );
            (nid, size)
        });
        let walk: ErofsWalk = walk_erofs(&image, 64 * 1024 * 1024).expect("walk");
        let file: &ErofsFile = walk
            .files
            .iter()
            .find(|f| f.path == "file.bin")
            .expect("file");
        assert_eq!(file.data, payload, "lz4 single head cluster decode");
    }

    #[test]
    fn compressed_full_plain_cluster_is_stored_verbatim() {
        let payload: Vec<u8> =
            b"erofs plain pcluster stored uncompressed in the data area".to_vec();
        let size: u32 = payload.len() as u32;
        let stored: Vec<u8> = payload.clone();
        let image: Vec<u8> = build_single_file_erofs(move |b: &mut ErofsBuilder| {
            let blk: u32 = b.alloc_data_block(1);
            b.put_block(blk, &stored);
            let nid: u64 = b.write_compressed_full_inode(
                S_IFREG | 0o644,
                size,
                Z_EROFS_ALGO_LZ4,
                0,
                &[(Z_EROFS_LCLUSTER_TYPE_PLAIN, blk)],
            );
            (nid, size)
        });
        let walk: ErofsWalk = walk_erofs(&image, 64 * 1024 * 1024).expect("walk");
        let file: &ErofsFile = walk
            .files
            .iter()
            .find(|f| f.path == "file.bin")
            .expect("file");
        assert_eq!(file.data, payload, "plain pcluster stored verbatim");
    }

    #[test]
    fn compressed_compact_inode_errors_instead_of_empty_success() {
        let size: u32 = 32;
        let image: Vec<u8> = build_single_file_erofs(move |b: &mut ErofsBuilder| {
            let nid: u64 = b.write_compact_inode_flat_plain(S_IFREG | 0o644, size, 0);
            let off: usize = b.meta_base() + (nid as usize) * 32;
            let format: u16 = (EROFS_INODE_COMPRESSED_COMPACT << 1) | EROFS_INODE_LAYOUT_COMPACT;
            b.image[off..off + 2].copy_from_slice(&format.to_le_bytes());
            (nid, size)
        });
        let err: Error = walk_erofs(&image, 64 * 1024 * 1024)
            .expect_err("compact compressed data must not recover as an empty file");
        assert!(matches!(err, Error::Erofs(msg) if msg.contains("compact")));
    }

    fn deflate_compress(input: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc: flate2::write::DeflateEncoder<Vec<u8>> =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(input).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn compressed_pcluster_reservation_is_input_proportional() {
        const HUGE_WANT: usize = 2 * 1024 * 1024 * 1024;
        let cap: usize = crate::quota::MAX_ENTRY_PREALLOC;
        {
            let payload: &[u8] = b"erofs deflate pcluster output stays small";
            let comp: Vec<u8> = deflate_compress(payload);
            let out: Vec<u8> = decode_deflate(&comp, HUGE_WANT).expect("deflate");
            assert_eq!(out, payload);
            assert!(
                out.capacity() <= cap,
                "deflate reservation capped at prealloc bound"
            );
        }
        {
            let payload: &[u8] = b"erofs lz4 pcluster output stays small";
            let block: Vec<u8> = lz4_literal_block(payload);
            let out: Vec<u8> =
                crate::containers::lz4_block::decompress_stop_at(&block, HUGE_WANT).expect("lz4");
            assert_eq!(out, payload);
            assert!(
                out.capacity() <= cap,
                "lz4 reservation capped at prealloc bound"
            );
        }
        {
            let payload: &[u8] = b"erofs zstd pcluster output stays small";
            let frame: Vec<u8> = zstd::bulk::compress(payload, 3).expect("zstd compress");
            let out: Vec<u8> = decode_zstd(&frame, HUGE_WANT, "file.bin").expect("zstd");
            assert_eq!(out, payload);
            assert!(
                out.capacity() <= cap,
                "zstd reservation capped at prealloc bound"
            );
        }
    }
}
