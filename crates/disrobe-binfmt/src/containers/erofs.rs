use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const EROFS_SUPER_OFFSET: usize = 1024;
const EROFS_MAGIC: u32 = 0xE0F5_E1E2;
const EROFS_ISLOTBITS: u32 = 5;
const EROFS_FEATURE_INCOMPAT_48BIT: u32 = 0x0000_0080;
const EROFS_FEATURE_INCOMPAT_COMPR_CFGS: u32 = 0x0000_0002;
const EROFS_FEATURE_INCOMPAT_COMPR_HEAD2: u32 = 0x0000_0008;

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
const MAX_PCLUSTER_ENCODED: usize = 1 << 20;
const MAX_PCLUSTER_DECODED: usize = 12 << 20;
const MAX_LZMA_DICTIONARY: u32 = 8 << 20;
const MAX_FULL_INDEX_ENTRIES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErofsSuperblock {
    pub blkszbits: u8,
    pub block_size: u32,
    pub sb_extslots: u8,
    pub root_nid: u64,
    pub inos: u64,
    pub blocks: u64,
    pub meta_blkaddr: u32,
    pub feature_incompat: u32,
    pub available_compr_algs: u16,
    pub extra_devices: u16,
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
    xattr_icount: u16,
    inode_slot_end: usize,
}

#[derive(Debug, Clone, Copy)]
struct ErofsCompressionConfig {
    lzma_dictionary: Option<u32>,
}

impl ErofsCompressionConfig {
    const EMPTY: Self = Self {
        lzma_dictionary: None,
    };
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
    let sb_extslots: u8 = bytes[EROFS_SUPER_OFFSET + 13];
    let feature_incompat: u32 = rd_u32(bytes, EROFS_SUPER_OFFSET + 80)?;
    let uses_48bit: bool = feature_incompat & EROFS_FEATURE_INCOMPAT_48BIT != 0;
    let root_nid: u64 = if uses_48bit {
        rd_u64(bytes, EROFS_SUPER_OFFSET + 120)?
    } else {
        u64::from(rd_u16(bytes, EROFS_SUPER_OFFSET + 14)?)
    };
    let inos: u64 = rd_u64(bytes, EROFS_SUPER_OFFSET + 16)?;
    let blocks_lo: u32 = rd_u32(bytes, EROFS_SUPER_OFFSET + 36)?;
    let blocks: u64 = if uses_48bit {
        let blocks_hi: u16 = rd_u16(bytes, EROFS_SUPER_OFFSET + 14)?;
        u64::from(blocks_lo) | (u64::from(blocks_hi) << 32)
    } else {
        u64::from(blocks_lo)
    };
    let meta_blkaddr: u32 = rd_u32(bytes, EROFS_SUPER_OFFSET + 40)?;
    let available_compr_algs: u16 = rd_u16(bytes, EROFS_SUPER_OFFSET + 84)?;
    let extra_devices: u16 = rd_u16(bytes, EROFS_SUPER_OFFSET + 86)?;
    Some(ErofsSuperblock {
        blkszbits,
        block_size: 1u32 << blkszbits,
        sb_extslots,
        root_nid,
        inos,
        blocks,
        meta_blkaddr,
        feature_incompat,
        available_compr_algs,
        extra_devices,
    })
}

fn inode_offset(sb: &ErofsSuperblock, nid: u64) -> Result<usize> {
    let meta_base: u64 = u64::from(sb.meta_blkaddr)
        .checked_mul(u64::from(sb.block_size))
        .ok_or_else(|| Error::Erofs("metadata base overflow".to_owned()))?;
    let slot_offset: u64 = nid
        .checked_mul(1u64 << EROFS_ISLOTBITS)
        .ok_or_else(|| Error::Erofs(format!("inode nid {nid} offset overflow")))?;
    let offset: u64 = meta_base
        .checked_add(slot_offset)
        .ok_or_else(|| Error::Erofs(format!("inode nid {nid} address overflow")))?;
    usize::try_from(offset)
        .map_err(|_| Error::Erofs(format!("inode nid {nid} address exceeds host size")))
}

fn parse_compression_config(bytes: &[u8], sb: &ErofsSuperblock) -> Result<ErofsCompressionConfig> {
    if sb.feature_incompat & EROFS_FEATURE_INCOMPAT_COMPR_CFGS == 0 {
        return Ok(ErofsCompressionConfig::EMPTY);
    }
    let mut offset: usize = EROFS_SUPER_OFFSET
        .checked_add(128)
        .and_then(|value: usize| value.checked_add(usize::from(sb.sb_extslots) * 16))
        .ok_or_else(|| Error::Erofs("compression config offset overflow".to_owned()))?;
    let unknown: u16 = sb.available_compr_algs & !0x000f;
    if unknown != 0 {
        return Err(Error::Erofs(format!(
            "compression config declares unknown algorithm bits 0x{unknown:04x}"
        )));
    }
    let mut config: ErofsCompressionConfig = ErofsCompressionConfig::EMPTY;
    for algorithm in 0u8..4 {
        if sb.available_compr_algs & (1u16 << algorithm) == 0 {
            continue;
        }
        offset = offset
            .checked_add(3)
            .map(|value: usize| value & !3)
            .ok_or_else(|| Error::Erofs("compression config alignment overflow".to_owned()))?;
        let size: usize =
            usize::from(rd_u16(bytes, offset).ok_or_else(|| {
                Error::Erofs("compression config length out of bounds".to_owned())
            })?);
        let body: usize = offset
            .checked_add(2)
            .ok_or_else(|| Error::Erofs("compression config body overflow".to_owned()))?;
        let end: usize = body
            .checked_add(size)
            .ok_or_else(|| Error::Erofs("compression config extent overflow".to_owned()))?;
        bytes
            .get(body..end)
            .ok_or_else(|| Error::Erofs("compression config body out of bounds".to_owned()))?;
        if algorithm == Z_EROFS_ALGO_LZMA {
            if size != 14 {
                return Err(Error::Erofs(format!(
                    "lzma compression config has size {size}, expected 14"
                )));
            }
            let dictionary: u32 = rd_u32(bytes, body)
                .ok_or_else(|| Error::Erofs("lzma dictionary out of bounds".to_owned()))?;
            let format: u16 = rd_u16(bytes, body + 4)
                .ok_or_else(|| Error::Erofs("lzma format out of bounds".to_owned()))?;
            if format != 0 {
                return Err(Error::Erofs(format!(
                    "lzma compression config format {format} is unsupported"
                )));
            }
            if !(4096..=MAX_LZMA_DICTIONARY).contains(&dictionary) {
                return Err(Error::Erofs(format!(
                    "lzma dictionary {dictionary} is outside 4096..={MAX_LZMA_DICTIONARY}"
                )));
            }
            if bytes[body + 6..end].iter().any(|byte: &u8| *byte != 0) {
                return Err(Error::Erofs(
                    "lzma compression config reserved bytes are nonzero".to_owned(),
                ));
            }
            config.lzma_dictionary = Some(dictionary);
        }
        offset = end;
    }
    Ok(config)
}

fn read_inode(bytes: &[u8], sb: &ErofsSuperblock, nid: u64) -> Result<ErofsInode> {
    let base: usize = inode_offset(sb, nid)?;
    let format: u16 = rd_u16(bytes, base)
        .ok_or_else(|| Error::Erofs(format!("inode nid {nid} format out of bounds")))?;
    let layout: u16 = (format >> 1) & 0x7;
    let version: u16 = format & 0x1;
    match version {
        EROFS_INODE_LAYOUT_EXTENDED => {
            let xattr_icount: u16 = rd_u16(bytes, base + 2)
                .ok_or_else(|| Error::Erofs("extended inode xattr count oob".to_owned()))?;
            let mode: u16 = rd_u16(bytes, base + 4)
                .ok_or_else(|| Error::Erofs("extended inode mode oob".to_owned()))?;
            let size: u64 = rd_u64(bytes, base + 8)
                .ok_or_else(|| Error::Erofs("extended inode size oob".to_owned()))?;
            let raw_blkaddr: u32 = rd_u32(bytes, base + 16)
                .ok_or_else(|| Error::Erofs("extended inode blkaddr oob".to_owned()))?;
            Ok(ErofsInode {
                format: layout,
                mode,
                size,
                raw_blkaddr,
                xattr_icount,
                inode_slot_end: base + 64,
            })
        }
        EROFS_INODE_LAYOUT_COMPACT => {
            let xattr_icount: u16 = rd_u16(bytes, base + 2)
                .ok_or_else(|| Error::Erofs("compact inode xattr count oob".to_owned()))?;
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
                xattr_icount,
                inode_slot_end: base + 32,
            })
        }
        other => Err(Error::Erofs(format!(
            "inode nid {nid} unknown version {other}"
        ))),
    }
}

fn inode_metadata_end(inode: &ErofsInode) -> Result<usize> {
    let xattr_size: usize = if inode.xattr_icount == 0 {
        0
    } else {
        usize::from(inode.xattr_icount - 1)
            .checked_mul(4)
            .and_then(|size: usize| size.checked_add(12))
            .ok_or_else(|| Error::Erofs("inode xattr body size overflow".to_owned()))?
    };
    inode
        .inode_slot_end
        .checked_add(xattr_size)
        .ok_or_else(|| Error::Erofs("inode metadata end overflow".to_owned()))
}

fn inode_data(
    bytes: &[u8],
    sb: &ErofsSuperblock,
    compression: ErofsCompressionConfig,
    inode: &ErofsInode,
    max_output: u64,
    path: &str,
) -> Result<Vec<u8>> {
    if inode.size > max_output {
        return Err(Error::Erofs(format!(
            "inode `{path}` size {} exceeds remaining output cap {max_output}",
            inode.size
        )));
    }
    let size: usize = usize::try_from(inode.size)
        .map_err(|_| Error::Erofs(format!("inode `{path}` size exceeds host size")))?;
    if size == 0 {
        return Ok(Vec::new());
    }
    match inode.format {
        EROFS_INODE_FLAT_PLAIN => {
            let start: usize = usize::try_from(inode.raw_blkaddr)
                .ok()
                .and_then(|block: usize| block.checked_mul(sb.block_size as usize))
                .ok_or_else(|| Error::Erofs(format!("flat-plain start for `{path}` overflow")))?;
            let end: usize = start
                .checked_add(size)
                .ok_or_else(|| Error::Erofs(format!("flat-plain end for `{path}` overflow")))?;
            let slice: &[u8] = bytes
                .get(start..end)
                .ok_or_else(|| Error::Erofs(format!("flat-plain data for `{path}` oob")))?;
            Ok(slice.to_vec())
        }
        EROFS_INODE_FLAT_INLINE => {
            let block_size: usize = sb.block_size as usize;
            let tail_len: usize = size % block_size;
            let head_blocks: usize = size / block_size;
            let mut out: Vec<u8> = Vec::with_capacity(size.min(bytes.len()));
            let block_start: usize = usize::try_from(inode.raw_blkaddr)
                .ok()
                .and_then(|block: usize| block.checked_mul(block_size))
                .ok_or_else(|| Error::Erofs(format!("flat-inline start for `{path}` overflow")))?;
            for i in 0..head_blocks {
                let s: usize = i
                    .checked_mul(block_size)
                    .and_then(|offset: usize| block_start.checked_add(offset))
                    .ok_or_else(|| {
                        Error::Erofs(format!("flat-inline block for `{path}` overflow"))
                    })?;
                let end: usize = s.checked_add(block_size).ok_or_else(|| {
                    Error::Erofs(format!("flat-inline block end for `{path}` overflow"))
                })?;
                let slice: &[u8] = bytes
                    .get(s..end)
                    .ok_or_else(|| Error::Erofs(format!("flat-inline block for `{path}` oob")))?;
                out.extend_from_slice(slice);
            }
            if tail_len > 0 {
                let inline_start: usize = inode_metadata_end(inode)?;
                let inline_end: usize = inline_start.checked_add(tail_len).ok_or_else(|| {
                    Error::Erofs(format!("flat-inline tail for `{path}` overflow"))
                })?;
                let slice: &[u8] = bytes
                    .get(inline_start..inline_end)
                    .ok_or_else(|| Error::Erofs(format!("flat-inline tail for `{path}` oob")))?;
                out.extend_from_slice(slice);
            }
            Ok(out)
        }
        EROFS_INODE_COMPRESSED_FULL => compressed_full_data(bytes, sb, compression, inode, path),
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
const EROFS_CHUNK_FORMAT_48BIT: u16 = 0x0040;
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
    if chunk_format & !(EROFS_CHUNK_FORMAT_BLKBITS_MASK | EROFS_CHUNK_FORMAT_INDEXES) != 0
        || chunk_format & EROFS_CHUNK_FORMAT_48BIT != 0
    {
        return Err(Error::Erofs(format!(
            "chunk format 0x{chunk_format:04x} for `{path}` is unsupported"
        )));
    }
    let chunkbits: u32 =
        sb.blkszbits as u32 + u32::from(chunk_format & EROFS_CHUNK_FORMAT_BLKBITS_MASK);
    let chunk_size: usize = 1usize
        .checked_shl(chunkbits)
        .ok_or_else(|| Error::Erofs(format!("chunk size for `{path}` exceeds host size")))?;
    let is_indexes: bool = chunk_format & EROFS_CHUNK_FORMAT_INDEXES != 0;
    let chunk_count: usize = size.div_ceil(chunk_size);
    let entry_size: usize = if is_indexes { 8 } else { 4 };
    let table_start: usize = inode_metadata_end(inode)?;
    let table_len: usize = chunk_count
        .checked_mul(entry_size)
        .ok_or_else(|| Error::Erofs(format!("chunk table for `{path}` overflows")))?;
    bytes
        .get(
            table_start
                ..table_start.checked_add(table_len).ok_or_else(|| {
                    Error::Erofs(format!("chunk table end for `{path}` overflows"))
                })?,
        )
        .ok_or_else(|| Error::Erofs(format!("chunk table for `{path}` out of bounds")))?;
    let mut out: Vec<u8> = Vec::with_capacity(size.min(bytes.len()));
    for index in 0..chunk_count {
        let entry_off: usize = table_start + index * entry_size;
        let blkaddr: u32 = if is_indexes {
            let startblk_hi: u16 = rd_u16(bytes, entry_off)
                .ok_or_else(|| Error::Erofs(format!("chunk high address for `{path}` oob")))?;
            let device_id: u16 = rd_u16(bytes, entry_off + 2)
                .ok_or_else(|| Error::Erofs(format!("chunk device id for `{path}` oob")))?;
            if startblk_hi != 0 || device_id != 0 {
                return Err(Error::Erofs(format!(
                    "chunk index for `{path}` uses high address {startblk_hi} or external device {device_id}"
                )));
            }
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
            let start: usize = usize::try_from(blkaddr)
                .ok()
                .and_then(|block: usize| block.checked_mul(block_size))
                .ok_or_else(|| Error::Erofs(format!("chunk data for `{path}` overflow")))?;
            let end: usize = start
                .checked_add(this_chunk)
                .ok_or_else(|| Error::Erofs(format!("chunk data end for `{path}` overflow")))?;
            let slice: &[u8] = bytes
                .get(start..end)
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
const Z_EROFS_LCLUSTER_TYPE_HEAD1: u16 = 1;
const Z_EROFS_LCLUSTER_TYPE_NONHEAD: u16 = 2;
const Z_EROFS_LCLUSTER_TYPE_HEAD2: u16 = 3;
const Z_EROFS_LI_PARTIAL_REF: u16 = 1 << 15;
const Z_EROFS_LI_HOLE: u16 = 1 << 14;
const Z_EROFS_LI_D0_CBLKCNT: u16 = 1 << 11;
const Z_EROFS_ADVISE_EXTENTS: u16 = 0x0001;
const Z_EROFS_ADVISE_BIG_PCLUSTER_1: u16 = 0x0002;
const Z_EROFS_ADVISE_BIG_PCLUSTER_2: u16 = 0x0004;
const Z_EROFS_ADVISE_INLINE_PCLUSTER: u16 = 0x0008;
const Z_EROFS_ADVISE_INTERLACED_PCLUSTER: u16 = 0x0010;
const Z_EROFS_ADVISE_FRAGMENT_PCLUSTER: u16 = 0x0020;

#[derive(Debug, Clone, Copy)]
struct FullIndexEntry {
    kind: u16,
    partial: bool,
    hole: bool,
    cluster_offset: u16,
    first: u16,
    second: u16,
}

#[derive(Debug, Clone, Copy)]
struct MappedExtent {
    logical_start: usize,
    logical_len: usize,
    physical_start: Option<usize>,
    physical_len: usize,
    algorithm: Option<u8>,
}

fn full_index_entries(
    bytes: &[u8],
    index_base: usize,
    count: usize,
    lcluster_size: usize,
    path: &str,
) -> Result<Vec<FullIndexEntry>> {
    let table_len: usize = count
        .checked_mul(8)
        .ok_or_else(|| Error::Erofs("z full index size overflow".to_owned()))?;
    if count > MAX_FULL_INDEX_ENTRIES {
        return Err(Error::Erofs(format!(
            "z full index entry count {count} exceeds {MAX_FULL_INDEX_ENTRIES}"
        )));
    }
    bytes
        .get(
            index_base
                ..index_base
                    .checked_add(table_len)
                    .ok_or_else(|| Error::Erofs("z full index extent overflow".to_owned()))?,
        )
        .ok_or_else(|| Error::Erofs(format!("z full index for `{path}` out of bounds")))?;
    let mut entries: Vec<FullIndexEntry> = Vec::with_capacity(count);
    for index in 0..count {
        let offset: usize = index_base + index * 8;
        let advise: u16 = rd_u16(bytes, offset)
            .ok_or_else(|| Error::Erofs(format!("z full index {index} advise out of bounds")))?;
        let kind: u16 = advise & 0x3;
        let cluster_offset: u16 = rd_u16(bytes, offset + 2).ok_or_else(|| {
            Error::Erofs(format!("z full index {index} cluster offset out of bounds"))
        })?;
        let first: u16 = rd_u16(bytes, offset + 4)
            .ok_or_else(|| Error::Erofs(format!("z full index {index} word 0 out of bounds")))?;
        let second: u16 = rd_u16(bytes, offset + 6)
            .ok_or_else(|| Error::Erofs(format!("z full index {index} word 1 out of bounds")))?;
        if kind != Z_EROFS_LCLUSTER_TYPE_NONHEAD && usize::from(cluster_offset) >= lcluster_size {
            return Err(Error::Erofs(format!(
                "z full index {index} cluster offset {cluster_offset} is invalid"
            )));
        }
        entries.push(FullIndexEntry {
            kind,
            partial: advise & Z_EROFS_LI_PARTIAL_REF != 0,
            hole: advise & Z_EROFS_LI_HOLE != 0,
            cluster_offset,
            first,
            second,
        });
    }
    Ok(entries)
}

fn resolve_head(entries: &[FullIndexEntry], start: usize, path: &str) -> Result<usize> {
    let mut index: usize = start;
    for _ in 0..=entries.len() {
        let entry: FullIndexEntry = entries[index];
        if entry.kind != Z_EROFS_LCLUSTER_TYPE_NONHEAD {
            return Ok(index);
        }
        let delta: usize = if entry.first & Z_EROFS_LI_D0_CBLKCNT != 0 {
            1
        } else {
            usize::from(entry.first)
        };
        if delta == 0 || delta > index {
            return Err(Error::Erofs(format!(
                "erofs `{path}` z index {index} has invalid lookback {delta}"
            )));
        }
        index -= delta;
    }
    Err(Error::Erofs(format!(
        "erofs `{path}` z index lookback cycle"
    )))
}

fn compressed_full_data(
    bytes: &[u8],
    sb: &ErofsSuperblock,
    compression: ErofsCompressionConfig,
    inode: &ErofsInode,
    path: &str,
) -> Result<Vec<u8>> {
    let metadata_end: usize = inode_metadata_end(inode)?;
    let header_off: usize = metadata_end
        .checked_add(7)
        .map(|value: usize| value & !7)
        .ok_or_else(|| Error::Erofs("z map header alignment overflow".to_owned()))?;
    let advise: u16 =
        rd_u16(bytes, header_off + 4).ok_or_else(|| Error::Erofs("z map header oob".to_owned()))?;
    let algo_byte: u8 = *bytes
        .get(header_off + 6)
        .ok_or_else(|| Error::Erofs("z map algorithm oob".to_owned()))?;
    let clusterbits_byte: u8 = *bytes
        .get(header_off + 7)
        .ok_or_else(|| Error::Erofs("z map clusterbits oob".to_owned()))?;
    if advise
        & (Z_EROFS_ADVISE_EXTENTS
            | Z_EROFS_ADVISE_INLINE_PCLUSTER
            | Z_EROFS_ADVISE_INTERLACED_PCLUSTER
            | Z_EROFS_ADVISE_FRAGMENT_PCLUSTER)
        != 0
    {
        return Err(Error::Erofs(format!(
            "erofs `{path}` uses an unsupported compressed extent, inline, interlaced, or fragment layout"
        )));
    }
    let algorithms: [u8; 2] = [algo_byte & 0x0f, algo_byte >> 4];
    let lclusterbits: u32 = sb.blkszbits as u32 + u32::from(clusterbits_byte & 0x0f);
    let lcluster_size: usize = 1usize << lclusterbits;
    let block_size: usize = sb.block_size as usize;
    let size: usize = inode.size as usize;
    let index_base: usize = header_off
        .checked_add(16)
        .ok_or_else(|| Error::Erofs("z full index offset overflow".to_owned()))?;
    let lcluster_count: usize = size.div_ceil(lcluster_size);

    let entries: Vec<FullIndexEntry> =
        full_index_entries(bytes, index_base, lcluster_count, lcluster_size, path)?;
    let mut extents: Vec<MappedExtent> = Vec::new();
    let mut physical_blocks_seen: std::collections::BTreeSet<u32> =
        std::collections::BTreeSet::new();
    let mut head: usize = 0;
    while head < entries.len() {
        let entry: FullIndexEntry = entries[head];
        if entry.kind == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
            return Err(Error::Erofs(format!(
                "erofs `{path}` z index {head} has no preceding head"
            )));
        }
        if entry.partial {
            return Err(Error::Erofs(format!(
                "erofs `{path}` uses a compressed partial-reference extent"
            )));
        }
        if entry.kind == Z_EROFS_LCLUSTER_TYPE_HEAD2
            && sb.feature_incompat & EROFS_FEATURE_INCOMPAT_COMPR_HEAD2 == 0
        {
            return Err(Error::Erofs(format!(
                "erofs `{path}` uses HEAD2 without the required incompatibility feature"
            )));
        }
        let mut next: usize = head + 1;
        while next < entries.len() && entries[next].kind == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
            if entries[next].hole {
                return Err(Error::Erofs(format!(
                    "erofs `{path}` z index {next} marks a nonhead as a hole"
                )));
            }
            if entries[next].first & Z_EROFS_LI_D0_CBLKCNT != 0 && next != head + 1 {
                return Err(Error::Erofs(format!(
                    "erofs `{path}` z index {next} stores a compressed block count away from the first nonhead"
                )));
            }
            if entries[next].partial || resolve_head(&entries, next, path)? != head {
                return Err(Error::Erofs(format!(
                    "erofs `{path}` z index {next} does not resolve to head {head}"
                )));
            }
            let forward: usize = usize::from(entries[next].second);
            if forward == 0
                || next
                    .checked_add(forward)
                    .is_none_or(|value: usize| value > entries.len())
            {
                return Err(Error::Erofs(format!(
                    "erofs `{path}` z index {next} has invalid forward delta {forward}"
                )));
            }
            next += 1;
        }
        for (index, indexed) in entries.iter().enumerate().take(next).skip(head + 1) {
            let expected_forward: usize = next - index;
            if usize::from(indexed.second) != expected_forward {
                return Err(Error::Erofs(format!(
                    "erofs `{path}` z index {index} forward delta {} does not reach head {next}",
                    indexed.second
                )));
            }
        }
        let logical_start: usize = head
            .checked_mul(lcluster_size)
            .and_then(|value: usize| value.checked_add(usize::from(entry.cluster_offset)))
            .ok_or_else(|| Error::Erofs("compressed logical start overflow".to_owned()))?;
        let logical_end: usize = if next < entries.len() {
            next.checked_mul(lcluster_size)
                .and_then(|value: usize| {
                    value.checked_add(usize::from(entries[next].cluster_offset))
                })
                .ok_or_else(|| Error::Erofs("compressed logical end overflow".to_owned()))?
        } else {
            size
        };
        if logical_start >= logical_end || logical_end > size {
            return Err(Error::Erofs(format!(
                "erofs `{path}` has invalid compressed logical range {logical_start}..{logical_end}"
            )));
        }
        let big: bool = match entry.kind {
            Z_EROFS_LCLUSTER_TYPE_HEAD1 => advise & Z_EROFS_ADVISE_BIG_PCLUSTER_1 != 0,
            Z_EROFS_LCLUSTER_TYPE_PLAIN | Z_EROFS_LCLUSTER_TYPE_HEAD2 => {
                advise & Z_EROFS_ADVISE_BIG_PCLUSTER_2 != 0
            }
            other => {
                return Err(Error::Erofs(format!(
                    "erofs `{path}` z index {head} has unknown head type {other}"
                )));
            }
        };
        let physical_blocks: usize = if entry.hole {
            0
        } else if big && head + 1 < next {
            let first_nonhead: FullIndexEntry = entries[head + 1];
            if first_nonhead.first & Z_EROFS_LI_D0_CBLKCNT == 0 {
                return Err(Error::Erofs(format!(
                    "erofs `{path}` big pcluster at {head} has no compressed block count"
                )));
            }
            let count: usize = usize::from(first_nonhead.first & !Z_EROFS_LI_D0_CBLKCNT);
            if count == 0 {
                return Err(Error::Erofs(format!(
                    "erofs `{path}` big pcluster at {head} has zero compressed blocks"
                )));
            }
            count
        } else {
            if head + 1 < next && entries[head + 1].first & Z_EROFS_LI_D0_CBLKCNT != 0 {
                return Err(Error::Erofs(format!(
                    "erofs `{path}` non-big pcluster at {head} stores a compressed block count"
                )));
            }
            1
        };
        if physical_blocks > inode.raw_blkaddr as usize {
            return Err(Error::Erofs(format!(
                "erofs `{path}` pcluster block count {physical_blocks} exceeds inode accounting {}",
                inode.raw_blkaddr
            )));
        }
        let block_address: u32 = u32::from(entry.first) | (u32::from(entry.second) << 16);
        let physical_start: Option<usize> = if entry.hole {
            None
        } else if block_address == EROFS_NULL_ADDR {
            if entry.kind != Z_EROFS_LCLUSTER_TYPE_PLAIN {
                return Err(Error::Erofs(format!(
                    "erofs `{path}` compressed pcluster has a null physical address"
                )));
            }
            return Err(Error::Erofs(format!(
                "erofs `{path}` plain pcluster uses a null address without the HOLE flag"
            )));
        } else {
            for delta in 0..physical_blocks {
                let block: u32 = block_address
                    .checked_add(u32::try_from(delta).map_err(|_| {
                        Error::Erofs("compressed block count exceeds u32".to_owned())
                    })?)
                    .ok_or_else(|| Error::Erofs("compressed block address overflow".to_owned()))?;
                physical_blocks_seen.insert(block);
            }
            Some(
                usize::try_from(block_address)
                    .ok()
                    .and_then(|block: usize| block.checked_mul(block_size))
                    .ok_or_else(|| Error::Erofs("compressed physical start overflow".to_owned()))?,
            )
        };
        let physical_len: usize = physical_blocks
            .checked_mul(block_size)
            .ok_or_else(|| Error::Erofs("compressed physical length overflow".to_owned()))?;
        if physical_len > MAX_PCLUSTER_ENCODED {
            return Err(Error::Erofs(format!(
                "erofs `{path}` pcluster length {physical_len} exceeds {MAX_PCLUSTER_ENCODED}"
            )));
        }
        let physical_end: Option<usize> = physical_start
            .map(|start: usize| {
                start
                    .checked_add(physical_len)
                    .ok_or_else(|| Error::Erofs("compressed physical extent overflow".to_owned()))
            })
            .transpose()?;
        let declared_end: u64 = sb
            .blocks
            .checked_mul(u64::from(sb.block_size))
            .ok_or_else(|| Error::Erofs("declared image extent overflow".to_owned()))?;
        if let (Some(start), Some(end)) = (physical_start, physical_end)
            && (end as u64 > declared_end || end > bytes.len())
        {
            return Err(Error::Erofs(format!(
                "erofs `{path}` pcluster {start}..{end} exceeds the image"
            )));
        }
        let algorithm: Option<u8> = match entry.kind {
            Z_EROFS_LCLUSTER_TYPE_PLAIN => None,
            Z_EROFS_LCLUSTER_TYPE_HEAD1 => Some(algorithms[0]),
            Z_EROFS_LCLUSTER_TYPE_HEAD2 => Some(algorithms[1]),
            other => {
                return Err(Error::Erofs(format!(
                    "erofs `{path}` z index {head} has unsupported type {other}"
                )));
            }
        };
        if algorithm.is_some_and(|value: u8| {
            value >= 16
                || if sb.feature_incompat & EROFS_FEATURE_INCOMPAT_COMPR_CFGS != 0 {
                    sb.available_compr_algs & (1u16 << value) == 0
                } else {
                    value != Z_EROFS_ALGO_LZ4
                }
        }) {
            return Err(Error::Erofs(format!(
                "erofs `{path}` uses an undeclared compression algorithm"
            )));
        }
        extents.push(MappedExtent {
            logical_start,
            logical_len: logical_end - logical_start,
            physical_start,
            physical_len,
            algorithm,
        });
        head = next;
    }
    if physical_blocks_seen.len() > inode.raw_blkaddr as usize {
        return Err(Error::Erofs(format!(
            "erofs `{path}` references {} physical blocks but inode accounting permits {}",
            physical_blocks_seen.len(),
            inode.raw_blkaddr
        )));
    }
    let mut out: Vec<u8> = vec![0; size];
    for extent in extents {
        if extent.logical_len > MAX_PCLUSTER_DECODED {
            return Err(Error::Erofs(format!(
                "erofs `{path}` decoded extent {} exceeds {MAX_PCLUSTER_DECODED}",
                extent.logical_len
            )));
        }
        let destination: &mut [u8] = out
            .get_mut(extent.logical_start..extent.logical_start + extent.logical_len)
            .ok_or_else(|| Error::Erofs("compressed destination out of bounds".to_owned()))?;
        let Some(physical_start): Option<usize> = extent.physical_start else {
            continue;
        };
        let source: &[u8] = &bytes[physical_start..physical_start + extent.physical_len];
        if let Some(algorithm) = extent.algorithm {
            let decoded: Vec<u8> = decode_pcluster(
                algorithm,
                compression,
                source,
                extent.logical_len,
                block_size,
                path,
            )?;
            destination.copy_from_slice(&decoded);
        } else {
            let plain: &[u8] = source
                .get(..extent.logical_len)
                .ok_or_else(|| Error::Erofs(format!("plain pcluster for `{path}` is too short")))?;
            destination.copy_from_slice(plain);
        }
    }
    Ok(out)
}

fn decode_pcluster(
    algorithm: u8,
    compression: ErofsCompressionConfig,
    comp: &[u8],
    want: usize,
    block_size: usize,
    path: &str,
) -> Result<Vec<u8>> {
    match algorithm {
        Z_EROFS_ALGO_LZ4 => crate::containers::lz4_block::decompress_stop_at(comp, want),
        Z_EROFS_ALGO_DEFLATE => decode_deflate(comp, want),
        Z_EROFS_ALGO_ZSTD => decode_zstd(comp, want, path),
        Z_EROFS_ALGO_LZMA => decode_microlzma(compression, comp, want, block_size, path),
        other => Err(Error::Erofs(format!(
            "erofs `{path}` unknown compression algorithm {other}"
        ))),
    }
}

fn decode_microlzma(
    compression: ErofsCompressionConfig,
    comp: &[u8],
    want: usize,
    block_size: usize,
    path: &str,
) -> Result<Vec<u8>> {
    use lzma_rs::decompress::raw::{LzmaDecoder, LzmaParams, LzmaProperties};
    use std::io::Cursor;

    if comp.len() > MAX_PCLUSTER_ENCODED || want > MAX_PCLUSTER_DECODED {
        return Err(Error::Erofs(format!(
            "erofs `{path}` microlzma pcluster exceeds the encoded or decoded ceiling"
        )));
    }
    let dictionary: u32 = compression.lzma_dictionary.ok_or_else(|| {
        Error::Erofs(format!(
            "erofs `{path}` microlzma pcluster has no validated lzma configuration"
        ))
    })?;
    let property_offset: usize = comp
        .get(..block_size.min(comp.len()))
        .ok_or_else(|| Error::Erofs("microlzma property window out of bounds".to_owned()))?
        .iter()
        .position(|byte: &u8| *byte != 0)
        .ok_or_else(|| Error::Erofs(format!("erofs `{path}` microlzma pcluster is empty")))?;
    let property: u8 = !comp[property_offset];
    if property >= 225 {
        return Err(Error::Erofs(format!(
            "erofs `{path}` microlzma property {property} is invalid"
        )));
    }
    let lc: u32 = u32::from(property % 9);
    let remainder: u8 = property / 9;
    let lp: u32 = u32::from(remainder % 5);
    let pb: u32 = u32::from(remainder / 5);
    let mut stream: Vec<u8> = Vec::with_capacity(comp.len() - property_offset);
    stream.push(0);
    stream.extend_from_slice(&comp[property_offset + 1..]);
    let params: LzmaParams =
        LzmaParams::new(LzmaProperties { lc, lp, pb }, dictionary, Some(want as u64));
    let memory_limit: usize = MAX_LZMA_DICTIONARY as usize + MAX_PCLUSTER_DECODED;
    let mut decoder: LzmaDecoder = LzmaDecoder::new(params, Some(memory_limit))
        .map_err(|error| Error::Erofs(format!("erofs `{path}` microlzma init: {error}")))?;
    let mut cursor: Cursor<&[u8]> = Cursor::new(&stream);
    let mut out: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(want as u64));
    decoder
        .decompress(&mut cursor, &mut out)
        .map_err(|error| Error::Erofs(format!("erofs `{path}` microlzma pcluster: {error}")))?;
    if out.len() != want {
        return Err(Error::Erofs(format!(
            "erofs `{path}` microlzma decoded {} bytes, expected {want}",
            out.len()
        )));
    }
    let consumed: usize = usize::try_from(cursor.position())
        .map_err(|_| Error::Erofs("microlzma input position exceeds host size".to_owned()))?;
    if consumed != stream.len() {
        return Err(Error::Erofs(format!(
            "erofs `{path}` microlzma consumed {consumed} of {} adjusted stream bytes",
            stream.len()
        )));
    }
    Ok(out)
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

fn read_directory(
    bytes: &[u8],
    sb: &ErofsSuperblock,
    compression: ErofsCompressionConfig,
    inode: &ErofsInode,
    max_output: u64,
    path: &str,
) -> Result<Vec<(u64, String, u8)>> {
    let dir_data: Vec<u8> = inode_data(bytes, sb, compression, inode, max_output, path)?;
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
    if sb.feature_incompat & EROFS_FEATURE_INCOMPAT_48BIT != 0 {
        return Err(Error::Erofs(
            "48-bit erofs block and inode addresses are outside this decoder profile".to_owned(),
        ));
    }
    if sb.extra_devices != 0 {
        return Err(Error::Erofs(format!(
            "erofs declares {} external devices; only the primary device is available",
            sb.extra_devices
        )));
    }
    let declared_bytes: u64 = sb
        .blocks
        .checked_mul(u64::from(sb.block_size))
        .ok_or_else(|| Error::Erofs("declared erofs image size overflow".to_owned()))?;
    if declared_bytes == 0 || declared_bytes > bytes.len() as u64 {
        return Err(Error::Erofs(format!(
            "declared erofs image size {declared_bytes} exceeds input length {}",
            bytes.len()
        )));
    }
    let compression: ErofsCompressionConfig = parse_compression_config(bytes, &sb)?;
    let notes: Vec<String> = Vec::new();
    let mut files: Vec<ErofsFile> = Vec::new();
    let mut total: u64 = 0;
    let mut stack: Vec<(u64, String, usize)> = vec![(sb.root_nid, String::new(), 0)];
    let mut visited: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    while let Some((nid, prefix, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(Error::Erofs(format!("directory depth exceeds {MAX_DEPTH}")));
        }
        if files.len() >= MAX_FILES {
            return Err(Error::Erofs(format!("file count reaches {MAX_FILES}")));
        }
        if !visited.insert(nid) {
            continue;
        }
        let inode: ErofsInode = read_inode(bytes, &sb, nid)?;
        let kind: u16 = inode.mode & S_IFMT;
        if kind == S_IFDIR {
            let entries: Vec<(u64, String, u8)> = read_directory(
                bytes,
                &sb,
                compression,
                &inode,
                max_total.saturating_sub(total),
                &prefix,
            )?;
            for (child_nid, name, _ft) in entries.into_iter().rev() {
                let child_path: String = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                stack.push((child_nid, child_path, depth + 1));
            }
        } else if kind == S_IFREG {
            let data: Vec<u8> = inode_data(
                bytes,
                &sb,
                compression,
                &inode,
                max_total.saturating_sub(total),
                &prefix,
            )?;
            total = total
                .checked_add(data.len() as u64)
                .ok_or_else(|| Error::Erofs("walk output total overflow".to_owned()))?;
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
            let data: Vec<u8> = inode_data(
                bytes,
                &sb,
                compression,
                &inode,
                max_total.saturating_sub(total),
                &prefix,
            )?;
            total = total
                .checked_add(data.len() as u64)
                .ok_or_else(|| Error::Erofs("walk output total overflow".to_owned()))?;
            if total > max_total {
                return Err(Error::Erofs(format!("walk exceeds total cap {max_total}")));
            }
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
pub(crate) fn hostile_named_image(name: &str, body: &[u8]) -> Option<Vec<u8>> {
    const DIRECTORY_BLOCK_NAME_AREA_BYTES: usize = 4096 - 4 * 12 - "..".len() - "zz.bin".len() - 1;
    let dropped_by_the_directory_parser_as_a_self_or_parent_link: bool =
        name == "." || name == "..";
    if name.is_empty()
        || name.len() > DIRECTORY_BLOCK_NAME_AREA_BYTES
        || dropped_by_the_directory_parser_as_a_self_or_parent_link
    {
        return None;
    }
    Some(tests::build_hostile_named_erofs(name, body))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const BLK_BITS: u8 = 12;
    const BLK: usize = 4096;
    const EROFS_FT_DIR: u8 = 2;

    pub(super) fn build_hostile_named_erofs(name: &str, body: &[u8]) -> Vec<u8> {
        let owned: Vec<u8> = body.to_vec();
        build_single_file_erofs(name, move |b: &mut ErofsBuilder| {
            let nid: u64 =
                b.write_compact_inode_inline(S_IFREG | 0o755, owned.len() as u32, 0, &owned);
            (nid, owned.len() as u32)
        })
    }

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
            let blocks: u32 = (self.image.len() / BLK) as u32;
            self.image[base..base + 4].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
            self.image[base + 12] = BLK_BITS;
            self.image[base + 14..base + 16].copy_from_slice(&root_nid.to_le_bytes());
            self.image[base + 16..base + 24].copy_from_slice(&8u64.to_le_bytes());
            self.image[base + 36..base + 40].copy_from_slice(&blocks.to_le_bytes());
            self.image[base + 40..base + 44]
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
            let compressed_blocks: u32 = lclusters
                .iter()
                .filter(|entry: &&(u16, u32)| entry.0 & 0x3 != Z_EROFS_LCLUSTER_TYPE_NONHEAD)
                .count() as u32;
            self.image[off + 16..off + 20].copy_from_slice(&compressed_blocks.to_le_bytes());
            let header_off: usize = off + 32;
            self.image[header_off + 6] = algorithm & 0x0f;
            self.image[header_off + 7] = clusterbits_delta & 0x0f;
            let index_off: usize = header_off + 16;
            for (i, (di_advise, blkaddr)) in lclusters.iter().enumerate() {
                let slot: usize = index_off + i * 8;
                self.image[slot..slot + 2].copy_from_slice(&di_advise.to_le_bytes());
                self.image[slot + 4..slot + 8].copy_from_slice(&blkaddr.to_le_bytes());
            }
            let inline_bytes: usize = 16 + lclusters.len() * 8;
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
    fn reads_superblock_fields_from_the_official_layout() {
        let mut image: Vec<u8> = vec![0u8; EROFS_SUPER_OFFSET + 144];
        let base: usize = EROFS_SUPER_OFFSET;
        let root_nid: u16 = 0x1234;
        let inos: u64 = 0x0102_0304_0506_0708;
        let meta_blkaddr: u32 = 0x1122_3344;
        image[base..base + 4].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
        image[base + 12] = BLK_BITS;
        image[base + 14..base + 16].copy_from_slice(&root_nid.to_le_bytes());
        image[base + 16..base + 24].copy_from_slice(&inos.to_le_bytes());
        image[base + 40..base + 44].copy_from_slice(&meta_blkaddr.to_le_bytes());

        let sb: ErofsSuperblock = detect_erofs(&image).expect("erofs superblock");
        assert_eq!(sb.root_nid, u64::from(root_nid));
        assert_eq!(sb.inos, inos);
        assert_eq!(sb.meta_blkaddr, meta_blkaddr);
    }

    #[test]
    fn official_lzma_config_and_microlzma_stream_are_exact() {
        use sha2::{Digest as _, Sha256};

        const IMAGE: &[u8] = include_bytes!("../../tests/fixtures/erofs/lzma-full-big-xattr.erofs");
        let sb: ErofsSuperblock = detect_erofs(IMAGE).expect("erofs superblock");
        let compression: ErofsCompressionConfig =
            parse_compression_config(IMAGE, &sb).expect("compression config");
        assert_eq!(compression.lzma_dictionary, Some(4096));
        let pcluster: &[u8] = &IMAGE[4096..12_288];
        let decoded: Vec<u8> = decode_microlzma(compression, pcluster, 21_490, BLK, "payload.txt")
            .expect("microlzma decode");
        assert_eq!(
            format!("{:x}", Sha256::digest(&decoded)),
            "422a25f7bdda720a7255d39352d9afd205183362db2e91fe26a4326118ae5b87"
        );

        let mut invalid_property: Vec<u8> = pcluster.to_vec();
        let property_offset: usize = invalid_property
            .iter()
            .position(|byte: &u8| *byte != 0)
            .expect("property byte");
        invalid_property[property_offset] = !225u8;
        assert!(decode_microlzma(compression, &invalid_property, 21_490, BLK, "bad").is_err());

        let truncated: &[u8] = &pcluster[..pcluster.len() - 16];
        assert!(decode_microlzma(compression, truncated, 21_490, BLK, "short").is_err());

        let mut trailing: Vec<u8> = pcluster.to_vec();
        trailing.push(0x5a);
        assert!(decode_microlzma(compression, &trailing, 21_490, BLK, "trailing").is_err());
    }

    #[test]
    fn malformed_lzma_configs_refuse_before_decode() {
        const IMAGE: &[u8] = include_bytes!("../../tests/fixtures/erofs/lzma-full-big-xattr.erofs");
        let mut image: Vec<u8> = IMAGE.to_vec();
        let sb: ErofsSuperblock = detect_erofs(&image).expect("erofs superblock");

        image[1154..1158].copy_from_slice(&4095u32.to_le_bytes());
        assert!(parse_compression_config(&image, &sb).is_err());

        image.copy_from_slice(IMAGE);
        image[1158..1160].copy_from_slice(&1u16.to_le_bytes());
        assert!(parse_compression_config(&image, &sb).is_err());

        image.copy_from_slice(IMAGE);
        image[1152..1154].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(parse_compression_config(&image, &sb).is_err());
    }

    #[test]
    fn official_full_index_supports_head2_and_rejects_bad_links() {
        use sha2::{Digest as _, Sha256};

        const IMAGE: &[u8] = include_bytes!("../../tests/fixtures/erofs/lzma-full-big-xattr.erofs");
        let mut head2: Vec<u8> = IMAGE.to_vec();
        let feature_incompat: u32 = rd_u32(&head2, EROFS_SUPER_OFFSET + 80)
            .expect("feature incompatibility bitmap")
            | EROFS_FEATURE_INCOMPAT_COMPR_HEAD2;
        head2[EROFS_SUPER_OFFSET + 80..EROFS_SUPER_OFFSET + 84]
            .copy_from_slice(&feature_incompat.to_le_bytes());
        head2[1428..1430].copy_from_slice(
            &(Z_EROFS_ADVISE_BIG_PCLUSTER_1 | Z_EROFS_ADVISE_BIG_PCLUSTER_2).to_le_bytes(),
        );
        head2[1430] = Z_EROFS_ALGO_LZMA << 4;
        for offset in [1440usize, 1480] {
            head2[offset..offset + 2].copy_from_slice(&Z_EROFS_LCLUSTER_TYPE_HEAD2.to_le_bytes());
        }
        let walk: ErofsWalk = walk_erofs(&head2, 1 << 20).expect("head2 walk");
        let payload: &ErofsFile = walk
            .files
            .iter()
            .find(|file: &&ErofsFile| file.path == "payload.txt")
            .expect("payload");
        assert_eq!(
            format!("{:x}", Sha256::digest(&payload.data)),
            "e7807e2e9a4b306c2c83d38059553aa2f67bc5aeec0ea2f8594adf5a634070b6"
        );

        let mut missing_head2_feature: Vec<u8> = head2.clone();
        missing_head2_feature[EROFS_SUPER_OFFSET + 80..EROFS_SUPER_OFFSET + 84].copy_from_slice(
            &(feature_incompat & !EROFS_FEATURE_INCOMPAT_COMPR_HEAD2).to_le_bytes(),
        );
        assert!(walk_erofs(&missing_head2_feature, 1 << 20).is_err());

        let mut invalid_lookback: Vec<u8> = IMAGE.to_vec();
        invalid_lookback[1452..1454].copy_from_slice(&0u16.to_le_bytes());
        assert!(walk_erofs(&invalid_lookback, 1 << 20).is_err());

        let mut misplaced_count: Vec<u8> = IMAGE.to_vec();
        misplaced_count[1460..1462].copy_from_slice(&(Z_EROFS_LI_D0_CBLKCNT | 2).to_le_bytes());
        assert!(walk_erofs(&misplaced_count, 1 << 20).is_err());

        let mut partial: Vec<u8> = IMAGE.to_vec();
        partial[1440..1442]
            .copy_from_slice(&(Z_EROFS_LCLUSTER_TYPE_HEAD1 | Z_EROFS_LI_PARTIAL_REF).to_le_bytes());
        assert!(walk_erofs(&partial, 1 << 20).is_err());
    }

    #[test]
    fn full_index_hole_flag_overrides_a_non_null_physical_address() {
        let size: u32 = 128;
        let image: Vec<u8> = build_single_file_erofs("hole.bin", move |b: &mut ErofsBuilder| {
            let nid: u64 = b.write_compressed_full_inode(
                S_IFREG | 0o644,
                size,
                Z_EROFS_ALGO_LZ4,
                0,
                &[(Z_EROFS_LCLUSTER_TYPE_PLAIN | Z_EROFS_LI_HOLE, 7)],
            );
            (nid, size)
        });
        let walk: ErofsWalk = walk_erofs(&image, 1 << 20).expect("hole walk");
        let file: &ErofsFile = walk
            .files
            .iter()
            .find(|file: &&ErofsFile| file.path == "hole.bin")
            .expect("hole file");
        assert_eq!(file.data, vec![0; size as usize]);
    }

    #[test]
    fn primary_device_chunk_indexes_reject_high_and_external_addresses() {
        let sb: ErofsSuperblock = ErofsSuperblock {
            blkszbits: BLK_BITS,
            block_size: BLK as u32,
            sb_extslots: 0,
            root_nid: 0,
            inos: 1,
            blocks: 2,
            meta_blkaddr: 0,
            feature_incompat: 0,
            available_compr_algs: 0,
            extra_devices: 0,
        };
        let inode: ErofsInode = ErofsInode {
            format: EROFS_INODE_CHUNK_BASED,
            mode: S_IFREG,
            size: 1,
            raw_blkaddr: u32::from(EROFS_CHUNK_FORMAT_INDEXES),
            xattr_icount: 0,
            inode_slot_end: 0,
        };
        let mut image: Vec<u8> = vec![0; BLK * 2];
        image[0..2].copy_from_slice(&1u16.to_le_bytes());
        image[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(chunk_based_data(&image, &sb, &inode, "high.bin").is_err());

        image[0..2].copy_from_slice(&0u16.to_le_bytes());
        image[2..4].copy_from_slice(&1u16.to_le_bytes());
        assert!(chunk_based_data(&image, &sb, &inode, "device.bin").is_err());
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
        let dir: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-erofs-e2e")
                .expect("create scratch dir");
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::Erofs, &image, dir.path())
                .expect("erofs extract");
        assert_eq!(result.kind, crate::container::ContainerKind::Erofs);
        assert_eq!(
            std::fs::read(dir.path().join("plain.bin")).expect("plain"),
            body_plain
        );
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

    const TRAILING_NAME_AREA_SENTINEL: &str = "zz.bin";

    fn build_single_file_erofs<F>(name: &str, make_inode: F) -> Vec<u8>
    where
        F: FnOnce(&mut ErofsBuilder) -> (u64, u32),
    {
        let mut b: ErofsBuilder = ErofsBuilder::new(24, 2, 6);
        let root_dir_blk: u32 = b.alloc_data_block(1);
        let root_nid: u64 = b.write_compact_inode_flat_plain(S_IFDIR | 0o755, 0, root_dir_blk);
        let (file_nid, _size): (u64, u32) = make_inode(&mut b);
        let sentinel_nid: u64 = b.write_compact_inode_inline(S_IFREG | 0o644, 0, 0, &[]);
        b.put_dir_block(
            root_dir_blk,
            &[
                (root_nid, ".", EROFS_FT_DIR),
                (root_nid, "..", EROFS_FT_DIR),
                (file_nid, name, 1),
                (sentinel_nid, TRAILING_NAME_AREA_SENTINEL, 1),
            ],
        );
        let root_dir_size: u32 = {
            let header: usize = 4 * 12;
            let names: usize =
                ".".len() + "..".len() + name.len() + TRAILING_NAME_AREA_SENTINEL.len();
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
        let image: Vec<u8> = build_single_file_erofs("file.bin", move |b: &mut ErofsBuilder| {
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
        let image: Vec<u8> = build_single_file_erofs("file.bin", move |b: &mut ErofsBuilder| {
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
        let image: Vec<u8> = build_single_file_erofs("file.bin", move |b: &mut ErofsBuilder| {
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
        let image: Vec<u8> = build_single_file_erofs("file.bin", move |b: &mut ErofsBuilder| {
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
