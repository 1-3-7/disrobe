use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const SQUASHFS_MAGIC_LE: u32 = 0x7371_7368;
pub const SQUASHFS_MAGIC_BE: u32 = 0x6873_7173;
pub const SUPERBLOCK_MIN_BYTES: usize = 96;

const MAGIC_HSQS: [u8; 4] = [0x68, 0x73, 0x71, 0x73];
const MAGIC_SQSH: [u8; 4] = [0x73, 0x71, 0x73, 0x68];
const MAGIC_SHSQ: [u8; 4] = [0x73, 0x68, 0x73, 0x71];
const MAGIC_QSHS: [u8; 4] = [0x71, 0x73, 0x68, 0x73];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SquashfsVendor {
    Standard,
    LzmaSwap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SquashfsCompression {
    Gzip,
    Lzma,
    Lzo,
    Xz,
    Lz4,
    Zstd,
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SquashfsSuperblock {
    pub inode_count: u32,
    pub block_size: u32,
    pub fragment_count: u32,
    pub compression: SquashfsCompression,
    pub version_major: u16,
    pub version_minor: u16,
    pub bytes_used: u64,
    pub little_endian: bool,
    pub vendor: SquashfsVendor,
}

const fn classify_magic(magic: [u8; 4]) -> Option<(bool, SquashfsVendor)> {
    match magic {
        MAGIC_HSQS => Some((true, SquashfsVendor::Standard)),
        MAGIC_SQSH => Some((false, SquashfsVendor::Standard)),
        MAGIC_SHSQ => Some((true, SquashfsVendor::LzmaSwap)),
        MAGIC_QSHS => Some((false, SquashfsVendor::LzmaSwap)),
        _ => None,
    }
}

pub fn parse_squashfs_superblock(bytes: &[u8], offset: usize) -> Result<SquashfsSuperblock> {
    let end: usize = offset
        .checked_add(SUPERBLOCK_MIN_BYTES)
        .ok_or_else(|| Error::Decompression("squashfs offset overflow".to_owned()))?;
    if bytes.len() < end {
        return Err(Error::Decompression(
            "squashfs superblock truncated".to_owned(),
        ));
    }
    let header: &[u8] = &bytes[offset..end];
    let magic: [u8; 4] = [header[0], header[1], header[2], header[3]];
    let Some((little_endian, vendor)): Option<(bool, SquashfsVendor)> = classify_magic(magic)
    else {
        let magic_le_read: u32 = u32::from_le_bytes(magic);
        return Err(Error::Decompression(format!(
            "squashfs magic mismatch: 0x{magic_le_read:08x}"
        )));
    };
    let endian: Endian = if little_endian {
        Endian::Little
    } else {
        Endian::Big
    };
    let version_major: u16 = endian.u16(header, 28);
    let version_minor: u16 = endian.u16(header, 30);
    let inode_count: u32 = endian.u32(header, 4);

    if version_major == 4 {
        let compression: SquashfsCompression = compression_from_id(endian.u16(header, 20));
        return Ok(SquashfsSuperblock {
            inode_count,
            block_size: endian.u32(header, 12),
            fragment_count: endian.u32(header, 16),
            compression,
            version_major,
            version_minor,
            bytes_used: endian.u64(header, 40),
            little_endian,
            vendor,
        });
    }

    if (1..=3).contains(&version_major) {
        let block_size: u32 = if version_major == 1 {
            u32::from(endian.u16(header, 32))
        } else {
            endian.u32(header, 52)
        };
        let bytes_used: u64 = if version_major == 3 {
            endian.u64(header, 64)
        } else {
            u64::from(endian.u32(header, 8))
        };
        let fragment_count: u32 = if version_major >= 2 {
            endian.u32(header, 56)
        } else {
            0
        };
        let compression: SquashfsCompression = match vendor {
            SquashfsVendor::LzmaSwap => SquashfsCompression::Lzma,
            SquashfsVendor::Standard => SquashfsCompression::Gzip,
        };
        return Ok(SquashfsSuperblock {
            inode_count,
            block_size,
            fragment_count,
            compression,
            version_major,
            version_minor,
            bytes_used,
            little_endian,
            vendor,
        });
    }

    Err(Error::Decompression(format!(
        "squashfs unsupported major version {version_major}"
    )))
}

const fn compression_from_id(compression_id: u16) -> SquashfsCompression {
    match compression_id {
        1 => SquashfsCompression::Gzip,
        2 => SquashfsCompression::Lzma,
        3 => SquashfsCompression::Lzo,
        4 => SquashfsCompression::Xz,
        5 => SquashfsCompression::Lz4,
        6 => SquashfsCompression::Zstd,
        other => SquashfsCompression::Unknown(other),
    }
}

const INODE_TYPE_DIR: u16 = 1;
const INODE_TYPE_FILE: u16 = 2;
const INODE_TYPE_SYMLINK: u16 = 3;
const INODE_TYPE_EXT_DIR: u16 = 8;
const INODE_TYPE_EXT_FILE: u16 = 9;
const METADATA_UNCOMPRESSED_FLAG: u16 = 0x8000;
const METADATA_SIZE_MASK: u16 = 0x7FFF;
const FRAGMENT_UNCOMPRESSED_FLAG: u32 = 0x0100_0000;
const FRAGMENT_SIZE_MASK: u32 = 0x00FF_FFFF;
const MAX_METADATA_BLOCK: usize = 8192;
const MAX_WALK_FILES: usize = 500_000;
const MAX_PATH_DEPTH: usize = 256;

#[derive(Debug, Clone)]
pub struct SquashfsFile {
    pub path: String,
    pub data: Vec<u8>,
    pub is_executable: bool,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SquashfsWalk {
    pub superblock: SquashfsSuperblock,
    pub files: Vec<SquashfsFile>,
}

#[derive(Debug, Clone, Copy)]
struct RawSuperblock {
    block_size: u32,
    root_inode_ref: u64,
    id_table_start: u64,
    inode_table_start: u64,
    directory_table_start: u64,
    fragment_table_start: u64,
    fragment_entry_count: u32,
}

#[derive(Debug, Clone, Copy)]
struct FragmentEntry {
    start: u64,
    size: u32,
    compressed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    #[inline]
    fn u16(self, b: &[u8], at: usize) -> u16 {
        let s: [u8; 2] = [b[at], b[at + 1]];
        match self {
            Self::Little => u16::from_le_bytes(s),
            Self::Big => u16::from_be_bytes(s),
        }
    }

    #[inline]
    fn u32(self, b: &[u8], at: usize) -> u32 {
        let s: [u8; 4] = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        match self {
            Self::Little => u32::from_le_bytes(s),
            Self::Big => u32::from_be_bytes(s),
        }
    }

    #[inline]
    fn u64(self, b: &[u8], at: usize) -> u64 {
        let s: [u8; 8] = [
            b[at],
            b[at + 1],
            b[at + 2],
            b[at + 3],
            b[at + 4],
            b[at + 5],
            b[at + 6],
            b[at + 7],
        ];
        match self {
            Self::Little => u64::from_le_bytes(s),
            Self::Big => u64::from_be_bytes(s),
        }
    }

    #[inline]
    fn u16_opt(self, b: &[u8], at: usize) -> Option<u16> {
        let s: &[u8] = b.get(at..at + 2)?;
        Some(match self {
            Self::Little => u16::from_le_bytes([s[0], s[1]]),
            Self::Big => u16::from_be_bytes([s[0], s[1]]),
        })
    }
}

pub fn walk_squashfs(bytes: &[u8], base: usize, max_total: u64) -> Result<SquashfsWalk> {
    let superblock: SquashfsSuperblock = parse_squashfs_superblock(bytes, base)?;
    if superblock.version_major != 4 {
        return Err(Error::Squashfs(format!(
            "squashfs walker recovers member bytes for v4 only; superblock reports v{}.{}",
            superblock.version_major, superblock.version_minor
        )));
    }
    let endian: Endian = if superblock.little_endian {
        Endian::Little
    } else {
        Endian::Big
    };
    let raw: RawSuperblock = read_raw_superblock(bytes, base, endian)?;
    let compression: SquashfsCompression = superblock.compression;
    let fragments: Vec<FragmentEntry> =
        read_fragment_table(bytes, base, &raw, compression, endian)?;

    let mut files: Vec<SquashfsFile> = Vec::new();
    let mut total: u64 = 0;
    let (root_block, root_offset): (u64, u16) = decode_inode_ref(raw.root_inode_ref);
    let mut stack: Vec<(u64, u16, String, usize)> =
        vec![(root_block, root_offset, String::new(), 0)];
    let mut visited: std::collections::BTreeSet<(u64, u16)> = std::collections::BTreeSet::new();

    while let Some((blk, off, prefix, depth)) = stack.pop() {
        if depth > MAX_PATH_DEPTH || files.len() > MAX_WALK_FILES {
            break;
        }
        if !visited.insert((blk, off)) {
            continue;
        }
        let inode: ParsedInode = read_inode(bytes, base, &raw, compression, endian, blk, off)?;
        match inode {
            ParsedInode::Directory {
                dir_block_start,
                file_size,
                block_offset,
            } => {
                let children: Vec<(u64, u16, String)> = read_directory(
                    bytes,
                    base,
                    &raw,
                    compression,
                    endian,
                    dir_block_start,
                    block_offset,
                    file_size,
                )?;
                for (cblk, coff, name) in children {
                    let child_path: String = if prefix.is_empty() {
                        name
                    } else {
                        format!("{prefix}/{name}")
                    };
                    stack.push((cblk, coff, child_path, depth + 1));
                }
            }
            ParsedInode::File(meta) => {
                let data: Vec<u8> =
                    read_file_data(bytes, base, &raw, compression, &fragments, &meta)?;
                total = total.saturating_add(data.len() as u64);
                if total > max_total {
                    return Err(Error::Squashfs(format!(
                        "squashfs walk exceeds total cap {max_total}"
                    )));
                }
                files.push(SquashfsFile {
                    path: prefix,
                    is_executable: meta.permissions & 0o111 != 0,
                    data,
                    is_symlink: false,
                    symlink_target: None,
                });
            }
            ParsedInode::Symlink { target } => {
                files.push(SquashfsFile {
                    path: prefix,
                    data: Vec::new(),
                    is_executable: false,
                    is_symlink: true,
                    symlink_target: Some(target),
                });
            }
            ParsedInode::Other => {}
        }
    }

    Ok(SquashfsWalk { superblock, files })
}

#[derive(Debug)]
enum ParsedInode {
    Directory {
        dir_block_start: u32,
        file_size: u32,
        block_offset: u16,
    },
    File(FileInode),
    Symlink {
        target: String,
    },
    Other,
}

#[derive(Debug, Clone)]
struct FileInode {
    blocks_start: u64,
    fragment_block_index: u32,
    block_offset: u32,
    file_size: u64,
    permissions: u16,
    block_sizes: Vec<u32>,
}

impl RawSuperblock {
    const fn inode_table_end(&self, total: u64) -> u64 {
        if self.directory_table_start > self.inode_table_start
            && self.directory_table_start <= total
        {
            self.directory_table_start
        } else {
            total
        }
    }

    fn directory_table_end(&self, total: u64) -> u64 {
        let candidates: [u64; 2] = [self.fragment_table_start, self.id_table_start];
        let mut end: u64 = total;
        for &c in &candidates {
            if c > self.directory_table_start && c <= total && c < end {
                end = c;
            }
        }
        end
    }
}

fn read_raw_superblock(bytes: &[u8], base: usize, endian: Endian) -> Result<RawSuperblock> {
    let sb: &[u8] = bytes
        .get(base..base + SUPERBLOCK_MIN_BYTES)
        .ok_or_else(|| Error::Squashfs("superblock truncated".to_owned()))?;
    Ok(RawSuperblock {
        block_size: endian.u32(sb, 0x0C),
        fragment_entry_count: endian.u32(sb, 0x10),
        root_inode_ref: endian.u64(sb, 0x20),
        id_table_start: endian.u64(sb, 0x30),
        inode_table_start: endian.u64(sb, 0x40),
        directory_table_start: endian.u64(sb, 0x48),
        fragment_table_start: endian.u64(sb, 0x50),
    })
}

const fn decode_inode_ref(reference: u64) -> (u64, u16) {
    let block: u64 = (reference >> 16) & 0xFFFF_FFFF;
    let offset: u16 = (reference & 0xFFFF) as u16;
    (block, offset)
}

fn read_inode(
    bytes: &[u8],
    base: usize,
    raw: &RawSuperblock,
    compression: SquashfsCompression,
    endian: Endian,
    block: u64,
    offset: u16,
) -> Result<ParsedInode> {
    let total: u64 = (bytes.len() as u64).saturating_sub(base as u64);
    let table: Vec<u8> = read_metadata_at(
        bytes,
        base,
        raw.inode_table_start,
        block,
        compression,
        endian,
        offset as usize + 256,
        raw.inode_table_end(total),
    )?;
    let cur: &[u8] = table
        .get(offset as usize..)
        .ok_or_else(|| Error::Squashfs("inode offset past metadata block".to_owned()))?;
    if cur.len() < 16 {
        return Err(Error::Squashfs("inode header truncated".to_owned()));
    }
    let inode_type: u16 = endian.u16(cur, 0);
    let permissions: u16 = endian.u16(cur, 2);
    match inode_type {
        INODE_TYPE_DIR => {
            if cur.len() < 32 {
                return Err(Error::Squashfs("basic dir inode truncated".to_owned()));
            }
            Ok(ParsedInode::Directory {
                dir_block_start: endian.u32(cur, 16),
                file_size: u32::from(endian.u16(cur, 24)),
                block_offset: endian.u16(cur, 26),
            })
        }
        INODE_TYPE_EXT_DIR => {
            if cur.len() < 40 {
                return Err(Error::Squashfs("ext dir inode truncated".to_owned()));
            }
            Ok(ParsedInode::Directory {
                dir_block_start: endian.u32(cur, 24),
                file_size: endian.u32(cur, 20),
                block_offset: endian.u16(cur, 34),
            })
        }
        INODE_TYPE_FILE => parse_basic_file(cur, raw, endian, permissions),
        INODE_TYPE_EXT_FILE => parse_ext_file(cur, raw, endian, permissions),
        INODE_TYPE_SYMLINK => parse_symlink(cur, endian),
        _ => Ok(ParsedInode::Other),
    }
}

fn parse_basic_file(
    cur: &[u8],
    raw: &RawSuperblock,
    endian: Endian,
    permissions: u16,
) -> Result<ParsedInode> {
    if cur.len() < 32 {
        return Err(Error::Squashfs("basic file inode truncated".to_owned()));
    }
    let blocks_start: u64 = u64::from(endian.u32(cur, 16));
    let fragment_block_index: u32 = endian.u32(cur, 20);
    let block_offset: u32 = endian.u32(cur, 24);
    let file_size: u64 = u64::from(endian.u32(cur, 28));
    let block_sizes: Vec<u32> =
        read_block_sizes(cur, 32, raw, endian, fragment_block_index, file_size)?;
    Ok(ParsedInode::File(FileInode {
        blocks_start,
        fragment_block_index,
        block_offset,
        file_size,
        permissions,
        block_sizes,
    }))
}

fn parse_ext_file(
    cur: &[u8],
    raw: &RawSuperblock,
    endian: Endian,
    permissions: u16,
) -> Result<ParsedInode> {
    if cur.len() < 56 {
        return Err(Error::Squashfs("ext file inode truncated".to_owned()));
    }
    let blocks_start: u64 = endian.u64(cur, 16);
    let file_size: u64 = endian.u64(cur, 24);
    let fragment_block_index: u32 = endian.u32(cur, 44);
    let block_offset: u32 = endian.u32(cur, 48);
    let block_sizes: Vec<u32> =
        read_block_sizes(cur, 56, raw, endian, fragment_block_index, file_size)?;
    Ok(ParsedInode::File(FileInode {
        blocks_start,
        fragment_block_index,
        block_offset,
        file_size,
        permissions,
        block_sizes,
    }))
}

fn parse_symlink(cur: &[u8], endian: Endian) -> Result<ParsedInode> {
    if cur.len() < 24 {
        return Err(Error::Squashfs("symlink inode truncated".to_owned()));
    }
    let target_size: usize = endian.u32(cur, 20) as usize;
    let target_bytes: &[u8] = cur
        .get(24..24 + target_size)
        .ok_or_else(|| Error::Squashfs("symlink target truncated".to_owned()))?;
    Ok(ParsedInode::Symlink {
        target: String::from_utf8_lossy(target_bytes).into_owned(),
    })
}

fn read_block_sizes(
    cur: &[u8],
    start: usize,
    raw: &RawSuperblock,
    endian: Endian,
    fragment_block_index: u32,
    file_size: u64,
) -> Result<Vec<u32>> {
    let block_size: u64 = u64::from(raw.block_size).max(1);
    let has_fragment: bool = fragment_block_index != 0xFFFF_FFFF;
    let full_blocks: u64 = if has_fragment {
        file_size / block_size
    } else {
        file_size.div_ceil(block_size)
    };
    let count: usize = usize::try_from(full_blocks).map_err(|_e: std::num::TryFromIntError| {
        Error::Squashfs("block count overflow".to_owned())
    })?;
    if count > 1_000_000 {
        return Err(Error::Squashfs("implausible block count".to_owned()));
    }
    let mut sizes: Vec<u32> = Vec::with_capacity(count);
    for i in 0..count {
        let at: usize = start + i * 4;
        if at + 4 > cur.len() {
            return Err(Error::Squashfs(
                "file inode block_sizes truncated".to_owned(),
            ));
        }
        sizes.push(endian.u32(cur, at));
    }
    Ok(sizes)
}

fn read_directory(
    bytes: &[u8],
    base: usize,
    raw: &RawSuperblock,
    compression: SquashfsCompression,
    endian: Endian,
    dir_block_start: u32,
    block_offset: u16,
    file_size: u32,
) -> Result<Vec<(u64, u16, String)>> {
    let want: usize = block_offset as usize + file_size as usize;
    let total: u64 = (bytes.len() as u64).saturating_sub(base as u64);
    let table: Vec<u8> = read_metadata_at(
        bytes,
        base,
        raw.directory_table_start,
        u64::from(dir_block_start),
        compression,
        endian,
        want,
        raw.directory_table_end(total),
    )?;
    let start: usize = block_offset as usize;
    let end: usize = (start + file_size.saturating_sub(3) as usize).min(table.len());
    let region: &[u8] = table
        .get(start..end)
        .map_or(&[] as &[u8], |value: &[u8]| value);
    let mut out: Vec<(u64, u16, String)> = Vec::new();
    let mut pos: usize = 0;
    while pos + 12 <= region.len() {
        let count: u32 = endian.u32(region, pos);
        let inode_start: u32 = endian.u32(region, pos + 4);
        pos += 12;
        let entries: u32 = count.saturating_add(1);
        if entries > 1_000_000 {
            break;
        }
        for _ in 0..entries {
            if pos + 8 > region.len() {
                return Ok(out);
            }
            let entry_offset: u16 = endian.u16(region, pos);
            let entry_type: u16 = endian.u16(region, pos + 4);
            let name_size: usize = endian.u16(region, pos + 6) as usize + 1;
            pos += 8;
            let name_bytes: &[u8] = match region.get(pos..pos + name_size) {
                Some(n) => n,
                None => return Ok(out),
            };
            pos += name_size;
            let name: String = String::from_utf8_lossy(name_bytes).into_owned();
            let basic_type: u16 = if entry_type > 7 {
                entry_type - 7
            } else {
                entry_type
            };
            let _ = basic_type;
            out.push((u64::from(inode_start), entry_offset, name));
        }
    }
    Ok(out)
}

fn read_file_data(
    bytes: &[u8],
    base: usize,
    raw: &RawSuperblock,
    compression: SquashfsCompression,
    fragments: &[FragmentEntry],
    meta: &FileInode,
) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(meta.file_size.min(64 * 1024 * 1024) as usize);
    let mut cursor: u64 = base as u64 + meta.blocks_start;
    for &size_word in &meta.block_sizes {
        let on_disk: u32 = size_word & 0x00FF_FFFF;
        let uncompressed: bool = size_word & 0x0100_0000 != 0;
        let start: usize = usize::try_from(cursor).map_err(|_e: std::num::TryFromIntError| {
            Error::Squashfs("block offset overflow".to_owned())
        })?;
        if on_disk == 0 {
            let zeros: usize = (u64::from(raw.block_size)).min(meta.file_size) as usize;
            out.extend(std::iter::repeat_n(0u8, zeros));
            continue;
        }
        let chunk: &[u8] = bytes
            .get(start..start + on_disk as usize)
            .ok_or_else(|| Error::Squashfs("data block past end of input".to_owned()))?;
        let block: Vec<u8> = if uncompressed {
            chunk.to_vec()
        } else {
            decompress_block(chunk, compression, raw.block_size as usize)?
        };
        out.extend_from_slice(&block);
        cursor += u64::from(on_disk);
    }
    let tail: u64 = meta.file_size - (out.len() as u64).min(meta.file_size);
    if tail > 0 && meta.fragment_block_index != 0xFFFF_FFFF {
        let frag: &FragmentEntry = fragments
            .get(meta.fragment_block_index as usize)
            .ok_or_else(|| Error::Squashfs("fragment index out of range".to_owned()))?;
        let frag_block: Vec<u8> =
            read_fragment_block(bytes, base, frag, compression, raw.block_size as usize)?;
        let off: usize = meta.block_offset as usize;
        let end: usize = off + tail as usize;
        let slice: &[u8] = frag_block
            .get(off..end)
            .ok_or_else(|| Error::Squashfs("fragment slice out of range".to_owned()))?;
        out.extend_from_slice(slice);
    }
    out.truncate(meta.file_size as usize);
    Ok(out)
}

fn read_fragment_block(
    bytes: &[u8],
    base: usize,
    frag: &FragmentEntry,
    compression: SquashfsCompression,
    block_size: usize,
) -> Result<Vec<u8>> {
    let start: usize =
        usize::try_from(base as u64 + frag.start).map_err(|_e: std::num::TryFromIntError| {
            Error::Squashfs("fragment offset overflow".to_owned())
        })?;
    let chunk: &[u8] = bytes
        .get(start..start + frag.size as usize)
        .ok_or_else(|| Error::Squashfs("fragment block past end of input".to_owned()))?;
    if frag.compressed {
        decompress_block(chunk, compression, block_size)
    } else {
        Ok(chunk.to_vec())
    }
}

fn read_fragment_table(
    bytes: &[u8],
    base: usize,
    raw: &RawSuperblock,
    compression: SquashfsCompression,
    endian: Endian,
) -> Result<Vec<FragmentEntry>> {
    if raw.fragment_entry_count == 0 || raw.fragment_table_start == 0 {
        return Ok(Vec::new());
    }
    let index_count: usize = raw.fragment_entry_count.div_ceil(512) as usize;
    let index_start: usize = usize::try_from(base as u64 + raw.fragment_table_start).map_err(
        |_e: std::num::TryFromIntError| Error::Squashfs("fragment index overflow".to_owned()),
    )?;
    let index_bytes: &[u8] = bytes
        .get(index_start..index_start + index_count * 8)
        .ok_or_else(|| Error::Squashfs("fragment index table truncated".to_owned()))?;
    let mut entries: Vec<FragmentEntry> =
        Vec::with_capacity((raw.fragment_entry_count as usize).min(bytes.len() / 16));
    for i in 0..index_count {
        let block_loc: u64 = endian.u64(index_bytes, i * 8);
        let block: Vec<u8> = read_one_metadata_block(bytes, base, block_loc, compression, endian)?;
        let mut pos: usize = 0;
        while pos + 16 <= block.len() && entries.len() < raw.fragment_entry_count as usize {
            let start: u64 = endian.u64(&block, pos);
            let size_word: u32 = endian.u32(&block, pos + 8);
            entries.push(FragmentEntry {
                start,
                size: size_word & FRAGMENT_SIZE_MASK,
                compressed: size_word & FRAGMENT_UNCOMPRESSED_FLAG == 0,
            });
            pos += 16;
        }
    }
    let _ = raw.id_table_start;
    Ok(entries)
}

fn read_metadata_at(
    bytes: &[u8],
    base: usize,
    table_start: u64,
    block: u64,
    compression: SquashfsCompression,
    endian: Endian,
    want_bytes: usize,
    table_end: u64,
) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut loc: u64 = table_start + block;
    let mut guard: usize = 0;
    while out.len() < want_bytes.min(MAX_METADATA_BLOCK * 64) {
        if loc >= table_end {
            break;
        }
        let (decoded, next): (Vec<u8>, u64) =
            match read_metadata_block_at(bytes, base, loc, compression, endian) {
                Ok(pair) => pair,
                Err(e) => {
                    if out.is_empty() {
                        return Err(e);
                    }
                    break;
                }
            };
        let empty: bool = decoded.is_empty();
        out.extend_from_slice(&decoded);
        loc = next;
        guard += 1;
        if empty || guard > 4096 {
            break;
        }
    }
    Ok(out)
}

fn read_one_metadata_block(
    bytes: &[u8],
    base: usize,
    loc: u64,
    compression: SquashfsCompression,
    endian: Endian,
) -> Result<Vec<u8>> {
    let (decoded, _next): (Vec<u8>, u64) =
        read_metadata_block_at(bytes, base, loc, compression, endian)?;
    Ok(decoded)
}

fn read_metadata_block_at(
    bytes: &[u8],
    base: usize,
    loc: u64,
    compression: SquashfsCompression,
    endian: Endian,
) -> Result<(Vec<u8>, u64)> {
    let at: usize =
        usize::try_from(base as u64 + loc).map_err(|_e: std::num::TryFromIntError| {
            Error::Squashfs("metadata loc overflow".to_owned())
        })?;
    let header: u16 = endian
        .u16_opt(bytes, at)
        .ok_or_else(|| Error::Squashfs("metadata header out of bounds".to_owned()))?;
    let size: usize = (header & METADATA_SIZE_MASK) as usize;
    let uncompressed: bool = header & METADATA_UNCOMPRESSED_FLAG != 0;
    if size == 0 || size > MAX_METADATA_BLOCK {
        return Ok((Vec::new(), loc + 2));
    }
    let payload: &[u8] = bytes
        .get(at + 2..at + 2 + size)
        .ok_or_else(|| Error::Squashfs("metadata payload out of bounds".to_owned()))?;
    let decoded: Vec<u8> = if uncompressed {
        payload.to_vec()
    } else {
        decompress_block(payload, compression, MAX_METADATA_BLOCK)?
    };
    Ok((decoded, loc + 2 + size as u64))
}

fn decompress_block(input: &[u8], compression: SquashfsCompression, cap: usize) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let limit: u64 = (cap as u64).saturating_mul(2).saturating_add(1024);
    let mut out: Vec<u8> = Vec::new();
    let read: std::io::Result<u64> = match compression {
        SquashfsCompression::Gzip => {
            let mut d: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(input);
            std::io::copy(&mut (&mut d).take(limit), &mut out)
        }
        SquashfsCompression::Xz => {
            let mut d: liblzma::read::XzDecoder<&[u8]> = liblzma::read::XzDecoder::new(input);
            std::io::copy(&mut (&mut d).take(limit), &mut out)
        }
        SquashfsCompression::Zstd => match zstd::stream::read::Decoder::new(input) {
            Ok(mut d) => std::io::copy(&mut (&mut d).take(limit), &mut out),
            Err(e) => return Err(Error::Squashfs(format!("zstd init: {e}"))),
        },
        SquashfsCompression::Lzma => {
            let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(input);
            return lzma_rs::lzma_decompress(&mut reader, &mut out)
                .map(|()| out)
                .map_err(|e: lzma_rs::error::Error| {
                    Error::Squashfs(format!("squashfs lzma decode: {e}"))
                });
        }
        SquashfsCompression::Lz4 => {
            return crate::containers::lz4_block::decompress_bounded(input, cap)
                .map_err(|e: Error| Error::Squashfs(format!("squashfs lz4 block decode: {e}")));
        }
        SquashfsCompression::Lzo => {
            return decompress_lzo_block(input, cap);
        }
        SquashfsCompression::Unknown(_) => {
            return Err(Error::Squashfs(format!(
                "squashfs compressor {compression:?} is not decoded in-tree"
            )));
        }
    };
    read.map_err(|e: std::io::Error| Error::Squashfs(format!("squashfs block decode: {e}")))?;
    Ok(out)
}

fn decompress_lzo_block(input: &[u8], cap: usize) -> Result<Vec<u8>> {
    let bound: usize = cap.saturating_add(1);
    let mut dst: Vec<u8> = vec![0u8; bound];
    let written: usize = lzokay::decompress::decompress(input, &mut dst)
        .map_err(|e: lzokay::Error| Error::Squashfs(format!("squashfs lzo block decode: {e:?}")))?;
    if written > cap {
        return Err(Error::Squashfs(format!(
            "squashfs lzo block decoded to {written} bytes, exceeding block cap {cap}"
        )));
    }
    dst.truncate(written);
    Ok(dst)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_superblock_le() -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; SUPERBLOCK_MIN_BYTES];
        out[0..4].copy_from_slice(&SQUASHFS_MAGIC_LE.to_le_bytes());
        out[4..8].copy_from_slice(&123u32.to_le_bytes());
        out[12..16].copy_from_slice(&131_072u32.to_le_bytes());
        out[16..20].copy_from_slice(&7u32.to_le_bytes());
        out[20..22].copy_from_slice(&6u16.to_le_bytes());
        out[28..30].copy_from_slice(&4u16.to_le_bytes());
        out[30..32].copy_from_slice(&0u16.to_le_bytes());
        out[40..48].copy_from_slice(&999_999u64.to_le_bytes());
        out
    }

    #[test]
    fn parse_le_superblock_zstd() {
        let bytes: Vec<u8> = synth_superblock_le();
        let sb: SquashfsSuperblock =
            parse_squashfs_superblock(&bytes, 0).expect("parse superblock");
        assert_eq!(sb.inode_count, 123);
        assert_eq!(sb.block_size, 131_072);
        assert_eq!(sb.fragment_count, 7);
        assert_eq!(sb.compression, SquashfsCompression::Zstd);
        assert_eq!(sb.version_major, 4);
        assert!(sb.little_endian);
    }

    fn legacy_superblock(major: u16, minor: u16, magic: [u8; 4]) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; SUPERBLOCK_MIN_BYTES];
        out[0..4].copy_from_slice(&magic);
        out[4..8].copy_from_slice(&77u32.to_le_bytes());
        out[8..12].copy_from_slice(&50_000u32.to_le_bytes());
        out[28..30].copy_from_slice(&major.to_le_bytes());
        out[30..32].copy_from_slice(&minor.to_le_bytes());
        out[32..34].copy_from_slice(&8192u16.to_le_bytes());
        out[34..36].copy_from_slice(&13u16.to_le_bytes());
        out[52..56].copy_from_slice(&131_072u32.to_le_bytes());
        out[56..60].copy_from_slice(&3u32.to_le_bytes());
        out[64..72].copy_from_slice(&123_456u64.to_le_bytes());
        out
    }

    #[test]
    fn parse_v1_superblock_uses_16bit_block_size_and_implicit_gzip() {
        let bytes: Vec<u8> = legacy_superblock(1, 0, MAGIC_HSQS);
        let sb: SquashfsSuperblock = parse_squashfs_superblock(&bytes, 0).expect("parse v1");
        assert_eq!(sb.version_major, 1);
        assert_eq!(sb.inode_count, 77);
        assert_eq!(
            sb.block_size, 8192,
            "v1 reads the 16-bit block_size_1 at 0x20"
        );
        assert_eq!(sb.bytes_used, 50_000, "v1 uses bytes_used_2 at 0x08");
        assert_eq!(sb.fragment_count, 0, "v1 predates fragments");
        assert_eq!(sb.compression, SquashfsCompression::Gzip);
        assert_eq!(sb.vendor, SquashfsVendor::Standard);
    }

    #[test]
    fn parse_v2_superblock_uses_32bit_block_size() {
        let bytes: Vec<u8> = legacy_superblock(2, 1, MAGIC_HSQS);
        let sb: SquashfsSuperblock = parse_squashfs_superblock(&bytes, 0).expect("parse v2");
        assert_eq!(sb.version_major, 2);
        assert_eq!(
            sb.block_size, 131_072,
            "v2 reads the 32-bit block_size at 0x34"
        );
        assert_eq!(sb.bytes_used, 50_000, "v2 still uses bytes_used_2 at 0x08");
        assert_eq!(sb.fragment_count, 3);
        assert_eq!(sb.compression, SquashfsCompression::Gzip);
    }

    #[test]
    fn parse_v3_superblock_uses_64bit_bytes_used() {
        let bytes: Vec<u8> = legacy_superblock(3, 0, MAGIC_HSQS);
        let sb: SquashfsSuperblock = parse_squashfs_superblock(&bytes, 0).expect("parse v3");
        assert_eq!(sb.version_major, 3);
        assert_eq!(sb.block_size, 131_072);
        assert_eq!(
            sb.bytes_used, 123_456,
            "v3 uses the 64-bit bytes_used at 0x40"
        );
        assert_eq!(sb.compression, SquashfsCompression::Gzip);
    }

    #[test]
    fn parse_vendor_lzma_swap_magic_reports_lzma() {
        let bytes: Vec<u8> = legacy_superblock(3, 1, MAGIC_SHSQ);
        let sb: SquashfsSuperblock = parse_squashfs_superblock(&bytes, 0).expect("parse shsq");
        assert_eq!(sb.version_major, 3);
        assert!(sb.little_endian);
        assert_eq!(sb.vendor, SquashfsVendor::LzmaSwap);
        assert_eq!(
            sb.compression,
            SquashfsCompression::Lzma,
            "the shsq swapped magic marks the vendor lzma fork"
        );
    }

    #[test]
    fn parse_big_endian_vendor_magic_qshs() {
        let mut bytes: Vec<u8> = vec![0u8; SUPERBLOCK_MIN_BYTES];
        bytes[0..4].copy_from_slice(&MAGIC_QSHS);
        bytes[28..30].copy_from_slice(&3u16.to_be_bytes());
        bytes[52..56].copy_from_slice(&65_536u32.to_be_bytes());
        let sb: SquashfsSuperblock = parse_squashfs_superblock(&bytes, 0).expect("parse qshs");
        assert!(!sb.little_endian, "qshs is the big-endian swapped magic");
        assert_eq!(sb.vendor, SquashfsVendor::LzmaSwap);
        assert_eq!(sb.block_size, 65_536);
    }

    #[test]
    fn walk_rejects_non_v4_superblock() {
        let bytes: Vec<u8> = legacy_superblock(3, 0, MAGIC_HSQS);
        let err: Error = walk_squashfs(&bytes, 0, 1 << 20).unwrap_err();
        assert!(matches!(err, Error::Squashfs(_)));
    }

    #[test]
    fn truncated_superblock_errors() {
        let err: Error = parse_squashfs_superblock(&[0u8; 10], 0).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn bad_magic_errors() {
        let mut bytes: Vec<u8> = vec![0u8; SUPERBLOCK_MIN_BYTES];
        bytes[0..4].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        let err: Error = parse_squashfs_superblock(&bytes, 0).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn parse_with_nonzero_offset() {
        let mut bytes: Vec<u8> = vec![0u8; 200];
        let sb: Vec<u8> = synth_superblock_le();
        bytes[64..64 + SUPERBLOCK_MIN_BYTES].copy_from_slice(&sb);
        let parsed: SquashfsSuperblock =
            parse_squashfs_superblock(&bytes, 64).expect("offset parse");
        assert_eq!(parsed.inode_count, 123);
    }

    fn put_u16(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn put_u32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn uncompressed_metadata(payload: &[u8]) -> Vec<u8> {
        let mut block: Vec<u8> = Vec::with_capacity(payload.len() + 2);
        let header: u16 = METADATA_UNCOMPRESSED_FLAG | (payload.len() as u16 & METADATA_SIZE_MASK);
        put_u16(&mut block, header);
        block.extend_from_slice(payload);
        block
    }

    fn build_real_squashfs(file_name: &str, file_body: &[u8]) -> Vec<u8> {
        let block_size: u32 = 131_072;
        let mut image: Vec<u8> = vec![0u8; SUPERBLOCK_MIN_BYTES];

        let data_offset: u64 = image.len() as u64;
        image.extend_from_slice(file_body);

        let inode_table_start: u64 = image.len() as u64;
        let mut dir_inode: Vec<u8> = Vec::new();
        put_u16(&mut dir_inode, INODE_TYPE_DIR);
        put_u16(&mut dir_inode, 0o755);
        put_u16(&mut dir_inode, 0);
        put_u16(&mut dir_inode, 0);
        put_u32(&mut dir_inode, 0);
        put_u32(&mut dir_inode, 1);
        put_u32(&mut dir_inode, 0);
        put_u32(&mut dir_inode, 1);
        put_u16(&mut dir_inode, 0);
        put_u16(&mut dir_inode, 0);
        put_u32(&mut dir_inode, 0);

        let file_inode_offset: u16 = dir_inode.len() as u16;
        let mut file_inode: Vec<u8> = Vec::new();
        put_u16(&mut file_inode, INODE_TYPE_FILE);
        put_u16(&mut file_inode, 0o755);
        put_u16(&mut file_inode, 0);
        put_u16(&mut file_inode, 0);
        put_u32(&mut file_inode, 0);
        put_u32(&mut file_inode, 2);
        put_u32(&mut file_inode, data_offset as u32);
        put_u32(&mut file_inode, 0xFFFF_FFFF);
        put_u32(&mut file_inode, 0);
        put_u32(&mut file_inode, file_body.len() as u32);
        put_u32(
            &mut file_inode,
            FRAGMENT_UNCOMPRESSED_FLAG | file_body.len() as u32,
        );

        let mut inode_payload: Vec<u8> = Vec::new();
        inode_payload.extend_from_slice(&dir_inode);
        inode_payload.extend_from_slice(&file_inode);
        image.extend_from_slice(&uncompressed_metadata(&inode_payload));

        let directory_table_start: u64 = image.len() as u64;
        let mut dir_payload: Vec<u8> = Vec::new();
        put_u32(&mut dir_payload, 0);
        put_u32(&mut dir_payload, 0);
        put_u32(&mut dir_payload, 1);
        put_u16(&mut dir_payload, file_inode_offset);
        put_u16(&mut dir_payload, 1);
        put_u16(&mut dir_payload, INODE_TYPE_FILE);
        put_u16(&mut dir_payload, file_name.len() as u16 - 1);
        dir_payload.extend_from_slice(file_name.as_bytes());
        image.extend_from_slice(&uncompressed_metadata(&dir_payload));
        let dir_file_size: u32 = dir_payload.len() as u32 + 3;

        let _ = dir_file_size;
        let mut dir_inode_fixed: Vec<u8> = Vec::new();
        put_u16(&mut dir_inode_fixed, INODE_TYPE_DIR);
        put_u16(&mut dir_inode_fixed, 0o755);
        put_u16(&mut dir_inode_fixed, 0);
        put_u16(&mut dir_inode_fixed, 0);
        put_u32(&mut dir_inode_fixed, 0);
        put_u32(&mut dir_inode_fixed, 1);
        put_u32(&mut dir_inode_fixed, 0);
        put_u32(&mut dir_inode_fixed, 1);
        put_u16(&mut dir_inode_fixed, dir_file_size as u16);
        put_u16(&mut dir_inode_fixed, 0);
        put_u32(&mut dir_inode_fixed, 0);
        let mut inode_payload2: Vec<u8> = Vec::new();
        inode_payload2.extend_from_slice(&dir_inode_fixed);
        inode_payload2.extend_from_slice(&file_inode);
        let meta2: Vec<u8> = uncompressed_metadata(&inode_payload2);
        image[inode_table_start as usize..inode_table_start as usize + meta2.len()]
            .copy_from_slice(&meta2);

        let fragment_table_start: u64 = 0;
        let id_table_start: u64 = image.len() as u64;
        image.extend_from_slice(&uncompressed_metadata(&[0u8, 0, 0, 0]));

        let bytes_used: u64 = image.len() as u64;
        let sb: &mut [u8] = &mut image[..SUPERBLOCK_MIN_BYTES];
        sb[0x00..0x04].copy_from_slice(&SQUASHFS_MAGIC_LE.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&2u32.to_le_bytes());
        sb[0x0C..0x10].copy_from_slice(&block_size.to_le_bytes());
        sb[0x10..0x14].copy_from_slice(&0u32.to_le_bytes());
        sb[0x14..0x16].copy_from_slice(&1u16.to_le_bytes());
        sb[0x16..0x18].copy_from_slice(&17u16.to_le_bytes());
        sb[0x1A..0x1C].copy_from_slice(&1u16.to_le_bytes());
        sb[0x1C..0x1E].copy_from_slice(&4u16.to_le_bytes());
        sb[0x1E..0x20].copy_from_slice(&0u16.to_le_bytes());
        sb[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
        sb[0x28..0x30].copy_from_slice(&bytes_used.to_le_bytes());
        sb[0x30..0x38].copy_from_slice(&id_table_start.to_le_bytes());
        sb[0x38..0x40].copy_from_slice(&u64::MAX.to_le_bytes());
        sb[0x40..0x48].copy_from_slice(&inode_table_start.to_le_bytes());
        sb[0x48..0x50].copy_from_slice(&directory_table_start.to_le_bytes());
        sb[0x50..0x58].copy_from_slice(&fragment_table_start.to_le_bytes());
        image
    }

    #[test]
    fn walks_real_format_squashfs_and_recovers_file() {
        let body: &[u8] = b"the squashfs walker recovers this exact body verbatim 1234567890";
        let image: Vec<u8> = build_real_squashfs("hello.txt", body);
        let walk: SquashfsWalk = walk_squashfs(&image, 0, 64 * 1024 * 1024).expect("walk squashfs");
        assert_eq!(walk.superblock.version_major, 4);
        let file: &SquashfsFile = walk
            .files
            .iter()
            .find(|f: &&SquashfsFile| f.path == "hello.txt")
            .expect("hello.txt present");
        assert_eq!(file.data, body);
        assert!(file.is_executable);
    }

    fn zlib_compress(input: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(input).expect("zlib write");
        enc.finish().expect("zlib finish")
    }

    #[test]
    fn decompresses_real_zlib_data_block() {
        let body: &[u8] = &b"AABBCCDDEEFFGG ".repeat(64);
        let compressed: Vec<u8> = zlib_compress(body);
        assert!(compressed.len() < body.len());
        let recovered: Vec<u8> =
            decompress_block(&compressed, SquashfsCompression::Gzip, body.len())
                .expect("zlib block decode");
        assert_eq!(recovered, body);
    }

    #[test]
    fn extract_to_writes_squashfs_file_to_disk() {
        let body: &[u8] = b"squashfs end-to-end extraction payload abcdefghijklmnop";
        let image: Vec<u8> = build_real_squashfs("readme.md", body);
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-squashfs-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::Squashfs, &image, &dir)
                .expect("squashfs extract");
        assert_eq!(result.kind, crate::container::ContainerKind::Squashfs);
        assert_eq!(
            std::fs::read(dir.join("readme.md")).expect("written file"),
            body
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn put_u16_e(out: &mut Vec<u8>, v: u16, endian: Endian) {
        match endian {
            Endian::Little => out.extend_from_slice(&v.to_le_bytes()),
            Endian::Big => out.extend_from_slice(&v.to_be_bytes()),
        }
    }

    fn put_u32_e(out: &mut Vec<u8>, v: u32, endian: Endian) {
        match endian {
            Endian::Little => out.extend_from_slice(&v.to_le_bytes()),
            Endian::Big => out.extend_from_slice(&v.to_be_bytes()),
        }
    }

    fn write_u32_e(buf: &mut [u8], at: usize, v: u32, endian: Endian) {
        let b: [u8; 4] = match endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        buf[at..at + 4].copy_from_slice(&b);
    }

    fn write_u64_e(buf: &mut [u8], at: usize, v: u64, endian: Endian) {
        let b: [u8; 8] = match endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        buf[at..at + 8].copy_from_slice(&b);
    }

    fn write_u16_e(buf: &mut [u8], at: usize, v: u16, endian: Endian) {
        let b: [u8; 2] = match endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        buf[at..at + 2].copy_from_slice(&b);
    }

    fn uncompressed_metadata_e(payload: &[u8], endian: Endian) -> Vec<u8> {
        let mut block: Vec<u8> = Vec::with_capacity(payload.len() + 2);
        let header: u16 = METADATA_UNCOMPRESSED_FLAG | (payload.len() as u16 & METADATA_SIZE_MASK);
        put_u16_e(&mut block, header, endian);
        block.extend_from_slice(payload);
        block
    }

    fn lz4_compress_block(input: &[u8]) -> Vec<u8> {
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

    fn build_squashfs_variant(
        file_name: &str,
        file_body: &[u8],
        endian: Endian,
        compression_id: u16,
        compress_data_block: bool,
    ) -> Vec<u8> {
        let block_size: u32 = 131_072;
        let mut image: Vec<u8> = vec![0u8; SUPERBLOCK_MIN_BYTES];

        let data_offset: u64 = image.len() as u64;
        let stored_block: Vec<u8> = if compress_data_block {
            lz4_compress_block(file_body)
        } else {
            file_body.to_vec()
        };
        let block_size_word: u32 = if compress_data_block {
            stored_block.len() as u32
        } else {
            FRAGMENT_UNCOMPRESSED_FLAG | file_body.len() as u32
        };
        image.extend_from_slice(&stored_block);

        let inode_table_start: u64 = image.len() as u64;
        let mut file_inode: Vec<u8> = Vec::new();
        put_u16_e(&mut file_inode, INODE_TYPE_FILE, endian);
        put_u16_e(&mut file_inode, 0o755, endian);
        put_u16_e(&mut file_inode, 0, endian);
        put_u16_e(&mut file_inode, 0, endian);
        put_u32_e(&mut file_inode, 0, endian);
        put_u32_e(&mut file_inode, 2, endian);
        put_u32_e(&mut file_inode, data_offset as u32, endian);
        put_u32_e(&mut file_inode, 0xFFFF_FFFF, endian);
        put_u32_e(&mut file_inode, 0, endian);
        put_u32_e(&mut file_inode, file_body.len() as u32, endian);
        put_u32_e(&mut file_inode, block_size_word, endian);
        let file_inode_offset: u16 = 32;

        let mut dir_payload: Vec<u8> = Vec::new();
        put_u32_e(&mut dir_payload, 0, endian);
        put_u32_e(&mut dir_payload, 0, endian);
        put_u32_e(&mut dir_payload, 1, endian);
        put_u16_e(&mut dir_payload, file_inode_offset, endian);
        put_u16_e(&mut dir_payload, 1, endian);
        put_u16_e(&mut dir_payload, INODE_TYPE_FILE, endian);
        put_u16_e(&mut dir_payload, file_name.len() as u16 - 1, endian);
        dir_payload.extend_from_slice(file_name.as_bytes());
        let dir_file_size: u32 = dir_payload.len() as u32 + 3;

        let mut dir_inode: Vec<u8> = Vec::new();
        put_u16_e(&mut dir_inode, INODE_TYPE_DIR, endian);
        put_u16_e(&mut dir_inode, 0o755, endian);
        put_u16_e(&mut dir_inode, 0, endian);
        put_u16_e(&mut dir_inode, 0, endian);
        put_u32_e(&mut dir_inode, 0, endian);
        put_u32_e(&mut dir_inode, 1, endian);
        put_u32_e(&mut dir_inode, 0, endian);
        put_u32_e(&mut dir_inode, 1, endian);
        put_u16_e(&mut dir_inode, dir_file_size as u16, endian);
        put_u16_e(&mut dir_inode, 0, endian);
        put_u32_e(&mut dir_inode, 0, endian);

        let mut inode_payload: Vec<u8> = Vec::new();
        inode_payload.extend_from_slice(&dir_inode);
        inode_payload.extend_from_slice(&file_inode);
        image.extend_from_slice(&uncompressed_metadata_e(&inode_payload, endian));

        let directory_table_start: u64 = image.len() as u64;
        image.extend_from_slice(&uncompressed_metadata_e(&dir_payload, endian));

        let fragment_table_start: u64 = 0;
        let id_table_start: u64 = image.len() as u64;
        image.extend_from_slice(&uncompressed_metadata_e(&[0u8, 0, 0, 0], endian));

        let bytes_used: u64 = image.len() as u64;
        let sb: &mut [u8] = &mut image[..SUPERBLOCK_MIN_BYTES];
        write_u32_e(sb, 0x00, SQUASHFS_MAGIC_LE, endian);
        write_u32_e(sb, 0x04, 2, endian);
        write_u32_e(sb, 0x0C, block_size, endian);
        write_u32_e(sb, 0x10, 0, endian);
        write_u16_e(sb, 0x14, compression_id, endian);
        write_u16_e(sb, 0x16, 17, endian);
        write_u16_e(sb, 0x1A, 1, endian);
        write_u16_e(sb, 0x1C, 4, endian);
        write_u16_e(sb, 0x1E, 0, endian);
        write_u64_e(sb, 0x20, 0, endian);
        write_u64_e(sb, 0x28, bytes_used, endian);
        write_u64_e(sb, 0x30, id_table_start, endian);
        write_u64_e(sb, 0x38, u64::MAX, endian);
        write_u64_e(sb, 0x40, inode_table_start, endian);
        write_u64_e(sb, 0x48, directory_table_start, endian);
        write_u64_e(sb, 0x50, fragment_table_start, endian);
        image
    }

    #[test]
    fn walks_lz4_compressed_squashfs_and_recovers_original_bytes() {
        let body: &[u8] =
            &b"LZ4 squashfs data block round-trips to these exact stored bytes. ".repeat(40);
        let image: Vec<u8> = build_squashfs_variant("payload.bin", body, Endian::Little, 5, true);
        let walk: SquashfsWalk =
            walk_squashfs(&image, 0, 64 * 1024 * 1024).expect("walk lz4 squashfs");
        assert_eq!(walk.superblock.compression, SquashfsCompression::Lz4);
        let file: &SquashfsFile = walk
            .files
            .iter()
            .find(|f: &&SquashfsFile| f.path == "payload.bin")
            .expect("payload.bin present");
        assert_eq!(file.data, body, "lz4-decoded body must equal the original");
    }

    #[test]
    fn walks_big_endian_squashfs_and_recovers_file() {
        let body: &[u8] = b"big-endian squashfs walker recovers this exact body 0xCAFEBABE";
        let image: Vec<u8> = build_squashfs_variant("be.txt", body, Endian::Big, 1, false);
        let sb: SquashfsSuperblock =
            parse_squashfs_superblock(&image, 0).expect("parse be superblock");
        assert!(!sb.little_endian, "image must be big-endian");
        let walk: SquashfsWalk =
            walk_squashfs(&image, 0, 64 * 1024 * 1024).expect("walk be squashfs");
        let file: &SquashfsFile = walk
            .files
            .iter()
            .find(|f: &&SquashfsFile| f.path == "be.txt")
            .expect("be.txt present");
        assert_eq!(file.data, body);
    }

    #[test]
    fn extract_to_writes_appimage_squashfs_payload() {
        let body: &[u8] = b"appimage embedded squashfs payload 0987654321 zyxwvut";
        let mut sqfs: Vec<u8> = build_real_squashfs("AppRun", body);
        let offset: usize = 0x10_000;
        let mut image: Vec<u8> = vec![0u8; offset];
        image[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        image[8..11].copy_from_slice(&[b'A', b'I', 0x02]);
        image.append(&mut sqfs);
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-appimage-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::AppImage, &image, &dir)
                .expect("appimage extract");
        assert_eq!(result.kind, crate::container::ContainerKind::AppImage);
        assert_eq!(std::fs::read(dir.join("AppRun")).expect("AppRun"), body);
        assert!(dir.join(".disrobe-appimage-layout.json").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fragment_table_reservation_is_input_proportional() {
        let fragment_entry_count: u32 = 1_000_000;
        let index_count: usize = fragment_entry_count.div_ceil(512) as usize;
        let fragment_table_start: usize = 16;
        let bytes: Vec<u8> = vec![0u8; fragment_table_start + index_count * 8];
        let raw: RawSuperblock = RawSuperblock {
            block_size: 131_072,
            root_inode_ref: 0,
            id_table_start: 0,
            inode_table_start: 0,
            directory_table_start: 0,
            fragment_table_start: fragment_table_start as u64,
            fragment_entry_count,
        };
        let entries: Vec<FragmentEntry> =
            read_fragment_table(&bytes, 0, &raw, SquashfsCompression::Gzip, Endian::Little)
                .expect("fragment table walk");
        assert!(entries.is_empty(), "empty metadata blocks yield no entries");
        assert!(
            entries.capacity() < fragment_entry_count as usize,
            "reservation must not follow the raw fragment count"
        );
        assert!(
            entries.capacity() <= bytes.len(),
            "reservation stays proportional to the input size"
        );
    }
}
