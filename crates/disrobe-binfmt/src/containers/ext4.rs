use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
pub const EXT4_MAGIC: u16 = 0xEF53;

const EXT4_ROOT_INODE: u32 = 2;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
const EXTENT_MAGIC: u16 = 0xF30A;
const S_IFMT: u16 = 0o170_000;
const S_IFDIR: u16 = 0o040_000;
const S_IFREG: u16 = 0o100_000;
const S_IFLNK: u16 = 0o120_000;
const MAX_EXT4_FILES: usize = 500_000;
const MAX_EXT4_DEPTH: usize = 256;
const MAX_EXTENT_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy)]
struct Ext4Geometry {
    block_size: u64,
    inodes_per_group: u32,
    inode_size: u32,
    desc_size: u32,
    first_data_block: u32,
}

#[derive(Debug, Clone, Copy)]
struct Ext4Inode {
    mode: u16,
    size: u64,
    flags: u32,
    i_block: [u8; 60],
}

#[derive(Debug, Clone)]
pub struct Ext4File {
    pub path: String,
    pub data: Vec<u8>,
    pub is_executable: bool,
    pub is_symlink: bool,
}

#[derive(Debug, Clone)]
pub struct Ext4Walk {
    pub summary: Ext4SuperblockSummary,
    pub files: Vec<Ext4File>,
}

pub fn walk_ext4(bytes: &[u8], max_total: u64) -> Result<Ext4Walk> {
    let summary: Ext4SuperblockSummary = detect_ext4(bytes).ok_or_else(|| {
        Error::Ext4("ext4 magic 0xEF53 not found at superblock offset".to_owned())
    })?;
    let geometry: Ext4Geometry = read_geometry(bytes)?;
    let mut files: Vec<Ext4File> = Vec::new();
    let mut total: u64 = 0;
    let mut stack: Vec<(u32, String, usize)> = vec![(EXT4_ROOT_INODE, String::new(), 0)];
    let mut visited: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    while let Some((ino, prefix, depth)) = stack.pop() {
        if depth > MAX_EXT4_DEPTH || files.len() > MAX_EXT4_FILES {
            break;
        }
        if !visited.insert(ino) {
            continue;
        }
        let inode: Ext4Inode = read_inode(bytes, &geometry, ino)?;
        match inode.mode & S_IFMT {
            S_IFDIR => {
                read_directory(bytes, &geometry, &inode, &prefix, depth, &mut stack)?;
            }
            S_IFREG => {
                let data: Vec<u8> = read_inode_data(bytes, &geometry, &inode, max_total)?;
                total = total.saturating_add(data.len() as u64);
                if total > max_total {
                    return Err(Error::Ext4(format!(
                        "ext4 walk exceeds total cap {max_total}"
                    )));
                }
                files.push(Ext4File {
                    path: prefix,
                    is_executable: inode.mode & 0o111 != 0,
                    data,
                    is_symlink: false,
                });
            }
            S_IFLNK => {
                let target: Vec<u8> = read_symlink_target(bytes, &geometry, &inode, max_total)?;
                files.push(Ext4File {
                    path: prefix,
                    data: target,
                    is_executable: false,
                    is_symlink: true,
                });
            }
            _ => {}
        }
    }
    Ok(Ext4Walk { summary, files })
}

fn read_geometry(bytes: &[u8]) -> Result<Ext4Geometry> {
    let sb: &[u8] = bytes
        .get(EXT4_SUPERBLOCK_OFFSET..EXT4_SUPERBLOCK_OFFSET + 0x100)
        .ok_or_else(|| Error::Ext4("ext4 superblock truncated".to_owned()))?;
    let log_block_size: u32 = le_u32(sb, 0x18);
    let block_size: u64 = 1024u64 << log_block_size.min(20);
    let inodes_per_group: u32 = le_u32(sb, 0x28);
    let inode_size: u32 = {
        let raw: u16 = le_u16(sb, 0x58);
        if raw == 0 { 128 } else { u32::from(raw) }
    };
    let feature_incompat: u32 = le_u32(sb, 0x60);
    let desc_size: u32 = if feature_incompat & 0x80 != 0 {
        u32::from(le_u16(sb, 0xFE)).max(64)
    } else {
        32
    };
    let first_data_block: u32 = le_u32(sb, 0x14);
    if inodes_per_group == 0 || block_size == 0 {
        return Err(Error::Ext4("ext4 superblock has zero geometry".to_owned()));
    }
    Ok(Ext4Geometry {
        block_size,
        inodes_per_group,
        inode_size,
        desc_size,
        first_data_block,
    })
}

fn read_inode(bytes: &[u8], geo: &Ext4Geometry, ino: u32) -> Result<Ext4Inode> {
    if ino == 0 {
        return Err(Error::Ext4("ext4 inode 0 is invalid".to_owned()));
    }
    let index: u32 = ino - 1;
    let group: u32 = index / geo.inodes_per_group;
    let inode_in_group: u32 = index % geo.inodes_per_group;
    let gdt_block: u64 = u64::from(geo.first_data_block) + 1;
    let desc_offset: u64 = gdt_block * geo.block_size + u64::from(group) * u64::from(geo.desc_size);
    let desc_at: usize = usize::try_from(desc_offset)
        .map_err(|_e: std::num::TryFromIntError| Error::Ext4("desc offset overflow".to_owned()))?;
    let desc: &[u8] = bytes
        .get(desc_at..desc_at + geo.desc_size as usize)
        .ok_or_else(|| Error::Ext4("ext4 group descriptor out of bounds".to_owned()))?;
    let inode_table_lo: u64 = u64::from(le_u32(desc, 0x8));
    let inode_table_hi: u64 = if geo.desc_size >= 64 {
        u64::from(le_u32(desc, 0x28))
    } else {
        0
    };
    let inode_table_block: u64 = inode_table_lo | (inode_table_hi << 32);
    let inode_offset: u64 =
        inode_table_block * geo.block_size + u64::from(inode_in_group) * u64::from(geo.inode_size);
    let at: usize = usize::try_from(inode_offset)
        .map_err(|_e: std::num::TryFromIntError| Error::Ext4("inode offset overflow".to_owned()))?;
    let raw: &[u8] = bytes
        .get(at..at + 128)
        .ok_or_else(|| Error::Ext4("ext4 inode out of bounds".to_owned()))?;
    let mode: u16 = le_u16(raw, 0x0);
    let size_lo: u64 = u64::from(le_u32(raw, 0x4));
    let size_hi: u64 = u64::from(le_u32(raw, 0x6C));
    let flags: u32 = le_u32(raw, 0x20);
    let mut i_block: [u8; 60] = [0u8; 60];
    i_block.copy_from_slice(&raw[0x28..0x28 + 60]);
    Ok(Ext4Inode {
        mode,
        size: size_lo | (size_hi << 32),
        flags,
        i_block,
    })
}

fn read_directory(
    bytes: &[u8],
    geo: &Ext4Geometry,
    inode: &Ext4Inode,
    prefix: &str,
    depth: usize,
    stack: &mut Vec<(u32, String, usize)>,
) -> Result<()> {
    let dir_bytes: Vec<u8> = read_inode_data(bytes, geo, inode, 64 * 1024 * 1024)?;
    let mut pos: usize = 0;
    let mut children: Vec<(u32, String, usize)> = Vec::new();
    while pos + 8 <= dir_bytes.len() {
        let child_ino: u32 = le_u32(&dir_bytes, pos);
        let rec_len: usize = le_u16(&dir_bytes, pos + 4) as usize;
        let name_len: usize = dir_bytes[pos + 6] as usize;
        if rec_len < 8 {
            break;
        }
        if child_ino != 0 && pos + 8 + name_len <= dir_bytes.len() {
            let name_bytes: &[u8] = &dir_bytes[pos + 8..pos + 8 + name_len];
            let name: String = String::from_utf8_lossy(name_bytes).into_owned();
            if name != "." && name != ".." && !name.is_empty() {
                let child_path: String = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                children.push((child_ino, child_path, depth + 1));
            }
        }
        pos += rec_len;
    }
    for child in children.into_iter().rev() {
        stack.push(child);
    }
    Ok(())
}

fn read_symlink_target(
    bytes: &[u8],
    geo: &Ext4Geometry,
    inode: &Ext4Inode,
    max_total: u64,
) -> Result<Vec<u8>> {
    if inode.size < 60 {
        return Ok(inode.i_block[..inode.size as usize].to_vec());
    }
    read_inode_data(bytes, geo, inode, max_total)
}

fn read_inode_data(
    bytes: &[u8],
    geo: &Ext4Geometry,
    inode: &Ext4Inode,
    max_total: u64,
) -> Result<Vec<u8>> {
    if inode.size > max_total {
        return Err(Error::Ext4("ext4 inode size exceeds total cap".to_owned()));
    }
    if inode.flags & EXT4_EXTENTS_FL == 0 {
        return Err(Error::Ext4(
            "ext4 inode uses legacy block-mapping (non-extent); only extent-tree inodes are walked in-tree".to_owned(),
        ));
    }
    let mut out: Vec<u8> = Vec::with_capacity(inode.size.min(64 * 1024 * 1024) as usize);
    walk_extent_node(bytes, geo, &inode.i_block, &mut out, 0, max_total)?;
    out.truncate(inode.size as usize);
    Ok(out)
}

fn walk_extent_node(
    bytes: &[u8],
    geo: &Ext4Geometry,
    node: &[u8],
    out: &mut Vec<u8>,
    depth: usize,
    max_total: u64,
) -> Result<()> {
    if depth > MAX_EXTENT_DEPTH || node.len() < 12 {
        return Err(Error::Ext4(
            "ext4 extent node truncated or too deep".to_owned(),
        ));
    }
    let magic: u16 = le_u16(node, 0);
    if magic != EXTENT_MAGIC {
        return Err(Error::Ext4(format!(
            "ext4 extent header magic mismatch: 0x{magic:04x}"
        )));
    }
    let entries: usize = le_u16(node, 2) as usize;
    let tree_depth: u16 = le_u16(node, 6);
    for i in 0..entries {
        let base: usize = 12 + i * 12;
        if base + 12 > node.len() {
            break;
        }
        if tree_depth == 0 {
            let logical_block: u32 = le_u32(node, base);
            let len_raw: u16 = le_u16(node, base + 4);
            let len: u64 = u64::from(len_raw & 0x7FFF);
            let start_hi: u64 = u64::from(le_u16(node, base + 6));
            let start_lo: u64 = u64::from(le_u32(node, base + 8));
            let phys: u64 = (start_hi << 32) | start_lo;
            write_extent_blocks(bytes, geo, logical_block, phys, len, out, max_total)?;
        } else {
            let leaf_lo: u64 = u64::from(le_u32(node, base + 4));
            let leaf_hi: u64 = u64::from(le_u16(node, base + 8));
            let child_block: u64 = (leaf_hi << 32) | leaf_lo;
            let child_byte: u64 = child_block
                .checked_mul(geo.block_size)
                .ok_or_else(|| Error::Ext4("extent child offset overflow".to_owned()))?;
            let child_at: usize =
                usize::try_from(child_byte).map_err(|_e: std::num::TryFromIntError| {
                    Error::Ext4("extent child overflow".to_owned())
                })?;
            let child_end: usize = child_at
                .checked_add(geo.block_size as usize)
                .ok_or_else(|| Error::Ext4("extent child end overflow".to_owned()))?;
            let child: &[u8] = bytes
                .get(child_at..child_end)
                .ok_or_else(|| Error::Ext4("ext4 extent child block out of bounds".to_owned()))?;
            walk_extent_node(bytes, geo, child, out, depth + 1, max_total)?;
        }
    }
    Ok(())
}

fn write_extent_blocks(
    bytes: &[u8],
    geo: &Ext4Geometry,
    logical_block: u32,
    phys_block: u64,
    len: u64,
    out: &mut Vec<u8>,
    max_total: u64,
) -> Result<()> {
    let want_offset: u64 = u64::from(logical_block)
        .checked_mul(geo.block_size)
        .ok_or_else(|| Error::Ext4("extent logical offset overflow".to_owned()))?;
    if want_offset > max_total {
        return Err(Error::Ext4(
            "ext4 extent logical offset exceeds total cap".to_owned(),
        ));
    }
    if out.len() as u64 != want_offset {
        out.resize(want_offset as usize, 0);
    }
    let start: usize = usize::try_from(
        phys_block
            .checked_mul(geo.block_size)
            .ok_or_else(|| Error::Ext4("extent phys offset overflow".to_owned()))?,
    )
    .map_err(|_e: std::num::TryFromIntError| Error::Ext4("extent phys overflow".to_owned()))?;
    let byte_len: usize = usize::try_from(
        len.checked_mul(geo.block_size)
            .ok_or_else(|| Error::Ext4("extent byte length overflow".to_owned()))?,
    )
    .map_err(|_e: std::num::TryFromIntError| Error::Ext4("extent len overflow".to_owned()))?;
    if out.len().saturating_add(byte_len) as u64 > max_total {
        return Err(Error::Ext4("ext4 extent data exceeds total cap".to_owned()));
    }
    let end: usize = start
        .checked_add(byte_len)
        .ok_or_else(|| Error::Ext4("extent data end overflow".to_owned()))?;
    let region: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| Error::Ext4("ext4 extent data past end of input".to_owned()))?;
    out.extend_from_slice(region);
    Ok(())
}

#[inline]
fn le_u16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .map_or(0, |s: &[u8]| u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn le_u32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .map_or(0, |s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4SuperblockSummary {
    pub inodes_count: u32,
    pub blocks_count_lo: u32,
    pub block_size_log: u32,
    pub magic: u16,
    pub state: u16,
    pub creator_os: u32,
    pub rev_level: u32,
}

#[must_use]
pub fn detect_ext4(bytes: &[u8]) -> Option<Ext4SuperblockSummary> {
    let end: usize = EXT4_SUPERBLOCK_OFFSET + 0x400;
    if bytes.len() < end {
        return None;
    }
    let magic: u16 = u16::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x38],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x39],
    ]);
    if magic != EXT4_MAGIC {
        return None;
    }
    let inodes_count: u32 = u32::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET],
        bytes[EXT4_SUPERBLOCK_OFFSET + 1],
        bytes[EXT4_SUPERBLOCK_OFFSET + 2],
        bytes[EXT4_SUPERBLOCK_OFFSET + 3],
    ]);
    let blocks_count_lo: u32 = u32::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET + 4],
        bytes[EXT4_SUPERBLOCK_OFFSET + 5],
        bytes[EXT4_SUPERBLOCK_OFFSET + 6],
        bytes[EXT4_SUPERBLOCK_OFFSET + 7],
    ]);
    let block_size_log: u32 = u32::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x18],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x19],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x1A],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x1B],
    ]);
    let state: u16 = u16::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x3A],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x3B],
    ]);
    let creator_os: u32 = u32::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x48],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x49],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4A],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4B],
    ]);
    let rev_level: u32 = u32::from_le_bytes([
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4C],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4D],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4E],
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4F],
    ]);
    Some(Ext4SuperblockSummary {
        inodes_count,
        blocks_count_lo,
        block_size_log,
        magic,
        state,
        creator_os,
        rev_level,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_ext4_image() -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0u8; EXT4_SUPERBLOCK_OFFSET + 0x400];
        bytes[EXT4_SUPERBLOCK_OFFSET..EXT4_SUPERBLOCK_OFFSET + 4]
            .copy_from_slice(&64u32.to_le_bytes());
        bytes[EXT4_SUPERBLOCK_OFFSET + 4..EXT4_SUPERBLOCK_OFFSET + 8]
            .copy_from_slice(&1024u32.to_le_bytes());
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x18..EXT4_SUPERBLOCK_OFFSET + 0x1C]
            .copy_from_slice(&2u32.to_le_bytes());
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x38..EXT4_SUPERBLOCK_OFFSET + 0x3A]
            .copy_from_slice(&EXT4_MAGIC.to_le_bytes());
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x3A..EXT4_SUPERBLOCK_OFFSET + 0x3C]
            .copy_from_slice(&1u16.to_le_bytes());
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x4C..EXT4_SUPERBLOCK_OFFSET + 0x50]
            .copy_from_slice(&1u32.to_le_bytes());
        bytes
    }

    #[test]
    fn detects_ext4_magic_at_offset_1024() {
        let bytes: Vec<u8> = synth_ext4_image();
        let sb: Ext4SuperblockSummary = detect_ext4(&bytes).expect("ext4");
        assert_eq!(sb.magic, EXT4_MAGIC);
        assert_eq!(sb.inodes_count, 64);
        assert_eq!(sb.blocks_count_lo, 1024);
        assert_eq!(sb.block_size_log, 2);
        assert_eq!(sb.rev_level, 1);
    }

    #[test]
    fn rejects_short_buffer() {
        let bytes: Vec<u8> = vec![0u8; 256];
        assert!(detect_ext4(&bytes).is_none());
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut bytes: Vec<u8> = vec![0u8; EXT4_SUPERBLOCK_OFFSET + 0x400];
        bytes[EXT4_SUPERBLOCK_OFFSET + 0x38..EXT4_SUPERBLOCK_OFFSET + 0x3A]
            .copy_from_slice(&0xDEAD_u16.to_le_bytes());
        assert!(detect_ext4(&bytes).is_none());
    }

    const BS: usize = 1024;
    const INODE_SIZE: usize = 128;
    const INODES_PER_GROUP: u32 = 16;

    fn extent_inode(mode: u16, size: u32, phys_block: u32, block_count: u16) -> [u8; INODE_SIZE] {
        let mut raw: [u8; INODE_SIZE] = [0u8; INODE_SIZE];
        raw[0x0..0x2].copy_from_slice(&mode.to_le_bytes());
        raw[0x4..0x8].copy_from_slice(&size.to_le_bytes());
        raw[0x20..0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
        let ib: &mut [u8] = &mut raw[0x28..0x28 + 60];
        ib[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        ib[2..4].copy_from_slice(&1u16.to_le_bytes());
        ib[4..6].copy_from_slice(&4u16.to_le_bytes());
        ib[6..8].copy_from_slice(&0u16.to_le_bytes());
        ib[12..16].copy_from_slice(&0u32.to_le_bytes());
        ib[16..18].copy_from_slice(&block_count.to_le_bytes());
        ib[18..20].copy_from_slice(&0u16.to_le_bytes());
        ib[20..24].copy_from_slice(&phys_block.to_le_bytes());
        raw
    }

    fn dir_entry(out: &mut Vec<u8>, ino: u32, name: &str, file_type: u8, rec_len: u16) {
        let start: usize = out.len();
        out.extend_from_slice(&ino.to_le_bytes());
        out.extend_from_slice(&rec_len.to_le_bytes());
        out.push(name.len() as u8);
        out.push(file_type);
        out.extend_from_slice(name.as_bytes());
        out.resize(start + rec_len as usize, 0);
    }

    fn build_real_ext4(file_name: &str, file_body: &[u8]) -> Vec<u8> {
        let total_blocks: usize = 16;
        let mut image: Vec<u8> = vec![0u8; total_blocks * BS];

        let sb_off: usize = EXT4_SUPERBLOCK_OFFSET;
        image[sb_off..sb_off + 4].copy_from_slice(&64u32.to_le_bytes());
        image[sb_off + 4..sb_off + 8].copy_from_slice(&(total_blocks as u32).to_le_bytes());
        image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&1u32.to_le_bytes());
        image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&0u32.to_le_bytes());
        image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&INODES_PER_GROUP.to_le_bytes());
        image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_MAGIC.to_le_bytes());
        image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&(INODE_SIZE as u16).to_le_bytes());

        let gdt_off: usize = 2 * BS;
        let inode_table_block: u32 = 3;
        image[gdt_off + 0x8..gdt_off + 0xC].copy_from_slice(&inode_table_block.to_le_bytes());

        let inode_table_off: usize = inode_table_block as usize * BS;
        let root_data_block: u32 = 5;
        let file_data_block: u32 = 6;
        let file_ino: u32 = 11;

        let root_inode: [u8; INODE_SIZE] =
            extent_inode(S_IFDIR | 0o755, BS as u32, root_data_block, 1);
        let root_off: usize = inode_table_off + (EXT4_ROOT_INODE as usize - 1) * INODE_SIZE;
        image[root_off..root_off + INODE_SIZE].copy_from_slice(&root_inode);

        let file_inode: [u8; INODE_SIZE] =
            extent_inode(S_IFREG | 0o755, file_body.len() as u32, file_data_block, 1);
        let file_inode_off: usize = inode_table_off + (file_ino as usize - 1) * INODE_SIZE;
        image[file_inode_off..file_inode_off + INODE_SIZE].copy_from_slice(&file_inode);

        let mut dir: Vec<u8> = Vec::new();
        dir_entry(&mut dir, EXT4_ROOT_INODE, ".", 2, 12);
        dir_entry(&mut dir, EXT4_ROOT_INODE, "..", 2, 12);
        let used: u16 = (12 + 12 + 8 + file_name.len()).next_multiple_of(4) as u16 - 24;
        let remaining: u16 = BS as u16 - 24;
        dir_entry(&mut dir, file_ino, file_name, 1, remaining.max(used));
        let root_data_off: usize = root_data_block as usize * BS;
        image[root_data_off..root_data_off + dir.len().min(BS)]
            .copy_from_slice(&dir[..dir.len().min(BS)]);

        let file_data_off: usize = file_data_block as usize * BS;
        image[file_data_off..file_data_off + file_body.len()].copy_from_slice(file_body);

        image
    }

    #[test]
    fn walks_real_format_ext4_and_recovers_file() {
        let body: &[u8] = b"ext4 extent-mapped file body recovered byte for byte 0xABCDEF";
        let image: Vec<u8> = build_real_ext4("hello.txt", body);
        let walk: Ext4Walk = walk_ext4(&image, 64 * 1024 * 1024).expect("walk ext4");
        let file: &Ext4File = walk
            .files
            .iter()
            .find(|f: &&Ext4File| f.path == "hello.txt")
            .expect("hello.txt present");
        assert_eq!(file.data, body);
        assert!(file.is_executable);
    }

    #[test]
    fn extract_to_writes_ext4_file() {
        let body: &[u8] = b"ext4 end to end extraction payload 13371337";
        let image: Vec<u8> = build_real_ext4("payload.bin", body);
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-ext4-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::Ext4, &image, &dir)
                .expect("ext4 extract");
        assert_eq!(result.kind, crate::container::ContainerKind::Ext4);
        assert_eq!(
            std::fs::read(dir.join("payload.bin")).expect("payload"),
            body
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
