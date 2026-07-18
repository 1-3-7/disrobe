use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const BOOT_BLOCK_LEN: usize = 1024;
const BLOCK_SIZE_V1V2: usize = 1024;
const SUPER_MAGIC_OFFSET_V1V2: usize = 16;
const SUPER_MAGIC_V1_14: u16 = 0x137F;
const SUPER_MAGIC_V1_30: u16 = 0x138F;
const SUPER_MAGIC_V2_14: u16 = 0x2468;
const SUPER_MAGIC_V2_30: u16 = 0x2478;
const SUPER_MAGIC_V3: u16 = 0x4D5A;

const INODE_V1_LEN: usize = 32;
const INODE_V2_LEN: usize = 64;
const INODE_SIZE_OFFSET_V1: usize = 4;
const INODE_SIZE_OFFSET_V2: usize = 8;
const DIRECT_ZONES_V1: usize = 7;
const DIRECT_ZONES_V2: usize = 7;
const S_IFMT: u16 = 0o170_000;
const S_IFDIR: u16 = 0o040_000;
const S_IFREG: u16 = 0o100_000;
const S_IFLNK: u16 = 0o120_000;
const ROOT_INODE: u32 = 1;
const MAX_FILES: usize = 500_000;
const MAX_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MinixVersion {
    V1,
    V2,
    V3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinixSuperblock {
    pub version: MinixVersion,
    pub ninodes: u32,
    pub imap_blocks: u32,
    pub zmap_blocks: u32,
    pub first_data_zone: u32,
    pub log_zone_size: u32,
    pub max_size: u64,
    pub zones: u32,
    pub block_size: usize,
    pub name_len: usize,
}

#[derive(Debug, Clone)]
pub struct MinixFile {
    pub path: String,
    pub data: Vec<u8>,
    pub is_executable: bool,
    pub is_symlink: bool,
}

#[derive(Debug, Clone)]
pub struct MinixWalk {
    pub superblock: MinixSuperblock,
    pub files: Vec<MinixFile>,
}

#[derive(Debug, Clone, Copy)]
struct MinixInode {
    mode: u16,
    size: u64,
    zones: [u32; 9],
}

fn rd_u16(bytes: &[u8], at: usize) -> Option<u16> {
    disrobe_bytes::read_u16_le_at(bytes, at).ok()
}

fn rd_u32(bytes: &[u8], at: usize) -> Option<u32> {
    disrobe_bytes::read_u32_le_at(bytes, at).ok()
}

#[must_use]
pub fn detect_minixfs(bytes: &[u8]) -> Option<MinixSuperblock> {
    let sb_base: usize = BOOT_BLOCK_LEN;
    if bytes.len() < sb_base + 64 {
        return None;
    }
    if let Some(magic) = rd_u16(bytes, sb_base + SUPER_MAGIC_OFFSET_V1V2) {
        match magic {
            SUPER_MAGIC_V1_14 => return parse_super_v1v2(bytes, sb_base, MinixVersion::V1, 14),
            SUPER_MAGIC_V1_30 => return parse_super_v1v2(bytes, sb_base, MinixVersion::V1, 30),
            SUPER_MAGIC_V2_14 => return parse_super_v1v2(bytes, sb_base, MinixVersion::V2, 14),
            SUPER_MAGIC_V2_30 => return parse_super_v1v2(bytes, sb_base, MinixVersion::V2, 30),
            _ => {}
        }
    }
    if rd_u16(bytes, sb_base + 24) == Some(SUPER_MAGIC_V3) {
        return parse_super_v3(bytes, sb_base);
    }
    None
}

fn parse_super_v1v2(
    bytes: &[u8],
    base: usize,
    version: MinixVersion,
    name_len: usize,
) -> Option<MinixSuperblock> {
    let ninodes: u32 = u32::from(rd_u16(bytes, base)?);
    let imap_blocks: u32 = u32::from(rd_u16(bytes, base + 4)?);
    let zmap_blocks: u32 = u32::from(rd_u16(bytes, base + 6)?);
    let first_data_zone: u32 = u32::from(rd_u16(bytes, base + 8)?);
    let log_zone_size: u32 = u32::from(rd_u16(bytes, base + 10)?);
    let max_size: u64 = u64::from(rd_u32(bytes, base + 12)?);
    let zones: u32 = match version {
        MinixVersion::V1 => u32::from(rd_u16(bytes, base + 2)?),
        _ => rd_u32(bytes, base + 20)?,
    };
    Some(MinixSuperblock {
        version,
        ninodes,
        imap_blocks,
        zmap_blocks,
        first_data_zone,
        log_zone_size,
        max_size,
        zones,
        block_size: BLOCK_SIZE_V1V2,
        name_len,
    })
}

fn parse_super_v3(bytes: &[u8], base: usize) -> Option<MinixSuperblock> {
    let ninodes: u32 = rd_u32(bytes, base)?;
    let imap_blocks: u32 = u32::from(rd_u16(bytes, base + 8)?);
    let zmap_blocks: u32 = u32::from(rd_u16(bytes, base + 10)?);
    let first_data_zone: u32 = u32::from(rd_u16(bytes, base + 12)?);
    let log_zone_size: u32 = u32::from(rd_u16(bytes, base + 14)?);
    let max_size: u64 = u64::from(rd_u32(bytes, base + 16)?);
    let zones: u32 = rd_u32(bytes, base + 20)?;
    let block_size: usize = rd_u16(bytes, base + 26)? as usize;
    let block_size: usize = if block_size == 0 { 1024 } else { block_size };
    Some(MinixSuperblock {
        version: MinixVersion::V3,
        ninodes,
        imap_blocks,
        zmap_blocks,
        first_data_zone,
        log_zone_size,
        max_size,
        zones,
        block_size,
        name_len: 60,
    })
}

const fn inode_table_offset(sb: &MinixSuperblock) -> usize {
    let blocks_before: usize = 2 + sb.imap_blocks as usize + sb.zmap_blocks as usize;
    blocks_before * sb.block_size
}

fn read_inode(bytes: &[u8], sb: &MinixSuperblock, ino: u32) -> Result<MinixInode> {
    if ino == 0 {
        return Err(Error::Minixfs("inode 0 is reserved".to_owned()));
    }
    let table: usize = inode_table_offset(sb);
    match sb.version {
        MinixVersion::V1 => {
            let at: usize = table + (ino as usize - 1) * INODE_V1_LEN;
            let raw: &[u8] = bytes
                .get(at..at + INODE_V1_LEN)
                .ok_or_else(|| Error::Minixfs(format!("v1 inode {ino} out of bounds")))?;
            let mode: u16 = u16::from_le_bytes([raw[0], raw[1]]);
            let size: u64 = u64::from(u32::from_le_bytes([
                raw[INODE_SIZE_OFFSET_V1],
                raw[INODE_SIZE_OFFSET_V1 + 1],
                raw[INODE_SIZE_OFFSET_V1 + 2],
                raw[INODE_SIZE_OFFSET_V1 + 3],
            ]));
            let mut zones: [u32; 9] = [0u32; 9];
            for (i, zone) in zones.iter_mut().enumerate().take(9) {
                let zoff: usize = 14 + i * 2;
                *zone = u32::from(u16::from_le_bytes([raw[zoff], raw[zoff + 1]]));
            }
            Ok(MinixInode { mode, size, zones })
        }
        MinixVersion::V2 | MinixVersion::V3 => {
            let at: usize = table + (ino as usize - 1) * INODE_V2_LEN;
            let raw: &[u8] = bytes
                .get(at..at + INODE_V2_LEN)
                .ok_or_else(|| Error::Minixfs(format!("v2/v3 inode {ino} out of bounds")))?;
            let mode: u16 = u16::from_le_bytes([raw[0], raw[1]]);
            let size: u64 = u64::from(u32::from_le_bytes([
                raw[INODE_SIZE_OFFSET_V2],
                raw[INODE_SIZE_OFFSET_V2 + 1],
                raw[INODE_SIZE_OFFSET_V2 + 2],
                raw[INODE_SIZE_OFFSET_V2 + 3],
            ]));
            let mut zones: [u32; 9] = [0u32; 9];
            for (i, zone) in zones.iter_mut().enumerate().take(9) {
                let zoff: usize = 24 + i * 4;
                *zone =
                    u32::from_le_bytes([raw[zoff], raw[zoff + 1], raw[zoff + 2], raw[zoff + 3]]);
            }
            Ok(MinixInode { mode, size, zones })
        }
    }
}

fn zone_bytes<'a>(bytes: &'a [u8], sb: &MinixSuperblock, zone: u32) -> Option<&'a [u8]> {
    if zone == 0 {
        return None;
    }
    let block_size: usize = sb.block_size << sb.log_zone_size;
    let start: usize = (zone as usize).checked_mul(block_size)?;
    let end: usize = start.checked_add(block_size)?;
    bytes.get(start..end.min(bytes.len()))
}

const fn direct_zone_count(sb: &MinixSuperblock) -> usize {
    match sb.version {
        MinixVersion::V1 => DIRECT_ZONES_V1,
        MinixVersion::V2 | MinixVersion::V3 => DIRECT_ZONES_V2,
    }
}

const fn ptrs_per_zone(sb: &MinixSuperblock) -> usize {
    let zone_bytes: usize = sb.block_size << sb.log_zone_size;
    match sb.version {
        MinixVersion::V1 => zone_bytes / 2,
        MinixVersion::V2 | MinixVersion::V3 => zone_bytes / 4,
    }
}

fn read_zone_ptr(bytes: &[u8], sb: &MinixSuperblock, zone: u32, index: usize) -> u32 {
    let Some(slice) = zone_bytes(bytes, sb, zone) else {
        return 0;
    };
    match sb.version {
        MinixVersion::V1 => {
            let at: usize = index * 2;
            slice
                .get(at..at + 2)
                .map_or(0, |s| u32::from(u16::from_le_bytes([s[0], s[1]])))
        }
        MinixVersion::V2 | MinixVersion::V3 => {
            let at: usize = index * 4;
            slice
                .get(at..at + 4)
                .map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        }
    }
}

fn collect_data_zones(bytes: &[u8], sb: &MinixSuperblock, inode: &MinixInode) -> Vec<u32> {
    let direct: usize = direct_zone_count(sb);
    let mut out: Vec<u32> = Vec::new();
    for &z in inode.zones.iter().take(direct) {
        out.push(z);
    }
    let single_indirect: u32 = inode.zones[direct];
    if single_indirect != 0 {
        for i in 0..ptrs_per_zone(sb) {
            out.push(read_zone_ptr(bytes, sb, single_indirect, i));
        }
    }
    let double_indirect: u32 = inode.zones[direct + 1];
    if double_indirect != 0 {
        for i in 0..ptrs_per_zone(sb) {
            let level1: u32 = read_zone_ptr(bytes, sb, double_indirect, i);
            if level1 == 0 {
                continue;
            }
            for j in 0..ptrs_per_zone(sb) {
                out.push(read_zone_ptr(bytes, sb, level1, j));
            }
        }
    }
    out
}

fn read_file_data(
    bytes: &[u8],
    sb: &MinixSuperblock,
    inode: &MinixInode,
    max_total: u64,
) -> Result<Vec<u8>> {
    if inode.size == 0 {
        return Ok(Vec::new());
    }
    if inode.size > max_total {
        return Err(Error::Minixfs("file exceeds total cap".to_owned()));
    }
    let zone_size: usize = sb.block_size << sb.log_zone_size;
    let mut out: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(inode.size));
    let zones: Vec<u32> = collect_data_zones(bytes, sb, inode);
    for z in zones {
        if out.len() as u64 >= inode.size {
            break;
        }
        match zone_bytes(bytes, sb, z) {
            Some(slice) => out.extend_from_slice(slice),
            None => out.extend(std::iter::repeat_n(0u8, zone_size)),
        }
    }
    out.truncate(inode.size as usize);
    Ok(out)
}

fn read_directory(
    bytes: &[u8],
    sb: &MinixSuperblock,
    inode: &MinixInode,
) -> Result<Vec<(u32, String)>> {
    let entry_len: usize = 2 + sb.name_len;
    let dir_data: Vec<u8> = read_file_data(bytes, sb, inode, u64::from(u32::MAX))?;
    let mut entries: Vec<(u32, String)> = Vec::new();
    let mut pos: usize = 0;
    while pos + entry_len <= dir_data.len() {
        let ino: u32 = u32::from(u16::from_le_bytes([dir_data[pos], dir_data[pos + 1]]));
        if ino != 0 {
            let name_raw: &[u8] = &dir_data[pos + 2..pos + 2 + sb.name_len];
            let trimmed: &[u8] = name_raw
                .iter()
                .position(|&b| b == 0)
                .map_or(name_raw, |z| &name_raw[..z]);
            let name: String = String::from_utf8_lossy(trimmed).into_owned();
            if !name.is_empty() && name != "." && name != ".." {
                entries.push((ino, name));
            }
        }
        pos += entry_len;
    }
    Ok(entries)
}

pub fn walk_minixfs(bytes: &[u8], max_total: u64) -> Result<MinixWalk> {
    let sb: MinixSuperblock = detect_minixfs(bytes)
        .ok_or_else(|| Error::Minixfs("minix superblock magic not found".to_owned()))?;
    let mut files: Vec<MinixFile> = Vec::new();
    let mut total: u64 = 0;
    let mut stack: Vec<(u32, String, usize)> = vec![(ROOT_INODE, String::new(), 0)];
    let mut visited: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    while let Some((ino, prefix, depth)) = stack.pop() {
        if depth > MAX_DEPTH || files.len() > MAX_FILES {
            break;
        }
        if !visited.insert(ino) {
            continue;
        }
        let inode: MinixInode = read_inode(bytes, &sb, ino)?;
        let kind: u16 = inode.mode & S_IFMT;
        if kind == S_IFDIR {
            let entries: Vec<(u32, String)> = read_directory(bytes, &sb, &inode)?;
            for (child_ino, name) in entries.into_iter().rev() {
                let child_path: String = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                stack.push((child_ino, child_path, depth + 1));
            }
        } else if kind == S_IFREG {
            let data: Vec<u8> = read_file_data(bytes, &sb, &inode, max_total)?;
            total = total.saturating_add(data.len() as u64);
            if total > max_total {
                return Err(Error::Minixfs(format!(
                    "walk exceeds total cap {max_total}"
                )));
            }
            files.push(MinixFile {
                path: prefix,
                is_executable: inode.mode & 0o111 != 0,
                data,
                is_symlink: false,
            });
        } else if kind == S_IFLNK {
            let data: Vec<u8> = read_file_data(bytes, &sb, &inode, max_total)?;
            files.push(MinixFile {
                path: prefix,
                data,
                is_executable: false,
                is_symlink: true,
            });
        }
    }
    Ok(MinixWalk {
        superblock: sb,
        files,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    struct MinixBuilder {
        version: MinixVersion,
        name_len: usize,
        inode_len: usize,
        block_size: usize,
        ninodes: u32,
        imap_blocks: u32,
        zmap_blocks: u32,
        inode_blocks: u32,
        image: Vec<u8>,
    }

    impl MinixBuilder {
        fn new(version: MinixVersion) -> Self {
            let (name_len, inode_len): (usize, usize) = match version {
                MinixVersion::V1 => (30, INODE_V1_LEN),
                MinixVersion::V2 => (30, INODE_V2_LEN),
                MinixVersion::V3 => (60, INODE_V2_LEN),
            };
            Self {
                version,
                name_len,
                inode_len,
                block_size: 1024,
                ninodes: 32,
                imap_blocks: 1,
                zmap_blocks: 1,
                inode_blocks: 1,
                image: Vec::new(),
            }
        }

        fn inode_table_block(&self) -> usize {
            2 + self.imap_blocks as usize + self.zmap_blocks as usize
        }

        fn first_data_block(&self) -> usize {
            self.inode_table_block() + self.inode_blocks as usize
        }

        fn build(&mut self, files: &[(&str, &[u8], bool)]) -> Vec<u8> {
            let first_data: usize = self.first_data_block();
            let mut total_blocks: usize = first_data;
            let mut data_zone_of_inode: Vec<u32> = Vec::new();
            let root_dir_zone: u32 = total_blocks as u32;
            total_blocks += 1;
            for (_, body, _) in files {
                let need: usize = (body.len()).div_ceil(self.block_size).max(1);
                data_zone_of_inode.push(total_blocks as u32);
                total_blocks += need;
            }

            self.image = vec![0u8; total_blocks * self.block_size];

            let mut root: Vec<u8> = Vec::new();
            for (idx, (name, _, _)) in files.iter().enumerate() {
                let child_ino: u32 = 2 + idx as u32;
                root.extend_from_slice(&(child_ino as u16).to_le_bytes());
                let mut name_field: Vec<u8> = name.as_bytes().to_vec();
                name_field.resize(self.name_len, 0);
                root.extend_from_slice(&name_field);
            }
            let root_off: usize = root_dir_zone as usize * self.block_size;
            self.image[root_off..root_off + root.len()].copy_from_slice(&root);

            for (idx, (_, body, _)) in files.iter().enumerate() {
                let zone: u32 = data_zone_of_inode[idx];
                let off: usize = zone as usize * self.block_size;
                self.image[off..off + body.len()].copy_from_slice(body);
            }

            self.write_root_inode(root_dir_zone, root.len() as u32);
            for (idx, (_, body, exec)) in files.iter().enumerate() {
                let ino: u32 = 2 + idx as u32;
                let first_zone: u32 = data_zone_of_inode[idx];
                let nblocks: usize = (body.len()).div_ceil(self.block_size).max(1);
                let direct_zones: Vec<u32> =
                    (0..nblocks.min(7) as u32).map(|i| first_zone + i).collect();
                assert!(nblocks <= 7, "test builder only populates direct zones");
                self.write_file_inode(ino, &direct_zones, body.len() as u32, *exec);
            }

            self.write_super(total_blocks as u32, first_data as u32);
            self.image.clone()
        }

        fn build_with_indirect(&mut self, name: &str, body: &[u8]) -> Vec<u8> {
            let first_data: usize = self.first_data_block();
            let root_dir_zone: usize = first_data;
            let nblocks: usize = body.len().div_ceil(self.block_size).max(1);
            assert!(nblocks > 7, "indirect test requires more than 7 blocks");
            let data_first_zone: usize = root_dir_zone + 1;
            let indirect_zone: usize = data_first_zone + nblocks;
            let total_blocks: usize = indirect_zone + 1;
            self.image = vec![0u8; total_blocks * self.block_size];

            let mut root: Vec<u8> = Vec::new();
            root.extend_from_slice(&2u16.to_le_bytes());
            let mut name_field: Vec<u8> = name.as_bytes().to_vec();
            name_field.resize(self.name_len, 0);
            root.extend_from_slice(&name_field);
            let root_off: usize = root_dir_zone * self.block_size;
            self.image[root_off..root_off + root.len()].copy_from_slice(&root);

            let data_off: usize = data_first_zone * self.block_size;
            self.image[data_off..data_off + body.len()].copy_from_slice(body);

            let direct: Vec<u32> = (0..7u32).map(|i| (data_first_zone as u32) + i).collect();
            let indirect_ptrs: Vec<u32> = (7..nblocks as u32)
                .map(|i| (data_first_zone as u32) + i)
                .collect();
            let ind_off: usize = indirect_zone * self.block_size;
            match self.version {
                MinixVersion::V1 => {
                    for (i, &z) in indirect_ptrs.iter().enumerate() {
                        let at: usize = ind_off + i * 2;
                        self.image[at..at + 2].copy_from_slice(&(z as u16).to_le_bytes());
                    }
                }
                MinixVersion::V2 | MinixVersion::V3 => {
                    for (i, &z) in indirect_ptrs.iter().enumerate() {
                        let at: usize = ind_off + i * 4;
                        self.image[at..at + 4].copy_from_slice(&z.to_le_bytes());
                    }
                }
            }

            let mut zones: Vec<u32> = direct;
            zones.push(indirect_zone as u32);
            self.write_root_inode(root_dir_zone as u32, root.len() as u32);
            self.write_file_inode(2, &zones, body.len() as u32, false);
            self.write_super(total_blocks as u32, first_data as u32);
            self.image.clone()
        }

        fn inode_offset(&self, ino: u32) -> usize {
            self.inode_table_block() * self.block_size + (ino as usize - 1) * self.inode_len
        }

        fn write_root_inode(&mut self, zone: u32, size: u32) {
            self.write_inode(ROOT_INODE, S_IFDIR | 0o755, size, &[zone]);
        }

        fn write_file_inode(&mut self, ino: u32, zones: &[u32], size: u32, exec: bool) {
            let mode: u16 = S_IFREG | if exec { 0o755 } else { 0o644 };
            self.write_inode(ino, mode, size, zones);
        }

        fn write_inode(&mut self, ino: u32, mode: u16, size: u32, zones: &[u32]) {
            let off: usize = self.inode_offset(ino);
            match self.version {
                MinixVersion::V1 => {
                    self.image[off..off + 2].copy_from_slice(&mode.to_le_bytes());
                    self.image[off + INODE_SIZE_OFFSET_V1..off + INODE_SIZE_OFFSET_V1 + 4]
                        .copy_from_slice(&size.to_le_bytes());
                    for (i, &z) in zones.iter().enumerate().take(9) {
                        let zoff: usize = off + 14 + i * 2;
                        self.image[zoff..zoff + 2].copy_from_slice(&(z as u16).to_le_bytes());
                    }
                }
                MinixVersion::V2 | MinixVersion::V3 => {
                    self.image[off..off + 2].copy_from_slice(&mode.to_le_bytes());
                    self.image[off + INODE_SIZE_OFFSET_V2..off + INODE_SIZE_OFFSET_V2 + 4]
                        .copy_from_slice(&size.to_le_bytes());
                    for (i, &z) in zones.iter().enumerate().take(9) {
                        let zoff: usize = off + 24 + i * 4;
                        self.image[zoff..zoff + 4].copy_from_slice(&z.to_le_bytes());
                    }
                }
            }
        }

        fn write_super(&mut self, zones: u32, first_data: u32) {
            let base: usize = BOOT_BLOCK_LEN;
            match self.version {
                MinixVersion::V1 | MinixVersion::V2 => {
                    self.image[base..base + 2]
                        .copy_from_slice(&(self.ninodes as u16).to_le_bytes());
                    if self.version == MinixVersion::V1 {
                        self.image[base + 2..base + 4]
                            .copy_from_slice(&(zones as u16).to_le_bytes());
                    }
                    self.image[base + 4..base + 6]
                        .copy_from_slice(&(self.imap_blocks as u16).to_le_bytes());
                    self.image[base + 6..base + 8]
                        .copy_from_slice(&(self.zmap_blocks as u16).to_le_bytes());
                    self.image[base + 8..base + 10]
                        .copy_from_slice(&(first_data as u16).to_le_bytes());
                    self.image[base + 10..base + 12].copy_from_slice(&0u16.to_le_bytes());
                    self.image[base + 12..base + 16].copy_from_slice(&0x1000_0000u32.to_le_bytes());
                    if self.version == MinixVersion::V2 {
                        self.image[base + 20..base + 24].copy_from_slice(&zones.to_le_bytes());
                    }
                    let magic: u16 = match (self.version, self.name_len) {
                        (MinixVersion::V1, 30) => SUPER_MAGIC_V1_30,
                        (MinixVersion::V1, _) => SUPER_MAGIC_V1_14,
                        (MinixVersion::V2, 30) => SUPER_MAGIC_V2_30,
                        (MinixVersion::V2, _) => SUPER_MAGIC_V2_14,
                        _ => unreachable!(),
                    };
                    self.image[base + 16..base + 18].copy_from_slice(&magic.to_le_bytes());
                }
                MinixVersion::V3 => {
                    self.image[base..base + 4].copy_from_slice(&self.ninodes.to_le_bytes());
                    self.image[base + 8..base + 10]
                        .copy_from_slice(&(self.imap_blocks as u16).to_le_bytes());
                    self.image[base + 10..base + 12]
                        .copy_from_slice(&(self.zmap_blocks as u16).to_le_bytes());
                    self.image[base + 12..base + 14]
                        .copy_from_slice(&(first_data as u16).to_le_bytes());
                    self.image[base + 14..base + 16].copy_from_slice(&0u16.to_le_bytes());
                    self.image[base + 16..base + 20].copy_from_slice(&0x1000_0000u32.to_le_bytes());
                    self.image[base + 20..base + 24].copy_from_slice(&zones.to_le_bytes());
                    self.image[base + 24..base + 26].copy_from_slice(&SUPER_MAGIC_V3.to_le_bytes());
                    self.image[base + 26..base + 28]
                        .copy_from_slice(&(self.block_size as u16).to_le_bytes());
                }
            }
        }
    }

    fn roundtrip_case(version: MinixVersion) {
        let body_a: Vec<u8> = b"minix regular file payload exact ".repeat(6);
        let body_b: Vec<u8> = b"second minix file 0123456789".to_vec();
        let files: [(&str, &[u8], bool); 2] =
            [("alpha.txt", &body_a, true), ("beta.bin", &body_b, false)];
        let image: Vec<u8> = MinixBuilder::new(version).build(&files);
        let sb: MinixSuperblock = detect_minixfs(&image).expect("detect minix");
        assert_eq!(sb.version, version);
        let walk: MinixWalk = walk_minixfs(&image, 64 * 1024 * 1024).expect("walk minix");
        assert_eq!(walk.files.len(), 2, "version {version:?}");
        let alpha: &MinixFile = walk
            .files
            .iter()
            .find(|f| f.path == "alpha.txt")
            .expect("alpha");
        assert_eq!(alpha.data, body_a, "version {version:?} alpha bytes");
        assert!(alpha.is_executable);
        let beta: &MinixFile = walk
            .files
            .iter()
            .find(|f| f.path == "beta.bin")
            .expect("beta");
        assert_eq!(beta.data, body_b, "version {version:?} beta bytes");
        assert!(!beta.is_executable);
    }

    #[test]
    fn roundtrip_v1() {
        roundtrip_case(MinixVersion::V1);
    }

    #[test]
    fn roundtrip_v2() {
        roundtrip_case(MinixVersion::V2);
    }

    #[test]
    fn roundtrip_v3() {
        roundtrip_case(MinixVersion::V3);
    }

    #[test]
    fn rejects_non_minix() {
        assert!(detect_minixfs(&[0u8; 2048]).is_none());
        assert!(detect_minixfs(&[0u8; 16]).is_none());
    }

    #[test]
    fn multi_block_file_via_direct_zones() {
        let big: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let files: [(&str, &[u8], bool); 1] = [("big.dat", &big, false)];
        let image: Vec<u8> = MinixBuilder::new(MinixVersion::V2).build(&files);
        let walk: MinixWalk = walk_minixfs(&image, 64 * 1024 * 1024).expect("walk");
        assert_eq!(walk.files.len(), 1);
        assert_eq!(walk.files[0].data, big);
    }

    #[test]
    fn large_file_via_single_indirect_zone() {
        for version in [MinixVersion::V1, MinixVersion::V2, MinixVersion::V3] {
            let big: Vec<u8> = (0..20_000u32).map(|i| ((i * 13) % 256) as u8).collect();
            let image: Vec<u8> = MinixBuilder::new(version).build_with_indirect("huge.bin", &big);
            let walk: MinixWalk = walk_minixfs(&image, 64 * 1024 * 1024).expect("walk indirect");
            assert_eq!(walk.files.len(), 1, "version {version:?}");
            assert_eq!(walk.files[0].path, "huge.bin");
            assert_eq!(
                walk.files[0].data, big,
                "version {version:?} indirect bytes"
            );
        }
    }

    #[test]
    fn extract_to_writes_minix_files() {
        let body: Vec<u8> = b"minix end to end extract abcdef".to_vec();
        let files: [(&str, &[u8], bool); 1] = [("note.txt", &body, false)];
        let image: Vec<u8> = MinixBuilder::new(MinixVersion::V3).build(&files);
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-minix-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::MinixFs, &image, &dir)
                .expect("minix extract");
        assert_eq!(result.kind, crate::container::ContainerKind::MinixFs);
        assert_eq!(std::fs::read(dir.join("note.txt")).expect("note"), body);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn put_u16(img: &mut [u8], at: usize, v: u16) {
        img[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u32(img: &mut [u8], at: usize, v: u32) {
        img[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn write_v2_super(img: &mut [u8], first_data: u16, zones: u32) {
        let base: usize = BOOT_BLOCK_LEN;
        put_u16(img, base, 32);
        put_u16(img, base + 4, 1);
        put_u16(img, base + 6, 1);
        put_u16(img, base + 8, first_data);
        put_u16(img, base + 10, 0);
        put_u32(img, base + 12, 0x1000_0000);
        put_u16(img, base + 16, SUPER_MAGIC_V2_30);
        put_u32(img, base + 20, zones);
    }

    fn write_v2_inode(img: &mut [u8], ino: u32, mode: u16, size: u32, zone0: u32) {
        let table: usize = 4 * 1024;
        let off: usize = table + (ino as usize - 1) * INODE_V2_LEN;
        put_u16(img, off, mode);
        put_u32(img, off + INODE_SIZE_OFFSET_V2, size);
        put_u32(img, off + 24, zone0);
    }

    fn write_v2_dir_entry(img: &mut [u8], at: usize, ino: u16, name: &str) {
        put_u16(img, at, ino);
        let nb: &[u8] = name.as_bytes();
        img[at + 2..at + 2 + nb.len()].copy_from_slice(nb);
    }

    #[test]
    fn oversized_root_inode_size_stays_bounded() {
        let body_a: Vec<u8> = b"alpha minix payload bytes".to_vec();
        let body_b: Vec<u8> = b"beta minix payload bytes".to_vec();
        let files: [(&str, &[u8], bool); 2] =
            [("a.txt", &body_a, false), ("b.bin", &body_b, false)];
        let mut builder: MinixBuilder = MinixBuilder::new(MinixVersion::V2);
        let mut image: Vec<u8> = builder.build(&files);
        let size_off: usize = builder.inode_offset(ROOT_INODE) + INODE_SIZE_OFFSET_V2;
        image[size_off..size_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let walk: MinixWalk =
            walk_minixfs(&image, 64 * 1024 * 1024).expect("bounded walk with huge root size");
        assert_eq!(walk.files.len(), 2);
    }

    #[test]
    fn self_referential_directory_terminates() {
        let block_size: usize = 1024;
        let total_blocks: usize = 7;
        let mut image: Vec<u8> = vec![0u8; total_blocks * block_size];
        write_v2_super(&mut image, 5, total_blocks as u32);
        write_v2_inode(&mut image, 1, S_IFDIR | 0o755, 32, 5);
        write_v2_inode(&mut image, 2, S_IFDIR | 0o755, 8 * 32, 6);
        write_v2_dir_entry(&mut image, 5 * block_size, 2, "sub");
        let loop_off: usize = 6 * block_size;
        for k in 0..8usize {
            write_v2_dir_entry(&mut image, loop_off + k * 32, 2, &format!("d{k}"));
        }
        let walk: MinixWalk =
            walk_minixfs(&image, 64 * 1024 * 1024).expect("self-referential walk terminates");
        assert!(walk.files.is_empty());
    }

    #[test]
    fn nested_directory_recovers_file() {
        let block_size: usize = 1024;
        let total_blocks: usize = 8;
        let mut image: Vec<u8> = vec![0u8; total_blocks * block_size];
        write_v2_super(&mut image, 5, total_blocks as u32);
        let body: &[u8] = b"nested minix file body 0123456789";
        write_v2_inode(&mut image, 1, S_IFDIR | 0o755, 32, 5);
        write_v2_inode(&mut image, 2, S_IFDIR | 0o755, 32, 6);
        write_v2_inode(&mut image, 3, S_IFREG | 0o644, body.len() as u32, 7);
        write_v2_dir_entry(&mut image, 5 * block_size, 2, "sub");
        write_v2_dir_entry(&mut image, 6 * block_size, 3, "file.txt");
        let data_off: usize = 7 * block_size;
        image[data_off..data_off + body.len()].copy_from_slice(body);
        let walk: MinixWalk = walk_minixfs(&image, 64 * 1024 * 1024).expect("nested walk");
        assert_eq!(walk.files.len(), 1);
        assert_eq!(walk.files[0].path, "sub/file.txt");
        assert_eq!(walk.files[0].data, body);
    }
}
