use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const DIR_ENTRY_LEN: usize = 32;
const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_LONG_NAME: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;
const ATTR_LONG_NAME_MASK: u8 =
    ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID | ATTR_DIRECTORY;
const DELETED_ENTRY: u8 = 0xe5;
const END_OF_DIR: u8 = 0x00;
const LFN_LAST_MASK: u8 = 0x40;
const LFN_SEQ_MASK: u8 = 0x1f;
const MAX_DIR_RECURSION: u32 = 64;
const MAX_DIR_ENTRIES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FatKind {
    Fat12,
    Fat16,
    Fat32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatBpb {
    pub kind: FatKind,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sector_count: u16,
    pub num_fats: u8,
    pub root_entry_count: u16,
    pub total_sectors: u32,
    pub fat_size_sectors: u32,
    pub root_cluster: u32,
    pub first_data_sector: u32,
    pub cluster_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatFile {
    pub path: String,
    pub size: u64,
    pub first_cluster: u32,
    pub is_read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatVolume {
    pub bpb: FatBpb,
    pub volume_label: Option<String>,
    pub files: Vec<FatFile>,
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice: &[u8] = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice: &[u8] = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[must_use]
pub fn detect_fat(bytes: &[u8]) -> bool {
    parse_bpb(bytes).is_ok()
}

pub fn parse_bpb(bytes: &[u8]) -> Result<FatBpb> {
    let boot: &[u8] = bytes
        .get(0..512)
        .ok_or_else(|| Error::Decompression("fat boot sector truncated".to_owned()))?;
    if boot[510] != 0x55 || boot[511] != 0xaa {
        return Err(Error::Decompression(
            "fat boot sector missing 0x55aa signature".to_owned(),
        ));
    }
    let bytes_per_sector: u16 = read_u16_le(boot, 11)
        .ok_or_else(|| Error::Decompression("fat bpb truncated".to_owned()))?;
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return Err(Error::Decompression(format!(
            "fat bytes-per-sector {bytes_per_sector} not a valid power of two"
        )));
    }
    let sectors_per_cluster: u8 = boot[13];
    if !matches!(sectors_per_cluster, 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128) {
        return Err(Error::Decompression(format!(
            "fat sectors-per-cluster {sectors_per_cluster} not a valid power of two"
        )));
    }
    let reserved_sector_count: u16 = read_u16_le(boot, 14)
        .ok_or_else(|| Error::Decompression("fat reserved-sector count truncated".to_owned()))?;
    if reserved_sector_count == 0 {
        return Err(Error::Decompression(
            "fat reserved-sector count is zero".to_owned(),
        ));
    }
    let num_fats: u8 = boot[16];
    if num_fats == 0 {
        return Err(Error::Decompression("fat fat-count is zero".to_owned()));
    }
    let root_entry_count: u16 = read_u16_le(boot, 17)
        .ok_or_else(|| Error::Decompression("fat root-entry count truncated".to_owned()))?;
    let total_sectors_16: u16 = read_u16_le(boot, 19)
        .ok_or_else(|| Error::Decompression("fat total-sectors16 truncated".to_owned()))?;
    let total_sectors_32: u32 = read_u32_le(boot, 32)
        .ok_or_else(|| Error::Decompression("fat total-sectors32 truncated".to_owned()))?;
    let fat_size_16: u16 = read_u16_le(boot, 22)
        .ok_or_else(|| Error::Decompression("fat size16 truncated".to_owned()))?;
    let total_sectors: u32 = if total_sectors_16 != 0 {
        u32::from(total_sectors_16)
    } else {
        total_sectors_32
    };
    if total_sectors == 0 {
        return Err(Error::Decompression("fat total-sectors is zero".to_owned()));
    }
    let fat_size_sectors: u32 = if fat_size_16 != 0 {
        u32::from(fat_size_16)
    } else {
        read_u32_le(boot, 36)
            .ok_or_else(|| Error::Decompression("fat size32 truncated".to_owned()))?
    };
    if fat_size_sectors == 0 {
        return Err(Error::Decompression("fat size is zero".to_owned()));
    }
    let root_dir_sectors: u32 = (u32::from(root_entry_count) * (DIR_ENTRY_LEN as u32))
        .div_ceil(u32::from(bytes_per_sector));
    let first_data_sector: u32 = u32::from(reserved_sector_count)
        .checked_add(
            (u32::from(num_fats))
                .checked_mul(fat_size_sectors)
                .ok_or_else(|| {
                    Error::Decompression("fat data-region offset overflow".to_owned())
                })?,
        )
        .and_then(|v: u32| v.checked_add(root_dir_sectors))
        .ok_or_else(|| Error::Decompression("fat data-region offset overflow".to_owned()))?;
    if first_data_sector >= total_sectors {
        return Err(Error::Decompression(
            "fat data region starts past end of volume".to_owned(),
        ));
    }
    let data_sectors: u32 = total_sectors - first_data_sector;
    let cluster_count: u32 = data_sectors / u32::from(sectors_per_cluster);
    let kind: FatKind = if cluster_count < 4085 {
        FatKind::Fat12
    } else if cluster_count < 65525 {
        FatKind::Fat16
    } else {
        FatKind::Fat32
    };
    let root_cluster: u32 = if kind == FatKind::Fat32 {
        read_u32_le(boot, 44)
            .ok_or_else(|| Error::Decompression("fat32 root-cluster truncated".to_owned()))?
    } else {
        0
    };
    Ok(FatBpb {
        kind,
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sector_count,
        num_fats,
        root_entry_count,
        total_sectors,
        fat_size_sectors,
        root_cluster,
        first_data_sector,
        cluster_count,
    })
}

struct FatReader<'a> {
    image: &'a [u8],
    bpb: FatBpb,
    cluster_bytes: usize,
    fat_offset: usize,
    max_total: u64,
}

impl<'a> FatReader<'a> {
    fn new(image: &'a [u8], bpb: FatBpb, max_total: u64) -> Self {
        let cluster_bytes: usize =
            usize::from(bpb.bytes_per_sector) * usize::from(bpb.sectors_per_cluster);
        let fat_offset: usize =
            usize::from(bpb.reserved_sector_count) * usize::from(bpb.bytes_per_sector);
        Self {
            image,
            bpb,
            cluster_bytes,
            fat_offset,
            max_total,
        }
    }

    fn fat_entry(&self, cluster: u32) -> Option<u32> {
        match self.bpb.kind {
            FatKind::Fat12 => {
                let index: usize = (cluster as usize).checked_mul(3)? / 2;
                let pair: &[u8] = self
                    .image
                    .get(self.fat_offset + index..self.fat_offset + index + 2)?;
                let raw: u16 = u16::from_le_bytes([pair[0], pair[1]]);
                let value: u16 = if cluster & 1 == 0 {
                    raw & 0x0fff
                } else {
                    raw >> 4
                };
                Some(u32::from(value))
            }
            FatKind::Fat16 => {
                let index: usize = (cluster as usize).checked_mul(2)?;
                let pair: &[u8] = self
                    .image
                    .get(self.fat_offset + index..self.fat_offset + index + 2)?;
                Some(u32::from(u16::from_le_bytes([pair[0], pair[1]])))
            }
            FatKind::Fat32 => {
                let index: usize = (cluster as usize).checked_mul(4)?;
                let quad: &[u8] = self
                    .image
                    .get(self.fat_offset + index..self.fat_offset + index + 4)?;
                Some(u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]) & 0x0fff_ffff)
            }
        }
    }

    const fn is_end_of_chain(&self, value: u32) -> bool {
        match self.bpb.kind {
            FatKind::Fat12 => value >= 0xff8,
            FatKind::Fat16 => value >= 0xfff8,
            FatKind::Fat32 => value >= 0x0fff_fff8,
        }
    }

    const fn is_bad_cluster(&self, value: u32) -> bool {
        match self.bpb.kind {
            FatKind::Fat12 => value == 0xff7,
            FatKind::Fat16 => value == 0xfff7,
            FatKind::Fat32 => value == 0x0fff_fff7,
        }
    }

    fn cluster_offset(&self, cluster: u32) -> Option<usize> {
        if cluster < 2 {
            return None;
        }
        let sector: u32 = self
            .bpb
            .first_data_sector
            .checked_add((cluster - 2).checked_mul(u32::from(self.bpb.sectors_per_cluster))?)?;
        (sector as usize).checked_mul(usize::from(self.bpb.bytes_per_sector))
    }

    fn root_dir_region(&self) -> Option<(usize, usize)> {
        if self.bpb.kind == FatKind::Fat32 {
            return None;
        }
        let root_dir_sectors: usize = (usize::from(self.bpb.root_entry_count) * DIR_ENTRY_LEN)
            .div_ceil(usize::from(self.bpb.bytes_per_sector));
        let first_root_sector: usize = usize::from(self.bpb.reserved_sector_count)
            + usize::from(self.bpb.num_fats) * (self.bpb.fat_size_sectors as usize);
        let start: usize = first_root_sector.checked_mul(usize::from(self.bpb.bytes_per_sector))?;
        let len: usize = root_dir_sectors.checked_mul(usize::from(self.bpb.bytes_per_sector))?;
        Some((start, len))
    }

    fn read_chain(&self, first_cluster: u32, declared_size: u64) -> Result<Vec<u8>> {
        let want: usize = usize::try_from(declared_size.min(self.max_total)).map_err(
            |_e: std::num::TryFromIntError| {
                Error::Decompression("fat file size overflow".to_owned())
            },
        )?;
        let mut out: Vec<u8> = Vec::with_capacity(want.min(self.cluster_bytes.max(1) * 16));
        let mut cluster: u32 = first_cluster;
        let mut seen: usize = 0;
        let cluster_limit: usize = (self.bpb.cluster_count as usize).saturating_add(2);
        while out.len() < want {
            if cluster < 2 || self.is_end_of_chain(cluster) || self.is_bad_cluster(cluster) {
                break;
            }
            if cluster >= self.bpb.cluster_count + 2 {
                return Err(Error::Decompression(format!(
                    "fat cluster {cluster} exceeds cluster count {}",
                    self.bpb.cluster_count
                )));
            }
            let Some(off): Option<usize> = self.cluster_offset(cluster) else {
                break;
            };
            let remaining: usize = want - out.len();
            let take: usize = remaining.min(self.cluster_bytes);
            let chunk: &[u8] = self.image.get(off..off + take).ok_or_else(|| {
                Error::Decompression(format!(
                    "fat cluster {cluster} at offset {off} runs past the {}-byte image",
                    self.image.len()
                ))
            })?;
            out.extend_from_slice(chunk);
            let Some(next): Option<u32> = self.fat_entry(cluster) else {
                break;
            };
            cluster = next;
            seen += 1;
            if seen > cluster_limit {
                return Err(Error::Decompression(
                    "fat cluster chain exceeds total cluster count (loop)".to_owned(),
                ));
            }
        }
        out.truncate(want);
        Ok(out)
    }

    fn read_dir_clusters(&self, first_cluster: u32) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut cluster: u32 = first_cluster;
        let mut seen: usize = 0;
        let cluster_limit: usize = (self.bpb.cluster_count as usize).saturating_add(2);
        while cluster >= 2 && !self.is_end_of_chain(cluster) && !self.is_bad_cluster(cluster) {
            if cluster >= self.bpb.cluster_count + 2 {
                break;
            }
            let Some(off): Option<usize> = self.cluster_offset(cluster) else {
                break;
            };
            let Some(chunk): Option<&[u8]> = self.image.get(off..off + self.cluster_bytes) else {
                break;
            };
            out.extend_from_slice(chunk);
            if out.len() > self.max_total as usize {
                break;
            }
            let Some(next): Option<u32> = self.fat_entry(cluster) else {
                break;
            };
            cluster = next;
            seen += 1;
            if seen > cluster_limit {
                break;
            }
        }
        out
    }
}

fn decode_short_name(entry: &[u8]) -> Option<String> {
    let base_raw: &[u8] = &entry[0..8];
    let ext_raw: &[u8] = &entry[8..11];
    let mut base: Vec<u8> = base_raw.to_vec();
    if base.first() == Some(&0x05) {
        base[0] = DELETED_ENTRY;
    }
    let base_str: String = String::from_utf8_lossy(&base)
        .trim_end_matches(' ')
        .to_owned();
    let ext_str: String = String::from_utf8_lossy(ext_raw)
        .trim_end_matches(' ')
        .to_owned();
    let lowercase_flags: u8 = entry[12];
    let base_final: String = if lowercase_flags & 0x08 != 0 {
        base_str.to_ascii_lowercase()
    } else {
        base_str
    };
    let ext_final: String = if lowercase_flags & 0x10 != 0 {
        ext_str.to_ascii_lowercase()
    } else {
        ext_str
    };
    if base_final.is_empty() && ext_final.is_empty() {
        return None;
    }
    if ext_final.is_empty() {
        Some(base_final)
    } else {
        Some(format!("{base_final}.{ext_final}"))
    }
}

fn decode_lfn_part(entry: &[u8]) -> Vec<u16> {
    let positions: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    let mut units: Vec<u16> = Vec::with_capacity(13);
    for pos in positions {
        let unit: u16 = u16::from_le_bytes([entry[pos], entry[pos + 1]]);
        if unit == 0x0000 || unit == 0xffff {
            break;
        }
        units.push(unit);
    }
    units
}

fn lfn_checksum(short_name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &byte in short_name {
        sum = sum.rotate_right(1).wrapping_add(byte);
    }
    sum
}

struct DirWalk<'a, 'b> {
    reader: &'b FatReader<'a>,
    prefix: &'b str,
    files: &'b mut Vec<FatFile>,
    label: &'b mut Option<String>,
    depth: u32,
    entries_budget: &'b mut usize,
}

fn walk_dir(walk: DirWalk<'_, '_>, dir_bytes: &[u8], visited_clusters: &mut Vec<u32>) {
    let DirWalk {
        reader,
        prefix,
        files,
        label,
        depth,
        entries_budget,
    } = walk;
    if depth > MAX_DIR_RECURSION {
        return;
    }
    let mut pending_lfn: Vec<u16> = Vec::new();
    let mut pending_checksum: Option<u8> = None;
    let mut entry_index: usize = 0;
    while (entry_index + 1) * DIR_ENTRY_LEN <= dir_bytes.len() {
        if *entries_budget == 0 {
            return;
        }
        *entries_budget -= 1;
        let off: usize = entry_index * DIR_ENTRY_LEN;
        let entry: &[u8] = &dir_bytes[off..off + DIR_ENTRY_LEN];
        entry_index += 1;
        let marker: u8 = entry[0];
        if marker == END_OF_DIR {
            break;
        }
        if marker == DELETED_ENTRY {
            pending_lfn.clear();
            pending_checksum = None;
            continue;
        }
        let attr: u8 = entry[11];
        if attr & ATTR_LONG_NAME_MASK == ATTR_LONG_NAME {
            let seq: u8 = entry[0];
            if seq & LFN_LAST_MASK != 0 {
                pending_lfn.clear();
                pending_checksum = Some(entry[13]);
            }
            let order: usize = (seq & LFN_SEQ_MASK) as usize;
            let part: Vec<u16> = decode_lfn_part(entry);
            let insert_at: usize = order.saturating_sub(1) * 13;
            if insert_at <= 256 {
                if pending_lfn.len() < insert_at + part.len() {
                    pending_lfn.resize(insert_at + part.len(), 0);
                }
                pending_lfn.splice(insert_at..insert_at + part.len(), part);
            }
            continue;
        }
        if attr & ATTR_VOLUME_ID != 0 && attr & ATTR_DIRECTORY == 0 {
            let raw_label: String = String::from_utf8_lossy(&entry[0..11]).trim_end().to_owned();
            if !raw_label.is_empty() && label.is_none() {
                *label = Some(raw_label);
            }
            pending_lfn.clear();
            pending_checksum = None;
            continue;
        }

        let mut short_raw: [u8; 11] = [0u8; 11];
        short_raw.copy_from_slice(&entry[0..11]);
        let long_name: Option<String> = if pending_lfn.is_empty() {
            None
        } else if pending_checksum == Some(lfn_checksum(&short_raw)) {
            let trimmed: Vec<u16> = pending_lfn
                .iter()
                .copied()
                .take_while(|&u: &u16| u != 0)
                .collect();
            Some(String::from_utf16_lossy(&trimmed))
        } else {
            None
        };
        pending_lfn.clear();
        pending_checksum = None;

        let name: String = match long_name.or_else(|| decode_short_name(entry)) {
            Some(n) => n,
            None => continue,
        };
        if name == "." || name == ".." {
            continue;
        }
        let high: u16 = u16::from_le_bytes([entry[20], entry[21]]);
        let low: u16 = u16::from_le_bytes([entry[26], entry[27]]);
        let first_cluster: u32 = (u32::from(high) << 16) | u32::from(low);
        let size: u32 = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
        let child_path: String = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };

        if attr & ATTR_DIRECTORY != 0 {
            if first_cluster < 2 || visited_clusters.contains(&first_cluster) {
                continue;
            }
            visited_clusters.push(first_cluster);
            let sub_bytes: Vec<u8> = reader.read_dir_clusters(first_cluster);
            walk_dir(
                DirWalk {
                    reader,
                    prefix: &child_path,
                    files,
                    label,
                    depth: depth + 1,
                    entries_budget,
                },
                &sub_bytes,
                visited_clusters,
            );
        } else {
            files.push(FatFile {
                path: child_path,
                size: u64::from(size),
                first_cluster,
                is_read_only: attr & ATTR_READ_ONLY != 0,
            });
        }
    }
}

pub fn walk_fat(image: &[u8], max_total: u64) -> Result<FatVolume> {
    let bpb: FatBpb = parse_bpb(image)?;
    let reader: FatReader<'_> = FatReader::new(image, bpb, max_total);
    let mut files: Vec<FatFile> = Vec::new();
    let mut label: Option<String> = None;
    let mut entries_budget: usize = MAX_DIR_ENTRIES;
    let mut visited: Vec<u32> = Vec::new();

    let root_bytes: Vec<u8> = if let Some((start, len)) = reader.root_dir_region() {
        image
            .get(start..start + len)
            .ok_or_else(|| Error::Decompression("fat root directory runs past image".to_owned()))?
            .to_vec()
    } else {
        let root_cluster: u32 = bpb.root_cluster;
        if root_cluster < 2 {
            return Err(Error::Decompression(
                "fat32 root cluster is invalid".to_owned(),
            ));
        }
        visited.push(root_cluster);
        reader.read_dir_clusters(root_cluster)
    };
    walk_dir(
        DirWalk {
            reader: &reader,
            prefix: "",
            files: &mut files,
            label: &mut label,
            depth: 0,
            entries_budget: &mut entries_budget,
        },
        &root_bytes,
        &mut visited,
    );
    Ok(FatVolume {
        bpb,
        volume_label: label,
        files,
    })
}

pub fn file_data(image: &[u8], bpb: FatBpb, file: &FatFile, cap: u64) -> Result<Vec<u8>> {
    let reader: FatReader<'_> = FatReader::new(image, bpb, cap);
    if file.size == 0 {
        return Ok(Vec::new());
    }
    reader.read_chain(file.first_cluster, file.size)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_fat16_image() -> (Vec<u8>, Vec<u8>) {
        let bytes_per_sector: usize = 512;
        let sectors_per_cluster: usize = 1;
        let reserved: usize = 1;
        let num_fats: usize = 1;
        let root_entries: usize = 16;
        let fat_size: usize = 8;
        let total_sectors: usize = 4096;

        let payload: Vec<u8> = b"FAT16 KNOWN PAYLOAD 0123456789 abcdefghijklmnopqrstuvwxyz"
            .iter()
            .cycle()
            .take(900)
            .copied()
            .collect();

        let mut image: Vec<u8> = vec![0u8; total_sectors * bytes_per_sector];
        image[11..13].copy_from_slice(&(bytes_per_sector as u16).to_le_bytes());
        image[13] = sectors_per_cluster as u8;
        image[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
        image[16] = num_fats as u8;
        image[17..19].copy_from_slice(&(root_entries as u16).to_le_bytes());
        image[19..21].copy_from_slice(&(total_sectors as u16).to_le_bytes());
        image[22..24].copy_from_slice(&(fat_size as u16).to_le_bytes());
        image[510] = 0x55;
        image[511] = 0xaa;

        let root_dir_sectors: usize = (root_entries * DIR_ENTRY_LEN).div_ceil(bytes_per_sector);
        let first_data_sector: usize = reserved + num_fats * fat_size + root_dir_sectors;
        let cluster_count: usize = (total_sectors - first_data_sector) / sectors_per_cluster;
        assert!((4085..65525).contains(&cluster_count), "must be FAT16");

        let cluster_bytes: usize = bytes_per_sector * sectors_per_cluster;
        let needed_clusters: usize = payload.len().div_ceil(cluster_bytes);
        let fat_off: usize = reserved * bytes_per_sector;
        let first_cluster: u32 = 2;
        for i in 0..needed_clusters {
            let cluster: u32 = first_cluster + i as u32;
            let entry_off: usize = fat_off + (cluster as usize) * 2;
            let value: u16 = if i + 1 == needed_clusters {
                0xffff
            } else {
                (cluster + 1) as u16
            };
            image[entry_off..entry_off + 2].copy_from_slice(&value.to_le_bytes());
        }

        let data_off: usize = first_data_sector * bytes_per_sector;
        image[data_off..data_off + payload.len()].copy_from_slice(&payload);

        let root_off: usize = (reserved + num_fats * fat_size) * bytes_per_sector;
        let label: &[u8; 11] = b"DISROBEVOL ";
        image[root_off..root_off + 11].copy_from_slice(label);
        image[root_off + 11] = ATTR_VOLUME_ID;

        let entry: usize = root_off + DIR_ENTRY_LEN;
        let name: &[u8; 11] = b"HELLO   TXT";
        image[entry..entry + 11].copy_from_slice(name);
        image[entry + 11] = 0x20;
        image[entry + 26..entry + 28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        image[entry + 28..entry + 32].copy_from_slice(&(payload.len() as u32).to_le_bytes());

        (image, payload)
    }

    #[test]
    fn parses_fat16_bpb_and_reads_file_byte_exact() {
        let (image, payload): (Vec<u8>, Vec<u8>) = build_fat16_image();
        assert!(detect_fat(&image));
        let volume: FatVolume = walk_fat(&image, 1 << 30).expect("walk fat");
        assert_eq!(volume.bpb.kind, FatKind::Fat16);
        assert_eq!(volume.volume_label.as_deref(), Some("DISROBEVOL"));
        assert_eq!(volume.files.len(), 1);
        let file: &FatFile = &volume.files[0];
        assert_eq!(file.path, "HELLO.TXT");
        assert_eq!(file.size, payload.len() as u64);
        let data: Vec<u8> = file_data(&image, volume.bpb, file, 1 << 30).expect("data");
        assert_eq!(data, payload, "fat cluster chain must reconstruct verbatim");
    }

    #[test]
    fn rejects_non_fat() {
        assert!(!detect_fat(&[0u8; 16]));
        assert!(!detect_fat(&[0u8; 512]));
        let mut almost: Vec<u8> = vec![0u8; 512];
        almost[510] = 0x55;
        almost[511] = 0xaa;
        assert!(!detect_fat(&almost));
    }

    #[test]
    fn lfn_checksum_matches_spec_vector() {
        let name: [u8; 11] = *b"HELLO   TXT";
        let sum: u8 = lfn_checksum(&name);
        assert_eq!(
            sum,
            name.iter()
                .fold(0u8, |s: u8, &b: &u8| s.rotate_right(1).wrapping_add(b))
        );
    }
}
