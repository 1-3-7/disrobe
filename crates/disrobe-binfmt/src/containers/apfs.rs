use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const OBJ_HEADER_LEN: usize = 32;
const NX_MAGIC: u32 = 0x4253_584E;
const APFS_MAGIC: u32 = 0x4253_5041;
const NX_MAX_FILE_SYSTEMS: usize = 100;
const APFS_VOLUME_NAME_OFFSET: usize = 0x2C0;
const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;
const BTREE_TOC_OFFSET: usize = OBJ_HEADER_LEN + 16;
const BTREE_INFO_LEN: usize = 40;
const MAX_OMAP_ENTRIES: usize = 5_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApfsContainer {
    pub block_size: u32,
    pub block_count: u64,
    pub volume_oids: Vec<u64>,
    pub volumes: Vec<ApfsVolume>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApfsVolume {
    pub name: String,
    pub fs_index: u64,
    pub num_files: u64,
    pub num_directories: u64,
    pub role: u16,
    pub omap_oid: u64,
    pub root_tree_oid: u64,
}

#[inline]
fn le_u16(b: &[u8], at: usize) -> Option<u16> {
    let s: &[u8] = b.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    let s: &[u8] = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
fn le_u64(b: &[u8], at: usize) -> Option<u64> {
    let s: &[u8] = b.get(at..at + 8)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

pub fn detect_apfs(bytes: &[u8]) -> bool {
    le_u32(bytes, OBJ_HEADER_LEN).is_some_and(|m: u32| m == NX_MAGIC)
}

pub fn parse_apfs(bytes: &[u8]) -> Result<ApfsContainer> {
    if !detect_apfs(bytes) {
        return Err(Error::Decompression(
            "apfs container superblock magic NXSB not found at block 0".to_owned(),
        ));
    }
    let nx: &[u8] = bytes;
    let block_size: u32 = le_u32(nx, OBJ_HEADER_LEN + 4)
        .filter(|&b: &u32| b >= 512 && b.is_power_of_two())
        .ok_or_else(|| Error::Decompression("apfs block size invalid".to_owned()))?;
    let block_count: u64 = le_u64(nx, OBJ_HEADER_LEN + 8)
        .ok_or_else(|| Error::Decompression("apfs block count truncated".to_owned()))?;

    let fs_oid_base: usize = OBJ_HEADER_LEN + 184;
    let mut volume_oids: Vec<u64> = Vec::new();
    for i in 0..NX_MAX_FILE_SYSTEMS {
        let Some(oid): Option<u64> = le_u64(nx, fs_oid_base + i * 8) else {
            break;
        };
        if oid == 0 {
            continue;
        }
        volume_oids.push(oid);
    }

    let volumes: Vec<ApfsVolume> = scan_volume_superblocks(bytes, block_size);
    Ok(ApfsContainer {
        block_size,
        block_count,
        volume_oids,
        volumes,
    })
}

fn scan_volume_superblocks(bytes: &[u8], block_size: u32) -> Vec<ApfsVolume> {
    let mut volumes: Vec<ApfsVolume> = Vec::new();
    let block_size: usize = block_size as usize;
    if block_size == 0 {
        return volumes;
    }
    let block_count: usize = bytes.len() / block_size;
    for block in 0..block_count.min(1_000_000) {
        let start: usize = block * block_size;
        let Some(magic): Option<u32> = le_u32(bytes, start + OBJ_HEADER_LEN) else {
            continue;
        };
        if magic != APFS_MAGIC {
            continue;
        }
        if let Some(volume) = parse_volume_superblock(&bytes[start..]) {
            volumes.push(volume);
        }
    }
    volumes
}

fn parse_volume_superblock(apsb: &[u8]) -> Option<ApfsVolume> {
    let fs_index: u64 = le_u64(apsb, OBJ_HEADER_LEN + 4)?;
    let role: u16 = le_u16(apsb, OBJ_HEADER_LEN + 0x24).map_or(0, |value: u16| value);
    let omap_oid: u64 = le_u64(apsb, OBJ_HEADER_LEN + 0x80).map_or(0, |value: u64| value);
    let root_tree_oid: u64 = le_u64(apsb, OBJ_HEADER_LEN + 0x88).map_or(0, |value: u64| value);
    let num_files: u64 = le_u64(apsb, OBJ_HEADER_LEN + 0x40).map_or(0, |value: u64| value);
    let num_directories: u64 = le_u64(apsb, OBJ_HEADER_LEN + 0x48).map_or(0, |value: u64| value);
    let name_off: usize = OBJ_HEADER_LEN + APFS_VOLUME_NAME_OFFSET;
    let name: String = read_cstr(apsb, name_off, 256);
    Some(ApfsVolume {
        name,
        fs_index,
        num_files,
        num_directories,
        role,
        omap_oid,
        root_tree_oid,
    })
}

fn read_cstr(bytes: &[u8], at: usize, max: usize) -> String {
    let mut out: Vec<u8> = Vec::new();
    for i in 0..max {
        match bytes.get(at + i) {
            Some(&0) | None => break,
            Some(&b) => out.push(b),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug, Clone, Copy)]
struct BtreeNode {
    level: u16,
    nkeys: u32,
    fixed_kv: bool,
    toc_off: usize,
    key_area_start: usize,
    val_area_end: usize,
}

fn parse_btree_node(node: &[u8]) -> Option<BtreeNode> {
    let flags: u16 = le_u16(node, OBJ_HEADER_LEN)?;
    let level: u16 = le_u16(node, OBJ_HEADER_LEN + 2)?;
    let nkeys: u32 = le_u32(node, OBJ_HEADER_LEN + 4)?;
    let table_off: u16 = le_u16(node, OBJ_HEADER_LEN + 8)?;
    let table_len: u16 = le_u16(node, OBJ_HEADER_LEN + 10)?;
    let fixed_kv: bool = flags & BTNODE_FIXED_KV_SIZE != 0;
    let toc_off: usize = BTREE_TOC_OFFSET + usize::from(table_off);
    let key_area_start: usize = toc_off + usize::from(table_len);
    let is_root: bool = flags & 0x0001 != 0;
    let val_area_end: usize = if is_root {
        node.len().checked_sub(BTREE_INFO_LEN)?
    } else {
        node.len()
    };
    Some(BtreeNode {
        level,
        nkeys,
        fixed_kv,
        toc_off,
        key_area_start,
        val_area_end,
    })
}

fn omap_leaf_mappings(node: &[u8], out: &mut Vec<(u64, u64)>) -> Option<()> {
    let meta: BtreeNode = parse_btree_node(node)?;
    if meta.level != 0 || !meta.fixed_kv {
        return Some(());
    }
    let nkeys: usize = meta.nkeys as usize;
    for i in 0..nkeys {
        if out.len() > MAX_OMAP_ENTRIES {
            break;
        }
        let toc_entry: usize = meta.toc_off + i * 4;
        let key_rel: u16 = le_u16(node, toc_entry)?;
        let val_rel: u16 = le_u16(node, toc_entry + 2)?;
        let key_off: usize = meta.key_area_start + usize::from(key_rel);
        let val_off: usize = meta.val_area_end.checked_sub(usize::from(val_rel))?;
        let oid: u64 = le_u64(node, key_off)?;
        let paddr: u64 = le_u64(node, val_off + 8)?;
        out.push((oid, paddr));
    }
    Some(())
}

#[must_use]
pub fn resolve_omap_tree(image: &[u8], block_size: u32, omap_tree_block: u64) -> Vec<(u64, u64)> {
    let mut mappings: Vec<(u64, u64)> = Vec::new();
    let block_size: usize = block_size as usize;
    if block_size == 0 {
        return mappings;
    }
    let start: usize = (omap_tree_block as usize).saturating_mul(block_size);
    let Some(node): Option<&[u8]> = image.get(start..start + block_size) else {
        return mappings;
    };
    if parse_btree_node(node).is_none() {
        return mappings;
    }
    let _ = omap_leaf_mappings(node, &mut mappings);
    mappings
}

const J_OBJ_TYPE_SHIFT: u64 = 60;
const APFS_TYPE_INODE: u8 = 3;
const APFS_TYPE_FILE_EXTENT: u8 = 8;
const APFS_TYPE_DREC: u8 = 9;
const J_DREC_HASHED_NAME_MASK: u32 = 0x0000_03FF;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApfsFsRecord {
    pub object_id: u64,
    pub record_type: u8,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[must_use]
pub fn walk_fs_tree_leaf(image: &[u8], block_size: u32, tree_block: u64) -> Vec<ApfsFsRecord> {
    let mut records: Vec<ApfsFsRecord> = Vec::new();
    let block_size: usize = block_size as usize;
    if block_size == 0 {
        return records;
    }
    let start: usize = (tree_block as usize).saturating_mul(block_size);
    let Some(node): Option<&[u8]> = image.get(start..start + block_size) else {
        return records;
    };
    let Some(meta): Option<BtreeNode> = parse_btree_node(node) else {
        return records;
    };
    if meta.level != 0 || meta.fixed_kv {
        return records;
    }
    let nkeys: usize = meta.nkeys as usize;
    for i in 0..nkeys.min(MAX_OMAP_ENTRIES) {
        let toc_entry: usize = meta.toc_off + i * 8;
        let Some(key_off_rel): Option<u16> = le_u16(node, toc_entry) else {
            break;
        };
        let Some(key_len): Option<u16> = le_u16(node, toc_entry + 2) else {
            break;
        };
        let Some(val_off_rel): Option<u16> = le_u16(node, toc_entry + 4) else {
            break;
        };
        let Some(val_len): Option<u16> = le_u16(node, toc_entry + 6) else {
            break;
        };
        let key_start: usize = meta.key_area_start + usize::from(key_off_rel);
        let key_end: usize = key_start + usize::from(key_len);
        let val_start: usize = match meta.val_area_end.checked_sub(usize::from(val_off_rel)) {
            Some(v) => v,
            None => continue,
        };
        let val_end: usize = val_start + usize::from(val_len);
        let (Some(key), Some(value)): (Option<&[u8]>, Option<&[u8]>) =
            (node.get(key_start..key_end), node.get(val_start..val_end))
        else {
            continue;
        };
        let Some(id_and_type): Option<u64> = le_u64(key, 0) else {
            continue;
        };
        let record_type: u8 = (id_and_type >> J_OBJ_TYPE_SHIFT) as u8;
        let object_id: u64 = id_and_type & ((1u64 << J_OBJ_TYPE_SHIFT) - 1);
        records.push(ApfsFsRecord {
            object_id,
            record_type,
            key: key.to_vec(),
            value: value.to_vec(),
        });
    }
    records
}

#[must_use]
pub fn drec_name(record: &ApfsFsRecord) -> Option<String> {
    if record.record_type != APFS_TYPE_DREC {
        return None;
    }
    let name_len_field: u32 = le_u32(&record.key, 8)?;
    let name_len: usize = (name_len_field & J_DREC_HASHED_NAME_MASK) as usize;
    let name_bytes: &[u8] = record.key.get(12..12 + name_len.saturating_sub(1))?;
    Some(String::from_utf8_lossy(name_bytes).into_owned())
}

#[must_use]
pub const fn is_inode_record(record: &ApfsFsRecord) -> bool {
    record.record_type == APFS_TYPE_INODE
}

#[must_use]
pub const fn is_file_extent_record(record: &ApfsFsRecord) -> bool {
    record.record_type == APFS_TYPE_FILE_EXTENT
}

const J_FILE_EXTENT_LEN_MASK: u64 = 0x00FF_FFFF_FFFF_FFFF;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApfsExtractedFile {
    pub name: String,
    pub object_id: u64,
    pub size: u64,
    pub extents: Vec<(u64, u64)>,
}

fn file_extent_value(record: &ApfsFsRecord) -> Option<(u64, u64)> {
    let len_and_flags: u64 = le_u64(&record.value, 0)?;
    let phys_block: u64 = le_u64(&record.value, 8)?;
    let byte_len: u64 = len_and_flags & J_FILE_EXTENT_LEN_MASK;
    Some((phys_block, byte_len))
}

fn drec_target_oid(record: &ApfsFsRecord) -> Option<u64> {
    let oid: u64 = le_u64(&record.value, 0)?;
    Some(oid & ((1u64 << J_OBJ_TYPE_SHIFT) - 1))
}

#[must_use]
pub fn extract_apfs_files(
    image: &[u8],
    block_size: u32,
    root_tree_block: u64,
) -> Vec<ApfsExtractedFile> {
    let records: Vec<ApfsFsRecord> = walk_fs_tree_leaf(image, block_size, root_tree_block);
    let mut names_by_oid: std::collections::BTreeMap<u64, String> =
        std::collections::BTreeMap::new();
    let mut extents_by_oid: std::collections::BTreeMap<u64, Vec<(u64, u64)>> =
        std::collections::BTreeMap::new();
    for record in &records {
        match record.record_type {
            APFS_TYPE_DREC => {
                if let (Some(name), Some(target)) = (drec_name(record), drec_target_oid(record)) {
                    names_by_oid.insert(target, name);
                }
            }
            APFS_TYPE_FILE_EXTENT => {
                if let Some(extent) = file_extent_value(record) {
                    extents_by_oid
                        .entry(record.object_id)
                        .or_default()
                        .push(extent);
                }
            }
            _ => {}
        }
    }

    let mut out: Vec<ApfsExtractedFile> = Vec::new();
    for (oid, extents) in extents_by_oid {
        let Some(name): Option<&String> = names_by_oid.get(&oid) else {
            continue;
        };
        let size: u64 = extents.iter().map(|(_, len): &(u64, u64)| *len).sum();
        out.push(ApfsExtractedFile {
            name: name.clone(),
            object_id: oid,
            size,
            extents,
        });
    }
    out
}

#[must_use]
pub fn apfs_file_bytes(
    image: &[u8],
    block_size: u32,
    file: &ApfsExtractedFile,
    cap: u64,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let block_size: u64 = u64::from(block_size);
    for (phys_block, byte_len) in &file.extents {
        let start: u64 = phys_block.saturating_mul(block_size);
        let end: u64 = start.saturating_add(*byte_len).min(image.len() as u64);
        if let Some(slice) = image.get(start as usize..end as usize) {
            out.extend_from_slice(slice);
        }
        if out.len() as u64 > cap {
            out.truncate(cap as usize);
            break;
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_apfs(volume_name: &str, num_files: u64) -> Vec<u8> {
        let block_size: u32 = 4096;
        let total_blocks: u32 = 8;
        let mut image: Vec<u8> = vec![0u8; total_blocks as usize * block_size as usize];

        image[OBJ_HEADER_LEN..OBJ_HEADER_LEN + 4].copy_from_slice(&NX_MAGIC.to_le_bytes());
        image[OBJ_HEADER_LEN + 4..OBJ_HEADER_LEN + 8].copy_from_slice(&block_size.to_le_bytes());
        image[OBJ_HEADER_LEN + 8..OBJ_HEADER_LEN + 16]
            .copy_from_slice(&u64::from(total_blocks).to_le_bytes());
        let fs_oid_base: usize = OBJ_HEADER_LEN + 184;
        image[fs_oid_base..fs_oid_base + 8].copy_from_slice(&1024u64.to_le_bytes());

        let vol_block: usize = 4;
        let vol_off: usize = vol_block * block_size as usize;
        image[vol_off + OBJ_HEADER_LEN..vol_off + OBJ_HEADER_LEN + 4]
            .copy_from_slice(&APFS_MAGIC.to_le_bytes());
        image[vol_off + OBJ_HEADER_LEN + 4..vol_off + OBJ_HEADER_LEN + 12]
            .copy_from_slice(&0u64.to_le_bytes());
        image[vol_off + OBJ_HEADER_LEN + 0x40..vol_off + OBJ_HEADER_LEN + 0x48]
            .copy_from_slice(&num_files.to_le_bytes());
        let name_off: usize = vol_off + OBJ_HEADER_LEN + 0x2C0;
        let name_bytes: &[u8] = volume_name.as_bytes();
        image[name_off..name_off + name_bytes.len()].copy_from_slice(name_bytes);
        image
    }

    #[test]
    fn detects_and_parses_apfs_container() {
        let image: Vec<u8> = build_apfs("Macintosh HD", 42);
        assert!(detect_apfs(&image));
        let container: ApfsContainer = parse_apfs(&image).expect("parse apfs");
        assert_eq!(container.block_size, 4096);
        assert_eq!(container.block_count, 8);
        assert_eq!(container.volume_oids, vec![1024]);
        let volume: &ApfsVolume = container
            .volumes
            .iter()
            .find(|v: &&ApfsVolume| v.name == "Macintosh HD")
            .expect("volume");
        assert_eq!(volume.num_files, 42);
    }

    #[test]
    fn rejects_non_apfs() {
        assert!(!detect_apfs(&vec![0u8; 4096]));
        assert!(parse_apfs(&vec![0u8; 4096]).is_err());
    }

    #[test]
    fn resolves_omap_leaf_mappings() {
        let block_size: u32 = 4096;
        let mut image: Vec<u8> = vec![0u8; 4 * block_size as usize];
        let omap_block: u64 = 2;
        let node_off: usize = omap_block as usize * block_size as usize;

        let entries: [(u64, u64); 2] = [(0x0400, 0x10), (0x0401, 0x11)];
        let flags: u16 = 0x0001 | BTNODE_FIXED_KV_SIZE;
        image[node_off + OBJ_HEADER_LEN..node_off + OBJ_HEADER_LEN + 2]
            .copy_from_slice(&flags.to_le_bytes());
        image[node_off + OBJ_HEADER_LEN + 2..node_off + OBJ_HEADER_LEN + 4]
            .copy_from_slice(&0u16.to_le_bytes());
        image[node_off + OBJ_HEADER_LEN + 4..node_off + OBJ_HEADER_LEN + 8]
            .copy_from_slice(&(entries.len() as u32).to_le_bytes());
        let table_off: u16 = 0;
        let table_len: u16 = (entries.len() * 4) as u16;
        image[node_off + OBJ_HEADER_LEN + 8..node_off + OBJ_HEADER_LEN + 10]
            .copy_from_slice(&table_off.to_le_bytes());
        image[node_off + OBJ_HEADER_LEN + 10..node_off + OBJ_HEADER_LEN + 12]
            .copy_from_slice(&table_len.to_le_bytes());

        let toc_off: usize = node_off + BTREE_TOC_OFFSET;
        let key_area: usize = toc_off + usize::from(table_len);
        let val_area_end: usize = node_off + block_size as usize - BTREE_INFO_LEN;
        for (i, (oid, paddr)) in entries.iter().enumerate() {
            let key_rel: u16 = (i * 16) as u16;
            let val_rel: u16 = ((i + 1) * 16) as u16;
            let toc_entry: usize = toc_off + i * 4;
            image[toc_entry..toc_entry + 2].copy_from_slice(&key_rel.to_le_bytes());
            image[toc_entry + 2..toc_entry + 4].copy_from_slice(&val_rel.to_le_bytes());
            let key_off: usize = key_area + usize::from(key_rel);
            image[key_off..key_off + 8].copy_from_slice(&oid.to_le_bytes());
            let val_off: usize = val_area_end - usize::from(val_rel);
            image[val_off + 8..val_off + 16].copy_from_slice(&paddr.to_le_bytes());
        }

        let mappings: Vec<(u64, u64)> = resolve_omap_tree(&image, block_size, omap_block);
        assert_eq!(mappings.len(), 2);
        assert!(mappings.contains(&(0x0400, 0x10)));
        assert!(mappings.contains(&(0x0401, 0x11)));
    }

    #[test]
    fn walks_fs_tree_drec_and_inode_records() {
        let block_size: u32 = 4096;
        let mut image: Vec<u8> = vec![0u8; 4 * block_size as usize];
        let tree_block: u64 = 2;
        let node_off: usize = tree_block as usize * block_size as usize;

        let flags: u16 = 0x0001;
        image[node_off + OBJ_HEADER_LEN..node_off + OBJ_HEADER_LEN + 2]
            .copy_from_slice(&flags.to_le_bytes());
        image[node_off + OBJ_HEADER_LEN + 4..node_off + OBJ_HEADER_LEN + 8]
            .copy_from_slice(&2u32.to_le_bytes());
        let table_off: u16 = 0;
        let table_len: u16 = 16;
        image[node_off + OBJ_HEADER_LEN + 8..node_off + OBJ_HEADER_LEN + 10]
            .copy_from_slice(&table_off.to_le_bytes());
        image[node_off + OBJ_HEADER_LEN + 10..node_off + OBJ_HEADER_LEN + 12]
            .copy_from_slice(&table_len.to_le_bytes());

        let toc_off: usize = node_off + BTREE_TOC_OFFSET;
        let key_area: usize = toc_off + usize::from(table_len);

        let name: &str = "hello.txt";
        let mut drec_key: Vec<u8> = Vec::new();
        let drec_obj_id: u64 = (u64::from(APFS_TYPE_DREC) << J_OBJ_TYPE_SHIFT) | 0x20;
        drec_key.extend_from_slice(&drec_obj_id.to_le_bytes());
        drec_key.extend_from_slice(&((name.len() + 1) as u32).to_le_bytes());
        drec_key.extend_from_slice(name.as_bytes());
        drec_key.push(0);

        let mut inode_key: Vec<u8> = Vec::new();
        let inode_obj_id: u64 = (u64::from(APFS_TYPE_INODE) << J_OBJ_TYPE_SHIFT) | 0x21;
        inode_key.extend_from_slice(&inode_obj_id.to_le_bytes());

        let keys: [&[u8]; 2] = [&drec_key, &inode_key];
        let mut key_cursor: usize = 0;
        let mut val_cursor: u16 = 0;
        for (i, key) in keys.iter().enumerate() {
            let key_rel: u16 = key_cursor as u16;
            val_cursor += 8;
            let val_rel: u16 = val_cursor;
            let toc_entry: usize = toc_off + i * 8;
            image[toc_entry..toc_entry + 2].copy_from_slice(&key_rel.to_le_bytes());
            image[toc_entry + 2..toc_entry + 4].copy_from_slice(&(key.len() as u16).to_le_bytes());
            image[toc_entry + 4..toc_entry + 6].copy_from_slice(&val_rel.to_le_bytes());
            image[toc_entry + 6..toc_entry + 8].copy_from_slice(&8u16.to_le_bytes());
            let key_off: usize = key_area + usize::from(key_rel);
            image[key_off..key_off + key.len()].copy_from_slice(key);
            key_cursor += key.len();
        }

        let records: Vec<ApfsFsRecord> = walk_fs_tree_leaf(&image, block_size, tree_block);
        assert_eq!(records.len(), 2);
        let drec: &ApfsFsRecord = records
            .iter()
            .find(|r: &&ApfsFsRecord| r.record_type == APFS_TYPE_DREC)
            .expect("drec");
        assert_eq!(drec.object_id, 0x20);
        assert_eq!(drec_name(drec).as_deref(), Some("hello.txt"));
        assert!(records.iter().any(is_inode_record));
    }

    #[test]
    fn extracts_apfs_file_via_drec_and_extent() {
        let block_size: u32 = 4096;
        let mut image: Vec<u8> = vec![0u8; 8 * block_size as usize];
        let tree_block: u64 = 2;
        let data_block: u64 = 5;
        let inode_oid: u64 = 0x30;
        let body: &[u8] = b"apfs extracted file body via fs-tree extent walk";

        let node_off: usize = tree_block as usize * block_size as usize;
        image[node_off + OBJ_HEADER_LEN..node_off + OBJ_HEADER_LEN + 2]
            .copy_from_slice(&0x0001u16.to_le_bytes());
        image[node_off + OBJ_HEADER_LEN + 4..node_off + OBJ_HEADER_LEN + 8]
            .copy_from_slice(&2u32.to_le_bytes());
        image[node_off + OBJ_HEADER_LEN + 8..node_off + OBJ_HEADER_LEN + 10]
            .copy_from_slice(&0u16.to_le_bytes());
        image[node_off + OBJ_HEADER_LEN + 10..node_off + OBJ_HEADER_LEN + 12]
            .copy_from_slice(&16u16.to_le_bytes());

        let toc_off: usize = node_off + BTREE_TOC_OFFSET;
        let key_area: usize = toc_off + 16;
        let val_area_end: usize = node_off + block_size as usize - BTREE_INFO_LEN;

        let name: &str = "doc.bin";
        let mut drec_key: Vec<u8> = Vec::new();
        drec_key.extend_from_slice(
            &((u64::from(APFS_TYPE_DREC) << J_OBJ_TYPE_SHIFT) | 0x10).to_le_bytes(),
        );
        drec_key.extend_from_slice(&((name.len() + 1) as u32).to_le_bytes());
        drec_key.extend_from_slice(name.as_bytes());
        drec_key.push(0);
        let drec_val: Vec<u8> = inode_oid.to_le_bytes().to_vec();

        let mut ext_key: Vec<u8> = Vec::new();
        ext_key.extend_from_slice(
            &((u64::from(APFS_TYPE_FILE_EXTENT) << J_OBJ_TYPE_SHIFT) | inode_oid).to_le_bytes(),
        );
        ext_key.extend_from_slice(&0u64.to_le_bytes());
        let mut ext_val: Vec<u8> = Vec::new();
        ext_val.extend_from_slice(&(body.len() as u64).to_le_bytes());
        ext_val.extend_from_slice(&data_block.to_le_bytes());
        ext_val.extend_from_slice(&0u64.to_le_bytes());

        let entries: [(&[u8], &[u8]); 2] = [(&drec_key, &drec_val), (&ext_key, &ext_val)];
        let mut key_cursor: u16 = 0;
        let mut val_cursor: u16 = 0;
        for (i, (key, val)) in entries.iter().enumerate() {
            let key_rel: u16 = key_cursor;
            val_cursor += val.len() as u16;
            let val_rel: u16 = val_cursor;
            let toc_entry: usize = toc_off + i * 8;
            image[toc_entry..toc_entry + 2].copy_from_slice(&key_rel.to_le_bytes());
            image[toc_entry + 2..toc_entry + 4].copy_from_slice(&(key.len() as u16).to_le_bytes());
            image[toc_entry + 4..toc_entry + 6].copy_from_slice(&val_rel.to_le_bytes());
            image[toc_entry + 6..toc_entry + 8].copy_from_slice(&(val.len() as u16).to_le_bytes());
            let key_off: usize = key_area + usize::from(key_rel);
            image[key_off..key_off + key.len()].copy_from_slice(key);
            let val_off: usize = val_area_end - usize::from(val_rel);
            image[val_off..val_off + val.len()].copy_from_slice(val);
            key_cursor += key.len() as u16;
        }

        let data_off: usize = data_block as usize * block_size as usize;
        image[data_off..data_off + body.len()].copy_from_slice(body);

        let files: Vec<ApfsExtractedFile> = extract_apfs_files(&image, block_size, tree_block);
        assert_eq!(
            files.len(),
            1,
            "one file should be reconstructed: {files:?}"
        );
        assert_eq!(files[0].name, "doc.bin");
        assert_eq!(files[0].size, body.len() as u64);
        let recovered: Vec<u8> = apfs_file_bytes(&image, block_size, &files[0], u64::MAX);
        assert_eq!(recovered, body);
    }
}
