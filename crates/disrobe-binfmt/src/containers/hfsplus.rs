use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const VOLUME_HEADER_OFFSET: usize = 1024;
const SIGNATURE_HFSPLUS: u16 = 0x482B;
const SIGNATURE_HFSX: u16 = 0x4858;
const RECORD_FOLDER: u16 = 0x0001;
const RECORD_FILE: u16 = 0x0002;
const BTREE_NODE_LEAF: i8 = -1;
const BTREE_HEADER_RECORD: usize = 14;
const UF_COMPRESSED: u8 = 0x20;
const MAX_FILES: usize = 2_000_000;
const MAX_NODES: usize = 5_000_000;
const EXTENTS_FORK_OFFSET: usize = 192;
const CATALOG_FORK_OFFSET: usize = 272;
const CATALOG_FILE_ID: u32 = 4;
const FORK_TYPE_DATA: u8 = 0x00;
const EXTENT_KEY_LENGTH: usize = 10;
const EXTENTS_PER_RECORD: usize = 8;
const MAX_OVERFLOW_RECORDS: usize = 1 << 20;
const MAX_FORK_EXTENTS: usize = 1 << 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HfsFile {
    pub name: String,
    pub cnid: u32,
    pub parent_cnid: u32,
    pub data_logical_size: u64,
    pub data_total_blocks: u32,
    pub extents: Vec<(u32, u32)>,
    pub compressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HfsFolder {
    pub name: String,
    pub cnid: u32,
    pub parent_cnid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HfsVolume {
    pub block_size: u32,
    pub total_blocks: u32,
    pub volume_base: u64,
    pub files: Vec<HfsFile>,
    pub folders: Vec<HfsFolder>,
    pub extents_overflow_error: Option<String>,
}

const HFS_ROOT_CNID: u32 = 2;

impl HfsVolume {
    #[must_use]
    pub fn full_path(&self, file: &HfsFile) -> String {
        let mut parts: Vec<&str> = vec![file.name.as_str()];
        let mut current: u32 = file.parent_cnid;
        let mut guard: usize = 0;
        while current != HFS_ROOT_CNID && current != 0 && guard < 256 {
            guard += 1;
            let Some(folder): Option<&HfsFolder> =
                self.folders.iter().find(|f: &&HfsFolder| f.cnid == current)
            else {
                break;
            };
            parts.push(folder.name.as_str());
            current = folder.parent_cnid;
        }
        parts.reverse();
        parts.join("/")
    }
}

#[inline]
fn be_u16(b: &[u8], at: usize) -> Option<u16> {
    disrobe_bytes::read_u16_be_at(b, at).ok()
}

#[inline]
fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    disrobe_bytes::read_u32_be_at(b, at).ok()
}

#[inline]
fn be_u64(b: &[u8], at: usize) -> Option<u64> {
    disrobe_bytes::read_u64_be_at(b, at).ok()
}

const APM_DRIVER_SIGNATURE: u16 = 0x4552;
const APM_PARTITION_SIGNATURE: u16 = 0x504D;
const APM_MAX_ENTRIES: u32 = 1024;

pub fn detect_hfsplus(bytes: &[u8]) -> bool {
    be_u16(bytes, VOLUME_HEADER_OFFSET)
        .is_some_and(|s: u16| s == SIGNATURE_HFSPLUS || s == SIGNATURE_HFSX)
}

fn volume_header_at(image: &[u8], base: usize) -> Option<u16> {
    be_u16(image, base.checked_add(VOLUME_HEADER_OFFSET)?)
        .filter(|&s: &u16| s == SIGNATURE_HFSPLUS || s == SIGNATURE_HFSX)
}

#[must_use]
pub fn locate_hfsplus_volumes(image: &[u8]) -> Vec<usize> {
    let mut bases: Vec<usize> = Vec::new();
    if volume_header_at(image, 0).is_some() {
        bases.push(0);
    }
    for base in apm_partition_bases(image) {
        if base != 0 && volume_header_at(image, base).is_some() && !bases.contains(&base) {
            bases.push(base);
        }
    }
    bases
}

fn apm_partition_bases(image: &[u8]) -> Vec<usize> {
    let mut bases: Vec<usize> = Vec::new();
    for sector_size in [512usize, 2048usize] {
        let Some(driver_sig): Option<u16> = be_u16(image, 0) else {
            continue;
        };
        if driver_sig != APM_DRIVER_SIGNATURE {
            continue;
        }
        let Some(first_entry): Option<&[u8]> =
            image.get(sector_size..sector_size.saturating_add(512))
        else {
            continue;
        };
        if be_u16(first_entry, 0) != Some(APM_PARTITION_SIGNATURE) {
            continue;
        }
        let map_entries: u32 = be_u32(first_entry, 4)
            .map_or(0, |value: u32| value)
            .min(APM_MAX_ENTRIES);
        for index in 0..map_entries as usize {
            let entry_off: usize = match sector_size.checked_mul(index + 1) {
                Some(v) => v,
                None => break,
            };
            let Some(entry): Option<&[u8]> = image.get(entry_off..entry_off.saturating_add(512))
            else {
                break;
            };
            if be_u16(entry, 0) != Some(APM_PARTITION_SIGNATURE) {
                continue;
            }
            let start_sector: u32 = be_u32(entry, 8).map_or(0, |value: u32| value);
            let Some(byte_offset): Option<usize> = (start_sector as usize).checked_mul(sector_size)
            else {
                continue;
            };
            if byte_offset < image.len() {
                bases.push(byte_offset);
            }
        }
        if !bases.is_empty() {
            break;
        }
    }
    bases
}

#[derive(Debug, Clone, Copy)]
struct ForkExtent {
    start_block: u32,
    block_count: u32,
}

#[derive(Debug, Clone)]
struct ForkData {
    logical_size: u64,
    total_blocks: u32,
    extents: Vec<ForkExtent>,
}

type OverflowExtents = BTreeMap<u32, BTreeMap<u32, Vec<ForkExtent>>>;

fn read_extent_record(bytes: &[u8], at: usize) -> Option<Vec<ForkExtent>> {
    let mut extents: Vec<ForkExtent> = Vec::with_capacity(EXTENTS_PER_RECORD);
    for index in 0..EXTENTS_PER_RECORD {
        let base: usize = at.checked_add(index * 8)?;
        let start_block: u32 = be_u32(bytes, base)?;
        let block_count: u32 = be_u32(bytes, base.checked_add(4)?)?;
        if block_count == 0 {
            break;
        }
        extents.push(ForkExtent {
            start_block,
            block_count,
        });
    }
    Some(extents)
}

fn read_fork(bytes: &[u8], fork_offset: usize) -> Option<ForkData> {
    Some(ForkData {
        logical_size: be_u64(bytes, fork_offset)?,
        total_blocks: be_u32(bytes, fork_offset.checked_add(12)?)?,
        extents: read_extent_record(bytes, fork_offset.checked_add(16)?)?,
    })
}

fn blocks_in(extents: &[ForkExtent]) -> u64 {
    extents
        .iter()
        .map(|extent: &ForkExtent| u64::from(extent.block_count))
        .sum()
}

fn resolve_fork_extents(
    mut extents: Vec<ForkExtent>,
    total_blocks: u32,
    records: Option<&BTreeMap<u32, Vec<ForkExtent>>>,
) -> Vec<ForkExtent> {
    let Some(records): Option<&BTreeMap<u32, Vec<ForkExtent>>> = records else {
        return extents;
    };
    let mut covered: u64 = blocks_in(&extents);
    while covered < u64::from(total_blocks) && extents.len() < MAX_FORK_EXTENTS {
        let Some(record): Option<&Vec<ForkExtent>> = u32::try_from(covered)
            .ok()
            .and_then(|start_block: u32| records.get(&start_block))
        else {
            break;
        };
        let added: u64 = blocks_in(record);
        if added == 0 {
            break;
        }
        extents.extend_from_slice(record);
        covered += added;
    }
    extents
}

fn read_fork_bytes(
    image: &[u8],
    base: u64,
    block_size: u32,
    extents: &[ForkExtent],
    cap: u64,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for extent in extents {
        let remaining: u64 = cap.saturating_sub(out.len() as u64);
        if remaining == 0 {
            break;
        }
        let start: u64 = base.saturating_add(u64::from(extent.start_block) * u64::from(block_size));
        let len: u64 = (u64::from(extent.block_count) * u64::from(block_size)).min(remaining);
        let end: u64 = start.saturating_add(len).min(image.len() as u64);
        let (Some(start), Some(end)): (Option<usize>, Option<usize>) =
            (usize::try_from(start).ok(), usize::try_from(end).ok())
        else {
            break;
        };
        let Some(slice): Option<&[u8]> = image.get(start..end) else {
            break;
        };
        out.extend_from_slice(slice);
    }
    out
}

pub fn parse_hfsplus(image: &[u8]) -> Result<HfsVolume> {
    parse_hfsplus_at(image, 0)
}

pub fn parse_hfsplus_at(image: &[u8], base: usize) -> Result<HfsVolume> {
    if volume_header_at(image, base).is_none() {
        return Err(Error::Decompression(
            "hfs+ volume header signature not found at offset 1024".to_owned(),
        ));
    }
    let header_off: usize = base
        .checked_add(VOLUME_HEADER_OFFSET)
        .ok_or_else(|| Error::Decompression("hfs+ volume base overflow".to_owned()))?;
    let header: &[u8] = header_off
        .checked_add(512)
        .and_then(|end: usize| image.get(header_off..end))
        .ok_or_else(|| Error::Decompression("hfs+ volume header truncated".to_owned()))?;
    let block_size: u32 = be_u32(header, 40)
        .filter(|&b: &u32| b >= 512 && b.is_power_of_two())
        .ok_or_else(|| Error::Decompression("hfs+ block size invalid".to_owned()))?;
    let total_blocks: u32 = be_u32(header, 44).map_or(0, |value: u32| value);
    let volume_len: u64 = image.len().saturating_sub(base) as u64;

    let (overflow, extents_overflow_error): (OverflowExtents, Option<String>) =
        match read_extents_overflow(image, base, block_size, header, volume_len) {
            Ok(overflow) => (overflow, None),
            Err(error) => (BTreeMap::new(), Some(error.to_string())),
        };

    let catalog_fork: ForkData = read_fork(header, CATALOG_FORK_OFFSET)
        .ok_or_else(|| Error::Decompression("hfs+ catalog fork truncated".to_owned()))?;
    if catalog_fork.extents.is_empty() {
        return Err(Error::Decompression(
            "hfs+ catalog file has no extents".to_owned(),
        ));
    }
    let catalog_extents: Vec<ForkExtent> = resolve_fork_extents(
        catalog_fork.extents,
        catalog_fork.total_blocks,
        overflow.get(&CATALOG_FILE_ID),
    );
    let catalog: Vec<u8> = read_fork_bytes(
        image,
        base as u64,
        block_size,
        &catalog_extents,
        catalog_fork.logical_size.min(volume_len),
    );

    let (files, folders): (Vec<HfsFile>, Vec<HfsFolder>) = walk_catalog_btree(&catalog, &overflow)?;
    Ok(HfsVolume {
        block_size,
        total_blocks,
        volume_base: base as u64,
        files,
        folders,
        extents_overflow_error,
    })
}

fn read_extents_overflow(
    image: &[u8],
    base: usize,
    block_size: u32,
    header: &[u8],
    volume_len: u64,
) -> Result<OverflowExtents> {
    let fork: ForkData = read_fork(header, EXTENTS_FORK_OFFSET)
        .ok_or_else(|| Error::Decompression("hfs+ extents overflow fork truncated".to_owned()))?;
    let mut overflow: OverflowExtents = BTreeMap::new();
    if fork.logical_size == 0 || fork.extents.is_empty() {
        return Ok(overflow);
    }
    let tree: Vec<u8> = read_fork_bytes(
        image,
        base as u64,
        block_size,
        &fork.extents,
        fork.logical_size.min(volume_len),
    );
    let mut records: usize = 0;
    walk_leaf_records(
        &tree,
        "extents overflow",
        |node: &[u8], record_off: usize| {
            records += 1;
            if records > MAX_OVERFLOW_RECORDS {
                return Err(Error::Decompression(format!(
                    "hfs+ extents overflow file holds more than {MAX_OVERFLOW_RECORDS} records"
                )));
            }
            if let Some((file_id, start_block, extents)) = parse_extent_record(node, record_off) {
                overflow
                    .entry(file_id)
                    .or_default()
                    .entry(start_block)
                    .or_insert(extents);
            }
            Ok(true)
        },
    )?;
    Ok(overflow)
}

fn parse_extent_record(node: &[u8], record_off: usize) -> Option<(u32, u32, Vec<ForkExtent>)> {
    let key_length: usize = usize::from(be_u16(node, record_off)?);
    if key_length < EXTENT_KEY_LENGTH {
        return None;
    }
    if *node.get(record_off.checked_add(2)?)? != FORK_TYPE_DATA {
        return None;
    }
    let file_id: u32 = be_u32(node, record_off.checked_add(4)?)?;
    let start_block: u32 = be_u32(node, record_off.checked_add(8)?)?;
    let extents: Vec<ForkExtent> =
        read_extent_record(node, record_off.checked_add(2)?.checked_add(key_length)?)?;
    Some((file_id, start_block, extents))
}

fn walk_leaf_records(
    tree: &[u8],
    tree_name: &str,
    mut visit: impl FnMut(&[u8], usize) -> Result<bool>,
) -> Result<()> {
    let node_size: u16 = be_u16(tree, 32)
        .filter(|&n: &u16| n >= 512 && n.is_power_of_two())
        .ok_or_else(|| Error::Decompression(format!("hfs+ {tree_name} node size invalid")))?;
    let node_size: usize = usize::from(node_size);
    let node_count: usize = tree.len() / node_size;
    if node_count > MAX_NODES {
        return Err(Error::Decompression(format!(
            "hfs+ {tree_name} node count exceeds sanity bound"
        )));
    }

    let mut next_leaf: u32 = be_u32(tree, BTREE_HEADER_RECORD + 10).unwrap_or(0);
    let mut leaves_walked: usize = 0;
    while next_leaf != 0 {
        if leaves_walked >= node_count {
            return Err(Error::Decompression(format!(
                "hfs+ {tree_name} leaf chain revisits a node"
            )));
        }
        leaves_walked += 1;
        let node_index: usize = usize::try_from(next_leaf).map_err(|_| {
            Error::Decompression(format!("hfs+ {tree_name} leaf link exceeds host range"))
        })?;
        let node_start: usize = node_index.checked_mul(node_size).ok_or_else(|| {
            Error::Decompression(format!("hfs+ {tree_name} leaf offset overflow"))
        })?;
        let node: &[u8] = node_start
            .checked_add(node_size)
            .and_then(|node_end: usize| tree.get(node_start..node_end))
            .ok_or_else(|| {
                Error::Decompression(format!(
                    "hfs+ {tree_name} leaf link {node_index} points past the {node_count}-node tree"
                ))
            })?;
        let kind: i8 = node[8] as i8;
        if kind != BTREE_NODE_LEAF {
            return Err(Error::Decompression(format!(
                "hfs+ {tree_name} leaf chain reaches node {node_index}, which is not a leaf"
            )));
        }
        next_leaf = be_u32(node, 0).unwrap_or(0);
        let num_records: u16 = be_u16(node, 10).map_or(0, |value: u16| value);
        if usize::from(num_records) * 2 > node_size {
            return Err(Error::Decompression(format!(
                "hfs+ {tree_name} node {node_index} declares {num_records} records, more offsets than its {node_size} bytes hold"
            )));
        }
        for record_index in 0..num_records {
            let offset_pos: usize = node_size - 2 * (usize::from(record_index) + 1);
            let Some(record_off): Option<u16> = be_u16(node, offset_pos) else {
                continue;
            };
            if !visit(node, usize::from(record_off))? {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn walk_catalog_btree(
    catalog: &[u8],
    overflow: &OverflowExtents,
) -> Result<(Vec<HfsFile>, Vec<HfsFolder>)> {
    let mut files: Vec<HfsFile> = Vec::new();
    let mut folders: Vec<HfsFolder> = Vec::new();
    walk_leaf_records(catalog, "catalog", |node: &[u8], record_off: usize| {
        match parse_catalog_record(node, record_off, overflow) {
            Some(CatalogRecord::File(file)) => files.push(file),
            Some(CatalogRecord::Folder(folder)) => folders.push(folder),
            None => {}
        }
        Ok(files.len() <= MAX_FILES && folders.len() <= MAX_FILES)
    })?;
    Ok((files, folders))
}

enum CatalogRecord {
    File(HfsFile),
    Folder(HfsFolder),
}

fn parse_catalog_record(
    node: &[u8],
    record_off: usize,
    overflow: &OverflowExtents,
) -> Option<CatalogRecord> {
    let key_length: usize = usize::from(be_u16(node, record_off)?);
    let parent_cnid: u32 = be_u32(node, record_off.checked_add(2)?)?;
    let name_length: usize = usize::from(be_u16(node, record_off.checked_add(6)?)?);
    let name_start: usize = record_off.checked_add(8)?;
    let mut name: String = String::with_capacity(name_length);
    for i in 0..name_length {
        let unit: u16 = be_u16(node, name_start.checked_add(i.checked_mul(2)?)?)?;
        if unit == 0 {
            break;
        }
        name.push(char::from_u32(u32::from(unit)).map_or('\u{fffd}', |value: char| value));
    }
    let data_start: usize = record_off
        .checked_add(2)?
        .checked_add(key_length)?
        .checked_add(key_length % 2)?;
    let record_type: u16 = be_u16(node, data_start)?;
    let cnid: u32 = be_u32(node, data_start.checked_add(8)?)?;
    if record_type == RECORD_FOLDER {
        return Some(CatalogRecord::Folder(HfsFolder {
            name,
            cnid,
            parent_cnid,
        }));
    }
    if record_type != RECORD_FILE {
        return None;
    }
    let owner_flags: u8 = *node.get(data_start.checked_add(41)?)?;
    let data_fork: ForkData = read_fork(node, data_start.checked_add(88)?)?;
    let extents: Vec<ForkExtent> = resolve_fork_extents(
        data_fork.extents,
        data_fork.total_blocks,
        overflow.get(&cnid),
    );
    Some(CatalogRecord::File(HfsFile {
        name,
        cnid,
        parent_cnid,
        data_logical_size: data_fork.logical_size,
        data_total_blocks: data_fork.total_blocks,
        extents: extents
            .iter()
            .map(|extent: &ForkExtent| (extent.start_block, extent.block_count))
            .collect(),
        compressed: owner_flags & UF_COMPRESSED != 0,
    }))
}

pub fn file_data(image: &[u8], volume: &HfsVolume, file: &HfsFile, cap: u64) -> Result<Vec<u8>> {
    if file.compressed {
        return Err(Error::Decompression(
            "decmpfs-compressed file: its data lives in the resource fork or an extended attribute, which is not decoded".to_owned(),
        ));
    }
    if file.data_logical_size > cap {
        return Err(Error::QuotaExceeded {
            entry: file.name.clone(),
            reason: format!(
                "data fork of {} bytes exceeds the {cap} byte per-entry cap",
                file.data_logical_size
            ),
        });
    }
    let extents: Vec<ForkExtent> = file
        .extents
        .iter()
        .map(|&(start, count): &(u32, u32)| ForkExtent {
            start_block: start,
            block_count: count,
        })
        .collect();
    let out: Vec<u8> = read_fork_bytes(
        image,
        volume.volume_base,
        volume.block_size,
        &extents,
        file.data_logical_size,
    );
    if (out.len() as u64) < file.data_logical_size {
        let cap_note: String = if extents.len() >= MAX_FORK_EXTENTS {
            format!("; the fork stops at the {MAX_FORK_EXTENTS}-extent cap")
        } else {
            String::new()
        };
        let overflow_note: String = volume
            .extents_overflow_error
            .as_ref()
            .map_or_else(String::new, |error: &String| {
                format!("; the extents overflow file was not read: {error}")
            });
        return Err(Error::Decompression(format!(
            "data fork holds {} of its {} bytes in its catalog and extents overflow records ({} of {} blocks mapped){cap_note}{overflow_note}",
            out.len(),
            file.data_logical_size,
            blocks_in(&extents),
            file.data_total_blocks
        )));
    }
    Ok(out)
}

#[cfg(test)]
fn hfsplus_put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}
#[cfg(test)]
fn hfsplus_put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}
#[cfg(test)]
fn hfsplus_put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}
#[cfg(test)]
fn hfsplus_put_u32_at(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_be_bytes());
}
#[cfg(test)]
fn hfsplus_put_u64_at(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
const TEST_BLOCK_SIZE: u32 = 4096;
#[cfg(test)]
const TEST_NODE_SIZE: u16 = 4096;
#[cfg(test)]
const TEST_CATALOG_BLOCK: u32 = 2;
#[cfg(test)]
const TEST_EXTENTS_BLOCK: u32 = 4;
#[cfg(test)]
const TEST_EXTENTS_NODES: u32 = 3;
#[cfg(test)]
const TEST_FIRST_DATA_BLOCK: u32 = TEST_EXTENTS_BLOCK + TEST_EXTENTS_NODES;
#[cfg(test)]
const TEST_FILE_ID: u32 = 16;

#[cfg(test)]
fn hfsplus_test_leaf(records: &[Vec<u8>], forward_link: u32) -> Vec<u8> {
    let node_size: usize = usize::from(TEST_NODE_SIZE);
    let mut node: Vec<u8> = vec![0u8; node_size];
    node[0..4].copy_from_slice(&forward_link.to_be_bytes());
    node[8] = BTREE_NODE_LEAF as u8;
    node[10..12].copy_from_slice(&(records.len() as u16).to_be_bytes());
    let mut record_pos: usize = 14;
    for (index, record) in records.iter().enumerate() {
        node[record_pos..record_pos + record.len()].copy_from_slice(record);
        let off_slot: usize = node_size - 2 * (index + 1);
        node[off_slot..off_slot + 2].copy_from_slice(&(record_pos as u16).to_be_bytes());
        record_pos += record.len();
    }
    node
}

#[cfg(test)]
fn hfsplus_test_header_node(first_leaf: u32) -> Vec<u8> {
    let mut node: Vec<u8> = vec![0u8; usize::from(TEST_NODE_SIZE)];
    node[8] = 1;
    node[BTREE_HEADER_RECORD + 10..BTREE_HEADER_RECORD + 14]
        .copy_from_slice(&first_leaf.to_be_bytes());
    node[32..34].copy_from_slice(&TEST_NODE_SIZE.to_be_bytes());
    node
}

#[cfg(test)]
fn hfsplus_test_extent_record(
    fork_type: u8,
    file_id: u32,
    start_block: u32,
    extents: &[(u32, u32)],
) -> Vec<u8> {
    let mut record: Vec<u8> = Vec::new();
    hfsplus_put_u16(&mut record, EXTENT_KEY_LENGTH as u16);
    record.push(fork_type);
    record.push(0);
    hfsplus_put_u32(&mut record, file_id);
    hfsplus_put_u32(&mut record, start_block);
    for &(start, count) in extents {
        hfsplus_put_u32(&mut record, start);
        hfsplus_put_u32(&mut record, count);
    }
    record.extend(std::iter::repeat_n(
        0u8,
        (EXTENTS_PER_RECORD - extents.len()) * 8,
    ));
    record
}

#[cfg(test)]
pub(crate) fn build_hfsplus_image(file_name: &str, body: &[u8]) -> Vec<u8> {
    build_hfsplus_image_with_extents(file_name, body, &[(TEST_FIRST_DATA_BLOCK, 1)])
}

#[cfg(test)]
pub(crate) fn build_hfsplus_image_with_extents(
    file_name: &str,
    body: &[u8],
    extents: &[(u32, u32)],
) -> Vec<u8> {
    let block_size: usize = TEST_BLOCK_SIZE as usize;
    let node_size: usize = usize::from(TEST_NODE_SIZE);
    let data_end: u32 = extents
        .iter()
        .map(|&(start, count): &(u32, u32)| start + count)
        .max()
        .unwrap_or(TEST_FIRST_DATA_BLOCK);
    let total_blocks: u32 = data_end.max(16);
    let fork_blocks: u32 = extents.iter().map(|&(_, count): &(u32, u32)| count).sum();
    let inline_count: usize = extents.len().min(EXTENTS_PER_RECORD);
    let inline: &[(u32, u32)] = &extents[..inline_count];
    let overflow: &[(u32, u32)] = &extents[inline_count..];

    let mut image: Vec<u8> = vec![0u8; total_blocks as usize * block_size];

    let mut header: Vec<u8> = Vec::new();
    hfsplus_put_u16(&mut header, SIGNATURE_HFSPLUS);
    hfsplus_put_u16(&mut header, 4);
    header.extend(std::iter::repeat_n(0u8, 36));
    hfsplus_put_u32(&mut header, TEST_BLOCK_SIZE);
    hfsplus_put_u32(&mut header, total_blocks);
    header.extend(std::iter::repeat_n(0u8, 512 - header.len()));
    hfsplus_put_u64_at(&mut header, CATALOG_FORK_OFFSET, node_size as u64 * 2);
    hfsplus_put_u32_at(&mut header, CATALOG_FORK_OFFSET + 12, 2);
    hfsplus_put_u32_at(&mut header, CATALOG_FORK_OFFSET + 16, TEST_CATALOG_BLOCK);
    hfsplus_put_u32_at(&mut header, CATALOG_FORK_OFFSET + 20, 2);
    if !overflow.is_empty() {
        let extents_bytes: u64 = node_size as u64 * u64::from(TEST_EXTENTS_NODES);
        hfsplus_put_u64_at(&mut header, EXTENTS_FORK_OFFSET, extents_bytes);
        hfsplus_put_u32_at(&mut header, EXTENTS_FORK_OFFSET + 12, TEST_EXTENTS_NODES);
        hfsplus_put_u32_at(&mut header, EXTENTS_FORK_OFFSET + 16, TEST_EXTENTS_BLOCK);
        hfsplus_put_u32_at(&mut header, EXTENTS_FORK_OFFSET + 20, TEST_EXTENTS_NODES);
    }
    image[VOLUME_HEADER_OFFSET..VOLUME_HEADER_OFFSET + 512].copy_from_slice(&header);

    let mut record: Vec<u8> = Vec::new();
    let name_units: Vec<u16> = file_name.encode_utf16().collect();
    let key_length: u16 = (4 + 2 + name_units.len() * 2) as u16;
    hfsplus_put_u16(&mut record, key_length);
    hfsplus_put_u32(&mut record, 2);
    hfsplus_put_u16(&mut record, name_units.len() as u16);
    for u in &name_units {
        hfsplus_put_u16(&mut record, *u);
    }
    if !record.len().is_multiple_of(2) {
        record.push(0);
    }
    let data_start: usize = record.len();
    hfsplus_put_u16(&mut record, RECORD_FILE);
    record.extend(std::iter::repeat_n(0u8, 6));
    hfsplus_put_u32(&mut record, TEST_FILE_ID);
    record.extend(std::iter::repeat_n(0u8, data_start + 88 - record.len()));
    hfsplus_put_u64(&mut record, body.len() as u64);
    hfsplus_put_u32(&mut record, 0);
    hfsplus_put_u32(&mut record, fork_blocks);
    for &(start, count) in inline {
        hfsplus_put_u32(&mut record, start);
        hfsplus_put_u32(&mut record, count);
    }
    record.extend(std::iter::repeat_n(
        0u8,
        (EXTENTS_PER_RECORD - inline.len()) * 8,
    ));

    let catalog_off: usize = TEST_CATALOG_BLOCK as usize * block_size;
    image[catalog_off..catalog_off + node_size].copy_from_slice(&hfsplus_test_header_node(1));
    image[catalog_off + node_size..catalog_off + 2 * node_size]
        .copy_from_slice(&hfsplus_test_leaf(&[record], 0));

    if !overflow.is_empty() {
        let mut data_records: Vec<Vec<u8>> = Vec::new();
        let mut start_block: u32 = inline.iter().map(|&(_, count): &(u32, u32)| count).sum();
        for chunk in overflow.chunks(EXTENTS_PER_RECORD) {
            data_records.push(hfsplus_test_extent_record(
                FORK_TYPE_DATA,
                TEST_FILE_ID,
                start_block,
                chunk,
            ));
            start_block += chunk
                .iter()
                .map(|&(_, count): &(u32, u32)| count)
                .sum::<u32>();
        }
        let first_overflow_block: u32 = inline.iter().map(|&(_, count): &(u32, u32)| count).sum();
        let decoy_extents: &[(u32, u32)] = &[(TEST_EXTENTS_BLOCK, 1)];
        let mut second_leaf: Vec<Vec<u8>> = data_records.split_off(1);
        second_leaf.push(hfsplus_test_extent_record(
            0xFF,
            TEST_FILE_ID,
            first_overflow_block,
            decoy_extents,
        ));
        second_leaf.push(hfsplus_test_extent_record(
            FORK_TYPE_DATA,
            TEST_FILE_ID + 1,
            first_overflow_block,
            decoy_extents,
        ));
        let extents_off: usize = TEST_EXTENTS_BLOCK as usize * block_size;
        image[extents_off..extents_off + node_size].copy_from_slice(&hfsplus_test_header_node(1));
        image[extents_off + node_size..extents_off + 2 * node_size]
            .copy_from_slice(&hfsplus_test_leaf(&data_records, 2));
        image[extents_off + 2 * node_size..extents_off + 3 * node_size]
            .copy_from_slice(&hfsplus_test_leaf(&second_leaf, 0));
    }

    let mut remaining: &[u8] = body;
    for &(start, count) in extents {
        let take: usize = remaining.len().min(count as usize * block_size);
        let at: usize = start as usize * block_size;
        image[at..at + take].copy_from_slice(&remaining[..take]);
        remaining = &remaining[take..];
    }
    image
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_leaf_declaring_more_records_than_it_holds_is_an_error_not_a_panic() {
        let node_size: usize = 512;
        let mut catalog: Vec<u8> = vec![0u8; node_size * 2];
        catalog[32..34].copy_from_slice(&u16::try_from(node_size).expect("fits").to_be_bytes());
        catalog[BTREE_HEADER_RECORD + 10..BTREE_HEADER_RECORD + 14]
            .copy_from_slice(&1u32.to_be_bytes());
        let leaf: &mut [u8] = &mut catalog[node_size..];
        leaf[8] = 0xFF;
        leaf[10..12].copy_from_slice(&u16::MAX.to_be_bytes());
        let error: Error =
            walk_catalog_btree(&catalog, &BTreeMap::new()).expect_err("hostile record count");
        assert!(
            error.to_string().contains("declares 65535 records"),
            "{error}"
        );
    }

    #[test]
    fn detects_and_extracts_hfsplus_file() {
        let body: &[u8] = b"hfs+ catalog recovered file body";
        let image: Vec<u8> = build_hfsplus_image("readme.txt", body);
        assert!(detect_hfsplus(&image));
        let vol: HfsVolume = parse_hfsplus(&image).expect("parse hfs+");
        assert_eq!(vol.block_size, 4096);
        let file: &HfsFile = vol
            .files
            .iter()
            .find(|f: &&HfsFile| f.name == "readme.txt")
            .expect("file");
        assert_eq!(file.data_logical_size, body.len() as u64);
        let data: Vec<u8> = file_data(&image, &vol, file, u64::MAX).expect("file data");
        assert_eq!(data, body);
    }

    fn fragmented_body_and_extents() -> (Vec<u8>, Vec<(u32, u32)>) {
        let extent_count: u32 = 19;
        let block: usize = TEST_BLOCK_SIZE as usize;
        let body: Vec<u8> = (0..extent_count as usize * block - 100)
            .map(|i: usize| ((i / block) * 37 + i % 251) as u8)
            .collect();
        let extents: Vec<(u32, u32)> = (0..extent_count)
            .map(|i: u32| (TEST_FIRST_DATA_BLOCK + 2 * (extent_count - 1 - i), 1))
            .collect();
        (body, extents)
    }

    #[test]
    fn a_fork_with_more_than_eight_extents_reads_the_overflow_file() {
        let (body, extents): (Vec<u8>, Vec<(u32, u32)>) = fragmented_body_and_extents();
        let image: Vec<u8> = build_hfsplus_image_with_extents("fragmented.bin", &body, &extents);
        let vol: HfsVolume = parse_hfsplus(&image).expect("parse hfs+");
        assert_eq!(vol.extents_overflow_error, None);
        let file: &HfsFile = &vol.files[0];
        assert_eq!(file.extents, extents);
        let data: Vec<u8> = file_data(&image, &vol, file, u64::MAX).expect("fragmented fork");
        assert_eq!(data.len(), body.len());
        assert!(data == body, "fragmented fork bytes differ from the body");
    }

    #[test]
    fn an_overflow_record_that_does_not_start_where_the_fork_left_off_is_refused() {
        let (body, extents): (Vec<u8>, Vec<(u32, u32)>) = fragmented_body_and_extents();
        let mut image: Vec<u8> =
            build_hfsplus_image_with_extents("fragmented.bin", &body, &extents);
        let first_leaf: usize =
            TEST_EXTENTS_BLOCK as usize * TEST_BLOCK_SIZE as usize + usize::from(TEST_NODE_SIZE);
        let start_block_field: usize = first_leaf + 14 + 8;
        image[start_block_field..start_block_field + 4].copy_from_slice(&9u32.to_be_bytes());
        let vol: HfsVolume = parse_hfsplus(&image).expect("parse hfs+");
        let error: Error =
            file_data(&image, &vol, &vol.files[0], u64::MAX).expect_err("gap in the fork");
        assert!(
            error.to_string().contains("(8 of 19 blocks mapped)"),
            "{error}"
        );
    }

    #[test]
    fn a_cyclic_extents_leaf_chain_refuses_the_fragmented_fork_and_names_the_cycle() {
        let (body, extents): (Vec<u8>, Vec<(u32, u32)>) = fragmented_body_and_extents();
        let mut image: Vec<u8> =
            build_hfsplus_image_with_extents("fragmented.bin", &body, &extents);
        let second_leaf: usize = TEST_EXTENTS_BLOCK as usize * TEST_BLOCK_SIZE as usize
            + 2 * usize::from(TEST_NODE_SIZE);
        image[second_leaf..second_leaf + 4].copy_from_slice(&1u32.to_be_bytes());
        let vol: HfsVolume = parse_hfsplus(&image).expect("parse hfs+");
        assert!(
            vol.extents_overflow_error
                .as_deref()
                .is_some_and(|error: &str| error.contains("leaf chain revisits a node")),
            "{:?}",
            vol.extents_overflow_error
        );
        let error: Error =
            file_data(&image, &vol, &vol.files[0], u64::MAX).expect_err("unread overflow");
        assert!(
            error
                .to_string()
                .contains("extents overflow file was not read"),
            "{error}"
        );
    }

    #[test]
    fn a_fork_longer_than_its_catalog_extents_is_refused_not_truncated() {
        let image: Vec<u8> = build_hfsplus_image("big.bin", b"short body");
        let vol: HfsVolume = parse_hfsplus(&image).expect("parse hfs+");
        let mut file: HfsFile = vol.files[0].clone();
        file.data_logical_size = 3 * u64::from(vol.block_size);
        let error: Error = file_data(&image, &vol, &file, u64::MAX).expect_err("short fork");
        assert!(
            error.to_string().contains("extents overflow records"),
            "{error}"
        );
    }

    #[test]
    fn a_compressed_file_is_refused_not_emitted_empty() {
        let image: Vec<u8> = build_hfsplus_image("packed.txt", b"");
        let vol: HfsVolume = parse_hfsplus(&image).expect("parse hfs+");
        let mut file: HfsFile = vol.files[0].clone();
        file.compressed = true;
        let error: Error = file_data(&image, &vol, &file, u64::MAX).expect_err("decmpfs");
        assert!(error.to_string().contains("decmpfs"), "{error}");
    }

    #[test]
    fn a_stale_leaf_off_the_chain_is_not_read() {
        let mut image: Vec<u8> = build_hfsplus_image("live.txt", b"live");
        let catalog_off: usize = 2 * 4096;
        let header_link: usize = catalog_off + BTREE_HEADER_RECORD + 10;
        image[header_link..header_link + 4].copy_from_slice(&0u32.to_be_bytes());
        let vol: HfsVolume = parse_hfsplus(&image).expect("parse hfs+");
        assert!(vol.files.is_empty(), "{:?}", vol.files);
    }

    #[test]
    fn rejects_non_hfsplus() {
        assert!(!detect_hfsplus(&vec![0u8; 2048]));
        assert!(parse_hfsplus(&vec![0u8; 2048]).is_err());
    }
}
