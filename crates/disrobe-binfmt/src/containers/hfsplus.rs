use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const VOLUME_HEADER_OFFSET: usize = 1024;
const SIGNATURE_HFSPLUS: u16 = 0x482B;
const SIGNATURE_HFSX: u16 = 0x4858;
const RECORD_FOLDER: u16 = 0x0001;
const RECORD_FILE: u16 = 0x0002;
const BTREE_NODE_LEAF: i8 = -1;
const MAX_FILES: usize = 2_000_000;
const MAX_NODES: usize = 5_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HfsFile {
    pub name: String,
    pub cnid: u32,
    pub parent_cnid: u32,
    pub data_logical_size: u64,
    pub extents: Vec<(u32, u32)>,
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
    let s: &[u8] = b.get(at..at + 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

#[inline]
fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    let s: &[u8] = b.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
fn be_u64(b: &[u8], at: usize) -> Option<u64> {
    let s: &[u8] = b.get(at..at + 8)?;
    Some(u64::from_be_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
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

fn read_fork_extents(header: &[u8], fork_offset: usize) -> Vec<ForkExtent> {
    let mut extents: Vec<ForkExtent> = Vec::with_capacity(8);
    let records_off: usize = fork_offset + 16;
    for i in 0..8 {
        let base: usize = records_off + i * 8;
        let start: u32 = be_u32(header, base).map_or(0, |value: u32| value);
        let count: u32 = be_u32(header, base + 4).map_or(0, |value: u32| value);
        if count == 0 {
            break;
        }
        extents.push(ForkExtent {
            start_block: start,
            block_count: count,
        });
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
        let start: u64 = base + u64::from(extent.start_block) * u64::from(block_size);
        let len: u64 = u64::from(extent.block_count) * u64::from(block_size);
        let start: usize = start as usize;
        let end: usize = (start as u64 + len).min(image.len() as u64) as usize;
        if let Some(slice) = image.get(start..end) {
            out.extend_from_slice(slice);
        }
        if out.len() as u64 > cap {
            out.truncate(cap as usize);
            break;
        }
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
    let header: &[u8] = image
        .get(header_off..header_off + 512)
        .ok_or_else(|| Error::Decompression("hfs+ volume header truncated".to_owned()))?;
    let block_size: u32 = be_u32(header, 40)
        .filter(|&b: &u32| b >= 512 && b.is_power_of_two())
        .ok_or_else(|| Error::Decompression("hfs+ block size invalid".to_owned()))?;
    let total_blocks: u32 = be_u32(header, 44).map_or(0, |value: u32| value);

    let catalog_fork_offset: usize = 272;
    let catalog_extents: Vec<ForkExtent> = read_fork_extents(header, catalog_fork_offset);
    let catalog_logical_size: u64 =
        be_u64(header, catalog_fork_offset).map_or(0, |value: u64| value);
    if catalog_extents.is_empty() {
        return Err(Error::Decompression(
            "hfs+ catalog file has no extents (fragmented catalog beyond the first 8 extents is not followed in-tree)".to_owned(),
        ));
    }
    let catalog: Vec<u8> = read_fork_bytes(
        image,
        base as u64,
        block_size,
        &catalog_extents,
        catalog_logical_size.max(1),
    );

    let (files, folders): (Vec<HfsFile>, Vec<HfsFolder>) = walk_catalog_btree(&catalog)?;
    Ok(HfsVolume {
        block_size,
        total_blocks,
        volume_base: base as u64,
        files,
        folders,
    })
}

fn walk_catalog_btree(catalog: &[u8]) -> Result<(Vec<HfsFile>, Vec<HfsFolder>)> {
    let node_size: u16 = be_u16(catalog, 32)
        .filter(|&n: &u16| n >= 512 && n.is_power_of_two())
        .ok_or_else(|| Error::Decompression("hfs+ btree node size invalid".to_owned()))?;
    let node_size: usize = usize::from(node_size);
    let node_count: usize = catalog.len() / node_size;
    if node_count > MAX_NODES {
        return Err(Error::Decompression(
            "hfs+ catalog node count exceeds sanity bound".to_owned(),
        ));
    }

    let mut files: Vec<HfsFile> = Vec::new();
    let mut folders: Vec<HfsFolder> = Vec::new();
    for node_index in 0..node_count {
        if files.len() > MAX_FILES || folders.len() > MAX_FILES {
            break;
        }
        let node_start: usize = node_index * node_size;
        let node: &[u8] = match catalog.get(node_start..node_start + node_size) {
            Some(n) => n,
            None => break,
        };
        let kind: i8 = node[8] as i8;
        if kind != BTREE_NODE_LEAF {
            continue;
        }
        let num_records: u16 = be_u16(node, 10).map_or(0, |value: u16| value);
        for record_index in 0..num_records {
            let offset_pos: usize = node_size - 2 * (usize::from(record_index) + 1);
            let Some(record_off): Option<u16> = be_u16(node, offset_pos) else {
                continue;
            };
            let record_off: usize = usize::from(record_off);
            match parse_catalog_record(node, record_off) {
                Some(CatalogRecord::File(file)) => files.push(file),
                Some(CatalogRecord::Folder(folder)) => folders.push(folder),
                None => {}
            }
        }
    }
    Ok((files, folders))
}

enum CatalogRecord {
    File(HfsFile),
    Folder(HfsFolder),
}

fn parse_catalog_record(node: &[u8], record_off: usize) -> Option<CatalogRecord> {
    let key_length: usize = usize::from(be_u16(node, record_off)?);
    let parent_cnid: u32 = be_u32(node, record_off + 2)?;
    let name_length: usize = usize::from(be_u16(node, record_off + 6)?);
    let name_start: usize = record_off + 8;
    let mut name: String = String::with_capacity(name_length);
    for i in 0..name_length {
        let unit: u16 = be_u16(node, name_start + i * 2)?;
        if unit == 0 {
            break;
        }
        name.push(char::from_u32(u32::from(unit)).map_or('\u{fffd}', |value: char| value));
    }
    let data_start: usize = record_off + 2 + key_length + (key_length % 2);
    let record_type: u16 = be_u16(node, data_start)?;
    if record_type == RECORD_FOLDER {
        let cnid: u32 = be_u32(node, data_start + 8)?;
        return Some(CatalogRecord::Folder(HfsFolder {
            name,
            cnid,
            parent_cnid,
        }));
    }
    if record_type != RECORD_FILE {
        return None;
    }
    let cnid: u32 = be_u32(node, data_start + 8)?;
    let data_fork_off: usize = data_start + 88;
    let data_logical_size: u64 = be_u64(node, data_fork_off)?;
    let mut extents: Vec<(u32, u32)> = Vec::with_capacity(8);
    let extents_off: usize = data_fork_off + 16;
    for i in 0..8 {
        let base: usize = extents_off + i * 8;
        let start: u32 = be_u32(node, base)?;
        let count: u32 = be_u32(node, base + 4)?;
        if count == 0 {
            break;
        }
        extents.push((start, count));
    }
    Some(CatalogRecord::File(HfsFile {
        name,
        cnid,
        parent_cnid,
        data_logical_size,
        extents,
    }))
}

pub fn file_data(image: &[u8], volume: &HfsVolume, file: &HfsFile, cap: u64) -> Vec<u8> {
    let extents: Vec<ForkExtent> = file
        .extents
        .iter()
        .map(|&(start, count): &(u32, u32)| ForkExtent {
            start_block: start,
            block_count: count,
        })
        .collect();
    let mut out: Vec<u8> =
        read_fork_bytes(image, volume.volume_base, volume.block_size, &extents, cap);
    let logical: usize =
        usize::try_from(file.data_logical_size).map_or(out.len(), |value: usize| value);
    if out.len() > logical {
        out.truncate(logical);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn put_u16(buf: &mut Vec<u8>, v: u16) {
        buf.extend_from_slice(&v.to_be_bytes());
    }
    fn put_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_be_bytes());
    }
    fn put_u64(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_be_bytes());
    }

    fn build_hfsplus(file_name: &str, body: &[u8]) -> Vec<u8> {
        let block_size: u32 = 4096;
        let node_size: u16 = 4096;
        let total_blocks: u32 = 16;
        let catalog_start_block: u32 = 2;
        let file_data_block: u32 = 4;

        let mut image: Vec<u8> = vec![0u8; total_blocks as usize * block_size as usize];

        let mut header: Vec<u8> = Vec::new();
        put_u16(&mut header, SIGNATURE_HFSPLUS);
        put_u16(&mut header, 4);
        header.extend(std::iter::repeat_n(0u8, 36));
        put_u32(&mut header, block_size);
        put_u32(&mut header, total_blocks);
        header.extend(std::iter::repeat_n(0u8, 512 - header.len()));
        let catalog_fork_off: usize = 272;
        put_u64_at(&mut header, catalog_fork_off, u64::from(node_size) * 2);
        put_u32_at(&mut header, catalog_fork_off + 16, catalog_start_block);
        put_u32_at(&mut header, catalog_fork_off + 20, 2);
        image[VOLUME_HEADER_OFFSET..VOLUME_HEADER_OFFSET + 512].copy_from_slice(&header);

        let mut record: Vec<u8> = Vec::new();
        let name_units: Vec<u16> = file_name.encode_utf16().collect();
        let key_length: u16 = (4 + 2 + name_units.len() * 2) as u16;
        put_u16(&mut record, key_length);
        put_u32(&mut record, 2);
        put_u16(&mut record, name_units.len() as u16);
        for u in &name_units {
            put_u16(&mut record, *u);
        }
        if !record.len().is_multiple_of(2) {
            record.push(0);
        }
        let data_start: usize = record.len();
        put_u16(&mut record, RECORD_FILE);
        record.extend(std::iter::repeat_n(0u8, 6));
        put_u32(&mut record, 16);
        record.extend(std::iter::repeat_n(0u8, data_start + 88 - record.len()));
        put_u64(&mut record, body.len() as u64);
        record.extend(std::iter::repeat_n(0u8, 8));
        put_u32(&mut record, file_data_block);
        put_u32(&mut record, 1);
        record.extend(std::iter::repeat_n(0u8, 48));

        let mut node: Vec<u8> = vec![0u8; node_size as usize];
        node[8] = BTREE_NODE_LEAF as u8;
        node[10] = 0;
        node[11] = 1;
        let record_pos: usize = 14;
        node[record_pos..record_pos + record.len()].copy_from_slice(&record);
        let first_record_offset: u16 = record_pos as u16;
        let off_slot: usize = node_size as usize - 2;
        node[off_slot..off_slot + 2].copy_from_slice(&first_record_offset.to_be_bytes());

        let mut btree_header_node: Vec<u8> = vec![0u8; node_size as usize];
        btree_header_node[32..34].copy_from_slice(&node_size.to_be_bytes());

        let catalog_off: usize = catalog_start_block as usize * block_size as usize;
        image[catalog_off..catalog_off + node_size as usize].copy_from_slice(&btree_header_node);
        image[catalog_off + node_size as usize..catalog_off + 2 * node_size as usize]
            .copy_from_slice(&node);

        let file_off: usize = file_data_block as usize * block_size as usize;
        image[file_off..file_off + body.len()].copy_from_slice(body);
        image
    }

    fn put_u32_at(buf: &mut [u8], at: usize, v: u32) {
        buf[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }
    fn put_u64_at(buf: &mut [u8], at: usize, v: u64) {
        buf[at..at + 8].copy_from_slice(&v.to_be_bytes());
    }

    #[test]
    fn detects_and_extracts_hfsplus_file() {
        let body: &[u8] = b"hfs+ catalog recovered file body";
        let image: Vec<u8> = build_hfsplus("readme.txt", body);
        assert!(detect_hfsplus(&image));
        let vol: HfsVolume = parse_hfsplus(&image).expect("parse hfs+");
        assert_eq!(vol.block_size, 4096);
        let file: &HfsFile = vol
            .files
            .iter()
            .find(|f: &&HfsFile| f.name == "readme.txt")
            .expect("file");
        assert_eq!(file.data_logical_size, body.len() as u64);
        let data: Vec<u8> = file_data(&image, &vol, file, u64::MAX);
        assert_eq!(data, body);
    }

    #[test]
    fn rejects_non_hfsplus() {
        assert!(!detect_hfsplus(&vec![0u8; 2048]));
        assert!(parse_hfsplus(&vec![0u8; 2048]).is_err());
    }
}
