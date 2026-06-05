use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const VHDX_SIGNATURE: &[u8; 8] = b"vhdxfile";
pub const VHDX_HEADER_SIGNATURE: &[u8; 4] = b"head";
pub const VHDX_REGION_SIGNATURE: &[u8; 4] = b"regi";
pub const VHDX_METADATA_SIGNATURE: &[u8; 8] = b"metadata";

pub const VHDX_HEADER_1_OFFSET: usize = 64 * 1024;
pub const VHDX_HEADER_2_OFFSET: usize = 128 * 1024;
pub const VHDX_REGION_1_OFFSET: usize = 192 * 1024;
pub const VHDX_REGION_2_OFFSET: usize = 256 * 1024;

pub const VHDX_BAT_REGION_GUID: [u8; 16] = [
    0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 0x08,
];
pub const VHDX_METADATA_REGION_GUID: [u8; 16] = [
    0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e,
];
pub const VHDX_META_FILE_PARAMETERS_GUID: [u8; 16] = [
    0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b,
];
pub const VHDX_META_VIRTUAL_DISK_SIZE_GUID: [u8; 16] = [
    0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8,
];
pub const VHDX_META_LOGICAL_SECTOR_SIZE_GUID: [u8; 16] = [
    0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab, 0x5f,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhdxHeader {
    pub sequence_number: u64,
    pub log_version: u16,
    pub format_version: u16,
    pub log_length: u32,
    pub log_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhdxRegion {
    pub guid: [u8; 16],
    pub file_offset: u64,
    pub length: u64,
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhdxMetadata {
    pub block_size: u32,
    pub leave_blocks_allocated: bool,
    pub has_parent: bool,
    pub logical_sector_size: u32,
    pub virtual_disk_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhdxImage {
    pub header: VhdxHeader,
    pub regions: Vec<VhdxRegion>,
    pub bat_region: Option<VhdxRegion>,
    pub metadata_region: Option<VhdxRegion>,
    pub metadata: Option<VhdxMetadata>,
    pub allocated_block_count: u32,
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn parse_header(bytes: &[u8], offset: usize) -> Option<VhdxHeader> {
    let header: &[u8] = bytes.get(offset..offset + 80)?;
    if &header[0..4] != VHDX_HEADER_SIGNATURE {
        return None;
    }
    Some(VhdxHeader {
        sequence_number: read_u64_le(header, 8),
        log_version: read_u16_le(header, 64),
        format_version: read_u16_le(header, 66),
        log_length: read_u32_le(header, 68),
        log_offset: read_u64_le(header, 72),
    })
}

fn parse_region_table(bytes: &[u8], offset: usize) -> Result<Vec<VhdxRegion>> {
    let head: &[u8] = bytes
        .get(offset..offset + 16)
        .ok_or_else(|| Error::Decompression("vhdx region table truncated".to_owned()))?;
    if &head[0..4] != VHDX_REGION_SIGNATURE {
        return Err(Error::Decompression(
            "vhdx region signature mismatch".to_owned(),
        ));
    }
    let entry_count: u32 = read_u32_le(head, 8);
    if entry_count > 2047 {
        return Err(Error::Decompression(
            "vhdx region entry count out of range".to_owned(),
        ));
    }
    let mut regions: Vec<VhdxRegion> = Vec::with_capacity(entry_count as usize);
    for index in 0..entry_count as usize {
        let entry_off: usize = offset + 16 + index * 32;
        let Some(entry): Option<&[u8]> = bytes.get(entry_off..entry_off + 32) else {
            break;
        };
        let mut guid: [u8; 16] = [0u8; 16];
        guid.copy_from_slice(&entry[0..16]);
        let file_offset: u64 = read_u64_le(entry, 16);
        let length: u64 = u64::from(read_u32_le(entry, 24));
        let required: bool = read_u32_le(entry, 28) & 1 == 1;
        regions.push(VhdxRegion {
            guid,
            file_offset,
            length,
            required,
        });
    }
    Ok(regions)
}

fn parse_metadata(bytes: &[u8], region: &VhdxRegion) -> Option<VhdxMetadata> {
    let region_off: usize = usize::try_from(region.file_offset).ok()?;
    let table: &[u8] = bytes.get(region_off..region_off + 32)?;
    if &table[0..8] != VHDX_METADATA_SIGNATURE {
        return None;
    }
    let entry_count: u16 = read_u16_le(table, 10);
    let mut block_size: u32 = 0;
    let mut leave_blocks_allocated: bool = false;
    let mut has_parent: bool = false;
    let mut logical_sector_size: u32 = 0;
    let mut virtual_disk_size: u64 = 0;
    for index in 0..entry_count as usize {
        let entry_off: usize = region_off + 32 + index * 32;
        let entry: &[u8] = bytes.get(entry_off..entry_off + 32)?;
        let mut item_guid: [u8; 16] = [0u8; 16];
        item_guid.copy_from_slice(&entry[0..16]);
        let item_offset: u32 = read_u32_le(entry, 16);
        let item_abs: usize = region_off.checked_add(item_offset as usize)?;
        if item_guid == VHDX_META_FILE_PARAMETERS_GUID {
            let item: &[u8] = bytes.get(item_abs..item_abs + 8)?;
            block_size = read_u32_le(item, 0);
            let flags: u32 = read_u32_le(item, 4);
            leave_blocks_allocated = flags & 0x1 != 0;
            has_parent = flags & 0x2 != 0;
        } else if item_guid == VHDX_META_LOGICAL_SECTOR_SIZE_GUID {
            let item: &[u8] = bytes.get(item_abs..item_abs + 4)?;
            logical_sector_size = read_u32_le(item, 0);
        } else if item_guid == VHDX_META_VIRTUAL_DISK_SIZE_GUID {
            let item: &[u8] = bytes.get(item_abs..item_abs + 8)?;
            virtual_disk_size = read_u64_le(item, 0);
        }
    }
    Some(VhdxMetadata {
        block_size,
        leave_blocks_allocated,
        has_parent,
        logical_sector_size,
        virtual_disk_size,
    })
}

fn count_allocated_bat_blocks(bytes: &[u8], region: &VhdxRegion, metadata: &VhdxMetadata) -> u32 {
    if metadata.block_size == 0
        || metadata.logical_sector_size == 0
        || metadata.virtual_disk_size == 0
    {
        return 0;
    }
    let region_off: usize = match usize::try_from(region.file_offset) {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let block_size: u64 = u64::from(metadata.block_size);
    let payload_blocks: u64 = metadata.virtual_disk_size.div_ceil(block_size);
    let sector_bitmap_span: u64 = (u64::from(1u32) << 23) * u64::from(metadata.logical_sector_size);
    let chunk_ratio: u64 = (sector_bitmap_span / block_size).max(1);
    let mut allocated: u32 = 0;
    let mut payload_index: u64 = 0;
    let mut entry_index: u64 = 0;
    while payload_index < payload_blocks {
        let entry_off: usize = match region_off.checked_add((entry_index * 8) as usize) {
            Some(value) => value,
            None => break,
        };
        let Some(slice): Option<&[u8]> = bytes.get(entry_off..entry_off + 8) else {
            break;
        };
        let is_bitmap_entry: bool =
            entry_index != 0 && (entry_index % (chunk_ratio + 1)) == chunk_ratio;
        if !is_bitmap_entry {
            let raw: u64 = read_u64_le(slice, 0);
            let state: u64 = raw & 0x7;
            if state == 6 || state == 7 {
                allocated += 1;
            }
            payload_index += 1;
        }
        entry_index += 1;
    }
    allocated
}

pub fn parse_vhdx(bytes: &[u8]) -> Result<VhdxImage> {
    if bytes.len() < VHDX_REGION_1_OFFSET + 16 {
        return Err(Error::Decompression("vhdx image too small".to_owned()));
    }
    if &bytes[0..8] != VHDX_SIGNATURE {
        return Err(Error::Decompression("vhdx signature mismatch".to_owned()));
    }
    let header_1: Option<VhdxHeader> = parse_header(bytes, VHDX_HEADER_1_OFFSET);
    let header_2: Option<VhdxHeader> = parse_header(bytes, VHDX_HEADER_2_OFFSET);
    let header: VhdxHeader = match (header_1, header_2) {
        (Some(h1), Some(h2)) => {
            if h2.sequence_number > h1.sequence_number {
                h2
            } else {
                h1
            }
        }
        (Some(h1), None) => h1,
        (None, Some(h2)) => h2,
        (None, None) => {
            return Err(Error::Decompression(
                "vhdx header signature missing".to_owned(),
            ));
        }
    };
    let regions: Vec<VhdxRegion> = parse_region_table(bytes, VHDX_REGION_1_OFFSET)
        .or_else(|_| parse_region_table(bytes, VHDX_REGION_2_OFFSET))?;
    let bat_region: Option<VhdxRegion> = regions
        .iter()
        .find(|r: &&VhdxRegion| r.guid == VHDX_BAT_REGION_GUID)
        .copied();
    let metadata_region: Option<VhdxRegion> = regions
        .iter()
        .find(|r: &&VhdxRegion| r.guid == VHDX_METADATA_REGION_GUID)
        .copied();
    let metadata: Option<VhdxMetadata> =
        metadata_region.and_then(|region: VhdxRegion| parse_metadata(bytes, &region));
    let allocated_block_count: u32 = match (bat_region, metadata) {
        (Some(region), Some(meta)) => count_allocated_bat_blocks(bytes, &region, &meta),
        _ => 0,
    };
    Ok(VhdxImage {
        header,
        regions,
        bat_region,
        metadata_region,
        metadata,
        allocated_block_count,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const META_REGION_OFFSET: u64 = 1024 * 1024;
    const BAT_REGION_OFFSET: u64 = 2 * 1024 * 1024;
    const BLOCK_SIZE: u32 = 2 * 1024 * 1024;
    const LOGICAL_SECTOR: u32 = 512;
    const VIRTUAL_DISK_SIZE: u64 = 6 * 1024 * 1024;

    fn build_vhdx() -> Vec<u8> {
        let mut image: Vec<u8> = vec![0u8; 4 * 1024 * 1024];
        image[0..8].copy_from_slice(VHDX_SIGNATURE);

        image[VHDX_HEADER_1_OFFSET..VHDX_HEADER_1_OFFSET + 4]
            .copy_from_slice(VHDX_HEADER_SIGNATURE);
        image[VHDX_HEADER_1_OFFSET + 8..VHDX_HEADER_1_OFFSET + 16]
            .copy_from_slice(&5u64.to_le_bytes());
        image[VHDX_HEADER_1_OFFSET + 66..VHDX_HEADER_1_OFFSET + 68]
            .copy_from_slice(&1u16.to_le_bytes());

        image[VHDX_REGION_1_OFFSET..VHDX_REGION_1_OFFSET + 4]
            .copy_from_slice(VHDX_REGION_SIGNATURE);
        image[VHDX_REGION_1_OFFSET + 8..VHDX_REGION_1_OFFSET + 12]
            .copy_from_slice(&2u32.to_le_bytes());
        let entry_0: usize = VHDX_REGION_1_OFFSET + 16;
        image[entry_0..entry_0 + 16].copy_from_slice(&VHDX_BAT_REGION_GUID);
        image[entry_0 + 16..entry_0 + 24].copy_from_slice(&BAT_REGION_OFFSET.to_le_bytes());
        image[entry_0 + 24..entry_0 + 28].copy_from_slice(&(1024u32 * 1024).to_le_bytes());
        image[entry_0 + 28..entry_0 + 32].copy_from_slice(&1u32.to_le_bytes());
        let entry_1: usize = entry_0 + 32;
        image[entry_1..entry_1 + 16].copy_from_slice(&VHDX_METADATA_REGION_GUID);
        image[entry_1 + 16..entry_1 + 24].copy_from_slice(&META_REGION_OFFSET.to_le_bytes());
        image[entry_1 + 24..entry_1 + 28].copy_from_slice(&(1024u32 * 1024).to_le_bytes());
        image[entry_1 + 28..entry_1 + 32].copy_from_slice(&1u32.to_le_bytes());

        let meta: usize = META_REGION_OFFSET as usize;
        image[meta..meta + 8].copy_from_slice(VHDX_METADATA_SIGNATURE);
        image[meta + 10..meta + 12].copy_from_slice(&3u16.to_le_bytes());
        let item_data_off: u32 = 256;
        let me0: usize = meta + 32;
        image[me0..me0 + 16].copy_from_slice(&VHDX_META_FILE_PARAMETERS_GUID);
        image[me0 + 16..me0 + 20].copy_from_slice(&item_data_off.to_le_bytes());
        image[me0 + 20..me0 + 24].copy_from_slice(&8u32.to_le_bytes());
        let me1: usize = me0 + 32;
        image[me1..me1 + 16].copy_from_slice(&VHDX_META_VIRTUAL_DISK_SIZE_GUID);
        image[me1 + 16..me1 + 20].copy_from_slice(&(item_data_off + 16).to_le_bytes());
        image[me1 + 20..me1 + 24].copy_from_slice(&8u32.to_le_bytes());
        let me2: usize = me1 + 32;
        image[me2..me2 + 16].copy_from_slice(&VHDX_META_LOGICAL_SECTOR_SIZE_GUID);
        image[me2 + 16..me2 + 20].copy_from_slice(&(item_data_off + 32).to_le_bytes());
        image[me2 + 20..me2 + 24].copy_from_slice(&4u32.to_le_bytes());

        let fp: usize = meta + item_data_off as usize;
        image[fp..fp + 4].copy_from_slice(&BLOCK_SIZE.to_le_bytes());
        image[fp + 4..fp + 8].copy_from_slice(&0u32.to_le_bytes());
        let vds: usize = fp + 16;
        image[vds..vds + 8].copy_from_slice(&VIRTUAL_DISK_SIZE.to_le_bytes());
        let lss: usize = fp + 32;
        image[lss..lss + 4].copy_from_slice(&LOGICAL_SECTOR.to_le_bytes());

        let bat: usize = BAT_REGION_OFFSET as usize;
        let present: u64 = (1u64 << 20) | 6;
        let not_present: u64 = 0;
        let third: u64 = (2u64 << 20) | 6;
        image[bat..bat + 8].copy_from_slice(&present.to_le_bytes());
        image[bat + 8..bat + 16].copy_from_slice(&not_present.to_le_bytes());
        image[bat + 16..bat + 24].copy_from_slice(&third.to_le_bytes());

        image
    }

    #[test]
    fn parses_vhdx_layout_and_metadata() {
        let image: Vec<u8> = build_vhdx();
        let parsed: VhdxImage = parse_vhdx(&image).expect("parse vhdx");
        assert_eq!(parsed.header.sequence_number, 5);
        assert_eq!(parsed.header.format_version, 1);
        assert_eq!(parsed.regions.len(), 2);
        assert!(parsed.bat_region.is_some());
        assert!(parsed.metadata_region.is_some());
        let meta: VhdxMetadata = parsed.metadata.expect("metadata");
        assert_eq!(meta.block_size, BLOCK_SIZE);
        assert_eq!(meta.logical_sector_size, LOGICAL_SECTOR);
        assert_eq!(meta.virtual_disk_size, VIRTUAL_DISK_SIZE);
        assert_eq!(parsed.allocated_block_count, 2);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut image: Vec<u8> = build_vhdx();
        image[0] = b'X';
        assert!(parse_vhdx(&image).is_err());
    }

    #[test]
    fn rejects_too_small() {
        assert!(parse_vhdx(&[0u8; 64]).is_err());
    }
}
