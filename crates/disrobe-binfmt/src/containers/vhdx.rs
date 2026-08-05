use disrobe_bytes::{ByteReadError, read_bytes_at, read_u16_le_at, read_u32_le_at, read_u64_le_at};
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

pub(crate) const VHDX_HEADER_LEN: usize = 80;
pub(crate) const VHDX_REGION_TABLE_HEAD_LEN: usize = 16;
pub(crate) const VHDX_REGION_ENTRY_LEN: usize = 32;
pub(crate) const VHDX_METADATA_TABLE_HEAD_LEN: usize = 32;
pub(crate) const VHDX_METADATA_ENTRY_LEN: usize = 32;
pub(crate) const VHDX_MAX_REGION_ENTRIES: u32 = 2047;
pub(crate) const VHDX_BAT_ENTRY_LEN: u64 = 8;

fn truncated(context: &'static str, e: &ByteReadError) -> Error {
    Error::Decompression(format!(
        "{context} truncated at offset {} (needed {}, available {})",
        e.offset, e.needed, e.available
    ))
}

fn parse_header(bytes: &[u8], offset: usize) -> Option<VhdxHeader> {
    let header: &[u8] = read_bytes_at(bytes, offset, VHDX_HEADER_LEN).ok()?;
    if header.get(0..4)? != VHDX_HEADER_SIGNATURE {
        return None;
    }
    Some(VhdxHeader {
        sequence_number: read_u64_le_at(header, 8).ok()?,
        log_version: read_u16_le_at(header, 64).ok()?,
        format_version: read_u16_le_at(header, 66).ok()?,
        log_length: read_u32_le_at(header, 68).ok()?,
        log_offset: read_u64_le_at(header, 72).ok()?,
    })
}

fn parse_region_table(bytes: &[u8], offset: usize) -> Result<Vec<VhdxRegion>> {
    let head: &[u8] = read_bytes_at(bytes, offset, VHDX_REGION_TABLE_HEAD_LEN)
        .map_err(|e: ByteReadError| truncated("vhdx region table", &e))?;
    if head.get(0..4) != Some(VHDX_REGION_SIGNATURE.as_slice()) {
        return Err(Error::Decompression(
            "vhdx region signature mismatch".to_owned(),
        ));
    }
    let entry_count: u32 = read_u32_le_at(head, 8)
        .map_err(|e: ByteReadError| truncated("vhdx region entry count", &e))?;
    if entry_count > VHDX_MAX_REGION_ENTRIES {
        return Err(Error::Decompression(
            "vhdx region entry count out of range".to_owned(),
        ));
    }
    let table_start: usize = offset
        .checked_add(VHDX_REGION_TABLE_HEAD_LEN)
        .ok_or_else(|| Error::Decompression("vhdx region table offset overflow".to_owned()))?;
    let mut regions: Vec<VhdxRegion> = Vec::with_capacity(entry_count as usize);
    for index in 0..entry_count as usize {
        let Some(entry_off): Option<usize> = index
            .checked_mul(VHDX_REGION_ENTRY_LEN)
            .and_then(|delta: usize| table_start.checked_add(delta))
        else {
            break;
        };
        let entry: &[u8] = read_bytes_at(bytes, entry_off, VHDX_REGION_ENTRY_LEN)
            .map_err(|e: ByteReadError| truncated("vhdx region entry", &e))?;
        let field = |e: ByteReadError| truncated("vhdx region entry", &e);
        let mut guid: [u8; 16] = [0u8; 16];
        guid.copy_from_slice(&entry[0..16]);
        let file_offset: u64 = read_u64_le_at(entry, 16).map_err(field)?;
        let length: u64 = u64::from(read_u32_le_at(entry, 24).map_err(field)?);
        let required: bool = read_u32_le_at(entry, 28).map_err(field)? & 1 == 1;
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
    let table: &[u8] = read_bytes_at(bytes, region_off, VHDX_METADATA_TABLE_HEAD_LEN).ok()?;
    if table.get(0..8)? != VHDX_METADATA_SIGNATURE {
        return None;
    }
    let entry_count: u16 = read_u16_le_at(table, 10).ok()?;
    let entries_start: usize = region_off.checked_add(VHDX_METADATA_TABLE_HEAD_LEN)?;
    let mut block_size: u32 = 0;
    let mut leave_blocks_allocated: bool = false;
    let mut has_parent: bool = false;
    let mut logical_sector_size: u32 = 0;
    let mut virtual_disk_size: u64 = 0;
    for index in 0..entry_count as usize {
        let entry_off: usize = index
            .checked_mul(VHDX_METADATA_ENTRY_LEN)
            .and_then(|delta: usize| entries_start.checked_add(delta))?;
        let entry: &[u8] = read_bytes_at(bytes, entry_off, VHDX_METADATA_ENTRY_LEN).ok()?;
        let mut item_guid: [u8; 16] = [0u8; 16];
        item_guid.copy_from_slice(&entry[0..16]);
        let item_offset: u32 = read_u32_le_at(entry, 16).ok()?;
        let item_abs: usize = region_off.checked_add(item_offset as usize)?;
        if item_guid == VHDX_META_FILE_PARAMETERS_GUID {
            block_size = read_u32_le_at(bytes, item_abs).ok()?;
            let flags: u32 = read_u32_le_at(bytes, item_abs.checked_add(4)?).ok()?;
            leave_blocks_allocated = flags & 0x1 != 0;
            has_parent = flags & 0x2 != 0;
        } else if item_guid == VHDX_META_LOGICAL_SECTOR_SIZE_GUID {
            logical_sector_size = read_u32_le_at(bytes, item_abs).ok()?;
        } else if item_guid == VHDX_META_VIRTUAL_DISK_SIZE_GUID {
            virtual_disk_size = read_u64_le_at(bytes, item_abs).ok()?;
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
        let Some(entry_off): Option<usize> = bat_entry_offset(region_off, entry_index) else {
            break;
        };
        let Ok(raw): std::result::Result<u64, ByteReadError> = read_u64_le_at(bytes, entry_off)
        else {
            break;
        };
        let is_bitmap_entry: bool =
            entry_index != 0 && (entry_index % (chunk_ratio + 1)) == chunk_ratio;
        if !is_bitmap_entry {
            let state: u64 = raw & 0x7;
            if state == 6 || state == 7 {
                allocated = allocated.saturating_add(1);
            }
            payload_index += 1;
        }
        entry_index += 1;
    }
    allocated
}

fn bat_entry_offset(region_off: usize, entry_index: u64) -> Option<usize> {
    let delta: usize = usize::try_from(entry_index.checked_mul(VHDX_BAT_ENTRY_LEN)?).ok()?;
    region_off.checked_add(delta)
}

const VHDX_PAYLOAD_BLOCK_MB_SHIFT: u32 = 20;

pub fn materialize_logical_disk(bytes: &[u8], image: &VhdxImage, cap: u64) -> Result<Vec<u8>> {
    let bat_region: &VhdxRegion = image
        .bat_region
        .as_ref()
        .ok_or_else(|| Error::Decompression("vhdx has no BAT region".to_owned()))?;
    let metadata: &VhdxMetadata = image
        .metadata
        .as_ref()
        .ok_or_else(|| Error::Decompression("vhdx has no parsed metadata".to_owned()))?;
    if metadata.block_size == 0
        || metadata.logical_sector_size == 0
        || metadata.virtual_disk_size == 0
    {
        return Err(Error::Decompression(
            "vhdx metadata missing block/sector/disk size".to_owned(),
        ));
    }
    if metadata.virtual_disk_size > cap {
        return Err(Error::Decompression(format!(
            "vhdx virtual disk size {} bytes exceeds materialization cap {cap}",
            metadata.virtual_disk_size
        )));
    }
    let logical_size: usize =
        usize::try_from(metadata.virtual_disk_size).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("vhdx disk size overflow".to_owned())
        })?;
    let block_size: usize = metadata.block_size as usize;
    let region_off: usize =
        usize::try_from(bat_region.file_offset).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("vhdx bat region offset overflow".to_owned())
        })?;
    let block_size_u64: u64 = u64::from(metadata.block_size);
    let payload_blocks: u64 = metadata.virtual_disk_size.div_ceil(block_size_u64);
    let sector_bitmap_span: u64 = (u64::from(1u32) << 23) * u64::from(metadata.logical_sector_size);
    let chunk_ratio: u64 = (sector_bitmap_span / block_size_u64).max(1);
    let mut disk: Vec<u8> = vec![0u8; logical_size];
    let mut payload_index: u64 = 0;
    let mut entry_index: u64 = 0;
    while payload_index < payload_blocks {
        let Some(entry_off): Option<usize> = bat_entry_offset(region_off, entry_index) else {
            break;
        };
        let Ok(raw): std::result::Result<u64, ByteReadError> = read_u64_le_at(bytes, entry_off)
        else {
            break;
        };
        let is_bitmap_entry: bool =
            entry_index != 0 && (entry_index % (chunk_ratio + 1)) == chunk_ratio;
        if !is_bitmap_entry {
            let state: u64 = raw & 0x7;
            if state == 6 || state == 7 {
                let file_off: usize = usize::try_from(
                    (raw >> VHDX_PAYLOAD_BLOCK_MB_SHIFT) << VHDX_PAYLOAD_BLOCK_MB_SHIFT,
                )
                .map_err(|_e: std::num::TryFromIntError| {
                    Error::Decompression("vhdx payload block offset overflow".to_owned())
                })?;
                let disk_off: usize = usize::try_from(payload_index)
                    .ok()
                    .and_then(|i: usize| i.checked_mul(block_size))
                    .ok_or_else(|| Error::Decompression("vhdx disk offset overflow".to_owned()))?;
                if disk_off < logical_size {
                    let copy_len: usize = block_size.min(logical_size - disk_off);
                    if let Ok(src) = read_bytes_at(bytes, file_off, copy_len) {
                        let disk_end: usize = disk_off.checked_add(copy_len).ok_or_else(|| {
                            Error::Decompression("vhdx disk write range overflow".to_owned())
                        })?;
                        disk[disk_off..disk_end].copy_from_slice(src);
                    }
                }
            }
            payload_index += 1;
        }
        entry_index += 1;
    }
    Ok(disk)
}

pub fn parse_vhdx(bytes: &[u8]) -> Result<VhdxImage> {
    if bytes.len() < VHDX_REGION_1_OFFSET + VHDX_REGION_TABLE_HEAD_LEN {
        return Err(Error::Decompression("vhdx image too small".to_owned()));
    }
    let signature: &[u8] = read_bytes_at(bytes, 0, 8)
        .map_err(|e: ByteReadError| truncated("vhdx file identifier", &e))?;
    if signature != VHDX_SIGNATURE {
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
    fn vhdx_parse_output_is_stable_for_a_spec_correct_image() {
        let image: Vec<u8> = build_vhdx();
        let parsed: VhdxImage = parse_vhdx(&image).expect("parse vhdx");
        let encoded: String = serde_json::to_string(&parsed).expect("encode vhdx image");
        assert_eq!(
            encoded,
            r#"{"header":{"sequence_number":5,"log_version":0,"format_version":1,"log_length":0,"log_offset":0},"regions":[{"guid":[102,119,194,45,35,246,0,66,157,100,17,94,155,253,74,8],"file_offset":2097152,"length":1048576,"required":true},{"guid":[6,162,124,139,144,71,154,75,184,254,87,95,5,15,136,110],"file_offset":1048576,"length":1048576,"required":true}],"bat_region":{"guid":[102,119,194,45,35,246,0,66,157,100,17,94,155,253,74,8],"file_offset":2097152,"length":1048576,"required":true},"metadata_region":{"guid":[6,162,124,139,144,71,154,75,184,254,87,95,5,15,136,110],"file_offset":1048576,"length":1048576,"required":true},"metadata":{"block_size":2097152,"leave_blocks_allocated":false,"has_parent":false,"logical_sector_size":512,"virtual_disk_size":6291456},"allocated_block_count":2}"#
        );
    }

    #[test]
    fn every_truncation_of_a_valid_image_errors_without_panicking() {
        let image: Vec<u8> = build_vhdx();
        for len in [
            0usize,
            1,
            7,
            8,
            VHDX_HEADER_1_OFFSET,
            VHDX_HEADER_1_OFFSET + VHDX_HEADER_LEN - 1,
            VHDX_HEADER_2_OFFSET + VHDX_HEADER_LEN - 1,
            VHDX_REGION_1_OFFSET - 1,
            VHDX_REGION_1_OFFSET + VHDX_REGION_TABLE_HEAD_LEN - 1,
            VHDX_REGION_1_OFFSET + VHDX_REGION_TABLE_HEAD_LEN,
            VHDX_REGION_1_OFFSET + VHDX_REGION_TABLE_HEAD_LEN + VHDX_REGION_ENTRY_LEN - 1,
        ] {
            let view: &[u8] = &image[..len.min(image.len())];
            let _: Result<VhdxImage> = parse_vhdx(view);
        }
        assert!(parse_vhdx(&image[..VHDX_REGION_1_OFFSET + 15]).is_err());
        let mut short_regions: Vec<u8> = image;
        short_regions.truncate(VHDX_REGION_1_OFFSET + VHDX_REGION_TABLE_HEAD_LEN);
        assert!(parse_vhdx(&short_regions).is_err());
    }

    #[test]
    fn a_bat_entry_pointing_outside_the_file_leaves_the_block_zeroed() {
        let mut image: Vec<u8> = build_vhdx();
        let bat: usize = BAT_REGION_OFFSET as usize;
        let outside: u64 = (u64::MAX >> VHDX_PAYLOAD_BLOCK_MB_SHIFT) << VHDX_PAYLOAD_BLOCK_MB_SHIFT;
        image[bat..bat + 8].copy_from_slice(&(outside | 6).to_le_bytes());
        image[bat + 8..bat + 16].copy_from_slice(&0u64.to_le_bytes());
        image[bat + 16..bat + 24].copy_from_slice(&0u64.to_le_bytes());
        let parsed: VhdxImage = parse_vhdx(&image).expect("parse vhdx");
        let disk: Vec<u8> =
            materialize_logical_disk(&image, &parsed, 1 << 30).expect("materialize vhdx");
        assert_eq!(disk.len(), VIRTUAL_DISK_SIZE as usize);
        assert!(
            disk.iter().all(|&b: &u8| b == 0),
            "an out-of-file BAT entry must contribute nothing"
        );
    }

    #[test]
    fn a_bat_entry_pointing_at_its_own_region_terminates() {
        let mut image: Vec<u8> = build_vhdx();
        let bat: usize = BAT_REGION_OFFSET as usize;
        let self_referential: u64 =
            (BAT_REGION_OFFSET >> VHDX_PAYLOAD_BLOCK_MB_SHIFT << VHDX_PAYLOAD_BLOCK_MB_SHIFT) | 6;
        for slot in 0..3usize {
            let off: usize = bat + slot * 8;
            image[off..off + 8].copy_from_slice(&self_referential.to_le_bytes());
        }
        let parsed: VhdxImage = parse_vhdx(&image).expect("parse vhdx");
        assert_eq!(parsed.allocated_block_count, 3);
        let disk: Vec<u8> =
            materialize_logical_disk(&image, &parsed, 1 << 30).expect("materialize vhdx");
        assert_eq!(disk.len(), VIRTUAL_DISK_SIZE as usize);
    }

    #[test]
    fn a_bat_region_offset_at_the_top_of_the_address_space_does_not_overflow() {
        let mut image: Vec<u8> = build_vhdx();
        let entry_0: usize = VHDX_REGION_1_OFFSET + 16;
        image[entry_0 + 16..entry_0 + 24].copy_from_slice(&u64::MAX.to_le_bytes());
        let parsed: VhdxImage = parse_vhdx(&image).expect("parse vhdx");
        assert_eq!(parsed.allocated_block_count, 0);
        let disk: Vec<u8> =
            materialize_logical_disk(&image, &parsed, 1 << 30).expect("materialize vhdx");
        assert!(disk.iter().all(|&b: &u8| b == 0));
    }

    #[test]
    fn an_oversized_metadata_entry_count_stops_at_the_end_of_the_image() {
        let mut image: Vec<u8> = build_vhdx();
        let meta: usize = META_REGION_OFFSET as usize;
        image[meta + 10..meta + 12].copy_from_slice(&u16::MAX.to_le_bytes());
        let inside: VhdxImage = parse_vhdx(&image).expect("parse vhdx");
        assert_eq!(
            inside.metadata.map(|m: VhdxMetadata| m.block_size),
            Some(BLOCK_SIZE),
            "zero-filled trailing metadata entries are inert, not fatal"
        );
        image.truncate(meta + 32 + 4 * VHDX_METADATA_ENTRY_LEN);
        let clipped: VhdxImage = parse_vhdx(&image).expect("parse vhdx");
        assert!(
            clipped.metadata.is_none(),
            "a metadata table that runs off the image must not be trusted"
        );
        assert_eq!(clipped.allocated_block_count, 0);
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

    #[test]
    fn materializes_present_bat_blocks_byte_identical() {
        let mut image: Vec<u8> = build_vhdx();
        let block0_file_off: u64 = 3 * 1024 * 1024;
        let block2_file_off: u64 = 4 * 1024 * 1024;
        image.resize((block2_file_off as usize) + BLOCK_SIZE as usize, 0u8);

        let bat: usize = BAT_REGION_OFFSET as usize;
        let present0: u64 = (block0_file_off >> 20 << 20) | 6;
        let present2: u64 = (block2_file_off >> 20 << 20) | 6;
        image[bat..bat + 8].copy_from_slice(&present0.to_le_bytes());
        image[bat + 8..bat + 16].copy_from_slice(&0u64.to_le_bytes());
        image[bat + 16..bat + 24].copy_from_slice(&present2.to_le_bytes());

        let marker0: &[u8] = b"VHDX-PAYLOAD-BLOCK-ZERO";
        let marker2: &[u8] = b"VHDX-PAYLOAD-BLOCK-TWO";
        let off0: usize = block0_file_off as usize;
        let off2: usize = block2_file_off as usize;
        image[off0..off0 + marker0.len()].copy_from_slice(marker0);
        image[off2..off2 + marker2.len()].copy_from_slice(marker2);

        let parsed: VhdxImage = parse_vhdx(&image).expect("parse vhdx");
        assert!(parsed.metadata.is_some());
        let disk: Vec<u8> =
            materialize_logical_disk(&image, &parsed, 1 << 30).expect("materialize vhdx");
        assert_eq!(disk.len(), VIRTUAL_DISK_SIZE as usize);
        assert_eq!(&disk[0..marker0.len()], marker0);
        let block2_disk_off: usize = 2 * BLOCK_SIZE as usize;
        assert_eq!(
            &disk[block2_disk_off..block2_disk_off + marker2.len()],
            marker2
        );
        let block1_disk_off: usize = BLOCK_SIZE as usize;
        assert!(
            disk[block1_disk_off..block1_disk_off + 32]
                .iter()
                .all(|&b: &u8| b == 0),
            "unallocated block 1 must read back as zeros"
        );
    }
}
