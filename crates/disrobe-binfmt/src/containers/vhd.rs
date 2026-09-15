use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const VHD_COOKIE: &[u8; 8] = b"conectix";
pub const VHD_DYNAMIC_COOKIE: &[u8; 8] = b"cxsparse";
pub const VHD_FOOTER_LEN: usize = 512;
pub const VHD_DYNAMIC_HEADER_LEN: usize = 1024;
pub const VHD_SECTOR_SIZE: u64 = 512;
pub const VHD_BAT_UNALLOCATED: u32 = 0xffff_ffff;
const MAX_BAT_ENTRIES: usize = 1 << 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VhdDiskType {
    Fixed,
    Dynamic,
    Differencing,
    Unknown(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhdGeometry {
    pub cylinders: u16,
    pub heads: u8,
    pub sectors_per_track: u8,
    pub total_sectors: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhdFooter {
    pub features: u32,
    pub format_version: u32,
    pub data_offset: u64,
    pub creator_application: [u8; 4],
    pub creator_version: u32,
    pub original_size: u64,
    pub current_size: u64,
    pub geometry: VhdGeometry,
    pub disk_type: VhdDiskType,
    pub checksum: u32,
    pub checksum_valid: bool,
    pub identifier: [u8; 16],
    pub saved_state: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhdDynamicHeader {
    pub bat_offset: u64,
    pub max_table_entries: u32,
    pub block_size: u32,
    pub checksum: u32,
    pub checksum_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhdImage {
    pub footer: VhdFooter,
    pub dynamic_header: Option<VhdDynamicHeader>,
    pub allocated_block_count: u32,
    pub allocated_block_sectors: Vec<u32>,
}

fn vhd_checksum(footer: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for (index, &byte) in footer.iter().enumerate() {
        if (64..68).contains(&index) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(byte));
    }
    !sum
}

fn read_u16_be(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64_be(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
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

pub fn parse_vhd_footer(footer: &[u8]) -> Result<VhdFooter> {
    if footer.len() < VHD_FOOTER_LEN {
        return Err(Error::Decompression("vhd footer truncated".to_owned()));
    }
    let footer: &[u8] = &footer[..VHD_FOOTER_LEN];
    if &footer[0..8] != VHD_COOKIE {
        return Err(Error::Decompression("vhd cookie mismatch".to_owned()));
    }
    let features: u32 = read_u32_be(footer, 8);
    let format_version: u32 = read_u32_be(footer, 12);
    let data_offset: u64 = read_u64_be(footer, 16);
    let creator_application: [u8; 4] = [footer[28], footer[29], footer[30], footer[31]];
    let creator_version: u32 = read_u32_be(footer, 32);
    let original_size: u64 = read_u64_be(footer, 40);
    let current_size: u64 = read_u64_be(footer, 48);
    let cylinders: u16 = read_u16_be(footer, 56);
    let heads: u8 = footer[58];
    let sectors_per_track: u8 = footer[59];
    let total_sectors: u64 = u64::from(cylinders) * u64::from(heads) * u64::from(sectors_per_track);
    let disk_type_raw: u32 = read_u32_be(footer, 60);
    let disk_type: VhdDiskType = match disk_type_raw {
        2 => VhdDiskType::Fixed,
        3 => VhdDiskType::Dynamic,
        4 => VhdDiskType::Differencing,
        other => VhdDiskType::Unknown(other),
    };
    let checksum: u32 = read_u32_be(footer, 64);
    let checksum_valid: bool = vhd_checksum(footer) == checksum;
    let mut identifier: [u8; 16] = [0u8; 16];
    identifier.copy_from_slice(&footer[68..84]);
    let saved_state: bool = footer[84] != 0;
    Ok(VhdFooter {
        features,
        format_version,
        data_offset,
        creator_application,
        creator_version,
        original_size,
        current_size,
        geometry: VhdGeometry {
            cylinders,
            heads,
            sectors_per_track,
            total_sectors,
        },
        disk_type,
        checksum,
        checksum_valid,
        identifier,
        saved_state,
    })
}

fn dynamic_checksum(header: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for (index, &byte) in header.iter().enumerate() {
        if (36..40).contains(&index) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(byte));
    }
    !sum
}

pub fn parse_vhd_dynamic_header(header: &[u8]) -> Result<VhdDynamicHeader> {
    if header.len() < VHD_DYNAMIC_HEADER_LEN {
        return Err(Error::Decompression(
            "vhd dynamic header truncated".to_owned(),
        ));
    }
    let header: &[u8] = &header[..VHD_DYNAMIC_HEADER_LEN];
    if &header[0..8] != VHD_DYNAMIC_COOKIE {
        return Err(Error::Decompression(
            "vhd dynamic cookie mismatch".to_owned(),
        ));
    }
    let bat_offset: u64 = read_u64_be(header, 16);
    let max_table_entries: u32 = read_u32_be(header, 28);
    let block_size: u32 = read_u32_be(header, 32);
    let checksum: u32 = read_u32_be(header, 36);
    let checksum_valid: bool = dynamic_checksum(header) == checksum;
    Ok(VhdDynamicHeader {
        bat_offset,
        max_table_entries,
        block_size,
        checksum,
        checksum_valid,
    })
}

pub fn parse_vhd(bytes: &[u8]) -> Result<VhdImage> {
    if bytes.len() < VHD_FOOTER_LEN {
        return Err(Error::Decompression("vhd image too small".to_owned()));
    }
    let footer_bytes: &[u8] = if &bytes[0..8] == VHD_COOKIE {
        &bytes[0..VHD_FOOTER_LEN]
    } else {
        &bytes[bytes.len() - VHD_FOOTER_LEN..]
    };
    let footer: VhdFooter = parse_vhd_footer(footer_bytes)?;
    let mut dynamic_header: Option<VhdDynamicHeader> = None;
    let mut allocated_block_sectors: Vec<u32> = Vec::new();
    if matches!(
        footer.disk_type,
        VhdDiskType::Dynamic | VhdDiskType::Differencing
    ) && footer.data_offset != u64::MAX
    {
        let header_off: usize = usize::try_from(footer.data_offset)
            .map_err(|_| Error::Decompression("vhd data offset overflow".to_owned()))?;
        let header_end: usize = header_off
            .checked_add(VHD_DYNAMIC_HEADER_LEN)
            .ok_or_else(|| Error::Decompression("vhd dynamic header overflow".to_owned()))?;
        if header_end <= bytes.len() {
            let dyn_header: VhdDynamicHeader =
                parse_vhd_dynamic_header(&bytes[header_off..header_end])?;
            let bat_off: usize = usize::try_from(dyn_header.bat_offset)
                .map_err(|_| Error::Decompression("vhd bat offset overflow".to_owned()))?;
            let entries: usize = dyn_header.max_table_entries as usize;
            if entries > MAX_BAT_ENTRIES {
                return Err(Error::Decompression(
                    "vhd bat table entry count exceeds materialization bound".to_owned(),
                ));
            }
            for index in 0..entries {
                let entry_off: usize = bat_off
                    .checked_add(index * 4)
                    .ok_or_else(|| Error::Decompression("vhd bat index overflow".to_owned()))?;
                let Some(slice): Option<&[u8]> = bytes.get(entry_off..entry_off + 4) else {
                    break;
                };
                let sector: u32 = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
                if sector != VHD_BAT_UNALLOCATED {
                    allocated_block_sectors.push(sector);
                }
            }
            dynamic_header = Some(dyn_header);
        }
    }
    let allocated_block_count: u32 = allocated_block_sectors.len() as u32;
    Ok(VhdImage {
        footer,
        dynamic_header,
        allocated_block_count,
        allocated_block_sectors,
    })
}

pub fn materialize_logical_disk(bytes: &[u8], image: &VhdImage, cap: u64) -> Result<Vec<u8>> {
    let logical_size: u64 = image.footer.current_size;
    if logical_size == 0 || logical_size > cap {
        return Err(Error::Decompression(format!(
            "vhd logical size {logical_size} bytes exceeds materialization cap {cap}"
        )));
    }
    let logical_size_usize: usize =
        usize::try_from(logical_size).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("vhd logical size overflow".to_owned())
        })?;
    match image.footer.disk_type {
        VhdDiskType::Fixed => {
            let payload_end: usize = bytes.len().saturating_sub(VHD_FOOTER_LEN);
            let copy_len: usize = payload_end.min(logical_size_usize);
            let mut disk: Vec<u8> = vec![0u8; logical_size_usize];
            disk[..copy_len].copy_from_slice(&bytes[..copy_len]);
            Ok(disk)
        }
        VhdDiskType::Dynamic | VhdDiskType::Differencing => {
            let header: &VhdDynamicHeader = image.dynamic_header.as_ref().ok_or_else(|| {
                Error::Decompression("vhd dynamic disk missing dynamic header".to_owned())
            })?;
            materialize_dynamic_disk(bytes, header, logical_size_usize)
        }
        VhdDiskType::Unknown(code) => Err(Error::Decompression(format!(
            "vhd disk type {code} is not materializable in-tree"
        ))),
    }
}

fn materialize_dynamic_disk(
    bytes: &[u8],
    header: &VhdDynamicHeader,
    logical_size: usize,
) -> Result<Vec<u8>> {
    let block_size: usize = header.block_size as usize;
    if block_size == 0 || !block_size.is_multiple_of(VHD_SECTOR_SIZE as usize) {
        return Err(Error::Decompression(
            "vhd dynamic block size invalid".to_owned(),
        ));
    }
    let sectors_per_block: usize = block_size / VHD_SECTOR_SIZE as usize;
    let bitmap_bytes: usize = sectors_per_block.div_ceil(8);
    let bitmap_sectors: usize = bitmap_bytes.div_ceil(VHD_SECTOR_SIZE as usize);
    let bat_off: usize =
        usize::try_from(header.bat_offset).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("vhd bat offset overflow".to_owned())
        })?;
    let entries: usize = header.max_table_entries as usize;
    if entries > MAX_BAT_ENTRIES {
        return Err(Error::Decompression(
            "vhd bat table entry count exceeds materialization bound".to_owned(),
        ));
    }
    let mut disk: Vec<u8> = vec![0u8; logical_size];
    for index in 0..entries {
        let entry_off: usize = bat_off
            .checked_add(index * 4)
            .ok_or_else(|| Error::Decompression("vhd bat index overflow".to_owned()))?;
        let Some(slice): Option<&[u8]> = bytes.get(entry_off..entry_off + 4) else {
            break;
        };
        let block_sector: u32 = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
        if block_sector == VHD_BAT_UNALLOCATED {
            continue;
        }
        let block_byte_off: usize = (block_sector as usize)
            .checked_mul(VHD_SECTOR_SIZE as usize)
            .and_then(|v: usize| v.checked_add(bitmap_sectors * VHD_SECTOR_SIZE as usize))
            .ok_or_else(|| Error::Decompression("vhd block offset overflow".to_owned()))?;
        let disk_off: usize = match index.checked_mul(block_size) {
            Some(value) if value < logical_size => value,
            _ => continue,
        };
        let copy_len: usize = block_size.min(logical_size - disk_off);
        let Some(src): Option<&[u8]> = bytes.get(block_byte_off..block_byte_off + copy_len) else {
            continue;
        };
        disk[disk_off..disk_off + copy_len].copy_from_slice(src);
    }
    Ok(disk)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_footer(disk_type: u32, data_offset: u64) -> Vec<u8> {
        let mut footer: Vec<u8> = vec![0u8; VHD_FOOTER_LEN];
        footer[0..8].copy_from_slice(VHD_COOKIE);
        footer[8..12].copy_from_slice(&0x0000_0002u32.to_be_bytes());
        footer[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        footer[16..24].copy_from_slice(&data_offset.to_be_bytes());
        footer[28..32].copy_from_slice(b"vpc ");
        footer[40..48].copy_from_slice(&(64u64 * 1024 * 1024).to_be_bytes());
        footer[48..56].copy_from_slice(&(64u64 * 1024 * 1024).to_be_bytes());
        footer[56..58].copy_from_slice(&130u16.to_be_bytes());
        footer[58] = 16;
        footer[59] = 63;
        footer[60..64].copy_from_slice(&disk_type.to_be_bytes());
        let checksum: u32 = vhd_checksum(&footer);
        footer[64..68].copy_from_slice(&checksum.to_be_bytes());
        footer
    }

    #[test]
    fn parses_fixed_footer_with_valid_checksum() {
        let footer: Vec<u8> = build_footer(2, u64::MAX);
        let parsed: VhdFooter = parse_vhd_footer(&footer).expect("parse footer");
        assert_eq!(parsed.disk_type, VhdDiskType::Fixed);
        assert!(parsed.checksum_valid);
        assert_eq!(parsed.geometry.cylinders, 130);
        assert_eq!(parsed.geometry.heads, 16);
        assert_eq!(parsed.geometry.sectors_per_track, 63);
        assert_eq!(parsed.geometry.total_sectors, 130 * 16 * 63);
        assert_eq!(&parsed.creator_application, b"vpc ");
        assert_eq!(parsed.current_size, 64 * 1024 * 1024);
    }

    #[test]
    fn rejects_bad_cookie() {
        let mut footer: Vec<u8> = build_footer(2, u64::MAX);
        footer[0] = b'X';
        assert!(parse_vhd_footer(&footer).is_err());
    }

    #[test]
    fn parses_dynamic_with_bat() {
        let footer: Vec<u8> = build_footer(3, 512);
        let mut dyn_header: Vec<u8> = vec![0u8; VHD_DYNAMIC_HEADER_LEN];
        dyn_header[0..8].copy_from_slice(VHD_DYNAMIC_COOKIE);
        let bat_offset: u64 = (VHD_FOOTER_LEN + VHD_DYNAMIC_HEADER_LEN) as u64;
        dyn_header[16..24].copy_from_slice(&bat_offset.to_be_bytes());
        dyn_header[28..32].copy_from_slice(&4u32.to_be_bytes());
        dyn_header[32..36].copy_from_slice(&(2u32 * 1024 * 1024).to_be_bytes());
        let checksum: u32 = dynamic_checksum(&dyn_header);
        dyn_header[36..40].copy_from_slice(&checksum.to_be_bytes());

        let mut image: Vec<u8> = Vec::new();
        image.extend_from_slice(&footer);
        image.extend_from_slice(&dyn_header);
        let bat: [u32; 4] = [
            0x0000_0010,
            VHD_BAT_UNALLOCATED,
            0x0000_0020,
            VHD_BAT_UNALLOCATED,
        ];
        for entry in bat {
            image.extend_from_slice(&entry.to_be_bytes());
        }
        image.extend_from_slice(&footer);

        let parsed: VhdImage = parse_vhd(&image).expect("parse dynamic vhd");
        assert_eq!(parsed.footer.disk_type, VhdDiskType::Dynamic);
        let dyn_h: &VhdDynamicHeader = parsed.dynamic_header.as_ref().expect("dynamic header");
        assert!(dyn_h.checksum_valid);
        assert_eq!(dyn_h.max_table_entries, 4);
        assert_eq!(dyn_h.block_size, 2 * 1024 * 1024);
        assert_eq!(parsed.allocated_block_count, 2);
        assert_eq!(parsed.allocated_block_sectors, vec![0x10, 0x20]);
    }

    #[test]
    fn rejects_too_small() {
        assert!(parse_vhd(&[0u8; 16]).is_err());
    }

    #[test]
    fn fixed_materializes_payload_minus_footer() {
        let logical: usize = 4 * VHD_FOOTER_LEN;
        let mut footer: Vec<u8> = build_footer(2, u64::MAX);
        footer[48..56].copy_from_slice(&(logical as u64).to_be_bytes());
        let csum: u32 = vhd_checksum(&footer);
        footer[64..68].copy_from_slice(&csum.to_be_bytes());
        let mut image: Vec<u8> = vec![0u8; logical];
        let marker: &[u8] = b"fixed-vhd-payload-marker";
        image[0..marker.len()].copy_from_slice(marker);
        image.extend_from_slice(&footer);

        let parsed: VhdImage = parse_vhd(&image).expect("parse");
        let disk: Vec<u8> =
            materialize_logical_disk(&image, &parsed, 1 << 30).expect("materialize fixed");
        assert_eq!(disk.len(), logical);
        assert_eq!(&disk[0..marker.len()], marker);
    }

    #[test]
    fn dynamic_materializes_allocated_blocks_byte_identical() {
        let block_size: u32 = 512;
        let logical: u64 = 4 * u64::from(block_size);
        let mut footer: Vec<u8> = build_footer(3, 512);
        footer[48..56].copy_from_slice(&logical.to_be_bytes());
        let csum: u32 = vhd_checksum(&footer);
        footer[64..68].copy_from_slice(&csum.to_be_bytes());

        let mut dyn_header: Vec<u8> = vec![0u8; VHD_DYNAMIC_HEADER_LEN];
        dyn_header[0..8].copy_from_slice(VHD_DYNAMIC_COOKIE);
        let bat_offset: u64 = (VHD_FOOTER_LEN + VHD_DYNAMIC_HEADER_LEN) as u64;
        dyn_header[16..24].copy_from_slice(&bat_offset.to_be_bytes());
        dyn_header[28..32].copy_from_slice(&4u32.to_be_bytes());
        dyn_header[32..36].copy_from_slice(&block_size.to_be_bytes());
        let csum: u32 = dynamic_checksum(&dyn_header);
        dyn_header[36..40].copy_from_slice(&csum.to_be_bytes());

        let bat_bytes: usize = 4 * 4;
        let header_region: usize = VHD_FOOTER_LEN + VHD_DYNAMIC_HEADER_LEN + bat_bytes;
        let sector: usize = VHD_SECTOR_SIZE as usize;
        let bitmap_sectors: usize = 1;
        let block_on_disk: usize = (bitmap_sectors + 1) * sector;
        let block0_off: usize = header_region.next_multiple_of(sector);
        let block2_off: usize = block0_off + block_on_disk;
        let total: usize = block2_off + block_on_disk + VHD_FOOTER_LEN;
        let mut image: Vec<u8> = vec![0u8; total];
        image[0..VHD_FOOTER_LEN].copy_from_slice(&footer);
        image[VHD_FOOTER_LEN..VHD_FOOTER_LEN + VHD_DYNAMIC_HEADER_LEN].copy_from_slice(&dyn_header);

        let block0_sector: u32 = (block0_off / VHD_SECTOR_SIZE as usize) as u32;
        let block2_sector: u32 = (block2_off / VHD_SECTOR_SIZE as usize) as u32;
        let bat_off: usize = VHD_FOOTER_LEN + VHD_DYNAMIC_HEADER_LEN;
        image[bat_off..bat_off + 4].copy_from_slice(&block0_sector.to_be_bytes());
        image[bat_off + 4..bat_off + 8].copy_from_slice(&VHD_BAT_UNALLOCATED.to_be_bytes());
        image[bat_off + 8..bat_off + 12].copy_from_slice(&block2_sector.to_be_bytes());
        image[bat_off + 12..bat_off + 16].copy_from_slice(&VHD_BAT_UNALLOCATED.to_be_bytes());

        let data0_off: usize = block0_off + VHD_SECTOR_SIZE as usize;
        let data2_off: usize = block2_off + VHD_SECTOR_SIZE as usize;
        let marker0: &[u8] = b"DYN-BLOCK-0";
        let marker2: &[u8] = b"DYN-BLOCK-2";
        image[data0_off..data0_off + marker0.len()].copy_from_slice(marker0);
        image[data2_off..data2_off + marker2.len()].copy_from_slice(marker2);
        image[total - VHD_FOOTER_LEN..].copy_from_slice(&footer);

        let parsed: VhdImage = parse_vhd(&image).expect("parse dynamic");
        let disk: Vec<u8> =
            materialize_logical_disk(&image, &parsed, 1 << 30).expect("materialize dynamic");
        assert_eq!(disk.len(), logical as usize);
        assert_eq!(&disk[0..marker0.len()], marker0);
        let block2_start: usize = 2 * block_size as usize;
        assert_eq!(&disk[block2_start..block2_start + marker2.len()], marker2);
        let block1_start: usize = block_size as usize;
        assert!(
            disk[block1_start..block1_start + 16]
                .iter()
                .all(|&b: &u8| b == 0)
        );
    }
}
