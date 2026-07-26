use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const SECTOR_SIZE: usize = 512;
pub const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
pub const GPT_HEADER_LBA: usize = 1;
pub const MBR_SIGNATURE_OFFSET: usize = 510;
pub const MBR_PARTITION_TABLE_OFFSET: usize = 446;
pub const MBR_SIGNATURE: &[u8; 2] = &[0x55, 0xaa];
pub const MBR_TYPE_GPT_PROTECTIVE: u8 = 0xee;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MbrPartition {
    pub bootable: bool,
    pub partition_type: u8,
    pub start_lba: u32,
    pub sector_count: u32,
    pub start_chs: [u8; 3],
    pub end_chs: [u8; 3],
}

impl MbrPartition {
    #[must_use]
    pub fn byte_range(&self) -> Option<(usize, usize)> {
        let start: usize = usize::try_from(self.start_lba)
            .ok()?
            .checked_mul(SECTOR_SIZE)?;
        let len: usize = usize::try_from(self.sector_count)
            .ok()?
            .checked_mul(SECTOR_SIZE)?;
        let end: usize = start.checked_add(len)?;
        Some((start, end))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MbrTable {
    pub partitions: Vec<MbrPartition>,
    pub is_protective: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GptHeader {
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub header_crc32_valid: bool,
    pub current_lba: u64,
    pub backup_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entry_lba: u64,
    pub partition_entry_count: u32,
    pub partition_entry_size: u32,
    pub partition_entry_array_crc32: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GptPartition {
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub start_lba: u64,
    pub end_lba: u64,
    pub attributes: u64,
    pub name: String,
}

impl GptPartition {
    #[must_use]
    pub fn byte_range(&self) -> Option<(usize, usize)> {
        if self.end_lba < self.start_lba {
            return None;
        }
        let sector_count: u64 = self.end_lba.checked_sub(self.start_lba)?.checked_add(1)?;
        let start: usize = usize::try_from(self.start_lba.checked_mul(SECTOR_SIZE as u64)?).ok()?;
        let len: usize = usize::try_from(sector_count.checked_mul(SECTOR_SIZE as u64)?).ok()?;
        let end: usize = start.checked_add(len)?;
        Some((start, end))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GptTable {
    pub header: GptHeader,
    pub partitions: Vec<GptPartition>,
    pub entries_crc32_valid: bool,
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

pub fn parse_mbr(bytes: &[u8]) -> Result<MbrTable> {
    if bytes.len() < SECTOR_SIZE {
        return Err(Error::Decompression("mbr sector truncated".to_owned()));
    }
    if &bytes[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2] != MBR_SIGNATURE {
        return Err(Error::Decompression(
            "mbr boot signature missing".to_owned(),
        ));
    }
    let mut partitions: Vec<MbrPartition> = Vec::with_capacity(4);
    let mut is_protective: bool = false;
    for index in 0..4usize {
        let entry_off: usize = MBR_PARTITION_TABLE_OFFSET + index * 16;
        let entry: &[u8] = &bytes[entry_off..entry_off + 16];
        let partition_type: u8 = entry[4];
        if partition_type == 0 {
            continue;
        }
        if partition_type == MBR_TYPE_GPT_PROTECTIVE {
            is_protective = true;
        }
        partitions.push(MbrPartition {
            bootable: entry[0] == 0x80,
            partition_type,
            start_chs: [entry[1], entry[2], entry[3]],
            end_chs: [entry[5], entry[6], entry[7]],
            start_lba: read_u32_le(entry, 8),
            sector_count: read_u32_le(entry, 12),
        });
    }
    Ok(MbrTable {
        partitions,
        is_protective,
    })
}

fn gpt_header_crc32(header: &[u8], header_size: u32) -> u32 {
    let span: usize = (header_size as usize).clamp(92, header.len());
    let mut hasher: crc32fast::Hasher = crc32fast::Hasher::new();
    hasher.update(&header[0..16]);
    hasher.update(&[0u8, 0u8, 0u8, 0u8]);
    hasher.update(&header[20..span]);
    hasher.finalize()
}

pub fn parse_gpt_header(bytes: &[u8], header_offset: usize) -> Result<GptHeader> {
    let overflowed = || Error::Decompression("gpt header offset overflow".to_owned());
    let size_field_start: usize = header_offset.checked_add(12).ok_or_else(overflowed)?;
    let size_field_end: usize = header_offset.checked_add(16).ok_or_else(overflowed)?;
    let stored_size: u32 = bytes
        .get(size_field_start..size_field_end)
        .map_or(92, |s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]));
    let span: usize = (stored_size as usize).max(92);
    let span_end: usize = header_offset.checked_add(span).ok_or_else(overflowed)?;
    let minimum_end: usize = header_offset.checked_add(92).ok_or_else(overflowed)?;
    let header: &[u8] = bytes
        .get(header_offset..span_end)
        .or_else(|| bytes.get(header_offset..minimum_end))
        .ok_or_else(|| Error::Decompression("gpt header truncated".to_owned()))?;
    if &header[0..8] != GPT_SIGNATURE {
        return Err(Error::Decompression("gpt signature mismatch".to_owned()));
    }
    let revision: u32 = read_u32_le(header, 8);
    let header_size: u32 = read_u32_le(header, 12);
    let header_crc32: u32 = read_u32_le(header, 16);
    let current_lba: u64 = read_u64_le(header, 24);
    let backup_lba: u64 = read_u64_le(header, 32);
    let first_usable_lba: u64 = read_u64_le(header, 40);
    let last_usable_lba: u64 = read_u64_le(header, 48);
    let mut disk_guid: [u8; 16] = [0u8; 16];
    disk_guid.copy_from_slice(&header[56..72]);
    let partition_entry_lba: u64 = read_u64_le(header, 72);
    let partition_entry_count: u32 = read_u32_le(header, 80);
    let partition_entry_size: u32 = read_u32_le(header, 84);
    let partition_entry_array_crc32: u32 = read_u32_le(header, 88);
    let header_crc32_valid: bool = gpt_header_crc32(header, header_size) == header_crc32;
    Ok(GptHeader {
        revision,
        header_size,
        header_crc32,
        header_crc32_valid,
        current_lba,
        backup_lba,
        first_usable_lba,
        last_usable_lba,
        disk_guid,
        partition_entry_lba,
        partition_entry_count,
        partition_entry_size,
        partition_entry_array_crc32,
    })
}

fn decode_partition_name(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut index: usize = 0;
    while index + 1 < bytes.len() {
        let unit: u16 = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        index += 2;
    }
    String::from_utf16_lossy(&units)
}

pub fn parse_gpt(bytes: &[u8]) -> Result<GptTable> {
    let header_offset: usize = GPT_HEADER_LBA * SECTOR_SIZE;
    let header: GptHeader = parse_gpt_header(bytes, header_offset)?;
    let entry_size: usize = header.partition_entry_size as usize;
    if entry_size < 128 {
        return Err(Error::Decompression(
            "gpt partition entry size too small".to_owned(),
        ));
    }
    let array_offset: usize = usize::try_from(header.partition_entry_lba)
        .ok()
        .and_then(|lba: usize| lba.checked_mul(SECTOR_SIZE))
        .ok_or_else(|| Error::Decompression("gpt entry array offset overflow".to_owned()))?;
    let array_byte_len: usize = (header.partition_entry_count as usize)
        .checked_mul(entry_size)
        .ok_or_else(|| Error::Decompression("gpt entry array length overflow".to_owned()))?;
    let entries_crc32_valid: bool = array_offset
        .checked_add(array_byte_len)
        .and_then(|end: usize| bytes.get(array_offset..end))
        .is_some_and(|array: &[u8]| crc32fast::hash(array) == header.partition_entry_array_crc32);
    let mut partitions: Vec<GptPartition> = Vec::new();
    for index in 0..header.partition_entry_count as usize {
        let entry_off: usize = match array_offset.checked_add(index * entry_size) {
            Some(value) => value,
            None => break,
        };
        let Some(entry): Option<&[u8]> = bytes.get(entry_off..entry_off + 128) else {
            break;
        };
        let mut type_guid: [u8; 16] = [0u8; 16];
        type_guid.copy_from_slice(&entry[0..16]);
        if type_guid == [0u8; 16] {
            continue;
        }
        let mut unique_guid: [u8; 16] = [0u8; 16];
        unique_guid.copy_from_slice(&entry[16..32]);
        let start_lba: u64 = read_u64_le(entry, 32);
        let end_lba: u64 = read_u64_le(entry, 40);
        let attributes: u64 = read_u64_le(entry, 48);
        let name: String = decode_partition_name(&entry[56..128]);
        partitions.push(GptPartition {
            type_guid,
            unique_guid,
            start_lba,
            end_lba,
            attributes,
            name,
        });
    }
    Ok(GptTable {
        header,
        partitions,
        entries_crc32_valid,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn write_mbr_entry(disk: &mut [u8], index: usize, boot: u8, ptype: u8, start: u32, count: u32) {
        let off: usize = MBR_PARTITION_TABLE_OFFSET + index * 16;
        disk[off] = boot;
        disk[off + 4] = ptype;
        disk[off + 8..off + 12].copy_from_slice(&start.to_le_bytes());
        disk[off + 12..off + 16].copy_from_slice(&count.to_le_bytes());
    }

    fn finalize_gpt_crcs(disk: &mut [u8], header_off: usize, array_off: usize, array_len: usize) {
        let array_crc: u32 = crc32fast::hash(&disk[array_off..array_off + array_len]);
        disk[header_off + 88..header_off + 92].copy_from_slice(&array_crc.to_le_bytes());
        disk[header_off + 16..header_off + 20].copy_from_slice(&[0u8; 4]);
        let header_crc: u32 = crc32fast::hash(&disk[header_off..header_off + 92]);
        disk[header_off + 16..header_off + 20].copy_from_slice(&header_crc.to_le_bytes());
    }

    #[test]
    fn parses_classic_mbr() {
        let mut disk: Vec<u8> = vec![0u8; SECTOR_SIZE];
        disk[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2].copy_from_slice(MBR_SIGNATURE);
        write_mbr_entry(&mut disk, 0, 0x80, 0x83, 2048, 204_800);
        write_mbr_entry(&mut disk, 1, 0x00, 0x07, 206_848, 409_600);
        let table: MbrTable = parse_mbr(&disk).expect("parse mbr");
        assert!(!table.is_protective);
        assert_eq!(table.partitions.len(), 2);
        assert!(table.partitions[0].bootable);
        assert_eq!(table.partitions[0].partition_type, 0x83);
        assert_eq!(table.partitions[0].start_lba, 2048);
        assert_eq!(table.partitions[1].sector_count, 409_600);
    }

    #[test]
    fn detects_protective_mbr() {
        let mut disk: Vec<u8> = vec![0u8; SECTOR_SIZE];
        disk[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2].copy_from_slice(MBR_SIGNATURE);
        write_mbr_entry(&mut disk, 0, 0x00, MBR_TYPE_GPT_PROTECTIVE, 1, 0xffff_ffff);
        let table: MbrTable = parse_mbr(&disk).expect("parse protective mbr");
        assert!(table.is_protective);
        assert_eq!(table.partitions.len(), 1);
    }

    #[test]
    fn parses_gpt_with_two_partitions() {
        let mut disk: Vec<u8> = vec![0u8; SECTOR_SIZE * 40];
        disk[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2].copy_from_slice(MBR_SIGNATURE);
        write_mbr_entry(&mut disk, 0, 0x00, MBR_TYPE_GPT_PROTECTIVE, 1, 0xffff_ffff);

        let header_off: usize = SECTOR_SIZE;
        disk[header_off..header_off + 8].copy_from_slice(GPT_SIGNATURE);
        disk[header_off + 8..header_off + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        disk[header_off + 12..header_off + 16].copy_from_slice(&92u32.to_le_bytes());
        disk[header_off + 24..header_off + 32].copy_from_slice(&1u64.to_le_bytes());
        disk[header_off + 72..header_off + 80].copy_from_slice(&2u64.to_le_bytes());
        disk[header_off + 80..header_off + 84].copy_from_slice(&128u32.to_le_bytes());
        disk[header_off + 84..header_off + 88].copy_from_slice(&128u32.to_le_bytes());

        let array_off: usize = SECTOR_SIZE * 2;
        let esp_type: [u8; 16] = [
            0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e,
            0xc9, 0x3b,
        ];
        disk[array_off..array_off + 16].copy_from_slice(&esp_type);
        disk[array_off + 32..array_off + 40].copy_from_slice(&2048u64.to_le_bytes());
        disk[array_off + 40..array_off + 48].copy_from_slice(&206_847u64.to_le_bytes());
        for (i, unit) in "EFI System".encode_utf16().enumerate() {
            let name_off: usize = array_off + 56 + i * 2;
            disk[name_off..name_off + 2].copy_from_slice(&unit.to_le_bytes());
        }

        let entry2: usize = array_off + 128;
        let linux_type: [u8; 16] = [
            0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47,
            0x7d, 0xe4,
        ];
        disk[entry2..entry2 + 16].copy_from_slice(&linux_type);
        disk[entry2 + 32..entry2 + 40].copy_from_slice(&206_848u64.to_le_bytes());
        disk[entry2 + 40..entry2 + 48].copy_from_slice(&999_999u64.to_le_bytes());
        for (i, unit) in "Linux".encode_utf16().enumerate() {
            let name_off: usize = entry2 + 56 + i * 2;
            disk[name_off..name_off + 2].copy_from_slice(&unit.to_le_bytes());
        }

        finalize_gpt_crcs(&mut disk, header_off, array_off, 128 * 128);

        let table: GptTable = parse_gpt(&disk).expect("parse gpt");
        assert_eq!(table.header.partition_entry_count, 128);
        assert_eq!(table.header.partition_entry_size, 128);
        assert!(
            table.header.header_crc32_valid,
            "spec-correct gpt header crc32 must validate"
        );
        assert!(
            table.entries_crc32_valid,
            "spec-correct gpt entry-array crc32 must validate"
        );
        assert_eq!(table.partitions.len(), 2);
        assert_eq!(table.partitions[0].name, "EFI System");
        assert_eq!(table.partitions[0].start_lba, 2048);
        assert_eq!(table.partitions[0].type_guid, esp_type);
        assert_eq!(
            table.partitions[0].byte_range(),
            Some((2048 * 512, 206_848 * 512))
        );
        assert_eq!(table.partitions[1].name, "Linux");
        assert_eq!(table.partitions[1].start_lba, 206_848);
    }

    #[test]
    fn gpt_corrupt_header_crc_flagged_invalid() {
        let mut disk: Vec<u8> = vec![0u8; SECTOR_SIZE * 40];
        let header_off: usize = SECTOR_SIZE;
        disk[header_off..header_off + 8].copy_from_slice(GPT_SIGNATURE);
        disk[header_off + 12..header_off + 16].copy_from_slice(&92u32.to_le_bytes());
        disk[header_off + 72..header_off + 80].copy_from_slice(&2u64.to_le_bytes());
        disk[header_off + 80..header_off + 84].copy_from_slice(&128u32.to_le_bytes());
        disk[header_off + 84..header_off + 88].copy_from_slice(&128u32.to_le_bytes());
        let array_off: usize = SECTOR_SIZE * 2;
        disk[array_off..array_off + 16].copy_from_slice(&[0x11u8; 16]);
        disk[array_off + 32..array_off + 40].copy_from_slice(&34u64.to_le_bytes());
        disk[array_off + 40..array_off + 48].copy_from_slice(&100u64.to_le_bytes());
        finalize_gpt_crcs(&mut disk, header_off, array_off, 128 * 128);
        disk[header_off + 16] ^= 0xff;
        let table: GptTable = parse_gpt(&disk).expect("parse gpt");
        assert!(!table.header.header_crc32_valid);
        assert!(table.entries_crc32_valid);
    }

    #[test]
    fn mbr_partition_byte_range_is_sector_scaled() {
        let part: MbrPartition = MbrPartition {
            bootable: true,
            partition_type: 0x83,
            start_lba: 2048,
            sector_count: 204_800,
            start_chs: [0; 3],
            end_chs: [0; 3],
        };
        assert_eq!(
            part.byte_range(),
            Some((2048 * 512, (2048 + 204_800) * 512))
        );
    }

    #[test]
    fn rejects_non_gpt() {
        let disk: Vec<u8> = vec![0u8; SECTOR_SIZE * 4];
        assert!(parse_gpt(&disk).is_err());
    }
}
