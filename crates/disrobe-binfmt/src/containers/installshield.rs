use std::collections::BTreeSet;
use std::fmt::Write as _;

use disrobe_bytes::{ByteReader, CStrOptions, read_cstr_at};
use flate2::{Decompress, FlushDecompress, Status};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::quota::{ExtractionQuota, QuotaGuard, QuotaReport};

const ISC_SIGNATURE: u32 = 0x2863_5349;
const COMMON_HEADER_LEN: usize = 20;
const VOLUME_HEADER_LEN_LEGACY: usize = 40;
const VOLUME_HEADER_LEN_MODERN: usize = 64;
const CAB_DESCRIPTOR_FIXED_LEN: usize = 0x30;
const CAB_DESCRIPTOR_TABLE_LEN: u32 = 0x276;
const LEGACY_DESCRIPTOR_LEN_V0: usize = 0x2A;
const LEGACY_DESCRIPTOR_LEN_V5: usize = 0x3A;
const MODERN_DESCRIPTOR_LEN: usize = 0x57;

const FILE_SPLIT: u16 = 0x0001;
const FILE_OBFUSCATED: u16 = 0x0002;
const FILE_COMPRESSED: u16 = 0x0004;
const FILE_INVALID: u16 = 0x0008;

const END_OF_CHUNK: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];
const CHUNK_OUTPUT_LIMIT: usize = 64 * 1024;
const OBFUSCATION_MODULUS: u32 = 0x47;
const OBFUSCATION_XOR: u8 = 0xD5;

const MAX_TABLE_ENTRIES: usize = 1_000_000;
const MAX_NAME_BYTES: usize = 4096;
const FILE_GROUP_SLOTS: usize = 71;
const FILE_GROUP_TABLE_OFFSET: usize = 0x3E;
const OFFSET_LIST_LEN: usize = 12;
const GROUP_RANGE_SKIP_LEGACY: usize = 0x48;
const GROUP_RANGE_SKIP_MODERN: usize = 0x12;
const MAX_FILE_GROUPS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstallShieldLayout {
    Legacy,
    Modern,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstallShieldCompression {
    Stored,
    FramedDeflate,
    FullFlushDeflate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstallShieldMemberState {
    Recovered,
    RefusedInvalidRecord,
    RefusedSplitMember,
    RefusedAbsentVolume,
    RefusedDataOutOfRange,
    RefusedAmbiguousFraming,
    RefusedDecode,
    RefusedIntegrity,
    RefusedQuota,
    RefusedDuplicatePath,
}

impl InstallShieldMemberState {
    #[must_use]
    pub const fn is_recovered(self) -> bool {
        matches!(self, Self::Recovered)
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Recovered => "recovered",
            Self::RefusedInvalidRecord => "invalid-record",
            Self::RefusedSplitMember => "split-member",
            Self::RefusedAbsentVolume => "absent-volume",
            Self::RefusedDataOutOfRange => "data-out-of-range",
            Self::RefusedAmbiguousFraming => "ambiguous-framing",
            Self::RefusedDecode => "decode-failed",
            Self::RefusedIntegrity => "integrity-mismatch",
            Self::RefusedQuota => "quota-exceeded",
            Self::RefusedDuplicatePath => "duplicate-path",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallShieldHeader {
    pub version: u32,
    pub major_version: u32,
    pub layout: InstallShieldLayout,
    pub volume_info: u32,
    pub cab_descriptor_offset: u32,
    pub cab_descriptor_size: u32,
    pub file_table_offset: u32,
    pub file_table_size: u32,
    pub file_table_size2: u32,
    pub file_table_offset2: u32,
    pub directory_count: u32,
    pub file_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallShieldVolume {
    pub data_offset: u64,
    pub first_file_index: u32,
    pub last_file_index: u32,
    pub first_file_offset: u64,
    pub first_file_size_expanded: u64,
    pub first_file_size_compressed: u64,
    pub last_file_offset: u64,
    pub last_file_size_expanded: u64,
    pub last_file_size_compressed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallShieldFile {
    pub index: u32,
    pub name: String,
    pub name_bytes: Vec<u8>,
    pub directory: String,
    pub directory_index: u32,
    pub file_group: String,
    pub path: String,
    pub data: Vec<u8>,
    pub compressed: bool,
    pub obfuscated: bool,
    pub compression: InstallShieldCompression,
    pub compressed_size: u64,
    pub expanded_size: u64,
    pub declared_volume: u32,
    pub state: InstallShieldMemberState,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct InstallShieldArchive {
    pub header: InstallShieldHeader,
    pub volume: InstallShieldVolume,
    pub directories: Vec<String>,
    pub file_groups: Vec<InstallShieldFileGroup>,
    pub files: Vec<InstallShieldFile>,
    pub integrity_violations: Vec<String>,
    pub quota: QuotaReport,
}

impl InstallShieldArchive {
    pub fn recovered(&self) -> impl Iterator<Item = &InstallShieldFile> {
        self.files
            .iter()
            .filter(|file: &&InstallShieldFile| file.state.is_recovered())
    }

    #[must_use]
    pub fn recovered_count(&self) -> usize {
        self.recovered().count()
    }
}

#[derive(Debug, Clone, Copy)]
struct RawDescriptor {
    name_offset: u32,
    directory_index: u32,
    flags: u16,
    expanded_size: u64,
    compressed_size: u64,
    data_offset: u64,
    md5: [u8; 16],
    volume: u32,
}

#[must_use]
pub const fn installshield_major_version(version: u32) -> u32 {
    match version >> 24 {
        1 => (version >> 12) & 0xF,
        2 | 4 => {
            let encoded: u32 = version & 0xFFFF;
            if encoded == 0 { 0 } else { encoded / 100 }
        }
        _ => 0,
    }
}

#[must_use]
pub const fn installshield_layout(major_version: u32) -> InstallShieldLayout {
    if major_version <= 5 {
        InstallShieldLayout::Legacy
    } else {
        InstallShieldLayout::Modern
    }
}

pub fn detect_installshield(bytes: &[u8]) -> Option<InstallShieldHeader> {
    parse_installshield_header(bytes).ok()
}

pub fn parse_installshield_header(bytes: &[u8]) -> Result<InstallShieldHeader> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let signature: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("common header"))?;
    if signature != ISC_SIGNATURE {
        return Err(is_err(
            "input does not carry the InstallShield `ISc(` signature",
        ));
    }
    let version: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("common header"))?;
    let volume_info: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("common header"))?;
    let cab_descriptor_offset: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("common header"))?;
    let cab_descriptor_size: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("common header"))?;
    if cab_descriptor_size == 0 {
        return Err(is_err(
            "cabinet declares no descriptor; header-only volume carries no member table",
        ));
    }
    let major_version: u32 = installshield_major_version(version);
    let layout: InstallShieldLayout = installshield_layout(major_version);
    let volume_header_len: usize = match layout {
        InstallShieldLayout::Legacy => VOLUME_HEADER_LEN_LEGACY,
        InstallShieldLayout::Modern => VOLUME_HEADER_LEN_MODERN,
    };
    if bytes.len() < COMMON_HEADER_LEN.saturating_add(volume_header_len) {
        return Err(truncated("volume header"));
    }
    let descriptor_base: usize = usize::try_from(cab_descriptor_offset)
        .map_err(|_| is_err("cabinet descriptor offset exceeds address space"))?;
    let descriptor_len: usize = usize::try_from(cab_descriptor_size)
        .map_err(|_| is_err("cabinet descriptor size exceeds address space"))?;
    if descriptor_len < CAB_DESCRIPTOR_FIXED_LEN {
        return Err(is_err(
            "cabinet descriptor is shorter than the 0x30-byte fixed prefix",
        ));
    }
    let descriptor_end: usize = descriptor_base
        .checked_add(descriptor_len)
        .ok_or_else(|| is_err("cabinet descriptor extent overflows"))?;
    if descriptor_end > bytes.len() {
        return Err(truncated("cabinet descriptor"));
    }
    let mut descriptor: ByteReader<'_> = ByteReader::new(bytes);
    descriptor
        .seek(descriptor_base.saturating_add(0x0C))
        .map_err(|_| truncated("cabinet descriptor"))?;
    let file_table_offset: u32 = descriptor
        .read_u32_le()
        .map_err(|_| truncated("cabinet descriptor"))?;
    descriptor
        .skip(4)
        .map_err(|_| truncated("cabinet descriptor"))?;
    let file_table_size: u32 = descriptor
        .read_u32_le()
        .map_err(|_| truncated("cabinet descriptor"))?;
    let file_table_size2: u32 = descriptor
        .read_u32_le()
        .map_err(|_| truncated("cabinet descriptor"))?;
    let directory_count: u32 = descriptor
        .read_u32_le()
        .map_err(|_| truncated("cabinet descriptor"))?;
    descriptor
        .skip(8)
        .map_err(|_| truncated("cabinet descriptor"))?;
    let file_count: u32 = descriptor
        .read_u32_le()
        .map_err(|_| truncated("cabinet descriptor"))?;
    let file_table_offset2: u32 = descriptor
        .read_u32_le()
        .map_err(|_| truncated("cabinet descriptor"))?;
    Ok(InstallShieldHeader {
        version,
        major_version,
        layout,
        volume_info,
        cab_descriptor_offset,
        cab_descriptor_size,
        file_table_offset,
        file_table_size,
        file_table_size2,
        file_table_offset2,
        directory_count,
        file_count,
    })
}

fn parse_volume(bytes: &[u8], layout: InstallShieldLayout) -> Result<InstallShieldVolume> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(COMMON_HEADER_LEN)
        .map_err(|_| truncated("volume header"))?;
    match layout {
        InstallShieldLayout::Legacy => {
            let data_offset: u32 = reader
                .read_u32_le()
                .map_err(|_| truncated("volume header"))?;
            reader.skip(4).map_err(|_| truncated("volume header"))?;
            let first_file_index: u32 = reader
                .read_u32_le()
                .map_err(|_| truncated("volume header"))?;
            let last_file_index: u32 = reader
                .read_u32_le()
                .map_err(|_| truncated("volume header"))?;
            let first_file_offset: u32 = reader
                .read_u32_le()
                .map_err(|_| truncated("volume header"))?;
            let first_file_size_expanded: u32 = reader
                .read_u32_le()
                .map_err(|_| truncated("volume header"))?;
            let first_file_size_compressed: u32 = reader
                .read_u32_le()
                .map_err(|_| truncated("volume header"))?;
            let last_file_offset: u32 = reader
                .read_u32_le()
                .map_err(|_| truncated("volume header"))?;
            let last_file_size_expanded: u32 = reader
                .read_u32_le()
                .map_err(|_| truncated("volume header"))?;
            let last_file_size_compressed: u32 = reader
                .read_u32_le()
                .map_err(|_| truncated("volume header"))?;
            Ok(InstallShieldVolume {
                data_offset: u64::from(data_offset),
                first_file_index,
                last_file_index,
                first_file_offset: u64::from(first_file_offset),
                first_file_size_expanded: u64::from(first_file_size_expanded),
                first_file_size_compressed: u64::from(first_file_size_compressed),
                last_file_offset: u64::from(last_file_offset),
                last_file_size_expanded: u64::from(last_file_size_expanded),
                last_file_size_compressed: u64::from(last_file_size_compressed),
            })
        }
        InstallShieldLayout::Modern => {
            let data_offset: u64 = read_split_u64(&mut reader)?;
            let first_file_index: u32 = reader
                .read_u32_le()
                .map_err(|_| truncated("volume header"))?;
            let last_file_index: u32 = reader
                .read_u32_le()
                .map_err(|_| truncated("volume header"))?;
            let first_file_offset: u64 = read_split_u64(&mut reader)?;
            let first_file_size_expanded: u64 = read_split_u64(&mut reader)?;
            let first_file_size_compressed: u64 = read_split_u64(&mut reader)?;
            let last_file_offset: u64 = read_split_u64(&mut reader)?;
            let last_file_size_expanded: u64 = read_split_u64(&mut reader)?;
            let last_file_size_compressed: u64 = read_split_u64(&mut reader)?;
            Ok(InstallShieldVolume {
                data_offset,
                first_file_index,
                last_file_index,
                first_file_offset,
                first_file_size_expanded,
                first_file_size_compressed,
                last_file_offset,
                last_file_size_expanded,
                last_file_size_compressed,
            })
        }
    }
}

fn read_split_u64(reader: &mut ByteReader<'_>) -> Result<u64> {
    let low: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("volume header"))?;
    let high: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("volume header"))?;
    Ok(u64::from(low) | (u64::from(high) << 32))
}

fn read_file_table(bytes: &[u8], header: &InstallShieldHeader) -> Result<Vec<u32>> {
    let entries: usize = usize::try_from(header.directory_count)
        .ok()
        .and_then(|dirs: usize| {
            usize::try_from(header.file_count)
                .ok()
                .and_then(|files: usize| dirs.checked_add(files))
        })
        .ok_or_else(|| is_err("directory and file counts overflow the table length"))?;
    if entries > MAX_TABLE_ENTRIES {
        return Err(Error::InstallShield(format!(
            "file table declares {entries} entries above the {MAX_TABLE_ENTRIES} ceiling"
        )));
    }
    let table_base: usize = table_base(header)?;
    let table_bytes: usize = entries
        .checked_mul(4)
        .ok_or_else(|| is_err("file table length overflows"))?;
    let table_end: usize = table_base
        .checked_add(table_bytes)
        .ok_or_else(|| is_err("file table extent overflows"))?;
    if table_end > bytes.len() {
        return Err(truncated("file table"));
    }
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(table_base)
        .map_err(|_| truncated("file table"))?;
    let mut table: Vec<u32> = Vec::with_capacity(entries);
    for _ in 0..entries {
        table.push(reader.read_u32_le().map_err(|_| truncated("file table"))?);
    }
    Ok(table)
}

fn table_base(header: &InstallShieldHeader) -> Result<usize> {
    let descriptor_base: usize = usize::try_from(header.cab_descriptor_offset)
        .map_err(|_| is_err("cabinet descriptor offset exceeds address space"))?;
    let table_offset: usize = usize::try_from(header.file_table_offset)
        .map_err(|_| is_err("file table offset exceeds address space"))?;
    descriptor_base
        .checked_add(table_offset)
        .ok_or_else(|| is_err("file table base overflows"))
}

fn read_name(bytes: &[u8], base: usize, offset: u32) -> Result<Vec<u8>> {
    let relative: usize =
        usize::try_from(offset).map_err(|_| is_err("string offset exceeds address space"))?;
    let at: usize = base
        .checked_add(relative)
        .ok_or_else(|| is_err("string offset overflows"))?;
    let raw: &[u8] = read_cstr_at(bytes, at, CStrOptions::terminated(MAX_NAME_BYTES))
        .map_err(|_| is_err("string is unterminated or out of range"))?;
    Ok(raw.to_vec())
}

#[must_use]
pub fn installshield_display_name(raw: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(raw) {
        return text.to_owned();
    }
    let mut out: String = String::with_capacity(raw.len());
    for byte in raw {
        if byte.is_ascii() && *byte != b'%' {
            out.push(char::from(*byte));
        } else {
            let _: std::fmt::Result = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallShieldFileGroup {
    pub name: String,
    pub first_file: i32,
    pub last_file: i32,
}

fn read_file_groups(
    bytes: &[u8],
    header: &InstallShieldHeader,
    violations: &mut Vec<String>,
) -> Vec<InstallShieldFileGroup> {
    let Ok(descriptor_base): Result<usize> = usize::try_from(header.cab_descriptor_offset)
        .map_err(|_| is_err("cabinet descriptor offset exceeds address space"))
    else {
        return Vec::new();
    };
    let mut groups: Vec<InstallShieldFileGroup> = Vec::new();
    let mut visited: BTreeSet<u32> = BTreeSet::new();
    for slot in 0..FILE_GROUP_SLOTS {
        let slot_at: usize = match descriptor_base
            .checked_add(FILE_GROUP_TABLE_OFFSET)
            .and_then(|value: usize| value.checked_add(slot.saturating_mul(4)))
        {
            Some(value) => value,
            None => break,
        };
        let Ok(head) = disrobe_bytes::read_u32_le_at(bytes, slot_at) else {
            violations.push(
                "installshield-file-group-table: group offset table lies outside the input"
                    .to_owned(),
            );
            break;
        };
        let mut next: u32 = head;
        while next != 0 && groups.len() < MAX_FILE_GROUPS {
            if !visited.insert(next) {
                violations.push(format!(
                    "installshield-file-group-cycle: offset {next:#010x} repeats in the group chain"
                ));
                break;
            }
            let Some(list_at): Option<usize> = usize::try_from(next)
                .ok()
                .and_then(|offset: usize| descriptor_base.checked_add(offset))
            else {
                break;
            };
            if list_at.saturating_add(OFFSET_LIST_LEN) > bytes.len() {
                violations.push(
                    "installshield-file-group-list: chain node lies outside the input".to_owned(),
                );
                break;
            }
            let Ok(descriptor_offset) = disrobe_bytes::read_u32_le_at(bytes, list_at + 4) else {
                break;
            };
            let Ok(next_offset) = disrobe_bytes::read_u32_le_at(bytes, list_at + 8) else {
                break;
            };
            match read_file_group(bytes, header, descriptor_base, descriptor_offset) {
                Ok(group) => groups.push(group),
                Err(error) => violations.push(format!("installshield-file-group: {error}")),
            }
            next = next_offset;
        }
    }
    groups
}

fn read_file_group(
    bytes: &[u8],
    header: &InstallShieldHeader,
    descriptor_base: usize,
    descriptor_offset: u32,
) -> Result<InstallShieldFileGroup> {
    let at: usize = usize::try_from(descriptor_offset)
        .ok()
        .and_then(|offset: usize| descriptor_base.checked_add(offset))
        .ok_or_else(|| is_err("file group descriptor offset overflows"))?;
    let skip: usize = match header.layout {
        InstallShieldLayout::Legacy => GROUP_RANGE_SKIP_LEGACY,
        InstallShieldLayout::Modern => GROUP_RANGE_SKIP_MODERN,
    };
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(at)
        .map_err(|_| truncated("file group descriptor"))?;
    let name_offset: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("file group descriptor"))?;
    reader
        .skip(skip)
        .map_err(|_| truncated("file group descriptor"))?;
    let first_file: i32 = reader
        .read_i32_le()
        .map_err(|_| truncated("file group descriptor"))?;
    let last_file: i32 = reader
        .read_i32_le()
        .map_err(|_| truncated("file group descriptor"))?;
    let raw: Vec<u8> = read_name(bytes, descriptor_base, name_offset)?;
    Ok(InstallShieldFileGroup {
        name: installshield_display_name(&raw),
        first_file,
        last_file,
    })
}

fn map_group_names(groups: &[InstallShieldFileGroup], file_count: usize) -> Vec<String> {
    let mut mapped: Vec<String> = vec![String::new(); file_count];
    let mut claimed: Vec<bool> = vec![false; file_count];
    for group in groups {
        if group.first_file < 0 || group.last_file < group.first_file {
            continue;
        }
        let first: usize = usize::try_from(group.first_file).unwrap_or(usize::MAX);
        let last: usize = usize::try_from(group.last_file).unwrap_or(usize::MAX);
        for index in first..=last.min(file_count.saturating_sub(1)) {
            if index >= file_count {
                break;
            }
            if !claimed[index] {
                claimed[index] = true;
                group.name.clone_into(&mut mapped[index]);
            }
        }
    }
    mapped
}

fn parse_descriptor(
    bytes: &[u8],
    header: &InstallShieldHeader,
    table: &[u32],
    index: usize,
) -> Result<RawDescriptor> {
    match header.layout {
        InstallShieldLayout::Legacy => parse_legacy_descriptor(bytes, header, table, index),
        InstallShieldLayout::Modern => parse_modern_descriptor(bytes, header, index),
    }
}

fn parse_legacy_descriptor(
    bytes: &[u8],
    header: &InstallShieldHeader,
    table: &[u32],
    index: usize,
) -> Result<RawDescriptor> {
    let directories: usize = usize::try_from(header.directory_count)
        .map_err(|_| is_err("directory count exceeds address space"))?;
    let slot: usize = directories
        .checked_add(index)
        .ok_or_else(|| is_err("descriptor slot overflows"))?;
    let relative: u32 = *table
        .get(slot)
        .ok_or_else(|| is_err("descriptor slot is outside the file table"))?;
    let base: usize = table_base(header)?;
    let at: usize = usize::try_from(relative)
        .ok()
        .and_then(|offset: usize| base.checked_add(offset))
        .ok_or_else(|| is_err("descriptor offset overflows"))?;
    let record_len: usize = if header.major_version == 5 {
        LEGACY_DESCRIPTOR_LEN_V5
    } else {
        LEGACY_DESCRIPTOR_LEN_V0
    };
    let end: usize = at
        .checked_add(record_len)
        .ok_or_else(|| is_err("descriptor extent overflows"))?;
    if end > bytes.len() {
        return Err(truncated("file descriptor"));
    }
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(at).map_err(|_| truncated("file descriptor"))?;
    let name_offset: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("file descriptor"))?;
    let directory_index: u16 = reader
        .read_u16_le()
        .map_err(|_| truncated("file descriptor"))?;
    reader.skip(2).map_err(|_| truncated("file descriptor"))?;
    let flags: u16 = reader
        .read_u16_le()
        .map_err(|_| truncated("file descriptor"))?;
    let expanded_size: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("file descriptor"))?;
    let compressed_size: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("file descriptor"))?;
    reader
        .skip(0x14)
        .map_err(|_| truncated("file descriptor"))?;
    let data_offset: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("file descriptor"))?;
    let mut md5: [u8; 16] = [0u8; 16];
    if header.major_version == 5 {
        let raw: &[u8] = reader
            .read_bytes(16)
            .map_err(|_| truncated("file descriptor"))?;
        md5.copy_from_slice(raw);
    }
    Ok(RawDescriptor {
        name_offset,
        directory_index: u32::from(directory_index),
        flags,
        expanded_size: u64::from(expanded_size),
        compressed_size: u64::from(compressed_size),
        data_offset: u64::from(data_offset),
        md5,
        volume: 1,
    })
}

fn parse_modern_descriptor(
    bytes: &[u8],
    header: &InstallShieldHeader,
    index: usize,
) -> Result<RawDescriptor> {
    let base: usize = table_base(header)?;
    let secondary: usize = usize::try_from(header.file_table_offset2)
        .map_err(|_| is_err("secondary file table offset exceeds address space"))?;
    let stride: usize = index
        .checked_mul(MODERN_DESCRIPTOR_LEN)
        .ok_or_else(|| is_err("descriptor stride overflows"))?;
    let at: usize = base
        .checked_add(secondary)
        .and_then(|value: usize| value.checked_add(stride))
        .ok_or_else(|| is_err("descriptor offset overflows"))?;
    let end: usize = at
        .checked_add(MODERN_DESCRIPTOR_LEN)
        .ok_or_else(|| is_err("descriptor extent overflows"))?;
    if end > bytes.len() {
        return Err(truncated("file descriptor"));
    }
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(at).map_err(|_| truncated("file descriptor"))?;
    let flags: u16 = reader
        .read_u16_le()
        .map_err(|_| truncated("file descriptor"))?;
    let expanded_size: u64 = reader
        .read_u64_le()
        .map_err(|_| truncated("file descriptor"))?;
    let compressed_size: u64 = reader
        .read_u64_le()
        .map_err(|_| truncated("file descriptor"))?;
    let data_offset: u64 = reader
        .read_u64_le()
        .map_err(|_| truncated("file descriptor"))?;
    let mut md5: [u8; 16] = [0u8; 16];
    let raw: &[u8] = reader
        .read_bytes(16)
        .map_err(|_| truncated("file descriptor"))?;
    md5.copy_from_slice(raw);
    reader.skip(16).map_err(|_| truncated("file descriptor"))?;
    let name_offset: u32 = reader
        .read_u32_le()
        .map_err(|_| truncated("file descriptor"))?;
    let directory_index: u16 = reader
        .read_u16_le()
        .map_err(|_| truncated("file descriptor"))?;
    reader
        .skip(0x0C)
        .map_err(|_| truncated("file descriptor"))?;
    reader.skip(8).map_err(|_| truncated("file descriptor"))?;
    reader.skip(1).map_err(|_| truncated("file descriptor"))?;
    let volume: u16 = reader
        .read_u16_le()
        .map_err(|_| truncated("file descriptor"))?;
    Ok(RawDescriptor {
        name_offset,
        directory_index: u32::from(directory_index),
        flags,
        expanded_size,
        compressed_size,
        data_offset,
        md5,
        volume: u32::from(volume),
    })
}

pub fn deobfuscate_installshield(buffer: &mut [u8], seed: u32) -> u32 {
    let mut running: u32 = seed;
    for byte in buffer.iter_mut() {
        let mixed: u8 = (*byte ^ OBFUSCATION_XOR).rotate_right(2);
        let subtrahend: u8 = u8::try_from(running % OBFUSCATION_MODULUS).unwrap_or(0);
        *byte = mixed.wrapping_sub(subtrahend);
        running = running.wrapping_add(1);
    }
    running
}

#[cfg(test)]
pub(crate) fn obfuscate_installshield(buffer: &mut [u8], seed: u32) -> u32 {
    let mut running: u32 = seed;
    for byte in buffer.iter_mut() {
        let subtrahend: u8 = u8::try_from(running % OBFUSCATION_MODULUS).unwrap_or(0);
        *byte = byte.wrapping_add(subtrahend).rotate_left(2) ^ OBFUSCATION_XOR;
        running = running.wrapping_add(1);
    }
    running
}

fn inflate_terminated_chunk(input: &[u8], scratch: &mut [u8]) -> Result<usize> {
    let mut padded: Vec<u8> = Vec::with_capacity(input.len().saturating_add(1));
    padded.extend_from_slice(input);
    padded.push(0);
    let mut decoder: Decompress = Decompress::new(false);
    let status: Status = decoder
        .decompress(&padded, scratch, FlushDecompress::Finish)
        .map_err(|error: flate2::DecompressError| {
            Error::InstallShield(format!("framed chunk inflate failed: {error}"))
        })?;
    if status != Status::StreamEnd {
        return Err(is_err(
            "framed chunk does not terminate within the 64 KiB chunk output limit",
        ));
    }
    let consumed: usize = usize::try_from(decoder.total_in())
        .map_err(|_| is_err("framed chunk consumed length exceeds address space"))?;
    if consumed < input.len() {
        return Err(Error::InstallShield(format!(
            "framed chunk left {} of {} compressed bytes unconsumed",
            input.len().saturating_sub(consumed),
            input.len()
        )));
    }
    usize::try_from(decoder.total_out())
        .map_err(|_| is_err("framed chunk output length exceeds address space"))
}

fn inflate_flush_chunk(input: &[u8], scratch: &mut [u8]) -> Result<usize> {
    let mut padded: Vec<u8> = Vec::with_capacity(input.len().saturating_add(1));
    padded.extend_from_slice(input);
    padded.push(0);
    let mut decoder: Decompress = Decompress::new(false);
    let status: Status = decoder
        .decompress(&padded, scratch, FlushDecompress::None)
        .map_err(|error: flate2::DecompressError| {
            Error::InstallShield(format!("full-flush chunk inflate failed: {error}"))
        })?;
    if status == Status::BufError {
        return Err(is_err("full-flush chunk made no decode progress"));
    }
    let consumed: usize = usize::try_from(decoder.total_in())
        .map_err(|_| is_err("full-flush chunk consumed length exceeds address space"))?;
    if consumed < input.len() {
        return Err(Error::InstallShield(format!(
            "full-flush chunk left {} of {} compressed bytes unconsumed within the 64 KiB output limit",
            input.len().saturating_sub(consumed),
            input.len()
        )));
    }
    usize::try_from(decoder.total_out())
        .map_err(|_| is_err("full-flush chunk output length exceeds address space"))
}

fn decode_framed_deflate(region: &[u8], expanded_size: usize) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(expanded_size.min(CHUNK_OUTPUT_LIMIT));
    let mut scratch: Vec<u8> = vec![0u8; CHUNK_OUTPUT_LIMIT];
    let mut cursor: usize = 0;
    while cursor < region.len() {
        let remaining: usize = region.len().saturating_sub(cursor);
        if remaining < 2 {
            return Err(is_err("framed stream ends inside a chunk length prefix"));
        }
        let length_bytes: &[u8] = region
            .get(cursor..cursor.saturating_add(2))
            .ok_or_else(|| is_err("framed stream chunk length is out of range"))?;
        let chunk_len: usize = usize::from(u16::from_le_bytes([
            *length_bytes.first().unwrap_or(&0),
            *length_bytes.get(1).unwrap_or(&0),
        ]));
        if chunk_len == 0 {
            return Err(is_err("framed stream declares a zero-length chunk"));
        }
        let chunk_start: usize = cursor.saturating_add(2);
        let chunk_end: usize = chunk_start
            .checked_add(chunk_len)
            .ok_or_else(|| is_err("framed chunk extent overflows"))?;
        if chunk_end > region.len() {
            return Err(is_err("framed chunk extends past the declared member data"));
        }
        let chunk: &[u8] = region
            .get(chunk_start..chunk_end)
            .ok_or_else(|| is_err("framed chunk is out of range"))?;
        let produced: usize = inflate_terminated_chunk(chunk, &mut scratch)?;
        let decoded: &[u8] = scratch
            .get(..produced)
            .ok_or_else(|| is_err("framed chunk output is out of range"))?;
        if out.len().saturating_add(produced) > expanded_size {
            return Err(is_err(
                "framed stream output exceeds the declared file size",
            ));
        }
        out.extend_from_slice(decoded);
        cursor = chunk_end;
    }
    Ok(out)
}

fn decode_full_flush_deflate(region: &[u8], expanded_size: usize) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(expanded_size.min(CHUNK_OUTPUT_LIMIT));
    let mut scratch: Vec<u8> = vec![0u8; CHUNK_OUTPUT_LIMIT];
    let mut cursor: usize = 0;
    while cursor < region.len() && out.len() < expanded_size {
        let window: &[u8] = region
            .get(cursor..)
            .ok_or_else(|| is_err("full-flush window is out of range"))?;
        let mut chunk_len: usize = find_end_of_chunk(window)
            .ok_or_else(|| is_err("full-flush stream has no end-of-chunk marker"))?;
        while chunk_len.saturating_add(END_OF_CHUNK.len()) < window.len()
            && window
                .get(chunk_len.saturating_add(END_OF_CHUNK.len()))
                .is_some_and(|byte: &u8| byte & 1 == 1)
        {
            let resume: usize = chunk_len.saturating_add(END_OF_CHUNK.len());
            let tail: &[u8] = window
                .get(resume..)
                .ok_or_else(|| is_err("full-flush window is out of range"))?;
            let next: usize = find_end_of_chunk(tail)
                .ok_or_else(|| is_err("full-flush stream has no end-of-chunk marker"))?;
            chunk_len = resume.saturating_add(next);
        }
        let chunk: &[u8] = window
            .get(..chunk_len)
            .ok_or_else(|| is_err("full-flush chunk is out of range"))?;
        let produced: usize = inflate_flush_chunk(chunk, &mut scratch)?;
        let decoded: &[u8] = scratch
            .get(..produced)
            .ok_or_else(|| is_err("full-flush chunk output is out of range"))?;
        if out.len().saturating_add(produced) > expanded_size {
            return Err(is_err(
                "full-flush stream output exceeds the declared file size",
            ));
        }
        out.extend_from_slice(decoded);
        cursor = cursor
            .saturating_add(chunk_len)
            .saturating_add(END_OF_CHUNK.len());
    }
    Ok(out)
}

fn find_end_of_chunk(window: &[u8]) -> Option<usize> {
    window
        .windows(END_OF_CHUNK.len())
        .position(|candidate: &[u8]| candidate == END_OF_CHUNK)
}

#[derive(Debug)]
struct DecodedMember {
    data: Vec<u8>,
    compression: InstallShieldCompression,
}

fn decode_member(region: &[u8], descriptor: &RawDescriptor) -> Result<DecodedMember> {
    let expanded_size: usize = usize::try_from(descriptor.expanded_size)
        .map_err(|_| is_err("declared expanded size exceeds address space"))?;
    if descriptor.flags & FILE_COMPRESSED == 0 {
        if region.len() != expanded_size {
            return Err(is_err(
                "stored member data extent does not match the declared expanded size",
            ));
        }
        return Ok(DecodedMember {
            data: region.to_vec(),
            compression: InstallShieldCompression::Stored,
        });
    }
    let framed: Result<Vec<u8>> = decode_framed_deflate(region, expanded_size)
        .and_then(|data: Vec<u8>| exact_length(data, expanded_size));
    let flushed: Result<Vec<u8>> = decode_full_flush_deflate(region, expanded_size)
        .and_then(|data: Vec<u8>| exact_length(data, expanded_size));
    resolve_framing(framed, flushed)
}

const AMBIGUOUS_FRAMING: &str =
    "compressed member decodes to different bytes under framed and full-flush interpretations";

fn resolve_framing(framed: Result<Vec<u8>>, flushed: Result<Vec<u8>>) -> Result<DecodedMember> {
    match (framed, flushed) {
        (Ok(a), Ok(b)) => {
            if a == b {
                Ok(DecodedMember {
                    data: a,
                    compression: InstallShieldCompression::FramedDeflate,
                })
            } else {
                Err(Error::InstallShield(AMBIGUOUS_FRAMING.to_owned()))
            }
        }
        (Ok(a), Err(_)) => Ok(DecodedMember {
            data: a,
            compression: InstallShieldCompression::FramedDeflate,
        }),
        (Err(_), Ok(b)) => Ok(DecodedMember {
            data: b,
            compression: InstallShieldCompression::FullFlushDeflate,
        }),
        (Err(framed_error), Err(flush_error)) => Err(Error::InstallShield(format!(
            "compressed member decodes under neither representation; framed: {framed_error}; full-flush: {flush_error}"
        ))),
    }
}

fn exact_length(data: Vec<u8>, expanded_size: usize) -> Result<Vec<u8>> {
    if data.len() == expanded_size {
        Ok(data)
    } else {
        Err(Error::InstallShield(format!(
            "decoded {} bytes against a declared expanded size of {expanded_size}",
            data.len()
        )))
    }
}

pub fn walk_installshield(bytes: &[u8], quota: ExtractionQuota) -> Result<InstallShieldArchive> {
    let header: InstallShieldHeader = parse_installshield_header(bytes)?;
    let volume: InstallShieldVolume = parse_volume(bytes, header.layout)?;
    let table: Vec<u32> = read_file_table(bytes, &header)?;
    let base: usize = table_base(&header)?;
    let mut violations: Vec<String> = Vec::new();
    if header.file_table_size != header.file_table_size2 {
        violations.push(format!(
            "installshield-table-size: declared {} and mirrored {} disagree",
            header.file_table_size, header.file_table_size2
        ));
    }
    if header.cab_descriptor_size < CAB_DESCRIPTOR_TABLE_LEN {
        violations.push(format!(
            "installshield-descriptor-short: {} bytes below the {CAB_DESCRIPTOR_TABLE_LEN}-byte group and component table",
            header.cab_descriptor_size
        ));
    }
    let directory_count: usize = usize::try_from(header.directory_count)
        .map_err(|_| is_err("directory count exceeds address space"))?;
    let mut directories: Vec<String> = Vec::with_capacity(directory_count);
    for index in 0..directory_count {
        let relative: u32 = *table
            .get(index)
            .ok_or_else(|| is_err("directory slot is outside the file table"))?;
        match read_name(bytes, base, relative) {
            Ok(raw) => directories.push(installshield_display_name(&raw)),
            Err(error) => {
                violations.push(format!("installshield-directory `{index}`: {error}"));
                directories.push(String::new());
            }
        }
    }
    let file_count: usize = usize::try_from(header.file_count)
        .map_err(|_| is_err("file count exceeds address space"))?;
    let file_groups: Vec<InstallShieldFileGroup> =
        read_file_groups(bytes, &header, &mut violations);
    let group_names: Vec<String> = map_group_names(&file_groups, file_count);
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let mut files: Vec<InstallShieldFile> = Vec::with_capacity(file_count.min(4096));
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for index in 0..file_count {
        let descriptor: RawDescriptor = match parse_descriptor(bytes, &header, &table, index) {
            Ok(value) => value,
            Err(error) => {
                files.push(refused_placeholder(
                    index,
                    InstallShieldMemberState::RefusedInvalidRecord,
                    error.to_string(),
                ));
                continue;
            }
        };
        let member: InstallShieldFile = build_member(
            bytes,
            &header,
            &volume,
            &directories,
            group_names
                .get(index)
                .map_or("", |value: &String| value.as_str()),
            base,
            index,
            file_count,
            &descriptor,
            &mut guard,
            &mut seen,
        );
        if !member.state.is_recovered() {
            violations.push(format!(
                "installshield-{}: `{}` {}",
                member.state.label(),
                if member.path.is_empty() {
                    format!("index {index}")
                } else {
                    member.path.clone()
                },
                member.detail
            ));
        }
        files.push(member);
    }
    Ok(InstallShieldArchive {
        header,
        volume,
        directories,
        file_groups,
        files,
        integrity_violations: violations,
        quota: *guard.report(),
    })
}

#[allow(clippy::too_many_arguments)]
fn build_member(
    bytes: &[u8],
    header: &InstallShieldHeader,
    volume: &InstallShieldVolume,
    directories: &[String],
    file_group: &str,
    base: usize,
    index: usize,
    file_count: usize,
    descriptor: &RawDescriptor,
    guard: &mut QuotaGuard,
    seen: &mut BTreeSet<String>,
) -> InstallShieldFile {
    let compressed: bool = descriptor.flags & FILE_COMPRESSED != 0;
    let obfuscated: bool = descriptor.flags & FILE_OBFUSCATED != 0;
    let index_u32: u32 = u32::try_from(index).unwrap_or(u32::MAX);
    let mut member: InstallShieldFile = InstallShieldFile {
        index: index_u32,
        name: String::new(),
        name_bytes: Vec::new(),
        directory: String::new(),
        directory_index: descriptor.directory_index,
        file_group: file_group.to_owned(),
        path: String::new(),
        data: Vec::new(),
        compressed,
        obfuscated,
        compression: if compressed {
            InstallShieldCompression::FramedDeflate
        } else {
            InstallShieldCompression::Stored
        },
        compressed_size: descriptor.compressed_size,
        expanded_size: descriptor.expanded_size,
        declared_volume: descriptor.volume,
        state: InstallShieldMemberState::Recovered,
        detail: String::new(),
    };
    if descriptor.flags & FILE_INVALID != 0 {
        return refuse(
            member,
            InstallShieldMemberState::RefusedInvalidRecord,
            format!("record carries the invalid flag {:#06x}", descriptor.flags),
        );
    }
    if descriptor.name_offset == 0 {
        return refuse(
            member,
            InstallShieldMemberState::RefusedInvalidRecord,
            "record carries no name offset".to_owned(),
        );
    }
    if descriptor.data_offset == 0 {
        return refuse(
            member,
            InstallShieldMemberState::RefusedInvalidRecord,
            "record carries no data offset".to_owned(),
        );
    }
    let name_bytes: Vec<u8> = match read_name(bytes, base, descriptor.name_offset) {
        Ok(raw) => raw,
        Err(error) => {
            return refuse(
                member,
                InstallShieldMemberState::RefusedInvalidRecord,
                error.to_string(),
            );
        }
    };
    member.name = installshield_display_name(&name_bytes);
    member.name_bytes = name_bytes;
    let directory: &str = match usize::try_from(descriptor.directory_index)
        .ok()
        .and_then(|slot: usize| directories.get(slot))
    {
        Some(value) => value.as_str(),
        None => {
            return refuse(
                member,
                InstallShieldMemberState::RefusedInvalidRecord,
                format!(
                    "directory index {} is outside the {} declared directories",
                    descriptor.directory_index,
                    directories.len()
                ),
            );
        }
    };
    directory.clone_into(&mut member.directory);
    member.path = join_member_path(file_group, directory, &member.name);
    if matches!(header.layout, InstallShieldLayout::Legacy) {
        if descriptor.flags & FILE_SPLIT != 0
            || is_split_by_volume(volume, index, file_count, descriptor)
        {
            return refuse(
                member,
                InstallShieldMemberState::RefusedSplitMember,
                "member spans volumes; a single-volume input cannot carry its full data".to_owned(),
            );
        }
        if index_u32 > volume.last_file_index {
            return refuse(
                member,
                InstallShieldMemberState::RefusedAbsentVolume,
                format!(
                    "volume header carries members {}..={} and this input is not the volume holding member {index}",
                    volume.first_file_index, volume.last_file_index
                ),
            );
        }
    }
    let stored_len: u64 = if compressed {
        descriptor.compressed_size
    } else {
        descriptor.expanded_size
    };
    let region: &[u8] = match member_region(bytes, descriptor.data_offset, stored_len) {
        Ok(value) => value,
        Err(error) => {
            return refuse(
                member,
                InstallShieldMemberState::RefusedDataOutOfRange,
                format!("{error} (declared volume {})", descriptor.volume),
            );
        }
    };
    if let Err(error) = guard.admit_entry(
        &member.path,
        descriptor.expanded_size,
        descriptor.compressed_size,
    ) {
        return refuse(
            member,
            InstallShieldMemberState::RefusedQuota,
            error.to_string(),
        );
    }
    let plain: Vec<u8> = if obfuscated {
        let mut working: Vec<u8> = region.to_vec();
        let _: u32 = deobfuscate_installshield(&mut working, 0);
        working
    } else {
        Vec::new()
    };
    let source: &[u8] = if obfuscated { plain.as_slice() } else { region };
    let decoded: DecodedMember = match decode_member(source, descriptor) {
        Ok(value) => value,
        Err(error) => {
            let state: InstallShieldMemberState = if error.to_string().contains(AMBIGUOUS_FRAMING) {
                InstallShieldMemberState::RefusedAmbiguousFraming
            } else {
                InstallShieldMemberState::RefusedDecode
            };
            return refuse(member, state, error.to_string());
        }
    };
    if matches!(header.layout, InstallShieldLayout::Modern) {
        let digest: [u8; 16] = md5::compute(&decoded.data).0;
        if digest != descriptor.md5 {
            return refuse(
                member,
                InstallShieldMemberState::RefusedIntegrity,
                "recovered bytes do not match the descriptor MD5".to_owned(),
            );
        }
    }
    let folded: String = member.path.to_ascii_lowercase();
    if !seen.insert(folded) {
        return refuse(
            member,
            InstallShieldMemberState::RefusedDuplicatePath,
            "another member already claims this carve path".to_owned(),
        );
    }
    member.compression = decoded.compression;
    member.data = decoded.data;
    member
}

fn is_split_by_volume(
    volume: &InstallShieldVolume,
    index: usize,
    file_count: usize,
    descriptor: &RawDescriptor,
) -> bool {
    let index_u32: u32 = u32::try_from(index).unwrap_or(u32::MAX);
    let last_index: usize = file_count.saturating_sub(1);
    if index < last_index
        && index_u32 == volume.last_file_index
        && volume.last_file_size_compressed != descriptor.compressed_size
    {
        return true;
    }
    index > 0
        && index_u32 == volume.first_file_index
        && volume.first_file_size_compressed != descriptor.compressed_size
}

fn member_region(bytes: &[u8], data_offset: u64, stored_len: u64) -> Result<&[u8]> {
    let start: usize = usize::try_from(data_offset)
        .map_err(|_| is_err("member data offset exceeds address space"))?;
    let length: usize = usize::try_from(stored_len)
        .map_err(|_| is_err("member data length exceeds address space"))?;
    let end: usize = start
        .checked_add(length)
        .ok_or_else(|| is_err("member data extent overflows"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| is_err("member data extent lies outside this volume"))
}

fn join_member_path(group: &str, directory: &str, name: &str) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(3);
    for component in [group, directory, name] {
        if !component.is_empty() {
            parts.push(component.replace('\\', "/"));
        }
    }
    parts.join("/")
}

fn refuse(
    mut member: InstallShieldFile,
    state: InstallShieldMemberState,
    detail: String,
) -> InstallShieldFile {
    member.state = state;
    member.detail = detail;
    member.data = Vec::new();
    member
}

fn refused_placeholder(
    index: usize,
    state: InstallShieldMemberState,
    detail: String,
) -> InstallShieldFile {
    InstallShieldFile {
        index: u32::try_from(index).unwrap_or(u32::MAX),
        name: String::new(),
        name_bytes: Vec::new(),
        directory: String::new(),
        directory_index: 0,
        file_group: String::new(),
        path: String::new(),
        data: Vec::new(),
        compressed: false,
        obfuscated: false,
        compression: InstallShieldCompression::Stored,
        compressed_size: 0,
        expanded_size: 0,
        declared_volume: 0,
        state,
        detail,
    }
}

#[inline]
fn is_err(msg: &'static str) -> Error {
    Error::InstallShield(msg.to_owned())
}

#[inline]
fn truncated(what: &'static str) -> Error {
    Error::InstallShield(format!("input is truncated inside the {what}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod builder {
    use std::io::Write as _;

    use super::{
        CAB_DESCRIPTOR_TABLE_LEN, FILE_COMPRESSED, FILE_INVALID, FILE_OBFUSCATED, FILE_SPLIT,
        ISC_SIGNATURE, InstallShieldHeader, LEGACY_DESCRIPTOR_LEN_V0, LEGACY_DESCRIPTOR_LEN_V5,
        MODERN_DESCRIPTOR_LEN, obfuscate_installshield, parse_installshield_header,
        read_file_table, table_base,
    };

    const CAB_DESCRIPTOR_OFFSET: u32 = 0x200;
    const CAB_DESCRIPTOR_SIZE: u32 = CAB_DESCRIPTOR_TABLE_LEN;
    const FILE_TABLE_OFFSET: u32 = CAB_DESCRIPTOR_TABLE_LEN;
    const BUILDER_CHUNK: usize = 32 * 1024;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum BuilderFraming {
        Stored,
        Framed,
        FullFlush,
    }

    #[derive(Debug, Clone)]
    pub(crate) struct BuilderMember {
        pub(crate) directory: String,
        pub(crate) name: Vec<u8>,
        pub(crate) body: Vec<u8>,
        pub(crate) framing: BuilderFraming,
        pub(crate) obfuscated: bool,
        pub(crate) split: bool,
        pub(crate) invalid: bool,
        pub(crate) raw: Option<Vec<u8>>,
    }

    impl BuilderMember {
        pub(crate) fn new(
            directory: &str,
            name: &str,
            body: &[u8],
            framing: BuilderFraming,
        ) -> Self {
            Self {
                directory: directory.to_owned(),
                name: name.as_bytes().to_vec(),
                body: body.to_vec(),
                framing,
                obfuscated: false,
                split: false,
                invalid: false,
                raw: None,
            }
        }

        pub(crate) fn raw_compressed(
            directory: &str,
            name: &str,
            expanded: &[u8],
            raw: &[u8],
        ) -> Self {
            let mut member: Self = Self::new(directory, name, expanded, BuilderFraming::FullFlush);
            member.raw = Some(raw.to_vec());
            member
        }

        pub(crate) fn obfuscated(mut self) -> Self {
            self.obfuscated = true;
            self
        }

        pub(crate) fn split(mut self) -> Self {
            self.split = true;
            self
        }

        pub(crate) fn invalid(mut self) -> Self {
            self.invalid = true;
            self
        }
    }

    fn deflate_raw_finish(input: &[u8]) -> Vec<u8> {
        let mut encoder: flate2::write::DeflateEncoder<Vec<u8>> =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(input).expect("deflate write");
        encoder.finish().expect("deflate finish")
    }

    fn deflate_raw_sync(input: &[u8]) -> Vec<u8> {
        let mut compressor: flate2::Compress =
            flate2::Compress::new(flate2::Compression::default(), false);
        let mut out: Vec<u8> = Vec::with_capacity(input.len() + 1024);
        compressor
            .compress_vec(input, &mut out, flate2::FlushCompress::Sync)
            .expect("deflate sync");
        assert_eq!(
            compressor.total_in(),
            input.len() as u64,
            "sync flush must consume the whole piece"
        );
        out
    }

    fn encode_member(member: &BuilderMember) -> Vec<u8> {
        if let Some(raw) = member.raw.as_ref() {
            let mut encoded: Vec<u8> = raw.clone();
            if member.obfuscated {
                let _: u32 = obfuscate_installshield(&mut encoded, 0);
            }
            return encoded;
        }
        let mut encoded: Vec<u8> = match member.framing {
            BuilderFraming::Stored => member.body.clone(),
            BuilderFraming::Framed => {
                let mut out: Vec<u8> = Vec::new();
                for piece in member.body.chunks(BUILDER_CHUNK) {
                    let chunk: Vec<u8> = deflate_raw_finish(piece);
                    let length: u16 = u16::try_from(chunk.len()).expect("chunk length fits u16");
                    out.extend_from_slice(&length.to_le_bytes());
                    out.extend_from_slice(&chunk);
                }
                out
            }
            BuilderFraming::FullFlush => {
                let mut out: Vec<u8> = Vec::new();
                for piece in member.body.chunks(BUILDER_CHUNK) {
                    out.extend_from_slice(&deflate_raw_sync(piece));
                }
                out
            }
        };
        if member.obfuscated {
            let _: u32 = obfuscate_installshield(&mut encoded, 0);
        }
        encoded
    }

    pub(crate) fn build_legacy_archive(major_version: u32, members: &[BuilderMember]) -> Vec<u8> {
        let record_len: usize = if major_version == 5 {
            LEGACY_DESCRIPTOR_LEN_V5
        } else {
            LEGACY_DESCRIPTOR_LEN_V0
        };
        let mut directories: Vec<String> = Vec::new();
        for member in members {
            if !directories.contains(&member.directory) {
                directories.push(member.directory.clone());
            }
        }
        if directories.is_empty() {
            directories.push(String::new());
        }
        let encoded: Vec<Vec<u8>> = members.iter().map(encode_member).collect();
        let table_entries: usize = directories.len() + members.len();
        let mut relative: usize = table_entries * 4;
        let mut directory_offsets: Vec<u32> = Vec::with_capacity(directories.len());
        let mut names: Vec<u8> = Vec::new();
        for directory in &directories {
            directory_offsets.push(u32::try_from(relative + names.len()).expect("name offset"));
            names.extend_from_slice(directory.as_bytes());
            names.push(0);
        }
        let mut name_offsets: Vec<u32> = Vec::with_capacity(members.len());
        for member in members {
            name_offsets.push(u32::try_from(relative + names.len()).expect("name offset"));
            names.extend_from_slice(&member.name);
            names.push(0);
        }
        relative += names.len();
        let mut descriptor_offsets: Vec<u32> = Vec::with_capacity(members.len());
        for index in 0..members.len() {
            descriptor_offsets
                .push(u32::try_from(relative + index * record_len).expect("descriptor offset"));
        }
        relative += members.len() * record_len;
        let table_base: usize = CAB_DESCRIPTOR_OFFSET as usize + FILE_TABLE_OFFSET as usize;
        let data_base: usize = table_base + relative;
        let mut data_offsets: Vec<u32> = Vec::with_capacity(members.len());
        let mut cursor: usize = data_base;
        for blob in &encoded {
            data_offsets.push(u32::try_from(cursor).expect("data offset"));
            cursor += blob.len();
        }
        let mut image: Vec<u8> = vec![0u8; cursor];
        write_u32(&mut image, 0x00, ISC_SIGNATURE);
        write_u32(&mut image, 0x04, encode_version(major_version));
        write_u32(&mut image, 0x08, 1);
        write_u32(&mut image, 0x0C, CAB_DESCRIPTOR_OFFSET);
        write_u32(&mut image, 0x10, CAB_DESCRIPTOR_SIZE);

        let first_compressed: u32 = encoded
            .first()
            .map_or(0, |blob: &Vec<u8>| u32::try_from(blob.len()).unwrap_or(0));
        let last_compressed: u32 = encoded
            .last()
            .map_or(0, |blob: &Vec<u8>| u32::try_from(blob.len()).unwrap_or(0));
        write_u32(&mut image, 0x14, u32::try_from(data_base).expect("base"));
        write_u32(&mut image, 0x1C, 0);
        write_u32(
            &mut image,
            0x20,
            u32::try_from(members.len().saturating_sub(1)).expect("last index"),
        );
        write_u32(
            &mut image,
            0x24,
            data_offsets.first().copied().unwrap_or_default(),
        );
        write_u32(
            &mut image,
            0x28,
            members.first().map_or(0, |m: &BuilderMember| {
                u32::try_from(m.body.len()).unwrap_or(0)
            }),
        );
        write_u32(&mut image, 0x2C, first_compressed);
        write_u32(
            &mut image,
            0x30,
            data_offsets.last().copied().unwrap_or_default(),
        );
        write_u32(
            &mut image,
            0x34,
            members.last().map_or(0, |m: &BuilderMember| {
                u32::try_from(m.body.len()).unwrap_or(0)
            }),
        );
        write_u32(&mut image, 0x38, last_compressed);

        let descriptor_base: usize = CAB_DESCRIPTOR_OFFSET as usize;
        write_u32(&mut image, descriptor_base + 0x0C, FILE_TABLE_OFFSET);
        write_u32(
            &mut image,
            descriptor_base + 0x14,
            u32::try_from(relative).expect("table size"),
        );
        write_u32(
            &mut image,
            descriptor_base + 0x18,
            u32::try_from(relative).expect("table size"),
        );
        write_u32(
            &mut image,
            descriptor_base + 0x1C,
            u32::try_from(directories.len()).expect("directory count"),
        );
        write_u32(
            &mut image,
            descriptor_base + 0x28,
            u32::try_from(members.len()).expect("file count"),
        );
        write_u32(&mut image, descriptor_base + 0x2C, 0);

        for (index, offset) in directory_offsets.iter().enumerate() {
            write_u32(&mut image, table_base + index * 4, *offset);
        }
        for (index, offset) in descriptor_offsets.iter().enumerate() {
            write_u32(
                &mut image,
                table_base + (directories.len() + index) * 4,
                *offset,
            );
        }
        let names_at: usize = table_base + table_entries * 4;
        image[names_at..names_at + names.len()].copy_from_slice(&names);

        for (index, member) in members.iter().enumerate() {
            let at: usize = table_base + descriptor_offsets[index] as usize;
            let directory_index: u16 = u16::try_from(
                directories
                    .iter()
                    .position(|d: &String| *d == member.directory)
                    .unwrap_or(0),
            )
            .expect("directory index");
            let mut flags: u16 = 0;
            if !matches!(member.framing, BuilderFraming::Stored) {
                flags |= FILE_COMPRESSED;
            }
            if member.obfuscated {
                flags |= FILE_OBFUSCATED;
            }
            if member.split {
                flags |= FILE_SPLIT;
            }
            if member.invalid {
                flags |= FILE_INVALID;
            }
            write_u32(&mut image, at, name_offsets[index]);
            write_u16(&mut image, at + 0x04, directory_index);
            write_u16(&mut image, at + 0x08, flags);
            write_u32(
                &mut image,
                at + 0x0A,
                u32::try_from(member.body.len()).expect("expanded size"),
            );
            write_u32(
                &mut image,
                at + 0x0E,
                u32::try_from(encoded[index].len()).expect("compressed size"),
            );
            write_u32(&mut image, at + 0x26, data_offsets[index]);
            if major_version == 5 {
                let digest: [u8; 16] = md5::compute(&member.body).0;
                image[at + 0x2A..at + 0x3A].copy_from_slice(&digest);
            }
        }

        for (index, blob) in encoded.iter().enumerate() {
            let at: usize = data_offsets[index] as usize;
            image[at..at + blob.len()].copy_from_slice(blob);
        }
        image
    }

    pub(crate) fn build_modern_archive(major_version: u32, members: &[BuilderMember]) -> Vec<u8> {
        let mut directories: Vec<String> = Vec::new();
        for member in members {
            if !directories.contains(&member.directory) {
                directories.push(member.directory.clone());
            }
        }
        if directories.is_empty() {
            directories.push(String::new());
        }
        let encoded: Vec<Vec<u8>> = members.iter().map(encode_member).collect();
        let table_entries: usize = directories.len() + members.len();
        let mut relative: usize = table_entries * 4;
        let mut directory_offsets: Vec<u32> = Vec::with_capacity(directories.len());
        let mut names: Vec<u8> = Vec::new();
        for directory in &directories {
            directory_offsets.push(u32::try_from(relative + names.len()).expect("name offset"));
            names.extend_from_slice(directory.as_bytes());
            names.push(0);
        }
        let mut name_offsets: Vec<u32> = Vec::with_capacity(members.len());
        for member in members {
            name_offsets.push(u32::try_from(relative + names.len()).expect("name offset"));
            names.extend_from_slice(&member.name);
            names.push(0);
        }
        relative += names.len();
        let file_table_offset2: u32 = u32::try_from(relative).expect("secondary table offset");
        relative += members.len() * MODERN_DESCRIPTOR_LEN;
        let table_base: usize = CAB_DESCRIPTOR_OFFSET as usize + FILE_TABLE_OFFSET as usize;
        let data_base: usize = table_base + relative;
        let mut data_offsets: Vec<u64> = Vec::with_capacity(members.len());
        let mut cursor: usize = data_base;
        for blob in &encoded {
            data_offsets.push(cursor as u64);
            cursor += blob.len();
        }
        let mut image: Vec<u8> = vec![0u8; cursor];
        write_u32(&mut image, 0x00, ISC_SIGNATURE);
        write_u32(&mut image, 0x04, 0x0200_0000 | (major_version * 100));
        write_u32(&mut image, 0x08, 1);
        write_u32(&mut image, 0x0C, CAB_DESCRIPTOR_OFFSET);
        write_u32(&mut image, 0x10, CAB_DESCRIPTOR_SIZE);
        write_u32(&mut image, 0x14, u32::try_from(data_base).expect("base"));
        write_u32(&mut image, 0x1C, 0);
        write_u32(
            &mut image,
            0x20,
            u32::try_from(members.len().saturating_sub(1)).expect("last index"),
        );

        let descriptor_base: usize = CAB_DESCRIPTOR_OFFSET as usize;
        write_u32(&mut image, descriptor_base + 0x0C, FILE_TABLE_OFFSET);
        write_u32(
            &mut image,
            descriptor_base + 0x14,
            u32::try_from(relative).expect("table size"),
        );
        write_u32(
            &mut image,
            descriptor_base + 0x18,
            u32::try_from(relative).expect("table size"),
        );
        write_u32(
            &mut image,
            descriptor_base + 0x1C,
            u32::try_from(directories.len()).expect("directory count"),
        );
        write_u32(
            &mut image,
            descriptor_base + 0x28,
            u32::try_from(members.len()).expect("file count"),
        );
        write_u32(&mut image, descriptor_base + 0x2C, file_table_offset2);

        for (index, offset) in directory_offsets.iter().enumerate() {
            write_u32(&mut image, table_base + index * 4, *offset);
        }
        let names_at: usize = table_base + table_entries * 4;
        image[names_at..names_at + names.len()].copy_from_slice(&names);

        for (index, member) in members.iter().enumerate() {
            let at: usize =
                table_base + file_table_offset2 as usize + index * MODERN_DESCRIPTOR_LEN;
            let directory_index: u16 = u16::try_from(
                directories
                    .iter()
                    .position(|d: &String| *d == member.directory)
                    .unwrap_or(0),
            )
            .expect("directory index");
            let mut flags: u16 = 0;
            if !matches!(member.framing, BuilderFraming::Stored) {
                flags |= FILE_COMPRESSED;
            }
            if member.obfuscated {
                flags |= FILE_OBFUSCATED;
            }
            if member.invalid {
                flags |= FILE_INVALID;
            }
            write_u16(&mut image, at, flags);
            write_u64(&mut image, at + 0x02, member.body.len() as u64);
            write_u64(&mut image, at + 0x0A, encoded[index].len() as u64);
            write_u64(&mut image, at + 0x12, data_offsets[index]);
            let digest: [u8; 16] = md5::compute(&member.body).0;
            image[at + 0x1A..at + 0x2A].copy_from_slice(&digest);
            write_u32(&mut image, at + 0x3A, name_offsets[index]);
            write_u16(&mut image, at + 0x3E, directory_index);
            write_u16(&mut image, at + 0x55, 1);
        }

        for (index, blob) in encoded.iter().enumerate() {
            let at: usize = data_offsets[index] as usize;
            image[at..at + blob.len()].copy_from_slice(blob);
        }
        image
    }

    pub(crate) fn corrupt_first_modern_md5(image: &mut [u8]) {
        let header: InstallShieldHeader = parse_installshield_header(image).expect("header");
        let base: usize = table_base(&header).expect("base");
        let at: usize = base + header.file_table_offset2 as usize;
        image[at + 0x1A] ^= 0xFF;
    }

    pub(crate) fn plant_cyclic_file_group(image: &mut [u8]) {
        let header: InstallShieldHeader = parse_installshield_header(image).expect("header");
        let descriptor_base: usize = header.cab_descriptor_offset as usize;
        let node: u32 = 0x100;
        write_u32(image, descriptor_base + 0x3E, node);
        let node_at: usize = descriptor_base + node as usize;
        write_u32(image, node_at, 0);
        write_u32(image, node_at + 4, 0);
        write_u32(image, node_at + 8, node);
    }

    const fn encode_version(major_version: u32) -> u32 {
        0x0100_0000 | (major_version << 12)
    }

    fn write_u64(image: &mut [u8], at: usize, value: u64) {
        image[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(image: &mut [u8], at: usize, value: u32) {
        image[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u16(image: &mut [u8], at: usize, value: u16) {
        image[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn build_test_installshield(name: &str, body: &[u8]) -> Vec<u8> {
        build_legacy_archive(
            5,
            &[BuilderMember::new("", name, body, BuilderFraming::Stored)],
        )
    }

    fn first_descriptor_at(image: &[u8]) -> usize {
        let header: InstallShieldHeader = parse_installshield_header(image).expect("header");
        let table: Vec<u32> = read_file_table(image, &header).expect("table");
        let base: usize = table_base(&header).expect("base");
        let slot: usize = header.directory_count as usize;
        base + table[slot] as usize
    }

    pub(crate) fn first_member_data_offset(image: &[u8]) -> usize {
        let at: usize = first_descriptor_at(image);
        u32::from_le_bytes([
            image[at + 0x26],
            image[at + 0x27],
            image[at + 0x28],
            image[at + 0x29],
        ]) as usize
    }

    pub(crate) fn set_first_member_expanded_size(image: &mut [u8], value: u32) {
        let at: usize = first_descriptor_at(image);
        write_u32(image, at + 0x0A, value);
    }

    pub(crate) fn set_first_member_directory_index(image: &mut [u8], value: u16) {
        let at: usize = first_descriptor_at(image);
        write_u16(image, at + 0x04, value);
    }

    pub(crate) fn set_volume_last_file_index(image: &mut [u8], value: u32) {
        write_u32(image, 0x20, value);
    }
}

#[cfg(test)]
pub(crate) use builder::build_test_installshield;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::builder::{BuilderFraming, BuilderMember, build_legacy_archive};
    use super::*;

    fn quota() -> ExtractionQuota {
        ExtractionQuota {
            max_per_entry_ratio: 4096,
            max_aggregate_ratio: 4096,
            ..ExtractionQuota::default_safe()
        }
    }

    #[test]
    fn major_version_decoding_follows_the_published_encodings() {
        assert_eq!(installshield_major_version(0x0100_0004), 0);
        assert_eq!(installshield_major_version(0x0100_5201), 5);
        assert_eq!(installshield_major_version(0x0200_0258), 6);
        assert_eq!(installshield_major_version(0x0400_02BC), 7);
        assert_eq!(installshield_major_version(0x0000_0000), 0);
        assert_eq!(
            installshield_layout(installshield_major_version(0x0100_5201)),
            InstallShieldLayout::Legacy
        );
        assert_eq!(
            installshield_layout(installshield_major_version(0x0200_0258)),
            InstallShieldLayout::Modern
        );
    }

    #[test]
    fn obfuscation_round_trips_against_a_frozen_vector() {
        const PLAIN: [u8; 16] = *b"installshield-05";
        const OBFUSCATED: [u8; 16] = [
            0x70, 0x68, 0x00, 0x08, 0x40, 0x10, 0x1C, 0x3C, 0x14, 0x1C, 0x68, 0x08, 0x14, 0x3D,
            0x2D, 0xC4,
        ];
        let mut encoded: Vec<u8> = PLAIN.to_vec();
        let seed: u32 = obfuscate_installshield(&mut encoded, 0);
        assert_eq!(seed, 16);
        assert_eq!(encoded.as_slice(), OBFUSCATED.as_slice());
        let mut decoded: Vec<u8> = OBFUSCATED.to_vec();
        let _: u32 = deobfuscate_installshield(&mut decoded, 0);
        assert_eq!(decoded.as_slice(), PLAIN.as_slice());
    }

    #[test]
    fn obfuscation_seed_wraps_at_the_published_modulus() {
        let plain: Vec<u8> = vec![0u8; 200];
        let mut encoded: Vec<u8> = plain.clone();
        let end: u32 = obfuscate_installshield(&mut encoded, 0);
        assert_eq!(end, 200);
        let mut decoded: Vec<u8> = encoded;
        let _: u32 = deobfuscate_installshield(&mut decoded, 0);
        assert_eq!(decoded, plain);
    }

    #[test]
    fn framed_and_stored_members_round_trip() {
        let body: Vec<u8> = b"framed installshield member body ".repeat(40);
        let stored: Vec<u8> = b"stored member".to_vec();
        let image: Vec<u8> = build_legacy_archive(
            5,
            &[
                BuilderMember::new("bin", "app.exe", &body, BuilderFraming::Framed),
                BuilderMember::new("", "plain.txt", &stored, BuilderFraming::Stored),
            ],
        );
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(archive.header.major_version, 5);
        assert_eq!(archive.recovered_count(), 2);
        let first: &InstallShieldFile = &archive.files[0];
        assert_eq!(first.path, "bin/app.exe");
        assert_eq!(first.data, body);
        assert_eq!(first.compression, InstallShieldCompression::FramedDeflate);
        let second: &InstallShieldFile = &archive.files[1];
        assert_eq!(second.path, "plain.txt");
        assert_eq!(second.data, stored);
        assert_eq!(second.compression, InstallShieldCompression::Stored);
    }

    #[test]
    fn full_flush_members_round_trip() {
        let body: Vec<u8> = b"full flush installshield member ".repeat(50);
        let image: Vec<u8> = build_legacy_archive(
            0,
            &[BuilderMember::new(
                "",
                "old.dat",
                &body,
                BuilderFraming::FullFlush,
            )],
        );
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(archive.recovered_count(), 1);
        assert_eq!(archive.files[0].data, body);
        assert_eq!(
            archive.files[0].compression,
            InstallShieldCompression::FullFlushDeflate
        );
    }

    #[test]
    fn obfuscated_members_round_trip() {
        let body: Vec<u8> = b"obfuscated installshield payload ".repeat(30);
        let image: Vec<u8> = build_legacy_archive(
            5,
            &[
                BuilderMember::new("", "hidden.bin", &body, BuilderFraming::Framed).obfuscated(),
                BuilderMember::new("", "hidden.txt", b"plain stored", BuilderFraming::Stored)
                    .obfuscated(),
            ],
        );
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(archive.recovered_count(), 2);
        assert!(archive.files[0].obfuscated);
        assert_eq!(archive.files[0].data, body);
        assert_eq!(archive.files[1].data, b"plain stored".to_vec());
    }

    #[test]
    fn zero_length_frame_is_refused() {
        let body: Vec<u8> = b"zero frame probe".to_vec();
        let mut image: Vec<u8> = build_legacy_archive(
            5,
            &[BuilderMember::new(
                "",
                "a.bin",
                &body,
                BuilderFraming::Framed,
            )],
        );
        let data_at: usize = builder::first_member_data_offset(&image);
        image[data_at] = 0;
        image[data_at + 1] = 0;
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(archive.recovered_count(), 0);
        assert_eq!(
            archive.files[0].state,
            InstallShieldMemberState::RefusedDecode
        );
        assert!(
            archive.files[0]
                .detail
                .contains("framed stream declares a zero-length chunk"),
            "the zero frame must be named exactly, got {}",
            archive.files[0].detail
        );
    }

    #[test]
    fn truncated_member_data_is_refused_without_partial_output() {
        let body: Vec<u8> = b"truncation probe body ".repeat(20);
        let image: Vec<u8> = build_legacy_archive(
            5,
            &[BuilderMember::new(
                "",
                "a.bin",
                &body,
                BuilderFraming::Framed,
            )],
        );
        let cut: usize = image.len().saturating_sub(8);
        let archive: InstallShieldArchive =
            walk_installshield(&image[..cut], quota()).expect("walk");
        assert_eq!(archive.recovered_count(), 0);
        assert_eq!(
            archive.files[0].state,
            InstallShieldMemberState::RefusedDataOutOfRange
        );
        assert!(archive.files[0].data.is_empty());
    }

    #[test]
    fn declared_size_mismatch_is_refused() {
        let body: Vec<u8> = b"size mismatch probe".to_vec();
        let mut image: Vec<u8> = build_legacy_archive(
            5,
            &[BuilderMember::new(
                "",
                "a.bin",
                &body,
                BuilderFraming::Framed,
            )],
        );
        builder::set_first_member_expanded_size(&mut image, body.len() as u32 + 7);
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(
            archive.files[0].state,
            InstallShieldMemberState::RefusedDecode
        );
    }

    #[test]
    fn expansion_bomb_is_stopped_by_the_quota() {
        let body: Vec<u8> = vec![0u8; 8 * 1024 * 1024];
        let image: Vec<u8> = build_legacy_archive(
            5,
            &[BuilderMember::new(
                "",
                "bomb.bin",
                &body,
                BuilderFraming::Framed,
            )],
        );
        let tight: ExtractionQuota = ExtractionQuota {
            max_per_entry_ratio: 10,
            max_aggregate_ratio: 10,
            ..ExtractionQuota::default_safe()
        };
        let archive: InstallShieldArchive = walk_installshield(&image, tight).expect("walk");
        assert_eq!(archive.recovered_count(), 0);
        assert_eq!(
            archive.files[0].state,
            InstallShieldMemberState::RefusedQuota
        );
        assert!(archive.files[0].data.is_empty());
        assert_eq!(archive.quota.total_uncompressed_bytes, 0);
    }

    #[test]
    fn duplicate_carve_paths_are_refused() {
        let image: Vec<u8> = build_legacy_archive(
            5,
            &[
                BuilderMember::new("dir", "Same.txt", b"first", BuilderFraming::Stored),
                BuilderMember::new("dir", "same.TXT", b"second", BuilderFraming::Stored),
            ],
        );
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(archive.recovered_count(), 1);
        assert_eq!(
            archive.files[1].state,
            InstallShieldMemberState::RefusedDuplicatePath
        );
    }

    #[test]
    fn invalid_records_are_reported_rather_than_dropped() {
        let image: Vec<u8> = build_legacy_archive(
            5,
            &[
                BuilderMember::new("", "kept.txt", b"kept", BuilderFraming::Stored),
                BuilderMember::new("", "gone.txt", b"gone", BuilderFraming::Stored).invalid(),
            ],
        );
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(archive.files.len(), 2);
        assert_eq!(archive.recovered_count(), 1);
        assert_eq!(
            archive.files[1].state,
            InstallShieldMemberState::RefusedInvalidRecord
        );
        assert!(
            archive
                .integrity_violations
                .iter()
                .any(|line: &String| line.contains("invalid-record"))
        );
    }

    #[test]
    fn out_of_range_directory_index_is_refused() {
        let mut image: Vec<u8> = build_legacy_archive(
            5,
            &[BuilderMember::new(
                "",
                "a.txt",
                b"body",
                BuilderFraming::Stored,
            )],
        );
        builder::set_first_member_directory_index(&mut image, 9);
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(
            archive.files[0].state,
            InstallShieldMemberState::RefusedInvalidRecord
        );
    }

    #[test]
    fn split_members_are_refused_not_silently_skipped() {
        let image: Vec<u8> = build_legacy_archive(
            5,
            &[
                BuilderMember::new("", "part.bin", b"partial member", BuilderFraming::Stored)
                    .split(),
            ],
        );
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(
            archive.files[0].state,
            InstallShieldMemberState::RefusedSplitMember
        );
        assert!(
            archive
                .integrity_violations
                .iter()
                .any(|line: &String| line.contains("split-member"))
        );
    }

    #[test]
    fn members_beyond_the_volume_range_are_refused() {
        let mut image: Vec<u8> = build_legacy_archive(
            5,
            &[
                BuilderMember::new("", "one.txt", b"one", BuilderFraming::Stored),
                BuilderMember::new("", "two.txt", b"two", BuilderFraming::Stored),
            ],
        );
        builder::set_volume_last_file_index(&mut image, 0);
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(archive.recovered_count(), 1);
        assert_eq!(
            archive.files[1].state,
            InstallShieldMemberState::RefusedAbsentVolume
        );
    }

    #[test]
    fn non_installshield_input_is_rejected() {
        assert!(detect_installshield(&vec![0u8; 4096]).is_none());
        assert!(walk_installshield(&vec![0u8; 4096], quota()).is_err());
        assert!(walk_installshield(&[], quota()).is_err());
        assert!(walk_installshield(b"ISc(", quota()).is_err());
    }

    #[test]
    fn truncated_headers_fail_precisely() {
        let image: Vec<u8> = build_legacy_archive(
            5,
            &[BuilderMember::new(
                "",
                "a.txt",
                b"body",
                BuilderFraming::Stored,
            )],
        );
        for cut in [4usize, 8, 16, 20, 32, 56, 64] {
            let error: Error = walk_installshield(&image[..cut.min(image.len())], quota())
                .expect_err("truncated header must fail");
            assert!(matches!(error, Error::InstallShield(_)));
        }
    }

    #[test]
    fn undecodable_name_bytes_survive_reversibly() {
        let raw: [u8; 5] = [b'a', 0xFF, b'%', 0xC3, b'z'];
        let display: String = installshield_display_name(&raw);
        assert_eq!(display, "a%FF%25%C3z");
        let ascii: String = installshield_display_name(b"plain%name.txt");
        assert_eq!(ascii, "plain%name.txt");
    }

    #[test]
    fn extract_to_writes_recovered_members_and_reports_refusals() {
        let body: Vec<u8> = b"installshield end to end payload 0xFEEDFACE ".repeat(8);
        let image: Vec<u8> = build_legacy_archive(
            5,
            &[
                BuilderMember::new("bin", "tool.dll", &body, BuilderFraming::Framed),
                BuilderMember::new("bin", "dropped.dll", b"dropped", BuilderFraming::Stored)
                    .invalid(),
            ],
        );
        let dir: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-installshield-e2e")
                .expect("create scratch dir");
        let result: crate::extract::ExtractionResult = crate::extract::extract_to(
            crate::container::ContainerKind::InstallShield,
            &image,
            dir.path(),
        )
        .expect("installshield extract");
        assert_eq!(result.kind, crate::container::ContainerKind::InstallShield);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].name, "bin/tool.dll");
        assert_eq!(result.entries[0].uncompressed_size, body.len() as u64);
        assert!(result.entries[0].compressed_size < body.len() as u64);
        assert_eq!(
            std::fs::read(dir.path().join("bin/tool.dll")).expect("file"),
            body
        );
        assert!(!dir.path().join("bin/dropped.dll").exists());
        assert!(
            result
                .integrity_violations
                .iter()
                .any(|line: &String| line.contains("invalid-record"))
        );
    }

    #[test]
    fn full_flush_marker_inside_a_chunk_is_stepped_over() {
        const PAYLOAD: [u8; 9] = [0x00, 0x00, 0xFF, 0xFF, 0x01, 0x41, 0x42, 0x43, 0x44];
        let mut raw: Vec<u8> = Vec::new();
        raw.push(0x00);
        raw.extend_from_slice(&9u16.to_le_bytes());
        raw.extend_from_slice(&(!9u16).to_le_bytes());
        raw.extend_from_slice(&PAYLOAD);
        raw.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
        let image: Vec<u8> = build_legacy_archive(
            0,
            &[builder::BuilderMember::raw_compressed(
                "",
                "marker.bin",
                &PAYLOAD,
                &raw,
            )],
        );
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(archive.recovered_count(), 1);
        assert_eq!(archive.files[0].data, PAYLOAD.to_vec());
        assert_eq!(
            archive.files[0].compression,
            InstallShieldCompression::FullFlushDeflate
        );
    }

    #[test]
    fn framing_resolution_refuses_two_disagreeing_readings() {
        let equal: Result<DecodedMember> =
            resolve_framing(Ok(b"same".to_vec()), Ok(b"same".to_vec()));
        assert_eq!(equal.expect("equal readings").data, b"same".to_vec());
        let disagreeing: Error = resolve_framing(Ok(b"one".to_vec()), Ok(b"two".to_vec()))
            .expect_err("disagreeing readings must be refused");
        assert!(disagreeing.to_string().contains(AMBIGUOUS_FRAMING));
        let framed_only: DecodedMember =
            resolve_framing(Ok(b"framed".to_vec()), Err(is_err("no marker"))).expect("framed only");
        assert_eq!(
            framed_only.compression,
            InstallShieldCompression::FramedDeflate
        );
        let flush_only: DecodedMember =
            resolve_framing(Err(is_err("bad prefix")), Ok(b"flush".to_vec()))
                .expect("full flush only");
        assert_eq!(
            flush_only.compression,
            InstallShieldCompression::FullFlushDeflate
        );
        let neither: Error = resolve_framing(Err(is_err("bad prefix")), Err(is_err("no marker")))
            .expect_err("neither reading");
        assert!(neither.to_string().contains("neither representation"));
    }

    #[test]
    fn modern_contiguous_records_round_trip_and_check_their_digest() {
        let body: Vec<u8> = b"modern installshield member body ".repeat(24);
        let image: Vec<u8> = builder::build_modern_archive(
            6,
            &[
                BuilderMember::new("app", "payload.bin", &body, BuilderFraming::Framed),
                BuilderMember::new("app", "notes.txt", b"plain", BuilderFraming::Stored),
            ],
        );
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(archive.header.major_version, 6);
        assert_eq!(archive.header.layout, InstallShieldLayout::Modern);
        assert_eq!(archive.recovered_count(), 2);
        assert_eq!(archive.files[0].path, "app/payload.bin");
        assert_eq!(archive.files[0].data, body);
        assert_eq!(archive.files[1].data, b"plain".to_vec());

        let mut tampered: Vec<u8> = image;
        builder::corrupt_first_modern_md5(&mut tampered);
        let checked: InstallShieldArchive =
            walk_installshield(&tampered, quota()).expect("walk tampered");
        assert_eq!(
            checked.files[0].state,
            InstallShieldMemberState::RefusedIntegrity
        );
        assert!(checked.files[0].data.is_empty());
        assert_eq!(checked.recovered_count(), 1);
    }

    #[test]
    fn cyclic_file_group_chains_are_broken_and_reported() {
        let mut image: Vec<u8> = build_legacy_archive(
            5,
            &[BuilderMember::new(
                "",
                "a.txt",
                b"body",
                BuilderFraming::Stored,
            )],
        );
        builder::plant_cyclic_file_group(&mut image);
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert!(
            archive
                .integrity_violations
                .iter()
                .any(|line: &String| line.contains("file-group-cycle"))
        );
        assert_eq!(archive.recovered_count(), 1);
    }

    #[test]
    fn a_group_table_outside_the_input_is_reported_without_losing_members() {
        let mut image: Vec<u8> = vec![0u8; 0x260];
        image[0x00..0x04].copy_from_slice(&ISC_SIGNATURE.to_le_bytes());
        image[0x04..0x08].copy_from_slice(&0x0100_5000u32.to_le_bytes());
        image[0x0C..0x10].copy_from_slice(&0x200u32.to_le_bytes());
        image[0x10..0x14].copy_from_slice(&0x30u32.to_le_bytes());
        image[0x20C..0x210].copy_from_slice(&0x30u32.to_le_bytes());
        let archive: InstallShieldArchive = walk_installshield(&image, quota()).expect("walk");
        assert_eq!(archive.header.major_version, 5);
        assert!(archive.files.is_empty());
        assert!(
            archive
                .integrity_violations
                .iter()
                .any(|line: &String| line.contains("file-group-table"))
        );
        assert!(
            archive
                .integrity_violations
                .iter()
                .any(|line: &String| line.contains("descriptor-short"))
        );
    }

    #[test]
    fn detector_never_panics_on_hostile_prefixes() {
        for length in 0usize..96 {
            let mut bytes: Vec<u8> = vec![0xFFu8; length];
            if length >= 4 {
                bytes[..4].copy_from_slice(&ISC_SIGNATURE.to_le_bytes());
            }
            let _: Option<InstallShieldHeader> = detect_installshield(&bytes);
            let _: Result<InstallShieldArchive> = walk_installshield(&bytes, quota());
        }
    }
}
