use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;

use disrobe_core::codec::crc32_ieee;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::container::find_subslice;
use crate::error::{Error, Result};
use crate::native_image::{NativeImage, parse_native_image};
use disrobe_bytes::ByteReader;

#[cfg(test)]
const INNO_DATA_ID_PREFIX: &[u8] = b"Inno Setup Setup Data (";
const INNO_HEADER_ID_LEN: usize = 64;
const INNO_CHUNK_SIZE: usize = 4096;
const MAX_INNO_OUTPUT: u64 = 4 * 1024 * 1024 * 1024;
const MAX_INNO_HEADER_STRING: usize = 16 * 1024 * 1024;
const MAX_INNO_TABLE_ENTRIES: u32 = 1 << 20;
const MAX_INNO_TOTAL_ENTRIES: u32 = 4_000_000;
const MAX_INNO_FILE_NAME_BYTES: usize = 64 * 1024 * 1024;

const SETUP_LOADER_RESOURCE_ID: u32 = 11111;
const LEGACY_LOADER_OFFSET: usize = 0x30;
const LOADER_TABLE_LEN: usize = 64;

const LOADER_MAGIC_4000: [u8; 12] = *b"rDlPtS04\x87eVx";
const LOADER_MAGIC_4003: [u8; 12] = *b"rDlPtS05\x87eVx";
const LOADER_MAGIC_4010: [u8; 12] = *b"rDlPtS06\x87eVx";
const LOADER_MAGIC_4016: [u8; 12] = *b"rDlPtS07\x87eVx";
const LOADER_MAGIC_515_A: [u8; 12] = *b"rDlPtS\xCD\xE6\xD7{\x0B*";
const LOADER_MAGIC_515_B: [u8; 12] = *b"nS5W7dT\x83\xAA\x1B\x0Fj";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupLoaderOffsets {
    pub revision: u32,
    pub exe_offset: u64,
    pub exe_compressed_size: u64,
    pub exe_uncompressed_size: u64,
    pub exe_checksum: u32,
    pub header_offset: u64,
    pub data_offset: u64,
    pub table_crc_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnoSetupInfo {
    pub version_string: String,
    pub version: InnoDataVersion,
    pub unicode: bool,
    pub encrypted: bool,
    pub data_id_offset: u64,
    pub block_stream_offset: u64,
    pub compression: InnoCompression,
    pub stored_size: u64,
    pub loader: Option<SetupLoaderOffsets>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnoSetupCounts {
    pub languages: u32,
    pub messages: u32,
    pub permissions: u32,
    pub types: u32,
    pub components: u32,
    pub tasks: u32,
    pub directories: u32,
    pub issig_keys: u32,
    pub files: u32,
    pub data_entries: u32,
    pub icons: u32,
    pub ini_entries: u32,
    pub registry_entries: u32,
    pub delete_entries: u32,
    pub uninstall_delete_entries: u32,
    pub run_entries: u32,
    pub uninstall_run_entries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnoMetadataBlocks {
    pub primary: Vec<u8>,
    pub secondary: Vec<u8>,
    pub data_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnoMetadata {
    pub info: InnoSetupInfo,
    pub counts: InnoSetupCounts,
    pub data_entries: Vec<InnoDataEntry>,
    pub files: Vec<InnoSetupFile>,
    pub file_compression: InnoFileCompression,
    pub slices_per_disk: u32,
    pub primary_entries_offset: u64,
    pub data_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnoSetupFile {
    pub source: String,
    pub destination: String,
    pub data_entry_index: u32,
    pub external_size: u64,
    pub options: u32,
    pub file_type: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnoRecoveredFile {
    pub path: String,
    pub data: Vec<u8>,
    pub compressed_size: u64,
    pub compression: InnoFileCompression,
    pub(crate) compressed_group: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnoNamedRecovery {
    pub files: Vec<InnoRecoveredFile>,
    pub refusals: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct InnoRecoveryLimits {
    pub max_entries: usize,
    pub max_total: u64,
    pub max_per_entry: u64,
    pub max_per_entry_ratio: u64,
    pub max_aggregate_ratio: u64,
    pub initial_uncompressed: u64,
    pub initial_compressed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnoChecksum {
    Crc32(u32),
    Md5([u8; 16]),
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnoSignMode {
    Unchanged,
    Yes,
    Once,
    Check,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnoDataEntry {
    pub first_slice: u32,
    pub last_slice: u32,
    pub chunk_offset: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub chunk_size: u64,
    pub checksum: InnoChecksum,
    pub timestamp_seconds: i64,
    pub timestamp_nanoseconds: u32,
    pub file_version: u64,
    pub compressed: bool,
    pub encrypted: bool,
    pub solid_break: bool,
    pub instruction_filter: bool,
    pub sign_mode: InnoSignMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InnoDataVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub revision: u16,
}

impl InnoDataVersion {
    const LZMA1_METADATA: Self = Self {
        major: 4,
        minor: 1,
        patch: 6,
        revision: 0,
    };
    const WIDE_BLOCK_EXTENT: Self = Self {
        major: 6,
        minor: 7,
        patch: 0,
        revision: 0,
    };

    const fn uses_wide_block_extent(self) -> bool {
        self.major > Self::WIDE_BLOCK_EXTENT.major
            || (self.major == Self::WIDE_BLOCK_EXTENT.major
                && self.minor >= Self::WIDE_BLOCK_EXTENT.minor)
    }

    fn is_supported(self) -> bool {
        SUPPORTED_DATA_VERSIONS.contains(&self)
    }
}

const fn inno_version(major: u16, minor: u16, patch: u16, revision: u16) -> InnoDataVersion {
    InnoDataVersion {
        major,
        minor,
        patch,
        revision,
    }
}

const SUPPORTED_DATA_VERSIONS: &[InnoDataVersion] = &[
    inno_version(4, 0, 9, 0),
    inno_version(4, 0, 10, 0),
    inno_version(4, 0, 11, 0),
    inno_version(4, 1, 0, 0),
    inno_version(4, 1, 2, 0),
    inno_version(4, 1, 3, 0),
    inno_version(4, 1, 4, 0),
    inno_version(4, 1, 5, 0),
    inno_version(4, 1, 6, 0),
    inno_version(4, 1, 8, 0),
    inno_version(4, 2, 0, 0),
    inno_version(4, 2, 1, 0),
    inno_version(4, 2, 2, 0),
    inno_version(4, 2, 3, 0),
    inno_version(4, 2, 4, 0),
    inno_version(4, 2, 5, 0),
    inno_version(4, 2, 6, 0),
    inno_version(5, 0, 0, 0),
    inno_version(5, 0, 1, 0),
    inno_version(5, 0, 3, 0),
    inno_version(5, 0, 4, 0),
    inno_version(5, 1, 0, 0),
    inno_version(5, 1, 2, 0),
    inno_version(5, 1, 7, 0),
    inno_version(5, 1, 10, 0),
    inno_version(5, 1, 13, 0),
    inno_version(5, 2, 0, 0),
    inno_version(5, 2, 1, 0),
    inno_version(5, 2, 3, 0),
    inno_version(5, 2, 5, 0),
    inno_version(5, 3, 0, 0),
    inno_version(5, 3, 3, 0),
    inno_version(5, 3, 5, 0),
    inno_version(5, 3, 6, 0),
    inno_version(5, 3, 7, 0),
    inno_version(5, 3, 8, 0),
    inno_version(5, 3, 9, 0),
    inno_version(5, 3, 10, 0),
    inno_version(5, 3, 10, 1),
    inno_version(5, 4, 2, 0),
    inno_version(5, 4, 2, 1),
    inno_version(5, 5, 0, 0),
    inno_version(5, 5, 0, 1),
    inno_version(5, 5, 6, 0),
    inno_version(5, 5, 7, 0),
    inno_version(5, 5, 7, 1),
    inno_version(5, 6, 0, 0),
    inno_version(5, 6, 2, 0),
    inno_version(6, 0, 0, 0),
    inno_version(6, 1, 0, 0),
    inno_version(6, 3, 0, 0),
    inno_version(6, 4, 0, 0),
    inno_version(6, 4, 0, 1),
    inno_version(6, 4, 2, 0),
    inno_version(6, 4, 3, 0),
    inno_version(6, 5, 0, 0),
    inno_version(6, 5, 2, 0),
    inno_version(6, 6, 0, 0),
    inno_version(6, 6, 1, 0),
    inno_version(6, 7, 0, 0),
    inno_version(7, 0, 0, 1),
    inno_version(7, 0, 0, 3),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InnoBlockHeader {
    stored_size: u64,
    compressed: u8,
    stream_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InnoEncryptionHeader {
    used: bool,
    stream_offset: usize,
}

fn parse_inno_version(version_string: &str) -> (Option<InnoDataVersion>, bool) {
    const PREFIX: &str = "Inno Setup Setup Data (";
    let Some(tail): Option<&str> = version_string.strip_prefix(PREFIX) else {
        return (None, false);
    };
    let Some((number, suffix)): Option<(&str, &str)> = tail.split_once(')') else {
        return (None, false);
    };
    if !matches!(suffix, "" | " (u)" | " (U)") {
        return (None, false);
    }
    let mut parts: [u16; 4] = [0; 4];
    let mut count: usize = 0;
    for component in number.split('.') {
        let Some(slot): Option<&mut u16> = parts.get_mut(count) else {
            return (None, false);
        };
        if component.is_empty() || !component.bytes().all(|byte: u8| byte.is_ascii_digit()) {
            return (None, false);
        }
        let Ok(value): std::result::Result<u16, std::num::ParseIntError> = component.parse::<u16>()
        else {
            return (None, false);
        };
        *slot = value;
        count = match count.checked_add(1) {
            Some(next) => next,
            None => return (None, false),
        };
    }
    if !(2..=4).contains(&count) {
        return (None, false);
    }
    let version: InnoDataVersion = inno_version(parts[0], parts[1], parts[2], parts[3]);
    let suffix_unicode: bool = matches!(suffix, " (u)" | " (U)");
    let suffix_valid: bool = if version < inno_version(5, 2, 5, 0) {
        !suffix_unicode
    } else if version < inno_version(6, 0, 0, 0) {
        true
    } else if version < inno_version(6, 3, 0, 0) {
        suffix_unicode
    } else {
        !suffix_unicode
    };
    if !suffix_valid {
        return (None, false);
    }
    (
        Some(version),
        suffix_unicode || version >= inno_version(6, 0, 0, 0),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InnoCompression {
    Stored,
    Zlib,
    Lzma1,
    Lzma2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InnoFileCompression {
    Stored,
    Zlib,
    Bzip2,
    Lzma1,
    Lzma2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InnoFilter {
    None,
    Instruction4108,
    Instruction5200,
    Instruction5309,
    Zlib,
}

fn inno_id_field(bytes: &[u8], id_at: usize) -> Option<String> {
    let id_block: &[u8] = bytes.get(id_at..id_at + INNO_HEADER_ID_LEN)?;
    let terminator: usize = id_block.iter().position(|b: &u8| *b == 0)?;
    if id_block[terminator..].iter().any(|b: &u8| *b != 0) {
        return None;
    }
    let version_string: String = id_block[..terminator]
        .iter()
        .map(|&b: &u8| char::from(b))
        .collect::<String>()
        .trim()
        .to_owned();
    version_string
        .starts_with("Inno Setup")
        .then_some(version_string)
}

fn inno_info_at(
    bytes: &[u8],
    id_at: usize,
    loader: Option<SetupLoaderOffsets>,
) -> Option<InnoSetupInfo> {
    let version_string: String = inno_id_field(bytes, id_at)?;
    let (version, unicode): (Option<InnoDataVersion>, bool) = parse_inno_version(&version_string);
    let version: InnoDataVersion = version?;
    if !version.is_supported() {
        return None;
    }
    let mut header_at: usize = id_at.checked_add(INNO_HEADER_ID_LEN)?;
    let encrypted: bool = if version >= inno_version(6, 5, 0, 0) {
        let encryption: InnoEncryptionHeader = parse_inno_encryption_header(bytes, header_at)?;
        header_at = encryption.stream_offset;
        encryption.used
    } else {
        false
    };
    let header: InnoBlockHeader = parse_inno_block_header(bytes, header_at, version)?;
    let stored_size: usize = usize::try_from(header.stored_size).ok()?;
    if header.stream_offset.checked_add(stored_size)? > bytes.len() {
        return None;
    }
    let compression: InnoCompression = compression_for_version(version, header.compressed)?;
    Some(InnoSetupInfo {
        version_string,
        version,
        unicode,
        encrypted,
        data_id_offset: id_at as u64,
        block_stream_offset: header.stream_offset as u64,
        compression,
        stored_size: header.stored_size,
        loader,
    })
}

fn parse_inno_encryption_header(bytes: &[u8], header_at: usize) -> Option<InnoEncryptionHeader> {
    const PROTECTED_LEN: usize = 49;
    let checksum_end: usize = header_at.checked_add(4)?;
    let protected_end: usize = checksum_end.checked_add(PROTECTED_LEN)?;
    let expected: u32 = disrobe_bytes::read_u32_le_at(bytes, header_at).ok()?;
    let protected: &[u8] = bytes.get(checksum_end..protected_end)?;
    if crc32(protected) != expected || protected[0] > 1 {
        return None;
    }
    Some(InnoEncryptionHeader {
        used: protected[0] != 0,
        stream_offset: protected_end,
    })
}

fn parse_inno_block_header(
    bytes: &[u8],
    header_at: usize,
    version: InnoDataVersion,
) -> Option<InnoBlockHeader> {
    let protected_len: usize = if version.uses_wide_block_extent() {
        9
    } else {
        5
    };
    let checksum_end: usize = header_at.checked_add(4)?;
    let protected_end: usize = checksum_end.checked_add(protected_len)?;
    let checksum_bytes: &[u8] = bytes.get(header_at..checksum_end)?;
    let protected: &[u8] = bytes.get(checksum_end..protected_end)?;
    let expected_checksum: u32 = u32::from_le_bytes([
        checksum_bytes[0],
        checksum_bytes[1],
        checksum_bytes[2],
        checksum_bytes[3],
    ]);
    if crc32(protected) != expected_checksum {
        return None;
    }
    let (stored_size, compressed): (u64, u8) = if version.uses_wide_block_extent() {
        let signed_size: i64 = i64::from_le_bytes([
            protected[0],
            protected[1],
            protected[2],
            protected[3],
            protected[4],
            protected[5],
            protected[6],
            protected[7],
        ]);
        (u64::try_from(signed_size).ok()?, protected[8])
    } else {
        (
            u64::from(u32::from_le_bytes([
                protected[0],
                protected[1],
                protected[2],
                protected[3],
            ])),
            protected[4],
        )
    };
    if stored_size == 0 || compressed > 1 {
        return None;
    }
    Some(InnoBlockHeader {
        stored_size,
        compressed,
        stream_offset: protected_end,
    })
}

pub fn detect_innosetup(bytes: &[u8]) -> Option<InnoSetupInfo> {
    let loader: SetupLoaderOffsets = locate_setup_loader(bytes)?;
    let id_at: usize = usize::try_from(loader.header_offset).ok()?;
    inno_info_at(bytes, id_at, Some(loader))
}

fn compression_for_version(version: InnoDataVersion, compressed: u8) -> Option<InnoCompression> {
    match compressed {
        0 => Some(InnoCompression::Stored),
        1 if version >= InnoDataVersion::LZMA1_METADATA => Some(InnoCompression::Lzma1),
        1 => Some(InnoCompression::Zlib),
        _ => None,
    }
}

fn skip_inno_string(bytes: &[u8], cursor: &mut usize) -> Option<()> {
    let length: usize =
        usize::try_from(disrobe_bytes::read_u32_le_at(bytes, *cursor).ok()?).ok()?;
    if length > MAX_INNO_HEADER_STRING {
        return None;
    }
    let data_start: usize = cursor.checked_add(4)?;
    let data_end: usize = data_start.checked_add(length)?;
    bytes.get(data_start..data_end)?;
    *cursor = data_end;
    Some(())
}

fn read_inno_string<'a>(bytes: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let length: usize =
        usize::try_from(disrobe_bytes::read_u32_le_at(bytes, *cursor).ok()?).ok()?;
    if length > MAX_INNO_HEADER_STRING {
        return None;
    }
    let data_start: usize = cursor.checked_add(4)?;
    let data_end: usize = data_start.checked_add(length)?;
    let value: &[u8] = bytes.get(data_start..data_end)?;
    *cursor = data_end;
    Some(value)
}

fn skip_inno_strings(bytes: &[u8], cursor: &mut usize, count: usize) -> Option<()> {
    for _ in 0..count {
        skip_inno_string(bytes, cursor)?;
    }
    Some(())
}

fn read_inno_count(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    let value: u32 = disrobe_bytes::read_u32_le_at(bytes, *cursor).ok()?;
    if value > MAX_INNO_TABLE_ENTRIES {
        return None;
    }
    *cursor = cursor.checked_add(4)?;
    Some(value)
}

fn setup_header_prefix_string_count(version: InnoDataVersion) -> usize {
    let mut count: usize = 23;
    if version >= inno_version(5, 1, 13, 0) {
        count += 1;
    }
    if version >= inno_version(4, 2, 4, 0) {
        count += 4;
    }
    if version >= inno_version(5, 3, 8, 0) {
        count += 1;
    }
    if version >= inno_version(5, 3, 10, 0) {
        count += 1;
    }
    if version >= inno_version(5, 5, 0, 0) {
        count += 1;
    }
    if version >= inno_version(5, 5, 6, 0) {
        count += 1;
    }
    if version >= inno_version(5, 6, 1, 0) {
        count += 2;
    }
    if version >= inno_version(6, 3, 0, 0) {
        count += 2;
    }
    if version >= inno_version(6, 4, 2, 0) {
        count += 1;
    }
    if version >= inno_version(6, 5, 0, 0) {
        count += 1;
    }
    if version >= inno_version(6, 7, 0, 0) {
        count += 5;
    }
    if version >= inno_version(5, 2, 1, 0) && version < inno_version(5, 3, 10, 0) {
        count += 1;
    }
    count
}

fn parse_inno_setup_counts_with_end(
    setup_header: &[u8],
    info: &InnoSetupInfo,
) -> Result<(InnoSetupCounts, usize)> {
    let mut cursor: usize = 0;
    skip_inno_strings(
        setup_header,
        &mut cursor,
        setup_header_prefix_string_count(info.version),
    )
    .ok_or_else(|| inno_err("setup header string table is truncated or exceeds its limit"))?;
    if !info.unicode {
        let lead_bytes_end: usize = cursor
            .checked_add(32)
            .ok_or_else(|| inno_err("setup header lead-byte extent overflow"))?;
        setup_header
            .get(cursor..lead_bytes_end)
            .ok_or_else(|| inno_err("setup header lead-byte table is truncated"))?;
        cursor = lead_bytes_end;
    }
    let languages: u32 = read_inno_count(setup_header, &mut cursor)
        .ok_or_else(|| inno_err("setup language count is invalid"))?;
    let messages: u32 = if info.version >= inno_version(4, 2, 1, 0) {
        read_inno_count(setup_header, &mut cursor)
            .ok_or_else(|| inno_err("setup message count is invalid"))?
    } else {
        0
    };
    let permissions: u32 = if info.version >= inno_version(4, 1, 0, 0) {
        read_inno_count(setup_header, &mut cursor)
            .ok_or_else(|| inno_err("setup permission count is invalid"))?
    } else {
        0
    };
    let types: u32 = read_inno_count(setup_header, &mut cursor)
        .ok_or_else(|| inno_err("setup type count is invalid"))?;
    let components: u32 = read_inno_count(setup_header, &mut cursor)
        .ok_or_else(|| inno_err("setup component count is invalid"))?;
    let tasks: u32 = read_inno_count(setup_header, &mut cursor)
        .ok_or_else(|| inno_err("setup task count is invalid"))?;
    let directories: u32 = read_inno_count(setup_header, &mut cursor)
        .ok_or_else(|| inno_err("setup directory count is invalid"))?;
    let issig_keys: u32 = if info.version >= inno_version(6, 5, 0, 0) {
        read_inno_count(setup_header, &mut cursor)
            .ok_or_else(|| inno_err("setup ISSig key count is invalid"))?
    } else {
        0
    };
    let mut entries: [u32; 9] = [0; 9];
    for value in &mut entries {
        *value = read_inno_count(setup_header, &mut cursor)
            .ok_or_else(|| inno_err("setup entry count is invalid"))?;
    }
    let counts: InnoSetupCounts = InnoSetupCounts {
        languages,
        messages,
        permissions,
        types,
        components,
        tasks,
        directories,
        issig_keys,
        files: entries[0],
        data_entries: entries[1],
        icons: entries[2],
        ini_entries: entries[3],
        registry_entries: entries[4],
        delete_entries: entries[5],
        uninstall_delete_entries: entries[6],
        run_entries: entries[7],
        uninstall_run_entries: entries[8],
    };
    let total: u32 = [
        counts.languages,
        counts.messages,
        counts.permissions,
        counts.types,
        counts.components,
        counts.tasks,
        counts.directories,
        counts.issig_keys,
        counts.files,
        counts.data_entries,
        counts.icons,
        counts.ini_entries,
        counts.registry_entries,
        counts.delete_entries,
        counts.uninstall_delete_entries,
        counts.run_entries,
        counts.uninstall_run_entries,
    ]
    .into_iter()
    .try_fold(0u32, u32::checked_add)
    .ok_or_else(|| inno_err("setup entry count total overflow"))?;
    if total > MAX_INNO_TOTAL_ENTRIES {
        return Err(inno_err("setup entry count total exceeds its limit"));
    }
    Ok((counts, cursor))
}

pub fn parse_inno_setup_counts(
    setup_header: &[u8],
    info: &InnoSetupInfo,
) -> Result<InnoSetupCounts> {
    parse_inno_setup_counts_with_end(setup_header, info)
        .map(|(counts, _cursor): (InnoSetupCounts, usize)| counts)
}

fn advance_inno_cursor(
    bytes: &[u8],
    cursor: &mut usize,
    length: usize,
    label: &'static str,
) -> Result<()> {
    let end: usize = cursor
        .checked_add(length)
        .ok_or_else(|| inno_err(format!("{label} extent overflows")))?;
    bytes
        .get(*cursor..end)
        .ok_or_else(|| inno_err(format!("{label} is truncated")))?;
    *cursor = end;
    Ok(())
}

fn parse_inno_header_layout(
    setup_header: &[u8],
    info: &InnoSetupInfo,
    mut cursor: usize,
) -> Result<(InnoFileCompression, u32, usize)> {
    if info.version >= inno_version(7, 0, 0, 3) {
        advance_inno_cursor(setup_header, &mut cursor, 4, "setup compiled-code version")?;
    }
    advance_inno_cursor(setup_header, &mut cursor, 20, "setup Windows version range")?;
    if info.version < inno_version(6, 4, 0, 1) {
        advance_inno_cursor(setup_header, &mut cursor, 8, "setup background colors")?;
    }
    if info.version < inno_version(5, 5, 7, 0) {
        advance_inno_cursor(setup_header, &mut cursor, 4, "setup image background color")?;
    }
    if info.version < inno_version(5, 0, 4, 0) {
        advance_inno_cursor(
            setup_header,
            &mut cursor,
            4,
            "setup small-image background color",
        )?;
    }
    if info.version >= inno_version(6, 0, 0, 0) {
        advance_inno_cursor(setup_header, &mut cursor, 9, "setup wizard style")?;
    }
    if info.version >= inno_version(5, 5, 7, 0) {
        advance_inno_cursor(setup_header, &mut cursor, 1, "setup image alpha format")?;
    }
    if info.version >= inno_version(6, 5, 2, 0) {
        advance_inno_cursor(setup_header, &mut cursor, 8, "setup wizard image colors")?;
    }
    if info.version >= inno_version(6, 7, 0, 0) {
        advance_inno_cursor(setup_header, &mut cursor, 4, "setup wizard back color")?;
    }
    if info.version >= inno_version(6, 6, 0, 0) {
        advance_inno_cursor(
            setup_header,
            &mut cursor,
            8,
            "setup dynamic-dark wizard image colors",
        )?;
    }
    if info.version >= inno_version(6, 7, 0, 0) {
        advance_inno_cursor(
            setup_header,
            &mut cursor,
            4,
            "setup dynamic-dark wizard back color",
        )?;
    }
    if info.version >= inno_version(6, 6, 1, 0) {
        advance_inno_cursor(setup_header, &mut cursor, 1, "setup wizard image opacity")?;
    }
    if info.version >= inno_version(6, 7, 0, 0) {
        advance_inno_cursor(
            setup_header,
            &mut cursor,
            2,
            "setup wizard back-image presentation",
        )?;
    }
    let password_length: usize = if info.version >= inno_version(6, 5, 0, 0) {
        0
    } else if info.version >= inno_version(6, 4, 0, 0) {
        4
    } else if info.version >= inno_version(5, 3, 9, 0) {
        20
    } else if info.version >= inno_version(4, 2, 0, 0) {
        16
    } else {
        4
    };
    advance_inno_cursor(
        setup_header,
        &mut cursor,
        password_length,
        "setup password checksum",
    )?;
    let salt_length: usize = if info.version >= inno_version(6, 5, 0, 0) {
        0
    } else if info.version >= inno_version(6, 4, 0, 0) {
        44
    } else if info.version >= inno_version(4, 2, 2, 0) {
        8
    } else {
        0
    };
    advance_inno_cursor(
        setup_header,
        &mut cursor,
        salt_length,
        "setup password salt",
    )?;
    advance_inno_cursor(
        setup_header,
        &mut cursor,
        8,
        "setup extra disk-space requirement",
    )?;
    let slices_per_disk: u32 = read_inno_u32(setup_header, &mut cursor)
        .ok_or_else(|| inno_err("setup slices-per-disk value is truncated"))?;
    if slices_per_disk == 0 {
        return Err(inno_err("setup slices-per-disk value is zero"));
    }
    if info.version < inno_version(5, 0, 0, 0) {
        advance_inno_cursor(setup_header, &mut cursor, 1, "setup install mode")?;
    }
    advance_inno_cursor(setup_header, &mut cursor, 1, "setup uninstall log mode")?;
    if info.version < inno_version(5, 0, 0, 0) {
        advance_inno_cursor(setup_header, &mut cursor, 1, "setup uninstall style")?;
    }
    advance_inno_cursor(setup_header, &mut cursor, 1, "setup directory warning mode")?;
    advance_inno_cursor(setup_header, &mut cursor, 1, "setup privilege mode")?;
    if info.version >= inno_version(5, 7, 0, 0) {
        advance_inno_cursor(
            setup_header,
            &mut cursor,
            1,
            "setup privilege override flags",
        )?;
    }
    if info.version >= inno_version(4, 0, 10, 0) {
        advance_inno_cursor(
            setup_header,
            &mut cursor,
            2,
            "setup language selection modes",
        )?;
    }
    if info.version < inno_version(4, 1, 5, 0) {
        let compression: InnoFileCompression =
            parse_legacy_inno_file_compression(setup_header, cursor, info.version)?;
        let flag_count: usize = setup_option_flag_count(info.version, info.unicode);
        advance_packed_inno_flags(setup_header, &mut cursor, flag_count, "setup option flags")?;
        return Ok((compression, slices_per_disk, cursor));
    }
    let stored: u8 = *setup_header
        .get(cursor)
        .ok_or_else(|| inno_err("setup file compression method is truncated"))?;
    let compression: InnoFileCompression = if info.version >= inno_version(5, 3, 9, 0) {
        match stored {
            0 => InnoFileCompression::Stored,
            1 => InnoFileCompression::Zlib,
            2 => InnoFileCompression::Bzip2,
            3 => InnoFileCompression::Lzma1,
            4 => InnoFileCompression::Lzma2,
            _ => return Err(inno_err("setup file compression method is invalid")),
        }
    } else if info.version >= inno_version(4, 2, 6, 0) {
        match stored {
            0 => InnoFileCompression::Stored,
            1 => InnoFileCompression::Zlib,
            2 => InnoFileCompression::Bzip2,
            3 => InnoFileCompression::Lzma1,
            _ => return Err(inno_err("setup file compression method is invalid")),
        }
    } else if info.version >= inno_version(4, 2, 5, 0) {
        match stored {
            0 => InnoFileCompression::Stored,
            1 => InnoFileCompression::Bzip2,
            2 => InnoFileCompression::Lzma1,
            _ => return Err(inno_err("setup file compression method is invalid")),
        }
    } else {
        match stored {
            0 => InnoFileCompression::Zlib,
            1 => InnoFileCompression::Bzip2,
            2 => InnoFileCompression::Lzma1,
            _ => return Err(inno_err("setup file compression method is invalid")),
        }
    };
    cursor = cursor
        .checked_add(1)
        .ok_or_else(|| inno_err("setup file compression cursor overflow"))?;
    if info.version < inno_version(6, 3, 0, 0) && info.version >= inno_version(5, 1, 0, 0) {
        advance_inno_cursor(setup_header, &mut cursor, 2, "setup architecture flags")?;
    }
    if info.version >= inno_version(5, 2, 1, 0) && info.version < inno_version(5, 3, 10, 0) {
        advance_inno_cursor(
            setup_header,
            &mut cursor,
            8,
            "setup signed-uninstaller metadata",
        )?;
    }
    if info.version >= inno_version(5, 3, 3, 0) {
        advance_inno_cursor(setup_header, &mut cursor, 2, "setup page modes")?;
    }
    if info.version >= inno_version(5, 5, 0, 0) {
        advance_inno_cursor(setup_header, &mut cursor, 8, "setup uninstall display size")?;
    } else if info.version >= inno_version(5, 3, 6, 0) {
        advance_inno_cursor(setup_header, &mut cursor, 4, "setup uninstall display size")?;
    }
    if matches!(
        info.version,
        InnoDataVersion {
            major: 5,
            minor: 3,
            patch: 10,
            revision: 1
        } | InnoDataVersion {
            major: 5,
            minor: 4,
            patch: 2,
            revision: 1
        } | InnoDataVersion {
            major: 5,
            minor: 5,
            patch: 0,
            revision: 1
        }
    ) {
        advance_inno_cursor(setup_header, &mut cursor, 1, "setup variant byte")?;
    }
    advance_packed_inno_flags(
        setup_header,
        &mut cursor,
        setup_option_flag_count(info.version, info.unicode),
        "setup option flags",
    )?;
    Ok((compression, slices_per_disk, cursor))
}

fn setup_option_flag_count(version: InnoDataVersion, unicode: bool) -> usize {
    if version >= inno_version(6, 7, 0, 0) {
        return 57;
    }
    let mut count: usize = 0;
    count += 1;
    count += usize::from(version < inno_version(5, 3, 10, 0));
    count += 1;
    count += usize::from(version < inno_version(5, 3, 3, 0));
    count += usize::from(version < inno_version(5, 3, 3, 0));
    count += 1;
    count += 1;
    count += 1;
    count += usize::from(version < inno_version(6, 4, 0, 1)) * 4;
    count += 1;
    count += usize::from(version < inno_version(4, 1, 2, 0));
    count += 1;
    count += 1;
    count += 1;
    count += usize::from(version < inno_version(5, 6, 1, 0));
    count += usize::from(version >= inno_version(1, 3, 0, 0) && version < inno_version(5, 3, 8, 0));
    count += 1;
    count += usize::from(version < inno_version(6, 4, 0, 1));
    count += 1;
    count += 1;
    count += 1;
    count += 6;
    count += 2;
    count +=
        usize::from(version >= inno_version(2, 0, 17, 0) && version < inno_version(4, 1, 5, 0));
    count += 1;
    count += 2;
    count += 1;
    count += 1;
    count += 1;
    count +=
        usize::from(version >= inno_version(4, 0, 0, 0) && version < inno_version(4, 0, 10, 0));
    count +=
        usize::from(version >= inno_version(4, 0, 1, 0) && version < inno_version(4, 0, 10, 0));
    count += 1;
    count += usize::from(version >= inno_version(4, 1, 3, 0));
    count += usize::from(version >= inno_version(4, 1, 8, 0)) * 2;
    count += usize::from(version >= inno_version(4, 2, 2, 0));
    count -= usize::from(version >= inno_version(6, 5, 0, 0));
    count += usize::from(version >= inno_version(5, 0, 4, 0) && version < inno_version(5, 6, 1, 0));
    count += usize::from(version >= inno_version(5, 1, 7, 0) && !unicode);
    count += usize::from(version >= inno_version(5, 1, 13, 0));
    count += usize::from(version >= inno_version(5, 2, 1, 0));
    count += usize::from(version >= inno_version(5, 3, 8, 0));
    count += usize::from(version >= inno_version(5, 3, 9, 0));
    count += usize::from(version >= inno_version(5, 5, 0, 0)) * 3;
    count += usize::from(version >= inno_version(5, 5, 7, 0));
    count += usize::from(version >= inno_version(6, 0, 0, 0)) * 3;
    count -= usize::from(version >= inno_version(6, 6, 0, 0));
    count += usize::from(version >= inno_version(6, 3, 0, 0));
    count += usize::from(version >= inno_version(6, 6, 0, 0)) * 4;
    count
}

fn advance_packed_inno_flags(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    label: &'static str,
) -> Result<()> {
    let mut byte_count: usize = count.div_ceil(8);
    if byte_count == 3 {
        byte_count = 4;
    }
    let start: usize = *cursor;
    advance_inno_cursor(bytes, cursor, byte_count, label)?;
    let used_bits: usize = count % 8;
    if used_bits != 0 {
        let last_data_byte: usize = start
            .checked_add(count.div_ceil(8) - 1)
            .ok_or_else(|| inno_err(format!("{label} extent overflows")))?;
        if bytes
            .get(last_data_byte)
            .is_some_and(|byte: &u8| byte >> used_bits != 0)
        {
            return Err(inno_err(format!("{label} contain undefined bits")));
        }
    }
    Ok(())
}

fn skip_inno_condition_data(
    bytes: &[u8],
    cursor: &mut usize,
    version: InnoDataVersion,
) -> Result<()> {
    let count: usize = if version >= inno_version(4, 1, 0, 0) {
        6
    } else {
        4
    };
    skip_inno_strings(bytes, cursor, count)
        .ok_or_else(|| inno_err("setup condition data is truncated or exceeds its limit"))
}

fn skip_inno_language_entry(bytes: &[u8], cursor: &mut usize, info: &InnoSetupInfo) -> Result<()> {
    let string_count: usize = if info.version >= inno_version(6, 6, 0, 0) {
        8
    } else if info.version == inno_version(5, 5, 7, 1) {
        11
    } else {
        10
    };
    skip_inno_strings(bytes, cursor, string_count)
        .ok_or_else(|| inno_err("setup language entry strings are truncated"))?;
    let mut fixed_size: usize = if info.version >= inno_version(6, 6, 0, 0) {
        18
    } else {
        20
    };
    if info.version >= inno_version(4, 2, 2, 0)
        && (!info.unicode || info.version < inno_version(5, 3, 0, 0))
    {
        fixed_size += 4;
    }
    if info.version < inno_version(4, 1, 0, 0) {
        fixed_size += 4;
    }
    if info.version == inno_version(5, 5, 7, 1) {
        fixed_size += 4;
    }
    if info.version >= inno_version(5, 2, 3, 0) {
        fixed_size += 1;
    }
    advance_inno_cursor(bytes, cursor, fixed_size, "setup language entry")
}

fn skip_inno_pre_file_tables(
    bytes: &[u8],
    mut cursor: usize,
    info: &InnoSetupInfo,
    counts: InnoSetupCounts,
) -> Result<usize> {
    for _ in 0..counts.languages {
        skip_inno_language_entry(bytes, &mut cursor, info)?;
    }
    for _ in 0..counts.messages {
        skip_inno_strings(bytes, &mut cursor, 2)
            .ok_or_else(|| inno_err("setup message entry strings are truncated"))?;
        advance_inno_cursor(bytes, &mut cursor, 4, "setup message entry")?;
    }
    for _ in 0..counts.permissions {
        skip_inno_string(bytes, &mut cursor)
            .ok_or_else(|| inno_err("setup permission entry is truncated"))?;
    }
    for _ in 0..counts.types {
        skip_inno_strings(bytes, &mut cursor, 4)
            .ok_or_else(|| inno_err("setup type entry strings are truncated"))?;
        advance_inno_cursor(bytes, &mut cursor, 30, "setup type entry")?;
    }
    for _ in 0..counts.components {
        skip_inno_strings(bytes, &mut cursor, 5)
            .ok_or_else(|| inno_err("setup component entry strings are truncated"))?;
        let fixed_size: usize = if info.version >= inno_version(6, 7, 0, 0) {
            39
        } else {
            42
        };
        advance_inno_cursor(bytes, &mut cursor, fixed_size, "setup component entry")?;
    }
    for _ in 0..counts.tasks {
        skip_inno_strings(bytes, &mut cursor, 6)
            .ok_or_else(|| inno_err("setup task entry strings are truncated"))?;
        let fixed_size: usize = if info.version >= inno_version(6, 7, 0, 0) {
            23
        } else {
            26
        };
        advance_inno_cursor(bytes, &mut cursor, fixed_size, "setup task entry")?;
    }
    for _ in 0..counts.directories {
        skip_inno_string(bytes, &mut cursor)
            .ok_or_else(|| inno_err("setup directory name is truncated"))?;
        skip_inno_condition_data(bytes, &mut cursor, info.version)?;
        if info.version >= inno_version(4, 0, 11, 0) && info.version < inno_version(4, 1, 0, 0) {
            skip_inno_string(bytes, &mut cursor)
                .ok_or_else(|| inno_err("setup directory permission string is truncated"))?;
        }
        let fixed_size: usize = if info.version >= inno_version(4, 1, 0, 0) {
            27
        } else {
            25
        };
        advance_inno_cursor(bytes, &mut cursor, fixed_size, "setup directory entry")?;
    }
    for _ in 0..counts.issig_keys {
        skip_inno_strings(bytes, &mut cursor, 3)
            .ok_or_else(|| inno_err("setup ISSig key entry is truncated"))?;
    }
    Ok(cursor)
}

fn decode_inno_string(bytes: &[u8], unicode: bool) -> Result<String> {
    if unicode {
        if !bytes.len().is_multiple_of(2) {
            return Err(inno_err("setup UTF-16 string has an odd byte length"));
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair: &[u8]| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        return String::from_utf16(&units).map_err(|_error: std::string::FromUtf16Error| {
            inno_err("setup UTF-16 string is invalid")
        });
    }
    let mut value: String = String::new();
    for byte in bytes {
        if *byte < 0x80 || *byte >= 0xA0 {
            let character: char = char::from_u32(u32::from(*byte))
                .ok_or_else(|| inno_err("setup ANSI string contains an invalid byte"))?;
            value.push(character);
        } else if let Some(character) = decode_windows_1252_byte(*byte) {
            value.push(character);
        } else {
            use std::fmt::Write as _;
            write!(&mut value, "%{byte:02X}").map_err(|_error: std::fmt::Error| {
                inno_err("setup ANSI string conversion failed")
            })?;
        }
    }
    Ok(value)
}

const fn decode_windows_1252_byte(byte: u8) -> Option<char> {
    match byte {
        0x80 => Some('\u{20AC}'),
        0x82 => Some('\u{201A}'),
        0x83 => Some('\u{0192}'),
        0x84 => Some('\u{201E}'),
        0x85 => Some('\u{2026}'),
        0x86 => Some('\u{2020}'),
        0x87 => Some('\u{2021}'),
        0x88 => Some('\u{02C6}'),
        0x89 => Some('\u{2030}'),
        0x8A => Some('\u{0160}'),
        0x8B => Some('\u{2039}'),
        0x8C => Some('\u{0152}'),
        0x8E => Some('\u{017D}'),
        0x91 => Some('\u{2018}'),
        0x92 => Some('\u{2019}'),
        0x93 => Some('\u{201C}'),
        0x94 => Some('\u{201D}'),
        0x95 => Some('\u{2022}'),
        0x96 => Some('\u{2013}'),
        0x97 => Some('\u{2014}'),
        0x98 => Some('\u{02DC}'),
        0x99 => Some('\u{2122}'),
        0x9A => Some('\u{0161}'),
        0x9B => Some('\u{203A}'),
        0x9C => Some('\u{0153}'),
        0x9E => Some('\u{017E}'),
        0x9F => Some('\u{0178}'),
        _ => None,
    }
}

fn inno_file_option_count(version: InnoDataVersion) -> usize {
    let mut count: usize = 21;
    count += usize::from(version >= inno_version(4, 1, 8, 0));
    count += usize::from(version >= inno_version(4, 2, 1, 0));
    count += usize::from(version >= inno_version(4, 2, 5, 0));
    count += usize::from(version >= inno_version(5, 0, 3, 0));
    count += usize::from(version >= inno_version(5, 1, 0, 0));
    count += usize::from(version >= inno_version(5, 1, 2, 0)) * 2;
    count += usize::from(version >= inno_version(5, 2, 0, 0)) * 3;
    count += usize::from(version >= inno_version(5, 2, 5, 0));
    count += usize::from(version >= inno_version(6, 5, 0, 0)) * 2;
    count -= usize::from(version >= inno_version(7, 0, 0, 3)) * 2;
    count
}

fn parse_inno_setup_files_with_end(
    bytes: &[u8],
    cursor: usize,
    info: &InnoSetupInfo,
    counts: InnoSetupCounts,
) -> Result<(Vec<InnoSetupFile>, usize)> {
    let mut cursor: usize = skip_inno_pre_file_tables(bytes, cursor, info, counts)?;
    let capacity: usize = usize::try_from(counts.files)
        .map_err(|_error: std::num::TryFromIntError| inno_err("setup file count overflow"))?;
    let mut files: Vec<InnoSetupFile> = Vec::with_capacity(capacity);
    let mut name_bytes: usize = 0;
    for _ in 0..counts.files {
        let source_bytes: &[u8] = read_inno_string(bytes, &mut cursor)
            .ok_or_else(|| inno_err("setup file source is truncated"))?;
        let destination_bytes: &[u8] = read_inno_string(bytes, &mut cursor)
            .ok_or_else(|| inno_err("setup file destination is truncated"))?;
        name_bytes = name_bytes
            .checked_add(source_bytes.len())
            .and_then(|total: usize| total.checked_add(destination_bytes.len()))
            .ok_or_else(|| inno_err("setup file-name byte count overflow"))?;
        if name_bytes > MAX_INNO_FILE_NAME_BYTES {
            return Err(inno_err("setup file names exceed their aggregate limit"));
        }
        skip_inno_string(bytes, &mut cursor)
            .ok_or_else(|| inno_err("setup file font name is truncated"))?;
        if info.version >= inno_version(5, 2, 5, 0) {
            skip_inno_string(bytes, &mut cursor)
                .ok_or_else(|| inno_err("setup file assembly name is truncated"))?;
        }
        skip_inno_condition_data(bytes, &mut cursor, info.version)?;
        if info.version >= inno_version(6, 5, 0, 0) {
            skip_inno_strings(bytes, &mut cursor, 6)
                .ok_or_else(|| inno_err("setup file verification strings are truncated"))?;
            advance_inno_cursor(bytes, &mut cursor, 33, "setup file verification")?;
        }
        advance_inno_cursor(bytes, &mut cursor, 20, "setup file Windows version range")?;
        let data_entry_index: u32 = read_inno_u32(bytes, &mut cursor)
            .ok_or_else(|| inno_err("setup file data-entry index is truncated"))?;
        advance_inno_cursor(bytes, &mut cursor, 4, "setup file attributes")?;
        let external_size: u64 = read_inno_u64(bytes, &mut cursor)
            .ok_or_else(|| inno_err("setup file external size is truncated"))?;
        if info.version >= inno_version(4, 1, 0, 0) {
            advance_inno_cursor(bytes, &mut cursor, 2, "setup file permission")?;
        }
        let option_count: usize = inno_file_option_count(info.version);
        if info.version >= inno_version(7, 0, 0, 3) {
            let bitness: u8 = *bytes
                .get(cursor)
                .ok_or_else(|| inno_err("setup file bitness is truncated"))?;
            if bitness > 4 {
                return Err(inno_err("setup file bitness is invalid"));
            }
            cursor = cursor
                .checked_add(1)
                .ok_or_else(|| inno_err("setup file bitness cursor overflow"))?;
        }
        let option_bytes: usize = if info.version >= inno_version(6, 7, 0, 0) {
            8
        } else {
            let packed: usize = option_count.div_ceil(8);
            if packed == 3 { 4 } else { packed }
        };
        let option_end: usize = cursor
            .checked_add(option_bytes)
            .ok_or_else(|| inno_err("setup file option extent overflow"))?;
        let options: &[u8] = bytes
            .get(cursor..option_end)
            .ok_or_else(|| inno_err("setup file option flags are truncated"))?;
        cursor = option_end;
        let used_bits: usize = option_count % 8;
        if used_bits != 0
            && options
                .get(option_count / 8)
                .is_some_and(|byte: &u8| byte >> used_bits != 0)
        {
            return Err(inno_err("setup file option flags contain undefined bits"));
        }
        let file_type: u8 = *bytes
            .get(cursor)
            .ok_or_else(|| inno_err("setup file type is truncated"))?;
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| inno_err("setup file cursor overflow"))?;
        let max_file_type: u8 = if info.version < inno_version(5, 0, 0, 0) {
            2
        } else {
            1
        };
        if file_type > max_file_type {
            return Err(inno_err("setup file type is invalid"));
        }
        files.push(InnoSetupFile {
            source: decode_inno_string(source_bytes, info.unicode)?,
            destination: decode_inno_string(destination_bytes, info.unicode)?,
            data_entry_index,
            external_size,
            options: options
                .iter()
                .take(4)
                .enumerate()
                .fold(0_u32, |value: u32, (index, byte): (usize, &u8)| {
                    value | (u32::from(*byte) << (index * 8))
                }),
            file_type,
        });
    }
    Ok((files, cursor))
}

#[cfg(test)]
fn parse_inno_setup_files(
    bytes: &[u8],
    cursor: usize,
    info: &InnoSetupInfo,
    counts: InnoSetupCounts,
) -> Result<Vec<InnoSetupFile>> {
    parse_inno_setup_files_with_end(bytes, cursor, info, counts)
        .map(|(files, _cursor): (Vec<InnoSetupFile>, usize)| files)
}

fn read_inno_enum(
    bytes: &[u8],
    cursor: &mut usize,
    maximum: u8,
    label: &'static str,
) -> Result<()> {
    let value: u8 = *bytes
        .get(*cursor)
        .ok_or_else(|| inno_err(format!("{label} is truncated")))?;
    if value > maximum {
        return Err(inno_err(format!("{label} is invalid")));
    }
    *cursor = cursor
        .checked_add(1)
        .ok_or_else(|| inno_err(format!("{label} cursor overflows")))?;
    Ok(())
}

fn inno_icon_option_count(version: InnoDataVersion) -> usize {
    let mut count: usize = 3;
    count += usize::from(version >= inno_version(5, 0, 3, 0) && version < inno_version(6, 3, 0, 0));
    count += usize::from(version >= inno_version(5, 4, 2, 0));
    count += usize::from(version >= inno_version(5, 5, 0, 0));
    count += usize::from(version >= inno_version(6, 1, 0, 0));
    count
}

fn inno_registry_option_count(version: InnoDataVersion) -> usize {
    10 + usize::from(version >= inno_version(5, 1, 0, 0) && version < inno_version(7, 0, 0, 3)) * 2
}

fn inno_run_option_count(version: InnoDataVersion) -> usize {
    let mut count: usize = 7;
    count +=
        usize::from(version >= inno_version(5, 1, 10, 0) && version < inno_version(7, 0, 0, 3)) * 2;
    count += usize::from(version >= inno_version(5, 2, 0, 0));
    count += usize::from(version >= inno_version(6, 1, 0, 0));
    count += usize::from(version >= inno_version(6, 3, 0, 0));
    count
}

fn skip_inno_icon_entry(bytes: &[u8], cursor: &mut usize, info: &InnoSetupInfo) -> Result<()> {
    skip_inno_strings(bytes, cursor, 6)
        .ok_or_else(|| inno_err("setup icon strings are truncated"))?;
    skip_inno_condition_data(bytes, cursor, info.version)?;
    if info.version >= inno_version(5, 3, 5, 0) {
        skip_inno_string(bytes, cursor)
            .ok_or_else(|| inno_err("setup icon application identifier is truncated"))?;
    }
    if info.version >= inno_version(6, 1, 0, 0) {
        advance_inno_cursor(bytes, cursor, 16, "setup icon activator identifier")?;
    }
    advance_inno_cursor(bytes, cursor, 28, "setup icon numeric fields")?;
    read_inno_enum(bytes, cursor, 2, "setup icon close mode")?;
    advance_inno_cursor(bytes, cursor, 2, "setup icon hotkey")?;
    advance_packed_inno_flags(
        bytes,
        cursor,
        inno_icon_option_count(info.version),
        "setup icon option flags",
    )
}

fn skip_inno_ini_entry(bytes: &[u8], cursor: &mut usize, info: &InnoSetupInfo) -> Result<()> {
    skip_inno_strings(bytes, cursor, 4)
        .ok_or_else(|| inno_err("setup INI strings are truncated"))?;
    skip_inno_condition_data(bytes, cursor, info.version)?;
    advance_inno_cursor(bytes, cursor, 20, "setup INI Windows version range")?;
    advance_packed_inno_flags(bytes, cursor, 5, "setup INI option flags")
}

fn skip_inno_registry_entry(bytes: &[u8], cursor: &mut usize, info: &InnoSetupInfo) -> Result<()> {
    skip_inno_strings(bytes, cursor, 3)
        .ok_or_else(|| inno_err("setup registry strings are truncated"))?;
    skip_inno_condition_data(bytes, cursor, info.version)?;
    if info.version >= inno_version(4, 0, 11, 0) && info.version < inno_version(4, 1, 0, 0) {
        skip_inno_string(bytes, cursor)
            .ok_or_else(|| inno_err("setup registry permission data is truncated"))?;
    }
    advance_inno_cursor(bytes, cursor, 24, "setup registry numeric fields")?;
    if info.version >= inno_version(4, 1, 0, 0) {
        advance_inno_cursor(bytes, cursor, 2, "setup registry permission")?;
    }
    let maximum_type: u8 = if info.version >= inno_version(5, 2, 5, 0) {
        6
    } else {
        5
    };
    read_inno_enum(bytes, cursor, maximum_type, "setup registry value type")?;
    if info.version >= inno_version(7, 0, 0, 3) {
        read_inno_enum(bytes, cursor, 4, "setup registry bitness")?;
    }
    advance_packed_inno_flags(
        bytes,
        cursor,
        inno_registry_option_count(info.version),
        "setup registry option flags",
    )
}

fn skip_inno_delete_entry(bytes: &[u8], cursor: &mut usize, info: &InnoSetupInfo) -> Result<()> {
    skip_inno_string(bytes, cursor).ok_or_else(|| inno_err("setup delete target is truncated"))?;
    skip_inno_condition_data(bytes, cursor, info.version)?;
    advance_inno_cursor(bytes, cursor, 20, "setup delete Windows version range")?;
    read_inno_enum(bytes, cursor, 2, "setup delete target type")
}

fn skip_inno_run_entry(bytes: &[u8], cursor: &mut usize, info: &InnoSetupInfo) -> Result<()> {
    let mut string_count: usize = 4;
    string_count += usize::from(info.version >= inno_version(2, 0, 2, 0));
    string_count += usize::from(info.version >= inno_version(5, 1, 13, 0));
    string_count += 1;
    string_count += usize::from(info.version >= inno_version(7, 0, 0, 3));
    skip_inno_strings(bytes, cursor, string_count)
        .ok_or_else(|| inno_err("setup run strings are truncated"))?;
    skip_inno_condition_data(bytes, cursor, info.version)?;
    advance_inno_cursor(bytes, cursor, 24, "setup run numeric fields")?;
    read_inno_enum(bytes, cursor, 2, "setup run wait mode")?;
    if info.version >= inno_version(7, 0, 0, 3) {
        read_inno_enum(bytes, cursor, 4, "setup run bitness")?;
    }
    advance_packed_inno_flags(
        bytes,
        cursor,
        inno_run_option_count(info.version),
        "setup run option flags",
    )
}

fn skip_inno_wizard_images(
    bytes: &[u8],
    cursor: &mut usize,
    version: InnoDataVersion,
    label: &'static str,
    shared_copy_allowed: bool,
) -> Result<()> {
    let count: u32 = if version >= inno_version(5, 6, 0, 0) {
        let value: u32 = read_inno_u32(bytes, cursor)
            .ok_or_else(|| inno_err(format!("{label} count is truncated")))?;
        if shared_copy_allowed && value == u32::MAX {
            return Ok(());
        }
        if value > MAX_INNO_TABLE_ENTRIES {
            return Err(inno_err(format!("{label} count exceeds its limit")));
        }
        value
    } else {
        1
    };
    for _ in 0..count {
        skip_inno_string(bytes, cursor)
            .ok_or_else(|| inno_err(format!("{label} data is truncated")))?;
    }
    Ok(())
}

fn validate_inno_primary_tail(
    bytes: &[u8],
    mut cursor: usize,
    info: &InnoSetupInfo,
    counts: InnoSetupCounts,
    compression: InnoFileCompression,
) -> Result<()> {
    for _ in 0..counts.icons {
        skip_inno_icon_entry(bytes, &mut cursor, info)?;
    }
    for _ in 0..counts.ini_entries {
        skip_inno_ini_entry(bytes, &mut cursor, info)?;
    }
    for _ in 0..counts.registry_entries {
        skip_inno_registry_entry(bytes, &mut cursor, info)?;
    }
    let delete_count: u32 = counts
        .delete_entries
        .checked_add(counts.uninstall_delete_entries)
        .ok_or_else(|| inno_err("setup delete entry count overflow"))?;
    for _ in 0..delete_count {
        skip_inno_delete_entry(bytes, &mut cursor, info)?;
    }
    let run_count: u32 = counts
        .run_entries
        .checked_add(counts.uninstall_run_entries)
        .ok_or_else(|| inno_err("setup run entry count overflow"))?;
    for _ in 0..run_count {
        skip_inno_run_entry(bytes, &mut cursor, info)?;
    }
    skip_inno_wizard_images(
        bytes,
        &mut cursor,
        info.version,
        "setup wizard image",
        false,
    )?;
    skip_inno_wizard_images(
        bytes,
        &mut cursor,
        info.version,
        "setup small wizard image",
        false,
    )?;
    if info.version >= inno_version(7, 0, 0, 3) {
        skip_inno_wizard_images(
            bytes,
            &mut cursor,
            info.version,
            "setup wizard back image",
            false,
        )?;
        skip_inno_wizard_images(
            bytes,
            &mut cursor,
            info.version,
            "setup dark wizard image",
            true,
        )?;
        skip_inno_wizard_images(
            bytes,
            &mut cursor,
            info.version,
            "setup dark small wizard image",
            true,
        )?;
        skip_inno_wizard_images(
            bytes,
            &mut cursor,
            info.version,
            "setup dark wizard back image",
            true,
        )?;
    }
    if compression == InnoFileCompression::Bzip2
        || (compression == InnoFileCompression::Lzma1 && info.version == inno_version(4, 1, 5, 0))
        || (compression == InnoFileCompression::Zlib && info.version >= inno_version(4, 2, 6, 0))
    {
        skip_inno_string(bytes, &mut cursor)
            .ok_or_else(|| inno_err("setup decompressor payload is truncated"))?;
    }
    if info.encrypted && info.version < inno_version(6, 4, 0, 0) {
        skip_inno_string(bytes, &mut cursor)
            .ok_or_else(|| inno_err("setup decryptor payload is truncated"))?;
    }
    if info.version >= inno_version(7, 0, 0, 3) && cursor < bytes.len() {
        skip_inno_string(bytes, &mut cursor)
            .ok_or_else(|| inno_err("setup 7-Zip payload is truncated"))?;
    }
    if cursor != bytes.len() {
        return Err(inno_err("setup primary header has trailing data"));
    }
    Ok(())
}

fn parse_legacy_inno_file_compression(
    setup_header: &[u8],
    cursor: usize,
    version: InnoDataVersion,
) -> Result<InnoFileCompression> {
    let (bzip_bit, flag_count): (usize, usize) = if version < inno_version(4, 0, 10, 0) {
        (32, 42)
    } else if version < inno_version(4, 1, 2, 0) {
        (32, 40)
    } else if version < inno_version(4, 1, 3, 0) {
        (31, 39)
    } else {
        (31, 40)
    };
    let flag_bytes: usize = flag_count.div_ceil(8);
    let end: usize = cursor
        .checked_add(flag_bytes)
        .ok_or_else(|| inno_err("setup option flag extent overflows"))?;
    let flags: &[u8] = setup_header
        .get(cursor..end)
        .ok_or_else(|| inno_err("setup option flags are truncated"))?;
    let used_last_bits: usize = flag_count % 8;
    if used_last_bits != 0
        && flags
            .last()
            .is_some_and(|byte: &u8| byte >> used_last_bits != 0)
    {
        return Err(inno_err("setup option flags contain undefined bits"));
    }
    let bzip_byte: u8 = *flags
        .get(bzip_bit / 8)
        .ok_or_else(|| inno_err("setup bzip option flag is truncated"))?;
    if bzip_byte & (1_u8 << (bzip_bit % 8)) != 0 {
        Ok(InnoFileCompression::Bzip2)
    } else {
        Ok(InnoFileCompression::Zlib)
    }
}

fn read_inno_u32(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    let value: u32 = disrobe_bytes::read_u32_le_at(bytes, *cursor).ok()?;
    *cursor = cursor.checked_add(4)?;
    Some(value)
}

fn read_inno_u64(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let value: u64 = disrobe_bytes::read_u64_le_at(bytes, *cursor).ok()?;
    *cursor = cursor.checked_add(8)?;
    Some(value)
}

fn read_inno_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Option<[u8; N]> {
    let end: usize = cursor.checked_add(N)?;
    let source: &[u8] = bytes.get(*cursor..end)?;
    let mut value: [u8; N] = [0; N];
    value.copy_from_slice(source);
    *cursor = end;
    Some(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InnoDataFlag {
    VersionValid,
    VersionInvalid,
    TimestampUtc,
    Uninstaller,
    InstructionFilter,
    Touch,
    Encrypted,
    Compressed,
    SolidBreak,
    Sign,
    SignOnce,
}

fn data_flag_layout(version: InnoDataVersion) -> [(InnoDataFlag, bool); 11] {
    [
        (InnoDataFlag::VersionValid, true),
        (
            InnoDataFlag::VersionInvalid,
            version < inno_version(6, 4, 3, 0),
        ),
        (
            InnoDataFlag::TimestampUtc,
            version >= inno_version(4, 0, 10, 0),
        ),
        (
            InnoDataFlag::Uninstaller,
            version >= inno_version(4, 1, 0, 0) && version < inno_version(6, 4, 3, 0),
        ),
        (
            InnoDataFlag::InstructionFilter,
            version >= inno_version(4, 1, 8, 0),
        ),
        (
            InnoDataFlag::Touch,
            version >= inno_version(4, 2, 0, 0) && version < inno_version(6, 4, 3, 0),
        ),
        (InnoDataFlag::Encrypted, version >= inno_version(4, 2, 2, 0)),
        (
            InnoDataFlag::Compressed,
            version >= inno_version(4, 2, 5, 0),
        ),
        (
            InnoDataFlag::SolidBreak,
            version >= inno_version(5, 1, 13, 0) && version < inno_version(6, 4, 3, 0),
        ),
        (
            InnoDataFlag::Sign,
            version >= inno_version(5, 5, 7, 0) && version < inno_version(6, 3, 0, 0),
        ),
        (
            InnoDataFlag::SignOnce,
            version >= inno_version(5, 5, 7, 0) && version < inno_version(6, 3, 0, 0),
        ),
    ]
}

fn data_flag_count(version: InnoDataVersion) -> usize {
    data_flag_layout(version)
        .into_iter()
        .filter(|(_flag, present): &(InnoDataFlag, bool)| *present)
        .count()
}

fn data_flag_position(version: InnoDataVersion, target: InnoDataFlag) -> Option<usize> {
    data_flag_layout(version)
        .into_iter()
        .filter_map(|(flag, present): (InnoDataFlag, bool)| present.then_some(flag))
        .position(|flag: InnoDataFlag| flag == target)
}

fn inno_flag(flags: &[u8], position: Option<usize>) -> bool {
    position.is_some_and(|position: usize| {
        flags
            .get(position / 8)
            .is_some_and(|byte: &u8| byte & (1_u8 << (position % 8)) != 0)
    })
}

fn legacy_sign_mode(version: InnoDataVersion, flags: &[u8]) -> InnoSignMode {
    if version < inno_version(5, 5, 7, 0) || version >= inno_version(6, 3, 0, 0) {
        return InnoSignMode::Unchanged;
    }
    if inno_flag(flags, data_flag_position(version, InnoDataFlag::SignOnce)) {
        InnoSignMode::Once
    } else if inno_flag(flags, data_flag_position(version, InnoDataFlag::Sign)) {
        InnoSignMode::Yes
    } else {
        InnoSignMode::Unchanged
    }
}

pub fn parse_inno_data_entries(
    secondary_header: &[u8],
    info: &InnoSetupInfo,
    count: u32,
) -> Result<Vec<InnoDataEntry>> {
    if count > MAX_INNO_TABLE_ENTRIES {
        return Err(inno_err("setup data-entry count exceeds its limit"));
    }
    let capacity: usize = usize::try_from(count)
        .map_err(|_error: std::num::TryFromIntError| inno_err("data-entry count overflow"))?;
    let mut entries: Vec<InnoDataEntry> = Vec::with_capacity(capacity);
    let mut cursor: usize = 0;
    for _ in 0..count {
        let first_slice: u32 = read_inno_u32(secondary_header, &mut cursor)
            .ok_or_else(|| inno_err("data entry first slice is truncated"))?;
        let last_slice: u32 = read_inno_u32(secondary_header, &mut cursor)
            .ok_or_else(|| inno_err("data entry last slice is truncated"))?;
        if first_slice > last_slice {
            return Err(inno_err("data entry slice range is reversed"));
        }
        let chunk_offset: u64 = if info.version >= inno_version(6, 5, 2, 0) {
            read_inno_u64(secondary_header, &mut cursor)
                .ok_or_else(|| inno_err("data entry chunk offset is truncated"))?
        } else {
            u64::from(
                read_inno_u32(secondary_header, &mut cursor)
                    .ok_or_else(|| inno_err("data entry chunk offset is truncated"))?,
            )
        };
        let file_offset: u64 = read_inno_u64(secondary_header, &mut cursor)
            .ok_or_else(|| inno_err("data entry file offset is truncated"))?;
        let file_size: u64 = read_inno_u64(secondary_header, &mut cursor)
            .ok_or_else(|| inno_err("data entry file size is truncated"))?;
        let chunk_size: u64 = read_inno_u64(secondary_header, &mut cursor)
            .ok_or_else(|| inno_err("data entry chunk size is truncated"))?;
        let checksum: InnoChecksum = if info.version >= inno_version(6, 4, 0, 0) {
            InnoChecksum::Sha256(
                read_inno_array(secondary_header, &mut cursor)
                    .ok_or_else(|| inno_err("data entry SHA-256 is truncated"))?,
            )
        } else if info.version >= inno_version(5, 3, 9, 0) {
            InnoChecksum::Sha1(
                read_inno_array(secondary_header, &mut cursor)
                    .ok_or_else(|| inno_err("data entry SHA-1 is truncated"))?,
            )
        } else if info.version >= inno_version(4, 2, 0, 0) {
            InnoChecksum::Md5(
                read_inno_array(secondary_header, &mut cursor)
                    .ok_or_else(|| inno_err("data entry MD5 is truncated"))?,
            )
        } else {
            InnoChecksum::Crc32(
                read_inno_u32(secondary_header, &mut cursor)
                    .ok_or_else(|| inno_err("data entry CRC32 is truncated"))?,
            )
        };
        let filetime: i64 = i64::from_le_bytes(
            read_inno_array(secondary_header, &mut cursor)
                .ok_or_else(|| inno_err("data entry timestamp is truncated"))?,
        );
        let unix_ticks: i64 = filetime
            .checked_sub(116_444_736_000_000_000)
            .ok_or_else(|| inno_err("data entry timestamp underflows"))?;
        let timestamp_seconds: i64 = unix_ticks.div_euclid(10_000_000);
        let timestamp_nanoseconds: u32 = u32::try_from(unix_ticks.rem_euclid(10_000_000))
            .map_err(|_error: std::num::TryFromIntError| {
                inno_err("data entry timestamp remainder overflows")
            })?
            .checked_mul(100)
            .ok_or_else(|| inno_err("data entry timestamp nanoseconds overflow"))?;
        let version_high: u32 = read_inno_u32(secondary_header, &mut cursor)
            .ok_or_else(|| inno_err("data entry version high word is truncated"))?;
        let version_low: u32 = read_inno_u32(secondary_header, &mut cursor)
            .ok_or_else(|| inno_err("data entry version low word is truncated"))?;
        let file_version: u64 = (u64::from(version_high) << 32) | u64::from(version_low);
        let flag_count: usize = data_flag_count(info.version);
        let flag_bytes: usize = flag_count.div_ceil(8);
        let flags: &[u8] = secondary_header
            .get(
                cursor
                    ..cursor
                        .checked_add(flag_bytes)
                        .ok_or_else(|| inno_err("data entry flag extent overflow"))?,
            )
            .ok_or_else(|| inno_err("data entry flags are truncated"))?;
        cursor = cursor
            .checked_add(flag_bytes)
            .ok_or_else(|| inno_err("data entry flag extent overflow"))?;
        if !flag_count.is_multiple_of(8)
            && flags
                .last()
                .is_some_and(|byte: &u8| byte >> (flag_count % 8) != 0)
        {
            return Err(inno_err("data entry flags contain undefined bits"));
        }
        let sign_mode: InnoSignMode = if info.version >= inno_version(6, 4, 3, 0) {
            InnoSignMode::Unchanged
        } else if info.version >= inno_version(6, 3, 0, 0) {
            let sign_mode: u8 = *secondary_header
                .get(cursor)
                .ok_or_else(|| inno_err("data entry sign mode is truncated"))?;
            cursor = cursor
                .checked_add(1)
                .ok_or_else(|| inno_err("data entry sign mode offset overflow"))?;
            match sign_mode {
                0 => InnoSignMode::Unchanged,
                1 => InnoSignMode::Yes,
                2 => InnoSignMode::Once,
                3 => InnoSignMode::Check,
                _ => return Err(inno_err("data entry sign mode is invalid")),
            }
        } else {
            legacy_sign_mode(info.version, flags)
        };
        entries.push(InnoDataEntry {
            first_slice,
            last_slice,
            chunk_offset,
            file_offset,
            file_size,
            chunk_size,
            checksum,
            timestamp_seconds,
            timestamp_nanoseconds,
            file_version,
            compressed: if info.version >= inno_version(4, 2, 5, 0) {
                inno_flag(
                    flags,
                    data_flag_position(info.version, InnoDataFlag::Compressed),
                )
            } else {
                true
            },
            encrypted: inno_flag(
                flags,
                data_flag_position(info.version, InnoDataFlag::Encrypted),
            ),
            solid_break: inno_flag(
                flags,
                data_flag_position(info.version, InnoDataFlag::SolidBreak),
            ),
            instruction_filter: inno_flag(
                flags,
                data_flag_position(info.version, InnoDataFlag::InstructionFilter),
            ),
            sign_mode,
        });
    }
    if cursor != secondary_header.len() {
        return Err(inno_err("secondary setup header has trailing bytes"));
    }
    Ok(entries)
}

fn locate_setup_loader(bytes: &[u8]) -> Option<SetupLoaderOffsets> {
    if let Some(table) = legacy_loader_table(bytes)
        && let Some(offsets) = decode_loader_table(table)
        && loader_offsets_are_valid(bytes, offsets)
    {
        return Some(offsets);
    }
    if let Some(table) = resource_loader_table(bytes)
        && let Some(offsets) = decode_loader_table(&table)
        && loader_offsets_are_valid(bytes, offsets)
    {
        return Some(offsets);
    }
    None
}

fn loader_offsets_are_valid(bytes: &[u8], offsets: SetupLoaderOffsets) -> bool {
    let Ok(data_at): std::result::Result<usize, std::num::TryFromIntError> =
        usize::try_from(offsets.data_offset)
    else {
        return false;
    };
    let Ok(header_at): std::result::Result<usize, std::num::TryFromIntError> =
        usize::try_from(offsets.header_offset)
    else {
        return false;
    };
    let Ok(exe_at): std::result::Result<usize, std::num::TryFromIntError> =
        usize::try_from(offsets.exe_offset)
    else {
        return false;
    };
    if data_at >= header_at
        || exe_at > bytes.len()
        || bytes.get(data_at..data_at.saturating_add(INNO_CHUNK_MAGIC.len()))
            != Some(INNO_CHUNK_MAGIC.as_slice())
        || inno_id_field(bytes, header_at).is_none()
    {
        return false;
    }
    if offsets.exe_compressed_size > 0 {
        if data_at >= exe_at {
            return false;
        }
        let Ok(exe_size): std::result::Result<usize, std::num::TryFromIntError> =
            usize::try_from(offsets.exe_compressed_size)
        else {
            return false;
        };
        if exe_at.checked_add(exe_size) != Some(header_at) {
            return false;
        }
    } else if !offsets.table_crc_valid || header_at >= exe_at {
        return false;
    }
    true
}

fn legacy_loader_table(bytes: &[u8]) -> Option<&[u8]> {
    let block: &[u8] = bytes.get(LEGACY_LOADER_OFFSET..LEGACY_LOADER_OFFSET + 12)?;
    let id: u32 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    let table_offset: u32 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
    let not_table_offset: u32 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
    if id == 0 || table_offset != !not_table_offset {
        return None;
    }
    let at: usize = table_offset as usize;
    let end: usize = at
        .checked_add(LOADER_TABLE_LEN)
        .map_or(bytes.len(), |value: usize| value.min(bytes.len()));
    bytes.get(at..end)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum InnoLoaderLayout {
    V4000,
    V4003,
    V4010,
    V4016,
    V515,
}

fn decode_loader_table(table: &[u8]) -> Option<SetupLoaderOffsets> {
    let magic: &[u8] = table.get(..12)?;
    let layout: InnoLoaderLayout = match magic {
        value if value == LOADER_MAGIC_4000 => InnoLoaderLayout::V4000,
        value if value == LOADER_MAGIC_4003 => InnoLoaderLayout::V4003,
        value if value == LOADER_MAGIC_4010 => InnoLoaderLayout::V4010,
        value if value == LOADER_MAGIC_4016 => InnoLoaderLayout::V4016,
        value if value == LOADER_MAGIC_515_A || value == LOADER_MAGIC_515_B => {
            InnoLoaderLayout::V515
        }
        _ => return None,
    };
    let mut cur: ByteReader<'_> = ByteReader::new(table);
    cur.skip(12).ok()?;
    let revision: u32 = if layout == InnoLoaderLayout::V515 {
        cur.read_u32_le().ok()?
    } else {
        0
    };
    let exe_offset: u64;
    let exe_compressed_size: u64;
    let exe_uncompressed_size: u64;
    let header_offset: u64;
    let data_offset: u64;
    if revision == 2 {
        cur.skip(8).ok()?;
        exe_offset = cur.read_u64_le().ok()?;
        exe_compressed_size = 0;
        exe_uncompressed_size = u64::from(cur.read_u32_le().ok()?);
        let exe_checksum: u32 = cur.read_u32_le().ok()?;
        header_offset = cur.read_u64_le().ok()?;
        data_offset = cur.read_u64_le().ok()?;
        cur.skip(4).ok()?;
        let table_crc: u32 = cur.read_u32_le().ok()?;
        let consumed: usize = cur.position();
        let table_crc_valid: bool = consumed >= 4 && crc32(&table[..consumed - 4]) == table_crc;
        if !table_crc_valid {
            return None;
        }
        return Some(SetupLoaderOffsets {
            revision,
            exe_offset,
            exe_compressed_size,
            exe_uncompressed_size,
            exe_checksum,
            header_offset,
            data_offset,
            table_crc_valid,
        });
    }
    if revision == 1 {
        cur.skip(4).ok()?;
        exe_offset = u64::from(cur.read_u32_le().ok()?);
        exe_compressed_size = 0;
        exe_uncompressed_size = u64::from(cur.read_u32_le().ok()?);
        let exe_checksum: u32 = cur.read_u32_le().ok()?;
        header_offset = u64::from(cur.read_u32_le().ok()?);
        data_offset = u64::from(cur.read_u32_le().ok()?);
        let table_crc: u32 = cur.read_u32_le().ok()?;
        let consumed: usize = cur.position();
        let table_crc_valid: bool = consumed >= 4 && crc32(&table[..consumed - 4]) == table_crc;
        if !table_crc_valid {
            return None;
        }
        return Some(SetupLoaderOffsets {
            revision,
            exe_offset,
            exe_compressed_size,
            exe_uncompressed_size,
            exe_checksum,
            header_offset,
            data_offset,
            table_crc_valid,
        });
    }
    if layout == InnoLoaderLayout::V515 {
        return None;
    }
    cur.skip(4).ok()?;
    exe_offset = u64::from(cur.read_u32_le().ok()?);
    exe_compressed_size = if layout < InnoLoaderLayout::V4016 {
        u64::from(cur.read_u32_le().ok()?)
    } else {
        0
    };
    exe_uncompressed_size = u64::from(cur.read_u32_le().ok()?);
    let exe_checksum: u32 = cur.read_u32_le().ok()?;
    header_offset = u64::from(cur.read_u32_le().ok()?);
    data_offset = u64::from(cur.read_u32_le().ok()?);
    let table_crc_valid: bool = if layout >= InnoLoaderLayout::V4010 {
        let table_crc: u32 = cur.read_u32_le().ok()?;
        let consumed: usize = cur.position();
        consumed >= 4 && crc32(&table[..consumed - 4]) == table_crc
    } else {
        false
    };
    if layout >= InnoLoaderLayout::V4010 && !table_crc_valid {
        return None;
    }
    Some(SetupLoaderOffsets {
        revision,
        exe_offset,
        exe_compressed_size,
        exe_uncompressed_size,
        exe_checksum,
        header_offset,
        data_offset,
        table_crc_valid,
    })
}

fn resource_loader_table(bytes: &[u8]) -> Option<Vec<u8>> {
    if !bytes.starts_with(b"MZ") {
        return None;
    }
    let e_lfanew_u32: u32 = disrobe_bytes::read_u32_le_at(bytes, 0x3C).ok()?;
    let e_lfanew: usize = usize::try_from(e_lfanew_u32).ok()?;
    let signature_end: usize = e_lfanew.checked_add(4)?;
    if bytes.get(e_lfanew..signature_end)? != b"PE\0\0" {
        return None;
    }
    let coff: usize = signature_end;
    let optional_size_offset: usize = coff.checked_add(16)?;
    let optional_size: usize =
        usize::from(disrobe_bytes::read_u16_le_at(bytes, optional_size_offset).ok()?);
    let optional: usize = coff.checked_add(20)?;
    let optional_end: usize = optional.checked_add(optional_size)?;
    let magic: u16 = disrobe_bytes::read_u16_le_at(bytes, optional).ok()?;
    let data_dir_delta: usize = match magic {
        0x10B => 96,
        0x20B => 112,
        _ => return None,
    };
    let directory_count_delta: usize = data_dir_delta.checked_sub(4)?;
    let directory_count_offset: usize = optional.checked_add(directory_count_delta)?;
    let directory_count: u32 = disrobe_bytes::read_u32_le_at(bytes, directory_count_offset).ok()?;
    if directory_count <= 2 {
        return None;
    }
    let data_dir: usize = optional.checked_add(data_dir_delta)?;
    let resource_rva_offset: usize = data_dir.checked_add(16)?;
    let resource_size_offset: usize = resource_rva_offset.checked_add(4)?;
    let resource_entry_end: usize = resource_size_offset.checked_add(4)?;
    if resource_entry_end > optional_end {
        return None;
    }
    let resource_rva: u32 = disrobe_bytes::read_u32_le_at(bytes, resource_rva_offset).ok()?;
    let resource_size_u32: u32 = disrobe_bytes::read_u32_le_at(bytes, resource_size_offset).ok()?;
    let resource_size: usize = usize::try_from(resource_size_u32).ok()?;
    if resource_rva == 0 || resource_size == 0 {
        return None;
    }
    let image: NativeImage<'_> = parse_native_image(bytes).ok()?;
    let resource_address: u64 = image.virtual_address_from_relative(resource_rva)?;
    let resource: &[u8] = image.bytes_at(resource_address)?.get(..resource_size)?;
    let rcdata_dir: usize = resource_dir_subdir(resource, 0, 10)?;
    let id_dir: usize = resource_dir_subdir(resource, rcdata_dir, SETUP_LOADER_RESOURCE_ID)?;
    let lang_entry: u32 = resource_dir_first_entry(resource, id_dir)?;
    if lang_entry & 0x8000_0000 != 0 {
        return None;
    }
    let data_entry_relative: usize = usize::try_from(lang_entry).ok()?;
    let (data_rva, data_size): (u32, usize) = resource_data_entry(
        resource,
        data_entry_relative,
        resource_rva,
        resource_size_u32,
    )?;
    if data_size == 0 || data_size > 4096 {
        return None;
    }
    let data_address: u64 = image.virtual_address_from_relative(data_rva)?;
    let data: &[u8] = image.bytes_at(data_address)?;
    data.get(..data_size).map(<[u8]>::to_vec)
}

fn resource_data_entry(
    resource: &[u8],
    entry_offset: usize,
    resource_rva: u32,
    resource_size: u32,
) -> Option<(u32, usize)> {
    let entry_end: usize = entry_offset.checked_add(16)?;
    let entry: &[u8] = resource.get(entry_offset..entry_end)?;
    let data_rva: u32 = disrobe_bytes::read_u32_le_at(entry, 0).ok()?;
    let data_size_u32: u32 = disrobe_bytes::read_u32_le_at(entry, 4).ok()?;
    let reserved: u32 = disrobe_bytes::read_u32_le_at(entry, 12).ok()?;
    if reserved != 0 {
        return None;
    }
    let resource_end: u32 = resource_rva.checked_add(resource_size)?;
    let data_end: u32 = data_rva.checked_add(data_size_u32)?;
    if data_rva < resource_rva || data_end > resource_end {
        return None;
    }
    let data_size: usize = usize::try_from(data_size_u32).ok()?;
    Some((data_rva, data_size))
}

fn resource_dir_subdir(bytes: &[u8], dir_off: usize, want_id: u32) -> Option<usize> {
    let named_offset: usize = dir_off.checked_add(12)?;
    let ids_offset: usize = dir_off.checked_add(14)?;
    let named: u16 = disrobe_bytes::read_u16_le_at(bytes, named_offset).ok()?;
    let ids: u16 = disrobe_bytes::read_u16_le_at(bytes, ids_offset).ok()?;
    let total: usize = usize::from(named).checked_add(usize::from(ids))?;
    let base: usize = dir_off.checked_add(16)?;
    for i in 0..total {
        let entry_delta: usize = i.checked_mul(8)?;
        let eo: usize = base.checked_add(entry_delta)?;
        let off_offset: usize = eo.checked_add(4)?;
        let id: u32 = disrobe_bytes::read_u32_le_at(bytes, eo).ok()?;
        let off: u32 = disrobe_bytes::read_u32_le_at(bytes, off_offset).ok()?;
        if id & 0x8000_0000 != 0 {
            continue;
        }
        if id == want_id && off & 0x8000_0000 != 0 {
            let relative: usize = usize::try_from(off & 0x7FFF_FFFF).ok()?;
            return Some(relative);
        }
    }
    None
}

fn resource_dir_first_entry(bytes: &[u8], dir_off: usize) -> Option<u32> {
    let named_offset: usize = dir_off.checked_add(12)?;
    let ids_offset: usize = dir_off.checked_add(14)?;
    let named: u16 = disrobe_bytes::read_u16_le_at(bytes, named_offset).ok()?;
    let ids: u16 = disrobe_bytes::read_u16_le_at(bytes, ids_offset).ok()?;
    let total: usize = usize::from(named).checked_add(usize::from(ids))?;
    if total == 0 {
        return None;
    }
    let eo: usize = dir_off.checked_add(16)?;
    let off_offset: usize = eo.checked_add(4)?;
    disrobe_bytes::read_u32_le_at(bytes, off_offset).ok()
}

pub fn extract_inno_block_stream(bytes: &[u8], info: &InnoSetupInfo) -> Result<Vec<u8>> {
    extract_inno_block_stream_with_limit(bytes, info, MAX_INNO_OUTPUT)
}

pub(crate) fn extract_inno_block_stream_with_limit(
    bytes: &[u8],
    info: &InnoSetupInfo,
    max_output: u64,
) -> Result<Vec<u8>> {
    let start: usize = usize::try_from(info.block_stream_offset)
        .map_err(|_e: std::num::TryFromIntError| inno_err("block stream offset overflow"))?;
    let compressed: u8 = match info.compression {
        InnoCompression::Stored => 0,
        InnoCompression::Zlib | InnoCompression::Lzma1 => 1,
        InnoCompression::Lzma2 => {
            return Err(inno_err("inno setup metadata does not use lzma2"));
        }
    };
    extract_inno_block_with_limit(
        bytes,
        InnoBlockHeader {
            stored_size: info.stored_size,
            compressed,
            stream_offset: start,
        },
        info.version,
        max_output,
    )
}

pub fn extract_inno_metadata_blocks(
    bytes: &[u8],
    info: &InnoSetupInfo,
) -> Result<InnoMetadataBlocks> {
    extract_inno_metadata_blocks_with_limit(bytes, info, MAX_INNO_OUTPUT)
}

fn extract_inno_metadata_blocks_with_limit(
    bytes: &[u8],
    info: &InnoSetupInfo,
    max_output: u64,
) -> Result<InnoMetadataBlocks> {
    let primary_start: usize = usize::try_from(info.block_stream_offset)
        .map_err(|_error: std::num::TryFromIntError| inno_err("primary block offset overflow"))?;
    let primary_size: usize = usize::try_from(info.stored_size)
        .map_err(|_error: std::num::TryFromIntError| inno_err("primary block size overflow"))?;
    let secondary_header_at: usize = primary_start
        .checked_add(primary_size)
        .ok_or_else(|| inno_err("secondary block header offset overflow"))?;
    let secondary_header: InnoBlockHeader =
        parse_inno_block_header(bytes, secondary_header_at, info.version)
            .ok_or_else(|| inno_err("secondary block header is invalid"))?;
    let secondary_size: usize = usize::try_from(secondary_header.stored_size)
        .map_err(|_error: std::num::TryFromIntError| inno_err("secondary block size overflow"))?;
    let data_offset: usize = secondary_header
        .stream_offset
        .checked_add(secondary_size)
        .ok_or_else(|| inno_err("setup data offset overflow"))?;
    if data_offset > bytes.len() {
        return Err(inno_err("secondary block extent exceeds input"));
    }
    let primary_header: InnoBlockHeader = InnoBlockHeader {
        stored_size: info.stored_size,
        compressed: match info.compression {
            InnoCompression::Stored => 0,
            InnoCompression::Zlib | InnoCompression::Lzma1 => 1,
            InnoCompression::Lzma2 => {
                return Err(inno_err("inno setup metadata does not use lzma2"));
            }
        },
        stream_offset: primary_start,
    };
    let primary: Vec<u8> =
        extract_inno_block_with_limit(bytes, primary_header, info.version, max_output)?;
    let primary_len: u64 = primary.len() as u64;
    let secondary_limit: u64 = max_output
        .checked_sub(primary_len)
        .ok_or_else(|| inno_err("setup headers exceed their aggregate limit"))?;
    let secondary: Vec<u8> =
        extract_inno_block_with_limit(bytes, secondary_header, info.version, secondary_limit)?;
    Ok(InnoMetadataBlocks {
        primary,
        secondary,
        data_offset: u64::try_from(data_offset)
            .map_err(|_error: std::num::TryFromIntError| inno_err("setup data offset overflow"))?,
    })
}

pub fn recover_inno_metadata(bytes: &[u8]) -> Result<InnoMetadata> {
    recover_inno_metadata_with_limits(bytes, MAX_INNO_OUTPUT, usize::MAX)
}

pub(crate) fn recover_inno_metadata_with_limits(
    bytes: &[u8],
    max_setup_output: u64,
    max_entries: usize,
) -> Result<InnoMetadata> {
    let info: InnoSetupInfo = detect_innosetup(bytes)
        .ok_or_else(|| inno_err("setup data profile is unsupported or malformed"))?;
    if info.encrypted {
        return Err(inno_err(
            "setup metadata is encrypted and requires a password",
        ));
    }
    let candidates: [Option<InnoDataVersion>; 3] = match info.version {
        version @ (InnoDataVersion {
            major: 5,
            minor: 3,
            patch: 10,
            revision: 0,
        }
        | InnoDataVersion {
            major: 5,
            minor: 4,
            patch: 2,
            revision: 0,
        }
        | InnoDataVersion {
            major: 5,
            minor: 5,
            patch: 0,
            revision: 0,
        }) => [
            Some(version),
            Some(InnoDataVersion {
                revision: 1,
                ..version
            }),
            None,
        ],
        version @ InnoDataVersion {
            major: 5,
            minor: 5,
            patch: 7,
            revision: 0,
        } => [
            Some(version),
            Some(inno_version(5, 5, 7, 1)),
            Some(inno_version(5, 6, 0, 0)),
        ],
        version => [Some(version), None, None],
    };
    let mut recovered: Option<InnoMetadata> = None;
    let mut last_error: Option<Error> = None;
    for version in candidates.into_iter().flatten() {
        let candidate_info: InnoSetupInfo = InnoSetupInfo {
            version,
            ..info.clone()
        };
        match recover_inno_metadata_profile(bytes, candidate_info, max_setup_output, max_entries) {
            Ok(candidate) if recovered.is_none() => recovered = Some(candidate),
            Ok(_candidate) => return Err(inno_err("setup data profile is ambiguous")),
            Err(error) => last_error = Some(error),
        }
    }
    recovered.ok_or_else(|| {
        last_error.unwrap_or_else(|| inno_err("setup data profile is unsupported or malformed"))
    })
}

fn recover_inno_metadata_profile(
    bytes: &[u8],
    info: InnoSetupInfo,
    max_setup_output: u64,
    max_entries: usize,
) -> Result<InnoMetadata> {
    let blocks: InnoMetadataBlocks =
        extract_inno_metadata_blocks_with_limit(bytes, &info, max_setup_output)?;
    let (counts, counts_end): (InnoSetupCounts, usize) =
        parse_inno_setup_counts_with_end(&blocks.primary, &info)?;
    let file_count: usize = usize::try_from(counts.files)
        .map_err(|_error: std::num::TryFromIntError| inno_err("file count overflow"))?;
    let data_count: usize = usize::try_from(counts.data_entries)
        .map_err(|_error: std::num::TryFromIntError| inno_err("data-entry count overflow"))?;
    if file_count > max_entries || data_count > max_entries {
        return Err(inno_err("setup table count exceeds its entry limit"));
    }
    let (file_compression, slices_per_disk, primary_entries_offset): (
        InnoFileCompression,
        u32,
        usize,
    ) = parse_inno_header_layout(&blocks.primary, &info, counts_end)?;
    let data_entries: Vec<InnoDataEntry> =
        parse_inno_data_entries(&blocks.secondary, &info, counts.data_entries)?;
    let (files, primary_tail_offset): (Vec<InnoSetupFile>, usize) =
        parse_inno_setup_files_with_end(&blocks.primary, primary_entries_offset, &info, counts)?;
    validate_inno_primary_tail(
        &blocks.primary,
        primary_tail_offset,
        &info,
        counts,
        file_compression,
    )?;
    let metadata: InnoMetadata = InnoMetadata {
        info,
        counts,
        data_entries,
        files,
        file_compression,
        slices_per_disk,
        primary_entries_offset: u64::try_from(primary_entries_offset).map_err(
            |_error: std::num::TryFromIntError| inno_err("primary entries offset overflow"),
        )?,
        data_offset: blocks.data_offset,
    };
    validate_inno_file_graph(bytes, &metadata)?;
    Ok(metadata)
}

fn validate_inno_file_graph(bytes: &[u8], metadata: &InnoMetadata) -> Result<()> {
    let loader: SetupLoaderOffsets = metadata
        .info
        .loader
        .ok_or_else(|| inno_err("setup loader offsets are unavailable"))?;
    let data_offset: u64 = loader.data_offset;
    let mut referenced: Vec<bool> = vec![false; metadata.data_entries.len()];
    for file in &metadata.files {
        if file.file_type != 0 || file.data_entry_index == u32::MAX {
            continue;
        }
        let index: usize = usize::try_from(file.data_entry_index)
            .map_err(|_error: std::num::TryFromIntError| inno_err("file data index overflow"))?;
        let edge: &mut bool = referenced
            .get_mut(index)
            .ok_or_else(|| inno_err("file references an unavailable data entry"))?;
        *edge = true;
    }
    if referenced.iter().any(|edge: &bool| !edge) {
        return Err(inno_err("data entry has no file-table reference"));
    }
    let mut spans: Vec<(u64, u64, InnoChunkKey)> = Vec::new();
    for entry in &metadata.data_entries {
        entry
            .file_offset
            .checked_add(entry.file_size)
            .ok_or_else(|| inno_err("file extent overflow"))?;
        if entry.first_slice != 0 || entry.last_slice != 0 {
            continue;
        }
        let key: InnoChunkKey = InnoChunkKey::from_entry(entry);
        if spans
            .iter()
            .any(|(_, _, existing): &(u64, u64, InnoChunkKey)| {
                existing.offset == key.offset && *existing != key
            })
        {
            return Err(inno_err("data entries disagree about a chunk extent"));
        }
        let start: u64 = data_offset
            .checked_add(entry.chunk_offset)
            .ok_or_else(|| inno_err("chunk offset overflow"))?;
        let body_start: u64 = start
            .checked_add(INNO_CHUNK_MAGIC.len() as u64)
            .ok_or_else(|| inno_err("chunk body offset overflow"))?;
        let end: u64 = body_start
            .checked_add(entry.chunk_size)
            .ok_or_else(|| inno_err("chunk extent overflow"))?;
        let start_usize: usize = usize::try_from(start)
            .map_err(|_error: std::num::TryFromIntError| inno_err("chunk offset overflow"))?;
        let body_start_usize: usize = usize::try_from(body_start)
            .map_err(|_error: std::num::TryFromIntError| inno_err("chunk offset overflow"))?;
        let end_usize: usize = usize::try_from(end)
            .map_err(|_error: std::num::TryFromIntError| inno_err("chunk extent overflow"))?;
        if bytes.get(start_usize..body_start_usize) != Some(INNO_CHUNK_MAGIC.as_slice())
            || bytes.get(body_start_usize..end_usize).is_none()
        {
            return Err(inno_err("file chunk graph exceeds the installer data area"));
        }
        if !spans
            .iter()
            .any(|(_, _, existing): &(u64, u64, InnoChunkKey)| *existing == key)
        {
            spans.push((start, end, key));
        }
    }
    spans.sort_unstable_by_key(|(start, end, _key): &(u64, u64, InnoChunkKey)| (*start, *end));
    for pair in spans.windows(2) {
        let [left, right]: &[(u64, u64, InnoChunkKey)] = pair else {
            continue;
        };
        if right.0 < left.1 {
            return Err(inno_err("file chunk extents overlap"));
        }
    }
    Ok(())
}

fn extract_inno_block_with_limit(
    bytes: &[u8],
    header: InnoBlockHeader,
    version: InnoDataVersion,
    max_output: u64,
) -> Result<Vec<u8>> {
    let stored_size: usize = usize::try_from(header.stored_size)
        .map_err(|_error: std::num::TryFromIntError| inno_err("block stored size overflow"))?;
    if header.stored_size > max_output {
        return Err(inno_err("setup block exceeds its output limit"));
    }
    let compressed: Vec<u8> = read_crc_framed_chunks(bytes, header.stream_offset, stored_size)?;
    match compression_for_version(version, header.compressed)
        .ok_or_else(|| inno_err("block compression marker is invalid"))?
    {
        InnoCompression::Stored => Ok(compressed),
        InnoCompression::Zlib => inflate_zlib(&compressed, max_output),
        InnoCompression::Lzma1 => inflate_lzma1(&compressed, max_output),
        InnoCompression::Lzma2 => Err(inno_err("inno setup metadata does not use lzma2")),
    }
}

fn read_crc_framed_chunks(bytes: &[u8], start: usize, stored_size: usize) -> Result<Vec<u8>> {
    let end: usize = start
        .checked_add(stored_size)
        .ok_or_else(|| inno_err("block stream extent overflow"))?;
    if end > bytes.len() {
        return Err(inno_err("block stream extent exceeds input"));
    }
    let mut out: Vec<u8> = Vec::new();
    let mut pos: usize = start;
    while pos < end {
        let framed_remaining: usize = end - pos;
        if framed_remaining < 5 {
            return Err(inno_err("truncated block-stream CRC frame"));
        }
        let expected_crc: u32 =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;
        let remaining: usize = end - pos;
        let chunk_len: usize = remaining.min(INNO_CHUNK_SIZE);
        let chunk: &[u8] = &bytes[pos..pos + chunk_len];
        let actual_crc: u32 = crc32(chunk);
        if actual_crc != expected_crc {
            return Err(inno_err("inno block-stream chunk CRC32 mismatch"));
        }
        let new_len: usize = out
            .len()
            .checked_add(chunk_len)
            .ok_or_else(|| inno_err("inno block stream output size overflow"))?;
        if new_len as u64 > MAX_INNO_OUTPUT {
            return Err(inno_err("inno block stream exceeds output limit"));
        }
        out.extend_from_slice(chunk);
        pos += chunk_len;
    }
    if out.is_empty() {
        return Err(inno_err("inno block stream produced no validated chunks"));
    }
    Ok(out)
}

fn inflate_zlib(input: &[u8], max_output: u64) -> Result<Vec<u8>> {
    let mut decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(input);
    let mut out: Vec<u8> = Vec::new();
    decoder
        .by_ref()
        .take(max_output + 1)
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| Error::InnoSetup(format!("inno zlib inflate: {e}")))?;
    if out.len() as u64 > max_output {
        return Err(inno_err("inno zlib setup metadata exceeds output limit"));
    }
    if decoder.total_in() != input.len() as u64 {
        return Err(inno_err(
            "inno zlib setup metadata has trailing compressed bytes",
        ));
    }
    Ok(out)
}

fn inflate_lzma1(input: &[u8], max_output: u64) -> Result<Vec<u8>> {
    let props: &[u8] = input
        .get(..5)
        .ok_or_else(|| inno_err("truncated lzma1 setup metadata properties"))?;
    let stream_bytes: &[u8] = input
        .get(5..)
        .ok_or_else(|| inno_err("truncated lzma1 setup metadata stream"))?;
    if stream_bytes.is_empty() {
        return Err(inno_err("empty lzma1 setup metadata stream"));
    }
    let mut filters: liblzma::stream::Filters = liblzma::stream::Filters::new();
    filters
        .lzma1_properties(props)
        .map_err(|error: liblzma::stream::Error| {
            Error::InnoSetup(format!("invalid lzma1 setup metadata properties: {error}"))
        })?;
    let decoder: liblzma::stream::Stream = liblzma::stream::Stream::new_raw_decoder(&filters)
        .map_err(|error: liblzma::stream::Error| {
            Error::InnoSetup(format!("invalid lzma1 setup metadata stream: {error}"))
        })?;
    let mut reader: liblzma::read::XzDecoder<&[u8]> =
        liblzma::read::XzDecoder::new_stream(stream_bytes, decoder);
    let mut out: Vec<u8> = Vec::new();
    reader
        .by_ref()
        .take(max_output + 1)
        .read_to_end(&mut out)
        .map_err(|error: std::io::Error| {
            Error::InnoSetup(format!("lzma1 setup metadata decode failed: {error}"))
        })?;
    if out.len() as u64 > max_output {
        return Err(inno_err("lzma1 setup metadata exceeds output limit"));
    }
    if reader.total_in() != stream_bytes.len() as u64 {
        return Err(inno_err(
            "lzma1 setup metadata has trailing compressed bytes",
        ));
    }
    Ok(out)
}

const INNO_CHUNK_MAGIC: [u8; 4] = [b'z', b'l', b'b', 0x1a];

#[cfg(test)]
#[derive(Debug, Clone)]
struct InnoFileChunk {
    pub data: Vec<u8>,
}

#[cfg(test)]
#[must_use]
fn data_area_start(bytes: &[u8], info: &InnoSetupInfo) -> usize {
    if let Some(loader) = info.loader
        && (loader.data_offset as usize) < bytes.len()
        && bytes
            .get(loader.data_offset as usize..loader.data_offset as usize + INNO_CHUNK_MAGIC.len())
            .is_some_and(|w: &[u8]| w == INNO_CHUNK_MAGIC)
    {
        return loader.data_offset as usize;
    }
    let header_end: usize =
        usize::try_from(info.block_stream_offset).map_or(bytes.len(), |value: usize| value);
    let Ok(stored_size): std::result::Result<usize, std::num::TryFromIntError> =
        usize::try_from(info.stored_size)
    else {
        return header_end;
    };
    let Some(stream_end): Option<usize> = header_end.checked_add(stored_size) else {
        return header_end;
    };
    let consumed: usize = match read_crc_framed_chunks(bytes, header_end, stored_size) {
        Ok(_chunks) => stream_end,
        Err(_error) => header_end,
    };
    consumed.min(bytes.len())
}

#[cfg(test)]
fn extract_inno_file_chunks(
    bytes: &[u8],
    info: &InnoSetupInfo,
    max_total: u64,
) -> Vec<InnoFileChunk> {
    let scan_floor: usize = data_area_start(bytes, info);
    let mut chunks: Vec<InnoFileChunk> = Vec::new();
    let mut pos: usize = scan_floor;
    let mut total: u64 = 0;
    while let Some(rel) = find_subslice(&bytes[pos..], &INNO_CHUNK_MAGIC, 0) {
        let chunk_start: usize = pos + rel + INNO_CHUNK_MAGIC.len();
        let Some(body) = bytes.get(chunk_start..) else {
            break;
        };
        let next_magic: usize =
            find_subslice(body, &INNO_CHUNK_MAGIC, 0).map_or(body.len(), |rel: usize| rel);
        let budget: u64 = max_total.saturating_sub(total);
        let Some((decoded, consumed, _compression)) = decode_inno_chunk(body, next_magic, budget)
        else {
            pos = chunk_start + next_magic.max(1);
            continue;
        };
        if decoded.is_empty() {
            pos = chunk_start + next_magic.max(1);
            continue;
        }
        total = total.saturating_add(decoded.len() as u64);
        chunks.push(InnoFileChunk { data: decoded });
        pos = chunk_start + consumed.max(1);
        if total >= max_total {
            break;
        }
    }
    chunks
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct InnoChunkKey {
    first_slice: u32,
    last_slice: u32,
    offset: u64,
    size: u64,
    compressed: bool,
    encrypted: bool,
}

impl InnoChunkKey {
    const fn from_entry(entry: &InnoDataEntry) -> Self {
        Self {
            first_slice: entry.first_slice,
            last_slice: entry.last_slice,
            offset: entry.chunk_offset,
            size: entry.chunk_size,
            compressed: entry.compressed,
            encrypted: entry.encrypted,
        }
    }
}

#[derive(Debug, Clone)]
enum InnoChunkRecovery {
    Data(Vec<u8>),
    Refused(String),
}

pub fn recover_inno_named_files(
    bytes: &[u8],
    metadata: &InnoMetadata,
    max_total: u64,
) -> Result<InnoNamedRecovery> {
    recover_inno_named_files_with_limits(bytes, metadata, max_total, 1000)
}

pub fn recover_inno_named_files_with_limits(
    bytes: &[u8],
    metadata: &InnoMetadata,
    max_total: u64,
    max_ratio: u64,
) -> Result<InnoNamedRecovery> {
    recover_inno_named_files_with_quota(
        bytes,
        metadata,
        InnoRecoveryLimits {
            max_entries: usize::MAX,
            max_total,
            max_per_entry: max_total,
            max_per_entry_ratio: max_ratio,
            max_aggregate_ratio: max_ratio,
            initial_uncompressed: 0,
            initial_compressed: 0,
        },
    )
}

pub(crate) fn recover_inno_named_files_with_quota(
    bytes: &[u8],
    metadata: &InnoMetadata,
    limits: InnoRecoveryLimits,
) -> Result<InnoNamedRecovery> {
    type GroupMember<'a> = (usize, &'a InnoSetupFile, &'a InnoDataEntry);

    let eligible_count: usize = metadata
        .files
        .iter()
        .filter(|file: &&InnoSetupFile| file.file_type == 0 && file.data_entry_index != u32::MAX)
        .count();
    if eligible_count > limits.max_entries {
        return Err(inno_err("named-file count exceeds its entry limit"));
    }
    let mut total: u64 = 0;
    let mut compressed_total: u64 = limits.initial_compressed;
    let mut charged_chunks: BTreeSet<InnoChunkKey> = BTreeSet::new();
    for file in &metadata.files {
        if file.file_type != 0 {
            continue;
        }
        if file.data_entry_index == u32::MAX {
            continue;
        }
        let data_index: usize = usize::try_from(file.data_entry_index)
            .map_err(|_error: std::num::TryFromIntError| inno_err("file data index overflow"))?;
        let entry: &InnoDataEntry = metadata
            .data_entries
            .get(data_index)
            .ok_or_else(|| inno_err("file references an unavailable data entry"))?;
        if entry.file_size > limits.max_per_entry {
            return Err(inno_err("named file exceeds its per-entry limit"));
        }
        if entry.chunk_size > 0 && entry.file_size / entry.chunk_size > limits.max_per_entry_ratio {
            return Err(inno_err("named file exceeds its per-entry ratio limit"));
        }
        total = total
            .checked_add(entry.file_size)
            .ok_or_else(|| inno_err("named-file output size overflow"))?;
        if total > limits.max_total {
            return Err(inno_err("named-file output exceeds its aggregate limit"));
        }
        if charged_chunks.insert(InnoChunkKey::from_entry(entry)) {
            compressed_total = compressed_total
                .checked_add(entry.chunk_size)
                .ok_or_else(|| inno_err("named-file compressed size overflow"))?;
        }
        let aggregate_total: u64 = limits
            .initial_uncompressed
            .checked_add(total)
            .ok_or_else(|| inno_err("named-file aggregate size overflow"))?;
        if compressed_total > 0 && aggregate_total / compressed_total > limits.max_aggregate_ratio {
            return Err(inno_err("named files exceed their aggregate ratio limit"));
        }
    }
    let mut groups: BTreeMap<InnoChunkKey, Vec<GroupMember<'_>>> = BTreeMap::new();
    for (position, file) in metadata.files.iter().enumerate() {
        if file.file_type != 0 || file.data_entry_index == u32::MAX {
            continue;
        }
        let data_index: usize = usize::try_from(file.data_entry_index)
            .map_err(|_error: std::num::TryFromIntError| inno_err("file data index overflow"))?;
        let entry: &InnoDataEntry = metadata
            .data_entries
            .get(data_index)
            .ok_or_else(|| inno_err("file references an unavailable data entry"))?;
        groups
            .entry(InnoChunkKey::from_entry(entry))
            .or_default()
            .push((position, file, entry));
    }
    let mut recovered_slots: Vec<Option<InnoRecoveredFile>> = vec![None; metadata.files.len()];
    let mut refusal_slots: Vec<Option<String>> = vec![None; metadata.files.len()];
    for (compressed_group, members) in groups.values().enumerate() {
        let (_, _, representative): &GroupMember<'_> = members
            .first()
            .ok_or_else(|| inno_err("file chunk group is empty"))?;
        let recovered: InnoChunkRecovery = match recover_inno_chunk(
            bytes,
            metadata,
            representative,
            limits.max_total,
            limits.max_per_entry_ratio,
        ) {
            Ok(data) => InnoChunkRecovery::Data(data),
            Err(error) => InnoChunkRecovery::Refused(error.to_string()),
        };
        for (position, file, entry) in members {
            let chunk: &Vec<u8> = match &recovered {
                InnoChunkRecovery::Data(chunk) => chunk,
                InnoChunkRecovery::Refused(reason) => {
                    refusal_slots[*position] = Some(format!("{}: {reason}", file.destination));
                    continue;
                }
            };
            let file_start: usize = usize::try_from(entry.file_offset)
                .map_err(|_error: std::num::TryFromIntError| inno_err("file offset overflow"))?;
            let file_size: usize = usize::try_from(entry.file_size)
                .map_err(|_error: std::num::TryFromIntError| inno_err("file size overflow"))?;
            let file_end: usize = file_start
                .checked_add(file_size)
                .ok_or_else(|| inno_err("file extent overflow"))?;
            let Some(stored): Option<&[u8]> = chunk.get(file_start..file_end) else {
                refusal_slots[*position] = Some(format!(
                    "{}: file extent exceeds its decoded chunk",
                    file.destination
                ));
                continue;
            };
            let filter: InnoFilter = if entry.instruction_filter {
                if metadata.info.version < inno_version(5, 2, 0, 0) {
                    InnoFilter::Instruction4108
                } else if metadata.info.version < inno_version(5, 3, 9, 0) {
                    InnoFilter::Instruction5200
                } else {
                    InnoFilter::Instruction5309
                }
            } else {
                InnoFilter::None
            };
            let data: Vec<u8> = unfilter_instructions_at(stored, filter, 0);
            if !inno_checksum_matches(&data, &entry.checksum) {
                refusal_slots[*position] =
                    Some(format!("{}: file checksum mismatch", file.destination));
                continue;
            }
            let compression: InnoFileCompression = if entry.compressed {
                metadata.file_compression
            } else {
                InnoFileCompression::Stored
            };
            let path: &str = if file.destination.is_empty() {
                &file.source
            } else {
                &file.destination
            };
            recovered_slots[*position] = Some(InnoRecoveredFile {
                path: normalize_inno_destination(path),
                data,
                compressed_size: entry.chunk_size,
                compression,
                compressed_group,
            });
        }
    }
    let files: Vec<InnoRecoveredFile> = recovered_slots.into_iter().flatten().collect();
    let refusals: Vec<String> = refusal_slots.into_iter().flatten().collect();
    Ok(InnoNamedRecovery { files, refusals })
}

fn normalize_inno_destination(path: &str) -> String {
    let Some(rest): Option<&str> = path.strip_prefix('{') else {
        return path.to_owned();
    };
    let Some((constant, suffix)): Option<(&str, &str)> = rest.split_once('}') else {
        return path.to_owned();
    };
    if constant.is_empty()
        || !constant
            .bytes()
            .all(|byte: u8| byte.is_ascii_alphanumeric())
        || !matches!(suffix.as_bytes().first(), Some(b'\\' | b'/'))
    {
        return path.to_owned();
    }
    format!("{}{}", constant.to_ascii_lowercase(), suffix)
}

fn recover_inno_chunk(
    bytes: &[u8],
    metadata: &InnoMetadata,
    entry: &InnoDataEntry,
    output_limit: u64,
    max_ratio: u64,
) -> Result<Vec<u8>> {
    if entry.first_slice != 0 || entry.last_slice != 0 {
        return Err(inno_err("file data requires an external installer slice"));
    }
    if entry.encrypted {
        return Err(inno_err("file data is encrypted and requires a password"));
    }
    let loader_data_offset: Option<u64> =
        metadata.info.loader.and_then(|loader: SetupLoaderOffsets| {
            let offset: usize = usize::try_from(loader.data_offset).ok()?;
            bytes
                .get(offset..offset.checked_add(INNO_CHUNK_MAGIC.len())?)
                .is_some_and(|value: &[u8]| value == INNO_CHUNK_MAGIC)
                .then_some(loader.data_offset)
        });
    let data_offset: u64 = loader_data_offset.unwrap_or(metadata.data_offset);
    let chunk_start: usize = usize::try_from(
        data_offset
            .checked_add(entry.chunk_offset)
            .ok_or_else(|| inno_err("chunk offset overflow"))?,
    )
    .map_err(|_error: std::num::TryFromIntError| inno_err("chunk offset overflow"))?;
    let body_start: usize = chunk_start
        .checked_add(INNO_CHUNK_MAGIC.len())
        .ok_or_else(|| inno_err("chunk body offset overflow"))?;
    if bytes.get(chunk_start..body_start) != Some(&INNO_CHUNK_MAGIC) {
        return Err(inno_err("file chunk magic is invalid"));
    }
    let chunk_size: usize = usize::try_from(entry.chunk_size)
        .map_err(|_error: std::num::TryFromIntError| inno_err("chunk size overflow"))?;
    let body_end: usize = body_start
        .checked_add(chunk_size)
        .ok_or_else(|| inno_err("chunk extent overflow"))?;
    let body: &[u8] = bytes
        .get(body_start..body_end)
        .ok_or_else(|| inno_err("file chunk is truncated"))?;
    let compression: InnoFileCompression = if entry.compressed {
        metadata.file_compression
    } else {
        InnoFileCompression::Stored
    };
    let required_output: u64 = metadata
        .data_entries
        .iter()
        .filter(|candidate: &&InnoDataEntry| {
            InnoChunkKey::from_entry(candidate) == InnoChunkKey::from_entry(entry)
        })
        .try_fold(0_u64, |required: u64, candidate: &InnoDataEntry| {
            candidate
                .file_offset
                .checked_add(candidate.file_size)
                .map(|end: u64| required.max(end))
                .ok_or_else(|| inno_err("decoded chunk file extent overflow"))
        })?;
    let cap: u64 = output_limit.min(MAX_INNO_OUTPUT);
    if required_output > cap {
        return Err(inno_err("file chunk exceeds its output limit"));
    }
    if entry.chunk_size == 0 {
        if required_output != 0 {
            return Err(inno_err("file chunk has zero compressed length"));
        }
    } else if required_output.div_ceil(entry.chunk_size) > max_ratio {
        return Err(inno_err("file chunk exceeds its expansion-ratio limit"));
    }
    let decoded: Vec<u8> = match compression {
        InnoFileCompression::Stored => {
            if entry.chunk_size > cap {
                return Err(inno_err("stored file chunk exceeds its output limit"));
            }
            body.to_vec()
        }
        InnoFileCompression::Zlib => {
            let (decoded, consumed): (Vec<u8>, usize) = inflate_zlib_stream(body, cap)?;
            if consumed != body.len() {
                return Err(inno_err("zlib file chunk has trailing compressed bytes"));
            }
            decoded
        }
        InnoFileCompression::Bzip2 => inflate_bzip2_chunk(body, cap)?,
        InnoFileCompression::Lzma1 => decode_lzma_chunk_exact(body, cap, required_output, true)?,
        InnoFileCompression::Lzma2 => decode_lzma_chunk_exact(body, cap, required_output, false)?,
    };
    let decoded_len: u64 = decoded.len() as u64;
    if decoded_len > cap {
        return Err(inno_err("file chunk exceeds its output limit"));
    }
    if decoded_len != required_output {
        return Err(inno_err(
            "file chunk decoded length does not match its member extents",
        ));
    }
    Ok(decoded)
}

fn decode_lzma_chunk_exact(
    body: &[u8],
    budget: u64,
    required_output: u64,
    lzma1: bool,
) -> Result<Vec<u8>> {
    let (props, stream): (&[u8], &[u8]) = if lzma1 {
        let props: &[u8] = body
            .get(..5)
            .ok_or_else(|| inno_err("lzma1 file chunk properties are truncated"))?;
        if props[0] >= 9 * 5 * 5 {
            return Err(inno_err("lzma1 file chunk properties are invalid"));
        }
        let stream: &[u8] = body
            .get(5..)
            .ok_or_else(|| inno_err("lzma1 file chunk stream is truncated"))?;
        (props, stream)
    } else {
        let prop: u8 = *body
            .first()
            .ok_or_else(|| inno_err("lzma2 file chunk property is truncated"))?;
        if prop > 40 {
            return Err(inno_err("lzma2 file chunk property is invalid"));
        }
        (&body[..1], &body[1..])
    };
    let mut filters: liblzma::stream::Filters = liblzma::stream::Filters::new();
    let prepared: std::result::Result<&mut liblzma::stream::Filters, liblzma::stream::Error> =
        if lzma1 {
            filters.lzma1_properties(props)
        } else {
            filters.lzma2_properties(props)
        };
    prepared.map_err(|error: liblzma::stream::Error| {
        inno_err(format!("lzma file chunk properties are invalid: {error}"))
    })?;
    let decoder: liblzma::stream::Stream = liblzma::stream::Stream::new_raw_decoder(&filters)
        .map_err(|error: liblzma::stream::Error| {
            inno_err(format!("lzma file chunk decoder is invalid: {error}"))
        })?;
    let mut reader: liblzma::read::XzDecoder<&[u8]> =
        liblzma::read::XzDecoder::new_stream(stream, decoder);
    let cap: u64 = budget.min(MAX_INNO_OUTPUT);
    let mut output: Vec<u8> = Vec::new();
    let result: std::io::Result<usize> = reader.by_ref().take(cap + 1).read_to_end(&mut output);
    let output_len: u64 = output.len() as u64;
    if output_len > cap {
        return Err(inno_err("lzma file chunk exceeds its output limit"));
    }
    if reader.total_in() != stream.len() as u64 {
        return Err(inno_err("lzma file chunk has trailing compressed bytes"));
    }
    if result.is_err() && output_len < required_output {
        return Err(inno_err("lzma file chunk is truncated"));
    }
    if output_len < required_output {
        return Err(inno_err("lzma file chunk output is truncated"));
    }
    Ok(output)
}

struct ExactBzipInput<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl std::io::Read for ExactBzipInput<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let Some(remaining): Option<&[u8]> = self.bytes.get(self.position..) else {
            return Ok(0);
        };
        let count: usize = output.len().min(remaining.len());
        output[..count].copy_from_slice(&remaining[..count]);
        self.position = self.position.saturating_add(count);
        Ok(count)
    }
}

fn inno_bit_at(bytes: &[u8], offset: usize) -> Option<u8> {
    let byte: u8 = *bytes.get(offset / 8)?;
    let shift: usize = 7_usize.checked_sub(offset % 8)?;
    Some((byte >> shift) & 1)
}

fn inno_zero_bits(bytes: &[u8], start: usize, end: usize) -> bool {
    (start..end).all(|offset: usize| inno_bit_at(bytes, offset) == Some(0))
}

fn bzip2_output_matches(input: &[u8], expected: &[u8], cap: u64) -> bool {
    let mut decoder: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(input);
    let mut buffer: [u8; 8 * 1024] = [0; 8 * 1024];
    let mut position: usize = 0;
    loop {
        let count: usize = match decoder.read(&mut buffer) {
            Ok(0) => return position == expected.len(),
            Ok(count) => count,
            Err(_error) => return false,
        };
        let Some(end): Option<usize> = position.checked_add(count) else {
            return false;
        };
        if u64::try_from(end).map_or(true, |value: u64| value > cap)
            || expected.get(position..end) != buffer.get(..count)
        {
            return false;
        }
        position = end;
    }
}

fn bzip2_exact_end(input: &[u8], expected: &[u8], cap: u64) -> Result<usize> {
    const END_MARKER: u64 = 0x17_72_45_38_50_90;
    const MARKER_BITS: usize = 48;
    const FOOTER_BITS: usize = 80;
    const CANDIDATE_CAP: usize = 64;
    let bit_len: usize = input
        .len()
        .checked_mul(8)
        .ok_or_else(|| inno_err("bzip2 file chunk bit length overflow"))?;
    if bit_len < 32 + FOOTER_BITS {
        return Err(inno_err("bzip2 file chunk is truncated"));
    }
    let mut marker: u64 = 0;
    for offset in 32..32 + MARKER_BITS {
        let bit: u8 = inno_bit_at(input, offset)
            .ok_or_else(|| inno_err("bzip2 file chunk marker range overflow"))?;
        marker = (marker << 1) | u64::from(bit);
    }
    let mask: u64 = (1_u64 << MARKER_BITS) - 1;
    let final_start: usize = bit_len - FOOTER_BITS;
    let mut candidates: usize = 0;
    for start in 32..=final_start {
        if marker == END_MARKER {
            candidates = candidates
                .checked_add(1)
                .ok_or_else(|| inno_err("bzip2 file chunk candidate count overflow"))?;
            if candidates > CANDIDATE_CAP {
                return Err(inno_err("bzip2 file chunk has too many end markers"));
            }
            let end_bits: usize = start
                .checked_add(FOOTER_BITS)
                .ok_or_else(|| inno_err("bzip2 file chunk end range overflow"))?;
            let end: usize = end_bits
                .checked_add(7)
                .ok_or_else(|| inno_err("bzip2 file chunk alignment overflow"))?
                / 8;
            if inno_zero_bits(input, end_bits, end * 8)
                && bzip2_output_matches(&input[..end], expected, cap)
            {
                return Ok(end);
            }
        }
        let next: usize = start + MARKER_BITS;
        if next < bit_len {
            let bit: u8 = inno_bit_at(input, next)
                .ok_or_else(|| inno_err("bzip2 file chunk marker range overflow"))?;
            marker = ((marker << 1) & mask) | u64::from(bit);
        }
    }
    Err(inno_err("bzip2 file chunk end marker is invalid"))
}

fn inflate_bzip2_chunk(input: &[u8], cap: u64) -> Result<Vec<u8>> {
    let mut counted: ExactBzipInput<'_> = ExactBzipInput {
        bytes: input,
        position: 0,
    };
    let mut decoder: bzip2_rs::DecoderReader<&mut ExactBzipInput<'_>> =
        bzip2_rs::DecoderReader::new(&mut counted);
    let mut output: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(cap));
    decoder
        .by_ref()
        .take(cap.saturating_add(1))
        .read_to_end(&mut output)
        .map_err(|error: std::io::Error| {
            inno_err(format!("bzip2 file chunk is invalid: {error}"))
        })?;
    if output.len() as u64 > cap {
        return Err(inno_err("bzip2 file chunk exceeds its output limit"));
    }
    drop(decoder);
    let consumed: usize = bzip2_exact_end(input, &output, cap)?;
    if counted.position < consumed {
        return Err(inno_err("bzip2 file chunk consumption is inconsistent"));
    }
    if consumed != input.len() {
        return Err(inno_err("bzip2 file chunk has trailing compressed bytes"));
    }
    Ok(output)
}

fn inno_checksum_matches(data: &[u8], expected: &InnoChecksum) -> bool {
    match expected {
        InnoChecksum::Crc32(value) => crc32(data) == *value,
        InnoChecksum::Md5(value) => md5::compute(data).0 == *value,
        InnoChecksum::Sha1(value) => {
            use sha1::Digest as _;
            sha1::Sha1::digest(data)[..] == value[..]
        }
        InnoChecksum::Sha256(value) => {
            use sha2::Digest as _;
            sha2::Sha256::digest(data)[..] == value[..]
        }
    }
}

#[cfg(test)]
fn decode_inno_chunk(
    body: &[u8],
    bound: usize,
    budget: u64,
) -> Option<(Vec<u8>, usize, InnoCompression)> {
    if body.len() >= 2
        && body[0] == 0x78
        && (u16::from(body[0]) * 256 + u16::from(body[1])) % 31 == 0
        && let Ok((out, consumed)) = inflate_zlib_stream(body, budget)
    {
        return Some((out, consumed, InnoCompression::Zlib));
    }
    let span: &[u8] = body.get(..bound).map_or(body, |value: &[u8]| value);
    if let Some((out, consumed)) = decode_lzma1_chunk(span, budget) {
        return Some((out, consumed, InnoCompression::Lzma1));
    }
    if let Some((out, consumed)) = decode_lzma2_chunk(span, budget) {
        return Some((out, consumed, InnoCompression::Lzma2));
    }
    if bound > 0 && (bound as u64) <= budget.min(MAX_INNO_OUTPUT) {
        return Some((span.to_vec(), bound, InnoCompression::Stored));
    }
    None
}

fn inflate_zlib_stream(input: &[u8], budget: u64) -> Result<(Vec<u8>, usize)> {
    let mut decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(input);
    let mut out: Vec<u8> = Vec::new();
    let cap: u64 = budget.min(MAX_INNO_OUTPUT);
    decoder
        .by_ref()
        .take(cap + 1)
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| Error::InnoSetup(format!("inno chunk inflate: {e}")))?;
    if out.len() as u64 > cap {
        return Err(inno_err("inno data chunk exceeds budget"));
    }
    let consumed: usize = decoder.total_in() as usize;
    Ok((out, consumed))
}

#[cfg(test)]
fn decode_lzma1_chunk(body: &[u8], budget: u64) -> Option<(Vec<u8>, usize)> {
    let props: &[u8] = body.get(..5)?;
    if props[0] >= 9 * 5 * 5 {
        return None;
    }
    let stream: &[u8] = body.get(5..)?;
    let (out, consumed): (Vec<u8>, usize) = raw_lzma_decode(props, stream, budget, true)?;
    Some((out, consumed.checked_add(5)?))
}

#[cfg(test)]
fn decode_lzma2_chunk(body: &[u8], budget: u64) -> Option<(Vec<u8>, usize)> {
    let prop: u8 = *body.first()?;
    if prop > 40 {
        return None;
    }
    let stream: &[u8] = body.get(1..)?;
    let (out, consumed): (Vec<u8>, usize) = raw_lzma_decode(&[prop], stream, budget, false)?;
    Some((out, consumed.checked_add(1)?))
}

#[cfg(test)]
fn raw_lzma_decode(
    props: &[u8],
    stream: &[u8],
    budget: u64,
    lzma1: bool,
) -> Option<(Vec<u8>, usize)> {
    let mut filters: liblzma::stream::Filters = liblzma::stream::Filters::new();
    let prepared: std::result::Result<&mut liblzma::stream::Filters, liblzma::stream::Error> =
        if lzma1 {
            filters.lzma1_properties(props)
        } else {
            filters.lzma2_properties(props)
        };
    prepared.ok()?;
    let decoder: liblzma::stream::Stream =
        liblzma::stream::Stream::new_raw_decoder(&filters).ok()?;
    let mut reader: liblzma::read::XzDecoder<&[u8]> =
        liblzma::read::XzDecoder::new_stream(stream, decoder);
    let cap: u64 = budget.min(MAX_INNO_OUTPUT);
    let mut out: Vec<u8> = Vec::new();
    match reader.by_ref().take(cap + 1).read_to_end(&mut out) {
        Ok(_) => {}
        Err(_e) if !out.is_empty() => {}
        Err(_e) => return None,
    }
    if out.is_empty() || out.len() as u64 > cap {
        return None;
    }
    let consumed: usize = usize::try_from(reader.total_in()).ok()?;
    Some((out, consumed))
}

#[must_use]
pub fn unfilter_instructions(data: &[u8], filter: InnoFilter) -> Vec<u8> {
    unfilter_instructions_at(data, filter, 0)
}

fn unfilter_instructions_at(data: &[u8], filter: InnoFilter, base_offset: u32) -> Vec<u8> {
    match filter {
        InnoFilter::None | InnoFilter::Zlib => data.to_vec(),
        InnoFilter::Instruction4108 => inno_exe_decode_4108(data, base_offset),
        InnoFilter::Instruction5200 => inno_exe_decode_5200(data, base_offset, false),
        InnoFilter::Instruction5309 => inno_exe_decode_5200(data, base_offset, true),
    }
}

fn inno_exe_decode_4108(data: &[u8], base_offset: u32) -> Vec<u8> {
    let mut out: Vec<u8> = data.to_vec();
    let mut i: usize = 0;
    let mut address: u32 = 0;
    let mut address_bytes: u8 = 0;
    while i < out.len() {
        if address_bytes == 0 {
            if out[i] == 0xe8 || out[i] == 0xe9 {
                let offset: u32 = base_offset.wrapping_add(i as u32).wrapping_add(5);
                address = offset.wrapping_neg();
                address_bytes = 4;
            }
        } else {
            address = address.wrapping_add(u32::from(out[i]));
            out[i] = address as u8;
            address >>= 8;
            address_bytes -= 1;
        }
        i += 1;
    }
    out
}

fn inno_exe_decode_5200(data: &[u8], base_offset: u32, flip_high_byte: bool) -> Vec<u8> {
    let mut out: Vec<u8> = data.to_vec();
    let mut i: usize = 0;
    while i < out.len() {
        if out[i] != 0xe8 && out[i] != 0xe9 {
            i += 1;
            continue;
        }
        let offset: u32 = base_offset.wrapping_add(i as u32).wrapping_add(1);
        let block_remaining: u32 = 0x1_0000 - ((offset - 1) & 0xffff);
        let Some(address_end): Option<usize> = i.checked_add(5) else {
            break;
        };
        if block_remaining < 5 || address_end > out.len() {
            i += 1;
            continue;
        }
        let high: u8 = out[i + 4];
        if high == 0 || high == 0xff {
            let stored: u32 = u32::from(out[i + 1])
                | (u32::from(out[i + 2]) << 8)
                | (u32::from(out[i + 3]) << 16);
            let address_after: u32 = base_offset.wrapping_add(address_end as u32) & 0x00ff_ffff;
            let relative: u32 = stored.wrapping_sub(address_after);
            out[i + 1] = relative as u8;
            out[i + 2] = (relative >> 8) as u8;
            out[i + 3] = (relative >> 16) as u8;
            if flip_high_byte && relative & 0x0080_0000 != 0 {
                out[i + 4] = !high;
            }
        }
        i = address_end;
    }
    out
}

fn crc32(data: &[u8]) -> u32 {
    crc32_ieee(data)
}

#[inline]
fn inno_err(msg: impl Into<String>) -> Error {
    Error::InnoSetup(msg.into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;

    const ZLIB_TABLE: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_zlib.table");
    const ZLIB_CHUNKS: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_zlib.chunks");
    const LZMA1_TABLE: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_lzma1.table");
    const LZMA1_CHUNKS: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_lzma1.chunks");
    const LZMA2_TABLE: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_lzma2.table");
    const LZMA2_CHUNKS: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_lzma2.chunks");
    const STORED_TABLE: &[u8] = include_bytes!("../../tests/fixtures/innosetup/real6_stored.table");
    const STORED_CHUNKS: &[u8] =
        include_bytes!("../../tests/fixtures/innosetup/real6_stored.chunks");

    const ORIG_APP: &[u8] = include_bytes!("../../tests/fixtures/innosetup/orig_app.py");
    const ORIG_UTIL: &[u8] = include_bytes!("../../tests/fixtures/innosetup/orig_util.py");
    const ORIG_README: &[u8] = include_bytes!("../../tests/fixtures/innosetup/orig_readme.txt");
    const ORIG_DATA: &[u8] = include_bytes!("../../tests/fixtures/innosetup/orig_data.bin");

    fn originals() -> [&'static [u8]; 4] {
        [ORIG_APP, ORIG_UTIL, ORIG_README, ORIG_DATA]
    }

    fn empty_setup_counts() -> InnoSetupCounts {
        InnoSetupCounts {
            languages: 0,
            messages: 0,
            permissions: 0,
            types: 0,
            components: 0,
            tasks: 0,
            directories: 0,
            issig_keys: 0,
            files: 0,
            data_entries: 0,
            icons: 0,
            ini_entries: 0,
            registry_entries: 0,
            delete_entries: 0,
            uninstall_delete_entries: 0,
            run_entries: 0,
            uninstall_run_entries: 0,
        }
    }

    #[test]
    fn primary_tail_validation_requires_exact_stream_consumption() {
        let info: InnoSetupInfo = InnoSetupInfo {
            version_string: "Inno Setup Setup Data (4.0.9)".to_owned(),
            version: inno_version(4, 0, 9, 0),
            unicode: false,
            encrypted: false,
            data_id_offset: 0,
            block_stream_offset: 0,
            compression: InnoCompression::Stored,
            stored_size: 0,
            loader: None,
        };
        let exact: [u8; 8] = [0; 8];
        assert!(
            validate_inno_primary_tail(
                &exact,
                0,
                &info,
                empty_setup_counts(),
                InnoFileCompression::Zlib,
            )
            .is_ok()
        );
        assert!(
            validate_inno_primary_tail(
                &exact[..7],
                0,
                &info,
                empty_setup_counts(),
                InnoFileCompression::Zlib,
            )
            .is_err()
        );
        let mut trailing: Vec<u8> = exact.to_vec();
        trailing.push(0);
        assert!(
            validate_inno_primary_tail(
                &trailing,
                0,
                &info,
                empty_setup_counts(),
                InnoFileCompression::Zlib,
            )
            .is_err()
        );

        let current_info: InnoSetupInfo = InnoSetupInfo {
            version_string: "Inno Setup Setup Data (7.0.0.3)".to_owned(),
            version: inno_version(7, 0, 0, 3),
            unicode: true,
            encrypted: false,
            data_id_offset: 0,
            block_stream_offset: 0,
            compression: InnoCompression::Lzma1,
            stored_size: 0,
            loader: None,
        };
        let mut current_tail: Vec<u8> = Vec::new();
        current_tail.extend_from_slice(&0_u32.to_le_bytes());
        current_tail.extend_from_slice(&0_u32.to_le_bytes());
        current_tail.extend_from_slice(&0_u32.to_le_bytes());
        current_tail.extend_from_slice(&u32::MAX.to_le_bytes());
        current_tail.extend_from_slice(&0_u32.to_le_bytes());
        current_tail.extend_from_slice(&0_u32.to_le_bytes());
        assert!(
            validate_inno_primary_tail(
                &current_tail,
                0,
                &current_info,
                empty_setup_counts(),
                InnoFileCompression::Lzma2,
            )
            .is_ok()
        );
    }

    #[test]
    fn traverses_real_pe_resources_without_fabricating_loader_data() {
        let bytes: &[u8] = include_bytes!("../../../../corpus/dotnet/cff/DecryptSample.exe");
        let image: NativeImage<'_> =
            parse_native_image(bytes).expect("real resource pe should parse");
        let resource_address: u64 = image
            .virtual_address_from_relative(0x4000)
            .expect("resource address should fit");
        let resource: &[u8] = image
            .bytes_at(resource_address)
            .expect("resource directory should be file-backed");
        let root_id_count: u16 =
            disrobe_bytes::read_u16_le_at(resource, 14).expect("resource root should parse");

        assert_eq!(root_id_count, 2);
        assert!(resource_dir_subdir(resource, 0, 16).is_some());
        assert!(resource_dir_subdir(resource, 0, 24).is_some());
        assert!(resource_loader_table(bytes).is_none());
    }

    fn resource_entry(data_rva: u32, data_size: u32, reserved: u32) -> [u8; 16] {
        let mut entry: [u8; 16] = [0; 16];
        let data_rva_field: &mut [u8] = entry
            .get_mut(0..4)
            .expect("resource data rva field should exist");
        data_rva_field.copy_from_slice(&data_rva.to_le_bytes());
        let data_size_field: &mut [u8] = entry
            .get_mut(4..8)
            .expect("resource data size field should exist");
        data_size_field.copy_from_slice(&data_size.to_le_bytes());
        let reserved_field: &mut [u8] = entry
            .get_mut(12..16)
            .expect("resource reserved field should exist");
        reserved_field.copy_from_slice(&reserved.to_le_bytes());
        entry
    }

    #[test]
    fn resource_data_entry_requires_complete_valid_leaf() {
        let valid: [u8; 16] = resource_entry(0x4040, 0x20, 0);
        let truncated: &[u8] = valid
            .get(..15)
            .expect("truncated resource entry range should exist");
        let reserved: [u8; 16] = resource_entry(0x4040, 0x20, 1);
        let outside: [u8; 16] = resource_entry(0x4100, 1, 0);

        assert_eq!(
            resource_data_entry(&valid, 0, 0x4000, 0x100),
            Some((0x4040, 0x20))
        );
        assert!(resource_data_entry(truncated, 0, 0x4000, 0x100).is_none());
        assert!(resource_data_entry(&reserved, 0, 0x4000, 0x100).is_none());
        assert!(resource_data_entry(&outside, 0, 0x4000, 0x100).is_none());
    }

    #[test]
    fn parses_inno_version_triples() {
        assert_eq!(
            parse_inno_version("Inno Setup Setup Data (5.6.1)"),
            (
                Some(InnoDataVersion {
                    major: 5,
                    minor: 6,
                    patch: 1,
                    revision: 0,
                }),
                false
            )
        );
        assert_eq!(
            parse_inno_version("Inno Setup Setup Data (6.2.0) (u)"),
            (
                Some(InnoDataVersion {
                    major: 6,
                    minor: 2,
                    patch: 0,
                    revision: 0,
                }),
                true
            )
        );
        assert_eq!(
            parse_inno_version("Inno Setup Setup Data (7.0.0.3)"),
            (
                Some(InnoDataVersion {
                    major: 7,
                    minor: 0,
                    patch: 0,
                    revision: 3,
                }),
                true
            )
        );
        assert_eq!(parse_inno_version("garbage no parens"), (None, false));
        assert_eq!(
            parse_inno_version("prefix Inno Setup Setup Data (6.7.0)"),
            (None, false)
        );
        assert_eq!(
            parse_inno_version("Inno Setup Setup Data (6.7.x)"),
            (None, false)
        );
        assert_eq!(
            parse_inno_version("Inno Setup Setup Data (6.7.0) (u)"),
            (None, false)
        );
    }

    #[test]
    fn setup_header_counts_are_versioned_and_bounded_before_entry_allocation() {
        let version: InnoDataVersion = inno_version(6, 7, 0, 0);
        let info: InnoSetupInfo = InnoSetupInfo {
            version_string: "Inno Setup Setup Data (6.7.0)".to_owned(),
            version,
            unicode: true,
            encrypted: false,
            data_id_offset: 0,
            block_stream_offset: 0,
            compression: InnoCompression::Stored,
            stored_size: 0,
            loader: None,
        };
        let build = |entry_count: u32| -> Vec<u8> {
            let mut bytes: Vec<u8> = Vec::new();
            for _ in 0..setup_header_prefix_string_count(version) {
                bytes.extend_from_slice(&0u32.to_le_bytes());
            }
            for value in [1u32, 2, 3, 4, 5, 6, 7, 8] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            for _ in 0..9 {
                bytes.extend_from_slice(&entry_count.to_le_bytes());
            }
            bytes
        };
        let accepted: Vec<u8> = build(7);
        let counts: InnoSetupCounts =
            parse_inno_setup_counts(&accepted, &info).expect("bounded setup header census");
        assert_eq!(counts.languages, 1);
        assert_eq!(counts.messages, 2);
        assert_eq!(counts.permissions, 3);
        assert_eq!(counts.types, 4);
        assert_eq!(counts.components, 5);
        assert_eq!(counts.tasks, 6);
        assert_eq!(counts.directories, 7);
        assert_eq!(counts.issig_keys, 8);
        assert_eq!(counts.files, 7);
        assert_eq!(counts.uninstall_run_entries, 7);
        assert!(parse_inno_setup_counts(&accepted[..accepted.len() - 1], &info).is_err());
        assert!(parse_inno_setup_counts(&build(500_000), &info).is_err());
    }

    #[test]
    fn data_entries_decode_versioned_ranges_checksums_and_flags() -> Result<()> {
        let info: InnoSetupInfo = InnoSetupInfo {
            version_string: "Inno Setup Setup Data (6.7.0)".to_owned(),
            version: inno_version(6, 7, 0, 0),
            unicode: true,
            encrypted: false,
            data_id_offset: 0,
            block_stream_offset: 0,
            compression: InnoCompression::Stored,
            stored_size: 0,
            loader: None,
        };
        let mut bytes: Vec<u8> = Vec::new();
        for value in [2_u32, 3] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for value in [4096_u64, 11, 13, 17] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend(0_u8..32);
        bytes.extend_from_slice(&116_444_736_190_000_001_i64.to_le_bytes());
        bytes.extend_from_slice(&23_u32.to_le_bytes());
        bytes.extend_from_slice(&29_u32.to_le_bytes());
        bytes.push(0b0001_0100);

        let entries: Vec<InnoDataEntry> = parse_inno_data_entries(&bytes, &info, 1)?;
        let [entry]: &[InnoDataEntry] = entries.as_slice() else {
            return Err(inno_err("test data entry was not parsed"));
        };
        assert_eq!(entry.first_slice, 2);
        assert_eq!(entry.last_slice, 3);
        assert_eq!(entry.chunk_offset, 4096);
        assert_eq!(entry.file_offset, 11);
        assert_eq!(entry.file_size, 13);
        assert_eq!(entry.chunk_size, 17);
        assert_eq!(
            entry.checksum,
            InnoChecksum::Sha256(std::array::from_fn(|index: usize| index as u8))
        );
        assert_eq!(entry.timestamp_seconds, 19);
        assert_eq!(entry.timestamp_nanoseconds, 100);
        assert_eq!(entry.file_version, (23_u64 << 32) | 0x1d);
        assert!(entry.compressed);
        assert!(!entry.solid_break);
        assert!(entry.instruction_filter);
        assert!(!entry.encrypted);
        assert_eq!(entry.sign_mode, InnoSignMode::Unchanged);
        assert!(parse_inno_data_entries(&bytes[..bytes.len() - 1], &info, 1).is_err());
        let mut trailing: Vec<u8> = bytes.clone();
        trailing.push(0);
        assert!(parse_inno_data_entries(&trailing, &info, 1).is_err());
        let mut undefined: Vec<u8> = bytes;
        let flags_last: usize = undefined.len() - 1;
        undefined[flags_last] |= 0b1000_0000;
        assert!(parse_inno_data_entries(&undefined, &info, 1).is_err());
        Ok(())
    }

    #[test]
    fn legacy_data_entry_sign_bits_preserve_once_precedence() {
        let version: InnoDataVersion = inno_version(5, 5, 7, 0);
        assert_eq!(legacy_sign_mode(version, &[0, 0]), InnoSignMode::Unchanged);
        assert_eq!(legacy_sign_mode(version, &[0, 2]), InnoSignMode::Yes);
        assert_eq!(legacy_sign_mode(version, &[0, 4]), InnoSignMode::Once);
        assert_eq!(legacy_sign_mode(version, &[0, 6]), InnoSignMode::Once);
        assert_eq!(
            legacy_sign_mode(inno_version(6, 3, 0, 0), &[0, 6]),
            InnoSignMode::Unchanged
        );
    }

    #[test]
    fn lzma1_setup_header_stream_decodes_with_exact_extent() {
        const COMPRESSED: [u8; 51] = [
            0x5d, 0x00, 0x00, 0x10, 0x00, 0x00, 0x24, 0x9b, 0xac, 0xde, 0x20, 0x39, 0x99, 0x7e,
            0x8f, 0x05, 0x25, 0x32, 0x45, 0x8f, 0xcd, 0x08, 0xba, 0xdb, 0xd3, 0xe5, 0xe8, 0xf2,
            0x71, 0x90, 0x14, 0xf8, 0x55, 0x90, 0x96, 0xa2, 0xbc, 0x01, 0xcc, 0xb3, 0xae, 0xc7,
            0x39, 0xd3, 0xa5, 0x5f, 0xff, 0x70, 0x94, 0x00, 0x00,
        ];
        let expected: Vec<u8> = b"Inno setup metadata lzma profile\0".repeat(8);
        let mut image: Vec<u8> = crc32(&COMPRESSED).to_le_bytes().to_vec();
        image.extend_from_slice(&COMPRESSED);
        image.extend_from_slice(b"unrelated trailing bytes");
        let info: InnoSetupInfo = InnoSetupInfo {
            version_string: "Inno Setup Setup Data (4.1.6)".to_owned(),
            version: InnoDataVersion {
                major: 4,
                minor: 1,
                patch: 6,
                revision: 0,
            },
            unicode: false,
            encrypted: false,
            data_id_offset: 0,
            block_stream_offset: 0,
            compression: InnoCompression::Lzma1,
            stored_size: u64::try_from(4 + COMPRESSED.len()).expect("test frame fits u64"),
            loader: None,
        };

        assert_eq!(
            extract_inno_block_stream(&image, &info).expect("decode setup stream"),
            expected
        );
    }

    #[test]
    fn decodes_real_setup_loader_table_with_valid_crc() {
        for table in [ZLIB_TABLE, LZMA1_TABLE, LZMA2_TABLE, STORED_TABLE] {
            let offsets: SetupLoaderOffsets =
                decode_loader_table(table).expect("decode loader table");
            assert_eq!(offsets.revision, 2);
            assert!(
                offsets.table_crc_valid,
                "table_crc must validate over the real loader table"
            );
            assert!(offsets.data_offset > 0);
            assert!(offsets.header_offset > 0);
            assert!(offsets.exe_offset > 0);
        }
    }

    #[test]
    fn revision_one_loader_fields_follow_the_maintained_layout() -> Result<()> {
        let mut table: Vec<u8> = LOADER_MAGIC_515_A.to_vec();
        table.extend_from_slice(&1_u32.to_le_bytes());
        table.extend_from_slice(&0x4433_2211_u32.to_le_bytes());
        table.extend_from_slice(&0x1020_3040_u32.to_le_bytes());
        table.extend_from_slice(&0x5060_7080_u32.to_le_bytes());
        table.extend_from_slice(&0x90a0_b0c0_u32.to_le_bytes());
        table.extend_from_slice(&0x1122_3344_u32.to_le_bytes());
        table.extend_from_slice(&0x5566_7788_u32.to_le_bytes());
        let checksum: u32 = crc32(&table);
        table.extend_from_slice(&checksum.to_le_bytes());
        table.resize(LOADER_TABLE_LEN, 0);

        let decoded: SetupLoaderOffsets = decode_loader_table(&table)
            .ok_or_else(|| inno_err("revision-one loader did not decode"))?;
        assert_eq!(decoded.revision, 1);
        assert_eq!(decoded.exe_offset, 0x1020_3040);
        assert_eq!(decoded.exe_compressed_size, 0);
        assert_eq!(decoded.exe_uncompressed_size, 0x5060_7080);
        assert_eq!(decoded.exe_checksum, 0x90a0_b0c0);
        assert_eq!(decoded.header_offset, 0x1122_3344);
        assert_eq!(decoded.data_offset, 0x5566_7788);
        assert!(decoded.table_crc_valid);
        let consumed: usize = 44;
        for length in 0..consumed {
            assert!(decode_loader_table(&table[..length]).is_none(), "{length}");
        }
        Ok(())
    }

    #[test]
    fn rejects_garbage_loader_table() {
        let table: [u8; 64] = [0u8; 64];
        assert!(decode_loader_table(&table).is_none());
    }

    fn carve(chunks_bytes: &[u8]) -> Vec<Vec<u8>> {
        let info: InnoSetupInfo = InnoSetupInfo {
            version_string: "Inno Setup Setup Data (6.7.0)".to_owned(),
            version: InnoDataVersion {
                major: 6,
                minor: 7,
                patch: 0,
                revision: 0,
            },
            unicode: false,
            encrypted: false,
            data_id_offset: 0,
            block_stream_offset: 0,
            compression: InnoCompression::Zlib,
            stored_size: 0,
            loader: None,
        };
        let mut info: InnoSetupInfo = info;
        info.loader = Some(SetupLoaderOffsets {
            revision: 2,
            exe_offset: 1,
            exe_compressed_size: 1,
            exe_uncompressed_size: 1,
            exe_checksum: 0,
            header_offset: 1,
            data_offset: 0,
            table_crc_valid: true,
        });
        extract_inno_file_chunks(chunks_bytes, &info, 64 * 1024 * 1024)
            .into_iter()
            .map(|c: InnoFileChunk| c.data)
            .collect()
    }

    fn assert_all_originals_recovered(bodies: &[Vec<u8>]) {
        let solid: Vec<u8> = bodies.iter().flatten().copied().collect();
        for orig in originals() {
            let separate: bool = bodies.iter().any(|b: &Vec<u8>| b.as_slice() == orig);
            let in_solid: bool = solid.windows(orig.len()).any(|w: &[u8]| w == orig);
            assert!(
                separate || in_solid,
                "original ({} bytes) must be byte-exact in carved output",
                orig.len()
            );
        }
    }

    #[test]
    fn carves_zlib_installer_byte_exact_per_file() {
        let bodies: Vec<Vec<u8>> = carve(ZLIB_CHUNKS);
        assert!(bodies.iter().any(|b: &Vec<u8>| b.as_slice() == ORIG_APP));
        assert!(bodies.iter().any(|b: &Vec<u8>| b.as_slice() == ORIG_UTIL));
        assert!(bodies.iter().any(|b: &Vec<u8>| b.as_slice() == ORIG_README));
        assert!(bodies.iter().any(|b: &Vec<u8>| b.as_slice() == ORIG_DATA));
    }

    #[test]
    fn carves_stored_installer_byte_exact_per_file() {
        let bodies: Vec<Vec<u8>> = carve(STORED_CHUNKS);
        assert_all_originals_recovered(&bodies);
    }

    #[test]
    fn carves_lzma1_solid_chunk_recovers_all_originals() {
        let bodies: Vec<Vec<u8>> = carve(LZMA1_CHUNKS);
        assert!(!bodies.is_empty());
        assert_all_originals_recovered(&bodies);
    }

    #[test]
    fn carves_lzma2_solid_chunk_recovers_all_originals() {
        let bodies: Vec<Vec<u8>> = carve(LZMA2_CHUNKS);
        assert!(!bodies.is_empty());
        assert_all_originals_recovered(&bodies);
    }

    fn assert_exact_lzma_chunk_rejects_extent_mutations(bytes: &[u8], lzma1: bool) -> Result<()> {
        let magic_at: usize = find_subslice(bytes, &INNO_CHUNK_MAGIC, 0)
            .ok_or_else(|| inno_err("test chunk magic is absent"))?;
        let body_at: usize = magic_at
            .checked_add(INNO_CHUNK_MAGIC.len())
            .ok_or_else(|| inno_err("test chunk offset overflow"))?;
        let remainder: &[u8] = bytes
            .get(body_at..)
            .ok_or_else(|| inno_err("test chunk body is absent"))?;
        let body_end: usize =
            find_subslice(remainder, &INNO_CHUNK_MAGIC, 0).unwrap_or(remainder.len());
        let body: &[u8] = remainder
            .get(..body_end)
            .ok_or_else(|| inno_err("test chunk extent is invalid"))?;
        let permissive: (Vec<u8>, usize) = if lzma1 {
            decode_lzma1_chunk(body, MAX_INNO_OUTPUT)
        } else {
            decode_lzma2_chunk(body, MAX_INNO_OUTPUT)
        }
        .ok_or_else(|| inno_err("test chunk did not decode"))?;
        let exact_body: &[u8] = body
            .get(..permissive.1)
            .ok_or_else(|| inno_err("test decoder consumed beyond its input"))?;
        let required: u64 = u64::try_from(permissive.0.len())
            .map_err(|_error: std::num::TryFromIntError| inno_err("test output overflow"))?;
        assert_eq!(
            decode_lzma_chunk_exact(exact_body, MAX_INNO_OUTPUT, required, lzma1)?,
            permissive.0
        );
        let mut trailing: Vec<u8> = exact_body.to_vec();
        trailing.push(0);
        assert!(decode_lzma_chunk_exact(&trailing, MAX_INNO_OUTPUT, required, lzma1).is_err());
        let truncated: &[u8] = exact_body
            .get(..exact_body.len() / 2)
            .ok_or_else(|| inno_err("test truncation failed"))?;
        assert!(decode_lzma_chunk_exact(truncated, MAX_INNO_OUTPUT, required, lzma1).is_err());
        Ok(())
    }

    #[test]
    fn named_lzma_chunks_require_exact_compressed_extents() -> Result<()> {
        assert_exact_lzma_chunk_rejects_extent_mutations(LZMA1_CHUNKS, true)?;
        assert_exact_lzma_chunk_rejects_extent_mutations(LZMA2_CHUNKS, false)?;
        Ok(())
    }

    #[test]
    fn bcj_unfilter_is_involutive_with_encoder() {
        let base_offset: u32 = 0x4000;
        let original: Vec<u8> = vec![
            0xE8, 0x10, 0x20, 0x30, 0x00, 0x90, 0xE9, 0x00, 0x01, 0x00, 0x00, 0x55, 0x8B, 0xEC,
        ];
        let mut encoded: Vec<u8> = original.clone();
        let mut i: usize = 0;
        let last: usize = encoded.len() - 5;
        while i <= last {
            if encoded[i] == 0xE8 || encoded[i] == 0xE9 {
                let abs: u32 = u32::from_le_bytes([
                    encoded[i + 1],
                    encoded[i + 2],
                    encoded[i + 3],
                    encoded[i + 4],
                ]);
                let addr: u32 = base_offset.wrapping_add(i as u32).wrapping_add(5);
                let rel: [u8; 4] = abs.wrapping_add(addr).to_le_bytes();
                encoded[i + 1] = rel[0];
                encoded[i + 2] = rel[1];
                encoded[i + 3] = rel[2];
                encoded[i + 4] = rel[3];
                i += 5;
            } else {
                i += 1;
            }
        }
        let decoded: Vec<u8> =
            unfilter_instructions_at(&encoded, InnoFilter::Instruction5309, base_offset);
        assert_eq!(decoded, original);
        assert_ne!(
            unfilter_instructions(&encoded, InnoFilter::Instruction5309),
            original
        );
    }

    #[test]
    fn rejects_non_inno() {
        let bytes: Vec<u8> = vec![0u8; 4096];
        assert!(detect_innosetup(&bytes).is_none());
    }

    fn zlib_compress(input: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(input).expect("zlib write");
        enc.finish().expect("zlib finish")
    }

    fn write_test_loader(
        bytes: &mut [u8],
        data_offset: usize,
        header_offset: usize,
        exe_offset: usize,
    ) {
        const TABLE_OFFSET: usize = 0x80;
        let loader_block: &mut [u8] = &mut bytes[LEGACY_LOADER_OFFSET..LEGACY_LOADER_OFFSET + 12];
        loader_block[..4].copy_from_slice(&1_u32.to_le_bytes());
        loader_block[4..8].copy_from_slice(&(TABLE_OFFSET as u32).to_le_bytes());
        loader_block[8..12].copy_from_slice(&(!(TABLE_OFFSET as u32)).to_le_bytes());
        let mut table: Vec<u8> = LOADER_MAGIC_515_A.to_vec();
        table.extend_from_slice(&2_u32.to_le_bytes());
        table.extend_from_slice(&[0_u8; 8]);
        table.extend_from_slice(&(exe_offset as u64).to_le_bytes());
        table.extend_from_slice(&0_u32.to_le_bytes());
        table.extend_from_slice(&0_u32.to_le_bytes());
        table.extend_from_slice(&(header_offset as u64).to_le_bytes());
        table.extend_from_slice(&(data_offset as u64).to_le_bytes());
        table.extend_from_slice(&0_u32.to_le_bytes());
        table.extend_from_slice(&crc32(&table).to_le_bytes());
        table.resize(LOADER_TABLE_LEN, 0);
        bytes[TABLE_OFFSET..TABLE_OFFSET + LOADER_TABLE_LEN].copy_from_slice(&table);
    }

    fn write_test_loader_4010(
        bytes: &mut [u8],
        data_offset: usize,
        header_offset: usize,
        exe_offset: usize,
        exe_compressed_size: usize,
    ) {
        const TABLE_OFFSET: usize = 0x80;
        let loader_block: &mut [u8] = &mut bytes[LEGACY_LOADER_OFFSET..LEGACY_LOADER_OFFSET + 12];
        loader_block[..4].copy_from_slice(&1_u32.to_le_bytes());
        loader_block[4..8].copy_from_slice(&(TABLE_OFFSET as u32).to_le_bytes());
        loader_block[8..12].copy_from_slice(&(!(TABLE_OFFSET as u32)).to_le_bytes());
        let mut table: Vec<u8> = LOADER_MAGIC_4010.to_vec();
        table.extend_from_slice(&0_u32.to_le_bytes());
        table.extend_from_slice(&(exe_offset as u32).to_le_bytes());
        table.extend_from_slice(&(exe_compressed_size as u32).to_le_bytes());
        table.extend_from_slice(&(exe_compressed_size as u32).to_le_bytes());
        table.extend_from_slice(&0_u32.to_le_bytes());
        table.extend_from_slice(&(header_offset as u32).to_le_bytes());
        table.extend_from_slice(&(data_offset as u32).to_le_bytes());
        table.extend_from_slice(&crc32(&table).to_le_bytes());
        table.resize(LOADER_TABLE_LEN, 0);
        bytes[TABLE_OFFSET..TABLE_OFFSET + LOADER_TABLE_LEN].copy_from_slice(&table);
    }

    fn build_test_inno_with_data(version: &str, setup_blob: &[u8], data: &[u8]) -> Vec<u8> {
        let version_string: String = format!("Inno Setup Setup Data ({version})");
        let (data_version, _unicode): (Option<InnoDataVersion>, bool) =
            parse_inno_version(&version_string);
        let data_version: InnoDataVersion = data_version.expect("test version is valid");
        let (stored, compressed_flag): (Vec<u8>, u8) =
            if data_version >= InnoDataVersion::LZMA1_METADATA {
                (setup_blob.to_vec(), 0)
            } else {
                (zlib_compress(setup_blob), 1)
            };
        let mut out: Vec<u8> = vec![0_u8; 0x100];
        out[..2].copy_from_slice(b"MZ");
        let data_offset: usize = out.len();
        out.extend_from_slice(data);
        let header_offset: usize = out.len();
        let mut id: Vec<u8> = format!("Inno Setup Setup Data ({version})").into_bytes();
        id.resize(INNO_HEADER_ID_LEN, 0);
        out.extend_from_slice(&id);
        if data_version >= inno_version(6, 5, 0, 0) {
            let protected: [u8; 49] = [0; 49];
            out.extend_from_slice(&crc32(&protected).to_le_bytes());
            out.extend_from_slice(&protected);
        }
        let frame_count: usize = stored.len().div_ceil(INNO_CHUNK_SIZE);
        let stored_size: usize = stored
            .len()
            .checked_add(frame_count * 4)
            .expect("test block extent fits usize");
        let mut block_header: Vec<u8> = Vec::new();
        if data_version
            >= (InnoDataVersion {
                major: 6,
                minor: 7,
                patch: 0,
                revision: 0,
            })
        {
            block_header.extend_from_slice(&(stored_size as u64).to_le_bytes());
        } else {
            block_header.extend_from_slice(&(stored_size as u32).to_le_bytes());
        }
        block_header.push(compressed_flag);
        out.extend_from_slice(&crc32(&block_header).to_le_bytes());
        out.extend_from_slice(&block_header);
        for chunk in stored.chunks(INNO_CHUNK_SIZE) {
            out.extend_from_slice(&crc32(chunk).to_le_bytes());
            out.extend_from_slice(chunk);
        }
        let exe_offset: usize = out.len();
        write_test_loader(&mut out, data_offset, header_offset, exe_offset);
        out
    }

    fn build_test_inno(version: &str, setup_blob: &[u8]) -> Vec<u8> {
        build_test_inno_with_data(version, setup_blob, &INNO_CHUNK_MAGIC)
    }

    #[test]
    fn detects_and_decodes_zlib_block_stream() {
        let blob: &[u8] = &b"Inno setup header payload recovered verbatim ".repeat(40);
        let image: Vec<u8> = build_test_inno("4.1.5", blob);
        let info: InnoSetupInfo = detect_innosetup(&image).expect("detect inno");
        assert!(info.version_string.contains("4.1.5"));
        assert_eq!(info.compression, InnoCompression::Zlib);
        let recovered: Vec<u8> = extract_inno_block_stream(&image, &info).expect("decode stream");
        assert_eq!(recovered, blob);
    }

    #[test]
    fn v4010_loader_accepts_a_crc_valid_compressed_setup_engine() {
        let blob: &[u8] = &b"V4010 setup header payload ".repeat(24);
        let mut image: Vec<u8> = build_test_inno("4.1.0", blob);
        let data_offset: usize = 0x100;
        let exe_offset: usize = data_offset + INNO_CHUNK_MAGIC.len();
        let engine: [u8; 8] = [0x5d, 0, 0, 0x80, 0, 0, 0, 0];
        image.splice(exe_offset..exe_offset, engine);
        let header_offset: usize = exe_offset + engine.len();
        write_test_loader_4010(
            &mut image,
            data_offset,
            header_offset,
            exe_offset,
            engine.len(),
        );

        let info: InnoSetupInfo = detect_innosetup(&image).expect("detect V4010 loader");
        let loader: SetupLoaderOffsets = info.loader.expect("V4010 loader offsets");
        assert!(loader.table_crc_valid);
        assert_eq!(loader.exe_compressed_size, engine.len() as u64);
        assert_eq!(
            extract_inno_block_stream(&image, &info).expect("decode V4010 setup stream"),
            blob
        );

        image[0x80 + 40] ^= 0x80;
        assert!(detect_innosetup(&image).is_none());
    }

    #[test]
    fn detects_wide_block_extent_at_version_6_7_0() {
        let blob: &[u8] = &b"wide block extent ".repeat(32);
        let image: Vec<u8> = build_test_inno("6.7.0", blob);
        let info: InnoSetupInfo = detect_innosetup(&image).expect("detect wide inno header");
        assert_eq!(info.version.major, 6);
        assert_eq!(info.version.minor, 7);
        assert_eq!(
            extract_inno_block_stream(&image, &info).expect("decode wide stream"),
            blob
        );
    }

    #[test]
    fn extracts_primary_and_secondary_metadata_blocks_before_file_data() -> Result<()> {
        let primary: &[u8] = b"primary setup metadata";
        let secondary: &[u8] = b"secondary location metadata";
        let mut image: Vec<u8> = build_test_inno("6.7.0", primary);
        let secondary_stored_size: u64 = u64::try_from(secondary.len() + 4)
            .map_err(|_error: std::num::TryFromIntError| inno_err("test extent overflow"))?;
        let mut protected: Vec<u8> = secondary_stored_size.to_le_bytes().to_vec();
        protected.push(0);
        image.extend_from_slice(&crc32(&protected).to_le_bytes());
        image.extend_from_slice(&protected);
        image.extend_from_slice(&crc32(secondary).to_le_bytes());
        image.extend_from_slice(secondary);
        let data_offset: usize = image.len();
        image.extend_from_slice(b"file-data");

        let info: InnoSetupInfo =
            detect_innosetup(&image).ok_or_else(|| inno_err("test installer was not detected"))?;
        let blocks: InnoMetadataBlocks = extract_inno_metadata_blocks(&image, &info)?;
        assert_eq!(blocks.primary, primary);
        assert_eq!(blocks.secondary, secondary);
        assert_eq!(
            blocks.data_offset,
            u64::try_from(data_offset)
                .map_err(|_error: std::num::TryFromIntError| inno_err("test offset overflow"))?
        );

        assert!(extract_inno_metadata_blocks(&image[..data_offset - 1], &info).is_err());
        Ok(())
    }

    #[test]
    fn metadata_recovery_rejects_an_unreferenced_data_entry() -> Result<()> {
        let version: InnoDataVersion = inno_version(6, 7, 0, 0);
        let mut primary: Vec<u8> = Vec::new();
        append_test_setup_counts(&mut primary, version, 0, 1);
        append_test_670_header_layout(&mut primary, 4);
        primary.extend_from_slice(&[0_u8; 8]);
        let mut secondary: Vec<u8> = Vec::new();
        secondary.extend_from_slice(&0_u32.to_le_bytes());
        secondary.extend_from_slice(&0_u32.to_le_bytes());
        secondary.extend_from_slice(&0_u64.to_le_bytes());
        secondary.extend_from_slice(&3_u64.to_le_bytes());
        secondary.extend_from_slice(&3_u64.to_le_bytes());
        secondary.extend_from_slice(&3_u64.to_le_bytes());
        secondary.extend_from_slice(&[0_u8; 32]);
        secondary.extend_from_slice(&116_444_736_000_000_000_i64.to_le_bytes());
        secondary.extend_from_slice(&0_u32.to_le_bytes());
        secondary.extend_from_slice(&0_u32.to_le_bytes());
        secondary.push(0);

        let mut image: Vec<u8> = build_test_inno("6.7.0", &primary);
        let stored_size: u64 = u64::try_from(secondary.len() + 4)
            .map_err(|_error: std::num::TryFromIntError| inno_err("test block size overflow"))?;
        let mut protected: Vec<u8> = stored_size.to_le_bytes().to_vec();
        protected.push(0);
        image.extend_from_slice(&crc32(&protected).to_le_bytes());
        image.extend_from_slice(&protected);
        image.extend_from_slice(&crc32(&secondary).to_le_bytes());
        image.extend_from_slice(&secondary);
        image.extend_from_slice(b"zlb\x1apayload");

        let error: Error = recover_inno_metadata(&image).expect_err("unreferenced data must fail");
        assert!(error.to_string().contains("no file-table reference"));
        Ok(())
    }

    fn append_test_inno_string(bytes: &mut Vec<u8>, value: &[u8]) -> Result<()> {
        let length: u32 = u32::try_from(value.len())
            .map_err(|_error: std::num::TryFromIntError| inno_err("test string is too long"))?;
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(value);
        Ok(())
    }

    fn append_test_setup_counts(
        bytes: &mut Vec<u8>,
        version: InnoDataVersion,
        files: u32,
        data_entries: u32,
    ) {
        for _ in 0..setup_header_prefix_string_count(version) {
            bytes.extend_from_slice(&0_u32.to_le_bytes());
        }
        for value in [0_u32, 0, 0, 0, 0, 0, 0] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        if version >= inno_version(6, 5, 0, 0) {
            bytes.extend_from_slice(&0_u32.to_le_bytes());
        }
        for value in [files, data_entries, 0, 0, 0, 0, 0, 0, 0] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }

    fn append_test_670_header_layout(bytes: &mut Vec<u8>, compression: u8) {
        bytes.extend_from_slice(&[0_u8; 20]);
        bytes.extend_from_slice(&[0_u8; 9]);
        bytes.push(0);
        bytes.extend_from_slice(&[0_u8; 8]);
        bytes.extend_from_slice(&[0_u8; 4]);
        bytes.extend_from_slice(&[0_u8; 8]);
        bytes.extend_from_slice(&[0_u8; 4]);
        bytes.push(0);
        bytes.extend_from_slice(&[0_u8; 2]);
        bytes.extend_from_slice(&[0_u8; 8]);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&[0_u8; 6]);
        bytes.push(compression);
        bytes.extend_from_slice(&[0_u8; 10]);
        bytes.extend_from_slice(&[0_u8; 8]);
    }

    fn test_utf16(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn build_named_files_test_inno_with_index(
        destinations: &[&str],
        payload: &[u8],
        data_entry_index: u32,
    ) -> Result<Vec<u8>> {
        use sha2::Digest as _;

        let version: InnoDataVersion = inno_version(6, 7, 0, 0);
        let mut primary: Vec<u8> = Vec::new();
        let file_count: u32 = u32::try_from(destinations.len())
            .map_err(|_error: std::num::TryFromIntError| inno_err("too many test files"))?;
        append_test_setup_counts(&mut primary, version, file_count, 1);
        append_test_670_header_layout(&mut primary, 4);
        for destination in destinations {
            append_test_inno_string(&mut primary, &test_utf16("bin\\tool.exe"))?;
            append_test_inno_string(&mut primary, &test_utf16(destination))?;
            for _ in 0..8 {
                append_test_inno_string(&mut primary, &[])?;
            }
            for _ in 0..6 {
                append_test_inno_string(&mut primary, &[])?;
            }
            primary.extend_from_slice(&[0_u8; 33]);
            primary.extend_from_slice(&[0_u8; 20]);
            primary.extend_from_slice(&data_entry_index.to_le_bytes());
            primary.extend_from_slice(&0_u32.to_le_bytes());
            primary.extend_from_slice(&0_u64.to_le_bytes());
            primary.extend_from_slice(&0_i16.to_le_bytes());
            primary.extend_from_slice(&0_u64.to_le_bytes());
            primary.push(0);
        }
        primary.extend_from_slice(&[0_u8; 8]);

        let payload_len: u64 = u64::try_from(payload.len())
            .map_err(|_error: std::num::TryFromIntError| inno_err("test payload is too large"))?;
        let mut secondary: Vec<u8> = Vec::new();
        secondary.extend_from_slice(&0_u32.to_le_bytes());
        secondary.extend_from_slice(&0_u32.to_le_bytes());
        secondary.extend_from_slice(&0_u64.to_le_bytes());
        secondary.extend_from_slice(&0_u64.to_le_bytes());
        secondary.extend_from_slice(&payload_len.to_le_bytes());
        secondary.extend_from_slice(&payload_len.to_le_bytes());
        secondary.extend_from_slice(&sha2::Sha256::digest(payload));
        secondary.extend_from_slice(&116_444_736_000_000_000_i64.to_le_bytes());
        secondary.extend_from_slice(&0_u32.to_le_bytes());
        secondary.extend_from_slice(&0_u32.to_le_bytes());
        secondary.push(0);

        let mut data: Vec<u8> = INNO_CHUNK_MAGIC.to_vec();
        data.extend_from_slice(payload);
        let mut image: Vec<u8> = build_test_inno_with_data("6.7.0", &primary, &data);
        let secondary_stored_size: u64 =
            u64::try_from(secondary.len() + 4).map_err(|_error: std::num::TryFromIntError| {
                inno_err("test secondary extent overflow")
            })?;
        let mut protected: Vec<u8> = secondary_stored_size.to_le_bytes().to_vec();
        protected.push(0);
        image.extend_from_slice(&crc32(&protected).to_le_bytes());
        image.extend_from_slice(&protected);
        image.extend_from_slice(&crc32(&secondary).to_le_bytes());
        image.extend_from_slice(&secondary);
        let exe_offset: usize = image.len();
        let data_offset: usize = 0x100;
        let header_offset: usize = data_offset + data.len();
        write_test_loader(&mut image, data_offset, header_offset, exe_offset);
        Ok(image)
    }

    pub(crate) fn build_named_file_test_inno(destination: &str, payload: &[u8]) -> Result<Vec<u8>> {
        build_named_files_test_inno_with_index(&[destination], payload, 0)
    }

    pub(crate) fn build_named_aliases_test_inno(
        destinations: &[&str],
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        build_named_files_test_inno_with_index(destinations, payload, 0)
    }

    pub(crate) fn build_solid_members_test_inno(members: &[(&str, &[u8])]) -> Result<Vec<u8>> {
        use sha2::Digest as _;

        let version: InnoDataVersion = inno_version(6, 7, 0, 0);
        let member_count: u32 = u32::try_from(members.len())
            .map_err(|_error: std::num::TryFromIntError| inno_err("too many solid test members"))?;
        let mut primary: Vec<u8> = Vec::new();
        append_test_setup_counts(&mut primary, version, member_count, member_count);
        append_test_670_header_layout(&mut primary, 1);
        for (index, (destination, _payload)) in members.iter().enumerate() {
            append_test_inno_string(&mut primary, &test_utf16("solid.bin"))?;
            append_test_inno_string(&mut primary, &test_utf16(destination))?;
            for _ in 0..8 {
                append_test_inno_string(&mut primary, &[])?;
            }
            for _ in 0..6 {
                append_test_inno_string(&mut primary, &[])?;
            }
            primary.extend_from_slice(&[0_u8; 33]);
            primary.extend_from_slice(&[0_u8; 20]);
            primary.extend_from_slice(
                &u32::try_from(index)
                    .map_err(|_error: std::num::TryFromIntError| {
                        inno_err("solid test member index overflow")
                    })?
                    .to_le_bytes(),
            );
            primary.extend_from_slice(&0_u32.to_le_bytes());
            primary.extend_from_slice(&0_u64.to_le_bytes());
            primary.extend_from_slice(&0_i16.to_le_bytes());
            primary.extend_from_slice(&0_u64.to_le_bytes());
            primary.push(0);
        }
        primary.extend_from_slice(&[0_u8; 8]);
        append_test_inno_string(&mut primary, &[])?;

        let decoded: Vec<u8> = members
            .iter()
            .flat_map(|(_destination, payload): &(&str, &[u8])| payload.iter().copied())
            .collect();
        let compressed: Vec<u8> = zlib_compress(&decoded);
        let chunk_size: u64 = u64::try_from(compressed.len())
            .map_err(|_error: std::num::TryFromIntError| inno_err("solid chunk is too large"))?;
        let mut file_offset: u64 = 0;
        let mut secondary: Vec<u8> = Vec::new();
        for (_destination, payload) in members {
            let file_size: u64 =
                u64::try_from(payload.len()).map_err(|_error: std::num::TryFromIntError| {
                    inno_err("solid member is too large")
                })?;
            secondary.extend_from_slice(&0_u32.to_le_bytes());
            secondary.extend_from_slice(&0_u32.to_le_bytes());
            secondary.extend_from_slice(&0_u64.to_le_bytes());
            secondary.extend_from_slice(&file_offset.to_le_bytes());
            secondary.extend_from_slice(&file_size.to_le_bytes());
            secondary.extend_from_slice(&chunk_size.to_le_bytes());
            secondary.extend_from_slice(&sha2::Sha256::digest(payload));
            secondary.extend_from_slice(&116_444_736_000_000_000_i64.to_le_bytes());
            secondary.extend_from_slice(&0_u32.to_le_bytes());
            secondary.extend_from_slice(&0_u32.to_le_bytes());
            secondary.push(1_u8 << 4);
            file_offset = file_offset
                .checked_add(file_size)
                .ok_or_else(|| inno_err("solid member extent overflow"))?;
        }

        let mut data: Vec<u8> = INNO_CHUNK_MAGIC.to_vec();
        data.extend_from_slice(&compressed);
        let mut image: Vec<u8> = build_test_inno_with_data("6.7.0", &primary, &data);
        let secondary_stored_size: u64 =
            u64::try_from(secondary.len() + 4).map_err(|_error: std::num::TryFromIntError| {
                inno_err("solid secondary extent overflow")
            })?;
        let mut protected: Vec<u8> = secondary_stored_size.to_le_bytes().to_vec();
        protected.push(0);
        image.extend_from_slice(&crc32(&protected).to_le_bytes());
        image.extend_from_slice(&protected);
        image.extend_from_slice(&crc32(&secondary).to_le_bytes());
        image.extend_from_slice(&secondary);
        let exe_offset: usize = image.len();
        let data_offset: usize = 0x100;
        let header_offset: usize = data_offset + data.len();
        write_test_loader(&mut image, data_offset, header_offset, exe_offset);
        Ok(image)
    }

    #[test]
    fn detection_requires_a_crc_valid_loader_table() {
        let mut image: Vec<u8> = build_test_inno("6.7.0", b"marker-only setup metadata");
        image[0x80 + 60] ^= 0x80;
        assert!(detect_innosetup(&image).is_none());
        let mut misplaced: Vec<u8> = build_test_inno("6.7.0", b"misplaced data offset");
        let header_offset: usize = misplaced
            .windows(INNO_DATA_ID_PREFIX.len())
            .position(|window: &[u8]| window == INNO_DATA_ID_PREFIX)
            .expect("test header id exists");
        let exe_offset: usize = misplaced.len();
        write_test_loader(&mut misplaced, 0x101, header_offset, exe_offset);
        assert!(detect_innosetup(&misplaced).is_none());
    }

    #[test]
    fn metadata_recovery_rejects_an_invalid_file_data_edge() -> Result<()> {
        let image: Vec<u8> =
            build_named_files_test_inno_with_index(&["app\\tool.exe"], b"payload", 1)?;
        assert!(recover_inno_metadata(&image).is_err());
        Ok(())
    }

    #[test]
    fn bzip2_file_chunks_reject_trailing_compressed_bytes() -> Result<()> {
        const COMPRESSED: [u8; 74] = [
            0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xf1, 0x33, 0x1e, 0x53,
            0x00, 0x00, 0x1b, 0x99, 0x80, 0x40, 0x00, 0x10, 0x00, 0x36, 0x25, 0xc2, 0x30, 0x20,
            0x00, 0x70, 0x40, 0x00, 0x00, 0xaa, 0xa6, 0x9b, 0x53, 0x13, 0xd1, 0xa4, 0x0f, 0x47,
            0xe2, 0x45, 0x85, 0x85, 0xc4, 0x0c, 0x8c, 0x09, 0x10, 0x20, 0x50, 0xa1, 0x43, 0x83,
            0x01, 0x42, 0x85, 0xc6, 0x47, 0x04, 0x88, 0x1d, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90,
            0xf1, 0x33, 0x1e, 0x53,
        ];
        let expected: Vec<u8> = b"bounded bzip2 inno payload".repeat(8);
        assert_eq!(inflate_bzip2_chunk(&COMPRESSED, 1024)?, expected);
        let mut trailing: Vec<u8> = COMPRESSED.to_vec();
        trailing.push(0);
        assert!(inflate_bzip2_chunk(&trailing, 1024).is_err());
        Ok(())
    }

    #[test]
    fn file_table_walks_every_preceding_record_and_recovers_names() -> Result<()> {
        let version: InnoDataVersion = inno_version(6, 7, 0, 0);
        let info: InnoSetupInfo = InnoSetupInfo {
            version_string: "Inno Setup Setup Data (6.7.0)".to_owned(),
            version,
            unicode: true,
            encrypted: false,
            data_id_offset: 0,
            block_stream_offset: 0,
            compression: InnoCompression::Stored,
            stored_size: 0,
            loader: None,
        };
        let counts: InnoSetupCounts = InnoSetupCounts {
            languages: 1,
            messages: 1,
            permissions: 1,
            types: 1,
            components: 1,
            tasks: 1,
            directories: 1,
            issig_keys: 0,
            files: 1,
            data_entries: 1,
            icons: 0,
            ini_entries: 0,
            registry_entries: 0,
            delete_entries: 0,
            uninstall_delete_entries: 0,
            run_entries: 0,
            uninstall_run_entries: 0,
        };
        let mut table: Vec<u8> = Vec::new();
        for _ in 0..8 {
            append_test_inno_string(&mut table, &[])?;
        }
        table.extend_from_slice(&[0_u8; 19]);
        for _ in 0..2 {
            append_test_inno_string(&mut table, &[])?;
        }
        table.extend_from_slice(&[0_u8; 4]);
        append_test_inno_string(&mut table, &[])?;
        for _ in 0..4 {
            append_test_inno_string(&mut table, &[])?;
        }
        table.extend_from_slice(&[0_u8; 30]);
        for _ in 0..5 {
            append_test_inno_string(&mut table, &[])?;
        }
        table.extend_from_slice(&[0_u8; 39]);
        for _ in 0..6 {
            append_test_inno_string(&mut table, &[])?;
        }
        table.extend_from_slice(&[0_u8; 23]);
        for _ in 0..7 {
            append_test_inno_string(&mut table, &[])?;
        }
        table.extend_from_slice(&[0_u8; 27]);
        append_test_inno_string(&mut table, &test_utf16("bin\\tool.exe"))?;
        append_test_inno_string(&mut table, &test_utf16("{app}\\tool.exe"))?;
        append_test_inno_string(&mut table, &[])?;
        append_test_inno_string(&mut table, &[])?;
        for _ in 0..6 {
            append_test_inno_string(&mut table, &[])?;
        }
        for _ in 0..6 {
            append_test_inno_string(&mut table, &[])?;
        }
        table.extend_from_slice(&[0_u8; 33]);
        table.extend_from_slice(&[0_u8; 20]);
        table.extend_from_slice(&0_u32.to_le_bytes());
        table.extend_from_slice(&0x20_u32.to_le_bytes());
        table.extend_from_slice(&123_u64.to_le_bytes());
        table.extend_from_slice(&0_i16.to_le_bytes());
        table.extend_from_slice(&1_u64.to_le_bytes());
        table.push(0);

        let files: Vec<InnoSetupFile> = parse_inno_setup_files(&table, 0, &info, counts)?;
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].source, "bin\\tool.exe");
        assert_eq!(files[0].destination, "{app}\\tool.exe");
        assert_eq!(files[0].data_entry_index, 0);
        assert_eq!(files[0].external_size, 123);
        assert_eq!(files[0].options, 1);
        assert_eq!(files[0].file_type, 0);
        assert!(parse_inno_setup_files(&table[..table.len() - 1], 0, &info, counts).is_err());
        Ok(())
    }

    #[test]
    fn ansi_file_names_decode_cp1252_and_reject_undefined_flags() -> Result<()> {
        let version: InnoDataVersion = inno_version(4, 0, 9, 0);
        let info: InnoSetupInfo = InnoSetupInfo {
            version_string: "Inno Setup Setup Data (4.0.9)".to_owned(),
            version,
            unicode: false,
            encrypted: false,
            data_id_offset: 0,
            block_stream_offset: 0,
            compression: InnoCompression::Stored,
            stored_size: 0,
            loader: None,
        };
        let counts: InnoSetupCounts = InnoSetupCounts {
            languages: 0,
            messages: 0,
            permissions: 0,
            types: 0,
            components: 0,
            tasks: 0,
            directories: 0,
            issig_keys: 0,
            files: 1,
            data_entries: 1,
            icons: 0,
            ini_entries: 0,
            registry_entries: 0,
            delete_entries: 0,
            uninstall_delete_entries: 0,
            run_entries: 0,
            uninstall_run_entries: 0,
        };
        let mut table: Vec<u8> = Vec::new();
        append_test_inno_string(&mut table, b"price-\x80-\x81.exe")?;
        append_test_inno_string(&mut table, b"{app}\\price.exe")?;
        append_test_inno_string(&mut table, &[])?;
        for _ in 0..4 {
            append_test_inno_string(&mut table, &[])?;
        }
        table.extend_from_slice(&[0_u8; 20]);
        table.extend_from_slice(&0_u32.to_le_bytes());
        table.extend_from_slice(&0_u32.to_le_bytes());
        table.extend_from_slice(&0_u64.to_le_bytes());
        let options_at: usize = table.len();
        table.extend_from_slice(&0_u32.to_le_bytes());
        table.push(0);

        let files: Vec<InnoSetupFile> = parse_inno_setup_files(&table, 0, &info, counts)?;
        assert_eq!(files[0].source, "price-\u{20AC}-%81.exe");
        let file_type_at: usize = table.len() - 1;
        table[file_type_at] = 2;
        let registration_files: Vec<InnoSetupFile> =
            parse_inno_setup_files(&table, 0, &info, counts)?;
        assert_eq!(registration_files[0].file_type, 2);
        table[file_type_at] = 0;
        table[options_at + 2] = 1_u8 << 5;
        assert!(parse_inno_setup_files(&table, 0, &info, counts).is_err());
        Ok(())
    }

    #[test]
    fn named_recovery_uses_the_data_entry_chunk_range_and_checksum() -> Result<()> {
        let payload: &[u8] = b"abcde";
        let mut bytes: Vec<u8> = INNO_CHUNK_MAGIC.to_vec();
        bytes.extend_from_slice(payload);
        let info: InnoSetupInfo = InnoSetupInfo {
            version_string: "Inno Setup Setup Data (6.7.0)".to_owned(),
            version: inno_version(6, 7, 0, 0),
            unicode: true,
            encrypted: false,
            data_id_offset: 0,
            block_stream_offset: 0,
            compression: InnoCompression::Stored,
            stored_size: 0,
            loader: None,
        };
        let counts: InnoSetupCounts = InnoSetupCounts {
            languages: 0,
            messages: 0,
            permissions: 0,
            types: 0,
            components: 0,
            tasks: 0,
            directories: 0,
            issig_keys: 0,
            files: 2,
            data_entries: 2,
            icons: 0,
            ini_entries: 0,
            registry_entries: 0,
            delete_entries: 0,
            uninstall_delete_entries: 0,
            run_entries: 0,
            uninstall_run_entries: 0,
        };
        let first_entry: InnoDataEntry = InnoDataEntry {
            first_slice: 0,
            last_slice: 0,
            chunk_offset: 0,
            file_offset: 0,
            file_size: 2,
            chunk_size: 5,
            checksum: InnoChecksum::Crc32(crc32(b"ab")),
            timestamp_seconds: 0,
            timestamp_nanoseconds: 0,
            file_version: 0,
            compressed: false,
            encrypted: false,
            solid_break: false,
            instruction_filter: false,
            sign_mode: InnoSignMode::Unchanged,
        };
        let mut second_entry: InnoDataEntry = first_entry.clone();
        second_entry.file_offset = 2;
        second_entry.file_size = 3;
        second_entry.checksum = InnoChecksum::Crc32(crc32(b"cde"));
        let first_file: InnoSetupFile = InnoSetupFile {
            source: "bin\\first.bin".to_owned(),
            destination: "app\\first.bin".to_owned(),
            data_entry_index: 0,
            external_size: 0,
            options: 0,
            file_type: 0,
        };
        let second_file: InnoSetupFile = InnoSetupFile {
            source: "bin\\second.bin".to_owned(),
            destination: "app\\second.bin".to_owned(),
            data_entry_index: 1,
            external_size: 0,
            options: 0,
            file_type: 0,
        };
        let metadata: InnoMetadata = InnoMetadata {
            info,
            counts,
            data_entries: vec![first_entry, second_entry],
            files: vec![first_file, second_file],
            file_compression: InnoFileCompression::Stored,
            slices_per_disk: 1,
            primary_entries_offset: 0,
            data_offset: 0,
        };

        let recovered: InnoNamedRecovery = recover_inno_named_files(&bytes, &metadata, 16)?;
        assert!(recovered.refusals.is_empty());
        assert_eq!(recovered.files.len(), 2);
        assert_eq!(recovered.files[0].path, "app\\first.bin");
        assert_eq!(recovered.files[0].data, b"ab");
        assert_eq!(recovered.files[1].path, "app\\second.bin");
        assert_eq!(recovered.files[1].data, b"cde");

        let mut oversized_bytes: Vec<u8> = bytes.clone();
        oversized_bytes.push(0);
        let mut oversized: InnoMetadata = metadata.clone();
        for entry in &mut oversized.data_entries {
            entry.chunk_size = 6;
        }
        let length_refused: InnoNamedRecovery =
            recover_inno_named_files(&oversized_bytes, &oversized, 16)?;
        assert!(length_refused.files.is_empty());
        assert_eq!(length_refused.refusals.len(), 2);
        assert!(length_refused.refusals[0].contains("decoded length"));

        let mut mismatched: InnoMetadata = metadata;
        mismatched.data_entries[1].checksum = InnoChecksum::Crc32(0);
        let refused: InnoNamedRecovery = recover_inno_named_files(&bytes, &mismatched, 16)?;
        assert_eq!(refused.files.len(), 1);
        assert_eq!(refused.refusals.len(), 1);
        assert!(refused.refusals[0].contains("checksum mismatch"));
        Ok(())
    }

    #[test]
    fn extract_to_publishes_validated_named_members() -> Result<()> {
        let payload: &[u8] = b"named inno member";
        let image: Vec<u8> = build_named_file_test_inno("app\\tool.exe", payload)?;
        let metadata: InnoMetadata = recover_inno_metadata(&image)?;
        let named_recovery: InnoNamedRecovery =
            recover_inno_named_files(&image, &metadata, MAX_INNO_OUTPUT)?;
        assert!(
            named_recovery.refusals.is_empty(),
            "unexpected named recovery refusals: {:?}",
            named_recovery.refusals
        );
        assert_eq!(named_recovery.files.len(), 1);
        assert_eq!(named_recovery.files[0].path, "app\\tool.exe");
        assert_eq!(named_recovery.files[0].data, payload);
        let scratch: disrobe_core::scratch::ScratchDir = disrobe_core::scratch::ScratchDir::create(
            "binfmt-inno-named",
        )
        .map_err(|error: std::io::Error| inno_err(format!("test scratch failed: {error}")))?;
        let result: crate::extract::ExtractionResult = crate::extract::extract_to(
            crate::container::ContainerKind::InnoSetup,
            &image,
            scratch.path(),
        )?;
        let named: Option<&crate::extract::ExtractedEntry> = result
            .entries
            .iter()
            .find(|entry: &&crate::extract::ExtractedEntry| entry.name == "app/tool.exe");
        let named: &crate::extract::ExtractedEntry =
            named.ok_or_else(|| inno_err("named member was not published"))?;
        let disk_path: &std::path::Path = named
            .disk_path
            .as_deref()
            .ok_or_else(|| inno_err("named member has no output path"))?;
        let recovered: Vec<u8> = std::fs::read(disk_path)?;
        assert_eq!(recovered, payload);
        assert!(
            result
                .entries
                .iter()
                .all(|entry: &crate::extract::ExtractedEntry| entry.name != "file-0.bin")
        );
        Ok(())
    }

    #[test]
    fn legacy_file_compression_uses_the_versioned_setup_option_bit() -> Result<()> {
        for (version, flag_count, bzip_bit) in [
            (inno_version(4, 0, 9, 0), 42_usize, 32_usize),
            (inno_version(4, 0, 10, 0), 40_usize, 32_usize),
            (inno_version(4, 1, 2, 0), 39_usize, 31_usize),
            (inno_version(4, 1, 4, 0), 40_usize, 31_usize),
        ] {
            assert_eq!(setup_option_flag_count(version, false), flag_count);
            let info: InnoSetupInfo = InnoSetupInfo {
                version_string: format!(
                    "Inno Setup Setup Data ({}.{}.{})",
                    version.major, version.minor, version.patch
                ),
                version,
                unicode: false,
                encrypted: false,
                data_id_offset: 0,
                block_stream_offset: 0,
                compression: InnoCompression::Zlib,
                stored_size: 0,
                loader: None,
            };
            let mut header: Vec<u8> = vec![0_u8; 20 + 8 + 4 + 4 + 4 + 8 + 4 + 5];
            let slices_at: usize = 20 + 8 + 4 + 4 + 4 + 8;
            header[slices_at..slices_at + 4].copy_from_slice(&1_u32.to_le_bytes());
            if version >= inno_version(4, 0, 10, 0) {
                header.extend_from_slice(&[0_u8; 2]);
            }
            let flags_at: usize = header.len();
            header.resize(flags_at + flag_count.div_ceil(8), 0);
            header[flags_at + bzip_bit / 8] |= 1_u8 << (bzip_bit % 8);

            assert_eq!(
                parse_inno_header_layout(&header, &info, 0)?,
                (InnoFileCompression::Bzip2, 1, header.len())
            );
            header[flags_at + bzip_bit / 8] = 0;
            assert_eq!(
                parse_inno_header_layout(&header, &info, 0)?,
                (InnoFileCompression::Zlib, 1, header.len())
            );
            let last_flag: usize = flags_at + flag_count.div_ceil(8) - 1;
            let undefined_bit: usize = flag_count % 8;
            if undefined_bit != 0 {
                header[last_flag] |= 1_u8 << undefined_bit;
                assert!(parse_inno_header_layout(&header, &info, 0).is_err());
                header[last_flag] = 0;
            }
            assert!(parse_inno_header_layout(&header[..last_flag], &info, 0).is_err());
        }
        Ok(())
    }

    #[test]
    fn rejects_block_header_crc_mismatch() {
        let blob: &[u8] = &b"header checksum ".repeat(16);
        let mut image: Vec<u8> = build_test_inno("6.6.1", blob);
        let checksum_at: usize = image
            .windows(INNO_DATA_ID_PREFIX.len())
            .position(|window: &[u8]| window == INNO_DATA_ID_PREFIX)
            .expect("test image contains data id")
            + INNO_HEADER_ID_LEN;
        image[checksum_at] ^= 0x80;
        assert!(detect_innosetup(&image).is_none());
    }

    #[test]
    fn compression_profile_changes_at_version_4_1_6() {
        let zlib_version: InnoDataVersion = InnoDataVersion {
            major: 4,
            minor: 1,
            patch: 5,
            revision: 0,
        };
        let lzma_version: InnoDataVersion = InnoDataVersion {
            major: 4,
            minor: 1,
            patch: 6,
            revision: 0,
        };
        assert_eq!(
            compression_for_version(zlib_version, 0),
            Some(InnoCompression::Stored)
        );
        assert_eq!(
            compression_for_version(zlib_version, 1),
            Some(InnoCompression::Zlib)
        );
        assert_eq!(
            compression_for_version(lzma_version, 0),
            Some(InnoCompression::Stored)
        );
        assert_eq!(
            compression_for_version(lzma_version, 1),
            Some(InnoCompression::Lzma1)
        );
        assert_eq!(compression_for_version(lzma_version, 2), None);
    }

    #[test]
    fn detection_enforces_declared_data_version_range() {
        let before: Vec<u8> = build_test_inno("4.0.8", b"before supported range");
        let first: Vec<u8> = build_test_inno("4.0.9", b"first supported version");
        let unknown: Vec<u8> = build_test_inno("4.1.7", b"unknown setup data version");
        let last: Vec<u8> = build_test_inno("7.0.0.3", b"last supported version");
        let after: Vec<u8> = build_test_inno("7.0.0.4", b"after supported range");
        assert!(detect_innosetup(&before).is_none());
        assert!(detect_innosetup(&first).is_some());
        assert!(detect_innosetup(&unknown).is_none());
        assert!(detect_innosetup(&last).is_some());
        assert!(detect_innosetup(&after).is_none());
    }

    #[test]
    fn extract_to_writes_decoded_header_blob() {
        let blob: &[u8] = &b"inno end-to-end setup-data stream 0xCAFEBABE ".repeat(30);
        let mut image: Vec<u8> = build_test_inno("6.3.0", blob);
        image.extend_from_slice(&INNO_CHUNK_MAGIC);
        image.extend_from_slice(b"untrusted marker payload");
        let dir: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-inno-e2e")
                .expect("create scratch dir");
        let result: crate::extract::ExtractionResult = crate::extract::extract_to(
            crate::container::ContainerKind::InnoSetup,
            &image,
            dir.path(),
        )
        .expect("inno extract");
        assert_eq!(result.kind, crate::container::ContainerKind::InnoSetup);
        assert_eq!(
            std::fs::read(dir.path().join("setup-headers.bin")).expect("header blob"),
            blob
        );
        assert!(
            result
                .entries
                .iter()
                .all(|entry: &crate::extract::ExtractedEntry| entry.name != "file-0.bin")
        );
        assert!(
            result
                .integrity_violations
                .iter()
                .any(|violation: &String| violation.starts_with("inno-metadata-refusal:"))
        );
    }
}
