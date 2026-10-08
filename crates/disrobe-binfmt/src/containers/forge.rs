use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::containers::forge_block::BlockMagic;
use crate::containers::{MAX_CONTAINER_METADATA_BYTES, admit_metadata_bytes};
use crate::error::{Error, Result};
use disrobe_bytes::ByteReader;

pub const FORGE_MAGIC: &[u8; 9] = b"scimitar\0";
pub const SUPPORTED_VERSIONS: &[u32] = &[27, 28, 29, 30, 33, 34];
pub const MAX_TABLES: usize = 64;
pub const MAX_FAT_SLOTS_PER_TABLE: usize = 1 << 20;
pub const MAX_TOTAL_ENTRIES: usize = 1 << 21;
pub const MAX_META_RECORD_BYTES: u64 = 4096;
pub const MAX_DIR_SLOTS: usize = 1 << 16;
pub const MAX_DESCRIPTOR_FIELDS: usize = 1024;
pub const MAX_DESCRIPTOR_TEXT_BYTES: usize = 4096;

pub const TABLE_DESCRIPTOR_LEN: usize = 48;
pub const FAT_RECORD_LEN: usize = 20;
pub const META_RECORD_LEN: u64 = 0x140;
pub const META_NAME_LEN: usize = 255;
pub const DIRECTORY_RECORD_LEN: u64 = 0x130;
pub const ENTRY_PAGE: u64 = 4096;
pub const ENTRY_HEAD_LEN: usize = 8;
const HEADER_PREFIX_LEN: usize = 0x2E;

pub const DESCRIPTOR_TAG: u32 = 1;
pub const DESCRIPTOR_TERMINATOR: [u8; 4] = [0; 4];
pub const FAST_LOAD_TOC_TAG: u32 = 6;
pub const RIFF_MAGIC: &[u8; 4] = b"RIFF";

pub const V34_OFFSET_K1: u64 = 0x2CBC_B979_EE3B_5724;
pub const V34_OFFSET_K2: u64 = 0x0000_000A_CA88_8000;
pub const V34_SIZE_K1: u32 = 0x53B7_1C06;
pub const V34_SIZE_K2: u32 = 0x02BF_AC5F;
pub const V34_UID_K1: u64 = 0x0343_3030_0A4C_8047;
pub const V34_UID_K2: u64 = 0xF9EA_2B4F_540B_495B;

pub const NAME_BASE_KEY: u64 = 0xA860_F0EC_DE33_39FB;
pub const ENTRY_NAME_KEY_STEP: u64 = 0x3572_67C7_6FFB_9EB2;
pub const FILE_NAME_KEY_STEP: u64 = 0xE684_BFF8_5769_9452;

#[must_use]
pub const fn descramble_v34_offset(encoded: u64) -> u64 {
    V34_OFFSET_K1.wrapping_sub(encoded ^ V34_OFFSET_K2)
}

#[must_use]
pub const fn descramble_v34_size(encoded: u32) -> u32 {
    V34_SIZE_K1.wrapping_sub(encoded ^ V34_SIZE_K2)
}

#[must_use]
pub const fn descramble_v34_uid(encoded: u64) -> u64 {
    V34_UID_K1.wrapping_sub(encoded) ^ V34_UID_K2
}

pub fn name_xor(buffer: &mut [u8], uid: u64, data_offset: u64, file_type: u32, step: u64) {
    let mut key: u64 = NAME_BASE_KEY
        .wrapping_add(uid)
        .wrapping_add(data_offset)
        .wrapping_add(u64::from(file_type))
        .wrapping_add(u64::from(file_type) << 32);
    for block in buffer.chunks_mut(8) {
        for (byte, key_byte) in block.iter_mut().zip(key.to_le_bytes()) {
            *byte ^= key_byte;
        }
        key = key.wrapping_add(step);
    }
}

pub trait ForgeSource {
    fn len(&self) -> u64;

    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ForgeSource for [u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }

    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let start: usize = usize::try_from(offset)
            .map_err(|_| source_truncated(offset, len, <[u8]>::len(self) as u64))?;
        let end: usize = start
            .checked_add(len)
            .ok_or_else(|| source_truncated(offset, len, <[u8]>::len(self) as u64))?;
        self.get(start..end)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| source_truncated(offset, len, <[u8]>::len(self) as u64))
    }
}

impl ForgeSource for std::fs::File {
    fn len(&self) -> u64 {
        self.metadata()
            .map_or(0, |meta: std::fs::Metadata| meta.len())
    }

    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let total: u64 = ForgeSource::len(self);
        let end: u64 = offset
            .checked_add(len as u64)
            .ok_or_else(|| source_truncated(offset, len, total))?;
        if end > total {
            return Err(source_truncated(offset, len, total));
        }
        let mut out: Vec<u8> = vec![0u8; len];
        read_exact_at(self, offset, &mut out)?;
        Ok(out)
    }
}

#[cfg(windows)]
fn read_exact_at(file: &std::fs::File, mut offset: u64, mut out: &mut [u8]) -> Result<()> {
    use std::os::windows::fs::FileExt;
    while !out.is_empty() {
        let read: usize = file.seek_read(out, offset)?;
        if read == 0 {
            return Err(Error::Io(std::io::Error::from(
                std::io::ErrorKind::UnexpectedEof,
            )));
        }
        offset += read as u64;
        out = &mut out[read..];
    }
    Ok(())
}

#[cfg(unix)]
fn read_exact_at(file: &std::fs::File, offset: u64, out: &mut [u8]) -> Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(out, offset)?;
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn read_exact_at(_file: &std::fs::File, offset: u64, out: &mut [u8]) -> Result<()> {
    Err(source_truncated(offset, out.len(), 0))
}

fn source_truncated(offset: u64, len: usize, total: u64) -> Error {
    Error::ForgeMalformed(format!(
        "read of {len} bytes at offset {offset} runs past the {total}-byte archive"
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeHeader {
    pub version: u32,
    pub header_size: u32,
    pub reserved: u32,
    pub global_meta_file_key: u64,
    pub flag: u8,
    pub max_files: u32,
    pub max_dirs: u32,
    pub unknown_a: u32,
    pub unknown_b: u32,
    pub extra_words: Vec<u32>,
    pub first_free_file: i32,
    pub first_free_dir: i32,
    pub size_of_fat: u32,
    pub num_tables: u32,
    pub first_table_pos: u64,
    pub header_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeTable {
    pub position: u64,
    pub num_files: u32,
    pub num_dirs: u32,
    pub pos_fat: u64,
    pub next_pos_fat: i64,
    pub first_index: u32,
    pub last_index: u32,
    pub slots: usize,
    pub meta_table_offset: i64,
    pub directory_offset: i64,
    pub meta_record_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeMeta {
    pub name: Option<String>,
    pub name_length: u8,
    pub timestamp: u32,
    pub prev_entry_index: i32,
    pub next_entry_index: i32,
    pub file_type: u32,
    pub data_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForgeEntryKind {
    Descriptor,
    FastLoadToc,
    FileContainer { magic: BlockMagic },
    RawRiff,
    Empty,
    Unknown { head: u64 },
}

impl ForgeEntryKind {
    #[must_use]
    pub fn from_head(size: u32, head: &[u8]) -> Self {
        if size == 0 {
            return Self::Empty;
        }
        if let Some(magic) = BlockMagic::from_bytes(head) {
            return Self::FileContainer { magic };
        }
        if head.starts_with(RIFF_MAGIC) {
            return Self::RawRiff;
        }
        let Some(first): Option<[u8; 4]> = head.get(..4).and_then(|b: &[u8]| b.try_into().ok())
        else {
            return Self::Unknown {
                head: head
                    .iter()
                    .rev()
                    .fold(0u64, |acc: u64, &b: &u8| (acc << 8) | u64::from(b)),
            };
        };
        match u32::from_le_bytes(first) {
            DESCRIPTOR_TAG => Self::Descriptor,
            FAST_LOAD_TOC_TAG => Self::FastLoadToc,
            _ => Self::Unknown {
                head: head
                    .iter()
                    .rev()
                    .fold(0u64, |acc: u64, &b: &u8| (acc << 8) | u64::from(b)),
            },
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Descriptor => "descriptor",
            Self::FastLoadToc => "fast-load-toc",
            Self::FileContainer { .. } => "file-container",
            Self::RawRiff => "raw-riff",
            Self::Empty => "empty",
            Self::Unknown { .. } => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeEntry {
    pub index: usize,
    pub table: usize,
    pub uid: u64,
    pub uid_opaque: bool,
    pub data_offset: u64,
    pub size: u32,
    pub page_aligned: bool,
    pub kind: ForgeEntryKind,
    pub meta: Option<ForgeMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeArchive {
    pub header: ForgeHeader,
    pub tables: Vec<ForgeTable>,
    pub entries: Vec<ForgeEntry>,
    pub free_slots: usize,
    pub directories: usize,
    pub source_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DescriptorValue {
    U32(u32),
    U64(u64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorField {
    pub id: u32,
    pub kind: u32,
    pub value: DescriptorValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLoadToc {
    pub hash_a: u64,
    pub hash_b: u64,
    pub name: Option<String>,
    pub trailer: Vec<u8>,
}

#[must_use]
pub fn detect_forge(bytes: &[u8]) -> bool {
    bytes.starts_with(FORGE_MAGIC)
}

const fn malformed(detail: String) -> Error {
    Error::ForgeMalformed(detail)
}

fn truncated(what: &str) -> Error {
    malformed(format!("header truncated inside {what}"))
}

#[must_use]
pub const fn extra_header_words(version: u32) -> usize {
    if version == 34 { 2 } else { 1 }
}

#[must_use]
pub const fn version_supported(version: u32) -> bool {
    matches!(version, 27..=30 | 33 | 34)
}

#[must_use]
pub const fn header_len_for(version: u32) -> usize {
    HEADER_PREFIX_LEN + 4 * extra_header_words(version) + 24
}

pub fn parse_header(bytes: &[u8]) -> Result<ForgeHeader> {
    if !detect_forge(bytes) {
        return Err(malformed("missing `scimitar` signature".to_owned()));
    }
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .skip(FORGE_MAGIC.len())
        .map_err(|_| truncated("magic"))?;
    let version: u32 = reader.read_u32_le().map_err(|_| truncated("version"))?;
    if !version_supported(version) {
        return Err(Error::ForgeUnsupportedVersion {
            version,
            supported: "27, 28, 29, 30, 33 and 34",
        });
    }
    let header_size: u32 = reader.read_u32_le().map_err(|_| truncated("header size"))?;
    let reserved: u32 = reader.read_u32_le().map_err(|_| truncated("reserved"))?;
    let global_meta_file_key: u64 = reader
        .read_u64_le()
        .map_err(|_| truncated("global meta file key"))?;
    let flag: u8 = reader.read_u8().map_err(|_| truncated("flag"))?;
    let max_files: u32 = reader.read_u32_le().map_err(|_| truncated("max files"))?;
    let max_dirs: u32 = reader.read_u32_le().map_err(|_| truncated("max dirs"))?;
    let unknown_a: u32 = reader.read_u32_le().map_err(|_| truncated("unknown a"))?;
    let unknown_b: u32 = reader.read_u32_le().map_err(|_| truncated("unknown b"))?;
    let mut extra_words: Vec<u32> = Vec::with_capacity(extra_header_words(version));
    for _ in 0..extra_header_words(version) {
        extra_words.push(
            reader
                .read_u32_le()
                .map_err(|_| truncated("reserved words"))?,
        );
    }
    let first_free_file: i32 = reader
        .read_i32_le()
        .map_err(|_| truncated("first free file"))?;
    let first_free_dir: i32 = reader
        .read_i32_le()
        .map_err(|_| truncated("first free dir"))?;
    let size_of_fat: u32 = reader.read_u32_le().map_err(|_| truncated("size of fat"))?;
    let num_tables: u32 = reader.read_u32_le().map_err(|_| truncated("table count"))?;
    let first_table_pos_raw: i64 = reader
        .read_i64_le()
        .map_err(|_| truncated("first table position"))?;
    let first_table_pos: u64 = u64::try_from(first_table_pos_raw).map_err(|_| {
        malformed(format!(
            "negative first table position {first_table_pos_raw}"
        ))
    })?;
    if num_tables == 0 || num_tables as usize > MAX_TABLES {
        return Err(malformed(format!(
            "header declares {num_tables} tables, outside 1..={MAX_TABLES}"
        )));
    }
    if max_files as usize > MAX_TOTAL_ENTRIES {
        return Err(malformed(format!(
            "header declares {max_files} file slots, above the {MAX_TOTAL_ENTRIES}-entry cap"
        )));
    }
    if max_dirs as usize > MAX_DIR_SLOTS {
        return Err(malformed(format!(
            "header declares {max_dirs} directory slots, above the {MAX_DIR_SLOTS}-slot cap"
        )));
    }
    Ok(ForgeHeader {
        version,
        header_size,
        reserved,
        global_meta_file_key,
        flag,
        max_files,
        max_dirs,
        unknown_a,
        unknown_b,
        extra_words,
        first_free_file,
        first_free_dir,
        size_of_fat,
        num_tables,
        first_table_pos,
        header_len: reader.position(),
    })
}

fn parse_table(bytes: &[u8], position: u64) -> Result<ForgeTable> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let err = |what: &str| malformed(format!("table at {position} truncated inside {what}"));
    let num_files_raw: i32 = reader.read_i32_le().map_err(|_| err("file count"))?;
    let num_dirs_raw: i32 = reader.read_i32_le().map_err(|_| err("dir count"))?;
    let pos_fat_raw: i64 = reader.read_i64_le().map_err(|_| err("fat position"))?;
    let next_pos_fat: i64 = reader.read_i64_le().map_err(|_| err("next table"))?;
    let first_index_raw: i32 = reader.read_i32_le().map_err(|_| err("first index"))?;
    let last_index_raw: i32 = reader.read_i32_le().map_err(|_| err("last index"))?;
    let meta_table_offset: i64 = reader.read_i64_le().map_err(|_| err("meta offset"))?;
    let directory_offset: i64 = reader.read_i64_le().map_err(|_| err("directory offset"))?;
    let num_files: u32 = u32::try_from(num_files_raw)
        .map_err(|_| malformed(format!("table at {position} has negative file count")))?;
    let num_dirs: u32 = u32::try_from(num_dirs_raw)
        .map_err(|_| malformed(format!("table at {position} has negative dir count")))?;
    let pos_fat: u64 = u64::try_from(pos_fat_raw)
        .map_err(|_| malformed(format!("table at {position} has negative fat position")))?;
    let first_index: u32 = u32::try_from(first_index_raw)
        .map_err(|_| malformed(format!("table at {position} has negative first index")))?;
    let last_index: u32 = u32::try_from(last_index_raw)
        .map_err(|_| malformed(format!("table at {position} has negative last index")))?;
    let slots: usize = if num_files == 0 && last_index < first_index {
        0
    } else {
        let span: u32 = last_index.checked_sub(first_index).ok_or_else(|| {
            malformed(format!(
                "table at {position} has last index {last_index} below first index {first_index}"
            ))
        })?;
        span as usize + 1
    };
    if slots > MAX_FAT_SLOTS_PER_TABLE {
        return Err(malformed(format!(
            "table at {position} spans {slots} slots, above the {MAX_FAT_SLOTS_PER_TABLE}-slot cap"
        )));
    }
    if num_files as usize > slots {
        return Err(malformed(format!(
            "table at {position} uses {num_files} files but spans only {slots} slots"
        )));
    }
    if num_dirs as usize > MAX_DIR_SLOTS {
        return Err(malformed(format!(
            "table at {position} declares {num_dirs} directories, above the {MAX_DIR_SLOTS}-slot cap"
        )));
    }
    let meta_record_bytes: Option<u64> = if slots > 0
        && meta_table_offset > 0
        && directory_offset > meta_table_offset
    {
        let span: u64 = (directory_offset - meta_table_offset) as u64;
        if !span.is_multiple_of(slots as u64) {
            return Err(malformed(format!(
                "table at {position}: meta span {span} is not a whole number of {slots} records"
            )));
        }
        let record: u64 = span / slots as u64;
        if record > MAX_META_RECORD_BYTES {
            return Err(malformed(format!(
                "table at {position}: meta record of {record} bytes is above the {MAX_META_RECORD_BYTES}-byte cap"
            )));
        }
        Some(record)
    } else {
        None
    };
    Ok(ForgeTable {
        position,
        num_files,
        num_dirs,
        pos_fat,
        next_pos_fat,
        first_index,
        last_index,
        slots,
        meta_table_offset,
        directory_offset,
        meta_record_bytes,
    })
}

struct RawFat {
    offset: u64,
    uid: u64,
    size: u32,
    all_zero: bool,
}

fn decode_fat_record(version: u32, record: &[u8]) -> RawFat {
    let offset_raw: u64 = u64::from_le_bytes(record[0..8].try_into().unwrap_or([0; 8]));
    let uid_raw: u64 = u64::from_le_bytes(record[8..16].try_into().unwrap_or([0; 8]));
    let size_raw: u32 = u32::from_le_bytes(record[16..20].try_into().unwrap_or([0; 4]));
    let all_zero: bool = record.iter().all(|&b: &u8| b == 0);
    if version == 34 {
        RawFat {
            offset: descramble_v34_offset(offset_raw),
            uid: descramble_v34_uid(uid_raw),
            size: descramble_v34_size(size_raw),
            all_zero,
        }
    } else {
        RawFat {
            offset: offset_raw,
            uid: uid_raw,
            size: size_raw,
            all_zero,
        }
    }
}

fn parse_meta_record(version: u32, record: &[u8], uid: u64, data_offset: u64) -> Option<ForgeMeta> {
    if record.len() != META_RECORD_LEN as usize || record.iter().all(|&b: &u8| b == 0) {
        return None;
    }
    let u32_at =
        |at: usize| -> u32 { u32::from_le_bytes(record[at..at + 4].try_into().unwrap_or([0; 4])) };
    let i32_at =
        |at: usize| -> i32 { i32::from_le_bytes(record[at..at + 4].try_into().unwrap_or([0; 4])) };
    let (name_at, name_length, timestamp, prev, next, file_type, data_size): (
        usize,
        u8,
        u32,
        i32,
        i32,
        u32,
        u32,
    ) = if version >= 30 {
        (
            0x14,
            record[0x113],
            u32_at(0x114),
            i32_at(0x11C),
            i32_at(0x120),
            u32_at(0x12C),
            u32_at(0x13C),
        )
    } else {
        (
            0x28,
            record[0x127],
            u32_at(0x24),
            i32_at(0x20),
            i32_at(0x1C),
            u32_at(0x10),
            u32_at(0x00),
        )
    };
    let name: Option<String> = (name_length > 0).then(|| {
        let mut encoded: [u8; META_NAME_LEN] = [0u8; META_NAME_LEN];
        encoded.copy_from_slice(&record[name_at..name_at + META_NAME_LEN]);
        name_xor(
            &mut encoded,
            uid,
            data_offset,
            file_type,
            ENTRY_NAME_KEY_STEP,
        );
        String::from_utf8_lossy(&encoded[..usize::from(name_length)]).into_owned()
    });
    Some(ForgeMeta {
        name,
        name_length,
        timestamp,
        prev_entry_index: prev,
        next_entry_index: next,
        file_type,
        data_size,
    })
}

pub fn parse_forge_from<S: ForgeSource + ?Sized>(source: &S) -> Result<ForgeArchive> {
    let source_len: u64 = source.len();
    let head_len: usize =
        usize::try_from(source_len.min(header_len_for(34) as u64)).unwrap_or(header_len_for(34));
    let head: Vec<u8> = source.read_at(0, head_len)?;
    let header: ForgeHeader = parse_header(&head)?;
    let mut metadata_bytes: usize = 0;
    let mut tables: Vec<ForgeTable> = Vec::new();
    let mut entries: Vec<ForgeEntry> = Vec::new();
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut free_slots: usize = 0;
    let mut directories: usize = 0;
    let mut position: u64 = header.first_table_pos;
    let mut total_slots: usize = 0;
    loop {
        if tables.len() >= MAX_TABLES {
            return Err(malformed(format!(
                "table chain is longer than the {MAX_TABLES}-table cap"
            )));
        }
        if !visited.insert(position) {
            return Err(malformed(format!(
                "table chain revisits position {position}"
            )));
        }
        let descriptor: Vec<u8> = source.read_at(position, TABLE_DESCRIPTOR_LEN)?;
        let table: ForgeTable = parse_table(&descriptor, position)?;
        total_slots = total_slots.saturating_add(table.slots);
        if total_slots > MAX_TOTAL_ENTRIES {
            return Err(malformed(format!(
                "tables span {total_slots} slots in total, above the {MAX_TOTAL_ENTRIES}-entry cap"
            )));
        }
        let fat_bytes: usize = table.slots * FAT_RECORD_LEN;
        admit_metadata_bytes(
            &mut metadata_bytes,
            fat_bytes,
            MAX_CONTAINER_METADATA_BYTES,
            "forge fat",
        )?;
        let fat: Vec<u8> = source.read_at(table.pos_fat, fat_bytes)?;
        let meta: Option<Vec<u8>> = match table.meta_record_bytes {
            Some(META_RECORD_LEN) => {
                let meta_bytes: usize = table.slots * META_RECORD_LEN as usize;
                admit_metadata_bytes(
                    &mut metadata_bytes,
                    meta_bytes,
                    MAX_CONTAINER_METADATA_BYTES,
                    "forge meta table",
                )?;
                Some(source.read_at(table.meta_table_offset as u64, meta_bytes)?)
            }
            _ => None,
        };
        directories = directories.saturating_add(table.num_dirs as usize);
        let table_index: usize = tables.len();
        for slot in 0..table.slots {
            let record: &[u8] = &fat[slot * FAT_RECORD_LEN..(slot + 1) * FAT_RECORD_LEN];
            let raw: RawFat = decode_fat_record(header.version, record);
            if slot >= table.num_files as usize || raw.all_zero {
                free_slots += 1;
                continue;
            }
            let end: u64 = raw.offset.checked_add(u64::from(raw.size)).ok_or_else(|| {
                malformed(format!(
                    "fat slot {slot} of table {table_index}: offset {} plus size {} overflows",
                    raw.offset, raw.size
                ))
            })?;
            if end > source_len {
                return Err(malformed(format!(
                    "fat slot {slot} of table {table_index}: entry {}..{end} runs past the {source_len}-byte archive",
                    raw.offset
                )));
            }
            let head_len: usize = (u64::from(raw.size).min(ENTRY_HEAD_LEN as u64)) as usize;
            let head: Vec<u8> = source.read_at(raw.offset, head_len)?;
            let kind: ForgeEntryKind = ForgeEntryKind::from_head(raw.size, &head);
            let meta_record: Option<ForgeMeta> = meta.as_ref().and_then(|table_meta: &Vec<u8>| {
                let at: usize = slot * META_RECORD_LEN as usize;
                parse_meta_record(
                    header.version,
                    &table_meta[at..at + META_RECORD_LEN as usize],
                    raw.uid,
                    raw.offset,
                )
            });
            entries.push(ForgeEntry {
                index: entries.len(),
                table: table_index,
                uid: raw.uid,
                uid_opaque: header.version == 33,
                data_offset: raw.offset,
                size: raw.size,
                page_aligned: raw.offset.is_multiple_of(ENTRY_PAGE),
                kind,
                meta: meta_record,
            });
        }
        let next: i64 = table.next_pos_fat;
        tables.push(table);
        if next < 0 {
            break;
        }
        position = next as u64;
    }
    Ok(ForgeArchive {
        header,
        tables,
        entries,
        free_slots,
        directories,
        source_len,
    })
}

pub fn parse_forge(bytes: &[u8]) -> Result<ForgeArchive> {
    parse_forge_from(bytes)
}

pub fn forge_entry_bytes<'a>(bytes: &'a [u8], entry: &ForgeEntry) -> Result<&'a [u8]> {
    let start: usize = usize::try_from(entry.data_offset).map_err(|_| {
        source_truncated(entry.data_offset, entry.size as usize, bytes.len() as u64)
    })?;
    let end: usize = start.checked_add(entry.size as usize).ok_or_else(|| {
        source_truncated(entry.data_offset, entry.size as usize, bytes.len() as u64)
    })?;
    bytes
        .get(start..end)
        .ok_or_else(|| source_truncated(entry.data_offset, entry.size as usize, bytes.len() as u64))
}

pub fn read_entry<S: ForgeSource + ?Sized>(
    source: &S,
    entry: &ForgeEntry,
    cap: u64,
) -> Result<Vec<u8>> {
    if u64::from(entry.size) > cap {
        return Err(Error::QuotaExceeded {
            entry: format!("{:016x}", entry.uid),
            reason: format!(
                "entry container of {} bytes exceeds the {cap}-byte cap",
                entry.size
            ),
        });
    }
    source.read_at(entry.data_offset, entry.size as usize)
}

pub fn parse_descriptor(bytes: &[u8]) -> Result<Vec<DescriptorField>> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let tag: u32 = reader
        .read_u32_le()
        .map_err(|_| malformed("descriptor shorter than its tag".to_owned()))?;
    if tag != DESCRIPTOR_TAG {
        return Err(malformed(format!(
            "descriptor tag is {tag}, expected {DESCRIPTOR_TAG}"
        )));
    }
    let mut fields: Vec<DescriptorField> = Vec::new();
    while !reader.is_empty() {
        if fields.len() >= MAX_DESCRIPTOR_FIELDS {
            return Err(malformed(format!(
                "descriptor carries more than {MAX_DESCRIPTOR_FIELDS} fields"
            )));
        }
        let at: usize = reader.position();
        if reader.remaining() < 8 {
            if bytes[at..] == DESCRIPTOR_TERMINATOR {
                break;
            }
            return Err(malformed(format!(
                "descriptor carries {} trailing bytes {:02x?} after its last field",
                reader.remaining(),
                &bytes[at..]
            )));
        }
        let id: u32 = reader
            .read_u32_le()
            .map_err(|_| malformed(format!("descriptor field at {at} truncated")))?;
        let kind: u32 = reader
            .read_u32_le()
            .map_err(|_| malformed(format!("descriptor field at {at} truncated")))?;
        let value: DescriptorValue = match kind {
            0 => DescriptorValue::U32(
                reader
                    .read_u32_le()
                    .map_err(|_| malformed(format!("descriptor field at {at} truncated")))?,
            ),
            2 | 5 => DescriptorValue::U64(
                reader
                    .read_u64_le()
                    .map_err(|_| malformed(format!("descriptor field at {at} truncated")))?,
            ),
            1 => {
                let len: usize = reader
                    .read_u32_le()
                    .map_err(|_| malformed(format!("descriptor field at {at} truncated")))?
                    as usize;
                if len > MAX_DESCRIPTOR_TEXT_BYTES {
                    return Err(malformed(format!(
                        "descriptor string at {at} declares {len} bytes, above the {MAX_DESCRIPTOR_TEXT_BYTES}-byte cap"
                    )));
                }
                let text: &[u8] = reader
                    .read_bytes(len)
                    .map_err(|_| malformed(format!("descriptor string at {at} truncated")))?;
                let terminator: u8 = reader
                    .read_u8()
                    .map_err(|_| malformed(format!("descriptor string at {at} truncated")))?;
                if terminator != 0 {
                    return Err(malformed(format!(
                        "descriptor string at {at} lacks its zero terminator"
                    )));
                }
                DescriptorValue::Text(String::from_utf8_lossy(text).into_owned())
            }
            other => {
                return Err(malformed(format!(
                    "descriptor field at {at} has unknown value type {other}"
                )));
            }
        };
        fields.push(DescriptorField { id, kind, value });
    }
    Ok(fields)
}

pub fn parse_fast_load_toc(bytes: &[u8]) -> Result<FastLoadToc> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let err = || malformed("fast-load table of contents truncated".to_owned());
    let tag: u32 = reader.read_u32_le().map_err(|_| err())?;
    if tag != FAST_LOAD_TOC_TAG {
        return Err(malformed(format!(
            "fast-load table of contents tag is {tag}, expected {FAST_LOAD_TOC_TAG}"
        )));
    }
    let hash_a: u64 = reader.read_u64_le().map_err(|_| err())?;
    let one: u32 = reader.read_u32_le().map_err(|_| err())?;
    if one != 1 {
        return Err(malformed(format!(
            "fast-load table of contents separator is {one}, expected 1"
        )));
    }
    let hash_b: u64 = reader.read_u64_le().map_err(|_| err())?;
    let has_name: u32 = reader.read_u32_le().map_err(|_| err())?;
    let name: Option<String> = match has_name {
        0 => None,
        1 => {
            let raw: &[u8] = reader.read_bytes(64).map_err(|_| err())?;
            let end: usize = raw.iter().position(|&b: &u8| b == 0).unwrap_or(raw.len());
            Some(String::from_utf8_lossy(&raw[..end]).into_owned())
        }
        other => {
            return Err(malformed(format!(
                "fast-load table of contents name flag is {other}, expected 0 or 1"
            )));
        }
    };
    let trailer: Vec<u8> = reader
        .read_bytes(reader.remaining())
        .map_err(|_| err())?
        .to_vec();
    Ok(FastLoadToc {
        hash_a,
        hash_b,
        name,
        trailer,
    })
}

#[must_use]
pub fn archive_extent(archive: &ForgeArchive) -> u64 {
    let mut end: u64 = archive
        .tables
        .iter()
        .map(|table: &ForgeTable| {
            let fat_end: u64 = table.pos_fat + (table.slots * FAT_RECORD_LEN) as u64;
            let dir_end: u64 = if table.directory_offset > 0 {
                table.directory_offset as u64 + table.num_dirs as u64 * DIRECTORY_RECORD_LEN
            } else {
                0
            };
            fat_end
                .max(dir_end)
                .max(table.position + TABLE_DESCRIPTOR_LEN as u64)
        })
        .fold(archive.header.header_len as u64, u64::max);
    for entry in &archive.entries {
        end = end.max(entry.data_offset + u64::from(entry.size));
    }
    end.min(archive.source_len)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn name_xor_is_an_involution_and_depends_on_every_key_input() {
        let plain: &[u8] = b"CompiledTextureMap_hero.texture";
        let mut buffer: Vec<u8> = plain.to_vec();
        name_xor(
            &mut buffer,
            0x1234,
            0x5000,
            0x1323_7FE9,
            ENTRY_NAME_KEY_STEP,
        );
        assert_ne!(buffer.as_slice(), plain);
        name_xor(
            &mut buffer,
            0x1234,
            0x5000,
            0x1323_7FE9,
            ENTRY_NAME_KEY_STEP,
        );
        assert_eq!(buffer.as_slice(), plain);
        let mut other: Vec<u8> = plain.to_vec();
        name_xor(&mut other, 0x1235, 0x5000, 0x1323_7FE9, ENTRY_NAME_KEY_STEP);
        let mut expected: Vec<u8> = plain.to_vec();
        name_xor(
            &mut expected,
            0x1234,
            0x5000,
            0x1323_7FE9,
            ENTRY_NAME_KEY_STEP,
        );
        assert_ne!(other, expected);
    }

    #[test]
    fn header_lengths_follow_the_per_version_table() {
        assert_eq!(header_len_for(33), 0x4A);
        assert_eq!(header_len_for(34), 0x4E);
        assert_eq!(header_len_for(30), 0x4A);
        assert_eq!(header_len_for(27), 0x4A);
        assert!(version_supported(27));
        assert!(!version_supported(31));
        assert!(!version_supported(26));
        assert!(!version_supported(35));
    }

    #[test]
    fn entry_kinds_follow_the_leading_bytes() {
        assert_eq!(
            ForgeEntryKind::from_head(4, &[1, 0, 0, 0]),
            ForgeEntryKind::Descriptor
        );
        assert_eq!(
            ForgeEntryKind::from_head(0x1C, &[6, 0, 0, 0, 1, 2, 3, 4]),
            ForgeEntryKind::FastLoadToc
        );
        assert_eq!(ForgeEntryKind::from_head(0, &[]), ForgeEntryKind::Empty);
        assert_eq!(
            ForgeEntryKind::from_head(12, b"RIFF\x04\0\0\0"),
            ForgeEntryKind::RawRiff
        );
        assert_eq!(
            ForgeEntryKind::from_head(64, &crate::containers::forge_block::BLOCK_MAGIC_V37_BYTES),
            ForgeEntryKind::FileContainer {
                magic: BlockMagic::V37
            }
        );
        assert_eq!(
            ForgeEntryKind::from_head(2, &[9, 9]),
            ForgeEntryKind::Unknown { head: 0x0909 }
        );
    }

    #[test]
    fn unsupported_versions_are_refused_by_number() {
        let mut bytes: Vec<u8> = FORGE_MAGIC.to_vec();
        bytes.extend_from_slice(&31u32.to_le_bytes());
        bytes.extend(std::iter::repeat_n(0u8, 0x60));
        let error: Error = parse_header(&bytes).unwrap_err();
        assert!(
            matches!(error, Error::ForgeUnsupportedVersion { version: 31, .. }),
            "{error}"
        );
        assert!(error.to_string().contains("33 and 34"));
    }
}
