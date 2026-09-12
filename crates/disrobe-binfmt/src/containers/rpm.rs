use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read as _};

use base64::Engine as _;
use disrobe_bytes::{ByteReadError, ByteReader};
use sha1::Sha1;
use sha2::{Digest as _, Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_512};

use crate::containers::{CpioArchive, CpioVariant, parse_cpio};
use crate::error::{Error, Result};

const LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];
const LEAD_LEN: usize = 96;
const HEADER_MAGIC: [u8; 8] = [0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];
const HEADER_INTRO_LEN: usize = 16;
const HEADER_INDEX_LEN: usize = 16;
const MAX_HEADER_ENTRIES: usize = 65_535;
const MAX_HEADER_STORE: usize = 64 * 1024 * 1024;
const MAX_TAG_VALUES: usize = 65_535;
const TAG_HEADER_SIGNATURES: u32 = 62;
const TAG_HEADER_IMMUTABLE: u32 = 63;
const TAG_SIGNATURE_SHA1: u32 = 269;
const TAG_SIGNATURE_LONG_SIZE: u32 = 270;
const TAG_SIGNATURE_LONG_PAYLOAD_SIZE: u32 = 271;
const TAG_SIGNATURE_SHA256: u32 = 273;
const TAG_SIGNATURE_OPENPGP: u32 = 278;
const TAG_SIGNATURE_SHA3_256: u32 = 279;
const TAG_SIGNATURE_RESERVED: u32 = 999;
const TAG_SIGNATURE_SIZE: u32 = 1000;
const TAG_SIGNATURE_MD5: u32 = 1004;
const TAG_SIGNATURE_PAYLOAD_SIZE: u32 = 1007;
const TAG_SIGNATURE_RESERVED_LEGACY: u32 = 1008;
const TAG_OLD_FILENAMES: u32 = 1027;
const TAG_FILE_SIZES: u32 = 1028;
const TAG_FILE_MODES: u32 = 1030;
const TAG_FILE_DIGESTS: u32 = 1035;
const TAG_FILE_LINK_TOS: u32 = 1036;
const TAG_FILE_FLAGS: u32 = 1037;
const TAG_FILE_DEVICES: u32 = 1095;
const TAG_FILE_INODES: u32 = 1096;
const TAG_DIR_INDEXES: u32 = 1116;
const TAG_BASE_NAMES: u32 = 1117;
const TAG_DIR_NAMES: u32 = 1118;
const TAG_PAYLOAD_FORMAT: u32 = 1124;
const TAG_PAYLOAD_COMPRESSOR: u32 = 1125;
const TAG_LONG_FILE_SIZES: u32 = 5008;
const TAG_FILE_DIGEST_ALGORITHM: u32 = 5011;
const TAG_ENCODING: u32 = 5062;
const TAG_PAYLOAD_SHA256: u32 = 5092;
const TAG_PAYLOAD_SHA256_ALT: u32 = 5097;
const TAG_PAYLOAD_SIZE: u32 = 5112;
const TAG_PAYLOAD_SIZE_ALT: u32 = 5113;
const TAG_RPM_FORMAT: u32 = 5114;
const TAG_PAYLOAD_SHA512: u32 = 5121;
const TAG_PAYLOAD_SHA512_ALT: u32 = 5122;
const TAG_PAYLOAD_SHA3_256: u32 = 5123;
const TAG_PAYLOAD_SHA3_256_ALT: u32 = 5124;
const RPM_FILE_GHOST: u32 = 1 << 6;
const STRIPPED_MAGIC: &[u8; 6] = b"07070X";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpmFormat {
    V3,
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpmCompression {
    Stored,
    Gzip,
    Xz,
    Zstd,
    Bzip2,
    Lzma,
}

#[derive(Debug)]
pub struct RecoveredRpm {
    pub format: RpmFormat,
    pub compression: RpmCompression,
    pub compressed_size: u64,
    pub signature_blobs: Vec<RpmSignatureBlob>,
    pub cpio: Vec<u8>,
    pub entries: Vec<RpmEntry>,
}

impl RecoveredRpm {
    pub fn member_bytes(&self, entry: &RpmEntry) -> Result<&[u8]> {
        let data_offset: usize = entry.data_offset.ok_or_else(|| {
            Error::Rpm(format!("RPM member `{}` has no payload bytes", entry.name))
        })?;
        let size: usize =
            usize::try_from(entry.file_size).map_err(|_error: std::num::TryFromIntError| {
                Error::Rpm("RPM member size overflow".to_owned())
            })?;
        let end: usize = data_offset
            .checked_add(size)
            .ok_or_else(|| Error::Rpm("RPM member range overflow".to_owned()))?;
        self.cpio
            .get(data_offset..end)
            .ok_or_else(|| Error::Rpm(format!("RPM member `{}` is out of bounds", entry.name)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmSignatureBlob {
    pub tag: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmEntry {
    pub name: String,
    pub mode: u32,
    pub file_size: u64,
    pub link_target: Option<String>,
    pub ghost: bool,
    data_offset: Option<usize>,
    digest: Option<String>,
    device: Option<u32>,
    inode: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileDigestAlgorithm {
    Md5,
    Sha1,
    Sha2_224,
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Sha3_256,
    Sha3_512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderType {
    Null,
    Char,
    Int8,
    Int16,
    Int32,
    Int64,
    String,
    Binary,
    StringArray,
    I18nString,
}

impl HeaderType {
    fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            0 => Ok(Self::Null),
            1 => Ok(Self::Char),
            2 => Ok(Self::Int8),
            3 => Ok(Self::Int16),
            4 => Ok(Self::Int32),
            5 => Ok(Self::Int64),
            6 => Ok(Self::String),
            7 => Ok(Self::Binary),
            8 => Ok(Self::StringArray),
            9 => Ok(Self::I18nString),
            _ => Err(Error::Rpm(format!("header tag has unknown type {raw}"))),
        }
    }

    const fn alignment(self) -> usize {
        match self {
            Self::Int16 => 2,
            Self::Int32 => 4,
            Self::Int64 => 8,
            Self::Null
            | Self::Char
            | Self::Int8
            | Self::String
            | Self::Binary
            | Self::StringArray
            | Self::I18nString => 1,
        }
    }

    const fn width(self) -> Option<usize> {
        match self {
            Self::Null => Some(0),
            Self::Char | Self::Int8 | Self::Binary => Some(1),
            Self::Int16 => Some(2),
            Self::Int32 => Some(4),
            Self::Int64 => Some(8),
            Self::String | Self::StringArray | Self::I18nString => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct HeaderEntry {
    tag: u32,
    kind: HeaderType,
    offset: usize,
    count: usize,
}

#[derive(Debug)]
struct Header<'a> {
    entries: Vec<HeaderEntry>,
    store: &'a [u8],
    start: usize,
    end: usize,
}

impl<'a> Header<'a> {
    fn entry(&self, tag: u32) -> Option<&HeaderEntry> {
        self.entries
            .binary_search_by_key(&tag, |entry: &HeaderEntry| entry.tag)
            .ok()
            .and_then(|index: usize| self.entries.get(index))
    }

    fn string(&self, tag: u32, allowed: &[HeaderType]) -> Result<Option<&'a str>> {
        let Some(entry): Option<&HeaderEntry> = self.entry(tag) else {
            return Ok(None);
        };
        if !allowed.contains(&entry.kind) || entry.count != 1 {
            return Err(Error::Rpm(format!(
                "header tag {tag} must contain one string"
            )));
        }
        let remaining: &'a [u8] = self
            .store
            .get(entry.offset..)
            .ok_or_else(|| Error::Rpm(format!("header tag {tag} offset is out of bounds")))?;
        let length: usize = memchr::memchr(0, remaining)
            .ok_or_else(|| Error::Rpm(format!("header tag {tag} string is unterminated")))?;
        let value: &'a str =
            std::str::from_utf8(&remaining[..length]).map_err(|error: std::str::Utf8Error| {
                Error::Rpm(format!("header tag {tag}: {error}"))
            })?;
        Ok(Some(value))
    }

    fn u32(&self, tag: u32) -> Result<Option<u32>> {
        let Some(entry): Option<&HeaderEntry> = self.entry(tag) else {
            return Ok(None);
        };
        if entry.kind != HeaderType::Int32 || entry.count != 1 {
            return Err(Error::Rpm(format!(
                "header tag {tag} must contain one 32-bit integer"
            )));
        }
        let end: usize = checked_end(entry.offset, 4, "header integer tag")?;
        let bytes: &[u8] = self
            .store
            .get(entry.offset..end)
            .ok_or_else(|| Error::Rpm(format!("header tag {tag} integer is out of bounds")))?;
        Ok(Some(u32::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ])))
    }

    fn binary(&self, tag: u32) -> Result<Option<&'a [u8]>> {
        let Some(entry): Option<&HeaderEntry> = self.entry(tag) else {
            return Ok(None);
        };
        if entry.kind != HeaderType::Binary {
            return Err(Error::Rpm(format!(
                "header tag {tag} must contain binary data"
            )));
        }
        let end: usize = checked_end(entry.offset, entry.count, "header binary tag")?;
        self.store
            .get(entry.offset..end)
            .map(Some)
            .ok_or_else(|| Error::Rpm(format!("header tag {tag} binary data is out of bounds")))
    }

    fn strings(&self, tag: u32) -> Result<Option<Vec<&'a str>>> {
        let Some(entry): Option<&HeaderEntry> = self.entry(tag) else {
            return Ok(None);
        };
        if !matches!(
            entry.kind,
            HeaderType::String | HeaderType::StringArray | HeaderType::I18nString
        ) {
            return Err(Error::Rpm(format!("header tag {tag} must contain strings")));
        }
        let mut remaining: &'a [u8] = self
            .store
            .get(entry.offset..)
            .ok_or_else(|| Error::Rpm(format!("header tag {tag} offset is out of bounds")))?;
        let mut values: Vec<&'a str> = Vec::with_capacity(entry.count);
        for _index in 0..entry.count {
            let length: usize = memchr::memchr(0, remaining)
                .ok_or_else(|| Error::Rpm(format!("header tag {tag} string is unterminated")))?;
            let value: &'a str = std::str::from_utf8(&remaining[..length]).map_err(
                |error: std::str::Utf8Error| Error::Rpm(format!("header tag {tag}: {error}")),
            )?;
            values.push(value);
            remaining = &remaining[length + 1..];
        }
        Ok(Some(values))
    }

    fn u16s(&self, tag: u32) -> Result<Option<Vec<u16>>> {
        let Some(entry): Option<&HeaderEntry> = self.entry(tag) else {
            return Ok(None);
        };
        if entry.kind != HeaderType::Int16 {
            return Err(Error::Rpm(format!(
                "header tag {tag} must contain 16-bit integers"
            )));
        }
        let length: usize = entry
            .count
            .checked_mul(2)
            .ok_or_else(|| Error::Rpm(format!("header tag {tag} size overflow")))?;
        let end: usize = checked_end(entry.offset, length, "header integer array")?;
        let bytes: &[u8] = self
            .store
            .get(entry.offset..end)
            .ok_or_else(|| Error::Rpm(format!("header tag {tag} integers are out of bounds")))?;
        Ok(Some(
            bytes
                .chunks_exact(2)
                .map(|value: &[u8]| u16::from_be_bytes([value[0], value[1]]))
                .collect(),
        ))
    }

    fn u32s(&self, tag: u32) -> Result<Option<Vec<u32>>> {
        let Some(entry): Option<&HeaderEntry> = self.entry(tag) else {
            return Ok(None);
        };
        if entry.kind != HeaderType::Int32 {
            return Err(Error::Rpm(format!(
                "header tag {tag} must contain 32-bit integers"
            )));
        }
        let length: usize = entry
            .count
            .checked_mul(4)
            .ok_or_else(|| Error::Rpm(format!("header tag {tag} size overflow")))?;
        let end: usize = checked_end(entry.offset, length, "header integer array")?;
        let bytes: &[u8] = self
            .store
            .get(entry.offset..end)
            .ok_or_else(|| Error::Rpm(format!("header tag {tag} integers are out of bounds")))?;
        Ok(Some(
            bytes
                .chunks_exact(4)
                .map(|value: &[u8]| u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
                .collect(),
        ))
    }

    fn u64s(&self, tag: u32) -> Result<Option<Vec<u64>>> {
        let Some(entry): Option<&HeaderEntry> = self.entry(tag) else {
            return Ok(None);
        };
        if entry.kind != HeaderType::Int64 {
            return Err(Error::Rpm(format!(
                "header tag {tag} must contain 64-bit integers"
            )));
        }
        let length: usize = entry
            .count
            .checked_mul(8)
            .ok_or_else(|| Error::Rpm(format!("header tag {tag} size overflow")))?;
        let end: usize = checked_end(entry.offset, length, "header integer array")?;
        let bytes: &[u8] = self
            .store
            .get(entry.offset..end)
            .ok_or_else(|| Error::Rpm(format!("header tag {tag} integers are out of bounds")))?;
        Ok(Some(
            bytes
                .chunks_exact(8)
                .map(|value: &[u8]| {
                    u64::from_be_bytes([
                        value[0], value[1], value[2], value[3], value[4], value[5], value[6],
                        value[7],
                    ])
                })
                .collect(),
        ))
    }

    fn size(&self, tag: u32) -> Result<Option<u64>> {
        let Some(entry): Option<&HeaderEntry> = self.entry(tag) else {
            return Ok(None);
        };
        if entry.count != 1 || !matches!(entry.kind, HeaderType::Int32 | HeaderType::Int64) {
            return Err(Error::Rpm(format!(
                "header tag {tag} must contain one size integer"
            )));
        }
        match entry.kind {
            HeaderType::Int32 => self.u32(tag).map(|value: Option<u32>| value.map(u64::from)),
            HeaderType::Int64 => self.u64s(tag).map(|values: Option<Vec<u64>>| {
                values.and_then(|items: Vec<u64>| items.first().copied())
            }),
            HeaderType::Null
            | HeaderType::Char
            | HeaderType::Int8
            | HeaderType::Int16
            | HeaderType::String
            | HeaderType::Binary
            | HeaderType::StringArray
            | HeaderType::I18nString => Err(Error::Rpm(format!(
                "header tag {tag} must contain one size integer"
            ))),
        }
    }

    fn validate_region(&self, tag: u32) -> Result<()> {
        let entry: &HeaderEntry = self
            .entries
            .first()
            .filter(|entry: &&HeaderEntry| entry.tag == tag)
            .ok_or_else(|| Error::Rpm(format!("header immutable region tag {tag} is missing")))?;
        if entry.kind != HeaderType::Binary || entry.count != HEADER_INDEX_LEN {
            return Err(Error::Rpm(format!(
                "header immutable region tag {tag} has the wrong type or size"
            )));
        }
        let trailer_end: usize = checked_end(entry.offset, HEADER_INDEX_LEN, "region trailer")?;
        let trailer: &[u8] = self
            .store
            .get(entry.offset..trailer_end)
            .ok_or_else(|| Error::Rpm(format!("header immutable region tag {tag} is truncated")))?;
        let mut reader: ByteReader<'_> = ByteReader::new(trailer);
        let trailer_tag: u32 = read_u32(&mut reader, "immutable region tag")?;
        let trailer_type: u32 = read_u32(&mut reader, "immutable region type")?;
        let trailer_offset: i32 = reader
            .read_i32_be()
            .map_err(|error: ByteReadError| rpm_read("immutable region offset", error))?;
        let trailer_count: u32 = read_u32(&mut reader, "immutable region count")?;
        let index_bytes: usize = self
            .entries
            .len()
            .checked_mul(HEADER_INDEX_LEN)
            .ok_or_else(|| Error::Rpm("immutable region index size overflow".to_owned()))?;
        let expected_offset: i32 = i32::try_from(index_bytes)
            .map_err(|_error: std::num::TryFromIntError| {
                Error::Rpm("immutable region index size exceeds signed range".to_owned())
            })?
            .checked_neg()
            .ok_or_else(|| Error::Rpm("immutable region offset overflow".to_owned()))?;
        if trailer_tag != tag
            || trailer_type != 7
            || trailer_offset != expected_offset
            || trailer_count != HEADER_INDEX_LEN as u32
        {
            return Err(Error::Rpm(format!(
                "header immutable region tag {tag} has an invalid trailer"
            )));
        }
        Ok(())
    }
}

fn rpm_read(field: &str, error: ByteReadError) -> Error {
    Error::Rpm(format!("{field} is truncated: {error}"))
}

fn read_u32(reader: &mut ByteReader<'_>, field: &str) -> Result<u32> {
    reader
        .read_u32_be()
        .map_err(|error: ByteReadError| rpm_read(field, error))
}

fn checked_end(start: usize, length: usize, field: &str) -> Result<usize> {
    start
        .checked_add(length)
        .ok_or_else(|| Error::Rpm(format!("{field} range overflow")))
}

fn validate_entry(store: &[u8], entry: HeaderEntry) -> Result<()> {
    if entry.count > MAX_TAG_VALUES {
        return Err(Error::Rpm(format!(
            "header tag {} count {} exceeds cap {MAX_TAG_VALUES}",
            entry.tag, entry.count
        )));
    }
    if !entry.offset.is_multiple_of(entry.kind.alignment()) {
        return Err(Error::Rpm(format!(
            "header tag {} offset {} violates alignment {}",
            entry.tag,
            entry.offset,
            entry.kind.alignment()
        )));
    }
    if let Some(width) = entry.kind.width() {
        let length: usize = entry
            .count
            .checked_mul(width)
            .ok_or_else(|| Error::Rpm(format!("header tag {} size overflow", entry.tag)))?;
        let end: usize = checked_end(entry.offset, length, "header tag")?;
        if end > store.len() {
            return Err(Error::Rpm(format!(
                "header tag {} range exceeds its store",
                entry.tag
            )));
        }
        return Ok(());
    }
    if entry.kind == HeaderType::String && entry.count != 1 {
        return Err(Error::Rpm(format!(
            "header string tag {} count must be one",
            entry.tag
        )));
    }
    let mut remaining: &[u8] = store
        .get(entry.offset..)
        .ok_or_else(|| Error::Rpm(format!("header tag {} offset is out of bounds", entry.tag)))?;
    for _index in 0..entry.count {
        let length: usize = memchr::memchr(0, remaining).ok_or_else(|| {
            Error::Rpm(format!("header tag {} string is unterminated", entry.tag))
        })?;
        remaining = &remaining[length + 1..];
    }
    Ok(())
}

fn parse_header<'a>(bytes: &'a [u8], start: usize, name: &str) -> Result<Header<'a>> {
    let intro_end: usize = checked_end(start, HEADER_INTRO_LEN, name)?;
    let intro: &[u8] = bytes
        .get(start..intro_end)
        .ok_or_else(|| Error::Rpm(format!("{name} intro is truncated")))?;
    let mut intro_reader: ByteReader<'_> = ByteReader::new(intro);
    let magic: &[u8] = intro_reader
        .read_bytes(HEADER_MAGIC.len())
        .map_err(|error: ByteReadError| rpm_read(name, error))?;
    if magic != HEADER_MAGIC {
        return Err(Error::Rpm(format!("{name} magic is invalid")));
    }
    let entry_count_u32: u32 = read_u32(&mut intro_reader, "header entry count")?;
    let store_len_u32: u32 = read_u32(&mut intro_reader, "header store size")?;
    let entry_count: usize =
        usize::try_from(entry_count_u32).map_err(|_error: std::num::TryFromIntError| {
            Error::Rpm("header entry count overflow".to_owned())
        })?;
    let store_len: usize =
        usize::try_from(store_len_u32).map_err(|_error: std::num::TryFromIntError| {
            Error::Rpm("header store size overflow".to_owned())
        })?;
    if entry_count == 0 || entry_count > MAX_HEADER_ENTRIES {
        return Err(Error::Rpm(format!(
            "{name} entry count {entry_count} is outside 1..={MAX_HEADER_ENTRIES}"
        )));
    }
    if store_len > MAX_HEADER_STORE {
        return Err(Error::Rpm(format!(
            "{name} store size {store_len} exceeds cap {MAX_HEADER_STORE}"
        )));
    }
    let index_len: usize = entry_count
        .checked_mul(HEADER_INDEX_LEN)
        .ok_or_else(|| Error::Rpm(format!("{name} index size overflow")))?;
    let index_end: usize = checked_end(intro_end, index_len, name)?;
    let header_end: usize = checked_end(index_end, store_len, name)?;
    let index: &[u8] = bytes
        .get(intro_end..index_end)
        .ok_or_else(|| Error::Rpm(format!("{name} index is truncated")))?;
    let store: &[u8] = bytes
        .get(index_end..header_end)
        .ok_or_else(|| Error::Rpm(format!("{name} store is truncated")))?;
    let mut index_reader: ByteReader<'_> = ByteReader::new(index);
    let mut entries: Vec<HeaderEntry> = Vec::with_capacity(entry_count);
    let mut previous_tag: Option<u32> = None;
    for _index in 0..entry_count {
        let tag: u32 = read_u32(&mut index_reader, "header tag")?;
        if previous_tag.is_some_and(|previous: u32| tag <= previous) {
            return Err(Error::Rpm(format!(
                "{name} tags are duplicated or unsorted at {tag}"
            )));
        }
        let kind_raw: u32 = read_u32(&mut index_reader, "header tag type")?;
        let kind: HeaderType = HeaderType::from_raw(kind_raw)?;
        let offset_i32: i32 = index_reader
            .read_i32_be()
            .map_err(|error: ByteReadError| rpm_read("header tag offset", error))?;
        let offset: usize =
            usize::try_from(offset_i32).map_err(|_error: std::num::TryFromIntError| {
                Error::Rpm(format!("header tag {tag} has a negative data offset"))
            })?;
        let count_u32: u32 = read_u32(&mut index_reader, "header tag count")?;
        let count: usize =
            usize::try_from(count_u32).map_err(|_error: std::num::TryFromIntError| {
                Error::Rpm(format!("header tag {tag} count overflow"))
            })?;
        let entry: HeaderEntry = HeaderEntry {
            tag,
            kind,
            offset,
            count,
        };
        validate_entry(store, entry)?;
        entries.push(entry);
        previous_tag = Some(tag);
    }
    Ok(Header {
        entries,
        store,
        start,
        end: header_end,
    })
}

fn align8(value: usize) -> Result<usize> {
    value
        .checked_add(7)
        .map(|aligned: usize| aligned & !7)
        .ok_or_else(|| Error::Rpm("signature padding offset overflow".to_owned()))
}

fn compression_from_header(header: &Header<'_>, payload: &[u8]) -> Result<RpmCompression> {
    let Some(label): Option<&str> = header.string(TAG_PAYLOAD_COMPRESSOR, &[HeaderType::String])?
    else {
        return match payload {
            [0x1f, 0x8b, ..] => Ok(RpmCompression::Gzip),
            [0xfd, b'7', b'z', b'X', b'Z', 0, ..] => Ok(RpmCompression::Xz),
            [0x28, 0xb5, 0x2f, 0xfd, ..] => Ok(RpmCompression::Zstd),
            [b'B', b'Z', b'h', ..] => Ok(RpmCompression::Bzip2),
            [b'0', b'7', b'0', b'7', b'0', _, ..] => Ok(RpmCompression::Stored),
            _ => Err(Error::Rpm(
                "payload compressor tag is absent and bytes are not recognizable".to_owned(),
            )),
        };
    };
    match label {
        "gzip" | "gz" => Ok(RpmCompression::Gzip),
        "xz" => Ok(RpmCompression::Xz),
        "zstd" => Ok(RpmCompression::Zstd),
        "bzip2" | "bzip" => Ok(RpmCompression::Bzip2),
        "lzma" => Ok(RpmCompression::Lzma),
        "none" | "cpio" => Ok(RpmCompression::Stored),
        other => Err(Error::Rpm(format!(
            "unsupported payload compressor `{other}`"
        ))),
    }
}

#[derive(Debug)]
struct Envelope<'a> {
    format: RpmFormat,
    compression: RpmCompression,
    payload: &'a [u8],
    signature: Header<'a>,
    main: Header<'a>,
}

fn validate_v6_signature(signature: &Header<'_>) -> Result<()> {
    if signature
        .entries
        .iter()
        .any(|entry: &HeaderEntry| entry.tag > TAG_SIGNATURE_RESERVED)
    {
        return Err(Error::Rpm(
            "RPM v6 signature header contains a tag above 999".to_owned(),
        ));
    }
    let reserved: &[u8] = signature
        .binary(TAG_SIGNATURE_RESERVED)?
        .ok_or_else(|| Error::Rpm("RPM v6 reserved signature space is missing".to_owned()))?;
    if signature
        .entries
        .last()
        .map(|entry: &HeaderEntry| entry.tag)
        != Some(TAG_SIGNATURE_RESERVED)
        || reserved.iter().any(|byte: &u8| *byte != 0)
    {
        return Err(Error::Rpm(
            "RPM v6 reserved signature space is not final and zero-filled".to_owned(),
        ));
    }
    Ok(())
}

fn signature_blobs_with_budget(
    signature: &Header<'_>,
    metadata_bytes: &mut usize,
    cap: usize,
) -> Result<Vec<RpmSignatureBlob>> {
    let mut blobs: Vec<RpmSignatureBlob> = Vec::new();
    for entry in &signature.entries {
        if entry.tag == TAG_SIGNATURE_OPENPGP {
            if entry.kind != HeaderType::StringArray {
                return Err(Error::Rpm(
                    "RPM OpenPGP signature tag must contain a string array".to_owned(),
                ));
            }
            let encoded_values: Vec<&str> = signature
                .strings(TAG_SIGNATURE_OPENPGP)?
                .ok_or_else(|| Error::Rpm("RPM OpenPGP signatures disappeared".to_owned()))?;
            for encoded in encoded_values {
                let allocation: usize = base64::decoded_len_estimate(encoded.len());
                super::admit_metadata_bytes(metadata_bytes, allocation, cap, "<rpm-signatures>")?;
                let bytes: Vec<u8> = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|error: base64::DecodeError| {
                        Error::Rpm(format!("RPM OpenPGP signature is not base64: {error}"))
                    })?;
                blobs.push(RpmSignatureBlob {
                    tag: entry.tag,
                    bytes,
                });
            }
        } else if entry.kind == HeaderType::Binary
            && !matches!(
                entry.tag,
                TAG_HEADER_SIGNATURES
                    | TAG_SIGNATURE_RESERVED
                    | TAG_SIGNATURE_MD5
                    | TAG_SIGNATURE_RESERVED_LEGACY
            )
        {
            let bytes: &[u8] = signature
                .binary(entry.tag)?
                .ok_or_else(|| Error::Rpm(format!("signature tag {} disappeared", entry.tag)))?;
            super::admit_metadata_bytes(metadata_bytes, bytes.len(), cap, "<rpm-signatures>")?;
            blobs.push(RpmSignatureBlob {
                tag: entry.tag,
                bytes: bytes.to_vec(),
            });
        }
    }
    Ok(blobs)
}

#[cfg(test)]
fn signature_blobs_with_cap(signature: &Header<'_>, cap: usize) -> Result<Vec<RpmSignatureBlob>> {
    let mut metadata_bytes: usize = 0;
    signature_blobs_with_budget(signature, &mut metadata_bytes, cap)
}

fn parse_envelope(bytes: &[u8]) -> Result<Envelope<'_>> {
    let lead: &[u8] = bytes
        .get(..LEAD_LEN)
        .ok_or_else(|| Error::Rpm("lead is truncated".to_owned()))?;
    if lead.get(..LEAD_MAGIC.len()) != Some(LEAD_MAGIC.as_slice()) {
        return Err(Error::Rpm("lead magic is invalid".to_owned()));
    }
    let lead_major: u8 = lead[4];
    if !matches!(lead_major, 3 | 4) || lead[5] != 0 {
        return Err(Error::Rpm(format!(
            "unsupported lead version {lead_major}.{}",
            lead[5]
        )));
    }
    if !lead[10..76].contains(&0) {
        return Err(Error::Rpm("lead name is unterminated".to_owned()));
    }
    let signature_type: u16 = u16::from_be_bytes([lead[78], lead[79]]);
    if signature_type != 5 {
        return Err(Error::Rpm(format!(
            "unsupported lead signature type {signature_type}"
        )));
    }
    let signature: Header<'_> = parse_header(bytes, LEAD_LEN, "signature header")?;
    let main_start: usize = align8(signature.end)?;
    let signature_padding: &[u8] = bytes
        .get(signature.end..main_start)
        .ok_or_else(|| Error::Rpm("signature padding is truncated".to_owned()))?;
    if signature_padding.iter().any(|byte: &u8| *byte != 0) {
        return Err(Error::Rpm("signature padding is not zero".to_owned()));
    }
    let main: Header<'_> = parse_header(bytes, main_start, "main header")?;
    let format: RpmFormat = match (lead_major, main.u32(TAG_RPM_FORMAT)?) {
        (3, None) if main.entry(TAG_HEADER_IMMUTABLE).is_some() => RpmFormat::V4,
        (3, None) => RpmFormat::V3,
        (3 | 4, Some(6)) => RpmFormat::V6,
        (4, None) => RpmFormat::V4,
        (_, Some(value)) => {
            return Err(Error::Rpm(format!(
                "unsupported RPM format tag value {value}"
            )));
        }
        _ => {
            return Err(Error::Rpm(format!("unsupported lead version {lead_major}")));
        }
    };
    if format != RpmFormat::V3 {
        signature.validate_region(TAG_HEADER_SIGNATURES)?;
        main.validate_region(TAG_HEADER_IMMUTABLE)?;
    }
    if format == RpmFormat::V6 {
        validate_v6_signature(&signature)?;
        let encoding: &str = main
            .string(TAG_ENCODING, &[HeaderType::String])?
            .ok_or_else(|| Error::Rpm("RPM v6 encoding tag is missing".to_owned()))?;
        if encoding != "utf-8" {
            return Err(Error::Rpm(format!(
                "RPM v6 encoding `{encoding}` is not utf-8"
            )));
        }
    }
    if let Some(payload_format) = main.string(TAG_PAYLOAD_FORMAT, &[HeaderType::String])?
        && payload_format != "cpio"
    {
        return Err(Error::Rpm(format!(
            "unsupported payload format `{payload_format}`"
        )));
    }
    let payload: &[u8] = bytes
        .get(main.end..)
        .filter(|payload: &&[u8]| !payload.is_empty())
        .ok_or_else(|| Error::Rpm("payload is absent".to_owned()))?;
    let compression: RpmCompression = compression_from_header(&main, payload)?;
    Ok(Envelope {
        format,
        compression,
        payload,
        signature,
        main,
    })
}

fn verify_hex(expected: &str, actual: &str, digits: usize, subject: &str) -> Result<()> {
    if expected.len() != digits || !expected.bytes().all(|byte: u8| byte.is_ascii_hexdigit()) {
        return Err(Error::Rpm(format!(
            "{subject} tag is not a {digits}-digit hexadecimal value"
        )));
    }
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(Error::Rpm(format!("{subject} mismatch")));
    }
    Ok(())
}

fn optional_string<'a>(header: &'a Header<'a>, tag: u32) -> Result<Option<&'a str>> {
    header.string(tag, &[HeaderType::String, HeaderType::StringArray])
}

fn verify_md5(header: &Header<'_>, tag: u32, bytes: &[u8], subject: &str) -> Result<bool> {
    let Some(expected): Option<&[u8]> = header.binary(tag)? else {
        return Ok(false);
    };
    if expected.len() != 16 {
        return Err(Error::Rpm(format!("{subject} tag has the wrong size")));
    }
    let actual: md5::Digest = md5::compute(bytes);
    if actual.as_ref() != expected {
        return Err(Error::Rpm(format!("{subject} mismatch")));
    }
    Ok(true)
}

fn verify_sha1(header: &Header<'_>, tag: u32, bytes: &[u8], subject: &str) -> Result<bool> {
    let Some(expected): Option<&str> = optional_string(header, tag)? else {
        return Ok(false);
    };
    let actual: String = format!("{:x}", Sha1::digest(bytes));
    verify_hex(expected, &actual, 40, subject)?;
    Ok(true)
}

fn verify_sha256(header: &Header<'_>, tag: u32, bytes: &[u8], subject: &str) -> Result<bool> {
    let Some(expected): Option<&str> = optional_string(header, tag)? else {
        return Ok(false);
    };
    let actual: String = format!("{:x}", Sha256::digest(bytes));
    verify_hex(expected, &actual, 64, subject)?;
    Ok(true)
}

fn verify_sha512(header: &Header<'_>, tag: u32, bytes: &[u8], subject: &str) -> Result<bool> {
    let Some(expected): Option<&str> = optional_string(header, tag)? else {
        return Ok(false);
    };
    let actual: String = format!("{:x}", Sha512::digest(bytes));
    verify_hex(expected, &actual, 128, subject)?;
    Ok(true)
}

fn verify_sha3_256(header: &Header<'_>, tag: u32, bytes: &[u8], subject: &str) -> Result<bool> {
    let Some(expected): Option<&str> = optional_string(header, tag)? else {
        return Ok(false);
    };
    let actual: String = format!("{:x}", Sha3_256::digest(bytes));
    verify_hex(expected, &actual, 64, subject)?;
    Ok(true)
}

fn declared_size(
    header: &Header<'_>,
    short_tag: u32,
    long_tag: u32,
    subject: &str,
) -> Result<Option<u64>> {
    let short: Option<u64> = header.size(short_tag)?;
    let long: Option<u64> = header.size(long_tag)?;
    match (short, long) {
        (Some(_), Some(_)) => Err(Error::Rpm(format!(
            "{subject} declares both short and long size tags"
        ))),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn read_capped<R: std::io::Read>(reader: &mut R, cap: u64, subject: &str) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut limited: std::io::Take<&mut R> = reader.take(cap.saturating_add(1));
    limited
        .read_to_end(&mut out)
        .map_err(|error: std::io::Error| Error::Rpm(format!("{subject}: {error}")))?;
    let actual: u64 = u64::try_from(out.len()).map_err(|_error: std::num::TryFromIntError| {
        Error::Rpm(format!("{subject} size overflow"))
    })?;
    if actual > cap {
        return Err(Error::QuotaExceeded {
            entry: "<rpm-payload>".to_owned(),
            reason: format!("decompressed stream exceeds bomb cap {cap}"),
        });
    }
    Ok(out)
}

fn require_exact_consumption(consumed: u64, available: usize, subject: &str) -> Result<()> {
    let available_u64: u64 =
        u64::try_from(available).map_err(|_error: std::num::TryFromIntError| {
            Error::Rpm(format!("{subject} input size overflow"))
        })?;
    if consumed != available_u64 {
        return Err(Error::Rpm(format!(
            "{subject} left trailing compressed bytes"
        )));
    }
    Ok(())
}

fn decompress_bzip2_once(payload: &[u8], cap: u64) -> Result<Vec<u8>> {
    let mut decoder: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(payload);
    read_capped(&mut decoder, cap, "bzip2 payload decompression failed")
}

fn bit_at(bytes: &[u8], offset: usize) -> Option<u8> {
    let byte: u8 = *bytes.get(offset / 8)?;
    let shift: usize = 7usize.checked_sub(offset % 8)?;
    Some((byte >> shift) & 1)
}

fn zero_bits(bytes: &[u8], start: usize, end: usize) -> bool {
    (start..end).all(|offset: usize| bit_at(bytes, offset) == Some(0))
}

fn bzip2_prefix_matches(payload: &[u8], expected: &[u8], cap: u64) -> bool {
    let mut decoder: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(payload);
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
        let Ok(end_u64): std::result::Result<u64, std::num::TryFromIntError> = u64::try_from(end)
        else {
            return false;
        };
        if end_u64 > cap || expected.get(position..end) != buffer.get(..count) {
            return false;
        }
        position = end;
    }
}

fn bzip2_stream_end(payload: &[u8], expected: &[u8], cap: u64) -> Result<usize> {
    const END_MARKER: u64 = 0x17_72_45_38_50_90;
    const MARKER_BITS: usize = 48;
    const FOOTER_BITS: usize = 80;
    const CANDIDATE_CAP: usize = 64;

    let bit_len: usize = payload
        .len()
        .checked_mul(8)
        .ok_or_else(|| Error::Rpm("bzip2 payload bit size overflow".to_owned()))?;
    if bit_len < 32 + FOOTER_BITS {
        return Err(Error::Rpm("bzip2 payload is truncated".to_owned()));
    }
    let mut marker: u64 = 0;
    for offset in 32..32 + MARKER_BITS {
        let bit: u8 = bit_at(payload, offset)
            .ok_or_else(|| Error::Rpm("bzip2 marker range overflow".to_owned()))?;
        marker = (marker << 1) | u64::from(bit);
    }
    let mask: u64 = (1u64 << MARKER_BITS) - 1;
    let final_start: usize = bit_len - FOOTER_BITS;
    let mut candidates: usize = 0;
    for start in 32..=final_start {
        if marker == END_MARKER {
            candidates = candidates
                .checked_add(1)
                .ok_or_else(|| Error::Rpm("bzip2 end marker count overflow".to_owned()))?;
            if candidates > CANDIDATE_CAP {
                return Err(Error::Rpm(
                    "bzip2 payload has too many end markers".to_owned(),
                ));
            }
            let end_bits: usize = start
                .checked_add(FOOTER_BITS)
                .ok_or_else(|| Error::Rpm("bzip2 end marker range overflow".to_owned()))?;
            let end: usize = end_bits
                .checked_add(7)
                .ok_or_else(|| Error::Rpm("bzip2 end marker alignment overflow".to_owned()))?
                / 8;
            if zero_bits(payload, end_bits, end * 8)
                && bzip2_prefix_matches(&payload[..end], expected, cap)
            {
                return Ok(end);
            }
        }
        let next: usize = start + MARKER_BITS;
        if next < bit_len {
            let bit: u8 = bit_at(payload, next)
                .ok_or_else(|| Error::Rpm("bzip2 marker range overflow".to_owned()))?;
            marker = ((marker << 1) & mask) | u64::from(bit);
        }
    }
    Err(Error::Rpm("bzip2 payload end marker is invalid".to_owned()))
}

fn decompress_bzip2(payload: &[u8], cap: u64) -> Result<Vec<u8>> {
    let output: Vec<u8> = decompress_bzip2_once(payload, cap)?;
    let consumed: usize = bzip2_stream_end(payload, &output, cap)?;
    require_exact_consumption(
        u64::try_from(consumed).map_err(|_error: std::num::TryFromIntError| {
            Error::Rpm("bzip2 payload input position overflow".to_owned())
        })?,
        payload.len(),
        "bzip2 payload",
    )?;
    Ok(output)
}

fn decompress_payload(payload: &[u8], compression: RpmCompression, cap: u64) -> Result<Vec<u8>> {
    match compression {
        RpmCompression::Stored => {
            let size: u64 =
                u64::try_from(payload.len()).map_err(|_error: std::num::TryFromIntError| {
                    Error::Rpm("payload size overflow".to_owned())
                })?;
            if size > cap {
                return Err(Error::QuotaExceeded {
                    entry: "<rpm-payload>".to_owned(),
                    reason: format!("stored payload exceeds cap {cap}"),
                });
            }
            Ok(payload.to_vec())
        }
        RpmCompression::Gzip => {
            let mut decoder: flate2::bufread::GzDecoder<Cursor<&[u8]>> =
                flate2::bufread::GzDecoder::new(Cursor::new(payload));
            let output: Vec<u8> =
                read_capped(&mut decoder, cap, "gzip payload decompression failed")?;
            let consumed: u64 = decoder.into_inner().position();
            require_exact_consumption(consumed, payload.len(), "gzip payload")?;
            Ok(output)
        }
        RpmCompression::Xz => {
            let mut decoder: liblzma::read::XzDecoder<&[u8]> =
                liblzma::read::XzDecoder::new(payload);
            let output: Vec<u8> =
                read_capped(&mut decoder, cap, "xz payload decompression failed")?;
            require_exact_consumption(decoder.total_in(), payload.len(), "xz payload")?;
            Ok(output)
        }
        RpmCompression::Zstd => {
            let mut decoder: zstd::stream::read::Decoder<'_, std::io::BufReader<&[u8]>> =
                zstd::stream::read::Decoder::new(payload)
                    .map_err(|error: std::io::Error| {
                        Error::Rpm(format!("zstd payload initialization failed: {error}"))
                    })?
                    .single_frame();
            let output: Vec<u8> =
                read_capped(&mut decoder, cap, "zstd payload decompression failed")?;
            let inner: std::io::BufReader<&[u8]> = decoder.finish();
            let remaining: usize = inner
                .buffer()
                .len()
                .checked_add(inner.get_ref().len())
                .ok_or_else(|| Error::Rpm("zstd payload remaining size overflow".to_owned()))?;
            let consumed: usize = payload
                .len()
                .checked_sub(remaining)
                .ok_or_else(|| Error::Rpm("zstd payload consumed size underflow".to_owned()))?;
            require_exact_consumption(
                u64::try_from(consumed).map_err(|_error: std::num::TryFromIntError| {
                    Error::Rpm("zstd payload consumed size overflow".to_owned())
                })?,
                payload.len(),
                "zstd payload",
            )?;
            Ok(output)
        }
        RpmCompression::Bzip2 => decompress_bzip2(payload, cap),
        RpmCompression::Lzma => {
            let output: Vec<u8> = crate::containers::decompress_lzma_alone(payload, cap).map_err(
                |error: Error| match error {
                    Error::QuotaExceeded { reason, .. } => Error::QuotaExceeded {
                        entry: "<rpm-payload>".to_owned(),
                        reason,
                    },
                    other => {
                        let message: String = other.to_string();
                        if message.contains("more bytes are available") {
                            Error::Rpm("lzma payload left trailing compressed bytes".to_owned())
                        } else {
                            Error::Rpm(format!("lzma payload decompression failed: {message}"))
                        }
                    }
                },
            )?;
            let mut reader: Cursor<&[u8]> = Cursor::new(payload);
            let mut sink: std::io::Sink = std::io::sink();
            let options: lzma_rs::decompress::Options = lzma_rs::decompress::Options {
                memlimit: Some(512 * 1024 * 1024),
                ..Default::default()
            };
            lzma_rs::lzma_decompress_with_options(&mut reader, &mut sink, &options).map_err(
                |error: lzma_rs::error::Error| {
                    Error::Rpm(format!("lzma payload decompression failed: {error}"))
                },
            )?;
            require_exact_consumption(reader.position(), payload.len(), "lzma payload")?;
            Ok(output)
        }
    }
}

fn normalized_member_name(raw: &str) -> Result<String> {
    let rooted: &str = raw.trim_start_matches('/');
    let relative: &str = rooted
        .strip_prefix("./")
        .map_or(rooted, |value: &str| value);
    if relative.is_empty() || relative.as_bytes().contains(&0) {
        return Err(Error::UnsafeEntryPath(raw.to_owned()));
    }
    Ok(relative.to_owned())
}

fn payload_member_name(raw: &str) -> Result<String> {
    if raw.starts_with('/') {
        return Err(Error::UnsafeEntryPath(raw.to_owned()));
    }
    normalized_member_name(raw)
}

fn file_digest_algorithm(header: &Header<'_>, format: RpmFormat) -> Result<FileDigestAlgorithm> {
    let algorithm: Option<u32> = header.u32(TAG_FILE_DIGEST_ALGORITHM)?;
    match algorithm {
        None if format == RpmFormat::V6 => Err(Error::Rpm(
            "RPM v6 file digest algorithm is missing".to_owned(),
        )),
        None | Some(1) if format != RpmFormat::V6 => Ok(FileDigestAlgorithm::Md5),
        Some(2) if format != RpmFormat::V6 => Ok(FileDigestAlgorithm::Sha1),
        Some(8) => Ok(FileDigestAlgorithm::Sha2_256),
        Some(9) => Ok(FileDigestAlgorithm::Sha2_384),
        Some(10) => Ok(FileDigestAlgorithm::Sha2_512),
        Some(11) if format != RpmFormat::V6 => Ok(FileDigestAlgorithm::Sha2_224),
        Some(12) => Ok(FileDigestAlgorithm::Sha3_256),
        Some(14) => Ok(FileDigestAlgorithm::Sha3_512),
        Some(1 | 2 | 11) if format == RpmFormat::V6 => Err(Error::Rpm(
            "RPM v6 file digest algorithm must be at least SHA-256".to_owned(),
        )),
        Some(value) => Err(Error::Rpm(format!(
            "unsupported per-file digest algorithm {value}"
        ))),
        None => Err(Error::Rpm(
            "RPM file digest algorithm is missing".to_owned(),
        )),
    }
}

fn require_file_count(actual: usize, expected: usize, tag: u32) -> Result<()> {
    if actual != expected {
        return Err(Error::Rpm(format!(
            "header tag {tag} has {actual} values for {expected} files"
        )));
    }
    Ok(())
}

fn join_file_names_with_budget(
    bases: &[&str],
    indexes: &[u32],
    directories: &[&str],
    metadata_bytes: &mut usize,
    cap: usize,
) -> Result<Vec<String>> {
    require_file_count(indexes.len(), bases.len(), TAG_DIR_INDEXES)?;
    let mut names: Vec<String> = Vec::with_capacity(bases.len());
    for (base, directory_index) in bases.iter().zip(indexes) {
        let index: usize =
            usize::try_from(*directory_index).map_err(|_error: std::num::TryFromIntError| {
                Error::Rpm(format!("directory index {directory_index} overflows usize"))
            })?;
        let directory: &&str = directories.get(index).ok_or_else(|| {
            Error::Rpm(format!(
                "directory index {directory_index} is out of bounds"
            ))
        })?;
        let length: usize = directory
            .len()
            .checked_add(base.len())
            .ok_or_else(|| Error::Rpm("RPM file name length overflow".to_owned()))?;
        if length > crate::quota::MAX_ENTRY_PATH_BYTES {
            return Err(Error::Rpm(format!(
                "RPM file name length {length} exceeds path bound {}",
                crate::quota::MAX_ENTRY_PATH_BYTES
            )));
        }
        super::admit_metadata_bytes(metadata_bytes, length, cap, "<rpm-file-names>")?;
        names.push(normalized_member_name(&format!("{directory}{base}"))?);
    }
    Ok(names)
}

#[cfg(test)]
fn join_file_names_with_cap(
    bases: &[&str],
    indexes: &[u32],
    directories: &[&str],
    cap: usize,
) -> Result<Vec<String>> {
    let mut metadata_bytes: usize = 0;
    join_file_names_with_budget(bases, indexes, directories, &mut metadata_bytes, cap)
}

fn normalize_file_names_with_budget(
    raw_names: &[&str],
    metadata_bytes: &mut usize,
    cap: usize,
) -> Result<Vec<String>> {
    let mut names: Vec<String> = Vec::with_capacity(raw_names.len());
    for raw_name in raw_names {
        if raw_name.len() > crate::quota::MAX_ENTRY_PATH_BYTES {
            return Err(Error::Rpm(format!(
                "RPM file name length {} exceeds path bound {}",
                raw_name.len(),
                crate::quota::MAX_ENTRY_PATH_BYTES
            )));
        }
        super::admit_metadata_bytes(metadata_bytes, raw_name.len(), cap, "<rpm-file-names>")?;
        names.push(normalized_member_name(raw_name)?);
    }
    Ok(names)
}

fn header_file_names(
    header: &Header<'_>,
    count: usize,
    metadata_bytes: &mut usize,
    cap: usize,
) -> Result<Vec<String>> {
    let old_names: Option<Vec<&str>> = header.strings(TAG_OLD_FILENAMES)?;
    let base_names: Option<Vec<&str>> = header.strings(TAG_BASE_NAMES)?;
    let dir_indexes: Option<Vec<u32>> = header.u32s(TAG_DIR_INDEXES)?;
    let dir_names: Option<Vec<&str>> = header.strings(TAG_DIR_NAMES)?;
    match (base_names, dir_indexes, dir_names, old_names) {
        (Some(bases), Some(indexes), Some(dirs), _) => {
            require_file_count(bases.len(), count, TAG_BASE_NAMES)?;
            require_file_count(indexes.len(), count, TAG_DIR_INDEXES)?;
            join_file_names_with_budget(&bases, &indexes, &dirs, metadata_bytes, cap)
        }
        (None, None, None, Some(names)) => {
            require_file_count(names.len(), count, TAG_OLD_FILENAMES)?;
            normalize_file_names_with_budget(&names, metadata_bytes, cap)
        }
        (None, None, None, None) => Err(Error::Rpm(
            "RPM file modes are present without file names".to_owned(),
        )),
        _ => Err(Error::Rpm(
            "RPM split file-name tags are incomplete".to_owned(),
        )),
    }
}

fn header_file_sizes(header: &Header<'_>, count: usize, format: RpmFormat) -> Result<Vec<u64>> {
    let long_sizes: Option<Vec<u64>> = header.u64s(TAG_LONG_FILE_SIZES)?;
    if format == RpmFormat::V6 && long_sizes.is_none() {
        return Err(Error::Rpm("RPM v6 long file sizes are missing".to_owned()));
    }
    let sizes: Vec<u64> = if let Some(values) = long_sizes {
        values
    } else {
        header
            .u32s(TAG_FILE_SIZES)?
            .ok_or_else(|| Error::Rpm("RPM file sizes are missing".to_owned()))?
            .into_iter()
            .map(u64::from)
            .collect()
    };
    require_file_count(sizes.len(), count, TAG_FILE_SIZES)?;
    Ok(sizes)
}

fn optional_u32_file_values(header: &Header<'_>, tag: u32, count: usize) -> Result<Vec<u32>> {
    let values: Vec<u32> = header.u32s(tag)?.unwrap_or_else(|| vec![0; count]);
    require_file_count(values.len(), count, tag)?;
    Ok(values)
}

fn optional_string_file_values<'a>(
    header: &'a Header<'a>,
    tag: u32,
    count: usize,
) -> Result<Vec<&'a str>> {
    let values: Vec<&str> = header.strings(tag)?.unwrap_or_else(|| vec![""; count]);
    require_file_count(values.len(), count, tag)?;
    Ok(values)
}

fn owned_file_metadata_with_budget(
    digest: &str,
    link_target: &str,
    metadata_bytes: &mut usize,
    cap: usize,
) -> Result<(Option<String>, Option<String>)> {
    let owned_digest: Option<String> = if digest.is_empty() {
        None
    } else {
        super::admit_metadata_bytes(metadata_bytes, digest.len(), cap, "<rpm-file-digests>")?;
        Some(digest.to_owned())
    };
    let owned_link_target: Option<String> = if link_target.is_empty() {
        None
    } else {
        super::admit_metadata_bytes(metadata_bytes, link_target.len(), cap, "<rpm-link-targets>")?;
        Some(link_target.to_owned())
    };
    Ok((owned_digest, owned_link_target))
}

#[cfg(test)]
fn owned_file_metadata_with_cap(
    digest: &str,
    link_target: &str,
    cap: usize,
) -> Result<(Option<String>, Option<String>)> {
    let mut metadata_bytes: usize = 0;
    owned_file_metadata_with_budget(digest, link_target, &mut metadata_bytes, cap)
}

fn header_files(
    header: &Header<'_>,
    format: RpmFormat,
    metadata_bytes: &mut usize,
    cap: usize,
) -> Result<Option<(Vec<RpmEntry>, FileDigestAlgorithm)>> {
    let Some(modes): Option<Vec<u16>> = header.u16s(TAG_FILE_MODES)? else {
        return Ok(None);
    };
    let count: usize = modes.len();
    if count > crate::quota::DEFAULT_MAX_ENTRIES {
        return Err(Error::Rpm(format!(
            "RPM file count exceeds cap {}",
            crate::quota::DEFAULT_MAX_ENTRIES
        )));
    }
    let names: Vec<String> = header_file_names(header, count, metadata_bytes, cap)?;
    let sizes: Vec<u64> = header_file_sizes(header, count, format)?;
    let flags: Vec<u32> = optional_u32_file_values(header, TAG_FILE_FLAGS, count)?;
    let links: Vec<&str> = optional_string_file_values(header, TAG_FILE_LINK_TOS, count)?;
    let digests: Vec<&str> = optional_string_file_values(header, TAG_FILE_DIGESTS, count)?;
    let devices: Option<Vec<u32>> = header.u32s(TAG_FILE_DEVICES)?;
    let inodes: Option<Vec<u32>> = header.u32s(TAG_FILE_INODES)?;
    if let Some(values) = devices.as_ref() {
        require_file_count(values.len(), count, TAG_FILE_DEVICES)?;
    }
    if let Some(values) = inodes.as_ref() {
        require_file_count(values.len(), count, TAG_FILE_INODES)?;
    }
    if devices.is_some() != inodes.is_some() {
        return Err(Error::Rpm(
            "RPM hardlink identity tags are incomplete".to_owned(),
        ));
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut files: Vec<RpmEntry> = Vec::with_capacity(count);
    for index in 0..count {
        let name: String = names[index].clone();
        if !seen.insert(name.clone()) {
            return Err(Error::Rpm(format!("duplicate RPM file name `{name}`")));
        }
        let (digest, link_target): (Option<String>, Option<String>) =
            owned_file_metadata_with_budget(digests[index], links[index], metadata_bytes, cap)?;
        files.push(RpmEntry {
            name,
            mode: u32::from(modes[index]),
            file_size: sizes[index],
            link_target,
            ghost: flags[index] & RPM_FILE_GHOST != 0,
            data_offset: None,
            digest,
            device: devices
                .as_ref()
                .and_then(|values: &Vec<u32>| values.get(index).copied()),
            inode: inodes
                .as_ref()
                .and_then(|values: &Vec<u32>| values.get(index).copied()),
        });
    }
    Ok(Some((files, file_digest_algorithm(header, format)?)))
}

const fn file_kind(mode: u32) -> u32 {
    mode & 0o170_000
}

fn align4(value: usize, subject: &str) -> Result<usize> {
    value
        .checked_add(3)
        .map(|aligned: usize| aligned & !3)
        .ok_or_else(|| Error::Rpm(format!("{subject} alignment overflow")))
}

fn parse_hex_u32(bytes: &[u8], subject: &str) -> Result<u32> {
    let text: &str = std::str::from_utf8(bytes).map_err(|error: std::str::Utf8Error| {
        Error::Rpm(format!("{subject} is not ASCII: {error}"))
    })?;
    u32::from_str_radix(text, 16).map_err(|_error: std::num::ParseIntError| {
        Error::Rpm(format!("{subject} is not hexadecimal"))
    })
}

fn zero_padding(bytes: &[u8], start: usize, end: usize, subject: &str) -> Result<()> {
    let padding: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| Error::Rpm(format!("{subject} padding is truncated")))?;
    if padding.iter().any(|byte: &u8| *byte != 0) {
        return Err(Error::Rpm(format!("{subject} padding is not zero")));
    }
    Ok(())
}

fn resolve_hardlinks(entries: &mut [RpmEntry]) -> Result<()> {
    let mut content: BTreeMap<(u32, u32), (usize, u64)> = BTreeMap::new();
    for entry in entries.iter() {
        if file_kind(entry.mode) == 0o100_000
            && !entry.ghost
            && entry.file_size != 0
            && let (Some(device), Some(inode), Some(offset)) =
                (entry.device, entry.inode, entry.data_offset)
        {
            let previous: Option<(usize, u64)> =
                content.insert((device, inode), (offset, entry.file_size));
            if previous.is_some_and(|value: (usize, u64)| value != (offset, entry.file_size)) {
                return Err(Error::Rpm(format!(
                    "hardlink group for `{}` carries conflicting payload bytes",
                    entry.name
                )));
            }
        }
    }
    for entry in entries.iter_mut() {
        if file_kind(entry.mode) == 0o100_000
            && !entry.ghost
            && entry.file_size != 0
            && entry.data_offset.is_none()
        {
            let identity: (u32, u32) = entry.device.zip(entry.inode).ok_or_else(|| {
                Error::Rpm(format!(
                    "regular member `{}` has no payload bytes",
                    entry.name
                ))
            })?;
            let (offset, size): (usize, u64) =
                content.get(&identity).copied().ok_or_else(|| {
                    Error::Rpm(format!(
                        "hardlink member `{}` has no shared payload bytes",
                        entry.name
                    ))
                })?;
            if size != entry.file_size {
                return Err(Error::Rpm(format!(
                    "hardlink member `{}` size differs from its group",
                    entry.name
                )));
            }
            entry.data_offset = Some(offset);
        }
    }
    Ok(())
}

fn map_standard_cpio(cpio: &[u8], mut entries: Vec<RpmEntry>) -> Result<Vec<RpmEntry>> {
    let archive: CpioArchive = parse_cpio(cpio).map_err(|error: Error| match error {
        Error::Tar(message) => Error::Rpm(format!("payload CPIO parse failed: {message}")),
        other => other,
    })?;
    if !matches!(archive.variant, CpioVariant::Newc | CpioVariant::Crc) {
        return Err(Error::Rpm(format!(
            "payload uses unsupported CPIO variant {}",
            archive.variant.label()
        )));
    }
    let mut payload: BTreeMap<String, crate::containers::CpioEntry> = BTreeMap::new();
    for cpio_entry in archive.entries {
        let name: String = payload_member_name(&cpio_entry.name)?;
        if payload.insert(name.clone(), cpio_entry).is_some() {
            return Err(Error::Rpm(format!("duplicate payload member `{name}`")));
        }
    }
    let mut consumed: BTreeSet<String> = BTreeSet::new();
    for entry in &mut entries {
        if entry.ghost {
            continue;
        }
        let payload_entry: &crate::containers::CpioEntry =
            payload.get(&entry.name).ok_or_else(|| {
                Error::Rpm(format!(
                    "RPM member `{}` is absent from payload",
                    entry.name
                ))
            })?;
        consumed.insert(entry.name.clone());
        if file_kind(payload_entry.mode) != file_kind(entry.mode) {
            return Err(Error::Rpm(format!(
                "RPM member `{}` type differs between header and payload",
                entry.name
            )));
        }
        let expected_size: u64 = match file_kind(entry.mode) {
            0o100_000 | 0o120_000 => entry.file_size,
            _ => 0,
        };
        if payload_entry.file_size != expected_size
            && !(file_kind(entry.mode) == 0o100_000 && payload_entry.file_size == 0)
        {
            return Err(Error::Rpm(format!(
                "RPM member `{}` payload size {} differs from header size {expected_size}",
                entry.name, payload_entry.file_size
            )));
        }
        match file_kind(entry.mode) {
            0o100_000 if payload_entry.file_size == expected_size => {
                entry.data_offset = Some(payload_entry.data_offset);
            }
            0o120_000 => {
                let end: usize = checked_end(
                    payload_entry.data_offset,
                    usize::try_from(payload_entry.file_size).map_err(
                        |_error: std::num::TryFromIntError| {
                            Error::Rpm(format!("symlink `{}` size overflow", entry.name))
                        },
                    )?,
                    "symlink payload",
                )?;
                let target: &[u8] = cpio.get(payload_entry.data_offset..end).ok_or_else(|| {
                    Error::Rpm(format!("symlink `{}` payload is out of bounds", entry.name))
                })?;
                if entry.link_target.as_deref().map(str::as_bytes) != Some(target) {
                    return Err(Error::Rpm(format!(
                        "symlink `{}` target differs between header and payload",
                        entry.name
                    )));
                }
            }
            _ => {}
        }
    }
    if payload.len() != consumed.len() {
        let extra: &String = payload
            .keys()
            .find(|name: &&String| !consumed.contains(*name))
            .ok_or_else(|| Error::Rpm("payload inventory mismatch".to_owned()))?;
        return Err(Error::Rpm(format!(
            "payload member `{extra}` is absent from RPM header"
        )));
    }
    resolve_hardlinks(&mut entries)?;
    Ok(entries)
}

fn fallback_cpio(cpio: &[u8]) -> Result<Vec<RpmEntry>> {
    let archive: CpioArchive = parse_cpio(cpio).map_err(|error: Error| match error {
        Error::Tar(message) => Error::Rpm(format!("payload CPIO parse failed: {message}")),
        other => other,
    })?;
    if !matches!(archive.variant, CpioVariant::Newc | CpioVariant::Crc) {
        return Err(Error::Rpm(format!(
            "payload uses unsupported CPIO variant {}",
            archive.variant.label()
        )));
    }
    archive
        .entries
        .into_iter()
        .map(|entry: crate::containers::CpioEntry| {
            Ok(RpmEntry {
                name: payload_member_name(&entry.name)?,
                mode: entry.mode,
                file_size: entry.file_size,
                link_target: None,
                ghost: false,
                data_offset: (file_kind(entry.mode) == 0o100_000).then_some(entry.data_offset),
                digest: None,
                device: None,
                inode: None,
            })
        })
        .collect()
}

fn map_stripped_cpio(cpio: &[u8], mut entries: Vec<RpmEntry>) -> Result<Vec<RpmEntry>> {
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut last_hardlink: BTreeMap<(u32, u32), usize> = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        if file_kind(entry.mode) == 0o100_000
            && !entry.ghost
            && let Some(identity) = entry.device.zip(entry.inode)
        {
            last_hardlink.insert(identity, index);
        }
    }
    let mut position: usize = 0;
    loop {
        if cpio.get(position..).is_some_and(|remaining: &[u8]| {
            remaining.starts_with(b"070701") || remaining.starts_with(b"070702")
        }) {
            let trailer_archive: CpioArchive =
                parse_cpio(&cpio[position..]).map_err(|error: Error| match error {
                    Error::Tar(message) => {
                        Error::Rpm(format!("stripped CPIO trailer parse failed: {message}"))
                    }
                    other => other,
                })?;
            if !trailer_archive.entries.is_empty() {
                return Err(Error::Rpm(
                    "stripped CPIO payload contains a standard member".to_owned(),
                ));
            }
            break;
        }
        let header_end: usize = checked_end(position, 14, "stripped CPIO header")?;
        let header: &[u8] = cpio.get(position..header_end).ok_or_else(|| {
            Error::Rpm("stripped CPIO trailer is missing or truncated".to_owned())
        })?;
        if header.get(..6) != Some(STRIPPED_MAGIC.as_slice()) {
            return Err(Error::Rpm(format!(
                "stripped CPIO magic is invalid at offset {position}"
            )));
        }
        let index_u32: u32 = parse_hex_u32(&header[6..14], "stripped CPIO file index")?;
        let data_start: usize = align4(header_end, "stripped CPIO header")?;
        zero_padding(cpio, header_end, data_start, "stripped CPIO header")?;
        if index_u32 == u32::MAX {
            zero_padding(cpio, data_start, cpio.len(), "stripped CPIO trailer")?;
            break;
        }
        let index: usize =
            usize::try_from(index_u32).map_err(|_error: std::num::TryFromIntError| {
                Error::Rpm("stripped CPIO index overflow".to_owned())
            })?;
        if !seen.insert(index) {
            return Err(Error::Rpm(format!(
                "stripped CPIO repeats file index {index}"
            )));
        }
        let entry: &mut RpmEntry = entries.get_mut(index).ok_or_else(|| {
            Error::Rpm(format!("stripped CPIO file index {index} is out of bounds"))
        })?;
        if entry.ghost {
            return Err(Error::Rpm(format!(
                "stripped CPIO contains ghost member `{}`",
                entry.name
            )));
        }
        let payload_size: u64 = match file_kind(entry.mode) {
            0o100_000
                if entry
                    .device
                    .zip(entry.inode)
                    .and_then(|identity: (u32, u32)| last_hardlink.get(&identity).copied())
                    .is_some_and(|last: usize| last != index) =>
            {
                0
            }
            0o100_000 | 0o120_000 => entry.file_size,
            _ => 0,
        };
        let data_size: usize =
            usize::try_from(payload_size).map_err(|_error: std::num::TryFromIntError| {
                Error::Rpm(format!("member `{}` size overflow", entry.name))
            })?;
        let data_end: usize = checked_end(data_start, data_size, "stripped CPIO member")?;
        let data: &[u8] = cpio.get(data_start..data_end).ok_or_else(|| {
            Error::Rpm(format!(
                "stripped CPIO member `{}` is truncated",
                entry.name
            ))
        })?;
        match file_kind(entry.mode) {
            0o100_000 if payload_size == entry.file_size => {
                entry.data_offset = Some(data_start);
            }
            0o120_000 if entry.link_target.as_deref().map(str::as_bytes) != Some(data) => {
                return Err(Error::Rpm(format!(
                    "symlink `{}` target differs between header and payload",
                    entry.name
                )));
            }
            _ => {}
        }
        let next: usize = align4(data_end, "stripped CPIO member")?;
        zero_padding(cpio, data_end, next, "stripped CPIO member")?;
        position = next;
    }
    for (index, entry) in entries.iter().enumerate() {
        if !entry.ghost && !seen.contains(&index) {
            return Err(Error::Rpm(format!(
                "RPM member `{}` is absent from stripped payload",
                entry.name
            )));
        }
    }
    resolve_hardlinks(&mut entries)?;
    Ok(entries)
}

fn verify_file_digests(
    cpio: &[u8],
    entries: &[RpmEntry],
    algorithm: FileDigestAlgorithm,
) -> Result<()> {
    for entry in entries {
        let Some(expected): Option<&str> = entry.digest.as_deref() else {
            continue;
        };
        if file_kind(entry.mode) != 0o100_000 || entry.ghost {
            continue;
        }
        let offset: usize = entry.data_offset.ok_or_else(|| {
            Error::Rpm(format!(
                "regular member `{}` has no payload bytes",
                entry.name
            ))
        })?;
        let size: usize =
            usize::try_from(entry.file_size).map_err(|_error: std::num::TryFromIntError| {
                Error::Rpm(format!("member `{}` size overflow", entry.name))
            })?;
        let end: usize = checked_end(offset, size, "RPM member digest")?;
        let data: &[u8] = cpio.get(offset..end).ok_or_else(|| {
            Error::Rpm(format!(
                "member `{}` digest range is out of bounds",
                entry.name
            ))
        })?;
        let (actual, digits): (String, usize) = match algorithm {
            FileDigestAlgorithm::Md5 => (format!("{:x}", md5::compute(data)), 32),
            FileDigestAlgorithm::Sha1 => (format!("{:x}", Sha1::digest(data)), 40),
            FileDigestAlgorithm::Sha2_224 => (format!("{:x}", Sha224::digest(data)), 56),
            FileDigestAlgorithm::Sha2_256 => (format!("{:x}", Sha256::digest(data)), 64),
            FileDigestAlgorithm::Sha2_384 => (format!("{:x}", Sha384::digest(data)), 96),
            FileDigestAlgorithm::Sha2_512 => (format!("{:x}", Sha512::digest(data)), 128),
            FileDigestAlgorithm::Sha3_256 => (format!("{:x}", Sha3_256::digest(data)), 64),
            FileDigestAlgorithm::Sha3_512 => (format!("{:x}", Sha3_512::digest(data)), 128),
        };
        verify_hex(
            expected,
            &actual,
            digits,
            &format!("file `{}` digest", entry.name),
        )?;
    }
    Ok(())
}

fn verify_envelope_digests(bytes: &[u8], envelope: &Envelope<'_>) -> Result<()> {
    let header_bytes: &[u8] = bytes
        .get(envelope.main.start..envelope.main.end)
        .ok_or_else(|| Error::Rpm("main header range is out of bounds".to_owned()))?;
    let signed_bytes: &[u8] = bytes
        .get(envelope.main.start..)
        .ok_or_else(|| Error::Rpm("RPM signed range is out of bounds".to_owned()))?;
    match envelope.format {
        RpmFormat::V3 => {
            if !verify_md5(
                &envelope.signature,
                TAG_SIGNATURE_MD5,
                signed_bytes,
                "RPM v3 header and payload MD5",
            )? {
                return Err(Error::Rpm("RPM v3 MD5 signature is missing".to_owned()));
            }
        }
        RpmFormat::V4 => {
            let _md5: bool = verify_md5(
                &envelope.signature,
                TAG_SIGNATURE_MD5,
                signed_bytes,
                "RPM v4 header and payload MD5",
            )?;
            let (_sha1, _sha256): (bool, bool) = (
                verify_sha1(
                    &envelope.signature,
                    TAG_SIGNATURE_SHA1,
                    header_bytes,
                    "main header SHA-1",
                )?,
                verify_sha256(
                    &envelope.signature,
                    TAG_SIGNATURE_SHA256,
                    header_bytes,
                    "main header SHA-256",
                )?,
            );
        }
        RpmFormat::V6 => {
            if !verify_sha256(
                &envelope.signature,
                TAG_SIGNATURE_SHA256,
                header_bytes,
                "main header SHA-256",
            )? || !verify_sha3_256(
                &envelope.signature,
                TAG_SIGNATURE_SHA3_256,
                header_bytes,
                "main header SHA3-256",
            )? {
                return Err(Error::Rpm(
                    "RPM v6 header digests are incomplete".to_owned(),
                ));
            }
        }
    }
    let signed_size: Option<u64> = declared_size(
        &envelope.signature,
        TAG_SIGNATURE_SIZE,
        TAG_SIGNATURE_LONG_SIZE,
        "RPM signed size",
    )?;
    if let Some(expected) = signed_size {
        let actual: u64 = u64::try_from(bytes.len() - envelope.main.start).map_err(
            |_error: std::num::TryFromIntError| Error::Rpm("RPM signed size overflow".to_owned()),
        )?;
        if expected != actual {
            return Err(Error::Rpm(format!(
                "RPM signed size {expected} differs from actual {actual}"
            )));
        }
    }
    Ok(())
}

fn verify_payload_digests(envelope: &Envelope<'_>, cpio: &[u8]) -> Result<()> {
    let compressed_sha256: bool = verify_sha256(
        &envelope.main,
        TAG_PAYLOAD_SHA256,
        envelope.payload,
        "compressed payload SHA-256",
    )?;
    let uncompressed_sha256: bool = verify_sha256(
        &envelope.main,
        TAG_PAYLOAD_SHA256_ALT,
        cpio,
        "uncompressed payload SHA-256",
    )?;
    let compressed_sha512: bool = verify_sha512(
        &envelope.main,
        TAG_PAYLOAD_SHA512,
        envelope.payload,
        "compressed payload SHA-512",
    )?;
    let uncompressed_sha512: bool = verify_sha512(
        &envelope.main,
        TAG_PAYLOAD_SHA512_ALT,
        cpio,
        "uncompressed payload SHA-512",
    )?;
    let compressed_sha3: bool = verify_sha3_256(
        &envelope.main,
        TAG_PAYLOAD_SHA3_256,
        envelope.payload,
        "compressed payload SHA3-256",
    )?;
    let uncompressed_sha3: bool = verify_sha3_256(
        &envelope.main,
        TAG_PAYLOAD_SHA3_256_ALT,
        cpio,
        "uncompressed payload SHA3-256",
    )?;
    if envelope.format == RpmFormat::V6
        && !(compressed_sha256
            && uncompressed_sha256
            && compressed_sha512
            && uncompressed_sha512
            && compressed_sha3
            && uncompressed_sha3)
    {
        return Err(Error::Rpm(
            "RPM v6 payload digests are incomplete".to_owned(),
        ));
    }
    let compressed_size: u64 =
        u64::try_from(envelope.payload.len()).map_err(|_error: std::num::TryFromIntError| {
            Error::Rpm("compressed payload size overflow".to_owned())
        })?;
    let uncompressed_size: u64 =
        u64::try_from(cpio.len()).map_err(|_error: std::num::TryFromIntError| {
            Error::Rpm("uncompressed payload size overflow".to_owned())
        })?;
    for (tag, actual, subject) in [
        (TAG_PAYLOAD_SIZE, compressed_size, "compressed payload"),
        (
            TAG_PAYLOAD_SIZE_ALT,
            uncompressed_size,
            "uncompressed payload",
        ),
    ] {
        let declared: Option<u64> = envelope.main.size(tag)?;
        if let Some(expected) = declared
            && expected != actual
        {
            return Err(Error::Rpm(format!(
                "{subject} size {expected} differs from actual {actual}"
            )));
        }
    }
    let signature_payload_size: Option<u64> = declared_size(
        &envelope.signature,
        TAG_SIGNATURE_PAYLOAD_SIZE,
        TAG_SIGNATURE_LONG_PAYLOAD_SIZE,
        "RPM signature payload size",
    )?;
    if let Some(expected) = signature_payload_size
        && expected != uncompressed_size
    {
        return Err(Error::Rpm(format!(
            "signature payload size {expected} differs from actual {uncompressed_size}"
        )));
    }
    if envelope.format == RpmFormat::V6
        && (envelope.main.entry(TAG_PAYLOAD_SIZE).is_none()
            || envelope.main.entry(TAG_PAYLOAD_SIZE_ALT).is_none())
    {
        return Err(Error::Rpm("RPM v6 payload sizes are missing".to_owned()));
    }
    Ok(())
}

pub fn recover_rpm(bytes: &[u8], cap: u64) -> Result<RecoveredRpm> {
    let envelope: Envelope<'_> = parse_envelope(bytes)?;
    verify_envelope_digests(bytes, &envelope)?;
    let mut metadata_bytes: usize = 0;
    let signature_blobs: Vec<RpmSignatureBlob> = signature_blobs_with_budget(
        &envelope.signature,
        &mut metadata_bytes,
        super::MAX_CONTAINER_METADATA_BYTES,
    )?;
    let inventory: Option<(Vec<RpmEntry>, FileDigestAlgorithm)> = header_files(
        &envelope.main,
        envelope.format,
        &mut metadata_bytes,
        super::MAX_CONTAINER_METADATA_BYTES,
    )?;
    let cpio: Vec<u8> = decompress_payload(envelope.payload, envelope.compression, cap)?;
    verify_payload_digests(&envelope, &cpio)?;
    let entries: Vec<RpmEntry> = match inventory {
        Some((header_entries, algorithm)) => {
            let mapped: Vec<RpmEntry> = if cpio.starts_with(STRIPPED_MAGIC) {
                map_stripped_cpio(&cpio, header_entries)?
            } else {
                map_standard_cpio(&cpio, header_entries)?
            };
            verify_file_digests(&cpio, &mapped, algorithm)?;
            mapped
        }
        None if cpio.starts_with(STRIPPED_MAGIC) => {
            return Err(Error::Rpm(
                "stripped CPIO requires an RPM file inventory".to_owned(),
            ));
        }
        None => fallback_cpio(&cpio)?,
    };
    let compressed_size: u64 =
        u64::try_from(envelope.payload.len()).map_err(|_error: std::num::TryFromIntError| {
            Error::Rpm("payload size overflow".to_owned())
        })?;
    Ok(RecoveredRpm {
        format: envelope.format,
        compression: envelope.compression,
        compressed_size,
        signature_blobs,
        cpio,
        entries,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn append_crc_entry(archive: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
        let name_size: usize = name.len() + 1;
        let checksum: u32 = data.iter().map(|byte: &u8| u32::from(*byte)).sum();
        let header: String = format!(
            "070702{0:08x}{mode:08x}{1:08x}{1:08x}{2:08x}{1:08x}{3:08x}{1:08x}{1:08x}{1:08x}{1:08x}{4:08x}{checksum:08x}",
            1,
            0,
            1,
            data.len(),
            name_size
        );
        assert_eq!(header.len(), 110);
        archive.extend_from_slice(header.as_bytes());
        archive.extend_from_slice(name.as_bytes());
        archive.push(0);
        while !archive.len().is_multiple_of(4) {
            archive.push(0);
        }
        archive.extend_from_slice(data);
        while !archive.len().is_multiple_of(4) {
            archive.push(0);
        }
    }

    fn indexed_header(entries: &[(u32, u32, i32, u32)], store: &[u8]) -> Vec<u8> {
        let mut bytes: Vec<u8> = HEADER_MAGIC.to_vec();
        bytes.extend_from_slice(
            &u32::try_from(entries.len())
                .expect("test entry count")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(store.len())
                .expect("test store size")
                .to_be_bytes(),
        );
        for (tag, kind, offset, count) in entries {
            bytes.extend_from_slice(&tag.to_be_bytes());
            bytes.extend_from_slice(&kind.to_be_bytes());
            bytes.extend_from_slice(&offset.to_be_bytes());
            bytes.extend_from_slice(&count.to_be_bytes());
        }
        bytes.extend_from_slice(store);
        bytes
    }

    fn regular_entry(name: &str, size: u64) -> RpmEntry {
        RpmEntry {
            name: name.to_owned(),
            mode: 0o100_644,
            file_size: size,
            link_target: None,
            ghost: false,
            data_offset: None,
            digest: None,
            device: Some(0),
            inode: Some(1),
        }
    }

    #[test]
    fn malformed_header_indices_types_counts_and_strings_fail() {
        for (bytes, message) in [
            (
                indexed_header(&[(1, 7, 1, 1)], b""),
                "range exceeds its store",
            ),
            (indexed_header(&[(1, 42, 0, 1)], b"x"), "unknown type"),
            (
                indexed_header(&[(1, 6, 0, 2)], b"a\0b\0"),
                "count must be one",
            ),
            (
                indexed_header(&[(1, 6, 0, 1)], b"unterminated"),
                "unterminated",
            ),
            (
                indexed_header(&[(1, 7, 0, 1), (1, 7, 1, 1)], b"ab"),
                "duplicated or unsorted",
            ),
        ] {
            let error: Error =
                parse_header(&bytes, 0, "test header").expect_err("malformed header must fail");
            assert!(error.to_string().contains(message), "{error}");
        }
    }

    #[test]
    fn truncated_lead_header_and_store_fail() {
        let lead: Vec<u8> = vec![0; LEAD_LEN - 1];
        let error: Error = parse_envelope(&lead).expect_err("truncated lead must fail");
        assert!(error.to_string().contains("lead is truncated"), "{error}");

        let error: Error = parse_header(&HEADER_MAGIC, 0, "test header")
            .expect_err("truncated header intro must fail");
        assert!(error.to_string().contains("intro is truncated"), "{error}");

        let mut store: Vec<u8> = indexed_header(&[(1, 7, 0, 2)], b"x");
        store[12..16].copy_from_slice(&2u32.to_be_bytes());
        let error: Error =
            parse_header(&store, 0, "test header").expect_err("truncated header store must fail");
        assert!(error.to_string().contains("store is truncated"), "{error}");
    }

    #[test]
    fn malformed_stripped_indices_and_missing_members_fail() {
        let mut out_of_bounds: Vec<u8> = b"07070X00000001".to_vec();
        out_of_bounds.extend_from_slice(&[0, 0]);
        let error: Error = map_stripped_cpio(&out_of_bounds, vec![regular_entry("x", 0)])
            .expect_err("out-of-bounds stripped index must fail");
        assert!(error.to_string().contains("out of bounds"), "{error}");

        let mut missing: Vec<u8> = b"07070Xffffffff".to_vec();
        missing.extend_from_slice(&[0, 0]);
        let error: Error = map_stripped_cpio(&missing, vec![regular_entry("x", 1)])
            .expect_err("missing stripped member must fail");
        assert!(error.to_string().contains("absent"), "{error}");
    }

    #[test]
    fn duplicate_standard_cpio_names_and_mismatched_arrays_fail() {
        let mut cpio: Vec<u8> = Vec::new();
        append_crc_entry(&mut cpio, "x", 0o100_644, b"a");
        append_crc_entry(&mut cpio, "x", 0o100_644, b"b");
        append_crc_entry(&mut cpio, "TRAILER!!!", 0, b"");
        let error: Error = map_standard_cpio(&cpio, vec![regular_entry("x", 1)])
            .expect_err("duplicate CPIO member must fail");
        assert!(error.to_string().contains("duplicate"), "{error}");

        let error: Error = require_file_count(1, 2, TAG_FILE_MODES)
            .expect_err("mismatched RPM file arrays must fail");
        assert!(error.to_string().contains("values for 2 files"), "{error}");
    }

    #[test]
    fn crc_cpio_maps_through_the_rpm_inventory() {
        let mut cpio: Vec<u8> = Vec::new();
        append_crc_entry(&mut cpio, "usr/bin/tool", 0o100_755, b"abc");
        append_crc_entry(&mut cpio, "TRAILER!!!", 0, b"");
        let mut entry: RpmEntry = regular_entry("usr/bin/tool", 3);
        entry.mode = 0o100_755;
        let entries: Vec<RpmEntry> = map_standard_cpio(&cpio, vec![entry]).expect("map CRC CPIO");
        let offset: usize = entries[0].data_offset.expect("mapped payload offset");
        assert_eq!(&cpio[offset..offset + 3], b"abc");
    }

    #[test]
    fn compressed_payload_decoders_reject_trailing_bytes() {
        for bytes in [
            include_bytes!("../../tests/fixtures/rpm/hello-v4-gzip.rpm").as_slice(),
            include_bytes!("../../tests/fixtures/rpm/rpm-v6-xz.rpm").as_slice(),
            include_bytes!("../../tests/fixtures/rpm/rpm-v6-zstd.rpm").as_slice(),
            include_bytes!("../../tests/fixtures/rpm/rpm-v6-bzip2.rpm").as_slice(),
            include_bytes!("../../tests/fixtures/rpm/rpm-opensuse11-lzma.rpm").as_slice(),
        ] {
            let envelope: Envelope<'_> = parse_envelope(bytes).expect("parse envelope");
            let mut payload: Vec<u8> = envelope.payload.to_vec();
            payload.push(0xa5);
            let error: Error = decompress_payload(&payload, envelope.compression, 64 * 1024 * 1024)
                .expect_err("trailing compressed bytes must fail");
            assert!(error.to_string().contains("trailing"), "{error}");
        }
    }

    #[test]
    fn repeated_signature_ranges_obey_the_derived_metadata_budget() {
        let header: Header<'_> = Header {
            entries: vec![
                HeaderEntry {
                    tag: 267,
                    kind: HeaderType::Binary,
                    offset: 0,
                    count: 8,
                },
                HeaderEntry {
                    tag: 268,
                    kind: HeaderType::Binary,
                    offset: 0,
                    count: 8,
                },
            ],
            store: b"12345678",
            start: 0,
            end: 8,
        };
        let error: Error = signature_blobs_with_cap(&header, 8)
            .expect_err("overlapping signature ranges must obey the aggregate cap");
        assert!(error.to_string().contains("metadata"), "{error}");
    }

    #[test]
    fn repeated_directory_prefixes_obey_the_derived_metadata_budget() {
        let error: Error =
            join_file_names_with_cap(&["a", "b", "c"], &[0, 0, 0], &["12345678/"], 16)
                .expect_err("repeated directory prefixes must obey the aggregate cap");
        assert!(error.to_string().contains("metadata"), "{error}");
    }

    #[test]
    fn link_targets_and_digests_share_one_metadata_budget() {
        let error: Error = owned_file_metadata_with_cap("1234", "5678", 7)
            .expect_err("link and digest copies must share the aggregate cap");
        assert!(error.to_string().contains("metadata"), "{error}");
        let (digest, link_target): (Option<String>, Option<String>) =
            owned_file_metadata_with_cap("1234", "5678", 8).expect("exact metadata boundary");
        assert_eq!(digest.as_deref(), Some("1234"));
        assert_eq!(link_target.as_deref(), Some("5678"));
    }

    #[test]
    fn v6_requires_a_modern_declared_file_digest_algorithm() {
        let missing: Header<'_> = Header {
            entries: Vec::new(),
            store: &[],
            start: 0,
            end: 0,
        };
        let error: Error = file_digest_algorithm(&missing, RpmFormat::V6)
            .expect_err("v6 digest algorithm must be present");
        assert!(error.to_string().contains("digest algorithm"), "{error}");

        let weak_store: [u8; 4] = 1u32.to_be_bytes();
        let weak: Header<'_> = Header {
            entries: vec![HeaderEntry {
                tag: TAG_FILE_DIGEST_ALGORITHM,
                kind: HeaderType::Int32,
                offset: 0,
                count: 1,
            }],
            store: &weak_store,
            start: 0,
            end: 4,
        };
        let error: Error = file_digest_algorithm(&weak, RpmFormat::V6)
            .expect_err("v6 weak digest algorithm must fail");
        assert!(error.to_string().contains("at least SHA-256"), "{error}");
    }

    #[test]
    fn long_signature_sizes_take_precedence_without_ambiguity() {
        let store: [u8; 8] = 123u64.to_be_bytes();
        let header: Header<'_> = Header {
            entries: vec![HeaderEntry {
                tag: 270,
                kind: HeaderType::Int64,
                offset: 0,
                count: 1,
            }],
            store: &store,
            start: 0,
            end: 8,
        };
        assert_eq!(
            declared_size(&header, TAG_SIGNATURE_SIZE, 270, "signed").expect("long size"),
            Some(123)
        );
    }
}
