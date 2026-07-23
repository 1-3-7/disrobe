use std::collections::BTreeMap;

use disrobe_bytes::ByteReader;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::pe::{ClrHeader, PeImage};

pub const METADATA_SIGNATURE: u32 = 0x424A_5342;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataRoot {
    pub signature: u32,
    pub major: u16,
    pub minor: u16,
    pub version: String,
    pub flags: u16,
    pub streams: BTreeMap<String, StreamHeader>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamHeader {
    pub offset: u32,
    pub size: u32,
}

impl MetadataRoot {
    #[must_use]
    pub fn runtime_label(&self) -> RuntimeLabel {
        RuntimeLabel::classify(&self.version)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeLabel {
    NetFramework1,
    NetFramework2,
    NetFramework4,
    NetCore3,
    Net5,
    Net6,
    Net7,
    Net8,
    Net9,
    Net10OrLater,
    Unknown,
}

impl RuntimeLabel {
    #[must_use]
    pub fn classify(version: &str) -> Self {
        let v: &str = version.trim_start_matches('v');
        if v.starts_with("1.") {
            Self::NetFramework1
        } else if v.starts_with("3.0") || v.starts_with("3.1") {
            Self::NetCore3
        } else if v.starts_with("2.0") || v.starts_with("2.1") || v.starts_with("3.5") {
            Self::NetFramework2
        } else if v.starts_with("4.") {
            Self::NetFramework4
        } else if v.starts_with("5.") {
            Self::Net5
        } else if v.starts_with("6.") {
            Self::Net6
        } else if v.starts_with("7.") {
            Self::Net7
        } else if v.starts_with("8.") {
            Self::Net8
        } else if v.starts_with("9.") {
            Self::Net9
        } else if v.starts_with("10.") || v.starts_with("11.") {
            Self::Net10OrLater
        } else {
            Self::Unknown
        }
    }

    #[must_use]
    pub const fn marketing_name(self) -> &'static str {
        match self {
            Self::NetFramework1 => ".NET Framework 1.x",
            Self::NetFramework2 => ".NET Framework 2.0/3.x",
            Self::NetFramework4 => ".NET Framework 4.x",
            Self::NetCore3 => ".NET Core 3.x",
            Self::Net5 => ".NET 5",
            Self::Net6 => ".NET 6",
            Self::Net7 => ".NET 7",
            Self::Net8 => ".NET 8",
            Self::Net9 => ".NET 9",
            Self::Net10OrLater => ".NET 10+",
            Self::Unknown => "unknown",
        }
    }
}

pub fn parse_metadata_root(image: &[u8], pe: &PeImage, clr: &ClrHeader) -> Result<MetadataRoot> {
    let slice: &[u8] = if clr.metadata.size == 0 {
        pe.slice_at_rva_to_end(image, clr.metadata.rva)?
    } else {
        pe.slice_at_rva(image, clr.metadata.rva, clr.metadata.size as usize)?
    };
    let mut r: ByteReader<'_> = ByteReader::new(slice);
    let signature: u32 = r.read_u32_le()?;
    if signature != METADATA_SIGNATURE {
        return Err(Error::BadMetadataSignature(signature));
    }
    let major: u16 = r.read_u16_le()?;
    let minor: u16 = r.read_u16_le()?;
    let _reserved: u32 = r.read_u32_le()?;
    let length: u32 = r.read_u32_le()?;
    let raw: &[u8] = r.read_bytes(length as usize)?;
    let version: String =
        String::from_utf8_lossy(raw.split(|b: &u8| *b == 0).next().unwrap_or(raw)).into_owned();
    let _flags_padding: u16 = r.read_u16_le()?;
    let stream_count: u16 = r.read_u16_le()?;
    let mut streams: BTreeMap<String, StreamHeader> = BTreeMap::new();
    for _ in 0..stream_count {
        let offset: u32 = r.read_u32_le()?;
        let size: u32 = r.read_u32_le()?;
        let name: String = read_aligned_cstring(&mut r)?;
        streams.insert(name, StreamHeader { offset, size });
    }
    Ok(MetadataRoot {
        signature,
        major,
        minor,
        version,
        flags: 0,
        streams,
    })
}

fn read_aligned_cstring(r: &mut ByteReader<'_>) -> Result<String> {
    let start: usize = r.position();
    let mut bytes: Vec<u8> = Vec::with_capacity(16);
    loop {
        let b: u8 = r.read_u8()?;
        if b == 0 {
            break;
        }
        bytes.push(b);
        if bytes.len() > 256 {
            return Err(Error::UnknownStream(
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
    }
    let length: usize = r.position() - start;
    let padding: usize = (4 - (length % 4)) % 4;
    r.skip(padding)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableStream {
    pub heap_sizes: u8,
    pub valid: u64,
    pub sorted: u64,
    pub row_counts: BTreeMap<u8, u32>,
}

pub fn parse_table_stream(metadata_bytes: &[u8], header: StreamHeader) -> Result<TableStream> {
    let off: usize = header.offset as usize;
    let end: usize = off.saturating_add(header.size as usize);
    if end > metadata_bytes.len() {
        return Err(Error::Truncated {
            offset: off,
            needed: header.size as usize,
            had: metadata_bytes.len().saturating_sub(off),
        });
    }
    let mut r: ByteReader<'_> = ByteReader::new(&metadata_bytes[off..end]);
    let _reserved: u32 = r.read_u32_le()?;
    let _major: u8 = r.read_u8()?;
    let _minor: u8 = r.read_u8()?;
    let heap_sizes: u8 = r.read_u8()?;
    let _padding: u8 = r.read_u8()?;
    let valid: u64 = r.read_u64_le()?;
    let sorted: u64 = r.read_u64_le()?;
    let mut row_counts: BTreeMap<u8, u32> = BTreeMap::new();
    for i in 0u8..64u8 {
        if (valid >> i) & 1 == 1 {
            let count: u32 = r.read_u32_le()?;
            row_counts.insert(i, count);
        }
    }
    Ok(TableStream {
        heap_sizes,
        valid,
        sorted,
        row_counts,
    })
}

#[must_use]
pub fn read_us_heap_strings(metadata_bytes: &[u8], us_header: StreamHeader) -> Vec<String> {
    let off: usize = us_header.offset as usize;
    let end: usize = off
        .saturating_add(us_header.size as usize)
        .min(metadata_bytes.len());
    if off >= end {
        return Vec::new();
    }
    let slice: &[u8] = &metadata_bytes[off..end];
    let mut out: Vec<String> = Vec::new();
    let mut pos: usize = 1;
    while pos < slice.len() {
        let Some((value, consumed)): Option<(u32, usize)> = decompress_uint(&slice[pos..]) else {
            break;
        };
        pos += consumed;
        let blob_len: usize = value as usize;
        if pos + blob_len > slice.len() || blob_len == 0 {
            break;
        }
        let blob: &[u8] = &slice[pos..pos + blob_len];
        let string_byte_len: usize = if blob_len > 0 { blob_len - 1 } else { 0 };
        let chars: usize = string_byte_len / 2;
        let mut units: Vec<u16> = Vec::with_capacity(chars);
        for ci in 0..chars {
            units.push(u16::from_le_bytes([blob[ci * 2], blob[ci * 2 + 1]]));
        }
        out.push(String::from_utf16_lossy(&units));
        pos += blob_len;
    }
    out
}

#[must_use]
pub fn read_strings_heap(metadata_bytes: &[u8], strings: StreamHeader) -> BTreeMap<u32, String> {
    let off: usize = strings.offset as usize;
    let end: usize = off
        .saturating_add(strings.size as usize)
        .min(metadata_bytes.len());
    if off >= end {
        return BTreeMap::new();
    }
    let slice: &[u8] = &metadata_bytes[off..end];
    let mut out: BTreeMap<u32, String> = BTreeMap::new();
    let mut cursor: usize = 0;
    while cursor < slice.len() {
        let start: usize = cursor;
        while cursor < slice.len() && slice[cursor] != 0 {
            cursor += 1;
        }
        if cursor > start {
            let s: String = String::from_utf8_lossy(&slice[start..cursor]).into_owned();
            let key: u32 = u32::try_from(start).unwrap_or(u32::MAX);
            out.insert(key, s);
        }
        cursor += 1;
    }
    out
}

#[must_use]
pub fn decompress_uint(bytes: &[u8]) -> Option<(u32, usize)> {
    if bytes.is_empty() {
        return None;
    }
    let b0: u8 = bytes[0];
    if (b0 & 0x80) == 0 {
        return Some((u32::from(b0), 1));
    }
    if (b0 & 0xC0) == 0x80 {
        if bytes.len() < 2 {
            return None;
        }
        let v: u32 = ((u32::from(b0) & 0x3F) << 8) | u32::from(bytes[1]);
        return Some((v, 2));
    }
    if (b0 & 0xE0) == 0xC0 {
        if bytes.len() < 4 {
            return None;
        }
        let v: u32 = ((u32::from(b0) & 0x1F) << 24)
            | (u32::from(bytes[1]) << 16)
            | (u32::from(bytes[2]) << 8)
            | u32::from(bytes[3]);
        return Some((v, 4));
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn signature_matches_ecma_335_bsjb() {
        assert_eq!(METADATA_SIGNATURE, 0x424A_5342);
        assert_eq!(&METADATA_SIGNATURE.to_le_bytes(), b"BSJB");
    }

    #[test]
    fn runtime_label_classifies_versions() {
        assert_eq!(
            RuntimeLabel::classify("v4.0.30319"),
            RuntimeLabel::NetFramework4
        );
        assert_eq!(RuntimeLabel::classify("v6.0.0"), RuntimeLabel::Net6);
        assert_eq!(RuntimeLabel::classify("v8.0.0"), RuntimeLabel::Net8);
        assert_eq!(RuntimeLabel::classify("v9.0.0"), RuntimeLabel::Net9);
        assert_eq!(
            RuntimeLabel::classify("v10.0.0"),
            RuntimeLabel::Net10OrLater
        );
    }

    #[test]
    fn net_core_3_versions_map_to_core_not_framework() {
        assert_eq!(RuntimeLabel::classify("v3.0.0"), RuntimeLabel::NetCore3);
        assert_eq!(RuntimeLabel::classify("v3.1.0"), RuntimeLabel::NetCore3);
        assert_eq!(RuntimeLabel::classify("3.1"), RuntimeLabel::NetCore3);
        assert_eq!(
            RuntimeLabel::classify("v3.5.0"),
            RuntimeLabel::NetFramework2
        );
        assert_eq!(
            RuntimeLabel::classify("v2.0.50727"),
            RuntimeLabel::NetFramework2
        );
    }

    #[test]
    fn decompress_uint_one_byte() {
        let (v, n): (u32, usize) = decompress_uint(&[0x03]).expect("ok");
        assert_eq!(v, 3);
        assert_eq!(n, 1);
    }

    #[test]
    fn decompress_uint_two_byte() {
        let (v, n): (u32, usize) = decompress_uint(&[0x80 | 0x12, 0x34]).expect("ok");
        assert_eq!(v, 0x1234);
        assert_eq!(n, 2);
    }

    #[test]
    fn decompress_uint_four_byte() {
        let (v, n): (u32, usize) = decompress_uint(&[0xC0 | 0x01, 0x02, 0x03, 0x04]).expect("ok");
        assert_eq!(v, 0x0102_0304);
        assert_eq!(n, 4);
    }

    #[test]
    fn marketing_names_present_for_every_label() {
        for label in [
            RuntimeLabel::NetFramework1,
            RuntimeLabel::NetFramework2,
            RuntimeLabel::NetFramework4,
            RuntimeLabel::NetCore3,
            RuntimeLabel::Net5,
            RuntimeLabel::Net6,
            RuntimeLabel::Net7,
            RuntimeLabel::Net8,
            RuntimeLabel::Net9,
            RuntimeLabel::Net10OrLater,
            RuntimeLabel::Unknown,
        ] {
            assert!(!label.marketing_name().is_empty());
        }
    }
}
