use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DEX_MAGIC_PREFIX: [u8; 4] = [b'd', b'e', b'x', b'\n'];
pub const DEX_ENDIAN_TAG: u32 = 0x1234_5678;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DexVersion {
    V035,
    V037,
    V038,
    V039,
    V040,
    V041,
}

impl DexVersion {
    #[inline]
    #[must_use]
    pub const fn from_ascii(version: [u8; 3]) -> Option<Self> {
        match &version {
            b"035" => Some(Self::V035),
            b"037" => Some(Self::V037),
            b"038" => Some(Self::V038),
            b"039" => Some(Self::V039),
            b"040" => Some(Self::V040),
            b"041" => Some(Self::V041),
            _ => None,
        }
    }

    #[inline]
    #[must_use]
    pub const fn android_marketing(self) -> &'static str {
        match self {
            Self::V035 => "Android 1.0 .. 6.0 (API 1 .. 23)",
            Self::V037 => "Android 7.0 (API 24, default-methods)",
            Self::V038 => "Android 8.0 (API 26, invoke-polymorphic)",
            Self::V039 => "Android 9.0 (API 28, const-method-handle)",
            Self::V040 => "Android 10 .. 13 (API 29 .. 33)",
            Self::V041 => "Android 14 .. 16 (API 34 .. 36, hidden API)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexHeader {
    pub version: DexVersion,
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

pub fn parse_header(bytes: &[u8]) -> Result<DexHeader> {
    if bytes.len() < 0x70 {
        return Err(Error::Truncated {
            offset: 0,
            needed: 0x70,
            had: bytes.len(),
        });
    }
    let mut magic: [u8; 8] = [0u8; 8];
    magic.copy_from_slice(&bytes[..8]);
    if magic[..4] != DEX_MAGIC_PREFIX || magic[7] != 0 {
        return Err(Error::BadDexMagic(magic));
    }
    let version_bytes: [u8; 3] = [magic[4], magic[5], magic[6]];
    let Some(version): Option<DexVersion> = DexVersion::from_ascii(version_bytes) else {
        return Err(Error::UnsupportedDexVersion(version_bytes));
    };
    let checksum: u32 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let mut signature: [u8; 20] = [0u8; 20];
    signature.copy_from_slice(&bytes[12..32]);
    let read_u32 = |o: usize| -> u32 {
        u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
    };
    let endian_tag: u32 = read_u32(40);
    if endian_tag != DEX_ENDIAN_TAG {
        return Err(Error::BadDexEndian(endian_tag));
    }
    Ok(DexHeader {
        version,
        checksum,
        signature,
        file_size: read_u32(32),
        header_size: read_u32(36),
        endian_tag,
        link_size: read_u32(44),
        link_off: read_u32(48),
        map_off: read_u32(52),
        string_ids_size: read_u32(56),
        string_ids_off: read_u32(60),
        type_ids_size: read_u32(64),
        type_ids_off: read_u32(68),
        proto_ids_size: read_u32(72),
        proto_ids_off: read_u32(76),
        field_ids_size: read_u32(80),
        field_ids_off: read_u32(84),
        method_ids_size: read_u32(88),
        method_ids_off: read_u32(92),
        class_defs_size: read_u32(96),
        class_defs_off: read_u32(100),
        data_size: read_u32(104),
        data_off: read_u32(108),
    })
}

fn read_uleb128(bytes: &[u8], off: usize) -> Result<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut cursor: usize = off;
    loop {
        if cursor >= bytes.len() {
            return Err(Error::Truncated {
                offset: cursor,
                needed: 1,
                had: 0,
            });
        }
        let b: u8 = bytes[cursor];
        cursor += 1;
        result |= u32::from(b & 0x7F) << shift;
        if (b & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift >= 32 {
            return Err(Error::BadDexEndian(0));
        }
    }
    Ok((result, cursor))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexFile {
    pub header: DexHeader,
    pub strings: Vec<String>,
    pub type_names: Vec<String>,
    pub class_descriptors: Vec<String>,
}

pub fn parse(bytes: &[u8]) -> Result<DexFile> {
    let header: DexHeader = parse_header(bytes)?;
    let mut strings: Vec<String> = Vec::with_capacity(header.string_ids_size as usize);
    for i in 0..header.string_ids_size as usize {
        let id_off: usize = header.string_ids_off as usize + i * 4;
        if id_off + 4 > bytes.len() {
            break;
        }
        let data_off: u32 = u32::from_le_bytes([
            bytes[id_off],
            bytes[id_off + 1],
            bytes[id_off + 2],
            bytes[id_off + 3],
        ]);
        let data_off_usize: usize = data_off as usize;
        if data_off_usize >= bytes.len() {
            break;
        }
        let (size, after_leb): (u32, usize) = read_uleb128(bytes, data_off_usize)?;
        let end: usize = after_leb + size as usize;
        if end > bytes.len() {
            break;
        }
        let raw: &[u8] = &bytes[after_leb..end];
        let decoded: String = decode_mutf8_lossy(raw);
        strings.push(decoded);
    }
    let mut type_names: Vec<String> = Vec::with_capacity(header.type_ids_size as usize);
    for i in 0..header.type_ids_size as usize {
        let id_off: usize = header.type_ids_off as usize + i * 4;
        if id_off + 4 > bytes.len() {
            break;
        }
        let descriptor_idx: u32 = u32::from_le_bytes([
            bytes[id_off],
            bytes[id_off + 1],
            bytes[id_off + 2],
            bytes[id_off + 3],
        ]);
        let idx: usize = descriptor_idx as usize;
        if idx < strings.len() {
            type_names.push(strings[idx].clone());
        } else {
            type_names.push(String::new());
        }
    }
    let mut class_descriptors: Vec<String> = Vec::with_capacity(header.class_defs_size as usize);
    let class_def_size: usize = 32;
    for i in 0..header.class_defs_size as usize {
        let cd_off: usize = header.class_defs_off as usize + i * class_def_size;
        if cd_off + 4 > bytes.len() {
            break;
        }
        let class_idx: u32 = u32::from_le_bytes([
            bytes[cd_off],
            bytes[cd_off + 1],
            bytes[cd_off + 2],
            bytes[cd_off + 3],
        ]);
        let idx: usize = class_idx as usize;
        if idx < type_names.len() {
            class_descriptors.push(type_names[idx].clone());
        }
    }
    Ok(DexFile {
        header,
        strings,
        type_names,
        class_descriptors,
    })
}

fn decode_mutf8_lossy(raw: &[u8]) -> String {
    let mut out: String = String::with_capacity(raw.len());
    let mut i: usize = 0;
    while i < raw.len() {
        let b1: u8 = raw[i];
        if b1 == 0 {
            break;
        }
        if b1 < 0x80 {
            out.push(b1 as char);
            i += 1;
        } else if (b1 & 0xE0) == 0xC0 && i + 1 < raw.len() {
            let b2: u8 = raw[i + 1];
            let cp: u32 = (u32::from(b1 & 0x1F) << 6) | u32::from(b2 & 0x3F);
            if let Some(ch) = char::from_u32(cp) {
                out.push(ch);
            }
            i += 2;
        } else if (b1 & 0xF0) == 0xE0 && i + 2 < raw.len() {
            let b2: u8 = raw[i + 1];
            let b3: u8 = raw[i + 2];
            let cp: u32 =
                (u32::from(b1 & 0x0F) << 12) | (u32::from(b2 & 0x3F) << 6) | u32::from(b3 & 0x3F);
            if let Some(ch) = char::from_u32(cp) {
                out.push(ch);
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiDex {
    pub files: Vec<DexFile>,
}

pub fn parse_multi_dex(named: &[(&str, &[u8])]) -> Result<MultiDex> {
    let mut files: Vec<DexFile> = Vec::with_capacity(named.len());
    for (_name, bytes) in named {
        files.push(parse(bytes)?);
    }
    Ok(MultiDex { files })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_magic() {
        let bytes: [u8; 0x70] = [0u8; 0x70];
        let err: Error = parse_header(&bytes).expect_err("bad magic");
        assert!(matches!(err, Error::BadDexMagic(_)));
    }

    #[test]
    fn dex_version_table_complete() {
        for v in [b"035", b"037", b"038", b"039", b"040", b"041"] {
            assert!(DexVersion::from_ascii(*v).is_some());
        }
        assert!(DexVersion::from_ascii(*b"099").is_none());
    }

    #[test]
    fn uleb128_single_byte() {
        let (v, n): (u32, usize) = read_uleb128(&[0x42], 0).expect("uleb");
        assert_eq!(v, 0x42);
        assert_eq!(n, 1);
    }

    #[test]
    fn uleb128_two_bytes() {
        let (v, n): (u32, usize) = read_uleb128(&[0xE5, 0x8E, 0x26], 0).expect("uleb");
        assert_eq!(v, 624485);
        assert_eq!(n, 3);
    }
}
