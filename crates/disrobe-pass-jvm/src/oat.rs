use serde::{Deserialize, Serialize};

use disrobe_binfmt::{NativeFile, SectionInfo, SymbolInfo, parse_native};

use crate::dex::{DexFile, parse as parse_dex};
use crate::error::{Error, Result};

pub const OAT_MAGIC: [u8; 4] = [b'o', b'a', b't', b'\n'];
pub const ODEX_MAGIC: [u8; 4] = [b'd', b'e', b'y', b'\n'];
pub const OAT_DATA_SYMBOL: &str = "oatdata";
pub const RODATA_SECTION: &str = ".rodata";

const OAT_HEADER_MIN: usize = 24;
const ODEX_HEADER_MIN: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstructionSet {
    None,
    Arm,
    Arm64,
    X86,
    X86_64,
    Mips,
    Mips64,
    Riscv64,
    Unknown(i32),
}

impl InstructionSet {
    #[inline]
    #[must_use]
    pub const fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Arm,
            2 => Self::Arm64,
            3 => Self::X86,
            4 => Self::X86_64,
            5 => Self::Mips,
            6 => Self::Mips64,
            8 => Self::Riscv64,
            other => Self::Unknown(other),
        }
    }

    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::Riscv64 => "riscv64",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OatVersion(pub [u8; 4]);

impl OatVersion {
    #[inline]
    #[must_use]
    pub const fn from_ascii(raw: [u8; 4]) -> Option<Self> {
        if raw[0].is_ascii_digit()
            && raw[1].is_ascii_digit()
            && raw[2].is_ascii_digit()
            && raw[3] == 0
        {
            Some(Self(raw))
        } else {
            None
        }
    }

    #[inline]
    #[must_use]
    pub fn digits(self) -> u32 {
        let hundreds: u32 = u32::from(self.0[0] - b'0');
        let tens: u32 = u32::from(self.0[1] - b'0');
        let units: u32 = u32::from(self.0[2] - b'0');
        hundreds * 100 + tens * 10 + units
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OatHeader {
    pub version: OatVersion,
    pub adler32_checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub executable_offset: u32,
    pub key_value_store_size: u32,
    pub key_value_store: Vec<(String, String)>,
}

#[inline]
fn read_u32_at(bytes: &[u8], off: usize) -> Option<u32> {
    bytes
        .get(off..off + 4)
        .map(|s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
fn read_i32_at(bytes: &[u8], off: usize) -> Option<i32> {
    bytes
        .get(off..off + 4)
        .map(|s: &[u8]| i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn parse_key_value_store(region: &[u8]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut cursor: usize = 0;
    while cursor < region.len() {
        let key_end: usize = match region[cursor..].iter().position(|&b: &u8| b == 0) {
            Some(rel) => cursor + rel,
            None => break,
        };
        let key: String = String::from_utf8_lossy(&region[cursor..key_end]).into_owned();
        let value_start: usize = key_end + 1;
        if value_start > region.len() {
            break;
        }
        let value_end: usize = match region[value_start..].iter().position(|&b: &u8| b == 0) {
            Some(rel) => value_start + rel,
            None => region.len(),
        };
        let value: String = String::from_utf8_lossy(&region[value_start..value_end]).into_owned();
        out.push((key, value));
        cursor = value_end + 1;
    }
    out
}

pub fn parse_oat_header(rodata: &[u8]) -> Result<OatHeader> {
    if rodata.len() < OAT_HEADER_MIN {
        return Err(Error::Truncated {
            offset: 0,
            needed: OAT_HEADER_MIN,
            had: rodata.len(),
        });
    }
    let magic: [u8; 4] = [rodata[0], rodata[1], rodata[2], rodata[3]];
    if magic != OAT_MAGIC {
        return Err(Error::BadOatMagic(magic));
    }
    let raw_version: [u8; 4] = [rodata[4], rodata[5], rodata[6], rodata[7]];
    let Some(version): Option<OatVersion> = OatVersion::from_ascii(raw_version) else {
        return Err(Error::UnsupportedOatVersion(raw_version));
    };
    let adler32_checksum: u32 = read_u32_at(rodata, 8).ok_or(Error::Truncated {
        offset: 8,
        needed: 4,
        had: rodata.len(),
    })?;
    let iset_raw: i32 = read_i32_at(rodata, 12).ok_or(Error::Truncated {
        offset: 12,
        needed: 4,
        had: rodata.len(),
    })?;
    let instruction_set: InstructionSet = InstructionSet::from_i32(iset_raw);
    let instruction_set_features_bitmap: u32 = read_u32_at(rodata, 16).ok_or(Error::Truncated {
        offset: 16,
        needed: 4,
        had: rodata.len(),
    })?;
    let dex_file_count: u32 = read_u32_at(rodata, 20).ok_or(Error::Truncated {
        offset: 20,
        needed: 4,
        had: rodata.len(),
    })?;
    let executable_offset: u32 = read_u32_at(rodata, 24).unwrap_or(0);
    let kv_size_off: usize = 28;
    let key_value_store_size: u32 = read_u32_at(rodata, kv_size_off).unwrap_or(0);
    let kv_data_off: usize = kv_size_off + 4;
    let kv_end: usize = kv_data_off
        .checked_add(key_value_store_size as usize)
        .ok_or(Error::OatOffsetOutOfRange {
            offset: usize::MAX,
            size: rodata.len(),
        })?;
    let key_value_store: Vec<(String, String)> = if key_value_store_size == 0 {
        Vec::new()
    } else if kv_end > rodata.len() {
        return Err(Error::OatOffsetOutOfRange {
            offset: kv_end,
            size: rodata.len(),
        });
    } else {
        parse_key_value_store(&rodata[kv_data_off..kv_end])
    };
    Ok(OatHeader {
        version,
        adler32_checksum,
        instruction_set,
        instruction_set_features_bitmap,
        dex_file_count,
        executable_offset,
        key_value_store_size,
        key_value_store,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OatFile {
    pub header: OatHeader,
    pub instruction_set: InstructionSet,
    pub dex_locations: Vec<String>,
}

fn find_oat_offset(elf_bytes: &[u8], native: &NativeFile) -> Result<usize> {
    let _anchor_symbol: Option<&SymbolInfo> = native
        .symbols
        .iter()
        .find(|s: &&SymbolInfo| s.name == OAT_DATA_SYMBOL);
    let _anchor_section: Option<&SectionInfo> = native
        .sections
        .iter()
        .find(|s: &&SectionInfo| s.name == RODATA_SECTION);
    elf_bytes
        .windows(OAT_MAGIC.len())
        .position(|w: &[u8]| w == OAT_MAGIC)
        .ok_or(Error::OatOffsetOutOfRange {
            offset: 0,
            size: elf_bytes.len(),
        })
}

pub fn parse_oat(elf_bytes: &[u8]) -> Result<OatFile> {
    let native: NativeFile = parse_native(elf_bytes).map_err(|_e| Error::OatOffsetOutOfRange {
        offset: 0,
        size: elf_bytes.len(),
    })?;
    let oat_off: usize = find_oat_offset(elf_bytes, &native)?;
    let header: OatHeader = parse_oat_header(&elf_bytes[oat_off..])?;
    let instruction_set: InstructionSet = header.instruction_set;
    let dex_locations: Vec<String> = header
        .key_value_store
        .iter()
        .filter(|(k, _)| k == "dex-locations" || k == "classpath")
        .map(|(_, v)| v.clone())
        .collect();
    Ok(OatFile {
        header,
        instruction_set,
        dex_locations,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexOptHeader {
    pub version: [u8; 4],
    pub dex_offset: u32,
    pub dex_length: u32,
    pub deps_offset: u32,
    pub deps_length: u32,
    pub opt_offset: u32,
    pub opt_length: u32,
    pub flags: u32,
    pub checksum: u32,
}

pub fn parse_odex_header(bytes: &[u8]) -> Result<DexOptHeader> {
    if bytes.len() < ODEX_HEADER_MIN {
        return Err(Error::Truncated {
            offset: 0,
            needed: ODEX_HEADER_MIN,
            had: bytes.len(),
        });
    }
    let magic: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if magic != ODEX_MAGIC {
        return Err(Error::BadOdexMagic(magic));
    }
    let raw_version: [u8; 4] = [bytes[4], bytes[5], bytes[6], bytes[7]];
    if OatVersion::from_ascii(raw_version).is_none() {
        return Err(Error::UnsupportedOatVersion(raw_version));
    }
    let read_u32 = |o: usize| -> u32 {
        u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
    };
    Ok(DexOptHeader {
        version: raw_version,
        dex_offset: read_u32(8),
        dex_length: read_u32(12),
        deps_offset: read_u32(16),
        deps_length: read_u32(20),
        opt_offset: read_u32(24),
        opt_length: read_u32(28),
        flags: read_u32(32),
        checksum: read_u32(36),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OdexFile {
    pub header: DexOptHeader,
    pub dex: DexFile,
}

pub fn parse_odex(bytes: &[u8]) -> Result<OdexFile> {
    let header: DexOptHeader = parse_odex_header(bytes)?;
    let dex_start: usize = header.dex_offset as usize;
    let dex_end: usize =
        dex_start
            .checked_add(header.dex_length as usize)
            .ok_or(Error::OatOffsetOutOfRange {
                offset: usize::MAX,
                size: bytes.len(),
            })?;
    if dex_end > bytes.len() {
        return Err(Error::OatOffsetOutOfRange {
            offset: dex_end,
            size: bytes.len(),
        });
    }
    let dex: DexFile = parse_dex(&bytes[dex_start..dex_end])?;
    Ok(OdexFile { header, dex })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn build_header(dex_count: u32, iset: i32) -> Vec<u8> {
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&OAT_MAGIC);
        b.extend_from_slice(b"183\0");
        b.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        b.extend_from_slice(&iset.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&dex_count.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        let kv: &[u8] = b"compiler-filter\0speed\0";
        b.extend_from_slice(&(kv.len() as u32).to_le_bytes());
        b.extend_from_slice(kv);
        b
    }

    #[test]
    fn oat_header_decodes_fields() {
        let h: OatHeader = parse_oat_header(&build_header(3, 2)).expect("oat header");
        assert_eq!(h.dex_file_count, 3);
        assert_eq!(h.instruction_set, InstructionSet::Arm64);
        assert_eq!(h.adler32_checksum, 0xDEAD_BEEF);
        assert_eq!(h.version.digits(), 183);
        assert!(
            h.key_value_store
                .iter()
                .any(|(k, v): &(String, String)| k == "compiler-filter" && v == "speed")
        );
    }

    #[test]
    fn oat_rejects_bad_magic() {
        let err: Error = parse_oat_header(&[0u8; 32]).expect_err("bad magic");
        assert!(matches!(err, Error::BadOatMagic(_)));
    }

    #[test]
    fn oat_rejects_truncated() {
        let err: Error = parse_oat_header(&[0u8; 8]).expect_err("truncated");
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn instruction_set_maps_aosp() {
        assert_eq!(InstructionSet::from_i32(2), InstructionSet::Arm64);
        assert_eq!(InstructionSet::from_i32(8), InstructionSet::Riscv64);
        assert_eq!(InstructionSet::from_i32(99), InstructionSet::Unknown(99));
    }

    #[test]
    fn odex_rejects_bad_magic() {
        let err: Error = parse_odex_header(&[0u8; 40]).expect_err("bad magic");
        assert!(matches!(err, Error::BadOdexMagic(_)));
    }
}
