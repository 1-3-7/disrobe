use serde::{Deserialize, Serialize};

use disrobe_binfmt::{NativeFile, SectionInfo, SymbolInfo, parse_native};

use crate::dex::{DexFile, parse as parse_dex};
use crate::error::{Error, Result};

pub const OAT_MAGIC: [u8; 4] = [b'o', b'a', b't', b'\n'];
pub const ODEX_MAGIC: [u8; 4] = [b'd', b'e', b'y', b'\n'];
pub const OAT_DATA_SYMBOL: &str = "oatdata";
pub const RODATA_SECTION: &str = ".rodata";

const OAT_HEADER_FIXED_SIZE: usize = 56;
const ODEX_HEADER_MIN: usize = 40;
const MAX_OAT_DEX_LOCATION_LEN: usize = 4096;
const MAX_OAT_DEX_BYTES: usize = 256 * 1024 * 1024;
const DEX_HEADER_FILE_SIZE_OFFSET: usize = 32;
const DEX_HEADER_MIN: usize = 0x70;

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
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
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

fn read_header_u32(rodata: &[u8], off: usize) -> Result<u32> {
    read_u32_at(rodata, off).ok_or(Error::Truncated {
        offset: off,
        needed: 4,
        had: rodata.len(),
    })
}

pub fn parse_oat_header(rodata: &[u8]) -> Result<OatHeader> {
    if rodata.len() < OAT_HEADER_FIXED_SIZE {
        return Err(Error::Truncated {
            offset: 0,
            needed: OAT_HEADER_FIXED_SIZE,
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
    let adler32_checksum: u32 = read_header_u32(rodata, 8)?;
    let iset_raw: i32 = read_i32_at(rodata, 12).ok_or(Error::Truncated {
        offset: 12,
        needed: 4,
        had: rodata.len(),
    })?;
    let instruction_set: InstructionSet = InstructionSet::from_i32(iset_raw);
    let instruction_set_features_bitmap: u32 = read_header_u32(rodata, 16)?;
    let dex_file_count: u32 = read_header_u32(rodata, 20)?;
    let oat_dex_files_offset: u32 = read_header_u32(rodata, 24)?;
    let executable_offset: u32 = read_header_u32(rodata, 28)?;
    let jni_dlsym_lookup_offset: u32 = read_header_u32(rodata, 32)?;
    let quick_generic_jni_trampoline_offset: u32 = read_header_u32(rodata, 36)?;
    let quick_imt_conflict_trampoline_offset: u32 = read_header_u32(rodata, 40)?;
    let quick_resolution_trampoline_offset: u32 = read_header_u32(rodata, 44)?;
    let quick_to_interpreter_bridge_offset: u32 = read_header_u32(rodata, 48)?;
    let key_value_store_size: u32 = read_header_u32(rodata, 52)?;
    if (oat_dex_files_offset as usize) < OAT_HEADER_FIXED_SIZE {
        return Err(Error::OatOffsetOutOfRange {
            offset: oat_dex_files_offset as usize,
            size: rodata.len(),
        });
    }
    let kv_data_off: usize = OAT_HEADER_FIXED_SIZE;
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
        oat_dex_files_offset,
        executable_offset,
        jni_dlsym_lookup_offset,
        quick_generic_jni_trampoline_offset,
        quick_imt_conflict_trampoline_offset,
        quick_resolution_trampoline_offset,
        quick_to_interpreter_bridge_offset,
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

fn locate_oat_region(elf_bytes: &[u8]) -> Result<usize> {
    let native: NativeFile = parse_native(elf_bytes).map_err(|_e| Error::OatOffsetOutOfRange {
        offset: 0,
        size: elf_bytes.len(),
    })?;
    find_oat_offset(elf_bytes, &native)
}

pub fn parse_oat(elf_bytes: &[u8]) -> Result<OatFile> {
    let oat_off: usize = locate_oat_region(elf_bytes)?;
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
pub struct OatEmbeddedDex {
    pub location: String,
    pub location_checksum: u32,
    pub bytes: Vec<u8>,
}

fn read_oat_dex_file_entry(rodata: &[u8], entry_off: usize) -> Result<(String, u32, usize)> {
    let out_of_range = |offset: usize| Error::OatOffsetOutOfRange {
        offset,
        size: rodata.len(),
    };
    let location_size: u32 =
        read_u32_at(rodata, entry_off).ok_or_else(|| out_of_range(entry_off))?;
    if location_size as usize > MAX_OAT_DEX_LOCATION_LEN {
        return Err(out_of_range(entry_off));
    }
    let location_start: usize = entry_off
        .checked_add(4)
        .ok_or_else(|| out_of_range(usize::MAX))?;
    let location_end: usize = location_start
        .checked_add(location_size as usize)
        .ok_or_else(|| out_of_range(usize::MAX))?;
    let location_bytes: &[u8] = rodata
        .get(location_start..location_end)
        .ok_or_else(|| out_of_range(location_end))?;
    let location: String = String::from_utf8_lossy(location_bytes).into_owned();
    let location_checksum: u32 =
        read_u32_at(rodata, location_end).ok_or_else(|| out_of_range(location_end))?;
    let dex_offset_field: usize = location_end
        .checked_add(4)
        .ok_or_else(|| out_of_range(usize::MAX))?;
    let dex_file_offset: u32 =
        read_u32_at(rodata, dex_offset_field).ok_or_else(|| out_of_range(dex_offset_field))?;
    Ok((location, location_checksum, dex_file_offset as usize))
}

fn slice_embedded_dex(rodata: &[u8], dex_start: usize) -> Result<&[u8]> {
    let out_of_range = |offset: usize| Error::OatOffsetOutOfRange {
        offset,
        size: rodata.len(),
    };
    let header_end: usize = dex_start
        .checked_add(DEX_HEADER_MIN)
        .ok_or_else(|| out_of_range(usize::MAX))?;
    let header: &[u8] = rodata
        .get(dex_start..header_end)
        .ok_or_else(|| out_of_range(header_end))?;
    if header[..4] != crate::dex::DEX_MAGIC_PREFIX {
        return Err(out_of_range(dex_start));
    }
    let file_size: u32 = read_u32_at(rodata, dex_start + DEX_HEADER_FILE_SIZE_OFFSET)
        .ok_or_else(|| out_of_range(dex_start + DEX_HEADER_FILE_SIZE_OFFSET))?;
    if (file_size as usize) < DEX_HEADER_MIN || file_size as usize > MAX_OAT_DEX_BYTES {
        return Err(out_of_range(dex_start));
    }
    let dex_end: usize = dex_start
        .checked_add(file_size as usize)
        .ok_or_else(|| out_of_range(usize::MAX))?;
    rodata
        .get(dex_start..dex_end)
        .ok_or_else(|| out_of_range(dex_end))
}

pub fn extract_oat_dex(elf_bytes: &[u8]) -> Result<Vec<OatEmbeddedDex>> {
    let oat_off: usize = locate_oat_region(elf_bytes)?;
    let rodata: &[u8] = &elf_bytes[oat_off..];
    if rodata.len() < OAT_HEADER_FIXED_SIZE {
        return Err(Error::Truncated {
            offset: 0,
            needed: OAT_HEADER_FIXED_SIZE,
            had: rodata.len(),
        });
    }
    let magic: [u8; 4] = [rodata[0], rodata[1], rodata[2], rodata[3]];
    if magic != OAT_MAGIC {
        return Err(Error::BadOatMagic(magic));
    }
    let raw_version: [u8; 4] = [rodata[4], rodata[5], rodata[6], rodata[7]];
    if OatVersion::from_ascii(raw_version).is_none() {
        return Err(Error::UnsupportedOatVersion(raw_version));
    }
    let dex_file_count: u32 = read_header_u32(rodata, 20)?;
    if dex_file_count == 0 {
        return Ok(Vec::new());
    }
    if dex_file_count > 1 {
        return Err(Error::OatMultiDexUnsupported {
            count: dex_file_count,
        });
    }
    let oat_dex_files_offset: u32 = read_header_u32(rodata, 24)?;
    if (oat_dex_files_offset as usize) < OAT_HEADER_FIXED_SIZE {
        return Err(Error::OatOffsetOutOfRange {
            offset: oat_dex_files_offset as usize,
            size: rodata.len(),
        });
    }
    let (location, location_checksum, dex_file_offset): (String, u32, usize) =
        read_oat_dex_file_entry(rodata, oat_dex_files_offset as usize)?;
    let dex_bytes: &[u8] = slice_embedded_dex(rodata, dex_file_offset)?;
    Ok(vec![OatEmbeddedDex {
        location,
        location_checksum,
        bytes: dex_bytes.to_vec(),
    }])
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

    fn build_header(dex_count: u32, iset: i32, kv: &[u8], oat_dex_files_offset: u32) -> Vec<u8> {
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&OAT_MAGIC);
        b.extend_from_slice(b"170\0");
        b.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        b.extend_from_slice(&iset.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&dex_count.to_le_bytes());
        b.extend_from_slice(&oat_dex_files_offset.to_le_bytes());
        for _ in 0..6 {
            b.extend_from_slice(&0u32.to_le_bytes());
        }
        b.extend_from_slice(&(kv.len() as u32).to_le_bytes());
        b.extend_from_slice(kv);
        b
    }

    #[test]
    fn oat_header_decodes_fields() {
        let kv: &[u8] = b"compiler-filter\0speed\0";
        let offset: u32 = OAT_HEADER_FIXED_SIZE as u32 + kv.len() as u32;
        let h: OatHeader = parse_oat_header(&build_header(3, 2, kv, offset)).expect("oat header");
        assert_eq!(h.dex_file_count, 3);
        assert_eq!(h.instruction_set, InstructionSet::Arm64);
        assert_eq!(h.adler32_checksum, 0xDEAD_BEEF);
        assert_eq!(h.version.digits(), 170);
        assert_eq!(h.oat_dex_files_offset, offset);
        assert!(
            h.key_value_store
                .iter()
                .any(|(k, v): &(String, String)| k == "compiler-filter" && v == "speed")
        );
    }

    #[test]
    fn oat_rejects_bad_magic() {
        let err: Error = parse_oat_header(&[0u8; 64]).expect_err("bad magic");
        assert!(matches!(err, Error::BadOatMagic(_)));
    }

    #[test]
    fn oat_rejects_truncated() {
        let err: Error = parse_oat_header(&[0u8; 8]).expect_err("truncated");
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn oat_rejects_dex_files_offset_inside_fixed_header() {
        let err: Error =
            parse_oat_header(&build_header(1, 2, b"", 10)).expect_err("offset too small");
        assert!(matches!(err, Error::OatOffsetOutOfRange { .. }));
    }

    fn build_oat_elf(rodata: &[u8]) -> Vec<u8> {
        use object::write::{Object, StandardSection, Symbol, SymbolFlags, SymbolSection};
        use object::{Architecture, BinaryFormat, Endianness, SymbolKind, SymbolScope};
        let mut obj: Object<'_> =
            Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
        let sec: object::write::SectionId = obj.section_id(StandardSection::ReadOnlyData);
        let off: u64 = obj.append_section_data(sec, rodata, 16);
        obj.add_symbol(Symbol {
            name: b"oatdata".to_vec(),
            value: off,
            size: rodata.len() as u64,
            kind: SymbolKind::Data,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(sec),
            flags: SymbolFlags::None,
        });
        obj.write().expect("elf write")
    }

    fn build_min_dex(extra_padding: usize) -> Vec<u8> {
        let mut b: Vec<u8> = vec![0u8; DEX_HEADER_MIN + extra_padding];
        b[..4].copy_from_slice(b"dex\n");
        b[4..8].copy_from_slice(b"035\0");
        let total_len: u32 = b.len() as u32;
        b[DEX_HEADER_FILE_SIZE_OFFSET..DEX_HEADER_FILE_SIZE_OFFSET + 4]
            .copy_from_slice(&total_len.to_le_bytes());
        b[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        b
    }

    fn build_single_dex_rodata(location: &str, dex_bytes: &[u8]) -> Vec<u8> {
        let entry_off: u32 = OAT_HEADER_FIXED_SIZE as u32;
        let mut entry: Vec<u8> = Vec::new();
        entry.extend_from_slice(&(location.len() as u32).to_le_bytes());
        entry.extend_from_slice(location.as_bytes());
        entry.extend_from_slice(&0x5EED_5EEDu32.to_le_bytes());
        let dex_file_offset: u32 = entry_off + entry.len() as u32 + 4;
        entry.extend_from_slice(&dex_file_offset.to_le_bytes());
        let mut rodata: Vec<u8> = build_header(1, 2, b"", entry_off);
        rodata.extend_from_slice(&entry);
        rodata.extend_from_slice(dex_bytes);
        rodata
    }

    #[test]
    fn extract_oat_dex_locates_the_embedded_dex_and_matches_its_declared_file_size() {
        let dex: Vec<u8> = build_min_dex(16);
        let rodata: Vec<u8> = build_single_dex_rodata("base.apk!classes.dex", &dex);
        let elf: Vec<u8> = build_oat_elf(&rodata);
        let extracted: Vec<OatEmbeddedDex> = extract_oat_dex(&elf).expect("extract oat dex");
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].location, "base.apk!classes.dex");
        assert_eq!(extracted[0].location_checksum, 0x5EED_5EED);
        assert_eq!(extracted[0].bytes, dex);
        let redecoded: DexFile = parse_dex(&extracted[0].bytes).expect("extracted bytes parse");
        assert_eq!(redecoded.header.file_size as usize, dex.len());
    }

    #[test]
    fn extract_oat_dex_reports_zero_dex_files_as_empty() {
        let rodata: Vec<u8> = build_header(0, 2, b"", OAT_HEADER_FIXED_SIZE as u32 + 4);
        let elf: Vec<u8> = build_oat_elf(&rodata);
        let extracted: Vec<OatEmbeddedDex> = extract_oat_dex(&elf).expect("zero dex files");
        assert!(extracted.is_empty());
    }

    #[test]
    fn extract_oat_dex_sound_rejects_multi_dex_rather_than_guessing_the_stride() {
        let rodata: Vec<u8> = build_header(2, 2, b"", OAT_HEADER_FIXED_SIZE as u32 + 4);
        let elf: Vec<u8> = build_oat_elf(&rodata);
        let err: Error = extract_oat_dex(&elf).expect_err("multi-dex must sound-reject");
        assert!(matches!(err, Error::OatMultiDexUnsupported { count: 2 }));
    }

    #[test]
    fn extract_oat_dex_rejects_a_dex_file_offset_that_does_not_point_at_dex_magic() {
        let entry_off: u32 = OAT_HEADER_FIXED_SIZE as u32;
        let mut entry: Vec<u8> = Vec::new();
        entry.extend_from_slice(&0u32.to_le_bytes());
        entry.extend_from_slice(&0x1111_1111u32.to_le_bytes());
        let dex_file_offset: u32 = entry_off + entry.len() as u32 + 4;
        entry.extend_from_slice(&dex_file_offset.to_le_bytes());
        let mut rodata: Vec<u8> = build_header(1, 2, b"", entry_off);
        rodata.extend_from_slice(&entry);
        rodata.extend_from_slice(&[0u8; DEX_HEADER_MIN]);
        let elf: Vec<u8> = build_oat_elf(&rodata);
        let err: Error = extract_oat_dex(&elf).expect_err("bogus dex magic");
        assert!(matches!(err, Error::OatOffsetOutOfRange { .. }));
    }

    #[test]
    fn extract_oat_dex_rejects_a_dex_file_offset_past_the_blob() {
        let entry_off: u32 = OAT_HEADER_FIXED_SIZE as u32;
        let mut entry: Vec<u8> = Vec::new();
        entry.extend_from_slice(&0u32.to_le_bytes());
        entry.extend_from_slice(&0x1111_1111u32.to_le_bytes());
        entry.extend_from_slice(&999_999u32.to_le_bytes());
        let mut rodata: Vec<u8> = build_header(1, 2, b"", entry_off);
        rodata.extend_from_slice(&entry);
        let elf: Vec<u8> = build_oat_elf(&rodata);
        let err: Error = extract_oat_dex(&elf).expect_err("dex_file_offset past the blob");
        assert!(matches!(err, Error::OatOffsetOutOfRange { .. }));
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
