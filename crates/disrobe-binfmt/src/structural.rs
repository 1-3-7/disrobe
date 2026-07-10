use disrobe_bytes::read_uleb128_at;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructuralFormat {
    Pe,
    Elf,
    MachO,
    MachOFat,
    Wasm,
    Zip,
    Dex,
    JavaClass,
}

impl StructuralFormat {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pe => "pe",
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::MachOFat => "macho-fat",
            Self::Wasm => "wasm",
            Self::Zip => "zip",
            Self::Dex => "dex",
            Self::JavaClass => "java-class",
        }
    }
}

const DOS_E_LFANEW_OFFSET: usize = 0x3C;
const PE_SIGNATURE: &[u8; 4] = b"PE\x00\x00";
const COFF_HEADER_SIZE: usize = 20;
const OPT_MAGIC_PE32: u16 = 0x010B;
const OPT_MAGIC_PE32_PLUS: u16 = 0x020B;
const SECTION_ENTRY_SIZE: usize = 40;
const MAX_PE_SECTIONS: usize = 96;

const KNOWN_COFF_MACHINES: &[u16] = &[
    0x014C, 0x0162, 0x0166, 0x0168, 0x0169, 0x0184, 0x01A2, 0x01A3, 0x01A4, 0x01A6, 0x01C0, 0x01C2,
    0x01C4, 0x01D3, 0x01F0, 0x01F1, 0x0200, 0x0266, 0x0284, 0x0366, 0x0466, 0x0520, 0x0CEF, 0x0EBC,
    0x5032, 0x5064, 0x5128, 0x6232, 0x6264, 0x8664, 0x9041, 0xAA64, 0xA641, 0xA64E, 0xC0EE,
];

const ELF_HEADER_MIN: usize = 0x40;
const ELF_PROGRAM_ENTRY_32: u64 = 32;
const ELF_PROGRAM_ENTRY_64: u64 = 56;
const ELF_SECTION_ENTRY_32: u64 = 40;
const ELF_SECTION_ENTRY_64: u64 = 64;

const MACHO_HEADER_MIN: usize = 28;
const MACHO_MAGIC_64_LE: u32 = 0xFEED_FACF;
const MACHO_MAGIC_64_BE: u32 = 0xCFFA_EDFE;
const MACHO_MAGIC_32_LE: u32 = 0xFEED_FACE;
const MACHO_MAGIC_32_BE: u32 = 0xCEFA_EDFE;
const MACHO_MAX_LOAD_COMMANDS: u32 = 4096;
const MACHO_LC_MIN: u32 = 8;

const ZIP_EOCD_SIGNATURE: u32 = 0x0605_4B50;
const ZIP_CDH_SIGNATURE: u32 = 0x0201_4B50;
const ZIP_EOCD_FIXED_LEN: usize = 22;
const ZIP_MAX_COMMENT: usize = 0xFFFF;
const ZIP_SEARCH_BUDGET: usize = ZIP_MAX_COMMENT + ZIP_EOCD_FIXED_LEN + 4;

const DEX_HEADER_MIN: usize = 0x70;
const DEX_HEADER_SIZE: u32 = 0x70;
const DEX_ENDIAN_TAG: u32 = 0x1234_5678;
const DEX_ENDIAN_TAG_REVERSE: u32 = 0x7856_3412;

const CLASS_MIN: usize = 24;
const CLASS_MIN_MAJOR: u16 = 45;
const CLASS_MAX_MAJOR: u16 = 80;
const CLASS_CP_TAGS: &[u8] = &[1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19, 20];

const WASM_VERSION_1: u32 = 1;
const WASM_MAX_SECTION_ID: u8 = 13;
const WASM_MAX_SECTIONS: u32 = 1024;

#[inline]
fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    let slice: &[u8] = bytes.get(off..off + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

#[inline]
fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let slice: &[u8] = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[inline]
fn read_u32_be(bytes: &[u8], off: usize) -> Option<u32> {
    let slice: &[u8] = bytes.get(off..off + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[inline]
fn read_u16_be(bytes: &[u8], off: usize) -> Option<u16> {
    let slice: &[u8] = bytes.get(off..off + 2)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

#[inline]
fn read_u64(bytes: &[u8], off: usize, little: bool) -> Option<u64> {
    let slice: &[u8] = bytes.get(off..off + 8)?;
    let mut arr: [u8; 8] = [0u8; 8];
    arr.copy_from_slice(slice);
    Some(if little {
        u64::from_le_bytes(arr)
    } else {
        u64::from_be_bytes(arr)
    })
}

#[inline]
fn read_u32(bytes: &[u8], off: usize, little: bool) -> Option<u32> {
    if little {
        read_u32_le(bytes, off)
    } else {
        read_u32_be(bytes, off)
    }
}

#[inline]
fn read_u16(bytes: &[u8], off: usize, little: bool) -> Option<u16> {
    if little {
        read_u16_le(bytes, off)
    } else {
        read_u16_be(bytes, off)
    }
}

#[must_use]
pub fn identify_by_structure(bytes: &[u8]) -> Option<StructuralFormat> {
    if validate_elf(bytes) {
        return Some(StructuralFormat::Elf);
    }
    if validate_macho_fat(bytes) {
        return Some(StructuralFormat::MachOFat);
    }
    if validate_macho(bytes) {
        return Some(StructuralFormat::MachO);
    }
    if validate_wasm(bytes) {
        return Some(StructuralFormat::Wasm);
    }
    if validate_dex(bytes) {
        return Some(StructuralFormat::Dex);
    }
    if validate_java_class(bytes) {
        return Some(StructuralFormat::JavaClass);
    }
    if validate_zip(bytes) {
        return Some(StructuralFormat::Zip);
    }
    if validate_pe(bytes) {
        return Some(StructuralFormat::Pe);
    }
    None
}

#[must_use]
pub fn validate_pe(bytes: &[u8]) -> bool {
    locate_pe_header(bytes).is_some()
}

#[must_use]
pub fn locate_pe_header(bytes: &[u8]) -> Option<usize> {
    if let Some(e_lfanew) = read_u32_le(bytes, DOS_E_LFANEW_OFFSET)
        && pe_header_is_valid(bytes, e_lfanew as usize)
    {
        return Some(e_lfanew as usize);
    }
    let scan_limit: usize = bytes.len().min(4096);
    let mut off: usize = 0;
    while off + 4 <= scan_limit {
        if bytes.get(off..off + 4) == Some(PE_SIGNATURE.as_slice())
            && pe_header_is_valid(bytes, off)
        {
            return Some(off);
        }
        off += 1;
    }
    None
}

fn pe_header_is_valid(bytes: &[u8], pe_off: usize) -> bool {
    if bytes.get(pe_off..pe_off + 4) != Some(PE_SIGNATURE.as_slice()) {
        return false;
    }
    let Some(coff_off): Option<usize> = pe_off.checked_add(4) else {
        return false;
    };
    if coff_off + COFF_HEADER_SIZE > bytes.len() {
        return false;
    }
    let Some(machine): Option<u16> = read_u16_le(bytes, coff_off) else {
        return false;
    };
    if !KNOWN_COFF_MACHINES.contains(&machine) {
        return false;
    }
    let Some(n_sections_raw): Option<u16> = read_u16_le(bytes, coff_off + 2) else {
        return false;
    };
    let n_sections: usize = n_sections_raw as usize;
    if n_sections == 0 || n_sections > MAX_PE_SECTIONS {
        return false;
    }
    let Some(opt_size): Option<u16> = read_u16_le(bytes, coff_off + 16) else {
        return false;
    };
    let opt_hdr_off: usize = coff_off + COFF_HEADER_SIZE;
    let Some(opt_magic): Option<u16> = read_u16_le(bytes, opt_hdr_off) else {
        return false;
    };
    if opt_magic != OPT_MAGIC_PE32 && opt_magic != OPT_MAGIC_PE32_PLUS {
        return false;
    }
    let Some(sec_table_off): Option<usize> = opt_hdr_off.checked_add(opt_size as usize) else {
        return false;
    };
    let Some(table_bytes): Option<usize> = n_sections.checked_mul(SECTION_ENTRY_SIZE) else {
        return false;
    };
    let Some(needed): Option<usize> = sec_table_off.checked_add(table_bytes) else {
        return false;
    };
    needed <= bytes.len()
}

#[must_use]
pub fn validate_elf(bytes: &[u8]) -> bool {
    if bytes.len() < ELF_HEADER_MIN {
        return false;
    }
    let Some(&ei_class): Option<&u8> = bytes.get(4) else {
        return false;
    };
    let Some(&ei_data): Option<&u8> = bytes.get(5) else {
        return false;
    };
    let is_64: bool = match ei_class {
        1 => false,
        2 => true,
        _ => return false,
    };
    let little: bool = match ei_data {
        1 => true,
        2 => false,
        _ => return false,
    };
    let Some(&ei_version): Option<&u8> = bytes.get(6) else {
        return false;
    };
    if ei_version != 1 {
        return false;
    }
    let Some(e_type): Option<u16> = read_u16(bytes, 16, little) else {
        return false;
    };
    if e_type > 4 && !(0xFE00..=0xFFFF).contains(&e_type) {
        return false;
    }
    let Some(t): Option<ElfTables> = elf_tables(bytes, is_64, little) else {
        return false;
    };
    let expected_ph: u64 = if is_64 {
        ELF_PROGRAM_ENTRY_64
    } else {
        ELF_PROGRAM_ENTRY_32
    };
    let expected_sh: u64 = if is_64 {
        ELF_SECTION_ENTRY_64
    } else {
        ELF_SECTION_ENTRY_32
    };
    let len: u64 = bytes.len() as u64;
    let mut tables_seen: u32 = 0;
    if t.phnum != 0 {
        if u64::from(t.phentsize) != expected_ph {
            return false;
        }
        let Some(span): Option<u64> = u64::from(t.phnum).checked_mul(u64::from(t.phentsize)) else {
            return false;
        };
        let Some(end): Option<u64> = t.phoff.checked_add(span) else {
            return false;
        };
        if t.phoff < ELF_HEADER_MIN as u64 || end > len {
            return false;
        }
        tables_seen += 1;
    }
    if t.shnum != 0 {
        if u64::from(t.shentsize) != expected_sh {
            return false;
        }
        let Some(span): Option<u64> = u64::from(t.shnum).checked_mul(u64::from(t.shentsize)) else {
            return false;
        };
        let Some(end): Option<u64> = t.shoff.checked_add(span) else {
            return false;
        };
        if t.shoff < ELF_HEADER_MIN as u64 || end > len {
            return false;
        }
        tables_seen += 1;
    }
    tables_seen > 0
}

#[derive(Debug, Clone, Copy)]
struct ElfTables {
    phoff: u64,
    shoff: u64,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
}

fn elf_tables(bytes: &[u8], is_64: bool, little: bool) -> Option<ElfTables> {
    if is_64 {
        Some(ElfTables {
            phoff: read_u64(bytes, 32, little)?,
            shoff: read_u64(bytes, 40, little)?,
            phentsize: read_u16(bytes, 54, little)?,
            phnum: read_u16(bytes, 56, little)?,
            shentsize: read_u16(bytes, 58, little)?,
            shnum: read_u16(bytes, 60, little)?,
        })
    } else {
        Some(ElfTables {
            phoff: u64::from(read_u32(bytes, 28, little)?),
            shoff: u64::from(read_u32(bytes, 32, little)?),
            phentsize: read_u16(bytes, 42, little)?,
            phnum: read_u16(bytes, 44, little)?,
            shentsize: read_u16(bytes, 46, little)?,
            shnum: read_u16(bytes, 48, little)?,
        })
    }
}

#[must_use]
pub fn validate_macho(bytes: &[u8]) -> bool {
    if bytes.len() < MACHO_HEADER_MIN {
        return false;
    }
    let Some(raw_le): Option<u32> = read_u32_le(bytes, 0) else {
        return false;
    };
    let little: bool = match raw_le {
        MACHO_MAGIC_64_LE | MACHO_MAGIC_32_LE => true,
        MACHO_MAGIC_64_BE | MACHO_MAGIC_32_BE => false,
        _ => return macho_loadcmds_walk(bytes, true) || macho_loadcmds_walk(bytes, false),
    };
    let is_64: bool = matches!(raw_le, MACHO_MAGIC_64_LE | MACHO_MAGIC_64_BE);
    macho_header_walk(bytes, little, is_64)
}

fn macho_loadcmds_walk(bytes: &[u8], little: bool) -> bool {
    macho_header_walk(bytes, little, true) || macho_header_walk(bytes, little, false)
}

fn macho_header_walk(bytes: &[u8], little: bool, is_64: bool) -> bool {
    let Some(cputype): Option<u32> = read_u32(bytes, 4, little) else {
        return false;
    };
    let cpu_is_64_flag: bool = (cputype & 0x0100_0000) != 0;
    if cpu_is_64_flag != is_64 {
        return false;
    }
    let Some(ncmds): Option<u32> = read_u32(bytes, 16, little) else {
        return false;
    };
    let Some(sizeofcmds): Option<u32> = read_u32(bytes, 20, little) else {
        return false;
    };
    if ncmds == 0 || ncmds > MACHO_MAX_LOAD_COMMANDS {
        return false;
    }
    let header_len: usize = if is_64 { 32 } else { 28 };
    let Some(total): Option<usize> = header_len.checked_add(sizeofcmds as usize) else {
        return false;
    };
    if total > bytes.len() {
        return false;
    }
    let mut cursor: usize = header_len;
    let mut walked: u32 = 0;
    while walked < ncmds {
        let Some(cmdsize): Option<u32> = read_u32(bytes, cursor + 4, little) else {
            return false;
        };
        if cmdsize < MACHO_LC_MIN || (cmdsize % 4) != 0 {
            return false;
        }
        let Some(next): Option<usize> = cursor.checked_add(cmdsize as usize) else {
            return false;
        };
        cursor = next;
        if cursor > total {
            return false;
        }
        walked += 1;
    }
    cursor == total
}

#[must_use]
pub fn validate_macho_fat(bytes: &[u8]) -> bool {
    let Some(nfat): Option<u32> = read_u32_be(bytes, 4) else {
        return false;
    };
    if nfat == 0 || nfat > 32 {
        return false;
    }
    let len: u64 = bytes.len() as u64;
    let mut entry: usize = 8;
    for _ in 0..nfat {
        let Some(offset): Option<u32> = read_u32_be(bytes, entry + 8) else {
            return false;
        };
        let Some(size): Option<u32> = read_u32_be(bytes, entry + 12) else {
            return false;
        };
        let Some(end): Option<u64> = u64::from(offset).checked_add(u64::from(size)) else {
            return false;
        };
        if u64::from(offset) < 8 || end > len {
            return false;
        }
        let Some(next): Option<usize> = entry.checked_add(20) else {
            return false;
        };
        entry = next;
    }
    true
}

#[must_use]
pub fn validate_wasm(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let Some(version): Option<u32> = read_u32_le(bytes, 4) else {
        return false;
    };
    if version != WASM_VERSION_1 {
        return false;
    }
    let mut cursor: usize = 8;
    let mut sections: u32 = 0;
    while cursor < bytes.len() {
        let Some(&id): Option<&u8> = bytes.get(cursor) else {
            return false;
        };
        if id > WASM_MAX_SECTION_ID {
            return false;
        }
        cursor += 1;
        let Some((payload_len, consumed)): Option<(u64, usize)> =
            read_uleb128_at(bytes, cursor).ok()
        else {
            return false;
        };
        cursor += consumed;
        let Some(end): Option<usize> = cursor.checked_add(payload_len as usize) else {
            return false;
        };
        if end > bytes.len() {
            return false;
        }
        cursor = end;
        sections += 1;
        if sections > WASM_MAX_SECTIONS {
            return false;
        }
    }
    cursor == bytes.len() && sections > 0
}

#[must_use]
pub fn validate_dex(bytes: &[u8]) -> bool {
    if bytes.len() < DEX_HEADER_MIN {
        return false;
    }
    let Some(header_size): Option<u32> = read_u32_le(bytes, 36) else {
        return false;
    };
    if header_size != DEX_HEADER_SIZE {
        return false;
    }
    let Some(endian_tag): Option<u32> = read_u32_le(bytes, 40) else {
        return false;
    };
    let little: bool = match endian_tag {
        DEX_ENDIAN_TAG => true,
        DEX_ENDIAN_TAG_REVERSE => false,
        _ => return false,
    };
    let Some(file_size): Option<u32> = read_u32(bytes, 32, little) else {
        return false;
    };
    let actual: u64 = bytes.len() as u64;
    if u64::from(file_size) > actual {
        return false;
    }
    let section_specs: [(usize, usize); 5] = [(56, 60), (64, 68), (72, 76), (88, 92), (96, 100)];
    let mut consistent: u32 = 0;
    for (size_off, off_off) in section_specs {
        let Some(size): Option<u32> = read_u32(bytes, size_off, little) else {
            return false;
        };
        let Some(off): Option<u32> = read_u32(bytes, off_off, little) else {
            return false;
        };
        if size == 0 {
            if off != 0 {
                return false;
            }
            continue;
        }
        if u64::from(off) >= actual || u64::from(off) < u64::from(DEX_HEADER_SIZE) {
            return false;
        }
        consistent += 1;
    }
    consistent > 0
}

#[must_use]
pub fn validate_java_class(bytes: &[u8]) -> bool {
    if bytes.len() < CLASS_MIN {
        return false;
    }
    let Some(major): Option<u16> = read_u16_be(bytes, 6) else {
        return false;
    };
    if !(CLASS_MIN_MAJOR..=CLASS_MAX_MAJOR).contains(&major) {
        return false;
    }
    let Some(cp_count): Option<u16> = read_u16_be(bytes, 8) else {
        return false;
    };
    if cp_count < 2 {
        return false;
    }
    let mut cursor: usize = 10;
    let mut index: u16 = 1;
    while index < cp_count {
        let Some(&tag): Option<&u8> = bytes.get(cursor) else {
            return false;
        };
        if !CLASS_CP_TAGS.contains(&tag) {
            return false;
        }
        cursor += 1;
        let advance: usize = match tag {
            1 => {
                let Some(len): Option<u16> = read_u16_be(bytes, cursor) else {
                    return false;
                };
                2 + len as usize
            }
            7 | 8 | 16 | 19 | 20 => 2,
            15 => 3,
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => 4,
            5 | 6 => 8,
            _ => return false,
        };
        let Some(next): Option<usize> = cursor.checked_add(advance) else {
            return false;
        };
        cursor = next;
        if cursor > bytes.len() {
            return false;
        }
        index += if matches!(tag, 5 | 6) { 2 } else { 1 };
    }
    read_u16_be(bytes, cursor).is_some()
}

#[must_use]
pub fn validate_zip(bytes: &[u8]) -> bool {
    locate_zip_central_directory(bytes).is_some()
}

#[must_use]
pub fn locate_zip_central_directory(bytes: &[u8]) -> Option<usize> {
    let eocd: usize = find_eocd(bytes)?;
    let cd_size: u32 = read_u32_le(bytes, eocd + 12)?;
    let cd_off_raw: u32 = read_u32_le(bytes, eocd + 16)?;
    let cd_off: usize = cd_off_raw as usize;
    let cd_size: usize = cd_size as usize;
    let cd_end: usize = cd_off.checked_add(cd_size)?;
    if cd_end > bytes.len() || cd_off > eocd {
        return None;
    }
    if cd_size == 0 {
        return Some(cd_off);
    }
    if read_u32_le(bytes, cd_off)? != ZIP_CDH_SIGNATURE {
        return None;
    }
    Some(cd_off)
}

fn find_eocd(bytes: &[u8]) -> Option<usize> {
    let len: usize = bytes.len();
    if len < ZIP_EOCD_FIXED_LEN {
        return None;
    }
    let start: usize = len.saturating_sub(ZIP_SEARCH_BUDGET);
    let mut off: usize = len - ZIP_EOCD_FIXED_LEN;
    while off >= start {
        if read_u32_le(bytes, off) == Some(ZIP_EOCD_SIGNATURE) {
            return Some(off);
        }
        if off == 0 {
            break;
        }
        off -= 1;
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_tiny_inputs_never_panic_and_yield_none() {
        for n in 0usize..40 {
            let buf: Vec<u8> = vec![0u8; n];
            assert!(identify_by_structure(&buf).is_none());
        }
        let one: Vec<u8> = vec![0xFFu8; 1];
        assert!(identify_by_structure(&one).is_none());
    }

    #[test]
    fn random_high_entropy_is_not_a_false_positive() {
        let buf: Vec<u8> = (0..4096u32)
            .map(|i: u32| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        assert_eq!(identify_by_structure(&buf), None);
    }

    fn synthetic_pe() -> Vec<u8> {
        let opt_size: usize = 0xE0;
        let sec_table: usize = 0x80 + 4 + COFF_HEADER_SIZE + opt_size;
        let total: usize = sec_table + SECTION_ENTRY_SIZE + 0x200;
        let mut buf: Vec<u8> = vec![0u8; total];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[DOS_E_LFANEW_OFFSET..DOS_E_LFANEW_OFFSET + 4].copy_from_slice(&0x80u32.to_le_bytes());
        let pe_off: usize = 0x80;
        buf[pe_off..pe_off + 4].copy_from_slice(PE_SIGNATURE);
        let coff: usize = pe_off + 4;
        buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt: usize = coff + COFF_HEADER_SIZE;
        buf[opt..opt + 2].copy_from_slice(&OPT_MAGIC_PE32_PLUS.to_le_bytes());
        buf
    }

    #[test]
    fn pe_validates_with_flipped_dos_magic() {
        let mut buf: Vec<u8> = synthetic_pe();
        buf[0] = 0x00;
        buf[1] = 0x00;
        assert_eq!(identify_by_structure(&buf), Some(StructuralFormat::Pe));
        assert!(validate_pe(&buf));
    }

    #[test]
    fn pe_locates_header_when_e_lfanew_is_corrupt() {
        let mut buf: Vec<u8> = synthetic_pe();
        buf[DOS_E_LFANEW_OFFSET..DOS_E_LFANEW_OFFSET + 4]
            .copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert_eq!(locate_pe_header(&buf), Some(0x80));
    }

    #[test]
    fn pe_rejects_bogus_machine() {
        let mut buf: Vec<u8> = synthetic_pe();
        let coff: usize = 0x80 + 4;
        buf[coff..coff + 2].copy_from_slice(&0xABCDu16.to_le_bytes());
        buf[DOS_E_LFANEW_OFFSET..DOS_E_LFANEW_OFFSET + 4].copy_from_slice(&0x80u32.to_le_bytes());
        assert!(!validate_pe(&buf));
    }

    fn synthetic_elf64() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 0x200];
        buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        buf[4] = 2;
        buf[5] = 1;
        buf[6] = 1;
        buf[16..18].copy_from_slice(&2u16.to_le_bytes());
        buf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        buf[32..40].copy_from_slice(&64u64.to_le_bytes());
        buf[40..48].copy_from_slice(&0u64.to_le_bytes());
        buf[54..56].copy_from_slice(&(ELF_PROGRAM_ENTRY_64 as u16).to_le_bytes());
        buf[56..58].copy_from_slice(&2u16.to_le_bytes());
        buf
    }

    #[test]
    fn elf_validates_with_zeroed_magic() {
        let mut buf: Vec<u8> = synthetic_elf64();
        buf[0..4].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(identify_by_structure(&buf), Some(StructuralFormat::Elf));
    }

    #[test]
    fn elf_rejects_inconsistent_phentsize() {
        let mut buf: Vec<u8> = synthetic_elf64();
        buf[54..56].copy_from_slice(&7u16.to_le_bytes());
        assert!(!validate_elf(&buf));
    }

    #[test]
    fn elf_rejects_phoff_past_eof() {
        let mut buf: Vec<u8> = synthetic_elf64();
        buf[32..40].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes());
        assert!(!validate_elf(&buf));
    }

    fn synthetic_macho64() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 64];
        buf[0..4].copy_from_slice(&MACHO_MAGIC_64_LE.to_le_bytes());
        buf[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        buf[16..20].copy_from_slice(&1u32.to_le_bytes());
        buf[20..24].copy_from_slice(&16u32.to_le_bytes());
        let lc: usize = 32;
        buf[lc..lc + 4].copy_from_slice(&0x19u32.to_le_bytes());
        buf[lc + 4..lc + 8].copy_from_slice(&16u32.to_le_bytes());
        buf
    }

    #[test]
    fn macho_validates_with_scrambled_magic() {
        let mut buf: Vec<u8> = synthetic_macho64();
        buf[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(identify_by_structure(&buf), Some(StructuralFormat::MachO));
    }

    #[test]
    fn macho_rejects_oversized_ncmds() {
        let mut buf: Vec<u8> = synthetic_macho64();
        buf[16..20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(!validate_macho(&buf));
    }

    fn synthetic_wasm() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6D];
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.push(1);
        buf.push(4);
        buf.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        buf
    }

    #[test]
    fn wasm_validates_with_scrambled_magic() {
        let mut buf: Vec<u8> = synthetic_wasm();
        buf[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(identify_by_structure(&buf), Some(StructuralFormat::Wasm));
    }

    #[test]
    fn wasm_rejects_section_overrun() {
        let mut buf: Vec<u8> = synthetic_wasm();
        buf[9] = 0x7F;
        assert!(!validate_wasm(&buf));
    }

    fn synthetic_dex() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 0x200];
        buf[0..8].copy_from_slice(b"dex\n035\0");
        buf[32..36].copy_from_slice(&0x200u32.to_le_bytes());
        buf[36..40].copy_from_slice(&DEX_HEADER_SIZE.to_le_bytes());
        buf[40..44].copy_from_slice(&DEX_ENDIAN_TAG.to_le_bytes());
        buf[56..60].copy_from_slice(&3u32.to_le_bytes());
        buf[60..64].copy_from_slice(&0x70u32.to_le_bytes());
        buf
    }

    #[test]
    fn dex_validates_with_zeroed_magic() {
        let mut buf: Vec<u8> = synthetic_dex();
        buf[0..8].copy_from_slice(&[0u8; 8]);
        assert_eq!(identify_by_structure(&buf), Some(StructuralFormat::Dex));
    }

    #[test]
    fn dex_rejects_wrong_header_size() {
        let mut buf: Vec<u8> = synthetic_dex();
        buf[36..40].copy_from_slice(&0x80u32.to_le_bytes());
        assert!(!validate_dex(&buf));
    }

    fn synthetic_class() -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&52u16.to_be_bytes());
        buf.extend_from_slice(&3u16.to_be_bytes());
        buf.push(7);
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.push(1);
        buf.extend_from_slice(&3u16.to_be_bytes());
        buf.extend_from_slice(b"Foo");
        buf.extend_from_slice(&0x0021u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        buf
    }

    #[test]
    fn class_validates_with_scrambled_magic() {
        let mut buf: Vec<u8> = synthetic_class();
        buf[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            identify_by_structure(&buf),
            Some(StructuralFormat::JavaClass)
        );
    }

    #[test]
    fn class_rejects_out_of_range_major() {
        let mut buf: Vec<u8> = synthetic_class();
        buf[6..8].copy_from_slice(&200u16.to_be_bytes());
        assert!(!validate_java_class(&buf));
    }

    fn synthetic_zip() -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"PK\x03\x04");
        buf.extend_from_slice(&[0u8; 26]);
        let cd_off: u32 = buf.len() as u32;
        buf.extend_from_slice(&ZIP_CDH_SIGNATURE.to_le_bytes());
        buf.extend_from_slice(&[0u8; 42]);
        let cd_size: u32 = buf.len() as u32 - cd_off;
        buf.extend_from_slice(&ZIP_EOCD_SIGNATURE.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&cd_size.to_le_bytes());
        buf.extend_from_slice(&cd_off.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf
    }

    #[test]
    fn zip_validates_with_scrambled_local_header() {
        let mut buf: Vec<u8> = synthetic_zip();
        buf[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(identify_by_structure(&buf), Some(StructuralFormat::Zip));
    }

    #[test]
    fn zip_rejects_cd_offset_past_eof() {
        let mut buf: Vec<u8> = synthetic_zip();
        let eocd: usize = find_eocd(&buf).expect("eocd");
        buf[eocd + 16..eocd + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(!validate_zip(&buf));
    }
}
