use serde::{Deserialize, Serialize};

use crate::native_image::{NativeImage, parse_native_image};

const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;

#[cfg(test)]
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_SONAME: u64 = 14;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6FFF_FFFB;

const DF_BIND_NOW: u64 = 0x0000_0008;
const DF_1_NOW: u64 = 0x0000_0001;
const DF_1_PIE: u64 = 0x0800_0000;

const E_PHOFF_64: usize = 0x20;
const E_PHENTSIZE_64: usize = 0x36;
const E_PHNUM_64: usize = 0x38;
const E_PHOFF_32: usize = 0x1C;
const E_PHENTSIZE_32: usize = 0x2A;
const E_PHNUM_32: usize = 0x2C;
const ELF_HEADER_MIN: usize = 0x34;

const DYN_ENTRY_64: usize = 16;
const DYN_ENTRY_32: usize = 8;

const MAX_PROGRAM_HEADERS: usize = 0x1_0000;
const MAX_DYNAMIC_ENTRIES: usize = 0x10_0000;
const MAX_DT_STRSZ: u64 = 0x100_0000;
const MAX_STRING_LEN: usize = 0x1_0000;
const MAX_NEEDED: usize = 0x1_0000;
const MAX_DYNAMIC_STRING_OUTPUT: usize = 0x100_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElfDynamic {
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub bind_now: bool,
    pub pie: bool,
    pub entry_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct ElfClass {
    is_64: bool,
    little: bool,
}

#[derive(Debug, Clone, Copy)]
struct LoadSegment {
    file_off: u64,
    file_size: u64,
}

fn read_u16(bytes: &[u8], off: usize, little: bool) -> Option<u16> {
    if little {
        disrobe_bytes::read_u16_le_at(bytes, off).ok()
    } else {
        disrobe_bytes::read_u16_be_at(bytes, off).ok()
    }
}

fn read_u32(bytes: &[u8], off: usize, little: bool) -> Option<u32> {
    if little {
        disrobe_bytes::read_u32_le_at(bytes, off).ok()
    } else {
        disrobe_bytes::read_u32_be_at(bytes, off).ok()
    }
}

fn read_u64(bytes: &[u8], off: usize, little: bool) -> Option<u64> {
    if little {
        disrobe_bytes::read_u64_le_at(bytes, off).ok()
    } else {
        disrobe_bytes::read_u64_be_at(bytes, off).ok()
    }
}

fn read_addr(bytes: &[u8], off: usize, class: ElfClass) -> Option<u64> {
    if class.is_64 {
        read_u64(bytes, off, class.little)
    } else {
        read_u32(bytes, off, class.little).map(u64::from)
    }
}

fn detect_class(bytes: &[u8]) -> Option<ElfClass> {
    if bytes.len() < ELF_HEADER_MIN {
        return None;
    }
    let &ei_class: &u8 = bytes.get(EI_CLASS)?;
    let &ei_data: &u8 = bytes.get(EI_DATA)?;
    let is_64: bool = match ei_class {
        ELFCLASS32 => false,
        ELFCLASS64 => true,
        _ => return None,
    };
    let little: bool = match ei_data {
        ELFDATA2LSB => true,
        ELFDATA2MSB => false,
        _ => return None,
    };
    Some(ElfClass { is_64, little })
}

fn program_headers(bytes: &[u8], class: ElfClass) -> Option<(u64, u16, usize)> {
    if class.is_64 {
        let phoff: u64 = read_u64(bytes, E_PHOFF_64, class.little)?;
        let phentsize: u16 = read_u16(bytes, E_PHENTSIZE_64, class.little)?;
        let phnum: u16 = read_u16(bytes, E_PHNUM_64, class.little)?;
        Some((phoff, phentsize, phnum as usize))
    } else {
        let phoff: u64 = u64::from(read_u32(bytes, E_PHOFF_32, class.little)?);
        let phentsize: u16 = read_u16(bytes, E_PHENTSIZE_32, class.little)?;
        let phnum: u16 = read_u16(bytes, E_PHNUM_32, class.little)?;
        Some((phoff, phentsize, phnum as usize))
    }
}

fn read_program_header(
    bytes: &[u8],
    entry_off: usize,
    class: ElfClass,
) -> Option<(u32, LoadSegment)> {
    let p_type: u32 = read_u32(bytes, entry_off, class.little)?;
    let (off_field, filesz_field): (usize, usize) = if class.is_64 { (8, 32) } else { (4, 16) };
    let file_off: u64 = read_addr(bytes, entry_off.checked_add(off_field)?, class)?;
    let file_size: u64 = read_addr(bytes, entry_off.checked_add(filesz_field)?, class)?;
    Some((
        p_type,
        LoadSegment {
            file_off,
            file_size,
        },
    ))
}

fn read_cstr(bytes: &[u8], off: usize) -> Option<String> {
    let tail: &[u8] = bytes.get(off..)?;
    let cap: usize = tail.len().min(MAX_STRING_LEN);
    let end: usize = tail[..cap].iter().position(|&b: &u8| b == 0)?;
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn resolve_string(string_table: &[u8], string_offset: u64) -> Option<String> {
    let index: usize = usize::try_from(string_offset).ok()?;
    if index >= string_table.len() {
        return None;
    }
    read_cstr(string_table, index)
}

fn resolve_bounded_string(
    string_table: &[u8],
    string_offset: u64,
    decoded_bytes: &mut usize,
    output_limit: usize,
) -> Option<String> {
    let value: String = resolve_string(string_table, string_offset)?;
    let next_decoded_bytes: usize = decoded_bytes.checked_add(value.len())?;
    if next_decoded_bytes > output_limit {
        return None;
    }
    *decoded_bytes = next_decoded_bytes;
    Some(value)
}

fn resolve_needed(
    string_table: &[u8],
    offsets: &[u64],
    decoded_bytes: &mut usize,
    output_limit: usize,
) -> Option<Vec<String>> {
    let mut needed: Vec<String> = Vec::with_capacity(offsets.len());
    for &offset in offsets {
        let value: String =
            resolve_bounded_string(string_table, offset, decoded_bytes, output_limit)?;
        needed.push(value);
    }
    Some(needed)
}

fn push_needed_offset(offsets: &mut Vec<u64>, value: u64, limit: usize) -> Option<()> {
    if offsets.len() >= limit {
        return None;
    }
    offsets.push(value);
    Some(())
}

#[must_use]
pub fn parse_elf_dynamic(bytes: &[u8]) -> Option<ElfDynamic> {
    let class: ElfClass = detect_class(bytes)?;
    let (phoff, phentsize, phnum): (u64, u16, usize) = program_headers(bytes, class)?;
    if phnum == 0 || phnum > MAX_PROGRAM_HEADERS {
        return None;
    }
    let min_entry: u16 = if class.is_64 { 56 } else { 32 };
    if phentsize < min_entry {
        return None;
    }
    let phoff_usize: usize = usize::try_from(phoff).ok()?;
    let entsize: usize = usize::from(phentsize);

    let mut dynamic: Option<LoadSegment> = None;
    for i in 0..phnum {
        let entry_off: usize = phoff_usize.checked_add(i.checked_mul(entsize)?)?;
        if entry_off.checked_add(entsize)? > bytes.len() {
            return None;
        }
        let (p_type, seg): (u32, LoadSegment) = read_program_header(bytes, entry_off, class)?;
        if p_type == PT_DYNAMIC {
            dynamic = Some(seg);
        }
    }

    let dyn_seg: LoadSegment = dynamic?;
    let dyn_off: usize = usize::try_from(dyn_seg.file_off).ok()?;
    let dyn_size: usize = usize::try_from(dyn_seg.file_size).ok()?;
    let dyn_end: usize = dyn_off.checked_add(dyn_size)?;
    if dyn_end > bytes.len() {
        return None;
    }
    let entry_width: usize = if class.is_64 {
        DYN_ENTRY_64
    } else {
        DYN_ENTRY_32
    };
    let entry_total: usize = dyn_size / entry_width;
    if entry_total > MAX_DYNAMIC_ENTRIES {
        return None;
    }

    let mut needed_offsets: Vec<u64> = Vec::new();
    let mut soname_off: Option<u64> = None;
    let mut rpath_off: Option<u64> = None;
    let mut runpath_off: Option<u64> = None;
    let mut strtab_vaddr: Option<u64> = None;
    let mut strsz: Option<u64> = None;
    let mut flags: u64 = 0;
    let mut flags_1: u64 = 0;
    let mut entry_count: usize = 0;

    for i in 0..entry_total {
        let off: usize = dyn_off.checked_add(i.checked_mul(entry_width)?)?;
        let tag: u64 = read_addr(bytes, off, class)?;
        let val: u64 = read_addr(bytes, off.checked_add(entry_width / 2)?, class)?;
        entry_count = entry_count.checked_add(1)?;
        match tag {
            DT_NULL => break,
            DT_NEEDED => push_needed_offset(&mut needed_offsets, val, MAX_NEEDED)?,
            DT_SONAME => soname_off = Some(val),
            DT_RPATH => rpath_off = Some(val),
            DT_RUNPATH => runpath_off = Some(val),
            DT_STRTAB => strtab_vaddr = Some(val),
            DT_STRSZ => strsz = Some(val),
            DT_FLAGS => flags = val,
            DT_FLAGS_1 => flags_1 = val,
            _ => {}
        }
    }

    let image: NativeImage<'_> = parse_native_image(bytes).ok()?;
    let strtab_address: u64 = strtab_vaddr?;
    let strtab_bytes: &[u8] = match image.bytes_at(strtab_address) {
        Some(mapped) => mapped,
        None if image.sections().is_empty() => image.loader_bytes_at(strtab_address)?,
        None => return None,
    };
    let string_table: &[u8] = match strsz {
        Some(size) if size <= MAX_DT_STRSZ => {
            let declared_size: usize = usize::try_from(size).ok()?;
            strtab_bytes.get(..declared_size)?
        }
        Some(_) => return None,
        None => strtab_bytes,
    };

    let mut decoded_bytes: usize = 0;
    let needed: Vec<String> = resolve_needed(
        string_table,
        &needed_offsets,
        &mut decoded_bytes,
        MAX_DYNAMIC_STRING_OUTPUT,
    )?;
    let soname: Option<String> = match soname_off {
        Some(offset) => Some(resolve_bounded_string(
            string_table,
            offset,
            &mut decoded_bytes,
            MAX_DYNAMIC_STRING_OUTPUT,
        )?),
        None => None,
    };
    let rpath: Option<String> = match rpath_off {
        Some(offset) => Some(resolve_bounded_string(
            string_table,
            offset,
            &mut decoded_bytes,
            MAX_DYNAMIC_STRING_OUTPUT,
        )?),
        None => None,
    };
    let runpath: Option<String> = match runpath_off {
        Some(offset) => Some(resolve_bounded_string(
            string_table,
            offset,
            &mut decoded_bytes,
            MAX_DYNAMIC_STRING_OUTPUT,
        )?),
        None => None,
    };
    let bind_now: bool = (flags & DF_BIND_NOW) != 0 || (flags_1 & DF_1_NOW) != 0;
    let pie: bool = (flags_1 & DF_1_PIE) != 0;

    Some(ElfDynamic {
        needed,
        soname,
        rpath,
        runpath,
        bind_now,
        pie,
        entry_count,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn repeated_needed_offsets_respect_cumulative_output_limit() {
        let string_table: &[u8] = b"abcd\0";
        let offsets: [u64; 3] = [0, 0, 0];
        let mut decoded_bytes: usize = 0;
        let resolved: Option<Vec<String>> =
            resolve_needed(string_table, &offsets, &mut decoded_bytes, 8);

        assert!(resolved.is_none());
        assert_eq!(decoded_bytes, 8);
    }

    #[test]
    fn needed_offset_limit_rejects_incomplete_dependency_list() {
        let mut offsets: Vec<u64> = vec![1, 2];

        assert!(push_needed_offset(&mut offsets, 3, 2).is_none());
        assert_eq!(offsets, vec![1, 2]);
    }

    #[test]
    fn non_elf_input_yields_none() {
        assert!(parse_elf_dynamic(&[0u8; 8]).is_none());
        assert!(parse_elf_dynamic(b"not an elf at all really").is_none());
    }

    #[test]
    fn elf_without_dynamic_segment_yields_none() {
        let mut buf: Vec<u8> = vec![0u8; 0x100];
        buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        buf[EI_CLASS] = ELFCLASS64;
        buf[EI_DATA] = ELFDATA2LSB;
        buf[E_PHOFF_64..E_PHOFF_64 + 8].copy_from_slice(&0x40u64.to_le_bytes());
        buf[E_PHENTSIZE_64..E_PHENTSIZE_64 + 2].copy_from_slice(&56u16.to_le_bytes());
        buf[E_PHNUM_64..E_PHNUM_64 + 2].copy_from_slice(&1u16.to_le_bytes());
        let ph: usize = 0x40;
        buf[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        assert!(parse_elf_dynamic(&buf).is_none());
    }

    #[test]
    fn oversized_phnum_does_not_allocate_or_overread() {
        let mut buf: Vec<u8> = vec![0u8; 0x80];
        buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        buf[EI_CLASS] = ELFCLASS64;
        buf[EI_DATA] = ELFDATA2LSB;
        buf[E_PHOFF_64..E_PHOFF_64 + 8].copy_from_slice(&0x40u64.to_le_bytes());
        buf[E_PHENTSIZE_64..E_PHENTSIZE_64 + 2].copy_from_slice(&56u16.to_le_bytes());
        buf[E_PHNUM_64..E_PHNUM_64 + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert!(parse_elf_dynamic(&buf).is_none());
    }
}
