use disrobe_bytes::{
    ByteReadError, ByteReader, CStrOptions, Endian, bounded_element_capacity, read_cstr_at,
};

use crate::error::Result;
use crate::native::NativeFormat;

use super::{ByteCoverage, ClaimSet, RegionClass, UnbackedReason, coverage_error, read_error};

const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELF_CLASS_32: u8 = 1;
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LSB: u8 = 1;
const ELF_DATA_MSB: u8 = 2;
const EHDR_SIZE_32: u64 = 52;
const EHDR_SIZE_64: u64 = 64;
const PHDR_SIZE_32: u64 = 32;
const PHDR_SIZE_64: u64 = 56;
const SHDR_SIZE_32: u64 = 40;
const SHDR_SIZE_64: u64 = 64;
const SHT_NULL: u32 = 0;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_HASH: u32 = 5;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;
const SHF_EXECINSTR: u64 = 0x4;
const PT_LOAD: u32 = 1;
const XINDEX: u16 = 0xFFFF;
const MAX_SECTION_NAME: usize = 512;

#[derive(Debug, Clone, Copy)]
struct ElfHeader {
    endian: Endian,
    wide: bool,
    ehdr_size: u64,
    phoff: u64,
    phentsize: u64,
    phnum: u16,
    shoff: u64,
    shentsize: u64,
    shnum: u16,
    shstrndx: u16,
}

#[derive(Debug, Clone, Copy)]
struct SectionHeader {
    name: u32,
    kind: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
}

#[derive(Debug, Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    flags: u32,
    offset: u64,
    filesz: u64,
}

pub(super) fn map_elf(bytes: &[u8], format: NativeFormat) -> Result<ByteCoverage> {
    let mut claims: ClaimSet<'_> = ClaimSet::new(bytes)?;
    let header: ElfHeader = read_header(bytes)?;

    claims.claim(0, header.ehdr_size, RegionClass::Header, "elf-header")?;

    let sections: Vec<SectionHeader> = read_section_headers(bytes, &header)?;
    let program_headers: Vec<ProgramHeader> = read_program_headers(bytes, &header, &sections)?;

    if !program_headers.is_empty() {
        let table_bytes: u64 = u64::try_from(program_headers.len())
            .ok()
            .and_then(|count: u64| count.checked_mul(header.phentsize))
            .ok_or_else(|| coverage_error("the program header table range overflows"))?;
        claims.claim(
            header.phoff,
            table_bytes,
            RegionClass::Table,
            "program-header-table",
        )?;
    }

    if !sections.is_empty() {
        let table_bytes: u64 = u64::try_from(sections.len())
            .ok()
            .and_then(|count: u64| count.checked_mul(header.shentsize))
            .ok_or_else(|| coverage_error("the section header table range overflows"))?;
        claims.claim(
            header.shoff,
            table_bytes,
            RegionClass::Table,
            "section-header-table",
        )?;
    }

    let names: Option<(usize, usize)> = string_table_span(&header, &sections, bytes);
    let mut claimed_from_sections: bool = false;

    for (index, section) in sections.iter().enumerate() {
        if index == 0 || section.kind == SHT_NULL {
            continue;
        }
        let name: String = section_name(bytes, names, section.name, index);
        let claimant: String = format!("section:{name}");

        if section.kind == SHT_NOBITS {
            if section.size > 0 {
                claims.unbacked(claimant, section.size, UnbackedReason::NoFileBytes);
            }
            continue;
        }
        if section.size == 0 {
            continue;
        }
        claimed_from_sections = true;
        claims.claim_payload(
            section.offset,
            section.size,
            section_class(&name, section.kind, section.flags),
            claimant,
        )?;
    }

    if !claimed_from_sections {
        let floor: u64 = header
            .phoff
            .checked_add(
                u64::try_from(program_headers.len())
                    .ok()
                    .and_then(|count: u64| count.checked_mul(header.phentsize))
                    .unwrap_or(0),
            )
            .unwrap_or(header.ehdr_size)
            .max(header.ehdr_size);
        for (index, program) in program_headers.iter().enumerate() {
            if program.kind != PT_LOAD || program.filesz == 0 {
                continue;
            }
            let start: u64 = program.offset.max(floor);
            let declared_end: u64 = program
                .offset
                .checked_add(program.filesz)
                .ok_or_else(|| coverage_error("a load segment file range overflows"))?;
            if declared_end <= start {
                continue;
            }
            let class: RegionClass = if program.flags & object::elf::PF_X == 0 {
                RegionClass::Data
            } else {
                RegionClass::Code
            };
            claims.claim_payload(
                start,
                declared_end.saturating_sub(start),
                class,
                format!("segment:load#{index}"),
            )?;
        }
    }

    claims.finish(format)
}

fn read_header(bytes: &[u8]) -> Result<ElfHeader> {
    let class: u8 = *bytes
        .get(EI_CLASS)
        .ok_or_else(|| coverage_error("the ELF identification is truncated"))?;
    let data: u8 = *bytes
        .get(EI_DATA)
        .ok_or_else(|| coverage_error("the ELF identification is truncated"))?;
    let wide: bool = match class {
        ELF_CLASS_32 => false,
        ELF_CLASS_64 => true,
        other => {
            return Err(coverage_error(format!(
                "EI_CLASS {other} is neither 32 nor 64 bit"
            )));
        }
    };
    let endian: Endian = match data {
        ELF_DATA_LSB => Endian::Little,
        ELF_DATA_MSB => Endian::Big,
        other => {
            return Err(coverage_error(format!(
                "EI_DATA {other} names neither little nor big endian"
            )));
        }
    };

    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(if wide { 32 } else { 28 })
        .map_err(|error: ByteReadError| read_error("the ELF header", error))?;
    let phoff: u64 = read_address(&mut reader, endian, wide, "e_phoff")?;
    let shoff: u64 = read_address(&mut reader, endian, wide, "e_shoff")?;
    let _flags: u32 = reader
        .read_u32(endian)
        .map_err(|error: ByteReadError| read_error("the ELF header", error))?;
    let ehsize: u16 = reader
        .read_u16(endian)
        .map_err(|error: ByteReadError| read_error("the ELF header", error))?;
    let phentsize: u16 = reader
        .read_u16(endian)
        .map_err(|error: ByteReadError| read_error("the ELF header", error))?;
    let phnum: u16 = reader
        .read_u16(endian)
        .map_err(|error: ByteReadError| read_error("the ELF header", error))?;
    let shentsize: u16 = reader
        .read_u16(endian)
        .map_err(|error: ByteReadError| read_error("the ELF header", error))?;
    let shnum: u16 = reader
        .read_u16(endian)
        .map_err(|error: ByteReadError| read_error("the ELF header", error))?;
    let shstrndx: u16 = reader
        .read_u16(endian)
        .map_err(|error: ByteReadError| read_error("the ELF header", error))?;

    let canonical: u64 = if wide { EHDR_SIZE_64 } else { EHDR_SIZE_32 };
    let ehdr_size: u64 = u64::from(ehsize);
    if ehdr_size < canonical {
        return Err(coverage_error(format!(
            "e_ehsize {ehdr_size} is shorter than the {canonical} byte ELF header"
        )));
    }

    Ok(ElfHeader {
        endian,
        wide,
        ehdr_size,
        phoff,
        phentsize: u64::from(phentsize),
        phnum,
        shoff,
        shentsize: u64::from(shentsize),
        shnum,
        shstrndx,
    })
}

fn read_address(
    reader: &mut ByteReader<'_>,
    endian: Endian,
    wide: bool,
    subject: &str,
) -> Result<u64> {
    if wide {
        return reader
            .read_u64(endian)
            .map_err(|error: ByteReadError| read_error(subject, error));
    }
    reader
        .read_u32(endian)
        .map(u64::from)
        .map_err(|error: ByteReadError| read_error(subject, error))
}

fn read_section_headers(bytes: &[u8], header: &ElfHeader) -> Result<Vec<SectionHeader>> {
    if header.shoff == 0 {
        return Ok(Vec::new());
    }
    let canonical: u64 = if header.wide {
        SHDR_SIZE_64
    } else {
        SHDR_SIZE_32
    };
    if header.shentsize < canonical {
        return Err(coverage_error(format!(
            "e_shentsize {} is shorter than the {canonical} byte section header",
            header.shentsize
        )));
    }
    let first: SectionHeader = read_section_header(bytes, header, 0)?;
    let declared: u64 = if header.shnum == 0 {
        first.size
    } else {
        u64::from(header.shnum)
    };
    if declared == 0 {
        return Ok(Vec::new());
    }

    let start_index: usize =
        usize::try_from(header.shoff).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("e_shoff overflows the address space")
        })?;
    let entry_bytes: usize =
        usize::try_from(header.shentsize).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("e_shentsize overflows usize")
        })?;
    let admitted: usize = bounded_element_capacity(
        declared,
        entry_bytes,
        bytes.len().saturating_sub(start_index),
    );
    let requested: usize = usize::try_from(declared).unwrap_or(usize::MAX);
    if admitted < requested {
        return Err(coverage_error(format!(
            "the section header table declares {declared} entries, more than the {} bytes that \
             follow e_shoff can hold",
            bytes.len().saturating_sub(start_index)
        )));
    }

    let mut sections: Vec<SectionHeader> = Vec::with_capacity(admitted);
    for index in 0..requested {
        sections.push(read_section_header(bytes, header, index)?);
    }

    Ok(sections)
}

fn read_section_header(bytes: &[u8], header: &ElfHeader, index: usize) -> Result<SectionHeader> {
    let position: usize = usize::try_from(header.shoff)
        .ok()
        .and_then(|base: usize| {
            usize::try_from(header.shentsize)
                .ok()
                .and_then(|stride: usize| index.checked_mul(stride))
                .and_then(|offset: usize| base.checked_add(offset))
        })
        .ok_or_else(|| coverage_error("a section header offset overflows"))?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(position)
        .map_err(|error: ByteReadError| read_error("a section header", error))?;

    let name: u32 = reader
        .read_u32(header.endian)
        .map_err(|error: ByteReadError| read_error("a section header", error))?;
    let kind: u32 = reader
        .read_u32(header.endian)
        .map_err(|error: ByteReadError| read_error("a section header", error))?;
    let flags: u64 = read_address(&mut reader, header.endian, header.wide, "sh_flags")?;
    let _addr: u64 = read_address(&mut reader, header.endian, header.wide, "sh_addr")?;
    let offset: u64 = read_address(&mut reader, header.endian, header.wide, "sh_offset")?;
    let size: u64 = read_address(&mut reader, header.endian, header.wide, "sh_size")?;
    let link: u32 = reader
        .read_u32(header.endian)
        .map_err(|error: ByteReadError| read_error("a section header", error))?;
    let info: u32 = reader
        .read_u32(header.endian)
        .map_err(|error: ByteReadError| read_error("a section header", error))?;

    Ok(SectionHeader {
        name,
        kind,
        flags,
        offset,
        size,
        link,
        info,
    })
}

fn read_program_headers(
    bytes: &[u8],
    header: &ElfHeader,
    sections: &[SectionHeader],
) -> Result<Vec<ProgramHeader>> {
    if header.phoff == 0 {
        return Ok(Vec::new());
    }
    let canonical: u64 = if header.wide {
        PHDR_SIZE_64
    } else {
        PHDR_SIZE_32
    };
    if header.phentsize < canonical {
        return Err(coverage_error(format!(
            "e_phentsize {} is shorter than the {canonical} byte program header",
            header.phentsize
        )));
    }
    let declared: u64 = if header.phnum == XINDEX {
        sections
            .first()
            .map_or(u64::from(XINDEX), |first: &SectionHeader| {
                u64::from(first.info)
            })
    } else {
        u64::from(header.phnum)
    };
    if declared == 0 {
        return Ok(Vec::new());
    }

    let start_index: usize =
        usize::try_from(header.phoff).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("e_phoff overflows the address space")
        })?;
    let entry_bytes: usize =
        usize::try_from(header.phentsize).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("e_phentsize overflows usize")
        })?;
    let admitted: usize = bounded_element_capacity(
        declared,
        entry_bytes,
        bytes.len().saturating_sub(start_index),
    );
    let requested: usize = usize::try_from(declared).unwrap_or(usize::MAX);
    if admitted < requested {
        return Err(coverage_error(format!(
            "the program header table declares {declared} entries, more than the {} bytes that \
             follow e_phoff can hold",
            bytes.len().saturating_sub(start_index)
        )));
    }

    let mut programs: Vec<ProgramHeader> = Vec::with_capacity(admitted);
    for index in 0..requested {
        let position: usize = index
            .checked_mul(entry_bytes)
            .and_then(|offset: usize| start_index.checked_add(offset))
            .ok_or_else(|| coverage_error("a program header offset overflows"))?;
        let mut reader: ByteReader<'_> = ByteReader::new(bytes);
        reader
            .seek(position)
            .map_err(|error: ByteReadError| read_error("a program header", error))?;
        let kind: u32 = reader
            .read_u32(header.endian)
            .map_err(|error: ByteReadError| read_error("a program header", error))?;
        let flags: u32 = if header.wide {
            reader
                .read_u32(header.endian)
                .map_err(|error: ByteReadError| read_error("a program header", error))?
        } else {
            0
        };
        let offset: u64 = read_address(&mut reader, header.endian, header.wide, "p_offset")?;
        let _vaddr: u64 = read_address(&mut reader, header.endian, header.wide, "p_vaddr")?;
        let _paddr: u64 = read_address(&mut reader, header.endian, header.wide, "p_paddr")?;
        let filesz: u64 = read_address(&mut reader, header.endian, header.wide, "p_filesz")?;
        let flags: u32 = if header.wide {
            flags
        } else {
            let _memsz: u64 = read_address(&mut reader, header.endian, header.wide, "p_memsz")?;
            reader
                .read_u32(header.endian)
                .map_err(|error: ByteReadError| read_error("a program header", error))?
        };

        programs.push(ProgramHeader {
            kind,
            flags,
            offset,
            filesz,
        });
    }

    Ok(programs)
}

fn string_table_span(
    header: &ElfHeader,
    sections: &[SectionHeader],
    bytes: &[u8],
) -> Option<(usize, usize)> {
    let index: usize = if header.shstrndx == XINDEX {
        usize::try_from(sections.first()?.link).ok()?
    } else {
        usize::from(header.shstrndx)
    };
    let table: &SectionHeader = sections.get(index)?;
    if table.kind != SHT_STRTAB || table.size == 0 {
        return None;
    }
    let start: usize = usize::try_from(table.offset).ok()?;
    let size: usize = usize::try_from(table.size).ok()?;
    let end: usize = start.checked_add(size)?;
    if end > bytes.len() {
        return None;
    }

    Some((start, end))
}

fn section_name(
    bytes: &[u8],
    names: Option<(usize, usize)>,
    name_offset: u32,
    index: usize,
) -> String {
    let fallback: String = format!("#{index}");
    let Some((start, end)): Option<(usize, usize)> = names else {
        return fallback;
    };
    let Ok(offset): std::result::Result<usize, std::num::TryFromIntError> =
        usize::try_from(name_offset)
    else {
        return fallback;
    };
    let Some(position): Option<usize> = start.checked_add(offset) else {
        return fallback;
    };
    if position >= end {
        return fallback;
    }
    let Some(window): Option<&[u8]> = bytes.get(..end) else {
        return fallback;
    };
    let Ok(raw): std::result::Result<&[u8], ByteReadError> =
        read_cstr_at(window, position, CStrOptions::new(MAX_SECTION_NAME, false))
    else {
        return fallback;
    };
    if raw.is_empty() {
        return fallback;
    }

    String::from_utf8_lossy(raw).into_owned()
}

fn section_class(name: &str, kind: u32, flags: u64) -> RegionClass {
    if matches!(
        kind,
        SHT_SYMTAB | SHT_STRTAB | SHT_RELA | SHT_HASH | SHT_DYNAMIC | SHT_REL | SHT_DYNSYM
    ) {
        return RegionClass::Table;
    }
    if name.starts_with(".debug")
        || name.starts_with(".zdebug")
        || name.starts_with(".stab")
        || name == ".gnu_debuglink"
    {
        return RegionClass::Debug;
    }
    if flags & SHF_EXECINSTR != 0 {
        return RegionClass::Code;
    }
    RegionClass::Data
}
