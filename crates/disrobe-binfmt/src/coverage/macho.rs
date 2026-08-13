use disrobe_bytes::{ByteReadError, ByteReader, Endian, bounded_element_capacity};
use object::macho;

use crate::error::Result;
use crate::native::NativeFormat;

use super::{ByteCoverage, ClaimSet, RegionClass, UnbackedReason, coverage_error, read_error};

const HEADER_SIZE_32: u64 = 28;
const HEADER_SIZE_64: u64 = 32;
const LOAD_COMMAND_MIN: u64 = 8;
const SECTION_SIZE_32: u64 = 68;
const SECTION_SIZE_64: u64 = 80;
const NLIST_SIZE_32: u64 = 12;
const NLIST_SIZE_64: u64 = 16;
const TOC_ENTRY_SIZE: u64 = 8;
const MODULE_SIZE_32: u64 = 52;
const MODULE_SIZE_64: u64 = 56;
const REFERENCE_ENTRY_SIZE: u64 = 4;
const INDIRECT_ENTRY_SIZE: u64 = 4;
const RELOCATION_ENTRY_SIZE: u64 = 8;
const FAT_HEADER_SIZE: u64 = 8;
const FAT_ARCH_SIZE_32: u64 = 20;
const FAT_ARCH_SIZE_64: u64 = 32;
const SECTION_TYPE_MASK: u32 = 0xFF;
const MAX_LOAD_COMMANDS: u64 = 65_536;
const MAX_SLICES: u64 = 4_096;

#[derive(Debug, Clone, Copy)]
struct MachHeader {
    endian: Endian,
    wide: bool,
    header_size: u64,
    ncmds: u32,
    sizeofcmds: u64,
}

pub(super) fn map_thin(bytes: &[u8], format: NativeFormat) -> Result<ByteCoverage> {
    let mut claims: ClaimSet<'_> = ClaimSet::new(bytes)?;
    let header: MachHeader = read_header(bytes)?;

    claims.claim(0, header.header_size, RegionClass::Header, "mach-header")?;

    let table_end: u64 = header
        .header_size
        .checked_add(header.sizeofcmds)
        .ok_or_else(|| coverage_error("the load command table range overflows"))?;
    if table_end > claims.file_len() {
        return Err(coverage_error(format!(
            "sizeofcmds {} runs past the {} byte input",
            header.sizeofcmds,
            claims.file_len()
        )));
    }
    if u64::from(header.ncmds) > MAX_LOAD_COMMANDS {
        return Err(coverage_error(format!(
            "ncmds {} exceeds the {MAX_LOAD_COMMANDS} command ceiling",
            header.ncmds
        )));
    }

    let mut cursor: u64 = header.header_size;
    for index in 0..header.ncmds {
        if cursor >= table_end {
            return Err(coverage_error(format!(
                "load command {index} starts past the end of the load command table"
            )));
        }
        let (command, size): (u32, u64) = read_command_head(bytes, &header, cursor)?;
        if size < LOAD_COMMAND_MIN {
            return Err(coverage_error(format!(
                "load command {index} declares a {size} byte size"
            )));
        }
        let end: u64 = cursor
            .checked_add(size)
            .ok_or_else(|| coverage_error("a load command range overflows"))?;
        if end > table_end {
            return Err(coverage_error(format!(
                "load command {index} runs past the end of the load command table"
            )));
        }
        claims.claim(
            cursor,
            size,
            RegionClass::Table,
            format!("load-command:{}", command_label(command)),
        )?;
        claim_command_payload(&mut claims, bytes, &header, command, cursor, size)?;
        cursor = end;
    }

    claims.finish(format)
}

pub(super) fn map_fat(bytes: &[u8]) -> Result<ByteCoverage> {
    let mut claims: ClaimSet<'_> = ClaimSet::new(bytes)?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let raw: u32 = reader
        .read_u32_be()
        .map_err(|error: ByteReadError| read_error("the fat header", error))?;
    let (endian, wide): (Endian, bool) = match raw {
        macho::FAT_MAGIC => (Endian::Big, false),
        macho::FAT_MAGIC_64 => (Endian::Big, true),
        macho::FAT_CIGAM => (Endian::Little, false),
        macho::FAT_CIGAM_64 => (Endian::Little, true),
        other => {
            return Err(coverage_error(format!(
                "fat magic {other:#010x} is not a universal binary"
            )));
        }
    };
    let count: u32 = reader
        .read_u32(endian)
        .map_err(|error: ByteReadError| read_error("the fat header", error))?;
    if u64::from(count) > MAX_SLICES {
        return Err(coverage_error(format!(
            "nfat_arch {count} exceeds the {MAX_SLICES} slice ceiling"
        )));
    }

    let entry_size: u64 = if wide {
        FAT_ARCH_SIZE_64
    } else {
        FAT_ARCH_SIZE_32
    };
    let entry_bytes: usize = usize::try_from(entry_size)
        .map_err(|_error: std::num::TryFromIntError| coverage_error("a fat entry overflows"))?;
    let start_index: usize = usize::try_from(FAT_HEADER_SIZE)
        .map_err(|_error: std::num::TryFromIntError| coverage_error("a fat offset overflows"))?;
    let admitted: usize = bounded_element_capacity(
        u64::from(count),
        entry_bytes,
        bytes.len().saturating_sub(start_index),
    );
    let requested: usize = usize::try_from(count).unwrap_or(usize::MAX);
    if admitted < requested {
        return Err(coverage_error(format!(
            "nfat_arch {count} needs more than the {} bytes that follow the fat header",
            bytes.len().saturating_sub(start_index)
        )));
    }

    claims.claim(0, FAT_HEADER_SIZE, RegionClass::Header, "fat-header")?;
    let table_bytes: u64 = u64::from(count)
        .checked_mul(entry_size)
        .ok_or_else(|| coverage_error("the fat architecture table range overflows"))?;
    claims.claim(
        FAT_HEADER_SIZE,
        table_bytes,
        RegionClass::Table,
        "fat-arch-table",
    )?;

    for index in 0..requested {
        let position: usize = index
            .checked_mul(entry_bytes)
            .and_then(|offset: usize| start_index.checked_add(offset))
            .ok_or_else(|| coverage_error("a fat entry offset overflows"))?;
        let mut entry: ByteReader<'_> = ByteReader::new(bytes);
        entry
            .seek(position)
            .map_err(|error: ByteReadError| read_error("a fat architecture entry", error))?;
        let cputype: u32 = entry
            .read_u32(endian)
            .map_err(|error: ByteReadError| read_error("a fat architecture entry", error))?;
        let cpusubtype: u32 = entry
            .read_u32(endian)
            .map_err(|error: ByteReadError| read_error("a fat architecture entry", error))?;
        let (offset, size): (u64, u64) = if wide {
            (
                entry
                    .read_u64(endian)
                    .map_err(|error: ByteReadError| read_error("a fat slice offset", error))?,
                entry
                    .read_u64(endian)
                    .map_err(|error: ByteReadError| read_error("a fat slice size", error))?,
            )
        } else {
            (
                u64::from(
                    entry
                        .read_u32(endian)
                        .map_err(|error: ByteReadError| read_error("a fat slice offset", error))?,
                ),
                u64::from(
                    entry
                        .read_u32(endian)
                        .map_err(|error: ByteReadError| read_error("a fat slice size", error))?,
                ),
            )
        };
        claims.claim_payload(
            offset,
            size,
            RegionClass::Data,
            format!("slice:{cputype:#x}-{cpusubtype:#x}"),
        )?;
    }

    claims.finish(NativeFormat::MachOFat)
}

fn read_header(bytes: &[u8]) -> Result<MachHeader> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let raw: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("the mach header", error))?;
    let (endian, wide): (Endian, bool) = match raw {
        macho::MH_MAGIC => (Endian::Little, false),
        macho::MH_MAGIC_64 => (Endian::Little, true),
        macho::MH_CIGAM => (Endian::Big, false),
        macho::MH_CIGAM_64 => (Endian::Big, true),
        other => {
            return Err(coverage_error(format!(
                "mach magic {other:#010x} is not a thin Mach-O image"
            )));
        }
    };

    reader
        .seek(16)
        .map_err(|error: ByteReadError| read_error("the mach header", error))?;
    let ncmds: u32 = reader
        .read_u32(endian)
        .map_err(|error: ByteReadError| read_error("the mach header", error))?;
    let sizeofcmds: u32 = reader
        .read_u32(endian)
        .map_err(|error: ByteReadError| read_error("the mach header", error))?;

    Ok(MachHeader {
        endian,
        wide,
        header_size: if wide { HEADER_SIZE_64 } else { HEADER_SIZE_32 },
        ncmds,
        sizeofcmds: u64::from(sizeofcmds),
    })
}

fn read_command_head(bytes: &[u8], header: &MachHeader, offset: u64) -> Result<(u32, u64)> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    seek_to(&mut reader, offset, "a load command")?;
    let command: u32 = reader
        .read_u32(header.endian)
        .map_err(|error: ByteReadError| read_error("a load command", error))?;
    let size: u32 = reader
        .read_u32(header.endian)
        .map_err(|error: ByteReadError| read_error("a load command", error))?;

    Ok((command, u64::from(size)))
}

#[allow(clippy::too_many_lines)]
fn claim_command_payload(
    claims: &mut ClaimSet<'_>,
    bytes: &[u8],
    header: &MachHeader,
    command: u32,
    offset: u64,
    size: u64,
) -> Result<()> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    seek_to(&mut reader, offset, "a load command")?;
    reader
        .skip(8)
        .map_err(|error: ByteReadError| read_error("a load command", error))?;

    match command {
        macho::LC_SEGMENT | macho::LC_SEGMENT_64 => {
            claim_segment_sections(claims, bytes, header, offset, size)
        }
        macho::LC_SYMTAB => {
            let symoff: u64 = read_u32_as(&mut reader, header, "symoff")?;
            let nsyms: u64 = read_u32_as(&mut reader, header, "nsyms")?;
            let stroff: u64 = read_u32_as(&mut reader, header, "stroff")?;
            let strsize: u64 = read_u32_as(&mut reader, header, "strsize")?;
            let entry: u64 = if header.wide {
                NLIST_SIZE_64
            } else {
                NLIST_SIZE_32
            };
            let table_bytes: u64 = nsyms
                .checked_mul(entry)
                .ok_or_else(|| coverage_error("the symbol table range overflows"))?;
            claims.claim_payload(symoff, table_bytes, RegionClass::Table, "symbol-table")?;
            claims.claim_payload(stroff, strsize, RegionClass::Table, "string-table")
        }
        macho::LC_DYSYMTAB => {
            reader
                .skip(24)
                .map_err(|error: ByteReadError| read_error("the dynamic symbol table", error))?;
            let module_size: u64 = if header.wide {
                MODULE_SIZE_64
            } else {
                MODULE_SIZE_32
            };
            claim_counted_table(claims, &mut reader, header, TOC_ENTRY_SIZE, "dysymtab-toc")?;
            claim_counted_table(claims, &mut reader, header, module_size, "dysymtab-modules")?;
            claim_counted_table(
                claims,
                &mut reader,
                header,
                REFERENCE_ENTRY_SIZE,
                "dysymtab-references",
            )?;
            claim_counted_table(
                claims,
                &mut reader,
                header,
                INDIRECT_ENTRY_SIZE,
                "dysymtab-indirect-symbols",
            )?;
            claim_counted_table(
                claims,
                &mut reader,
                header,
                RELOCATION_ENTRY_SIZE,
                "dysymtab-external-relocations",
            )?;
            claim_counted_table(
                claims,
                &mut reader,
                header,
                RELOCATION_ENTRY_SIZE,
                "dysymtab-local-relocations",
            )
        }
        macho::LC_DYLD_INFO | macho::LC_DYLD_INFO_ONLY => {
            for label in [
                "dyld-rebase",
                "dyld-bind",
                "dyld-weak-bind",
                "dyld-lazy-bind",
                "dyld-export",
            ] {
                let start: u64 = read_u32_as(&mut reader, header, label)?;
                let length: u64 = read_u32_as(&mut reader, header, label)?;
                claims.claim_payload(start, length, RegionClass::Table, label)?;
            }
            Ok(())
        }
        macho::LC_CODE_SIGNATURE => claim_linkedit_data(
            claims,
            &mut reader,
            header,
            RegionClass::Signature,
            "code-signature",
        ),
        macho::LC_SEGMENT_SPLIT_INFO => claim_linkedit_data(
            claims,
            &mut reader,
            header,
            RegionClass::Table,
            "segment-split-info",
        ),
        macho::LC_FUNCTION_STARTS => claim_linkedit_data(
            claims,
            &mut reader,
            header,
            RegionClass::Table,
            "function-starts",
        ),
        macho::LC_DATA_IN_CODE => claim_linkedit_data(
            claims,
            &mut reader,
            header,
            RegionClass::Table,
            "data-in-code",
        ),
        macho::LC_DYLIB_CODE_SIGN_DRS => claim_linkedit_data(
            claims,
            &mut reader,
            header,
            RegionClass::Signature,
            "code-sign-designated-requirements",
        ),
        macho::LC_LINKER_OPTIMIZATION_HINT => claim_linkedit_data(
            claims,
            &mut reader,
            header,
            RegionClass::Table,
            "linker-optimization-hint",
        ),
        macho::LC_DYLD_EXPORTS_TRIE => claim_linkedit_data(
            claims,
            &mut reader,
            header,
            RegionClass::Table,
            "dyld-exports-trie",
        ),
        macho::LC_DYLD_CHAINED_FIXUPS => claim_linkedit_data(
            claims,
            &mut reader,
            header,
            RegionClass::Table,
            "dyld-chained-fixups",
        ),
        _ => Ok(()),
    }
}

fn claim_segment_sections(
    claims: &mut ClaimSet<'_>,
    bytes: &[u8],
    header: &MachHeader,
    offset: u64,
    size: u64,
) -> Result<()> {
    let command_size: u64 = if header.wide { 72 } else { 56 };
    if size < command_size {
        return Err(coverage_error(format!(
            "a segment command declares {size} bytes, less than its fixed {command_size} bytes"
        )));
    }
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    seek_to(&mut reader, offset, "a segment command")?;
    reader
        .skip(8)
        .map_err(|error: ByteReadError| read_error("a segment command", error))?;
    let segment_name: String = read_fixed_name(&mut reader, "a segment name")?;
    reader
        .skip(if header.wide { 32 } else { 16 })
        .map_err(|error: ByteReadError| read_error("a segment command", error))?;
    reader
        .skip(8)
        .map_err(|error: ByteReadError| read_error("a segment command", error))?;
    let nsects: u32 = reader
        .read_u32(header.endian)
        .map_err(|error: ByteReadError| read_error("a segment command", error))?;

    let entry_size: u64 = if header.wide {
        SECTION_SIZE_64
    } else {
        SECTION_SIZE_32
    };
    let declared: u64 = u64::from(nsects)
        .checked_mul(entry_size)
        .ok_or_else(|| coverage_error("a segment section table range overflows"))?;
    let available: u64 = size.saturating_sub(command_size);
    if declared > available {
        return Err(coverage_error(format!(
            "segment {segment_name} declares {nsects} sections, more than its {available} byte \
             command body can hold"
        )));
    }

    let table_start: u64 = offset
        .checked_add(command_size)
        .ok_or_else(|| coverage_error("a segment section table offset overflows"))?;
    for index in 0..nsects {
        let position: u64 = u64::from(index)
            .checked_mul(entry_size)
            .and_then(|delta: u64| table_start.checked_add(delta))
            .ok_or_else(|| coverage_error("a section record offset overflows"))?;
        let mut record: ByteReader<'_> = ByteReader::new(bytes);
        seek_to(&mut record, position, "a section record")?;
        let section_name: String = read_fixed_name(&mut record, "a section name")?;
        record
            .skip(16)
            .map_err(|error: ByteReadError| read_error("a section record", error))?;
        let _address: u64 = read_word(&mut record, header, "a section address")?;
        let declared_size: u64 = read_word(&mut record, header, "a section size")?;
        let file_offset: u64 = read_u32_as(&mut record, header, "a section file offset")?;
        let _align: u64 = read_u32_as(&mut record, header, "a section alignment")?;
        let reloff: u64 = read_u32_as(&mut record, header, "a relocation table offset")?;
        let nreloc: u64 = read_u32_as(&mut record, header, "a relocation count")?;
        let flags: u32 = record
            .read_u32(header.endian)
            .map_err(|error: ByteReadError| read_error("a section record", error))?;

        let claimant: String = format!("section:{segment_name},{section_name}");
        let zero_filled: bool = matches!(
            flags & SECTION_TYPE_MASK,
            macho::S_ZEROFILL | macho::S_GB_ZEROFILL | macho::S_THREAD_LOCAL_ZEROFILL
        );
        if zero_filled {
            if declared_size > 0 {
                claims.unbacked(claimant.clone(), declared_size, UnbackedReason::NoFileBytes);
            }
        } else if declared_size > 0 {
            if file_offset == 0 {
                claims.unbacked(
                    claimant.clone(),
                    declared_size,
                    UnbackedReason::NoFileOffset,
                );
            } else {
                claims.claim_payload(
                    file_offset,
                    declared_size,
                    section_class(&section_name, flags),
                    claimant.clone(),
                )?;
            }
        }

        if nreloc > 0 && reloff > 0 {
            let relocation_bytes: u64 = nreloc
                .checked_mul(RELOCATION_ENTRY_SIZE)
                .ok_or_else(|| coverage_error("a relocation table range overflows"))?;
            claims.claim_payload(
                reloff,
                relocation_bytes,
                RegionClass::Table,
                format!("relocations:{claimant}"),
            )?;
        }
    }

    Ok(())
}

fn claim_counted_table(
    claims: &mut ClaimSet<'_>,
    reader: &mut ByteReader<'_>,
    header: &MachHeader,
    entry_size: u64,
    label: &str,
) -> Result<()> {
    let offset: u64 = read_u32_as(reader, header, label)?;
    let count: u64 = read_u32_as(reader, header, label)?;
    let length: u64 = count
        .checked_mul(entry_size)
        .ok_or_else(|| coverage_error(format!("the {label} range overflows")))?;

    claims.claim_payload(offset, length, RegionClass::Table, label.to_owned())
}

fn claim_linkedit_data(
    claims: &mut ClaimSet<'_>,
    reader: &mut ByteReader<'_>,
    header: &MachHeader,
    class: RegionClass,
    label: &str,
) -> Result<()> {
    let offset: u64 = read_u32_as(reader, header, label)?;
    let length: u64 = read_u32_as(reader, header, label)?;

    claims.claim_payload(offset, length, class, label.to_owned())
}

fn read_word(reader: &mut ByteReader<'_>, header: &MachHeader, subject: &str) -> Result<u64> {
    if header.wide {
        return reader
            .read_u64(header.endian)
            .map_err(|error: ByteReadError| read_error(subject, error));
    }
    read_u32_as(reader, header, subject)
}

fn read_u32_as(reader: &mut ByteReader<'_>, header: &MachHeader, subject: &str) -> Result<u64> {
    reader
        .read_u32(header.endian)
        .map(u64::from)
        .map_err(|error: ByteReadError| read_error(subject, error))
}

fn read_fixed_name(reader: &mut ByteReader<'_>, subject: &str) -> Result<String> {
    let raw: &[u8] = reader
        .read_bytes(16)
        .map_err(|error: ByteReadError| read_error(subject, error))?;
    let length: usize = raw
        .iter()
        .position(|value: &u8| *value == 0)
        .unwrap_or(raw.len());
    let trimmed: &[u8] = raw
        .get(..length)
        .ok_or_else(|| coverage_error(format!("{subject} range is invalid")))?;

    Ok(String::from_utf8_lossy(trimmed).into_owned())
}

fn seek_to(reader: &mut ByteReader<'_>, offset: u64, subject: &str) -> Result<()> {
    let position: usize =
        usize::try_from(offset).map_err(|_error: std::num::TryFromIntError| {
            coverage_error(format!("{subject} offset overflows usize"))
        })?;
    reader
        .seek(position)
        .map_err(|error: ByteReadError| read_error(subject, error))
}

fn section_class(name: &str, flags: u32) -> RegionClass {
    if flags & macho::S_ATTR_PURE_INSTRUCTIONS != 0 || flags & macho::S_ATTR_SOME_INSTRUCTIONS != 0
    {
        return RegionClass::Code;
    }
    if name.starts_with("__debug") || name.starts_with("__zdebug") {
        return RegionClass::Debug;
    }
    RegionClass::Data
}

fn command_label(command: u32) -> String {
    match command {
        macho::LC_SEGMENT => "LC_SEGMENT".to_owned(),
        macho::LC_SEGMENT_64 => "LC_SEGMENT_64".to_owned(),
        macho::LC_SYMTAB => "LC_SYMTAB".to_owned(),
        macho::LC_DYSYMTAB => "LC_DYSYMTAB".to_owned(),
        macho::LC_DYLD_INFO => "LC_DYLD_INFO".to_owned(),
        macho::LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY".to_owned(),
        macho::LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE".to_owned(),
        macho::LC_SEGMENT_SPLIT_INFO => "LC_SEGMENT_SPLIT_INFO".to_owned(),
        macho::LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS".to_owned(),
        macho::LC_DATA_IN_CODE => "LC_DATA_IN_CODE".to_owned(),
        macho::LC_DYLIB_CODE_SIGN_DRS => "LC_DYLIB_CODE_SIGN_DRS".to_owned(),
        macho::LC_LINKER_OPTIMIZATION_HINT => "LC_LINKER_OPTIMIZATION_HINT".to_owned(),
        macho::LC_DYLD_EXPORTS_TRIE => "LC_DYLD_EXPORTS_TRIE".to_owned(),
        macho::LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS".to_owned(),
        macho::LC_UUID => "LC_UUID".to_owned(),
        macho::LC_LOAD_DYLIB => "LC_LOAD_DYLIB".to_owned(),
        macho::LC_ID_DYLIB => "LC_ID_DYLIB".to_owned(),
        macho::LC_LOAD_DYLINKER => "LC_LOAD_DYLINKER".to_owned(),
        macho::LC_MAIN => "LC_MAIN".to_owned(),
        macho::LC_BUILD_VERSION => "LC_BUILD_VERSION".to_owned(),
        macho::LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX".to_owned(),
        macho::LC_SOURCE_VERSION => "LC_SOURCE_VERSION".to_owned(),
        macho::LC_RPATH => "LC_RPATH".to_owned(),
        macho::LC_UNIXTHREAD => "LC_UNIXTHREAD".to_owned(),
        other => format!("{other:#010x}"),
    }
}
