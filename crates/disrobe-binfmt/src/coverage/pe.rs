use disrobe_bytes::{ByteReadError, ByteReader, bounded_element_capacity};

use crate::error::Result;
use crate::native::NativeFormat;

use super::{ByteCoverage, ClaimSet, RegionClass, UnbackedReason, coverage_error, read_error};

const DOS_HEADER_SIZE: u64 = 64;
const LFANEW_OFFSET: usize = 0x3C;
const PE_SIGNATURE_SIZE: u64 = 4;
const COFF_HEADER_SIZE: u64 = 20;
const SECTION_RECORD_SIZE: u64 = 40;
const SECTION_RECORD_BYTES: usize = 40;
const SYMBOL_RECORD_SIZE: u64 = 18;
const SYMBOL_RECORD_BYTES: usize = 18;
const OPTIONAL_MAGIC_PE32: u16 = 0x010B;
const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x020B;
const DIRECTORY_RECORD_SIZE: u64 = 8;
const DIRECTORY_LIMIT: u32 = 16;
const CERTIFICATE_DIRECTORY: u64 = 4;
const DEBUG_DIRECTORY: u64 = 6;
const DEBUG_DIRECTORY_ENTRY_SIZE: u64 = 28;
const DEBUG_DATA_SIZE_OFFSET: usize = 16;
const DEBUG_DATA_POINTER_OFFSET: usize = 24;
const MAX_DEBUG_DIRECTORY_ENTRIES: u64 = 4_096;
const CERTIFICATE_ALIGNMENT: u64 = 8;
const SIZE_OF_HEADERS_OFFSET: usize = 0x3C;
const PE32_DIRECTORY_COUNT_OFFSET: usize = 0x5C;
const PE32_PLUS_DIRECTORY_COUNT_OFFSET: usize = 0x6C;
const PE32_DIRECTORY_OFFSET: u64 = 0x60;
const PE32_PLUS_DIRECTORY_OFFSET: u64 = 0x70;

#[derive(Debug, Clone, Copy)]
struct SectionRecord {
    virtual_size: u32,
    virtual_address: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
}

#[derive(Debug, Clone)]
struct PeSection {
    name: String,
    virtual_address: u64,
    virtual_size: u64,
    raw_offset: u64,
    raw_size: u64,
}

#[derive(Debug, Clone, Copy)]
struct DataDirectory {
    address: u64,
    size: u64,
}

pub(super) fn map_pe32(bytes: &[u8]) -> Result<ByteCoverage> {
    map(bytes, NativeFormat::Pe32)
}

pub(super) fn map_pe64(bytes: &[u8]) -> Result<ByteCoverage> {
    map(bytes, NativeFormat::Pe64)
}

#[allow(clippy::too_many_lines)]
fn map(bytes: &[u8], format: NativeFormat) -> Result<ByteCoverage> {
    let mut claims: ClaimSet<'_> = ClaimSet::new(bytes)?;
    let file_len: u64 = claims.file_len();
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);

    reader
        .seek(LFANEW_OFFSET)
        .map_err(|error: ByteReadError| read_error("the DOS header", error))?;
    let lfanew: u64 = u64::from(
        reader
            .read_u32_le()
            .map_err(|error: ByteReadError| read_error("the DOS header", error))?,
    );
    if lfanew < DOS_HEADER_SIZE {
        return Err(coverage_error(format!(
            "e_lfanew points at {lfanew}, inside the {DOS_HEADER_SIZE} byte DOS header"
        )));
    }

    claims.claim(0, DOS_HEADER_SIZE, RegionClass::Header, "dos-header")?;
    claims.claim(
        DOS_HEADER_SIZE,
        lfanew.saturating_sub(DOS_HEADER_SIZE),
        RegionClass::Data,
        "dos-stub",
    )?;
    claims.claim(
        lfanew,
        PE_SIGNATURE_SIZE,
        RegionClass::Header,
        "pe-signature",
    )?;

    let coff_start: u64 = lfanew
        .checked_add(PE_SIGNATURE_SIZE)
        .ok_or_else(|| coverage_error("the PE signature offset overflows"))?;
    claims.claim(
        coff_start,
        COFF_HEADER_SIZE,
        RegionClass::Header,
        "coff-header",
    )?;

    let coff_index: usize = usize::try_from(coff_start)
        .map_err(|_error: std::num::TryFromIntError| coverage_error("the PE offset overflows"))?;
    reader
        .seek(coff_index)
        .map_err(|error: ByteReadError| read_error("the COFF header", error))?;
    let _machine: u16 = reader
        .read_u16_le()
        .map_err(|error: ByteReadError| read_error("the COFF header", error))?;
    let section_count: u16 = reader
        .read_u16_le()
        .map_err(|error: ByteReadError| read_error("the COFF header", error))?;
    let _timestamp: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("the COFF header", error))?;
    let symbol_table_offset: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("the COFF header", error))?;
    let symbol_count: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("the COFF header", error))?;
    let optional_size: u64 = u64::from(
        reader
            .read_u16_le()
            .map_err(|error: ByteReadError| read_error("the COFF header", error))?,
    );

    let optional_start: u64 = coff_start
        .checked_add(COFF_HEADER_SIZE)
        .ok_or_else(|| coverage_error("the optional header offset overflows"))?;
    let optional_end: u64 = optional_start
        .checked_add(optional_size)
        .ok_or_else(|| coverage_error("the optional header range overflows"))?;
    if optional_end > file_len {
        return Err(coverage_error(format!(
            "SizeOfOptionalHeader {optional_size} runs past the {file_len} byte input"
        )));
    }

    let optional_index: usize =
        usize::try_from(optional_start).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("the optional header offset overflows")
        })?;
    reader
        .seek(optional_index)
        .map_err(|error: ByteReadError| read_error("the optional header", error))?;
    let magic: u16 = reader
        .read_u16_le()
        .map_err(|error: ByteReadError| read_error("the optional header", error))?;
    let (directory_offset, count_offset): (u64, usize) = match magic {
        OPTIONAL_MAGIC_PE32 => (PE32_DIRECTORY_OFFSET, PE32_DIRECTORY_COUNT_OFFSET),
        OPTIONAL_MAGIC_PE32_PLUS => (PE32_PLUS_DIRECTORY_OFFSET, PE32_PLUS_DIRECTORY_COUNT_OFFSET),
        other => {
            return Err(coverage_error(format!(
                "optional header magic {other:#06x} is neither PE32 nor PE32+"
            )));
        }
    };
    if optional_size < directory_offset {
        return Err(coverage_error(format!(
            "SizeOfOptionalHeader {optional_size} is shorter than the {directory_offset} byte \
             fixed optional header"
        )));
    }

    let size_of_headers: u64 = u64::from(read_u32_at(
        bytes,
        optional_index,
        SIZE_OF_HEADERS_OFFSET,
        "SizeOfHeaders",
    )?);
    let declared_directories: u32 =
        read_u32_at(bytes, optional_index, count_offset, "NumberOfRvaAndSizes")?;
    let declared_directory_count: u64 = u64::from(declared_directories.min(DIRECTORY_LIMIT));
    let directory_bytes: u64 = declared_directory_count
        .checked_mul(DIRECTORY_RECORD_SIZE)
        .ok_or_else(|| coverage_error("the data directory range overflows"))?;
    let directory_bytes: u64 = directory_bytes.min(optional_size.saturating_sub(directory_offset));
    let directory_count: u64 = directory_bytes / DIRECTORY_RECORD_SIZE;

    claims.claim(
        optional_start,
        directory_offset,
        RegionClass::Header,
        "optional-header",
    )?;
    let directory_start: u64 = optional_start
        .checked_add(directory_offset)
        .ok_or_else(|| coverage_error("the data directory offset overflows"))?;
    claims.claim(
        directory_start,
        directory_bytes,
        RegionClass::Table,
        "data-directories",
    )?;
    let directory_end: u64 = directory_start
        .checked_add(directory_bytes)
        .ok_or_else(|| coverage_error("the data directory range overflows"))?;
    claims.claim(
        directory_end,
        optional_end.saturating_sub(directory_end),
        RegionClass::Padding,
        "optional-header-slack",
    )?;

    let table_start: u64 = optional_end;
    let table_index: usize =
        usize::try_from(table_start).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("the section table offset overflows")
        })?;
    let admitted_sections: usize = bounded_element_capacity(
        u64::from(section_count),
        SECTION_RECORD_BYTES,
        bytes.len().saturating_sub(table_index),
    );
    if admitted_sections < usize::from(section_count) {
        return Err(coverage_error(format!(
            "NumberOfSections {section_count} needs more than the {} bytes that follow the \
             section table",
            bytes.len().saturating_sub(table_index)
        )));
    }
    let table_bytes: u64 = u64::from(section_count)
        .checked_mul(SECTION_RECORD_SIZE)
        .ok_or_else(|| coverage_error("the section table range overflows"))?;
    claims.claim(
        table_start,
        table_bytes,
        RegionClass::Table,
        "section-table",
    )?;

    let table_end: u64 = table_start
        .checked_add(table_bytes)
        .ok_or_else(|| coverage_error("the section table range overflows"))?;
    if size_of_headers > table_end {
        claims.claim_payload(
            table_end,
            size_of_headers.saturating_sub(table_end),
            RegionClass::Padding,
            "header-padding",
        )?;
    }

    reader
        .seek(table_index)
        .map_err(|error: ByteReadError| read_error("the section table", error))?;
    let mut sections: Vec<PeSection> = Vec::with_capacity(admitted_sections);
    for index in 0..usize::from(section_count) {
        let record: SectionRecord = read_section_record(&mut reader)?;
        let name: String = section_name(bytes, table_index, index)?;
        let claimant: String = format!("section:{name}");
        let class: RegionClass = section_class(&name, record.characteristics);
        let raw_offset: u64 = u64::from(record.raw_offset);
        let raw_size: u64 = u64::from(record.raw_size);

        sections.push(PeSection {
            name: name.clone(),
            virtual_address: u64::from(record.virtual_address),
            virtual_size: u64::from(record.virtual_size),
            raw_offset,
            raw_size,
        });

        if raw_size == 0 {
            if record.virtual_size > 0 {
                claims.unbacked(
                    claimant,
                    u64::from(record.virtual_size),
                    UnbackedReason::NoFileBytes,
                );
            }
            continue;
        }
        if raw_offset == 0 {
            claims.unbacked(claimant, raw_size, UnbackedReason::NoFileOffset);
            continue;
        }
        claims.claim_payload(raw_offset, raw_size, class, claimant)?;
    }

    if symbol_table_offset != 0 && symbol_count != 0 {
        claim_symbol_tables(&mut claims, bytes, symbol_table_offset, symbol_count)?;
    }

    let certificate: Option<DataDirectory> = read_directory(
        bytes,
        directory_start,
        directory_count,
        CERTIFICATE_DIRECTORY,
        "the certificate table",
    )?;
    if let Some(directory) = certificate.filter(|entry: &DataDirectory| entry.size > 0) {
        if directory.address == 0 {
            return Err(coverage_error(
                "the certificate table has a nonzero size at file offset zero",
            ));
        }
        claims.claim_payload(
            directory.address,
            directory.size,
            RegionClass::Signature,
            "certificate-table",
        )?;
    }

    let debug: Option<DataDirectory> = read_directory(
        bytes,
        directory_start,
        directory_count,
        DEBUG_DIRECTORY,
        "the debug directory",
    )?;
    if let Some(directory) = debug.filter(|entry: &DataDirectory| entry.size > 0) {
        if directory.address == 0 {
            return Err(coverage_error(
                "the debug directory has a nonzero size at RVA zero",
            ));
        }
        if !directory.size.is_multiple_of(DEBUG_DIRECTORY_ENTRY_SIZE) {
            return Err(coverage_error(format!(
                "debug directory size {} is not a multiple of {DEBUG_DIRECTORY_ENTRY_SIZE}",
                directory.size
            )));
        }
        let entry_count: u64 = directory.size / DEBUG_DIRECTORY_ENTRY_SIZE;
        if entry_count > MAX_DEBUG_DIRECTORY_ENTRIES {
            return Err(coverage_error(format!(
                "debug directory entry count {entry_count} exceeds the supported bound \
                 {MAX_DEBUG_DIRECTORY_ENTRIES}"
            )));
        }
        let table_start: u64 = rva_range_to_file(
            directory.address,
            directory.size,
            size_of_headers,
            &sections,
            file_len,
            "the debug directory",
        )?;
        claims.refine(
            table_start,
            directory.size,
            RegionClass::Debug,
            "debug-directory",
        )?;

        let table_index: usize =
            usize::try_from(table_start).map_err(|_error: std::num::TryFromIntError| {
                coverage_error("the debug directory offset overflows")
            })?;
        for index in 0_u64..entry_count {
            let entry_delta: u64 = index
                .checked_mul(DEBUG_DIRECTORY_ENTRY_SIZE)
                .ok_or_else(|| coverage_error("a debug directory entry offset overflows"))?;
            let entry_offset: usize =
                usize::try_from(entry_delta).map_err(|_error: std::num::TryFromIntError| {
                    coverage_error("a debug directory entry offset overflows usize")
                })?;
            let data_size_offset: usize = entry_offset
                .checked_add(DEBUG_DATA_SIZE_OFFSET)
                .ok_or_else(|| coverage_error("the debug data size offset overflows"))?;
            let data_pointer_offset: usize = entry_offset
                .checked_add(DEBUG_DATA_POINTER_OFFSET)
                .ok_or_else(|| coverage_error("the debug data pointer offset overflows"))?;
            let data_size: u64 = u64::from(read_u32_at(
                bytes,
                table_index,
                data_size_offset,
                "the debug data size",
            )?);
            let data_offset: u64 = u64::from(read_u32_at(
                bytes,
                table_index,
                data_pointer_offset,
                "the debug data pointer",
            )?);
            if data_size == 0 {
                continue;
            }
            if data_offset == 0 {
                return Err(coverage_error(format!(
                    "debug data entry {index} has a nonzero size at file offset zero"
                )));
            }
            claims.refine(
                data_offset,
                data_size,
                RegionClass::Debug,
                format!("debug-data:{index}"),
            )?;
        }
    }

    if let Some(directory) =
        certificate.filter(|entry: &DataDirectory| entry.size > 0 && entry.address < file_len)
    {
        claims.claim_zero_alignment_before(
            directory.address,
            CERTIFICATE_ALIGNMENT,
            "certificate-alignment-padding",
        )?;
    }

    claims.finish(format)
}

fn claim_symbol_tables(
    claims: &mut ClaimSet<'_>,
    bytes: &[u8],
    symbol_table_offset: u32,
    symbol_count: u32,
) -> Result<()> {
    let start: u64 = u64::from(symbol_table_offset);
    let start_index: usize =
        usize::try_from(start).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("the symbol table offset overflows")
        })?;
    let admitted: usize = bounded_element_capacity(
        u64::from(symbol_count),
        SYMBOL_RECORD_BYTES,
        bytes.len().saturating_sub(start_index),
    );
    let table_bytes: u64 = u64::from(symbol_count)
        .checked_mul(SYMBOL_RECORD_SIZE)
        .ok_or_else(|| coverage_error("the symbol table range overflows"))?;
    claims.claim_payload(start, table_bytes, RegionClass::Table, "symbol-table")?;

    if admitted < usize::try_from(symbol_count).unwrap_or(usize::MAX) {
        return Ok(());
    }
    let string_start: u64 = start
        .checked_add(table_bytes)
        .ok_or_else(|| coverage_error("the string table offset overflows"))?;
    let string_index: usize =
        usize::try_from(string_start).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("the string table offset overflows")
        })?;
    let Ok(declared) = read_u32_at(bytes, string_index, 0, "the string table size") else {
        return Ok(());
    };
    claims.claim_payload(
        string_start,
        u64::from(declared.max(4)),
        RegionClass::Table,
        "string-table",
    )
}

fn read_section_record(reader: &mut ByteReader<'_>) -> Result<SectionRecord> {
    reader
        .skip(8)
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let virtual_size: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let virtual_address: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let raw_size: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let raw_offset: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    reader
        .skip(12)
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let characteristics: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;

    Ok(SectionRecord {
        virtual_size,
        virtual_address,
        raw_offset,
        raw_size,
        characteristics,
    })
}

fn read_directory(
    bytes: &[u8],
    directory_start: u64,
    directory_count: u64,
    index: u64,
    subject: &str,
) -> Result<Option<DataDirectory>> {
    if index >= directory_count {
        return Ok(None);
    }
    let directory_index: usize =
        usize::try_from(directory_start).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("the data directory offset overflows")
        })?;
    let record_offset: u64 = index
        .checked_mul(DIRECTORY_RECORD_SIZE)
        .ok_or_else(|| coverage_error(format!("{subject} record offset overflows")))?;
    let record_index: usize =
        usize::try_from(record_offset).map_err(|_error: std::num::TryFromIntError| {
            coverage_error(format!("{subject} record offset overflows usize"))
        })?;
    let address: u64 = u64::from(read_u32_at(
        bytes,
        directory_index,
        record_index,
        &format!("{subject} address"),
    )?);
    let size_offset: usize = record_index
        .checked_add(4)
        .ok_or_else(|| coverage_error(format!("{subject} size offset overflows")))?;
    let size: u64 = u64::from(read_u32_at(
        bytes,
        directory_index,
        size_offset,
        &format!("{subject} size"),
    )?);
    Ok(Some(DataDirectory { address, size }))
}

fn rva_range_to_file(
    rva: u64,
    size: u64,
    size_of_headers: u64,
    sections: &[PeSection],
    file_len: u64,
    subject: &str,
) -> Result<u64> {
    let rva_end: u64 = rva
        .checked_add(size)
        .ok_or_else(|| coverage_error(format!("{subject} RVA range overflows")))?;
    if rva_end <= size_of_headers {
        if rva_end > file_len {
            return Err(coverage_error(format!(
                "{subject} spans {rva}..{rva_end}, past the {file_len} byte input"
            )));
        }
        return Ok(rva);
    }

    for section in sections {
        if section.raw_offset == 0 || section.raw_size == 0 {
            continue;
        }
        let mapped_size: u64 = if section.virtual_size == 0 {
            section.raw_size
        } else {
            section.virtual_size.min(section.raw_size)
        };
        let section_end: u64 = section
            .virtual_address
            .checked_add(mapped_size)
            .ok_or_else(|| coverage_error("a PE section RVA range overflows"))?;
        if rva < section.virtual_address || rva_end > section_end {
            continue;
        }
        let delta: u64 = rva
            .checked_sub(section.virtual_address)
            .ok_or_else(|| coverage_error("a directory RVA precedes its section"))?;
        let raw_end: u64 = delta
            .checked_add(size)
            .ok_or_else(|| coverage_error(format!("{subject} raw range overflows")))?;
        if raw_end > section.raw_size {
            return Err(coverage_error(format!(
                "{subject} exceeds raw bytes for section {:?}",
                section.name
            )));
        }
        let file_offset: u64 = section
            .raw_offset
            .checked_add(delta)
            .ok_or_else(|| coverage_error(format!("{subject} file offset overflows")))?;
        let file_end: u64 = file_offset
            .checked_add(size)
            .ok_or_else(|| coverage_error(format!("{subject} file range overflows")))?;
        if file_end > file_len {
            return Err(coverage_error(format!(
                "{subject} spans {file_offset}..{file_end}, past the {file_len} byte input"
            )));
        }
        return Ok(file_offset);
    }

    Err(coverage_error(format!(
        "{subject} RVA 0x{rva:x} is not file-backed by a section"
    )))
}

fn section_name(bytes: &[u8], table_index: usize, index: usize) -> Result<String> {
    let start: usize = index
        .checked_mul(SECTION_RECORD_BYTES)
        .and_then(|offset: usize| table_index.checked_add(offset))
        .ok_or_else(|| coverage_error("a section record offset overflows"))?;
    let end: usize = start
        .checked_add(8)
        .ok_or_else(|| coverage_error("a section name range overflows"))?;
    let raw: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| coverage_error("a section name runs past the input"))?;
    let length: usize = raw
        .iter()
        .position(|value: &u8| *value == 0)
        .unwrap_or(raw.len());
    let name: &[u8] = raw
        .get(..length)
        .ok_or_else(|| coverage_error("a section name range is invalid"))?;

    Ok(String::from_utf8_lossy(name).into_owned())
}

fn section_class(name: &str, characteristics: u32) -> RegionClass {
    if characteristics & (object::pe::IMAGE_SCN_CNT_CODE | object::pe::IMAGE_SCN_MEM_EXECUTE) != 0 {
        return RegionClass::Code;
    }
    if name.starts_with(".debug") || name == ".stab" || name == ".stabstr" {
        return RegionClass::Debug;
    }
    RegionClass::Data
}

fn read_u32_at(bytes: &[u8], base: usize, offset: usize, subject: &str) -> Result<u32> {
    let position: usize = base
        .checked_add(offset)
        .ok_or_else(|| coverage_error(format!("{subject} offset overflows")))?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(position)
        .map_err(|error: ByteReadError| read_error(subject, error))?;
    reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error(subject, error))
}
