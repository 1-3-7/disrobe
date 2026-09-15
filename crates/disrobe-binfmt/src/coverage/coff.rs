use disrobe_bytes::{ByteReadError, ByteReader, bounded_element_capacity};

use crate::error::Result;
use crate::native::NativeFormat;
use crate::rewrite::coff::{CoffLayout, CoffLayoutError, decode_layout, format_class_id};

use super::{ByteCoverage, ClaimSet, RegionClass, UnbackedReason, coverage_error, read_error};

const SECTION_RECORD_SIZE: u64 = 40;
const SECTION_RECORD_BYTES: usize = 40;
const RELOCATION_RECORD_SIZE: u64 = 10;
const RELOCATION_RECORD_BYTES: usize = 10;
const LINE_NUMBER_RECORD_SIZE: u64 = 6;
const NAME_FIELD: usize = 8;
const RELOCATION_OVERFLOW: u16 = 0xFFFF;
const STRING_TABLE_MINIMUM: u64 = 4;

#[derive(Debug, Clone, Copy)]
struct SectionRecord {
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    relocation_offset: u32,
    line_number_offset: u32,
    relocation_count: u16,
    line_number_count: u16,
    characteristics: u32,
}

fn layout_coverage_error(error: CoffLayoutError) -> crate::error::Error {
    match error {
        CoffLayoutError::Read(context, source) => read_error(context, source),
        CoffLayoutError::BigObjVersion(version) => coverage_error(format!(
            "anonymous COFF version {version} is not bigobj version 2 or later"
        )),
        CoffLayoutError::BigObjClassId(class_id) => coverage_error(format!(
            "anonymous COFF class ID {} is not the Microsoft bigobj class ID",
            format_class_id(&class_id)
        )),
    }
}

pub(super) fn map_coff(bytes: &[u8]) -> Result<ByteCoverage> {
    let mut claims: ClaimSet<'_> = ClaimSet::new(bytes)?;
    let layout: CoffLayout = decode_layout(bytes).map_err(layout_coverage_error)?;
    let header_size: u64 = layout.header_size();
    let optional_size: u64 = layout.optional_size();
    let section_count: u64 = layout.section_count();
    claims.claim(0, header_size, RegionClass::Header, "coff-header")?;
    claims.claim(
        header_size,
        optional_size,
        RegionClass::Header,
        "optional-header",
    )?;

    let table_start: u64 = header_size
        .checked_add(optional_size)
        .ok_or_else(|| coverage_error("the section table offset overflows"))?;
    let table_index: usize =
        usize::try_from(table_start).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("the section table offset overflows")
        })?;
    let admitted: usize = bounded_element_capacity(
        section_count,
        SECTION_RECORD_BYTES,
        bytes.len().saturating_sub(table_index),
    );
    let requested_sections: usize =
        usize::try_from(section_count).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("NumberOfSections overflows usize")
        })?;
    if admitted < requested_sections {
        return Err(coverage_error(format!(
            "NumberOfSections {section_count} needs more than the {} bytes that follow the \
             section table",
            bytes.len().saturating_sub(table_index)
        )));
    }
    let table_bytes: u64 = section_count
        .checked_mul(SECTION_RECORD_SIZE)
        .ok_or_else(|| coverage_error("the section table range overflows"))?;
    claims.claim(
        table_start,
        table_bytes,
        RegionClass::Table,
        "section-table",
    )?;

    let string_table_start: u64 = claim_symbol_tables(
        &mut claims,
        bytes,
        layout.symbol_table_offset(),
        layout.symbol_count(),
        layout.symbol_record_size(),
    )?;
    let long_names: Option<(usize, usize)> = string_table_span(bytes, string_table_start);

    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(table_index)
        .map_err(|error: ByteReadError| read_error("the section table", error))?;
    for index in 0..requested_sections {
        let record: SectionRecord = read_section_record(&mut reader)?;
        let name: String = section_name(bytes, table_index, index, long_names)?;
        let claimant: String = format!("section:{name}");
        let raw_offset: u64 = u64::from(record.raw_offset);
        let raw_size: u64 = u64::from(record.raw_size);

        if raw_size == 0 {
            if record.virtual_size > 0 {
                claims.unbacked(
                    claimant.clone(),
                    u64::from(record.virtual_size),
                    UnbackedReason::NoFileBytes,
                );
            }
        } else if raw_offset == 0 {
            claims.unbacked(claimant.clone(), raw_size, UnbackedReason::NoFileOffset);
        } else {
            claims.claim_payload(
                raw_offset,
                raw_size,
                section_class(&name, record.characteristics),
                claimant.clone(),
            )?;
        }

        let relocation_count: u64 = resolved_relocation_count(bytes, &record)?;
        if relocation_count > 0 && record.relocation_offset != 0 {
            let length: u64 = relocation_count
                .checked_mul(RELOCATION_RECORD_SIZE)
                .ok_or_else(|| coverage_error("a relocation table range overflows"))?;
            claims.claim_payload(
                u64::from(record.relocation_offset),
                length,
                RegionClass::Table,
                format!("relocations:{name}"),
            )?;
        }

        if record.line_number_count > 0 && record.line_number_offset != 0 {
            let length: u64 = u64::from(record.line_number_count)
                .checked_mul(LINE_NUMBER_RECORD_SIZE)
                .ok_or_else(|| coverage_error("a line number table range overflows"))?;
            claims.claim_payload(
                u64::from(record.line_number_offset),
                length,
                RegionClass::Debug,
                format!("line-numbers:{name}"),
            )?;
        }
    }

    claims.finish(NativeFormat::Coff)
}

fn claim_symbol_tables(
    claims: &mut ClaimSet<'_>,
    bytes: &[u8],
    symbol_table_offset: u64,
    symbol_count: u64,
    symbol_record_size: u64,
) -> Result<u64> {
    if symbol_table_offset == 0 || symbol_count == 0 {
        return Ok(0);
    }
    let start_index: usize =
        usize::try_from(symbol_table_offset).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("the symbol table offset overflows")
        })?;
    let symbol_record_bytes: usize =
        usize::try_from(symbol_record_size).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("the symbol record size overflows")
        })?;
    let admitted: usize = bounded_element_capacity(
        symbol_count,
        symbol_record_bytes,
        bytes.len().saturating_sub(start_index),
    );
    let requested: usize =
        usize::try_from(symbol_count).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("SymbolCount overflows usize")
        })?;
    let table_bytes: u64 = symbol_count
        .checked_mul(symbol_record_size)
        .ok_or_else(|| coverage_error("the symbol table range overflows"))?;
    claims.claim_payload(
        symbol_table_offset,
        table_bytes,
        RegionClass::Table,
        "symbol-table",
    )?;
    if admitted < requested {
        return Ok(0);
    }

    let string_start: u64 = symbol_table_offset
        .checked_add(table_bytes)
        .ok_or_else(|| coverage_error("the string table offset overflows"))?;
    let string_index: usize =
        usize::try_from(string_start).map_err(|_error: std::num::TryFromIntError| {
            coverage_error("the string table offset overflows")
        })?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    if reader.seek(string_index).is_err() {
        return Ok(0);
    }
    let Ok(declared): std::result::Result<u32, ByteReadError> = reader.read_u32_le() else {
        return Ok(0);
    };
    claims.claim_payload(
        string_start,
        u64::from(declared).max(STRING_TABLE_MINIMUM),
        RegionClass::Table,
        "string-table",
    )?;

    Ok(string_start)
}

fn string_table_span(bytes: &[u8], start: u64) -> Option<(usize, usize)> {
    if start == 0 {
        return None;
    }
    let start_index: usize = usize::try_from(start).ok()?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(start_index).ok()?;
    let declared: u32 = reader.read_u32_le().ok()?;
    let size: usize = usize::try_from(declared).ok()?;
    let end: usize = start_index.checked_add(size)?.min(bytes.len());

    Some((start_index, end))
}

fn read_section_record(reader: &mut ByteReader<'_>) -> Result<SectionRecord> {
    reader
        .skip(NAME_FIELD)
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let virtual_size: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let _virtual_address: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let raw_size: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let raw_offset: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let relocation_offset: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let line_number_offset: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let relocation_count: u16 = reader
        .read_u16_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let line_number_count: u16 = reader
        .read_u16_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;
    let characteristics: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("a section record", error))?;

    Ok(SectionRecord {
        virtual_size,
        raw_offset,
        raw_size,
        relocation_offset,
        line_number_offset,
        relocation_count,
        line_number_count,
        characteristics,
    })
}

fn resolved_relocation_count(bytes: &[u8], record: &SectionRecord) -> Result<u64> {
    if record.relocation_count != RELOCATION_OVERFLOW
        || record.characteristics & object::pe::IMAGE_SCN_LNK_NRELOC_OVFL == 0
    {
        return Ok(u64::from(record.relocation_count));
    }
    let start: usize = usize::try_from(record.relocation_offset).map_err(
        |_error: std::num::TryFromIntError| coverage_error("a relocation table offset overflows"),
    )?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(start)
        .map_err(|error: ByteReadError| read_error("an extended relocation count", error))?;
    let count: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("an extended relocation count", error))?;
    let admitted: usize = bounded_element_capacity(
        u64::from(count),
        RELOCATION_RECORD_BYTES,
        bytes.len().saturating_sub(start),
    );
    if admitted < usize::try_from(count).unwrap_or(usize::MAX) {
        return Err(coverage_error(format!(
            "the extended relocation count {count} needs more than the {} bytes that follow it",
            bytes.len().saturating_sub(start)
        )));
    }

    Ok(u64::from(count))
}

fn section_name(
    bytes: &[u8],
    table_index: usize,
    index: usize,
    long_names: Option<(usize, usize)>,
) -> Result<String> {
    let start: usize = index
        .checked_mul(SECTION_RECORD_BYTES)
        .and_then(|offset: usize| table_index.checked_add(offset))
        .ok_or_else(|| coverage_error("a section record offset overflows"))?;
    let end: usize = start
        .checked_add(NAME_FIELD)
        .ok_or_else(|| coverage_error("a section name range overflows"))?;
    let raw: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| coverage_error("a section name runs past the input"))?;
    let length: usize = raw
        .iter()
        .position(|value: &u8| *value == 0)
        .unwrap_or(raw.len());
    let field: &[u8] = raw
        .get(..length)
        .ok_or_else(|| coverage_error("a section name range is invalid"))?;
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(field);

    let Some(digits): Option<&str> = text.strip_prefix('/') else {
        return Ok(text.into_owned());
    };
    let Ok(offset): std::result::Result<usize, std::num::ParseIntError> = digits.parse::<usize>()
    else {
        return Ok(text.into_owned());
    };
    let Some((table_start, table_end)): Option<(usize, usize)> = long_names else {
        return Ok(text.into_owned());
    };
    let Some(position): Option<usize> = table_start.checked_add(offset) else {
        return Ok(text.into_owned());
    };
    if position >= table_end {
        return Ok(text.into_owned());
    }
    let Some(window): Option<&[u8]> = bytes.get(position..table_end) else {
        return Ok(text.into_owned());
    };
    let long_length: usize = window
        .iter()
        .position(|value: &u8| *value == 0)
        .unwrap_or(window.len());
    let Some(long): Option<&[u8]> = window.get(..long_length) else {
        return Ok(text.into_owned());
    };
    if long.is_empty() {
        return Ok(text.into_owned());
    }

    Ok(String::from_utf8_lossy(long).into_owned())
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
