use disrobe_bytes::{ByteReadError, ByteReader};

use crate::error::Result;
use crate::native::NativeFormat;

use super::encode::FieldWriter;
use super::{
    ImagePlan, PlanBuilder, Structure, bounded_entries, rewrite_error, rewrite_read_error,
    unsupported,
};

pub(crate) const COFF_HEADER_SIZE: u64 = 20;
pub(crate) const SECTION_RECORD_SIZE: u64 = 40;
const BIGOBJ_SIG1: u16 = 0x0000;
const BIGOBJ_SIG2: u16 = 0xFFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl CoffHeader {
    pub(super) const ENCODED_LEN: u64 = COFF_HEADER_SIZE;

    pub(super) fn encode(&self, writer: &mut FieldWriter<'_>) {
        writer.u16(self.machine);
        writer.u16(self.number_of_sections);
        writer.u32(self.time_date_stamp);
        writer.u32(self.pointer_to_symbol_table);
        writer.u32(self.number_of_symbols);
        writer.u16(self.size_of_optional_header);
        writer.u16(self.characteristics);
    }

    pub(super) fn read(reader: &mut ByteReader<'_>) -> Result<Self> {
        let machine: u16 = reader
            .read_u16_le()
            .map_err(|error: ByteReadError| rewrite_read_error("the COFF header", error))?;
        let number_of_sections: u16 = reader
            .read_u16_le()
            .map_err(|error: ByteReadError| rewrite_read_error("the COFF header", error))?;
        let time_date_stamp: u32 = reader
            .read_u32_le()
            .map_err(|error: ByteReadError| rewrite_read_error("the COFF header", error))?;
        let pointer_to_symbol_table: u32 = reader
            .read_u32_le()
            .map_err(|error: ByteReadError| rewrite_read_error("the COFF header", error))?;
        let number_of_symbols: u32 = reader
            .read_u32_le()
            .map_err(|error: ByteReadError| rewrite_read_error("the COFF header", error))?;
        let size_of_optional_header: u16 = reader
            .read_u16_le()
            .map_err(|error: ByteReadError| rewrite_read_error("the COFF header", error))?;
        let characteristics: u16 = reader
            .read_u16_le()
            .map_err(|error: ByteReadError| rewrite_read_error("the COFF header", error))?;

        Ok(Self {
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl CoffSectionHeader {
    fn encode(&self, writer: &mut FieldWriter<'_>) {
        writer.bytes(&self.name);
        writer.u32(self.virtual_size);
        writer.u32(self.virtual_address);
        writer.u32(self.size_of_raw_data);
        writer.u32(self.pointer_to_raw_data);
        writer.u32(self.pointer_to_relocations);
        writer.u32(self.pointer_to_linenumbers);
        writer.u16(self.number_of_relocations);
        writer.u16(self.number_of_linenumbers);
        writer.u32(self.characteristics);
    }

    fn read(reader: &mut ByteReader<'_>) -> Result<Self> {
        let raw: &[u8] = reader
            .read_bytes(8)
            .map_err(|error: ByteReadError| rewrite_read_error("a section name", error))?;
        let name: [u8; 8] =
            <[u8; 8]>::try_from(raw).map_err(|_error: std::array::TryFromSliceError| {
                rewrite_error("a section name is short")
            })?;
        let virtual_size: u32 = reader
            .read_u32_le()
            .map_err(|error: ByteReadError| rewrite_read_error("a section record", error))?;
        let virtual_address: u32 = reader
            .read_u32_le()
            .map_err(|error: ByteReadError| rewrite_read_error("a section record", error))?;
        let size_of_raw_data: u32 = reader
            .read_u32_le()
            .map_err(|error: ByteReadError| rewrite_read_error("a section record", error))?;
        let pointer_to_raw_data: u32 = reader
            .read_u32_le()
            .map_err(|error: ByteReadError| rewrite_read_error("a section record", error))?;
        let pointer_to_relocations: u32 = reader
            .read_u32_le()
            .map_err(|error: ByteReadError| rewrite_read_error("a section record", error))?;
        let pointer_to_linenumbers: u32 = reader
            .read_u32_le()
            .map_err(|error: ByteReadError| rewrite_read_error("a section record", error))?;
        let number_of_relocations: u16 = reader
            .read_u16_le()
            .map_err(|error: ByteReadError| rewrite_read_error("a section record", error))?;
        let number_of_linenumbers: u16 = reader
            .read_u16_le()
            .map_err(|error: ByteReadError| rewrite_read_error("a section record", error))?;
        let characteristics: u32 = reader
            .read_u32_le()
            .map_err(|error: ByteReadError| rewrite_read_error("a section record", error))?;

        Ok(Self {
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            pointer_to_relocations,
            pointer_to_linenumbers,
            number_of_relocations,
            number_of_linenumbers,
            characteristics,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffSectionTable {
    pub sections: Vec<CoffSectionHeader>,
}

impl CoffSectionTable {
    pub(super) const fn encoded_len(&self) -> u64 {
        (self.sections.len() as u64).saturating_mul(SECTION_RECORD_SIZE)
    }

    pub(super) fn encode(&self, writer: &mut FieldWriter<'_>) {
        for section in &self.sections {
            section.encode(writer);
        }
    }

    pub(super) fn read(reader: &mut ByteReader<'_>, count: usize) -> Result<Self> {
        let mut sections: Vec<CoffSectionHeader> = Vec::with_capacity(count);
        for _ in 0..count {
            sections.push(CoffSectionHeader::read(reader)?);
        }
        Ok(Self { sections })
    }
}

pub(super) fn plan_header_and_sections(
    builder: &mut PlanBuilder,
    bytes: &[u8],
    header_start: u64,
) -> Result<CoffHeader> {
    let header_index: usize =
        usize::try_from(header_start).map_err(|_error: std::num::TryFromIntError| {
            rewrite_error("the COFF header offset overflows")
        })?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(header_index)
        .map_err(|error: ByteReadError| rewrite_read_error("the COFF header", error))?;
    let header: CoffHeader = CoffHeader::read(&mut reader)?;
    builder.push(header_start, Structure::CoffHeader(header))?;

    let optional_size: u64 = u64::from(header.size_of_optional_header);
    let table_start: u64 = header_start
        .checked_add(COFF_HEADER_SIZE)
        .and_then(|value: u64| value.checked_add(optional_size))
        .ok_or_else(|| rewrite_error("the section table offset overflows"))?;
    plan_section_table(
        builder,
        bytes,
        table_start,
        u64::from(header.number_of_sections),
    )?;

    Ok(header)
}

pub(super) fn plan_section_table(
    builder: &mut PlanBuilder,
    bytes: &[u8],
    table_start: u64,
    declared: u64,
) -> Result<()> {
    if declared == 0 {
        return Ok(());
    }
    let table_index: usize =
        usize::try_from(table_start).map_err(|_error: std::num::TryFromIntError| {
            rewrite_error("the section table offset overflows")
        })?;
    let available: u64 = builder.file_len().saturating_sub(table_start);
    let count: usize = bounded_entries(
        builder.format(),
        "the section table",
        declared,
        SECTION_RECORD_SIZE,
        available,
    )?;

    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(table_index)
        .map_err(|error: ByteReadError| rewrite_read_error("the section table", error))?;
    let table: CoffSectionTable = CoffSectionTable::read(&mut reader, count)?;
    builder.push(table_start, Structure::CoffSectionTable(table))
}

pub(super) fn plan(bytes: &[u8]) -> Result<ImagePlan> {
    let file_len: u64 = u64::try_from(bytes.len())
        .map_err(|_error: std::num::TryFromIntError| rewrite_error("file length overflows"))?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let sig1: u16 = reader
        .read_u16_le()
        .map_err(|error: ByteReadError| rewrite_read_error("the COFF header", error))?;
    let sig2: u16 = reader
        .read_u16_le()
        .map_err(|error: ByteReadError| rewrite_read_error("the COFF header", error))?;
    if sig1 == BIGOBJ_SIG1 && sig2 == BIGOBJ_SIG2 {
        return Err(unsupported(
            NativeFormat::Coff,
            "the extended `bigobj` COFF header has no typed model in this writer",
        ));
    }

    let mut builder: PlanBuilder = PlanBuilder::new(NativeFormat::Coff, file_len);
    let header: CoffHeader = plan_header_and_sections(&mut builder, bytes, 0)?;
    if header.size_of_optional_header != 0 {
        return Err(unsupported(
            NativeFormat::Coff,
            format!(
                "a bare COFF object declares a {} byte optional header, which has no typed model \
                 in this writer",
                header.size_of_optional_header
            ),
        ));
    }
    builder.finish()
}
