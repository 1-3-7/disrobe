use disrobe_bytes::{ByteReadError, ByteReader};
use std::fmt::Write as _;

use crate::error::Result;
use crate::native::NativeFormat;

use super::encode::FieldWriter;
use super::{
    ImagePlan, PlanBuilder, Structure, bounded_entries, rewrite_error, rewrite_read_error,
    unsupported,
};

pub(crate) const COFF_HEADER_SIZE: u64 = 20;
pub(crate) const BIGOBJ_HEADER_SIZE: u64 = 56;
pub(crate) const SECTION_RECORD_SIZE: u64 = 40;
pub(crate) const COFF_SYMBOL_RECORD_SIZE: u64 = 18;
pub(crate) const BIGOBJ_SYMBOL_RECORD_SIZE: u64 = 20;
const BIGOBJ_SIG1: u16 = 0x0000;
const BIGOBJ_SIG2: u16 = 0xFFFF;
const BIGOBJ_CLASS_ID: [u8; 16] = [
    0xC7, 0xA1, 0xBA, 0xD1, 0xEE, 0xBA, 0xA9, 0x4B, 0xAF, 0x20, 0xFA, 0xF6, 0x6A, 0xA4, 0xDC, 0xB8,
];

#[derive(Debug)]
pub(crate) enum CoffLayoutError {
    Read(&'static str, ByteReadError),
    BigObjVersion(u16),
    BigObjClassId([u8; 16]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoffLayout {
    Standard(CoffHeader),
    BigObj(CoffBigObjHeader),
}

impl CoffLayout {
    pub(crate) const fn header_size(self) -> u64 {
        match self {
            Self::Standard(_) => COFF_HEADER_SIZE,
            Self::BigObj(_) => BIGOBJ_HEADER_SIZE,
        }
    }

    pub(crate) const fn optional_size(self) -> u64 {
        match self {
            Self::Standard(header) => header.size_of_optional_header as u64,
            Self::BigObj(_) => 0,
        }
    }

    pub(crate) const fn section_count(self) -> u64 {
        match self {
            Self::Standard(header) => header.number_of_sections as u64,
            Self::BigObj(header) => header.number_of_sections as u64,
        }
    }

    pub(crate) const fn symbol_table_offset(self) -> u64 {
        match self {
            Self::Standard(header) => header.pointer_to_symbol_table as u64,
            Self::BigObj(header) => header.pointer_to_symbol_table as u64,
        }
    }

    pub(crate) const fn symbol_count(self) -> u64 {
        match self {
            Self::Standard(header) => header.number_of_symbols as u64,
            Self::BigObj(header) => header.number_of_symbols as u64,
        }
    }

    pub(crate) const fn symbol_record_size(self) -> u64 {
        match self {
            Self::Standard(_) => COFF_SYMBOL_RECORD_SIZE,
            Self::BigObj(_) => BIGOBJ_SYMBOL_RECORD_SIZE,
        }
    }
}

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
        Self::read_raw(reader)
            .map_err(|error: ByteReadError| rewrite_read_error("the COFF header", error))
    }

    fn read_raw(reader: &mut ByteReader<'_>) -> std::result::Result<Self, ByteReadError> {
        let machine: u16 = reader.read_u16_le()?;
        let number_of_sections: u16 = reader.read_u16_le()?;
        let time_date_stamp: u32 = reader.read_u32_le()?;
        let pointer_to_symbol_table: u32 = reader.read_u32_le()?;
        let number_of_symbols: u32 = reader.read_u32_le()?;
        let size_of_optional_header: u16 = reader.read_u16_le()?;
        let characteristics: u16 = reader.read_u16_le()?;
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
pub struct CoffBigObjHeader {
    pub sig1: u16,
    pub sig2: u16,
    pub version: u16,
    pub machine: u16,
    pub time_date_stamp: u32,
    pub class_id: [u8; 16],
    pub size_of_data: u32,
    pub flags: u32,
    pub meta_data_size: u32,
    pub meta_data_offset: u32,
    pub number_of_sections: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
}

impl CoffBigObjHeader {
    pub(super) const ENCODED_LEN: u64 = BIGOBJ_HEADER_SIZE;

    pub(super) fn encode(&self, writer: &mut FieldWriter<'_>) {
        writer.u16(self.sig1);
        writer.u16(self.sig2);
        writer.u16(self.version);
        writer.u16(self.machine);
        writer.u32(self.time_date_stamp);
        writer.bytes(&self.class_id);
        writer.u32(self.size_of_data);
        writer.u32(self.flags);
        writer.u32(self.meta_data_size);
        writer.u32(self.meta_data_offset);
        writer.u32(self.number_of_sections);
        writer.u32(self.pointer_to_symbol_table);
        writer.u32(self.number_of_symbols);
    }

    fn read_raw(reader: &mut ByteReader<'_>) -> std::result::Result<Self, ByteReadError> {
        let sig1: u16 = reader.read_u16_le()?;
        let sig2: u16 = reader.read_u16_le()?;
        let version: u16 = reader.read_u16_le()?;
        let machine: u16 = reader.read_u16_le()?;
        let time_date_stamp: u32 = reader.read_u32_le()?;
        let class_id_bytes: &[u8] = reader.read_bytes(16)?;
        let class_id: [u8; 16] = <[u8; 16]>::try_from(class_id_bytes).map_err(
            |_error: std::array::TryFromSliceError| ByteReadError {
                offset: 12,
                needed: 16,
                available: class_id_bytes.len(),
            },
        )?;
        let size_of_data: u32 = reader.read_u32_le()?;
        let flags: u32 = reader.read_u32_le()?;
        let meta_data_size: u32 = reader.read_u32_le()?;
        let meta_data_offset: u32 = reader.read_u32_le()?;
        let number_of_sections: u32 = reader.read_u32_le()?;
        let pointer_to_symbol_table: u32 = reader.read_u32_le()?;
        let number_of_symbols: u32 = reader.read_u32_le()?;
        Ok(Self {
            sig1,
            sig2,
            version,
            machine,
            time_date_stamp,
            class_id,
            size_of_data,
            flags,
            meta_data_size,
            meta_data_offset,
            number_of_sections,
            pointer_to_symbol_table,
            number_of_symbols,
        })
    }
}

pub(crate) fn format_class_id(class_id: &[u8; 16]) -> String {
    let mut rendered: String = String::with_capacity(class_id.len() * 2);
    for byte in class_id {
        let _ = write!(rendered, "{byte:02x}");
    }
    rendered
}

pub(crate) fn decode_layout(bytes: &[u8]) -> std::result::Result<CoffLayout, CoffLayoutError> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let sig1: u16 = reader
        .read_u16_le()
        .map_err(|error: ByteReadError| CoffLayoutError::Read("the COFF header", error))?;
    let sig2: u16 = reader
        .read_u16_le()
        .map_err(|error: ByteReadError| CoffLayoutError::Read("the COFF header", error))?;
    let mut full_reader: ByteReader<'_> = ByteReader::new(bytes);
    if sig1 != BIGOBJ_SIG1 || sig2 != BIGOBJ_SIG2 {
        let header: CoffHeader = CoffHeader::read_raw(&mut full_reader)
            .map_err(|error: ByteReadError| CoffLayoutError::Read("the COFF header", error))?;
        return Ok(CoffLayout::Standard(header));
    }
    let header: CoffBigObjHeader = CoffBigObjHeader::read_raw(&mut full_reader)
        .map_err(|error: ByteReadError| CoffLayoutError::Read("the COFF bigobj header", error))?;
    if header.version < 2 {
        return Err(CoffLayoutError::BigObjVersion(header.version));
    }
    if header.class_id != BIGOBJ_CLASS_ID {
        return Err(CoffLayoutError::BigObjClassId(header.class_id));
    }
    Ok(CoffLayout::BigObj(header))
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
    let layout: CoffLayout = decode_layout(bytes).map_err(layout_rewrite_error)?;
    let mut builder: PlanBuilder = PlanBuilder::new(NativeFormat::Coff, file_len);
    let table_start: u64 = match layout {
        CoffLayout::Standard(header) => {
            if header.size_of_optional_header != 0 {
                return Err(unsupported(
                    NativeFormat::Coff,
                    format!(
                        "a bare COFF object declares a {} byte optional header, which has no \
                         typed model in this writer",
                        header.size_of_optional_header
                    ),
                ));
            }
            builder.push(0, Structure::CoffHeader(header))?;
            COFF_HEADER_SIZE
        }
        CoffLayout::BigObj(header) => {
            builder.push(0, Structure::CoffBigObjHeader(header))?;
            BIGOBJ_HEADER_SIZE
        }
    };
    plan_section_table(&mut builder, bytes, table_start, layout.section_count())?;
    builder.finish()
}

fn layout_rewrite_error(error: CoffLayoutError) -> crate::error::Error {
    match error {
        CoffLayoutError::Read(context, source) => rewrite_read_error(context, source),
        CoffLayoutError::BigObjVersion(version) => unsupported(
            NativeFormat::Coff,
            format!("anonymous COFF version {version} is not bigobj version 2 or later"),
        ),
        CoffLayoutError::BigObjClassId(class_id) => unsupported(
            NativeFormat::Coff,
            format!(
                "anonymous COFF class ID {} is not the Microsoft bigobj class ID",
                format_class_id(&class_id)
            ),
        ),
    }
}
