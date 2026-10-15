use disrobe_bytes::{ByteReadError, read_u32_le_at, read_u64_le_at};
use serde::{Deserialize, Serialize};

use super::dart_graph_layout::DartCodeTableLayout;
use super::snapshot::{ImageHeader, parse_image_header};
use crate::error::{Error, Result};

const OBJECT_START_ALIGNMENT: usize = 64;

const SNAPSHOT_MAGIC_BYTES: usize = 4;

const MAX_CODE_TABLE_ENTRIES: usize = 1 << 22;

const INSTRUCTIONS_SECTION_PAYLOAD_LENGTH_OFFSET: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartCodeTableEntry {
    pub instructions_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartCodeTable {
    pub rodata_image_offset: usize,
    pub rodata_image_size: u64,
    pub descriptor_offset: usize,
    pub first_entry_with_code: usize,
    pub entries: Vec<DartCodeTableEntry>,
}

impl DartCodeTable {
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn instructions_offset(&self, code_index: u64) -> Option<u64> {
        let ordinal: usize = usize::try_from(code_index).ok()?.checked_sub(1)?;
        self.entries
            .get(ordinal)
            .map(|entry: &DartCodeTableEntry| entry.instructions_offset)
    }

    #[must_use]
    pub fn payload_span(&self, code_index: u64, image_len: usize) -> Option<(u64, u64)> {
        let ordinal: usize = usize::try_from(code_index).ok()?.checked_sub(1)?;
        let start: u64 = self
            .entries
            .get(ordinal)
            .map(|entry: &DartCodeTableEntry| entry.instructions_offset)?;
        let end: u64 = self.entries.get(ordinal + 1).map_or_else(
            || u64::try_from(image_len).unwrap_or(u64::MAX),
            |entry: &DartCodeTableEntry| entry.instructions_offset,
        );
        (end > start).then_some((start, end))
    }
}

#[must_use]
pub fn instructions_payload_end(isolate_instructions: &[u8], table: &DartCodeTable) -> Option<u64> {
    let header: ImageHeader = parse_image_header(isolate_instructions)?;
    let section: usize = usize::try_from(header.instructions_section_offset).ok()?;
    let payload_length: u64 = read_u64_le_at(
        isolate_instructions,
        section.checked_add(INSTRUCTIONS_SECTION_PAYLOAD_LENGTH_OFFSET)?,
    )
    .ok()?;
    let end: u64 = table
        .entries
        .first()?
        .instructions_offset
        .checked_add(payload_length)?;
    let last: u64 = table.entries.last()?.instructions_offset;
    (last < end && end <= u64::try_from(isolate_instructions.len()).ok()?).then_some(end)
}

fn image_spans_to_section_end(isolate_data: &[u8], offset: usize) -> bool {
    let Some(image): Option<&[u8]> = isolate_data.get(offset..) else {
        return false;
    };
    let Some(header): Option<ImageHeader> = parse_image_header(image) else {
        return false;
    };
    header.image_size != 0 && header.image_size == u64::try_from(image.len()).unwrap_or(u64::MAX)
}

#[must_use]
pub fn rodata_image_offset(isolate_data: &[u8]) -> Option<usize> {
    let stored: usize =
        usize::try_from(super::parse_dart_snapshot(isolate_data).ok()?.length).ok()?;
    let aligned: usize = stored
        .checked_add(SNAPSHOT_MAGIC_BYTES + OBJECT_START_ALIGNMENT - 1)
        .map(|raised: usize| raised & !(OBJECT_START_ALIGNMENT - 1))?;
    (aligned < isolate_data.len() && image_spans_to_section_end(isolate_data, aligned))
        .then_some(aligned)
}

fn read_descriptor_word(image: &[u8], offset: usize, reason: &'static str) -> Result<usize> {
    let value: u32 = read_u32_le_at(image, offset)
        .map_err(|_: ByteReadError| Error::DartCodeTableUnavailable { reason })?;
    usize::try_from(value)
        .map_err(|_: std::num::TryFromIntError| Error::DartCodeTableUnavailable { reason })
}

pub fn parse_code_table(
    isolate_data: &[u8],
    isolate_instructions_len: usize,
    instructions_table_len: usize,
    instruction_table_data_offset: usize,
    layout: DartCodeTableLayout,
) -> Result<DartCodeTable> {
    if instructions_table_len == 0 {
        return Err(Error::DartCodeTableUnavailable {
            reason: "the isolate snapshot preamble declares no instructions-table entries, so this image carries no code-index-to-payload mapping",
        });
    }
    if instructions_table_len > MAX_CODE_TABLE_ENTRIES {
        return Err(Error::DartCodeTableUnavailable {
            reason: "the declared instructions-table entry count exceeds the reader cap",
        });
    }
    if instruction_table_data_offset == 0 {
        return Err(Error::DartCodeTableUnavailable {
            reason: "the isolate snapshot preamble carries no instructions-table data offset, so the table was not serialized into the read-only image",
        });
    }
    let image_offset: usize = rodata_image_offset(isolate_data).ok_or(
        Error::DartCodeTableUnavailable {
            reason: "no read-only image begins at the end of the isolate snapshot stream rounded up to the 64-byte object start alignment",
        },
    )?;
    let image: &[u8] = isolate_data
        .get(image_offset..)
        .ok_or(Error::DartCodeTableUnavailable {
            reason: "the computed read-only image offset is outside the isolate snapshot section",
        })?;
    let header: ImageHeader = parse_image_header(image).ok_or(Error::DartCodeTableUnavailable {
        reason: "the read-only image header is truncated",
    })?;
    if header.image_size != u64::try_from(image.len()).unwrap_or(u64::MAX) {
        return Err(Error::DartCodeTableUnavailable {
            reason: "the read-only image header size does not cover the remainder of the isolate snapshot section, so the computed image offset is not an image",
        });
    }
    let descriptor_offset: usize = instruction_table_data_offset
        .checked_add(layout.object_header_bytes)
        .ok_or(Error::DartCodeTableUnavailable {
            reason: "the instructions-table object offset overflows",
        })?;
    let declared: usize = read_descriptor_word(
        image,
        descriptor_offset,
        "the instructions-table descriptor is outside the read-only image",
    )?;
    if declared < instructions_table_len || declared > MAX_CODE_TABLE_ENTRIES {
        return Err(Error::DartCodeTableLengthMismatch {
            offset: descriptor_offset,
            declared,
            expected: instructions_table_len,
        });
    }
    let first_entry_with_code: usize = read_descriptor_word(
        image,
        descriptor_offset
            .checked_add(layout.first_entry_with_code_offset)
            .ok_or(Error::DartCodeTableUnavailable {
                reason: "the instructions-table descriptor offset overflows",
            })?,
        "the instructions-table first-entry-with-code word is outside the read-only image",
    )?;
    if first_entry_with_code != declared - instructions_table_len {
        return Err(Error::DartCodeTableUnavailable {
            reason: "the instructions table does not end in exactly the entries the preamble counts as carrying a code object",
        });
    }
    let entries_offset: usize = descriptor_offset
        .checked_add(layout.descriptor_bytes)
        .ok_or(Error::DartCodeTableUnavailable {
            reason: "the instructions-table entry array offset overflows",
        })?;
    let span: usize =
        declared
            .checked_mul(layout.entry_stride)
            .ok_or(Error::DartCodeTableUnavailable {
                reason: "the instructions-table entry array size overflows",
            })?;
    if entries_offset.saturating_add(span) > image.len() {
        return Err(Error::DartCodeTableUnavailable {
            reason: "the instructions-table entry array runs past the read-only image",
        });
    }
    let mut entries: Vec<DartCodeTableEntry> = Vec::with_capacity(declared);
    let mut previous: Option<u64> = None;
    for index in 0..declared {
        let at: usize = entries_offset + index * layout.entry_stride;
        let instructions_offset: u64 =
            u64::from(read_u32_le_at(image, at).map_err(|_: ByteReadError| {
                Error::DartCodeTableUnavailable {
                    reason: "an instructions-table entry is outside the read-only image",
                }
            })?);
        let ascending: bool = previous.is_none_or(|last: u64| instructions_offset > last);
        if !ascending
            || instructions_offset >= u64::try_from(isolate_instructions_len).unwrap_or(u64::MAX)
        {
            return Err(Error::DartCodeTableEntryOutOfOrder {
                index,
                offset: instructions_offset,
                limit: isolate_instructions_len,
            });
        }
        previous = Some(instructions_offset);
        entries.push(DartCodeTableEntry {
            instructions_offset,
        });
    }
    Ok(DartCodeTable {
        rodata_image_offset: image_offset,
        rodata_image_size: header.image_size,
        descriptor_offset,
        first_entry_with_code,
        entries,
    })
}
