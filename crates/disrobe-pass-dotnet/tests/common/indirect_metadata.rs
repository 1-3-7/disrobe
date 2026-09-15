#![allow(dead_code, clippy::redundant_pub_crate, unreachable_pub)]

use std::collections::BTreeMap;

use disrobe_pass_dotnet::metadata::StreamHeader;
use disrobe_pass_dotnet::tables::{TableSpan, table_spans};

const COM_DESCRIPTOR_DIRECTORY: usize = 14;
const METADATA_SIGNATURE: u32 = 0x424A_5342;
const PARAM_TABLE: u8 = 0x08;
const PARAM_PTR_TABLE: u8 = 0x07;
const SECTION_HEADER_LEN: usize = 40;
const SECTION_READABLE_DATA: u32 = 0x4000_0040;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParamPtrShape {
    Faithful,
    IdentityPointerOverPermutedRows,
}

#[derive(Debug)]
pub(crate) struct BuildError(String);

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn err<T>(message: impl Into<String>) -> Result<T, BuildError> {
    Err(BuildError(message.into()))
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, BuildError> {
    let slice: &[u8] = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| BuildError(format!("truncated u16 at {offset}")))?;
    let array: [u8; 2] = slice.try_into().map_err(|_| BuildError("u16".to_owned()))?;
    Ok(u16::from_le_bytes(array))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, BuildError> {
    let slice: &[u8] = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| BuildError(format!("truncated u32 at {offset}")))?;
    let array: [u8; 4] = slice.try_into().map_err(|_| BuildError("u32".to_owned()))?;
    Ok(u32::from_le_bytes(array))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, BuildError> {
    let slice: &[u8] = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or_else(|| BuildError(format!("truncated u64 at {offset}")))?;
    let array: [u8; 8] = slice.try_into().map_err(|_| BuildError("u64".to_owned()))?;
    Ok(u64::from_le_bytes(array))
}

const fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    value.div_ceil(alignment).saturating_mul(alignment)
}

#[derive(Debug, Clone, Copy)]
struct PeLayout {
    pe_offset: usize,
    section_count: u16,
    optional_header_size: u16,
    section_table: usize,
    section_alignment: u32,
    file_alignment: u32,
    size_of_headers: u32,
    size_of_image_field: usize,
    directories: usize,
    directory_count: u32,
}

fn read_layout(image: &[u8]) -> Result<PeLayout, BuildError> {
    if image.get(..2) != Some(b"MZ") {
        return err("not a PE image");
    }
    let pe_offset: usize = u32_at(image, 0x3C)? as usize;
    if image.get(pe_offset..pe_offset.saturating_add(4)) != Some(b"PE\0\0") {
        return err("missing PE signature");
    }
    let section_count: u16 = u16_at(image, pe_offset.saturating_add(6))?;
    let optional_header_size: u16 = u16_at(image, pe_offset.saturating_add(20))?;
    let optional: usize = pe_offset.saturating_add(24);
    let magic: u16 = u16_at(image, optional)?;
    let plus: bool = magic == 0x20B;
    let section_alignment: u32 = u32_at(image, optional.saturating_add(32))?;
    let file_alignment: u32 = u32_at(image, optional.saturating_add(36))?;
    let size_of_image_field: usize = optional.saturating_add(56);
    let size_of_headers: u32 = u32_at(image, optional.saturating_add(60))?;
    let count_offset: usize = optional.saturating_add(if plus { 108 } else { 92 });
    let directory_count: u32 = u32_at(image, count_offset)?;
    Ok(PeLayout {
        pe_offset,
        section_count,
        optional_header_size,
        section_table: optional.saturating_add(optional_header_size as usize),
        section_alignment,
        file_alignment,
        size_of_headers,
        size_of_image_field,
        directories: count_offset.saturating_add(4),
        directory_count,
    })
}

fn rva_to_offset(image: &[u8], layout: PeLayout, rva: u32) -> Result<usize, BuildError> {
    for index in 0..layout.section_count as usize {
        let header: usize = layout
            .section_table
            .saturating_add(index.saturating_mul(SECTION_HEADER_LEN));
        let virtual_size: u32 = u32_at(image, header.saturating_add(8))?;
        let virtual_address: u32 = u32_at(image, header.saturating_add(12))?;
        let raw_size: u32 = u32_at(image, header.saturating_add(16))?;
        let raw_pointer: u32 = u32_at(image, header.saturating_add(20))?;
        let span: u32 = virtual_size.max(raw_size);
        if rva >= virtual_address && rva < virtual_address.saturating_add(span) {
            return Ok(raw_pointer.saturating_add(rva - virtual_address) as usize);
        }
    }
    err(format!("rva {rva:#x} is outside every section"))
}

#[derive(Debug, Clone)]
struct StreamEntry {
    name: String,
    offset: u32,
    size: u32,
    header_offset: usize,
}

fn read_streams(metadata: &[u8]) -> Result<Vec<StreamEntry>, BuildError> {
    if u32_at(metadata, 0)? != METADATA_SIGNATURE {
        return err("metadata root signature is wrong");
    }
    let version_length: u32 = u32_at(metadata, 12)?;
    let count_offset: usize = 16usize
        .saturating_add(version_length as usize)
        .saturating_add(2);
    let stream_count: u16 = u16_at(metadata, count_offset)?;
    let mut cursor: usize = count_offset.saturating_add(2);
    let mut out: Vec<StreamEntry> = Vec::with_capacity(stream_count as usize);
    for _ in 0..stream_count {
        let header_offset: usize = cursor;
        let offset: u32 = u32_at(metadata, cursor)?;
        let size: u32 = u32_at(metadata, cursor.saturating_add(4))?;
        let name_start: usize = cursor.saturating_add(8);
        let mut end: usize = name_start;
        while metadata.get(end).copied().unwrap_or(0) != 0 {
            end = end.saturating_add(1);
            if end.saturating_sub(name_start) > 32 {
                return err("stream name is not terminated");
            }
        }
        let name: String = String::from_utf8_lossy(
            metadata
                .get(name_start..end)
                .ok_or_else(|| BuildError("stream name".to_owned()))?,
        )
        .into_owned();
        let padded: usize = end
            .saturating_sub(name_start)
            .saturating_div(4)
            .saturating_add(1)
            .saturating_mul(4);
        cursor = name_start.saturating_add(padded);
        out.push(StreamEntry {
            name,
            offset,
            size,
            header_offset,
        });
    }
    Ok(out)
}

pub(crate) fn build_param_ptr_image(
    image: &[u8],
    shape: ParamPtrShape,
) -> Result<Vec<u8>, BuildError> {
    let layout: PeLayout = read_layout(image)?;
    if layout.directory_count <= COM_DESCRIPTOR_DIRECTORY as u32 {
        return err("image carries no CLR directory");
    }
    let clr_directory: usize = layout
        .directories
        .saturating_add(COM_DESCRIPTOR_DIRECTORY.saturating_mul(8));
    let clr_rva: u32 = u32_at(image, clr_directory)?;
    let clr_offset: usize = rva_to_offset(image, layout, clr_rva)?;
    let metadata_rva: u32 = u32_at(image, clr_offset.saturating_add(8))?;
    let metadata_size: u32 = u32_at(image, clr_offset.saturating_add(12))?;
    let metadata_offset: usize = rva_to_offset(image, layout, metadata_rva)?;
    let metadata: &[u8] = image
        .get(metadata_offset..metadata_offset.saturating_add(metadata_size as usize))
        .ok_or_else(|| BuildError("metadata is truncated".to_owned()))?;

    let streams: Vec<StreamEntry> = read_streams(metadata)?;
    let tables_stream: &StreamEntry = streams
        .iter()
        .find(|s: &&StreamEntry| s.name == "#~" || s.name == "#-")
        .ok_or_else(|| BuildError("no table stream".to_owned()))?;
    let stream_start: usize = tables_stream.offset as usize;
    let stream: &[u8] = metadata
        .get(stream_start..stream_start.saturating_add(tables_stream.size as usize))
        .ok_or_else(|| BuildError("table stream is truncated".to_owned()))?;

    let valid: u64 = u64_at(stream, 8)?;
    if (valid >> PARAM_PTR_TABLE) & 1 == 1 {
        return err("image already carries a ParamPtr table");
    }
    let mut row_counts: BTreeMap<u8, u32> = BTreeMap::new();
    let mut cursor: usize = 24;
    for table in 0u8..64u8 {
        if (valid >> table) & 1 == 1 {
            row_counts.insert(table, u32_at(stream, cursor)?);
            cursor = cursor.saturating_add(4);
        }
    }
    let param_rows: u32 = row_counts.get(&PARAM_TABLE).copied().unwrap_or(0);
    if param_rows == 0 {
        return err("image carries no Param rows");
    }
    if param_rows >= 1 << 16 {
        return err("this builder assumes two byte simple indexes");
    }
    let spans: BTreeMap<u8, TableSpan> = table_spans(
        metadata,
        StreamHeader {
            offset: tables_stream.offset,
            size: tables_stream.size,
        },
    )
    .map_err(|e| BuildError(format!("read the table layout: {e}")))?;
    let param_span: TableSpan = spans
        .get(&PARAM_TABLE)
        .copied()
        .ok_or_else(|| BuildError("no Param table span".to_owned()))?;
    let param_row_width: usize = param_span.row_width;
    let param_start: usize = param_span.offset;
    let param_end: usize =
        param_start.saturating_add(param_row_width.saturating_mul(param_rows as usize));
    if param_end > stream.len() {
        return err("Param table runs past the stream");
    }

    let count: usize = param_rows as usize;
    let permutation: Vec<usize> = (0..count).map(|i: usize| count - 1 - i).collect();

    let mut permuted_params: Vec<u8> = vec![0u8; param_row_width * count];
    for (source, target) in permutation.iter().copied().enumerate() {
        let from: usize = param_start.saturating_add(source.saturating_mul(param_row_width));
        let to: usize = target.saturating_mul(param_row_width);
        let row: &[u8] = stream
            .get(from..from.saturating_add(param_row_width))
            .ok_or_else(|| BuildError("param row".to_owned()))?;
        permuted_params
            .get_mut(to..to.saturating_add(param_row_width))
            .ok_or_else(|| BuildError("permuted row".to_owned()))?
            .copy_from_slice(row);
    }

    let mut pointer_rows: Vec<u8> = Vec::with_capacity(count.saturating_mul(2));
    for source in 0..count {
        let target: u16 = match shape {
            ParamPtrShape::Faithful => u16::try_from(
                permutation
                    .get(source)
                    .copied()
                    .ok_or_else(|| BuildError("permutation".to_owned()))?
                    .saturating_add(1),
            )
            .map_err(|_| BuildError("rid overflow".to_owned()))?,
            ParamPtrShape::IdentityPointerOverPermutedRows => {
                u16::try_from(source.saturating_add(1))
                    .map_err(|_| BuildError("rid overflow".to_owned()))?
            }
        };
        pointer_rows.extend_from_slice(&target.to_le_bytes());
    }

    let new_valid: u64 = valid | (1u64 << PARAM_PTR_TABLE);
    let mut new_stream: Vec<u8> = Vec::with_capacity(
        stream
            .len()
            .saturating_add(4)
            .saturating_add(pointer_rows.len()),
    );
    new_stream.extend_from_slice(
        stream
            .get(..8)
            .ok_or_else(|| BuildError("stream head".to_owned()))?,
    );
    new_stream.extend_from_slice(&new_valid.to_le_bytes());
    new_stream.extend_from_slice(
        stream
            .get(16..24)
            .ok_or_else(|| BuildError("sorted mask".to_owned()))?,
    );
    for table in 0u8..64u8 {
        if (new_valid >> table) & 1 != 1 {
            continue;
        }
        let rows: u32 = if table == PARAM_PTR_TABLE {
            param_rows
        } else {
            row_counts.get(&table).copied().unwrap_or(0)
        };
        new_stream.extend_from_slice(&rows.to_le_bytes());
    }
    let header_len: usize = 24usize.saturating_add(row_counts.len().saturating_mul(4));
    new_stream.extend_from_slice(
        stream
            .get(header_len..param_start)
            .ok_or_else(|| BuildError("tables before Param".to_owned()))?,
    );
    new_stream.extend_from_slice(&pointer_rows);
    new_stream.extend_from_slice(&permuted_params);
    new_stream.extend_from_slice(
        stream
            .get(param_end..)
            .ok_or_else(|| BuildError("tables after Param".to_owned()))?,
    );

    let growth: usize = new_stream.len().saturating_sub(stream.len());
    let mut new_metadata: Vec<u8> = metadata.to_vec();
    for entry in &streams {
        if entry.offset <= tables_stream.offset && entry.name != tables_stream.name {
            continue;
        }
        let shifted: u32 = if entry.name == tables_stream.name {
            entry.offset
        } else {
            entry
                .offset
                .saturating_add(u32::try_from(growth).map_err(|_| BuildError("growth".to_owned()))?)
        };
        let size: u32 = if entry.name == tables_stream.name {
            u32::try_from(new_stream.len()).map_err(|_| BuildError("stream size".to_owned()))?
        } else {
            entry.size
        };
        new_metadata
            .get_mut(entry.header_offset..entry.header_offset.saturating_add(4))
            .ok_or_else(|| BuildError("stream offset field".to_owned()))?
            .copy_from_slice(&shifted.to_le_bytes());
        new_metadata
            .get_mut(entry.header_offset.saturating_add(4)..entry.header_offset.saturating_add(8))
            .ok_or_else(|| BuildError("stream size field".to_owned()))?
            .copy_from_slice(&size.to_le_bytes());
    }
    new_metadata.splice(
        stream_start..stream_start.saturating_add(stream.len()),
        new_stream.iter().copied(),
    );

    append_metadata_section(image, layout, clr_offset, &new_metadata)
}

fn append_metadata_section(
    image: &[u8],
    layout: PeLayout,
    clr_offset: usize,
    metadata: &[u8],
) -> Result<Vec<u8>, BuildError> {
    if layout.section_count == 0 {
        return err("image carries no sections");
    }
    let last: usize = layout.section_table.saturating_add(
        (layout.section_count as usize)
            .saturating_sub(1)
            .saturating_mul(SECTION_HEADER_LEN),
    );
    let last_virtual_size: u32 = u32_at(image, last.saturating_add(8))?;
    let last_virtual_address: u32 = u32_at(image, last.saturating_add(12))?;
    let last_raw_size: u32 = u32_at(image, last.saturating_add(16))?;
    let last_raw_pointer: u32 = u32_at(image, last.saturating_add(20))?;
    let last_characteristics: u32 = u32_at(image, last.saturating_add(36))?;

    let payload_raw: usize = last_raw_pointer.saturating_add(last_raw_size) as usize;
    if payload_raw > image.len() {
        return err("the last section runs past the end of the file");
    }
    let payload_rva: u32 = last_virtual_address.saturating_add(last_raw_size);
    let payload_len: u32 =
        u32::try_from(metadata.len()).map_err(|_| BuildError("metadata size".to_owned()))?;

    let mut out: Vec<u8> = image.to_vec();
    out.resize(payload_raw, 0u8);
    out.extend_from_slice(metadata);
    let new_raw_size: u32 = align_up(
        last_raw_size.saturating_add(payload_len),
        layout.file_alignment,
    );
    out.resize(
        (last_raw_pointer as usize).saturating_add(new_raw_size as usize),
        0u8,
    );

    let new_virtual_size: u32 = last_virtual_size.max(last_raw_size.saturating_add(payload_len));
    out.get_mut(last.saturating_add(8)..last.saturating_add(12))
        .ok_or_else(|| BuildError("virtual size".to_owned()))?
        .copy_from_slice(&new_virtual_size.to_le_bytes());
    out.get_mut(last.saturating_add(16)..last.saturating_add(20))
        .ok_or_else(|| BuildError("raw size".to_owned()))?
        .copy_from_slice(&new_raw_size.to_le_bytes());
    out.get_mut(last.saturating_add(36)..last.saturating_add(40))
        .ok_or_else(|| BuildError("characteristics".to_owned()))?
        .copy_from_slice(&(last_characteristics | SECTION_READABLE_DATA).to_le_bytes());

    let size_of_image: u32 = align_up(
        last_virtual_address.saturating_add(new_virtual_size),
        layout.section_alignment,
    );
    out.get_mut(layout.size_of_image_field..layout.size_of_image_field.saturating_add(4))
        .ok_or_else(|| BuildError("size of image".to_owned()))?
        .copy_from_slice(&size_of_image.to_le_bytes());

    out.get_mut(clr_offset.saturating_add(8)..clr_offset.saturating_add(12))
        .ok_or_else(|| BuildError("metadata rva".to_owned()))?
        .copy_from_slice(&payload_rva.to_le_bytes());
    out.get_mut(clr_offset.saturating_add(12)..clr_offset.saturating_add(16))
        .ok_or_else(|| BuildError("metadata size".to_owned()))?
        .copy_from_slice(&payload_len.to_le_bytes());

    Ok(out)
}
