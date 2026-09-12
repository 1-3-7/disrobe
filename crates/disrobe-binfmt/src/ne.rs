use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use disrobe_bytes::{ByteReadError, ByteReader};

use crate::debug::{dbg_kv, dbg_section};
use crate::error::{Error, Result};
use crate::native::{
    Arch, Endian, ExportInfo, ImportInfo, NativeFile, NativeFormat, SectionInfo, SegmentInfo,
    SymbolInfo, SymbolRole,
};

const DOS_HEADER_SIZE: usize = 0x40;
const NE_HEADER_SIZE: usize = 0x40;
const SEGMENT_RECORD_SIZE: usize = 8;
const RELOCATION_RECORD_SIZE: usize = 8;
const RESOURCE_RECORD_SIZE: usize = 12;
const MAX_RELOCATION_RECORDS: usize = 65_536;
const MAX_RELOCATION_CHAIN_STEPS: usize = 1_000_000;
const MAX_ITERATED_RECORDS: usize = 65_536;
const MAX_TOTAL_ITERATED_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESOURCE_RECORDS: usize = 65_536;
const MAX_UNIQUE_IMPORTS: usize = 65_536;
const SEGMENT_RELOCATIONS_FLAG: u16 = 0x0100;
const SEGMENT_ITERATED_FLAG: u16 = 0x0008;
const RELOCATION_TARGET_MASK: u8 = 0x03;
const RELOCATION_ADDITIVE: u8 = 0x04;
const RELOCATION_INTERNAL_CHAIN: u8 = 0x08;
const RELOCATION_KNOWN_FLAGS: u8 =
    RELOCATION_TARGET_MASK | RELOCATION_ADDITIVE | RELOCATION_INTERNAL_CHAIN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetOs {
    Os2,
    Windows,
}

#[derive(Debug, Clone, Copy)]
struct NeHeader {
    base: usize,
    linker_version: u8,
    linker_revision: u8,
    entry_table_offset: u16,
    entry_table_length: u16,
    flags: u16,
    automatic_data_segment: u16,
    initial_ip: u16,
    initial_cs: u16,
    initial_sp: u16,
    initial_ss: u16,
    segment_count: u16,
    module_count: u16,
    nonresident_name_size: u16,
    segment_table_offset: u16,
    resource_table_offset: u16,
    resident_name_offset: u16,
    module_table_offset: u16,
    imported_name_offset: u16,
    nonresident_name_offset: u32,
    movable_entry_count: u16,
    alignment_shift: u16,
    os2_resource_segment_count: u16,
    target_os: TargetOs,
    expected_os_version: u16,
}

#[derive(Debug, Clone, Copy)]
struct NeSegment {
    ordinal: u16,
    file_offset: usize,
    data_len: usize,
    initialized_len: usize,
    flags: u16,
    allocation_len: usize,
}

#[derive(Debug, Clone, Copy)]
struct NeEntry {
    segment: u8,
    offset: u16,
    exported: bool,
    movable: bool,
}

#[derive(Debug, Clone)]
struct NamedOrdinal {
    name: String,
    ordinal: u16,
}

#[derive(Debug, Clone)]
struct ParsedNameTable {
    names: Vec<NamedOrdinal>,
    consumed_end: usize,
}

#[derive(Debug, Clone, Copy)]
struct ResourceRange {
    type_id: u16,
    name_id: u16,
    file_offset: usize,
    length: usize,
    segment_ordinal: Option<u16>,
}

#[derive(Debug)]
struct ParsedResources {
    ranges: Vec<ResourceRange>,
    loader_span: Option<(usize, usize)>,
}

pub(crate) fn is_ne(bytes: &[u8]) -> bool {
    if bytes.len() < DOS_HEADER_SIZE || !bytes.starts_with(b"MZ") {
        return false;
    }
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    if reader.seek(0x3c).is_err() {
        return false;
    }
    let Ok(base_raw) = reader.read_u32_le() else {
        return false;
    };
    let Ok(base) = usize::try_from(base_raw) else {
        return false;
    };
    let Some(end) = base.checked_add(2) else {
        return false;
    };
    bytes.get(base..end) == Some(b"NE")
}

pub(crate) fn parse_ne(bytes: &[u8]) -> Result<NativeFile> {
    let header: NeHeader = parse_header(bytes)?;
    let mut segments: Vec<NeSegment> = parse_segments(bytes, &header)?;
    validate_iterated_segments(bytes, &mut segments)?;
    validate_segment_ranges(&segments)?;
    validate_initial_registers(&header, &segments)?;
    let entries: Vec<Option<NeEntry>> = parse_entries(bytes, &header)?;
    validate_entries(&entries, &segments, header.movable_entry_count)?;
    let (resident_names, resident_span): (Vec<NamedOrdinal>, Option<(usize, usize)>) =
        if header.resident_name_offset == 0 {
            (Vec::new(), None)
        } else {
            let start: usize =
                relative_offset(&header, header.resident_name_offset, "resident name table")?;
            let limit: usize = next_relative_table_offset(
                &header,
                header.resident_name_offset,
                [
                    header.module_table_offset,
                    header.imported_name_offset,
                    header.entry_table_offset,
                ],
                bytes.len(),
            )?;
            let length: usize = limit
                .checked_sub(start)
                .ok_or_else(|| ne_error("resident name table bounds are invalid"))?;
            let parsed: ParsedNameTable =
                parse_name_table(bytes, start, Some(length), "resident name table")?;
            let span: (usize, usize) = (start, parsed.consumed_end);
            (parsed.names, Some(span))
        };
    let nonresident_names: Vec<NamedOrdinal> = if header.nonresident_name_size == 0 {
        Vec::new()
    } else {
        if header.nonresident_name_offset == 0 {
            return Err(ne_error(
                "nonresident name table has bytes but a zero offset",
            ));
        }
        parse_name_table(
            bytes,
            usize::try_from(header.nonresident_name_offset)
                .map_err(|_| ne_error("nonresident name table offset does not fit this host"))?,
            Some(usize::from(header.nonresident_name_size)),
            "nonresident name table",
        )?
        .names
    };
    validate_name_table_roles(&resident_names, "resident name table")?;
    validate_name_table_roles(&nonresident_names, "nonresident name table")?;
    let imported_name_range: Option<(usize, usize)> = if header.module_count == 0 {
        None
    } else {
        let start: usize =
            relative_offset(&header, header.imported_name_offset, "imported name table")?;
        let end: usize = relative_offset(&header, header.entry_table_offset, "entry table")?;
        if end <= start {
            return Err(ne_error("imported name table bounds are invalid"));
        }
        Some((start, end))
    };
    let modules: Vec<String> = parse_modules(bytes, &header, imported_name_range)?;
    let parsed_resources: ParsedResources = parse_resources(bytes, &header, &segments)?;
    let resource_span: Option<(usize, usize)> = parsed_resources.loader_span;
    let resources: Vec<ResourceRange> = parsed_resources.ranges;
    validate_loader_data_ownership(
        bytes.len(),
        &header,
        &segments,
        &resources,
        resource_span,
        resident_span,
        imported_name_range,
    )?;
    validate_resource_segment_overlap(&resources, &segments)?;
    let imports: Vec<ImportInfo> = parse_relocations(
        bytes,
        &header,
        &segments,
        &entries,
        &modules,
        imported_name_range,
        &resources,
    )?;
    let (mut symbols, exports): (Vec<SymbolInfo>, Vec<ExportInfo>) =
        lower_entries(&entries, &resident_names, &nonresident_names)?;
    if header.initial_cs != 0 {
        symbols.insert(
            0,
            SymbolInfo {
                name: "entry".to_owned(),
                address: segmented_address(header.initial_cs, header.initial_ip),
                size: 0,
                kind: SymbolRole::Text,
            },
        );
    }
    let sections: Vec<SectionInfo> = lower_sections(&segments, &resources)?;
    let segment_info: Vec<SegmentInfo> = segments
        .iter()
        .map(|segment: &NeSegment| {
            Ok(SegmentInfo {
                name: Some(segment_name(segment)),
                address: segmented_address(segment.ordinal, 0),
                size: host_size_to_u64(segment.allocation_len, "segment allocation size")?,
            })
        })
        .collect::<Result<Vec<SegmentInfo>>>()?;
    dbg_section("ne");
    dbg_kv("target", || match header.target_os {
        TargetOs::Os2 => "os2".to_owned(),
        TargetOs::Windows => "windows".to_owned(),
    });
    dbg_kv("segments", || segments.len().to_string());
    dbg_kv("imports", || imports.len().to_string());
    dbg_kv("linker-version", || {
        format!("{}.{}", header.linker_version, header.linker_revision)
    });
    dbg_kv("expected-os-version", || {
        format!("0x{:04x}", header.expected_os_version)
    });
    dbg_kv("flags", || format!("0x{:04x}", header.flags));
    dbg_kv("automatic-data-segment", || {
        header.automatic_data_segment.to_string()
    });
    dbg_kv("entry", || {
        format!("{}:{:04x}", header.initial_cs, header.initial_ip)
    });
    dbg_kv("stack", || {
        format!("{}:{:04x}", header.initial_ss, header.initial_sp)
    });
    Ok(NativeFile {
        format: match header.target_os {
            TargetOs::Os2 => NativeFormat::NeOs2,
            TargetOs::Windows => NativeFormat::NeWindows,
        },
        arch: Arch::X86,
        bits: 16,
        endian: Endian::Little,
        sections,
        symbols,
        imports,
        exports,
        debug_info_present: false,
        segments: segment_info,
        dynamic: None,
    })
}

fn parse_header(bytes: &[u8]) -> Result<NeHeader> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    if reader
        .read_bytes(2)
        .map_err(|error: ByteReadError| read_error("DOS signature", error))?
        != b"MZ"
    {
        return Err(ne_error("DOS signature is not MZ"));
    }
    reader
        .seek(0x08)
        .map_err(|error: ByteReadError| read_error("DOS header", error))?;
    let dos_header_paragraphs: u16 = read_u16(&mut reader, "DOS header size")?;
    let dos_header_size: usize = usize::from(dos_header_paragraphs)
        .checked_mul(16)
        .ok_or_else(|| ne_error("DOS header size overflow"))?;
    if dos_header_size < DOS_HEADER_SIZE {
        return Err(ne_error("DOS header is shorter than its fixed fields"));
    }
    reader
        .seek(0x3c)
        .map_err(|error: ByteReadError| read_error("DOS header", error))?;
    let base_raw: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error("DOS header", error))?;
    let base: usize = usize::try_from(base_raw)
        .map_err(|_| ne_error("new executable header offset does not fit this host"))?;
    if base < dos_header_size {
        return Err(ne_error("new executable header overlaps the DOS header"));
    }
    let header_end: usize = base
        .checked_add(NE_HEADER_SIZE)
        .ok_or_else(|| ne_error("new executable header range overflow"))?;
    if header_end > bytes.len() {
        return Err(ne_error("new executable header is truncated"));
    }
    reader
        .seek(base)
        .map_err(|error: ByteReadError| read_error("new executable header", error))?;
    if reader
        .read_bytes(2)
        .map_err(|error: ByteReadError| read_error("new executable signature", error))?
        != b"NE"
    {
        return Err(ne_error("signature is not NE"));
    }
    let linker_version: u8 = reader
        .read_u8()
        .map_err(|error: ByteReadError| read_error("linker version", error))?;
    let linker_revision: u8 = reader
        .read_u8()
        .map_err(|error: ByteReadError| read_error("linker revision", error))?;
    let entry_table_offset: u16 = read_u16(&mut reader, "entry table offset")?;
    let entry_table_length: u16 = read_u16(&mut reader, "entry table length")?;
    let _checksum: u32 = read_u32(&mut reader, "checksum")?;
    let flags: u16 = read_u16(&mut reader, "module flags")?;
    let automatic_data_segment: u16 = read_u16(&mut reader, "automatic data segment")?;
    let _heap_size: u16 = read_u16(&mut reader, "heap size")?;
    let _stack_size: u16 = read_u16(&mut reader, "stack size")?;
    let initial_ip: u16 = read_u16(&mut reader, "initial IP")?;
    let initial_cs: u16 = read_u16(&mut reader, "initial CS")?;
    let initial_sp: u16 = read_u16(&mut reader, "initial SP")?;
    let initial_ss: u16 = read_u16(&mut reader, "initial SS")?;
    let segment_count: u16 = read_u16(&mut reader, "segment count")?;
    let module_count: u16 = read_u16(&mut reader, "module reference count")?;
    let nonresident_name_size: u16 = read_u16(&mut reader, "nonresident name size")?;
    let segment_table_offset: u16 = read_u16(&mut reader, "segment table offset")?;
    let resource_table_offset: u16 = read_u16(&mut reader, "resource table offset")?;
    let resident_name_offset: u16 = read_u16(&mut reader, "resident name offset")?;
    let module_table_offset: u16 = read_u16(&mut reader, "module table offset")?;
    let imported_name_offset: u16 = read_u16(&mut reader, "imported name offset")?;
    let nonresident_name_offset: u32 = read_u32(&mut reader, "nonresident name offset")?;
    let movable_entry_count: u16 = read_u16(&mut reader, "movable entry count")?;
    let alignment_shift: u16 = read_u16(&mut reader, "segment alignment shift")?;
    let os2_resource_segment_count: u16 = read_u16(&mut reader, "OS/2 resource segment count")?;
    let target_os_raw: u8 = reader
        .read_u8()
        .map_err(|error: ByteReadError| read_error("target operating system", error))?;
    let target_os: TargetOs = match target_os_raw {
        1 => TargetOs::Os2,
        2 => TargetOs::Windows,
        _ => {
            return Err(ne_error(format!(
                "unsupported target operating system {target_os_raw}"
            )));
        }
    };
    let _other_flags: u8 = reader
        .read_u8()
        .map_err(|error: ByteReadError| read_error("other operating system flags", error))?;
    let _return_thunks: u16 = read_u16(&mut reader, "return thunk offset")?;
    let _segment_thunks: u16 = read_u16(&mut reader, "segment thunk offset")?;
    let _swap_area: u16 = read_u16(&mut reader, "minimum code swap area")?;
    let expected_os_version: u16 = read_u16(&mut reader, "expected operating system version")?;
    if nonresident_name_size != 0 {
        if nonresident_name_offset == 0 {
            return Err(ne_error(
                "nonresident name table has bytes but a zero offset",
            ));
        }
        let nonresident_start: usize = usize::try_from(nonresident_name_offset)
            .map_err(|_| ne_error("nonresident name table offset does not fit this host"))?;
        if nonresident_start < header_end {
            return Err(ne_error(
                "nonresident name table starts before the new executable header",
            ));
        }
    }
    for (name, offset) in [
        ("segment table", segment_table_offset),
        ("resource table", resource_table_offset),
        ("resident name table", resident_name_offset),
        ("module reference table", module_table_offset),
        ("imported name table", imported_name_offset),
        ("entry table", entry_table_offset),
    ] {
        if offset != 0 && usize::from(offset) < NE_HEADER_SIZE {
            return Err(ne_error(format!(
                "{name} points inside the new executable header"
            )));
        }
    }
    let mut previous_table: Option<(&str, u16, bool)> = None;
    for (name, offset, can_be_empty) in [
        ("segment table", segment_table_offset, segment_count == 0),
        (
            "resource table",
            if resource_table_offset == resident_name_offset {
                0
            } else {
                resource_table_offset
            },
            target_os == TargetOs::Os2 && os2_resource_segment_count == 0,
        ),
        ("resident name table", resident_name_offset, false),
        (
            "module reference table",
            module_table_offset,
            module_count == 0,
        ),
        ("imported name table", imported_name_offset, true),
        ("entry table", entry_table_offset, entry_table_length == 0),
    ] {
        if offset == 0 {
            continue;
        }
        if let Some((previous_name, previous_offset, previous_can_be_empty)) = previous_table
            && (offset < previous_offset || (offset == previous_offset && !previous_can_be_empty))
        {
            return Err(ne_error(format!("{name} does not follow {previous_name}")));
        }
        previous_table = Some((name, offset, can_be_empty));
    }
    let data_mode: u16 = flags & 0x0003;
    if data_mode == 0x0003 {
        return Err(ne_error("module declares both single and multiple data"));
    }
    if (data_mode == 0) != (automatic_data_segment == 0) {
        return Err(ne_error(
            "automatic data segment does not match the module flags",
        ));
    }
    for (name, segment) in [
        ("automatic data", automatic_data_segment),
        ("initial code", initial_cs),
        ("initial stack", initial_ss),
    ] {
        if segment > segment_count {
            return Err(ne_error(format!(
                "{name} segment is outside the segment table"
            )));
        }
    }
    Ok(NeHeader {
        base,
        linker_version,
        linker_revision,
        entry_table_offset,
        entry_table_length,
        flags,
        automatic_data_segment,
        initial_ip,
        initial_cs,
        initial_sp,
        initial_ss,
        segment_count,
        module_count,
        nonresident_name_size,
        segment_table_offset,
        resource_table_offset,
        resident_name_offset,
        module_table_offset,
        imported_name_offset,
        nonresident_name_offset,
        movable_entry_count,
        alignment_shift,
        os2_resource_segment_count,
        target_os,
        expected_os_version,
    })
}

fn parse_segments(bytes: &[u8], header: &NeHeader) -> Result<Vec<NeSegment>> {
    let count: usize = usize::from(header.segment_count);
    let table_size: usize = count
        .checked_mul(SEGMENT_RECORD_SIZE)
        .ok_or_else(|| ne_error("segment table size overflow"))?;
    let table_start: usize = relative_offset(header, header.segment_table_offset, "segment table")?;
    let table_end: usize = table_start
        .checked_add(table_size)
        .ok_or_else(|| ne_error("segment table range overflow"))?;
    if table_end > bytes.len() {
        return Err(ne_error("segment table extends past end of file"));
    }
    let table_limit: usize = next_relative_table_offset(
        header,
        header.segment_table_offset,
        [
            header.resource_table_offset,
            header.resident_name_offset,
            header.module_table_offset,
            header.imported_name_offset,
            header.entry_table_offset,
        ],
        bytes.len(),
    )?;
    if table_end > table_limit {
        return Err(ne_error("segment table overlaps another loader table"));
    }
    let shift: u32 = if header.alignment_shift == 0 {
        9
    } else {
        u32::from(header.alignment_shift)
    };
    if shift >= usize::BITS {
        return Err(ne_error("segment alignment shift exceeds host width"));
    }
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(table_start)
        .map_err(|error: ByteReadError| read_error("segment table", error))?;
    let mut segments: Vec<NeSegment> = Vec::with_capacity(count);
    for index in 0..count {
        let sector: u16 = read_u16(&mut reader, "segment sector")?;
        let raw_len: u16 = read_u16(&mut reader, "segment length")?;
        let flags: u16 = read_u16(&mut reader, "segment flags")?;
        let raw_allocation: u16 = read_u16(&mut reader, "segment allocation size")?;
        let file_offset: usize = checked_scaled_u16(sector, shift, "segment file offset")?;
        let data_len: usize = if sector == 0 {
            0
        } else if raw_len == 0 {
            65_536
        } else {
            usize::from(raw_len)
        };
        let allocation_len: usize = if raw_allocation == 0 {
            65_536
        } else {
            usize::from(raw_allocation)
        };
        if sector != 0 && flags & SEGMENT_ITERATED_FLAG == 0 && allocation_len < data_len {
            return Err(ne_error(format!(
                "segment {} allocation is smaller than its data",
                index + 1
            )));
        }
        if sector != 0 {
            let data_end: usize = file_offset
                .checked_add(data_len)
                .ok_or_else(|| ne_error("segment data range overflow"))?;
            if data_end > bytes.len() {
                return Err(ne_error(format!(
                    "segment {} extends past end of file",
                    index + 1
                )));
            }
        }
        let ordinal: u16 = u16::try_from(index + 1)
            .map_err(|_| ne_error("segment ordinal does not fit 16 bits"))?;
        segments.push(NeSegment {
            ordinal,
            file_offset,
            data_len,
            initialized_len: data_len,
            flags,
            allocation_len,
        });
    }
    Ok(segments)
}

fn validate_iterated_segments(bytes: &[u8], segments: &mut [NeSegment]) -> Result<()> {
    let mut total_records: usize = 0;
    let mut total_expanded: usize = 0;
    for segment in segments {
        if segment.flags & SEGMENT_ITERATED_FLAG == 0 {
            continue;
        }
        if segment.file_offset == 0 {
            return Err(ne_error("uninitialized segment declares iterated data"));
        }
        let end: usize = segment
            .file_offset
            .checked_add(segment.data_len)
            .ok_or_else(|| ne_error("iterated segment range overflow"))?;
        let encoded: &[u8] = bytes
            .get(segment.file_offset..end)
            .ok_or_else(|| ne_error("iterated segment data is truncated"))?;
        let mut reader: ByteReader<'_> = ByteReader::new(encoded);
        let mut expanded: usize = 0;
        while !reader.is_empty() {
            total_records = total_records
                .checked_add(1)
                .ok_or_else(|| ne_error("total iterated record count overflow"))?;
            if total_records > MAX_ITERATED_RECORDS {
                return Err(ne_error("iterated segment records exceed 65536"));
            }
            let repeat_count: usize = usize::from(read_u16(&mut reader, "iteration count")?);
            let item_length: usize = usize::from(read_u16(&mut reader, "iteration item length")?);
            reader
                .read_bytes(item_length)
                .map_err(|error: ByteReadError| read_error("iteration item", error))?;
            let repeated_bytes: usize = repeat_count
                .checked_mul(item_length)
                .ok_or_else(|| ne_error("iterated segment expansion overflow"))?;
            expanded = expanded
                .checked_add(repeated_bytes)
                .ok_or_else(|| ne_error("iterated segment expansion overflow"))?;
            if expanded > segment.allocation_len {
                return Err(ne_error("iterated segment exceeds its allocation"));
            }
        }
        total_expanded = total_expanded
            .checked_add(expanded)
            .ok_or_else(|| ne_error("total iterated segment expansion overflow"))?;
        if total_expanded > MAX_TOTAL_ITERATED_BYTES {
            return Err(ne_error(
                "total iterated segment expansion exceeds 16777216 bytes",
            ));
        }
        segment.initialized_len = expanded;
    }
    Ok(())
}

fn initialized_segment_data<'a>(bytes: &'a [u8], segment: &NeSegment) -> Result<Cow<'a, [u8]>> {
    let end: usize = segment
        .file_offset
        .checked_add(segment.data_len)
        .ok_or_else(|| ne_error("segment data range overflow"))?;
    let encoded: &'a [u8] = bytes
        .get(segment.file_offset..end)
        .ok_or_else(|| ne_error("segment data is truncated"))?;
    if segment.flags & SEGMENT_ITERATED_FLAG == 0 {
        return Ok(Cow::Borrowed(encoded));
    }
    let mut reader: ByteReader<'_> = ByteReader::new(encoded);
    let mut expanded: Vec<u8> = Vec::with_capacity(segment.initialized_len);
    while !reader.is_empty() {
        let repeat_count: usize = usize::from(read_u16(&mut reader, "iteration count")?);
        let item_length: usize = usize::from(read_u16(&mut reader, "iteration item length")?);
        let item: &[u8] = reader
            .read_bytes(item_length)
            .map_err(|error: ByteReadError| read_error("iteration item", error))?;
        for _ in 0..repeat_count {
            expanded.extend_from_slice(item);
        }
    }
    if expanded.len() != segment.initialized_len {
        return Err(ne_error("iterated segment expansion is inconsistent"));
    }
    Ok(Cow::Owned(expanded))
}

fn validate_segment_ranges(segments: &[NeSegment]) -> Result<()> {
    let mut ranges: Vec<(usize, usize, u16)> = Vec::with_capacity(segments.len());
    for segment in segments
        .iter()
        .filter(|segment: &&NeSegment| segment.file_offset != 0)
    {
        let end: usize = segment
            .file_offset
            .checked_add(segment.data_len)
            .ok_or_else(|| ne_error("segment data range overflow"))?;
        ranges.push((segment.file_offset, end, segment.ordinal));
    }
    ranges.sort_unstable_by_key(|range: &(usize, usize, u16)| range.0);
    for pair in ranges.windows(2) {
        let left: (usize, usize, u16) = pair[0];
        let right: (usize, usize, u16) = pair[1];
        if left.1 > right.0 {
            return Err(ne_error(format!(
                "segments {} and {} overlap",
                left.2, right.2
            )));
        }
    }
    Ok(())
}

fn validate_initial_registers(header: &NeHeader, segments: &[NeSegment]) -> Result<()> {
    if header.initial_cs != 0 {
        let code: &NeSegment = segments
            .get(usize::from(header.initial_cs - 1))
            .ok_or_else(|| ne_error("initial code segment is missing"))?;
        if usize::from(header.initial_ip) >= code.allocation_len {
            return Err(ne_error("initial IP is outside the initial code segment"));
        }
    } else if header.initial_ip != 0 {
        return Err(ne_error("initial IP requires an initial code segment"));
    }
    if header.initial_ss != 0 {
        let stack: &NeSegment = segments
            .get(usize::from(header.initial_ss - 1))
            .ok_or_else(|| ne_error("initial stack segment is missing"))?;
        if usize::from(header.initial_sp) > stack.allocation_len {
            return Err(ne_error("initial SP is outside the initial stack segment"));
        }
    } else if header.initial_sp != 0 {
        return Err(ne_error("initial SP requires an explicit stack segment"));
    }
    Ok(())
}

fn parse_entries(bytes: &[u8], header: &NeHeader) -> Result<Vec<Option<NeEntry>>> {
    if header.entry_table_offset == 0 && header.entry_table_length != 0 {
        return Err(ne_error(
            "entry table offset and length must both be present or absent",
        ));
    }
    if header.entry_table_offset == 0 {
        return Ok(Vec::new());
    }
    let start: usize = relative_offset(header, header.entry_table_offset, "entry table")?;
    let length: usize = usize::from(header.entry_table_length);
    let end: usize = start
        .checked_add(length)
        .ok_or_else(|| ne_error("entry table range overflow"))?;
    let table: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| ne_error("entry table extends past end of file"))?;
    if table.is_empty() {
        return Ok(Vec::new());
    }
    let mut reader: ByteReader<'_> = ByteReader::new(table);
    let mut entries: Vec<Option<NeEntry>> = Vec::new();
    while !reader.is_empty() {
        let count: u8 = reader
            .read_u8()
            .map_err(|error: ByteReadError| read_error("entry bundle count", error))?;
        if count == 0 {
            return Ok(entries);
        }
        let segment_indicator: u8 = reader
            .read_u8()
            .map_err(|error: ByteReadError| read_error("entry bundle segment", error))?;
        let new_len: usize = entries
            .len()
            .checked_add(usize::from(count))
            .ok_or_else(|| ne_error("entry table count overflow"))?;
        if new_len > usize::from(u16::MAX) {
            return Err(ne_error("entry table has more than 65535 entries"));
        }
        if segment_indicator == 0 {
            entries.resize(new_len, None);
            continue;
        }
        for _ in 0..count {
            let flags: u8 = reader
                .read_u8()
                .map_err(|error: ByteReadError| read_error("entry flags", error))?;
            let movable: bool = segment_indicator == 0xff;
            let (segment, offset): (u8, u16) = if movable {
                let interrupt: u16 = read_u16(&mut reader, "movable entry interrupt")?;
                if interrupt != 0x3fcd {
                    return Err(ne_error("movable entry is missing the CD 3F marker"));
                }
                let segment: u8 = reader
                    .read_u8()
                    .map_err(|error: ByteReadError| read_error("movable entry segment", error))?;
                let offset: u16 = read_u16(&mut reader, "movable entry offset")?;
                (segment, offset)
            } else {
                (
                    segment_indicator,
                    read_u16(&mut reader, "fixed entry offset")?,
                )
            };
            if segment == 0 || u16::from(segment) > header.segment_count {
                return Err(ne_error(
                    "entry references a segment outside the segment table",
                ));
            }
            entries.push(Some(NeEntry {
                segment,
                offset,
                exported: flags & 1 != 0,
                movable,
            }));
        }
    }
    Err(ne_error("entry table has no terminating bundle"))
}

fn parse_name_table(
    bytes: &[u8],
    start: usize,
    declared_len: Option<usize>,
    context: &'static str,
) -> Result<ParsedNameTable> {
    if declared_len == Some(0) {
        return Ok(ParsedNameTable {
            names: Vec::new(),
            consumed_end: start,
        });
    }
    let end: usize = match declared_len {
        Some(length) => start
            .checked_add(length)
            .ok_or_else(|| ne_error(format!("{context} range overflow")))?,
        None => bytes.len(),
    };
    let table: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| ne_error(format!("{context} extends past end of file")))?;
    let mut reader: ByteReader<'_> = ByteReader::new(table);
    let mut names: Vec<NamedOrdinal> = Vec::new();
    while !reader.is_empty() {
        let length: u8 = reader
            .read_u8()
            .map_err(|error: ByteReadError| read_error(context, error))?;
        if length == 0 {
            let consumed_end: usize = start
                .checked_add(reader.position())
                .ok_or_else(|| ne_error(format!("{context} consumed range overflow")))?;
            return Ok(ParsedNameTable {
                names,
                consumed_end,
            });
        }
        let raw: &[u8] = reader
            .read_bytes(usize::from(length))
            .map_err(|error: ByteReadError| read_error(context, error))?;
        let ordinal: u16 = read_u16(&mut reader, context)?;
        names.push(NamedOrdinal {
            name: decode_oem(raw),
            ordinal,
        });
        if names.len() > usize::from(u16::MAX) {
            return Err(ne_error(format!("{context} has too many entries")));
        }
    }
    if declared_len.is_some() {
        Err(ne_error(format!("{context} has no terminator")))
    } else {
        Err(ne_error(format!(
            "{context} reaches end of file without a terminator"
        )))
    }
}

fn validate_name_table_roles(names: &[NamedOrdinal], context: &'static str) -> Result<()> {
    let Some((first, rest)): Option<(&NamedOrdinal, &[NamedOrdinal])> = names.split_first() else {
        return Ok(());
    };
    if first.ordinal != 0 {
        return Err(ne_error(format!(
            "{context} does not begin with its module name"
        )));
    }
    if rest.iter().any(|name: &NamedOrdinal| name.ordinal == 0) {
        return Err(ne_error(format!("{context} contains another zero ordinal")));
    }
    Ok(())
}

fn validate_entries(
    entries: &[Option<NeEntry>],
    segments: &[NeSegment],
    expected_movable_count: u16,
) -> Result<()> {
    let movable_count: usize = entries
        .iter()
        .flatten()
        .filter(|entry: &&NeEntry| entry.movable)
        .count();
    if movable_count != usize::from(expected_movable_count) {
        return Err(ne_error(
            "movable entry count does not match the entry table",
        ));
    }
    for entry in entries.iter().flatten() {
        let segment_index: usize = usize::from(entry.segment)
            .checked_sub(1)
            .ok_or_else(|| ne_error("entry segment index is zero"))?;
        let segment: &NeSegment = segments
            .get(segment_index)
            .ok_or_else(|| ne_error("entry segment is missing"))?;
        if usize::from(entry.offset) >= segment.allocation_len {
            return Err(ne_error("entry offset is outside its segment"));
        }
    }
    Ok(())
}

fn parse_modules(
    bytes: &[u8],
    header: &NeHeader,
    imported_name_range: Option<(usize, usize)>,
) -> Result<Vec<String>> {
    let count: usize = usize::from(header.module_count);
    if count == 0 {
        return Ok(Vec::new());
    }
    let (imported_name_base, imported_name_limit): (usize, usize) = imported_name_range
        .ok_or_else(|| ne_error("module references require an imported name table"))?;
    let table_size: usize = count
        .checked_mul(2)
        .ok_or_else(|| ne_error("module reference table size overflow"))?;
    let start: usize =
        relative_offset(header, header.module_table_offset, "module reference table")?;
    let end: usize = start
        .checked_add(table_size)
        .ok_or_else(|| ne_error("module reference table range overflow"))?;
    if end > imported_name_base {
        return Err(ne_error(
            "module reference table overlaps the imported name table",
        ));
    }
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(start)
        .map_err(|error: ByteReadError| read_error("module reference table", error))?;
    let mut modules: Vec<String> = Vec::with_capacity(count);
    for _ in 0..count {
        let offset: u16 = read_u16(&mut reader, "module reference")?;
        modules.push(read_imported_name(
            bytes,
            imported_name_base,
            imported_name_limit,
            offset,
        )?);
    }
    Ok(modules)
}

fn parse_relocations(
    bytes: &[u8],
    header: &NeHeader,
    segments: &[NeSegment],
    entries: &[Option<NeEntry>],
    modules: &[String],
    imported_name_range: Option<(usize, usize)>,
    resources: &[ResourceRange],
) -> Result<Vec<ImportInfo>> {
    let mut imports: BTreeSet<(String, String)> = BTreeSet::new();
    let mut total_records: usize = 0;
    let mut total_chain_steps: usize = 0;
    let mut segment_starts: Vec<usize> = segments
        .iter()
        .filter_map(|segment: &NeSegment| (segment.file_offset != 0).then_some(segment.file_offset))
        .collect();
    segment_starts.sort_unstable();
    let mut resource_ranges: Vec<(usize, usize)> = resources
        .iter()
        .map(|resource: &ResourceRange| {
            resource
                .file_offset
                .checked_add(resource.length)
                .map(|end: usize| (resource.file_offset, end))
                .ok_or_else(|| ne_error("resource range overflow"))
        })
        .collect::<Result<Vec<(usize, usize)>>>()?;
    resource_ranges.sort_unstable_by_key(|range: &(usize, usize)| range.0);
    let nonresident_range: Option<(usize, usize)> = if header.nonresident_name_size == 0 {
        None
    } else {
        let start: usize = usize::try_from(header.nonresident_name_offset)
            .map_err(|_| ne_error("nonresident name table offset does not fit this host"))?;
        let end: usize = start
            .checked_add(usize::from(header.nonresident_name_size))
            .ok_or_else(|| ne_error("nonresident name table range overflow"))?;
        Some((start, end))
    };
    for segment in segments {
        if segment.flags & SEGMENT_RELOCATIONS_FLAG == 0 {
            continue;
        }
        if segment.file_offset == 0 {
            return Err(ne_error(
                "uninitialized segment declares a relocation table",
            ));
        }
        let initialized_data: Cow<'_, [u8]> = initialized_segment_data(bytes, segment)?;
        let table_start: usize = segment
            .file_offset
            .checked_add(segment.data_len)
            .ok_or_else(|| ne_error("relocation table offset overflow"))?;
        let resource_insertion: usize =
            resource_ranges.partition_point(|range: &(usize, usize)| range.0 < table_start);
        if resource_insertion > 0 && resource_ranges[resource_insertion - 1].1 > table_start {
            return Err(ne_error("relocation table overlaps resource data"));
        }
        if nonresident_range
            .is_some_and(|range: (usize, usize)| range.0 < table_start && table_start < range.1)
        {
            return Err(ne_error(
                "relocation table overlaps the nonresident name table",
            ));
        }
        let mut reader: ByteReader<'_> = ByteReader::new(bytes);
        reader
            .seek(table_start)
            .map_err(|error: ByteReadError| read_error("relocation table", error))?;
        let count: usize = usize::from(read_u16(&mut reader, "relocation count")?);
        total_records = total_records
            .checked_add(count)
            .ok_or_else(|| ne_error("total relocation count overflow"))?;
        if total_records > MAX_RELOCATION_RECORDS {
            return Err(ne_error("total relocation count exceeds 65536"));
        }
        let table_bytes: usize = count
            .checked_mul(RELOCATION_RECORD_SIZE)
            .ok_or_else(|| ne_error("relocation table size overflow"))?;
        let table_end: usize = reader
            .position()
            .checked_add(table_bytes)
            .ok_or_else(|| ne_error("relocation table range overflow"))?;
        let next_segment_index: usize =
            segment_starts.partition_point(|candidate: &usize| *candidate < table_start);
        let next_segment_start: usize = segment_starts
            .get(next_segment_index)
            .copied()
            .unwrap_or(bytes.len());
        let next_resource_index: usize =
            resource_ranges.partition_point(|range: &(usize, usize)| range.0 < table_start);
        let next_resource_start: usize = resource_ranges
            .get(next_resource_index)
            .map_or(bytes.len(), |range: &(usize, usize)| range.0);
        let next_nonresident_start: usize =
            nonresident_range.map_or(bytes.len(), |range: (usize, usize)| {
                if range.0 >= table_start {
                    range.0
                } else {
                    bytes.len()
                }
            });
        let table_limit: usize = next_segment_start
            .min(next_resource_start)
            .min(next_nonresident_start);
        if table_bytes > reader.remaining() || table_end > table_limit {
            return Err(ne_error(format!(
                "segment {} relocation table is truncated",
                segment.ordinal
            )));
        }
        for _ in 0..count {
            let source_type: u8 = reader
                .read_u8()
                .map_err(|error: ByteReadError| read_error("relocation source type", error))?;
            let normalized_source_type: u8 = source_type & RELOCATION_SOURCE_MASK;
            let source_width: usize =
                relocation_source_width(normalized_source_type).ok_or_else(|| {
                    ne_error(format!("unsupported relocation source type {source_type}"))
                })?;
            let relocation_flags: u8 = reader
                .read_u8()
                .map_err(|error: ByteReadError| read_error("relocation flags", error))?;
            if relocation_flags & !RELOCATION_KNOWN_FLAGS != 0 {
                return Err(ne_error("relocation contains unsupported flag bits"));
            }
            if relocation_flags & RELOCATION_INTERNAL_CHAIN != 0 {
                return Err(ne_error(
                    "classic NE does not support the internal-chain relocation flag",
                ));
            }
            let source_offset: u16 = read_u16(&mut reader, "relocation source offset")?;
            let source_end: usize = usize::from(source_offset)
                .checked_add(source_width)
                .ok_or_else(|| ne_error("relocation source range overflow"))?;
            if source_end > initialized_data.len() {
                return Err(ne_error(
                    "relocation source range exceeds file-backed segment data",
                ));
            }
            let target_a: u16 = read_u16(&mut reader, "relocation target module")?;
            let target_b: u16 = read_u16(&mut reader, "relocation target value")?;
            if relocation_flags & RELOCATION_ADDITIVE == 0 {
                validate_relocation_chain(
                    &initialized_data,
                    source_offset,
                    &mut total_chain_steps,
                )?;
            }
            match relocation_flags & RELOCATION_TARGET_MASK {
                0 => validate_internal_relocation(segments, entries, target_a, target_b)?,
                1 | 2 => {
                    let (imported_name_base, imported_name_limit): (usize, usize) =
                        imported_name_range.ok_or_else(|| {
                            ne_error("imported relocation requires an imported name table")
                        })?;
                    let module_index: usize = usize::from(target_a)
                        .checked_sub(1)
                        .ok_or_else(|| ne_error("relocation module index is zero"))?;
                    let library: String = modules
                        .get(module_index)
                        .cloned()
                        .ok_or_else(|| ne_error("relocation module index is out of range"))?;
                    let name: String = if relocation_flags & RELOCATION_TARGET_MASK == 1 {
                        if target_b == 0 {
                            return Err(ne_error("imported relocation ordinal is zero"));
                        }
                        format!("#{target_b}")
                    } else {
                        read_imported_name(
                            bytes,
                            imported_name_base,
                            imported_name_limit,
                            target_b,
                        )?
                    };
                    imports.insert((library, name));
                    if imports.len() > MAX_UNIQUE_IMPORTS {
                        return Err(ne_error("unique imports exceed 65536"));
                    }
                }
                3 => {
                    if !(1..=6).contains(&target_a) {
                        return Err(ne_error("OS fixup type is unsupported"));
                    }
                    if target_b != 0 {
                        return Err(ne_error("OS fixup reserved field is nonzero"));
                    }
                }
                _ => return Err(ne_error("relocation target type is invalid")),
            }
        }
    }
    Ok(imports
        .into_iter()
        .map(|(library, name): (String, String)| ImportInfo { library, name })
        .collect())
}

const RELOCATION_SOURCE_MASK: u8 = 0x0f;

const fn relocation_source_width(source_type: u8) -> Option<usize> {
    match source_type {
        0 => Some(1),
        2 | 5 => Some(2),
        3 | 13 => Some(4),
        11 => Some(6),
        _ => None,
    }
}

fn validate_internal_relocation(
    segments: &[NeSegment],
    entries: &[Option<NeEntry>],
    target_segment_word: u16,
    target_value: u16,
) -> Result<()> {
    let [target_segment, reserved]: [u8; 2] = target_segment_word.to_le_bytes();
    if reserved != 0 {
        return Err(ne_error("internal relocation segment has reserved bits"));
    }
    if target_segment == 0xff {
        let entry_index: usize = usize::from(target_value)
            .checked_sub(1)
            .ok_or_else(|| ne_error("internal relocation entry ordinal is zero"))?;
        let Some(Some(entry)) = entries.get(entry_index) else {
            return Err(ne_error(
                "internal relocation references a missing movable entry",
            ));
        };
        if !entry.movable {
            return Err(ne_error(
                "internal relocation references a non-movable entry",
            ));
        }
        return Ok(());
    }
    let segment_index: usize = usize::from(target_segment)
        .checked_sub(1)
        .ok_or_else(|| ne_error("internal relocation segment is zero"))?;
    let segment: &NeSegment = segments
        .get(segment_index)
        .ok_or_else(|| ne_error("internal relocation segment is out of range"))?;
    if usize::from(target_value) >= segment.allocation_len {
        return Err(ne_error(
            "internal relocation offset is outside its segment",
        ));
    }
    Ok(())
}

fn validate_relocation_chain(
    initialized_data: &[u8],
    source_offset: u16,
    total_steps: &mut usize,
) -> Result<()> {
    let max_steps: usize = initialized_data.len().saturating_add(1);
    let mut current: u16 = source_offset;
    for _ in 0..max_steps {
        *total_steps = total_steps
            .checked_add(1)
            .ok_or_else(|| ne_error("total relocation chain work overflow"))?;
        if *total_steps > MAX_RELOCATION_CHAIN_STEPS {
            return Err(ne_error("total relocation chain work exceeds 1000000"));
        }
        let relative: usize = usize::from(current);
        let relative_end: usize = relative
            .checked_add(2)
            .ok_or_else(|| ne_error("relocation chain offset overflow"))?;
        if relative_end > initialized_data.len() {
            return Err(ne_error("relocation chain leaves its segment data"));
        }
        let mut reader: ByteReader<'_> = ByteReader::new(initialized_data);
        reader
            .seek(relative)
            .map_err(|error: ByteReadError| read_error("relocation chain", error))?;
        current = read_u16(&mut reader, "relocation chain")?;
        if current == u16::MAX {
            return Ok(());
        }
    }
    Err(ne_error("relocation chain has no terminator"))
}

fn parse_resources(
    bytes: &[u8],
    header: &NeHeader,
    segments: &[NeSegment],
) -> Result<ParsedResources> {
    if header.target_os == TargetOs::Os2 {
        return parse_os2_resources(bytes, header, segments);
    }
    if header.resource_table_offset == 0
        || header.resource_table_offset == header.resident_name_offset
    {
        return Ok(ParsedResources {
            ranges: Vec::new(),
            loader_span: None,
        });
    }
    let start: usize = relative_offset(header, header.resource_table_offset, "resource table")?;
    let limit: usize = next_relative_table_offset(
        header,
        header.resource_table_offset,
        [
            header.resident_name_offset,
            header.module_table_offset,
            header.imported_name_offset,
            header.entry_table_offset,
        ],
        bytes.len(),
    )?;
    if limit <= start || limit > bytes.len() {
        return Err(ne_error("resource table bounds are invalid"));
    }
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(start)
        .map_err(|error: ByteReadError| read_error("resource table", error))?;
    let shift: u16 = read_u16(&mut reader, "resource alignment shift")?;
    if u32::from(shift) >= usize::BITS {
        return Err(ne_error("resource alignment shift exceeds host width"));
    }
    let mut resources: Vec<ResourceRange> = Vec::new();
    let mut string_identifiers: Vec<(u16, &'static str)> = Vec::new();
    loop {
        if reader.position() >= limit {
            return Err(ne_error("resource type list has no terminator"));
        }
        let type_id: u16 = read_u16(&mut reader, "resource type")?;
        if type_id == 0 {
            break;
        }
        if type_id & 0x8000 == 0 {
            string_identifiers.push((type_id, "resource type"));
        }
        let count: usize = usize::from(read_u16(&mut reader, "resource type count")?);
        let _reserved: u32 = read_u32(&mut reader, "resource reserved value")?;
        let next_count: usize = resources
            .len()
            .checked_add(count)
            .ok_or_else(|| ne_error("resource count overflow"))?;
        if next_count > MAX_RESOURCE_RECORDS {
            return Err(ne_error("resource records exceed 65536"));
        }
        let records_size: usize = count
            .checked_mul(RESOURCE_RECORD_SIZE)
            .ok_or_else(|| ne_error("resource records size overflow"))?;
        let records_end: usize = reader
            .position()
            .checked_add(records_size)
            .ok_or_else(|| ne_error("resource records range overflow"))?;
        if records_end > limit {
            return Err(ne_error("resource records extend past the resource table"));
        }
        for _ in 0..count {
            let raw_offset: u16 = read_u16(&mut reader, "resource offset")?;
            let raw_length: u16 = read_u16(&mut reader, "resource length")?;
            let _flags: u16 = read_u16(&mut reader, "resource flags")?;
            let name_id: u16 = read_u16(&mut reader, "resource name")?;
            if name_id & 0x8000 == 0 {
                string_identifiers.push((name_id, "resource name"));
            }
            let _reserved: u32 = read_u32(&mut reader, "resource runtime value")?;
            let file_offset: usize =
                checked_scaled_u16(raw_offset, u32::from(shift), "resource offset")?;
            let length: usize =
                checked_scaled_u16(raw_length, u32::from(shift), "resource length")?;
            let end: usize = file_offset
                .checked_add(length)
                .ok_or_else(|| ne_error("resource range overflow"))?;
            if end > bytes.len() {
                return Err(ne_error("resource data extends past end of file"));
            }
            resources.push(ResourceRange {
                type_id,
                name_id,
                file_offset,
                length,
                segment_ordinal: None,
            });
        }
    }
    let string_area_start: usize = reader.position();
    for &(raw, context) in &string_identifiers {
        validate_resource_identifier_bounds(start, string_area_start, limit, raw, context)?;
    }
    let (valid_string_offsets, resource_table_end): (BTreeSet<u16>, usize) =
        if string_identifiers.is_empty() {
            (BTreeSet::new(), string_area_start)
        } else {
            parse_resource_string_offsets(bytes, start, string_area_start, limit)?
        };
    for (raw, context) in string_identifiers {
        validate_resource_identifier_start(&valid_string_offsets, raw, context)?;
    }
    Ok(ParsedResources {
        ranges: resources,
        loader_span: Some((start, resource_table_end)),
    })
}

fn parse_os2_resources(
    bytes: &[u8],
    header: &NeHeader,
    segments: &[NeSegment],
) -> Result<ParsedResources> {
    let count: usize = usize::from(header.os2_resource_segment_count);
    if count == 0 {
        return Ok(ParsedResources {
            ranges: Vec::new(),
            loader_span: None,
        });
    }
    if count > segments.len() {
        return Err(ne_error("OS/2 resource count exceeds the segment count"));
    }
    let start: usize =
        relative_offset(header, header.resource_table_offset, "OS/2 resource table")?;
    let table_bytes: usize = count
        .checked_mul(4)
        .ok_or_else(|| ne_error("OS/2 resource table size overflow"))?;
    let end: usize = start
        .checked_add(table_bytes)
        .ok_or_else(|| ne_error("OS/2 resource table range overflow"))?;
    let limit: usize = next_relative_table_offset(
        header,
        header.resource_table_offset,
        [
            header.resident_name_offset,
            header.module_table_offset,
            header.imported_name_offset,
            header.entry_table_offset,
        ],
        bytes.len(),
    )?;
    if end > limit || end > bytes.len() {
        return Err(ne_error("OS/2 resource table is truncated"));
    }
    let first_resource_segment: usize = segments.len() - count;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(start)
        .map_err(|error: ByteReadError| read_error("OS/2 resource table", error))?;
    let mut resources: Vec<ResourceRange> = Vec::with_capacity(count);
    for index in 0..count {
        let type_id: u16 = read_u16(&mut reader, "OS/2 resource type")?;
        let name_id: u16 = read_u16(&mut reader, "OS/2 resource name")?;
        let segment: &NeSegment = segments
            .get(first_resource_segment + index)
            .ok_or_else(|| ne_error("OS/2 resource segment is missing"))?;
        if segment.file_offset == 0 {
            return Err(ne_error("OS/2 resource segment has no file-backed data"));
        }
        resources.push(ResourceRange {
            type_id,
            name_id,
            file_offset: segment.file_offset,
            length: segment.data_len,
            segment_ordinal: Some(segment.ordinal),
        });
    }
    Ok(ParsedResources {
        ranges: resources,
        loader_span: Some((start, end)),
    })
}

fn validate_loader_data_ownership(
    file_len: usize,
    header: &NeHeader,
    segments: &[NeSegment],
    resources: &[ResourceRange],
    resource_span: Option<(usize, usize)>,
    resident_span: Option<(usize, usize)>,
    imported_name_range: Option<(usize, usize)>,
) -> Result<()> {
    let header_end: usize = header
        .base
        .checked_add(NE_HEADER_SIZE)
        .ok_or_else(|| ne_error("new executable header range overflow"))?;
    let segment_table_start: usize =
        relative_offset(header, header.segment_table_offset, "segment table")?;
    let segment_table_bytes: usize = usize::from(header.segment_count)
        .checked_mul(SEGMENT_RECORD_SIZE)
        .ok_or_else(|| ne_error("segment table size overflow"))?;
    let segment_table_end: usize = segment_table_start
        .checked_add(segment_table_bytes)
        .ok_or_else(|| ne_error("segment table range overflow"))?;
    let mut loader_spans: Vec<(usize, usize, &'static str)> = vec![
        (header.base, header_end, "new executable header"),
        (segment_table_start, segment_table_end, "segment table"),
    ];
    if let Some((start, end)) = resource_span {
        let context: &'static str = match header.target_os {
            TargetOs::Windows => "resource table",
            TargetOs::Os2 => "OS/2 resource table",
        };
        loader_spans.push((start, end, context));
    }
    if let Some((start, end)) = resident_span
        && end > start
    {
        loader_spans.push((start, end, "resident name table"));
    }
    if header.module_count != 0 {
        let start: usize =
            relative_offset(header, header.module_table_offset, "module reference table")?;
        let length: usize = usize::from(header.module_count)
            .checked_mul(2)
            .ok_or_else(|| ne_error("module reference table size overflow"))?;
        let end: usize = start
            .checked_add(length)
            .ok_or_else(|| ne_error("module reference table range overflow"))?;
        loader_spans.push((start, end, "module reference table"));
    }
    if let Some((start, end)) = imported_name_range {
        loader_spans.push((start, end, "imported name table"));
    }
    if header.entry_table_offset != 0 {
        let start: usize = relative_offset(header, header.entry_table_offset, "entry table")?;
        let end: usize = start
            .checked_add(usize::from(header.entry_table_length))
            .ok_or_else(|| ne_error("entry table range overflow"))?;
        loader_spans.push((start, end, "entry table"));
    }
    let relative_loader_end: usize = loader_spans
        .iter()
        .map(|(_, end, _): &(usize, usize, &'static str)| *end)
        .max()
        .ok_or_else(|| ne_error("new executable loader spans are empty"))?;
    if header.nonresident_name_size != 0 {
        let start: usize = usize::try_from(header.nonresident_name_offset)
            .map_err(|_| ne_error("nonresident name table offset does not fit this host"))?;
        let end: usize = start
            .checked_add(usize::from(header.nonresident_name_size))
            .ok_or_else(|| ne_error("nonresident name table range overflow"))?;
        loader_spans.push((start, end, "nonresident name table"));
    }
    if loader_spans
        .iter()
        .any(|(_, end, _): &(usize, usize, &'static str)| *end > file_len)
    {
        return Err(ne_error(
            "new executable loader table extends past end of file",
        ));
    }
    loader_spans.sort_unstable_by_key(|span: &(usize, usize, &'static str)| span.0);
    for pair in loader_spans.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(ne_error(format!("{} overlaps {}", pair[0].2, pair[1].2)));
        }
    }
    for segment in segments
        .iter()
        .filter(|segment: &&NeSegment| segment.file_offset != 0)
    {
        if segment.file_offset < relative_loader_end {
            return Err(ne_error("segment data precedes new executable loader data"));
        }
        let end: usize = segment
            .file_offset
            .checked_add(segment.data_len)
            .ok_or_else(|| ne_error("segment data range overflow"))?;
        if loader_spans.iter().any(
            |(loader_start, loader_end, _): &(usize, usize, &'static str)| {
                segment.file_offset < *loader_end && *loader_start < end
            },
        ) {
            return Err(ne_error("segment data overlaps new executable loader data"));
        }
    }
    for resource in resources
        .iter()
        .filter(|resource: &&ResourceRange| resource.length != 0)
    {
        if resource.file_offset < relative_loader_end {
            return Err(ne_error(
                "resource data precedes new executable loader data",
            ));
        }
        let end: usize = resource
            .file_offset
            .checked_add(resource.length)
            .ok_or_else(|| ne_error("resource range overflow"))?;
        if loader_spans.iter().any(
            |(loader_start, loader_end, _): &(usize, usize, &'static str)| {
                resource.file_offset < *loader_end && *loader_start < end
            },
        ) {
            return Err(ne_error(
                "resource data overlaps new executable loader data",
            ));
        }
    }
    Ok(())
}

fn validate_resource_segment_overlap(
    resources: &[ResourceRange],
    segments: &[NeSegment],
) -> Result<()> {
    let mut resource_ranges: Vec<(usize, usize)> = resources
        .iter()
        .filter(|resource: &&ResourceRange| resource.length != 0)
        .map(|resource: &ResourceRange| {
            resource
                .file_offset
                .checked_add(resource.length)
                .map(|end: usize| (resource.file_offset, end))
                .ok_or_else(|| ne_error("resource range overflow"))
        })
        .collect::<Result<Vec<(usize, usize)>>>()?;
    resource_ranges.sort_unstable_by_key(|range: &(usize, usize)| range.0);
    if resource_ranges
        .windows(2)
        .any(|pair: &[(usize, usize)]| pair[0].1 > pair[1].0)
    {
        return Err(ne_error("resource data ranges overlap"));
    }
    let mut segment_ranges: Vec<(usize, usize)> = Vec::with_capacity(segments.len());
    for segment in segments
        .iter()
        .filter(|segment: &&NeSegment| segment.file_offset != 0)
    {
        let end: usize = segment
            .file_offset
            .checked_add(segment.data_len)
            .ok_or_else(|| ne_error("segment data range overflow"))?;
        segment_ranges.push((segment.file_offset, end));
    }
    segment_ranges.sort_unstable_by_key(|range: &(usize, usize)| range.0);
    for resource in resources {
        if resource.segment_ordinal.is_some() || resource.length == 0 {
            continue;
        }
        let resource_end: usize = resource
            .file_offset
            .checked_add(resource.length)
            .ok_or_else(|| ne_error("resource range overflow"))?;
        let insertion: usize =
            segment_ranges.partition_point(|range: &(usize, usize)| range.0 < resource_end);
        if insertion > 0 && segment_ranges[insertion - 1].1 > resource.file_offset {
            return Err(ne_error("resource data overlaps segment data"));
        }
    }
    Ok(())
}

fn parse_resource_string_offsets(
    bytes: &[u8],
    table_start: usize,
    string_area_start: usize,
    table_limit: usize,
) -> Result<(BTreeSet<u16>, usize)> {
    let addressable_end: usize = table_start
        .checked_add(usize::from(u16::MAX) + 1)
        .ok_or_else(|| ne_error("resource string address range overflow"))?
        .min(table_limit);
    let area: &[u8] = bytes
        .get(string_area_start..addressable_end)
        .ok_or_else(|| ne_error("resource string area leaves the file"))?;
    let mut reader: ByteReader<'_> = ByteReader::new(area);
    let mut offsets: BTreeSet<u16> = BTreeSet::new();
    while !reader.is_empty() {
        let absolute: usize = string_area_start
            .checked_add(reader.position())
            .ok_or_else(|| ne_error("resource string offset overflow"))?;
        let relative: u16 = u16::try_from(
            absolute
                .checked_sub(table_start)
                .ok_or_else(|| ne_error("resource string precedes its table"))?,
        )
        .map_err(|_| ne_error("resource string offset exceeds 65535"))?;
        let length: usize = usize::from(
            reader
                .read_u8()
                .map_err(|error: ByteReadError| read_error("resource string", error))?,
        );
        if length == 0 {
            let end: usize = string_area_start
                .checked_add(reader.position())
                .ok_or_else(|| ne_error("resource string area range overflow"))?;
            return Ok((offsets, end));
        }
        reader
            .read_bytes(length)
            .map_err(|error: ByteReadError| read_error("resource string", error))?;
        offsets.insert(relative);
    }
    let end: usize = string_area_start
        .checked_add(reader.position())
        .ok_or_else(|| ne_error("resource string area range overflow"))?;
    Ok((offsets, end))
}

fn validate_resource_identifier_bounds(
    table_start: usize,
    string_area_start: usize,
    table_limit: usize,
    raw: u16,
    context: &'static str,
) -> Result<()> {
    let offset: usize = table_start
        .checked_add(usize::from(raw))
        .ok_or_else(|| ne_error(format!("{context} offset overflow")))?;
    if offset < string_area_start {
        return Err(ne_error(format!(
            "{context} offset precedes resource strings"
        )));
    }
    if offset >= table_limit {
        return Err(ne_error(format!("{context} offset is outside the table")));
    }
    Ok(())
}

fn validate_resource_identifier_start(
    valid_offsets: &BTreeSet<u16>,
    raw: u16,
    context: &'static str,
) -> Result<()> {
    if !valid_offsets.contains(&raw) {
        return Err(ne_error(format!(
            "{context} does not reference a resource string start"
        )));
    }
    Ok(())
}

fn lower_entries(
    entries: &[Option<NeEntry>],
    resident_names: &[NamedOrdinal],
    nonresident_names: &[NamedOrdinal],
) -> Result<(Vec<SymbolInfo>, Vec<ExportInfo>)> {
    let mut names_by_ordinal: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    for named in resident_names.iter().chain(nonresident_names) {
        if named.ordinal != 0 {
            let index: usize = usize::from(named.ordinal - 1);
            if !matches!(entries.get(index), Some(Some(_))) {
                return Err(ne_error("export name references a missing entry ordinal"));
            }
            names_by_ordinal
                .entry(named.ordinal)
                .or_default()
                .insert(named.name.clone());
        }
    }
    let mut symbols: Vec<SymbolInfo> = Vec::new();
    let mut exports: Vec<ExportInfo> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let Some(entry) = entry else {
            continue;
        };
        let ordinal: u16 =
            u16::try_from(index + 1).map_err(|_| ne_error("entry ordinal does not fit 16 bits"))?;
        let address: u64 = segmented_address(u16::from(entry.segment), entry.offset);
        let names: Vec<String> = names_by_ordinal.get(&ordinal).map_or_else(
            || vec![format!("ordinal_{ordinal}")],
            |names| names.iter().cloned().collect(),
        );
        for name in names {
            symbols.push(SymbolInfo {
                name: name.clone(),
                address,
                size: 0,
                kind: SymbolRole::Text,
            });
            if entry.exported || names_by_ordinal.contains_key(&ordinal) {
                exports.push(ExportInfo { name, address });
            }
        }
    }
    Ok((symbols, exports))
}

fn lower_sections(segments: &[NeSegment], resources: &[ResourceRange]) -> Result<Vec<SectionInfo>> {
    let capacity: usize = segments
        .len()
        .checked_add(resources.len())
        .ok_or_else(|| ne_error("section count overflow"))?;
    let mut sections: Vec<SectionInfo> = Vec::with_capacity(capacity);
    for segment in segments {
        if resources
            .iter()
            .any(|resource: &ResourceRange| resource.segment_ordinal == Some(segment.ordinal))
        {
            continue;
        }
        sections.push(SectionInfo {
            name: segment_name(segment),
            address: segmented_address(segment.ordinal, 0),
            size: host_size_to_u64(segment.allocation_len, "segment allocation size")?,
        });
    }
    for resource in resources {
        let (address, size): (u64, u64) = if let Some(ordinal) = resource.segment_ordinal {
            let segment_index: usize = usize::from(ordinal)
                .checked_sub(1)
                .ok_or_else(|| ne_error("OS/2 resource segment ordinal is zero"))?;
            let segment: &NeSegment = segments
                .get(segment_index)
                .ok_or_else(|| ne_error("OS/2 resource segment is missing"))?;
            (
                segmented_address(ordinal, 0),
                host_size_to_u64(segment.allocation_len, "resource segment allocation size")?,
            )
        } else {
            (
                host_size_to_u64(resource.file_offset, "resource file offset")?,
                host_size_to_u64(resource.length, "resource length")?,
            )
        };
        sections.push(SectionInfo {
            name: format!("resource_{:04x}_{:04x}", resource.type_id, resource.name_id),
            address,
            size,
        });
    }
    Ok(sections)
}

fn host_size_to_u64(value: usize, context: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| ne_error(format!("{context} does not fit 64 bits")))
}

fn checked_scaled_u16(value: u16, shift: u32, context: &'static str) -> Result<usize> {
    let scale: usize = 1usize
        .checked_shl(shift)
        .ok_or_else(|| ne_error(format!("{context} shift exceeds host width")))?;
    usize::from(value)
        .checked_mul(scale)
        .ok_or_else(|| ne_error(format!("{context} overflow")))
}

fn relative_offset(header: &NeHeader, raw: u16, context: &'static str) -> Result<usize> {
    if raw == 0 {
        return Err(ne_error(format!("{context} offset is zero")));
    }
    header
        .base
        .checked_add(usize::from(raw))
        .ok_or_else(|| ne_error(format!("{context} offset overflow")))
}

fn next_relative_table_offset<const N: usize>(
    header: &NeHeader,
    start: u16,
    candidates: [u16; N],
    file_len: usize,
) -> Result<usize> {
    let raw_limit: Option<u16> = candidates
        .into_iter()
        .filter(|candidate: &u16| *candidate > start)
        .min();
    raw_limit.map_or(Ok(file_len), |raw: u16| {
        relative_offset(header, raw, "table boundary")
    })
}

fn read_imported_name(bytes: &[u8], base: usize, limit: usize, raw_offset: u16) -> Result<String> {
    let offset: usize = base
        .checked_add(usize::from(raw_offset))
        .ok_or_else(|| ne_error("imported name offset overflow"))?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(offset)
        .map_err(|error: ByteReadError| read_error("imported name", error))?;
    let length: u8 = reader
        .read_u8()
        .map_err(|error: ByteReadError| read_error("imported name length", error))?;
    if length == 0 {
        return Err(ne_error("imported name is empty"));
    }
    let name_end: usize = offset
        .checked_add(1 + usize::from(length))
        .ok_or_else(|| ne_error("imported name range overflow"))?;
    if name_end > limit {
        return Err(ne_error(
            "imported name extends past the imported name table",
        ));
    }
    let raw: &[u8] = reader
        .read_bytes(usize::from(length))
        .map_err(|error: ByteReadError| read_error("imported name", error))?;
    Ok(decode_oem(raw))
}

fn decode_oem(raw: &[u8]) -> String {
    let mut decoded: String = String::with_capacity(raw.len());
    for byte in raw {
        if (byte.is_ascii_graphic() || *byte == b' ') && *byte != b'\\' {
            decoded.push(char::from(*byte));
        } else {
            let _: std::fmt::Result = write!(decoded, "\\x{byte:02X}");
        }
    }
    decoded
}

fn segment_name(segment: &NeSegment) -> String {
    let kind: &str = if segment.flags & 1 == 0 {
        "code"
    } else {
        "data"
    };
    format!("{kind}_{}", segment.ordinal)
}

fn segmented_address(segment: u16, offset: u16) -> u64 {
    u64::from(segment) << 16 | u64::from(offset)
}

fn read_u16(reader: &mut ByteReader<'_>, context: &'static str) -> Result<u16> {
    reader
        .read_u16_le()
        .map_err(|error: ByteReadError| read_error(context, error))
}

fn read_u32(reader: &mut ByteReader<'_>, context: &'static str) -> Result<u32> {
    reader
        .read_u32_le()
        .map_err(|error: ByteReadError| read_error(context, error))
}

fn read_error(context: &'static str, error: ByteReadError) -> Error {
    ne_error(format!("{context}: {error}"))
}

fn ne_error(reason: impl Into<String>) -> Error {
    Error::Ne(reason.into())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn write_u16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn minimal_ne(resident_export: bool, resource: bool) -> Vec<u8> {
        const BASE: usize = 0x40;
        const SEGMENT_TABLE: usize = 0x80;
        const RESIDENT_TABLE: usize = 0x88;
        const ENTRY_TABLE: usize = 0xa0;
        let mut image: Vec<u8> = vec![0u8; 514];
        image[..2].copy_from_slice(b"MZ");
        write_u16(&mut image, 0x08, 4);
        write_u32(&mut image, 0x3c, 0x40);
        image[BASE..BASE + 2].copy_from_slice(b"NE");
        image[BASE + 2] = 5;
        image[BASE + 3] = 1;
        if resident_export {
            write_u16(&mut image, BASE + 4, 0x60);
            write_u16(&mut image, BASE + 6, 6);
        }
        write_u16(&mut image, BASE + 0x16, 1);
        write_u16(&mut image, BASE + 0x1c, 1);
        write_u16(&mut image, BASE + 0x22, 0x40);
        if resource {
            write_u16(&mut image, BASE + 0x24, 0x48);
            write_u16(&mut image, BASE + 0x26, 0x60);
        } else if resident_export {
            write_u16(&mut image, BASE + 0x26, 0x48);
        }
        image[BASE + 0x36] = 2;
        write_u16(&mut image, SEGMENT_TABLE, 1);
        write_u16(&mut image, SEGMENT_TABLE + 2, 1);
        write_u16(&mut image, SEGMENT_TABLE + 6, 1);
        image[0x200] = 0x90;
        if resident_export {
            image[RESIDENT_TABLE] = 1;
            image[RESIDENT_TABLE + 1] = b'm';
            write_u16(&mut image, RESIDENT_TABLE + 2, 0);
            image[RESIDENT_TABLE + 4] = 4;
            image[RESIDENT_TABLE + 5..RESIDENT_TABLE + 9].copy_from_slice(b"main");
            write_u16(&mut image, RESIDENT_TABLE + 9, 1);
            image[RESIDENT_TABLE + 11] = 0;
            image[ENTRY_TABLE] = 1;
            image[ENTRY_TABLE + 1] = 1;
            image[ENTRY_TABLE + 2] = 1;
            write_u16(&mut image, ENTRY_TABLE + 3, 0);
            image[ENTRY_TABLE + 5] = 0;
        }
        if resource {
            write_u16(&mut image, RESIDENT_TABLE, 0);
            write_u16(&mut image, RESIDENT_TABLE + 2, 0x8002);
            write_u16(&mut image, RESIDENT_TABLE + 4, 1);
            write_u32(&mut image, RESIDENT_TABLE + 6, 0);
            write_u16(&mut image, RESIDENT_TABLE + 10, 0x0201);
            write_u16(&mut image, RESIDENT_TABLE + 12, 1);
            write_u16(&mut image, RESIDENT_TABLE + 14, 0);
            write_u16(&mut image, RESIDENT_TABLE + 16, 0x8001);
            write_u32(&mut image, RESIDENT_TABLE + 18, 0);
            write_u16(&mut image, RESIDENT_TABLE + 22, 0);
            image[0xa0] = 0;
            image[0x201] = 0xaa;
        }
        image
    }

    fn zero_segment_ne_with_nonresident(base: usize, nonresident_start: usize) -> Vec<u8> {
        let header_end: usize = base + NE_HEADER_SIZE;
        let image_len: usize = header_end.max(nonresident_start + 1);
        let mut image: Vec<u8> = vec![0; image_len];
        image[..2].copy_from_slice(b"MZ");
        write_u16(&mut image, 0x08, 4);
        write_u32(
            &mut image,
            0x3c,
            u32::try_from(base).expect("base fits u32"),
        );
        image[base..base + 2].copy_from_slice(b"NE");
        write_u16(&mut image, base + 0x20, 1);
        write_u16(&mut image, base + 0x22, 0x40);
        image[base + 0x36] = 2;
        image[nonresident_start] = 0;
        write_u32(
            &mut image,
            base + 0x2c,
            u32::try_from(nonresident_start).expect("nonresident start fits u32"),
        );
        image
    }

    fn os2_ne_with_resource() -> Vec<u8> {
        let mut image: Vec<u8> = minimal_ne(false, false);
        image.resize(0x401, 0);
        image[0x76] = 1;
        write_u16(&mut image, 0x5c, 2);
        write_u16(&mut image, 0x64, 0x50);
        write_u16(&mut image, 0x66, 0x54);
        write_u16(&mut image, 0x74, 1);
        write_u16(&mut image, 0x88, 2);
        write_u16(&mut image, 0x8a, 1);
        write_u16(&mut image, 0x8e, 4);
        write_u16(&mut image, 0x90, 0x8001);
        write_u16(&mut image, 0x92, 0x0042);
        image[0x94] = 0;
        image[0x400] = 0xaa;
        image
    }

    fn resource_only_windows_ne() -> Vec<u8> {
        let mut image: Vec<u8> = minimal_ne(false, false);
        write_u16(&mut image, 0x54, 0);
        write_u16(&mut image, 0x56, 0);
        write_u16(&mut image, 0x58, 0);
        write_u16(&mut image, 0x5a, 0);
        write_u16(&mut image, 0x5c, 0);
        write_u16(&mut image, 0x64, 0x40);
        write_u16(&mut image, 0x66, 0x70);
        write_u16(&mut image, 0x68, 0x74);
        write_u16(&mut image, 0x6a, 0x74);
        write_u16(&mut image, 0x44, 0x74);
        write_u16(&mut image, 0x46, 0);
        write_u16(&mut image, 0x80, 0);
        write_u16(&mut image, 0x82, 0x0018);
        write_u16(&mut image, 0x84, 1);
        write_u32(&mut image, 0x86, 0);
        write_u16(&mut image, 0x8a, 0x0201);
        write_u16(&mut image, 0x8c, 1);
        write_u16(&mut image, 0x8e, 0);
        write_u16(&mut image, 0x90, 0x0018);
        write_u32(&mut image, 0x92, 0);
        write_u16(&mut image, 0x96, 0);
        image[0x98] = 0x17;
        image[0x99..0xb0].fill(b'x');
        image[0xb0] = 0;
        image[0x201] = 0xaa;
        image
    }

    #[test]
    fn zero_alignment_uses_the_specified_512_byte_default() {
        let image: Vec<u8> = minimal_ne(false, false);
        let parsed: NativeFile = parse_ne(&image).expect("zero-shift NE");
        assert_eq!(parsed.segments.len(), 1);
        assert!(matches!(parse_ne(&image[..0x200]), Err(Error::Ne(_))));
    }

    #[test]
    fn scaled_offsets_reject_lost_high_bits() {
        let mut segment: Vec<u8> = minimal_ne(false, false);
        write_u16(&mut segment, 0x72, 63);
        write_u16(&mut segment, 0x80, 2);
        assert!(matches!(parse_ne(&segment), Err(Error::Ne(_))));

        let mut resource: Vec<u8> = minimal_ne(false, true);
        write_u16(&mut resource, 0x88, 63);
        write_u16(&mut resource, 0x92, 2);
        write_u16(&mut resource, 0x94, 0);
        assert!(matches!(parse_ne(&resource), Err(Error::Ne(_))));
    }

    #[test]
    fn empty_loader_tables_can_share_their_boundary() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        write_u16(&mut image, 0x66, 0x48);
        write_u16(&mut image, 0x68, 0x49);
        write_u16(&mut image, 0x6a, 0x49);
        image[0x88] = 0;
        let parsed: NativeFile = parse_ne(&image).expect("empty module table boundary");
        assert_eq!(parsed.segments.len(), 1);
    }

    #[test]
    fn resources_do_not_require_a_resident_name_table() {
        let mut windows: Vec<u8> = minimal_ne(false, true);
        write_u16(&mut windows, 0x66, 0);
        parse_ne(&windows).expect("Windows resource without resident names");

        let mut os2: Vec<u8> = os2_ne_with_resource();
        write_u16(&mut os2, 0x66, 0);
        parse_ne(&os2).expect("OS/2 resource without resident names");
    }

    #[test]
    fn nonresident_names_after_segment_data_are_allowed() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        write_u16(&mut image, 0x72, 1);
        write_u16(&mut image, 0x80, 0x60);
        write_u16(&mut image, 0x60, 1);
        write_u32(&mut image, 0x6c, 0xd0);
        image[0xd0] = 0;
        let parsed: NativeFile = parse_ne(&image).expect("segment before nonresident names");
        assert_eq!(parsed.segments.len(), 1);
    }

    #[test]
    fn nonresident_names_still_reject_segment_overlap() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        write_u16(&mut image, 0x72, 1);
        write_u16(&mut image, 0x80, 0x60);
        write_u16(&mut image, 0x60, 1);
        write_u32(&mut image, 0x6c, 0xc0);
        image[0xc0] = 0;
        assert!(matches!(
            parse_ne(&image),
            Err(Error::Ne(reason)) if reason == "segment data overlaps new executable loader data"
        ));
    }

    #[test]
    fn nonresident_names_at_the_new_header_end_are_allowed_for_a_nonzero_base() {
        let base: usize = 0x100;
        let image: Vec<u8> = zero_segment_ne_with_nonresident(base, base + NE_HEADER_SIZE);

        let parsed: NativeFile = parse_ne(&image).expect("header-end nonresident names");
        assert_eq!(parsed.format, NativeFormat::NeWindows);
    }

    #[test]
    fn nonresident_names_before_the_new_header_are_rejected_for_a_nonzero_base() {
        let base: usize = 0x100;
        let image: Vec<u8> = zero_segment_ne_with_nonresident(base, base - 1);

        let error: Error = parse_ne(&image).expect_err("pre-header nonresident names");
        assert!(matches!(
            error,
            Error::Ne(reason) if reason == "nonresident name table starts before the new executable header"
        ));
    }

    #[test]
    fn real_os2_relocations_accept_standard_ptr48_and_offset32_sources() {
        let real_os2: &[u8] = include_bytes!("../../../corpus/native/formats/hello_os2_ne.exe");
        let mut ptr48: Vec<u8> = real_os2.to_vec();
        ptr48[0x494] = 0x0b;
        let parsed_ptr48: NativeFile = parse_ne(&ptr48).expect("OS/2 PTR48 relocation");
        assert_eq!(parsed_ptr48.format, NativeFormat::NeOs2);
        assert_eq!(parsed_ptr48.imports.len(), 6);

        let mut offset32: Vec<u8> = real_os2.to_vec();
        offset32[0x49c] = 0x0d;
        let parsed_offset32: NativeFile = parse_ne(&offset32).expect("OS/2 OFS32 relocation");
        assert_eq!(parsed_offset32.format, NativeFormat::NeOs2);
        assert_eq!(parsed_offset32.imports.len(), 6);
    }

    #[test]
    fn nonresident_names_can_follow_real_segment_data() {
        let real_ne: &[u8] = include_bytes!("../../../corpus/native/formats/hello_ne.exe");
        let mut image: Vec<u8> = real_ne.to_vec();
        let nonresident_offset: usize = 0x114;
        let nonresident_size: usize = 16;
        let nonresident_names: Vec<u8> =
            image[nonresident_offset..nonresident_offset + nonresident_size].to_vec();
        let new_nonresident_offset: usize = image.len();
        image.extend_from_slice(&nonresident_names);
        let base: usize = 0x80;
        write_u32(
            &mut image,
            base + 0x2c,
            u32::try_from(new_nonresident_offset).expect("fixture offset fits u32"),
        );
        let parsed: NativeFile = parse_ne(&image).expect("nonresident names after segments");
        assert_eq!(parsed.format, NativeFormat::NeWindows);
        assert_eq!(parsed.segments.len(), 2);
    }

    #[test]
    fn resource_only_windows_ne_accepts_empty_program_tables() {
        let image: Vec<u8> = resource_only_windows_ne();
        let parsed: NativeFile = parse_ne(&image).expect("resource-only Windows NE");
        assert_eq!(parsed.format, NativeFormat::NeWindows);
        assert!(parsed.segments.is_empty());
        assert!(parsed.sections.iter().any(|section: &SectionInfo| {
            section.name == "resource_0018_0018" && section.address == 0x201 && section.size == 1
        }));
    }

    #[test]
    fn zero_segment_program_rejects_nonzero_start_registers() {
        for (offset, value, flags, reason) in [
            (
                0x4e,
                1,
                1,
                "automatic data segment is outside the segment table",
            ),
            (0x54, 1, 0, "initial IP requires an initial code segment"),
            (
                0x56,
                1,
                0,
                "initial code segment is outside the segment table",
            ),
            (0x58, 1, 0, "initial SP requires an explicit stack segment"),
            (
                0x5a,
                1,
                0,
                "initial stack segment is outside the segment table",
            ),
        ] {
            let mut image: Vec<u8> = resource_only_windows_ne();
            write_u16(&mut image, 0x4c, flags);
            write_u16(&mut image, offset, value);
            let error: Error = parse_ne(&image).expect_err("zero-segment program register");
            let Error::Ne(actual) = error else {
                unreachable!();
            };
            assert_eq!(actual, reason);
        }
    }

    #[test]
    fn new_executable_header_cannot_overlap_the_dos_header() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        let header: Vec<u8> = image[0x40..0x80].to_vec();
        image[2..0x42].copy_from_slice(&header);
        image[..2].copy_from_slice(b"MZ");
        write_u16(&mut image, 0x08, 4);
        write_u32(&mut image, 0x3c, 2);
        let error: Error = parse_header(&image).expect_err("overlapping header");
        let Error::Ne(reason) = &error else {
            assert!(matches!(error, Error::Ne(_)), "unexpected error: {error}");
            return;
        };
        assert_eq!(reason, "new executable header overlaps the DOS header");
    }

    #[test]
    fn new_executable_header_follows_an_extended_dos_header() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        write_u16(&mut image, 0x08, 8);
        let error: Error = parse_header(&image).expect_err("extended DOS header overlap");
        let Error::Ne(reason) = &error else {
            assert!(matches!(error, Error::Ne(_)), "unexpected error: {error}");
            return;
        };
        assert_eq!(reason, "new executable header overlaps the DOS header");
    }

    #[test]
    fn loader_table_offsets_cannot_point_inside_the_new_executable_header() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        write_u16(&mut image, 0x62, 2);
        let error: Error = parse_header(&image).expect_err("loader table inside NE header");
        let Error::Ne(reason) = &error else {
            assert!(matches!(error, Error::Ne(_)), "unexpected error: {error}");
            return;
        };
        assert_eq!(
            reason,
            "segment table points inside the new executable header"
        );
    }

    #[test]
    fn loader_table_offsets_follow_their_declared_order() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        write_u16(&mut image, 0x62, 0x70);
        write_u16(&mut image, 0x66, 0x60);
        let error: Error = parse_header(&image).expect_err("descending loader tables");
        let Error::Ne(reason) = &error else {
            assert!(matches!(error, Error::Ne(_)), "unexpected error: {error}");
            return;
        };
        assert_eq!(reason, "resident name table does not follow segment table");
    }

    #[test]
    fn odd_new_executable_header_offset_is_parsed_without_alignment_assumptions() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        let loader_tables: Vec<u8> = image[0x40..0xc0].to_vec();
        image[0x41..0xc1].copy_from_slice(&loader_tables);
        image[..2].copy_from_slice(b"MZ");
        write_u16(&mut image, 0x08, 4);
        write_u32(&mut image, 0x3c, 0x41);
        let parsed: NativeFile = parse_ne(&image).expect("odd-offset NE");
        assert_eq!(parsed.format, NativeFormat::NeWindows);
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.sections[0].address, 0x0001_0000);
    }

    #[test]
    fn zero_sector_is_an_uninitialized_segment() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        write_u16(&mut image, 0x80, 0);
        write_u16(&mut image, 0x82, 0xffff);
        write_u16(&mut image, 0x86, 32);
        let parsed: NativeFile = parse_ne(&image).expect("uninitialized NE segment");
        assert_eq!(parsed.sections[0].size, 32);
        assert_eq!(parsed.segments[0].size, 32);
    }

    #[test]
    fn iterated_segment_records_are_validated_and_bounded() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        image[0x76] = 1;
        image.resize(0x207, 0);
        write_u16(&mut image, 0x82, 7);
        write_u16(&mut image, 0x84, SEGMENT_ITERATED_FLAG);
        write_u16(&mut image, 0x86, 6);
        image[0x200..0x207].copy_from_slice(&[2, 0, 3, 0, b'A', b'B', b'C']);
        let parsed: NativeFile = parse_ne(&image).expect("iterated NE segment");
        assert_eq!(parsed.sections[0].size, 6);

        let mut truncated: Vec<u8> = image.clone();
        write_u16(&mut truncated, 0x82, 6);
        assert!(matches!(parse_ne(&truncated), Err(Error::Ne(_))));

        let mut expanded_past_allocation: Vec<u8> = image;
        write_u16(&mut expanded_past_allocation, 0x200, 3);
        assert!(matches!(
            parse_ne(&expanded_past_allocation),
            Err(Error::Ne(_))
        ));
    }

    #[test]
    fn windows_segments_accept_iterated_data() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        image.resize(0x207, 0);
        write_u16(&mut image, 0x82, 7);
        write_u16(&mut image, 0x84, SEGMENT_ITERATED_FLAG);
        write_u16(&mut image, 0x86, 6);
        image[0x200..0x207].copy_from_slice(&[2, 0, 3, 0, b'A', b'B', b'C']);
        let parsed: NativeFile = parse_ne(&image).expect("Windows iterated segment");
        assert_eq!(parsed.format, NativeFormat::NeWindows);
        assert_eq!(parsed.sections[0].size, 6);
    }

    #[test]
    fn cumulative_iterated_expansion_is_bounded_before_materialization() {
        let bytes: [u8; 7] = [0, 0, 128, 2, 0, b'A', b'B'];
        let segment: NeSegment = NeSegment {
            ordinal: 1,
            file_offset: 1,
            data_len: 6,
            initialized_len: 6,
            flags: SEGMENT_ITERATED_FLAG,
            allocation_len: 65_536,
        };
        let mut segments: Vec<NeSegment> = vec![segment; 257];
        assert!(matches!(
            validate_iterated_segments(&bytes, &mut segments),
            Err(Error::Ne(_))
        ));
    }

    #[test]
    fn iterated_segment_record_count_is_bounded() {
        const TOO_MANY_RECORDS: usize = 65_537;
        let bytes: Vec<u8> = vec![0; TOO_MANY_RECORDS * 4 + 1];
        let segment: NeSegment = NeSegment {
            ordinal: 1,
            file_offset: 1,
            data_len: TOO_MANY_RECORDS * 4,
            initialized_len: 0,
            flags: SEGMENT_ITERATED_FLAG,
            allocation_len: 0,
        };
        let mut segments: Vec<NeSegment> = vec![segment];
        let error: Error = validate_iterated_segments(&bytes, &mut segments)
            .expect_err("iterated segment record count");
        let Error::Ne(reason) = error else {
            unreachable!();
        };
        assert_eq!(reason, "iterated segment records exceed 65536");
    }

    #[test]
    fn uninitialized_segment_cannot_declare_file_relocations() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        write_u16(&mut image, 0x80, 0);
        write_u16(&mut image, 0x84, SEGMENT_RELOCATIONS_FLAG);
        write_u16(&mut image, 0x86, 32);
        assert!(matches!(parse_ne(&image), Err(Error::Ne(_))));
    }

    #[test]
    fn additive_relocation_source_must_be_inside_file_backed_segment_data() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        image.resize(0x20b, 0);
        write_u16(&mut image, 0x84, SEGMENT_RELOCATIONS_FLAG);
        write_u16(&mut image, 0x86, 16);
        write_u16(&mut image, 0x201, 1);
        image[0x203] = 0;
        image[0x204] = 0x04;
        write_u16(&mut image, 0x205, 8);
        write_u16(&mut image, 0x207, 1);
        write_u16(&mut image, 0x209, 0);
        assert!(matches!(parse_ne(&image), Err(Error::Ne(_))));
    }

    #[test]
    fn internal_relocation_ff_rejects_a_fixed_entry_ordinal() {
        let mut image: Vec<u8> = minimal_ne(true, false);
        image.resize(0x20b, 0);
        write_u16(&mut image, 0x84, SEGMENT_RELOCATIONS_FLAG);
        write_u16(&mut image, 0x201, 1);
        image[0x203] = 0;
        image[0x204] = RELOCATION_ADDITIVE;
        write_u16(&mut image, 0x205, 0);
        write_u16(&mut image, 0x207, 0x00ff);
        write_u16(&mut image, 0x209, 1);

        let error: Error = parse_ne(&image).expect_err("fixed entry must not resolve as movable");
        assert!(matches!(
            error,
            Error::Ne(reason) if reason == "internal relocation references a non-movable entry"
        ));
    }

    #[test]
    fn internal_relocation_ff_accepts_a_movable_entry_ordinal() {
        let mut image: Vec<u8> = minimal_ne(true, false);
        image.resize(0x20b, 0);
        write_u16(&mut image, 0x46, 9);
        write_u16(&mut image, 0x70, 1);
        image[0xa1] = 0xff;
        image[0xa2] = 1;
        write_u16(&mut image, 0xa3, 0x3fcd);
        image[0xa5] = 1;
        write_u16(&mut image, 0xa6, 0);
        image[0xa8] = 0;
        write_u16(&mut image, 0x84, SEGMENT_RELOCATIONS_FLAG);
        write_u16(&mut image, 0x201, 1);
        image[0x203] = 0;
        image[0x204] = RELOCATION_ADDITIVE;
        write_u16(&mut image, 0x205, 0);
        write_u16(&mut image, 0x207, 0x00ff);
        write_u16(&mut image, 0x209, 1);

        parse_ne(&image).expect("movable entry must resolve as an internal relocation");
    }

    #[test]
    fn os_fixups_are_validated_and_internal_chain_flags_are_refused() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        image.resize(0x20c, 0);
        write_u16(&mut image, 0x82, 2);
        write_u16(&mut image, 0x84, SEGMENT_RELOCATIONS_FLAG);
        write_u16(&mut image, 0x86, 2);
        image[0x200..0x202].copy_from_slice(&u16::MAX.to_le_bytes());
        write_u16(&mut image, 0x202, 1);
        image[0x204] = 2;
        image[0x205] = 3;
        write_u16(&mut image, 0x206, 0);
        write_u16(&mut image, 0x208, 1);
        write_u16(&mut image, 0x20a, 0);
        parse_ne(&image).expect("valid OS fixup");

        let mut reserved: Vec<u8> = image.clone();
        write_u16(&mut reserved, 0x20a, 1);
        assert!(matches!(parse_ne(&reserved), Err(Error::Ne(_))));

        let mut unsupported_type: Vec<u8> = image.clone();
        write_u16(&mut unsupported_type, 0x208, 7);
        assert!(matches!(parse_ne(&unsupported_type), Err(Error::Ne(_))));

        let mut internal_chain: Vec<u8> = image;
        internal_chain[0x205] = RELOCATION_INTERNAL_CHAIN;
        assert!(matches!(parse_ne(&internal_chain), Err(Error::Ne(_))));
    }

    #[test]
    fn windows_relocations_accept_the_loader_compatible_address_type_high_bit() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        image.resize(0x20c, 0);
        write_u16(&mut image, 0x82, 2);
        write_u16(&mut image, 0x84, SEGMENT_RELOCATIONS_FLAG);
        write_u16(&mut image, 0x86, 2);
        image[0x200..0x202].copy_from_slice(&u16::MAX.to_le_bytes());
        write_u16(&mut image, 0x202, 1);
        image[0x204] = 0x82;
        image[0x205] = 3;
        write_u16(&mut image, 0x206, 0);
        write_u16(&mut image, 0x208, 1);
        write_u16(&mut image, 0x20a, 0);

        parse_ne(&image).expect("Windows loader-compatible address type");
    }

    #[test]
    fn fixed_entry_and_resident_name_lower_to_a_shared_export() {
        let image: Vec<u8> = minimal_ne(true, false);
        let parsed: NativeFile = parse_ne(&image).expect("fixed entry NE");
        assert_eq!(
            parsed.exports,
            vec![ExportInfo {
                name: "main".to_owned(),
                address: 0x0001_0000,
            }]
        );
        assert!(
            parsed
                .symbols
                .iter()
                .any(|symbol: &SymbolInfo| symbol.name == "main")
        );
    }

    #[test]
    fn entry_offset_must_fit_its_segment_allocation() {
        let mut image: Vec<u8> = minimal_ne(true, false);
        write_u16(&mut image, 0xa3, 1);
        assert!(matches!(parse_ne(&image), Err(Error::Ne(_))));
    }

    #[test]
    fn resident_names_must_terminate_before_the_next_table() {
        let mut image: Vec<u8> = minimal_ne(true, false);
        image[0x93] = 1;
        assert!(matches!(parse_ne(&image), Err(Error::Ne(_))));
    }

    #[test]
    fn resident_name_offset_past_the_file_returns_a_typed_error() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        write_u16(&mut image, 0x80, 0);
        write_u16(&mut image, 0x66, u16::MAX);
        let outcome: std::thread::Result<Result<NativeFile>> =
            std::panic::catch_unwind(|| parse_ne(&image));
        assert!(matches!(outcome, Ok(Err(Error::Ne(_)))));
    }

    #[test]
    fn segment_data_cannot_alias_a_loader_table_boundary() {
        let mut image: Vec<u8> = minimal_ne(false, false);
        write_u16(&mut image, 0x66, 0x48);
        write_u16(&mut image, 0x72, 1);
        write_u16(&mut image, 0x80, 0x44);
        image[0x88] = 0;
        assert!(matches!(parse_ne(&image), Err(Error::Ne(_))));
    }

    #[test]
    fn movable_entry_count_must_match_the_entry_bundles() {
        let mut image: Vec<u8> = minimal_ne(true, false);
        write_u16(&mut image, 0x70, 1);
        assert!(matches!(parse_ne(&image), Err(Error::Ne(_))));
    }

    #[test]
    fn every_name_alias_for_an_entry_reaches_the_shared_exports() {
        let entries: Vec<Option<NeEntry>> = vec![Some(NeEntry {
            segment: 1,
            offset: 0,
            exported: true,
            movable: false,
        })];
        let names: Vec<NamedOrdinal> = vec![
            NamedOrdinal {
                name: "first".to_owned(),
                ordinal: 1,
            },
            NamedOrdinal {
                name: "second".to_owned(),
                ordinal: 1,
            },
        ];
        let (_, exports): (Vec<SymbolInfo>, Vec<ExportInfo>) =
            lower_entries(&entries, &names, &[]).expect("alias exports");
        assert_eq!(
            exports,
            vec![
                ExportInfo {
                    name: "first".to_owned(),
                    address: 0x0001_0000,
                },
                ExportInfo {
                    name: "second".to_owned(),
                    address: 0x0001_0000,
                },
            ]
        );
    }

    #[test]
    fn resource_table_lowers_bounded_ranges_to_shared_sections() {
        let image: Vec<u8> = minimal_ne(false, true);
        let parsed: NativeFile = parse_ne(&image).expect("resource NE");
        assert!(parsed.sections.iter().any(|section: &SectionInfo| {
            section.name == "resource_8002_8001" && section.address == 0x201 && section.size == 1
        }));
    }

    #[test]
    fn resource_string_identifiers_cannot_alias_resource_records() {
        for (field, context) in [(0x8a, "resource type"), (0x98, "resource name")] {
            let mut image: Vec<u8> = minimal_ne(false, true);
            write_u16(&mut image, field, 2);
            let error: Error = parse_ne(&image).expect_err("resource record alias");
            let Error::Ne(reason) = error else {
                unreachable!();
            };
            assert_eq!(
                reason,
                format!("{context} offset precedes resource strings")
            );
        }
    }

    #[test]
    fn resource_string_identifiers_start_after_the_type_list_terminator() {
        let mut image: Vec<u8> = minimal_ne(false, true);
        write_u16(&mut image, 0x66, 0x68);
        write_u16(&mut image, 0x98, 0x18);
        image[0xa0] = 3;
        image[0xa1..0xa4].copy_from_slice(b"bmp");
        image[0xa8] = 0;
        let parsed: NativeFile = parse_ne(&image).expect("resource string identifier");
        assert!(
            parsed
                .sections
                .iter()
                .any(|section: &SectionInfo| section.name == "resource_8002_0018")
        );
    }

    #[test]
    fn resource_string_identifiers_must_reference_a_string_start() {
        let mut image: Vec<u8> = minimal_ne(false, true);
        write_u16(&mut image, 0x66, 0x68);
        image[0xa0..0xa5].copy_from_slice(&[3, 1, b'a', b'b', 0]);

        for invalid_offset in [0x19, 0x1c] {
            write_u16(&mut image, 0x98, invalid_offset);
            assert!(matches!(parse_ne(&image), Err(Error::Ne(_))));
        }
    }

    #[test]
    fn os2_resource_records_map_to_trailing_resource_segments() {
        let image: Vec<u8> = os2_ne_with_resource();
        let parsed: NativeFile = parse_ne(&image).expect("OS/2 resource NE");
        assert_eq!(parsed.format, NativeFormat::NeOs2);
        assert_eq!(parsed.segments.len(), 2);
        assert_eq!(parsed.sections.len(), 2);
        assert!(parsed.sections.iter().any(|section: &SectionInfo| {
            section.name == "resource_8001_0042"
                && section.address == 0x0002_0000
                && section.size == 4
        }));
        assert!(
            !parsed.sections.iter().any(|section: &SectionInfo| {
                section.name == "code_2" || section.name == "data_2"
            })
        );
    }

    #[test]
    fn os2_resource_table_count_and_bounds_are_validated() {
        let mut too_many: Vec<u8> = os2_ne_with_resource();
        write_u16(&mut too_many, 0x74, 3);
        assert!(matches!(parse_ne(&too_many), Err(Error::Ne(_))));

        let mut truncated: Vec<u8> = os2_ne_with_resource();
        write_u16(&mut truncated, 0x66, 0x52);
        assert!(matches!(parse_ne(&truncated), Err(Error::Ne(_))));
    }

    #[test]
    fn overlapping_resource_payloads_are_rejected() {
        let resources: Vec<ResourceRange> = vec![
            ResourceRange {
                type_id: 0x8001,
                name_id: 0x8001,
                file_offset: 0x200,
                length: 0x20,
                segment_ordinal: None,
            },
            ResourceRange {
                type_id: 0x8002,
                name_id: 0x8002,
                file_offset: 0x210,
                length: 0x20,
                segment_ordinal: None,
            },
        ];
        assert!(validate_resource_segment_overlap(&resources, &[]).is_err());
    }

    #[test]
    fn zero_length_file_resource_inside_segment_is_accepted() {
        let resources: Vec<ResourceRange> = vec![ResourceRange {
            type_id: 0x8001,
            name_id: 0x8001,
            file_offset: 0x210,
            length: 0,
            segment_ordinal: None,
        }];
        let segments: Vec<NeSegment> = vec![NeSegment {
            ordinal: 1,
            file_offset: 0x200,
            data_len: 0x20,
            initialized_len: 0x20,
            flags: 0,
            allocation_len: 0x20,
        }];
        assert!(validate_resource_segment_overlap(&resources, &segments).is_ok());
        let nonzero_resources: Vec<ResourceRange> = vec![ResourceRange {
            length: 1,
            ..resources[0]
        }];
        assert!(validate_resource_segment_overlap(&nonzero_resources, &segments).is_err());
    }

    #[test]
    fn oem_names_escape_every_non_ascii_byte_without_loss() {
        assert_eq!(decode_oem(b"A\x80\0"), "A\\x80\\x00");
    }

    #[test]
    fn oem_name_escaping_distinguishes_bytes_from_literal_escape_text() {
        assert_ne!(decode_oem(b"\x80"), decode_oem(br"\x80"));
        assert_eq!(decode_oem(br"\x80"), r"\x5Cx80");
    }

    #[test]
    fn relocation_sources_cover_the_complete_ne_width_set() {
        let windows: Vec<(u8, usize)> = (0..=u8::MAX)
            .filter_map(|source_type: u8| {
                relocation_source_width(source_type)
                    .map(|source_width: usize| (source_type, source_width))
            })
            .collect();
        assert_eq!(
            windows,
            vec![(0, 1), (2, 2), (3, 4), (5, 2), (11, 6), (13, 4)]
        );
        let os2: Vec<(u8, usize)> = (0..=u8::MAX)
            .filter_map(|source_type: u8| {
                relocation_source_width(source_type)
                    .map(|source_width: usize| (source_type, source_width))
            })
            .collect();
        assert_eq!(os2, vec![(0, 1), (2, 2), (3, 4), (5, 2), (11, 6), (13, 4)]);
    }

    #[test]
    fn odd_offset_relocation_chain_may_exceed_half_segment_length() {
        const INITIALIZED_DATA_LENGTH: usize = 65_536;
        let mut occupied: Vec<bool> = vec![false; INITIALIZED_DATA_LENGTH];
        let candidates: Vec<Vec<usize>> = (0..=u8::MAX)
            .map(|low: u8| {
                (usize::from(low)..INITIALIZED_DATA_LENGTH - 2)
                    .step_by(usize::from(u8::MAX) + 1)
                    .collect::<Vec<usize>>()
            })
            .collect();
        let mut starts: Vec<usize> = Vec::new();
        let mut current: usize = 0xff;
        loop {
            let current_end: usize = current + 3;
            if current_end > INITIALIZED_DATA_LENGTH
                || occupied[current..current_end]
                    .iter()
                    .any(|used: &bool| *used)
            {
                break;
            }
            occupied[current..current_end].fill(true);
            starts.push(current);
            let required_low: usize = (current + 1) >> 8;
            let next: Option<usize> =
                candidates[required_low]
                    .iter()
                    .copied()
                    .find(|candidate: &usize| {
                        let end: usize = *candidate + 3;
                        end <= INITIALIZED_DATA_LENGTH
                            && !occupied[*candidate..end].iter().any(|used: &bool| *used)
                    });
            let Some(next) = next else {
                break;
            };
            current = next;
        }
        assert!(starts.len() * 2 > INITIALIZED_DATA_LENGTH / 2 + 1);
        assert!(starts.first().is_some_and(|start: &usize| start % 2 == 1));

        let mut initialized_data: Vec<u8> = vec![0; INITIALIZED_DATA_LENGTH];
        for (index, start) in starts.iter().copied().enumerate() {
            let next: u16 = starts
                .get(index + 1)
                .copied()
                .map_or(u16::MAX, |offset: usize| {
                    u16::try_from(offset).expect("relocation offset fits")
                });
            initialized_data[start..start + 2].copy_from_slice(
                &u16::try_from(start + 1)
                    .expect("relocation offset fits")
                    .to_le_bytes(),
            );
            initialized_data[start + 1..start + 3].copy_from_slice(&next.to_le_bytes());
        }
        let mut total_steps: usize = 0;
        assert!(validate_relocation_chain(&initialized_data, 0xff, &mut total_steps).is_ok());
        assert!(total_steps > INITIALIZED_DATA_LENGTH / 2 + 1);
        assert_eq!(total_steps, starts.len() * 2);
    }
}
