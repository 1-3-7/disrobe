use std::collections::BTreeMap;
use std::io::Read as _;

use flate2::read::ZlibDecoder;
use gimli::{Dwarf, EndianSlice, RunTimeEndian};
use serde::{Deserialize, Serialize};

use crate::image::{ImageKind, NativeImage};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DwarfFunction {
    pub name: String,
    pub low_pc: Option<u64>,
    pub high_pc: Option<u64>,
    pub decl_file: Option<String>,
    pub decl_line: Option<u64>,
    pub line_lo: Option<u64>,
    pub line_hi: Option<u64>,
    pub params: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DwarfMember {
    pub name: String,
    pub type_name: Option<String>,
    pub byte_offset: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AggregateKind {
    Struct,
    Class,
    Union,
    Enum,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DwarfAggregate {
    pub name: String,
    pub kind: AggregateKind,
    pub byte_size: Option<u64>,
    pub members: Vec<DwarfMember>,
    pub bases: Vec<String>,
    pub enumerators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DwarfReport {
    pub present: bool,
    pub compressed: bool,
    pub dwarf_version: Option<u16>,
    pub compile_units: u32,
    pub functions: Vec<DwarfFunction>,
    #[serde(default)]
    pub aggregates: Vec<DwarfAggregate>,
}

impl DwarfReport {
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            present: false,
            compressed: false,
            dwarf_version: None,
            compile_units: 0,
            functions: Vec::new(),
            aggregates: Vec::new(),
        }
    }
}

const ZLIB_MAGIC: &[u8; 4] = b"ZLIB";
const MAX_DWARF_FUNCS: usize = 1 << 18;
const MAX_DWARF_AGGREGATES: usize = 1 << 16;
const MAX_LINE_ROWS: u64 = 1 << 24;
const MAX_UNCOMPRESSED: usize = 1 << 30;
const MAX_INFLATE_READ: u64 = MAX_UNCOMPRESSED as u64 + 1;
const INITIAL_INFLATE_CAP: usize = 64 * 1024;

#[must_use]
pub fn recover_dwarf(image: &NativeImage<'_>) -> DwarfReport {
    let mut sections: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut compressed_seen: bool = false;
    for sec in &image.sections {
        let Some(canonical): Option<&'static str> = canonical_debug_name(&sec.name) else {
            continue;
        };
        let Some((data, was_compressed)): Option<(Vec<u8>, bool)> =
            (if sec.name.starts_with(".zdebug") || sec.name.starts_with("__zdebug") {
                decompress_zdebug(sec.data).map(|d: Vec<u8>| (d, true))
            } else if starts_with_zlib_magic(sec.data) {
                decompress_zdebug(sec.data).map(|d: Vec<u8>| (d, true))
            } else {
                strip_elf_chdr(image.kind, sec.data)
            })
        else {
            continue;
        };
        compressed_seen |= was_compressed;
        sections.entry(canonical.to_owned()).or_insert(data);
    }

    if !sections.contains_key(".debug_info") {
        return DwarfReport::absent();
    }

    if image.kind == ImageKind::Elf && !compressed_seen {
        apply_debug_relocations(image.raw, &mut sections);
    }

    let endian: RunTimeEndian = RunTimeEndian::Little;
    let empty: Vec<u8> = Vec::new();
    let load = |id: gimli::SectionId| -> Result<EndianSlice<'_, RunTimeEndian>, gimli::Error> {
        let data: &[u8] = sections.get(id.name()).unwrap_or(&empty);
        Ok(EndianSlice::new(data, endian))
    };
    let Ok(dwarf): Result<Dwarf<EndianSlice<'_, RunTimeEndian>>, _> = Dwarf::load(load) else {
        return DwarfReport::absent();
    };

    walk_dwarf(&dwarf, compressed_seen)
}

fn apply_debug_relocations(raw: &[u8], sections: &mut BTreeMap<String, Vec<u8>>) {
    use object::Object as _;
    use object::ObjectSection as _;

    let Ok(file): Result<object::read::File<'_, &[u8]>, _> = object::read::File::parse(raw) else {
        return;
    };
    if file.kind() != object::ObjectKind::Relocatable {
        return;
    }
    for section in file.sections() {
        let Ok(raw_name): Result<&str, _> = section.name() else {
            continue;
        };
        let Some(canonical): Option<&'static str> = canonical_debug_name(raw_name) else {
            continue;
        };
        let Some(target): Option<&mut Vec<u8>> = sections.get_mut(canonical) else {
            continue;
        };
        for (offset, reloc) in section.relocations() {
            apply_one_relocation(&file, target, offset, &reloc);
        }
    }
}

fn apply_one_relocation<'data>(
    file: &object::read::File<'data, &'data [u8]>,
    target: &mut [u8],
    offset: u64,
    reloc: &object::Relocation,
) {
    use object::Object as _;
    use object::ObjectSection as _;
    use object::ObjectSymbol as _;

    if reloc.kind() != object::RelocationKind::Absolute {
        return;
    }
    let base: i128 = match reloc.target() {
        object::RelocationTarget::Symbol(sym_index) => {
            let Ok(sym): Result<object::read::Symbol<'data, '_, &'data [u8]>, _> =
                file.symbol_by_index(sym_index)
            else {
                return;
            };
            let section_base: u64 = sym
                .section_index()
                .and_then(|idx: object::SectionIndex| file.section_by_index(idx).ok())
                .map_or(0, |s: object::read::Section<'data, '_, &'data [u8]>| {
                    s.address()
                });
            i128::from(section_base.wrapping_add(sym.address()))
        }
        object::RelocationTarget::Section(sec_index) => file
            .section_by_index(sec_index)
            .ok()
            .map_or(0, |s: object::read::Section<'data, '_, &'data [u8]>| {
                i128::from(s.address())
            }),
        _ => return,
    };
    let value: i128 = base.wrapping_add(i128::from(reloc.addend()));
    let Ok(start): Result<usize, _> = usize::try_from(offset) else {
        return;
    };
    let unsigned: u128 = value.cast_unsigned();
    match reloc.size() {
        32 => {
            let Some(slot): Option<&mut [u8]> = target.get_mut(start..start + 4) else {
                return;
            };
            let truncated: u32 = u32::try_from(unsigned & u128::from(u32::MAX)).unwrap_or(0);
            slot.copy_from_slice(&truncated.to_le_bytes());
        }
        64 => {
            let Some(slot): Option<&mut [u8]> = target.get_mut(start..start + 8) else {
                return;
            };
            let truncated: u64 = u64::try_from(unsigned & u128::from(u64::MAX)).unwrap_or(0);
            slot.copy_from_slice(&truncated.to_le_bytes());
        }
        _ => {}
    }
}

fn walk_dwarf(dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>, compressed: bool) -> DwarfReport {
    let mut functions: Vec<DwarfFunction> = Vec::new();
    let mut aggregates: Vec<DwarfAggregate> = Vec::new();
    let mut compile_units: u32 = 0;
    let mut dwarf_version: Option<u16> = None;

    let mut headers: gimli::DebugInfoUnitHeadersIter<EndianSlice<'_, RunTimeEndian>> =
        dwarf.units();
    while let Ok(Some(header)) = headers.next() {
        let Ok(unit): Result<gimli::Unit<EndianSlice<'_, RunTimeEndian>>, _> = dwarf.unit(header)
        else {
            continue;
        };
        compile_units = compile_units.saturating_add(1);
        dwarf_version.get_or_insert_with(|| unit.header.version());
        collect_unit(dwarf, &unit, &mut functions);
        collect_aggregates(dwarf, &unit, &mut aggregates);
        if functions.len() >= MAX_DWARF_FUNCS && aggregates.len() >= MAX_DWARF_AGGREGATES {
            break;
        }
    }

    fill_line_ranges(dwarf, &mut functions);

    functions.sort();
    functions.dedup();
    aggregates.sort();
    aggregates.dedup();

    DwarfReport {
        present: true,
        compressed,
        dwarf_version,
        compile_units,
        functions,
        aggregates,
    }
}

fn collect_aggregates(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    aggregates: &mut Vec<DwarfAggregate>,
) {
    let mut entries: gimli::EntriesCursor<'_, '_, EndianSlice<'_, RunTimeEndian>> = unit.entries();
    let mut current: Option<DwarfAggregate> = None;
    let mut agg_depth: isize = isize::MIN;
    let mut depth: isize = 0;

    while let Ok(Some((delta, entry))) = entries.next_dfs() {
        depth += delta;
        if current.is_some() && depth <= agg_depth {
            if let Some(done) = current.take() {
                push_aggregate(aggregates, done);
            }
            agg_depth = isize::MIN;
        }
        let tag: gimli::DwTag = entry.tag();
        if let Some(kind) = aggregate_kind(tag) {
            if let Some(done) = current.take() {
                push_aggregate(aggregates, done);
            }
            if let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name) {
                current = Some(DwarfAggregate {
                    name,
                    kind,
                    byte_size: attr_udata(entry, gimli::DW_AT_byte_size),
                    members: Vec::new(),
                    bases: Vec::new(),
                    enumerators: Vec::new(),
                });
                agg_depth = depth;
            }
            continue;
        }
        let Some(agg): Option<&mut DwarfAggregate> = current.as_mut() else {
            continue;
        };
        if depth != agg_depth + 1 {
            continue;
        }
        if tag == gimli::DW_TAG_member {
            if let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name) {
                agg.members.push(DwarfMember {
                    name,
                    type_name: type_ref_name(dwarf, unit, entry),
                    byte_offset: attr_udata(entry, gimli::DW_AT_data_member_location),
                });
            }
        } else if tag == gimli::DW_TAG_inheritance {
            if let Some(base) = type_ref_name(dwarf, unit, entry) {
                agg.bases.push(base);
            }
        } else if tag == gimli::DW_TAG_enumerator
            && let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name)
        {
            agg.enumerators.push(name);
        }
    }
    if let Some(done) = current.take() {
        push_aggregate(aggregates, done);
    }
}

const fn aggregate_kind(tag: gimli::DwTag) -> Option<AggregateKind> {
    match tag {
        gimli::DW_TAG_structure_type => Some(AggregateKind::Struct),
        gimli::DW_TAG_class_type => Some(AggregateKind::Class),
        gimli::DW_TAG_union_type => Some(AggregateKind::Union),
        gimli::DW_TAG_enumeration_type => Some(AggregateKind::Enum),
        _ => None,
    }
}

fn type_ref_name(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
) -> Option<String> {
    let value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> =
        entry.attr_value(gimli::DW_AT_type).ok()??;
    let offset: gimli::UnitOffset = match value {
        gimli::AttributeValue::UnitRef(o) => o,
        _ => return None,
    };
    resolve_type_name(dwarf, unit, offset, 0)
}

fn resolve_type_name(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    offset: gimli::UnitOffset,
    depth: u8,
) -> Option<String> {
    if depth > 8 {
        return None;
    }
    let target: gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>> =
        unit.entry(offset).ok()?;
    if let Some(name) = attr_string(dwarf, unit, &target, gimli::DW_AT_name) {
        return Some(name);
    }
    let inner: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> =
        target.attr_value(gimli::DW_AT_type).ok()??;
    let inner_offset: gimli::UnitOffset = match inner {
        gimli::AttributeValue::UnitRef(o) => o,
        _ => return None,
    };
    let prefix: &str = match target.tag() {
        gimli::DW_TAG_pointer_type => "ptr ",
        _ => "",
    };
    let name: String = resolve_type_name(dwarf, unit, inner_offset, depth + 1)?;
    Some(format!("{prefix}{name}"))
}

fn collect_unit(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    functions: &mut Vec<DwarfFunction>,
) {
    let mut entries: gimli::EntriesCursor<'_, '_, EndianSlice<'_, RunTimeEndian>> = unit.entries();
    let mut current: Option<DwarfFunction> = None;
    let mut func_depth: isize = isize::MIN;
    let mut depth: isize = 0;

    while let Ok(Some((delta, entry))) = entries.next_dfs() {
        depth += delta;
        if current.is_some() && depth <= func_depth {
            if let Some(done) = current.take() {
                push_function(functions, done);
            }
            func_depth = isize::MIN;
        }
        let tag: gimli::DwTag = entry.tag();
        if tag == gimli::DW_TAG_subprogram {
            if let Some(done) = current.take() {
                push_function(functions, done);
            }
            let low_pc: Option<u64> = attr_low_pc(dwarf, unit, entry);
            if let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name)
                && low_pc.is_some()
            {
                current = Some(DwarfFunction {
                    name,
                    high_pc: attr_high_pc(entry, low_pc),
                    low_pc,
                    decl_file: attr_decl_file(dwarf, unit, entry),
                    decl_line: attr_udata(entry, gimli::DW_AT_decl_line),
                    line_lo: None,
                    line_hi: None,
                    params: Vec::new(),
                });
                func_depth = depth;
            }
            continue;
        }
        if let Some(func) = current.as_mut()
            && depth == func_depth + 1
            && tag == gimli::DW_TAG_formal_parameter
            && let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name)
        {
            func.params.push(name);
        }
    }
    if let Some(done) = current.take() {
        push_function(functions, done);
    }
}

fn fill_line_ranges(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    functions: &mut [DwarfFunction],
) {
    if functions.is_empty() {
        return;
    }
    let mut rows: Vec<(u64, u64)> = Vec::new();
    let mut headers: gimli::DebugInfoUnitHeadersIter<EndianSlice<'_, RunTimeEndian>> =
        dwarf.units();
    let mut budget: u64 = MAX_LINE_ROWS;
    while let Ok(Some(header)) = headers.next() {
        let Ok(unit): Result<gimli::Unit<EndianSlice<'_, RunTimeEndian>>, _> = dwarf.unit(header)
        else {
            continue;
        };
        let Some(program): Option<gimli::IncompleteLineProgram<EndianSlice<'_, RunTimeEndian>>> =
            unit.line_program.clone()
        else {
            continue;
        };
        let mut state: gimli::LineRows<
            EndianSlice<'_, RunTimeEndian>,
            gimli::IncompleteLineProgram<EndianSlice<'_, RunTimeEndian>>,
        > = program.rows();
        while let Ok(Some((_, row))) = state.next_row() {
            if budget == 0 {
                break;
            }
            budget -= 1;
            if row.end_sequence() {
                continue;
            }
            if let Some(line) = row.line() {
                rows.push((row.address(), line.get()));
            }
        }
        if budget == 0 {
            break;
        }
    }
    if rows.is_empty() {
        return;
    }
    rows.sort_unstable();
    for func in functions.iter_mut() {
        let Some(lo): Option<u64> = func.low_pc else {
            continue;
        };
        let hi: u64 = func.high_pc.unwrap_or(u64::MAX);
        let mut line_lo: Option<u64> = None;
        let mut line_hi: Option<u64> = None;
        for (addr, line) in &rows {
            if *addr < lo {
                continue;
            }
            if *addr >= hi {
                break;
            }
            line_lo = Some(line_lo.map_or(*line, |existing: u64| existing.min(*line)));
            line_hi = Some(line_hi.map_or(*line, |existing: u64| existing.max(*line)));
        }
        func.line_lo = line_lo;
        func.line_hi = line_hi;
    }
}

fn push_function(functions: &mut Vec<DwarfFunction>, func: DwarfFunction) {
    if functions.len() < MAX_DWARF_FUNCS {
        functions.push(func);
    }
}

fn push_aggregate(aggregates: &mut Vec<DwarfAggregate>, agg: DwarfAggregate) {
    if aggregates.len() < MAX_DWARF_AGGREGATES
        && (!agg.members.is_empty() || !agg.enumerators.is_empty() || !agg.bases.is_empty())
    {
        aggregates.push(agg);
    }
}

fn attr_string(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
    attr: gimli::DwAt,
) -> Option<String> {
    let value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> =
        entry.attr_value(attr).ok()??;
    let slice: EndianSlice<'_, RunTimeEndian> = dwarf.attr_string(unit, value).ok()?;
    let text: &str = std::str::from_utf8(slice.slice()).ok()?;
    if text.is_empty() {
        None
    } else {
        Some(text.to_owned())
    }
}

fn attr_low_pc(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
) -> Option<u64> {
    let value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> =
        entry.attr_value(gimli::DW_AT_low_pc).ok()??;
    match value {
        gimli::AttributeValue::Addr(a) => Some(a),
        gimli::AttributeValue::DebugAddrIndex(index) => dwarf.address(unit, index).ok(),
        _ => None,
    }
}

fn attr_high_pc(
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
    low_pc: Option<u64>,
) -> Option<u64> {
    let value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> =
        entry.attr_value(gimli::DW_AT_high_pc).ok()??;
    match value {
        gimli::AttributeValue::Addr(a) => Some(a),
        gimli::AttributeValue::Udata(offset) => low_pc.and_then(|lo: u64| lo.checked_add(offset)),
        _ => None,
    }
}

fn attr_udata(
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
    attr: gimli::DwAt,
) -> Option<u64> {
    let value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> =
        entry.attr_value(attr).ok()??;
    match value {
        gimli::AttributeValue::Udata(v) | gimli::AttributeValue::Data8(v) => Some(v),
        gimli::AttributeValue::Data1(v) => Some(u64::from(v)),
        gimli::AttributeValue::Data2(v) => Some(u64::from(v)),
        gimli::AttributeValue::Data4(v) => Some(u64::from(v)),
        _ => None,
    }
}

fn attr_decl_file(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
) -> Option<String> {
    let value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> =
        entry.attr_value(gimli::DW_AT_decl_file).ok()??;
    let index: u64 = match value {
        gimli::AttributeValue::FileIndex(i) | gimli::AttributeValue::Udata(i) => i,
        _ => return None,
    };
    let program: &gimli::IncompleteLineProgram<EndianSlice<'_, RunTimeEndian>> =
        unit.line_program.as_ref()?;
    let header: &gimli::LineProgramHeader<EndianSlice<'_, RunTimeEndian>> = program.header();
    let file: &gimli::FileEntry<EndianSlice<'_, RunTimeEndian>> = header.file(index)?;
    let value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> = file.path_name();
    let slice: EndianSlice<'_, RunTimeEndian> = dwarf.attr_string(unit, value).ok()?;
    let text: &str = std::str::from_utf8(slice.slice()).ok()?;
    if text.is_empty() {
        None
    } else {
        Some(text.to_owned())
    }
}

fn canonical_debug_name(name: &str) -> Option<&'static str> {
    let stem: &str = name
        .strip_prefix(".zdebug_")
        .or_else(|| name.strip_prefix(".debug_"))
        .or_else(|| name.strip_prefix("__zdebug_"))
        .or_else(|| name.strip_prefix("__debug_"))?;
    Some(match stem {
        "info" => ".debug_info",
        "abbrev" => ".debug_abbrev",
        "str" => ".debug_str",
        "str_offsets" | "str_offs" => ".debug_str_offsets",
        "line" => ".debug_line",
        "line_str" => ".debug_line_str",
        "ranges" => ".debug_ranges",
        "rnglists" => ".debug_rnglists",
        "addr" => ".debug_addr",
        "aranges" => ".debug_aranges",
        _ => return None,
    })
}

fn starts_with_zlib_magic(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == ZLIB_MAGIC
}

fn strip_elf_chdr(kind: ImageKind, data: &[u8]) -> Option<(Vec<u8>, bool)> {
    if kind != ImageKind::Elf || data.len() < 24 {
        return Some((data.to_vec(), false));
    }
    let ch_type: u32 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if ch_type != 1 {
        return Some((data.to_vec(), false));
    }
    let size_bytes: [u8; 8] = match data[8..16].try_into() {
        Ok(bytes) => bytes,
        Err(_) => return None,
    };
    let uncompressed: usize = match usize::try_from(u64::from_le_bytes(size_bytes)) {
        Ok(value) if value <= MAX_UNCOMPRESSED => value,
        _ => return None,
    };
    inflate_capped(&data[24..], uncompressed, false, Some(uncompressed))
        .map(|decoded: Vec<u8>| (decoded, true))
}

fn decompress_zdebug(data: &[u8]) -> Option<Vec<u8>> {
    if !starts_with_zlib_magic(data) {
        return inflate_raw(data);
    }
    let len_bytes: [u8; 8] = data.get(4..12)?.try_into().ok()?;
    let uncompressed_len: usize = usize::try_from(u64::from_be_bytes(len_bytes)).ok()?;
    if uncompressed_len > MAX_UNCOMPRESSED {
        return None;
    }
    inflate_capped(&data[12..], uncompressed_len, true, Some(uncompressed_len))
}

fn inflate_raw(data: &[u8]) -> Option<Vec<u8>> {
    inflate_capped(data, data.len(), false, None)
}

fn inflate_capped(
    data: &[u8],
    capacity_hint: usize,
    allow_empty: bool,
    expected_len: Option<usize>,
) -> Option<Vec<u8>> {
    let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(data);
    let mut limited: std::io::Take<&mut ZlibDecoder<&[u8]>> =
        decoder.by_ref().take(MAX_INFLATE_READ);
    let capacity: usize = capacity_hint.min(data.len()).min(INITIAL_INFLATE_CAP);
    let mut out: Vec<u8> = Vec::with_capacity(capacity);
    limited.read_to_end(&mut out).ok()?;
    if out.len() > MAX_UNCOMPRESSED || (!allow_empty && out.is_empty()) {
        return None;
    }
    if let Some(expected) = expected_len {
        let expected: usize = expected;
        if out.len() != expected {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).expect("zlib input must encode");
        encoder.finish().expect("zlib stream must finish")
    }

    #[test]
    fn canonical_names_map_zdebug_and_debug() {
        assert_eq!(canonical_debug_name(".zdebug_info"), Some(".debug_info"));
        assert_eq!(canonical_debug_name(".debug_line"), Some(".debug_line"));
        assert_eq!(canonical_debug_name(".debug_str"), Some(".debug_str"));
        assert_eq!(canonical_debug_name("__zdebug_line"), Some(".debug_line"));
        assert_eq!(canonical_debug_name(".text"), None);
        assert_eq!(canonical_debug_name(".debug_gdb_scripts"), None);
    }

    #[test]
    fn zlib_magic_detection() {
        assert!(starts_with_zlib_magic(b"ZLIB\x00\x00\x00\x00"));
        assert!(!starts_with_zlib_magic(b"\x78\x9c"));
        assert!(!starts_with_zlib_magic(b"ZL"));
    }

    #[test]
    fn absent_report_is_empty() {
        let r: DwarfReport = DwarfReport::absent();
        assert!(!r.present);
        assert!(r.functions.is_empty());
    }

    #[test]
    fn strip_chdr_passthrough_on_uncompressed() {
        let raw: &[u8] = b"\x00\x01\x02\x03not a chdr header at all really";
        assert_eq!(
            strip_elf_chdr(ImageKind::Elf, raw),
            Some((raw.to_vec(), false))
        );
        assert_eq!(
            strip_elf_chdr(ImageKind::Pe, raw),
            Some((raw.to_vec(), false))
        );
    }

    #[test]
    fn zdebug_small_stream_keeps_small_capacity() {
        let mut raw: Vec<u8> = Vec::from(ZLIB_MAGIC.as_slice());
        raw.extend_from_slice(&3u64.to_be_bytes());
        raw.extend_from_slice(&zlib(b"abc"));
        let out: Vec<u8> = decompress_zdebug(&raw).expect("valid zdebug stream must inflate");
        assert_eq!(out, b"abc");
        assert!(
            out.capacity() < 1024 * 1024,
            "unexpected zdebug capacity {}",
            out.capacity()
        );
    }

    #[test]
    fn zdebug_declared_length_mismatch_rejected() {
        let mut raw: Vec<u8> = Vec::from(ZLIB_MAGIC.as_slice());
        raw.extend_from_slice(&4u64.to_be_bytes());
        raw.extend_from_slice(&zlib(b"abc"));
        assert!(decompress_zdebug(&raw).is_none());
    }

    #[test]
    fn elf_chdr_small_stream_keeps_small_capacity() {
        let mut raw: Vec<u8> = vec![0; 24];
        raw[0..4].copy_from_slice(&1u32.to_le_bytes());
        raw[8..16].copy_from_slice(&3u64.to_le_bytes());
        raw.extend_from_slice(&zlib(b"abc"));
        let (out, compressed): (Vec<u8>, bool) =
            strip_elf_chdr(ImageKind::Elf, &raw).expect("valid chdr stream must inflate");
        assert_eq!(out, b"abc");
        assert!(compressed);
        assert!(
            out.capacity() < 1024 * 1024,
            "unexpected chdr capacity {}",
            out.capacity()
        );
    }

    #[test]
    fn elf_chdr_declared_length_mismatch_rejected() {
        let mut raw: Vec<u8> = vec![0; 24];
        raw[0..4].copy_from_slice(&1u32.to_le_bytes());
        raw[8..16].copy_from_slice(&4u64.to_le_bytes());
        raw.extend_from_slice(&zlib(b"abc"));
        assert!(strip_elf_chdr(ImageKind::Elf, &raw).is_none());
    }
}
