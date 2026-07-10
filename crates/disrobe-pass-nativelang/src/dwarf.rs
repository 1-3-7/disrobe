use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::io::Read as _;

use flate2::read::ZlibDecoder;
use gimli::{Dwarf, EndianSlice, RunTimeEndian};
use serde::{Deserialize, Serialize};

use crate::image::{ImageKind, NativeImage};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DwarfFunction {
    pub name: String,
    #[serde(default)]
    pub linkage_name: Option<String>,
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
const MAX_DWARF_AGGREGATE_DEPTH: usize = 1 << 8;
const MAX_DWARF_AGGREGATE_ITEMS: usize = 1 << 16;
const MAX_DWARF_FUNCTION_PARAMS: usize = 1 << 16;
const MAX_DWARF_DIE_VISITS: usize = 1 << 22;
const MAX_DWARF_STRING_LEN: usize = 1 << 14;
const MAX_DWARF_STRING_BYTES: usize = 1 << 26;
const MAX_DWARF_REFERENCE_DEPTH: usize = 8;
const MAX_DWARF_REFERENCE_VISITS: usize = 16;
const MAX_LINE_ROWS: u64 = 1 << 24;
const MAX_UNCOMPRESSED: usize = 1 << 30;
const MAX_INFLATE_READ: u64 = MAX_UNCOMPRESSED as u64 + 1;
const INITIAL_INFLATE_CAP: usize = 64 * 1024;

type DwarfAttrResult<T> = core::result::Result<Option<T>, ()>;

#[derive(Debug)]
struct DwarfBudget {
    aggregate_items: usize,
    function_params: usize,
    die_visits: usize,
    string_bytes: usize,
    string_limit_hit: bool,
}

impl DwarfBudget {
    const fn new() -> Self {
        Self {
            aggregate_items: 0,
            function_params: 0,
            die_visits: 0,
            string_bytes: 0,
            string_limit_hit: false,
        }
    }

    const fn visit_die(&mut self) -> bool {
        if self.die_visits >= MAX_DWARF_DIE_VISITS {
            return false;
        }
        self.die_visits += 1;
        true
    }

    const fn take_aggregate_item(&mut self) -> bool {
        if self.aggregate_items >= MAX_DWARF_AGGREGATE_ITEMS {
            return false;
        }
        self.aggregate_items += 1;
        true
    }

    const fn take_function_param(&mut self) -> bool {
        if self.function_params >= MAX_DWARF_FUNCTION_PARAMS {
            return false;
        }
        self.function_params += 1;
        true
    }

    const fn reserve_string(&mut self, len: usize) -> bool {
        if len == 0 {
            return false;
        }
        if len > MAX_DWARF_STRING_LEN {
            self.string_limit_hit = true;
            return false;
        }
        self.reserve_string_bytes(len)
    }

    const fn exhausted(&self) -> bool {
        self.die_visits >= MAX_DWARF_DIE_VISITS || self.string_limit_hit
    }

    const fn reserve_string_bytes(&mut self, len: usize) -> bool {
        let Some(next): Option<usize> = self.string_bytes.checked_add(len) else {
            self.string_limit_hit = true;
            return false;
        };
        if next > MAX_DWARF_STRING_BYTES {
            self.string_limit_hit = true;
            return false;
        }
        self.string_bytes = next;
        true
    }
}

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
    let mut budget: DwarfBudget = DwarfBudget::new();
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
        collect_unit(dwarf, &unit, &mut functions, &mut budget);
        if budget.exhausted() {
            break;
        }
        collect_aggregates(dwarf, &unit, &mut aggregates, &mut budget);
        if functions.len() >= MAX_DWARF_FUNCS && aggregates.len() >= MAX_DWARF_AGGREGATES {
            break;
        }
        if budget.exhausted() {
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
    budget: &mut DwarfBudget,
) {
    let mut entries: gimli::EntriesCursor<'_, '_, EndianSlice<'_, RunTimeEndian>> = unit.entries();
    let mut pending: Vec<(isize, DwarfAggregate)> = Vec::new();
    let mut depth: isize = 0;
    let mut seen_entry: bool = false;
    let mut cursor_exhausted: bool = false;

    loop {
        if !budget.visit_die() {
            break;
        }
        let (delta, entry): (
            isize,
            &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
        ) = match entries.next_dfs() {
            Ok(Some(item)) => item,
            Ok(None) => {
                cursor_exhausted = true;
                break;
            }
            Err(_) => break,
        };
        if (!seen_entry && delta != 0) || delta > 1 {
            break;
        }
        let Some(next_depth): Option<isize> = depth.checked_add(delta) else {
            break;
        };
        if next_depth < 0 {
            break;
        }
        depth = next_depth;
        seen_entry = true;
        while pending
            .last()
            .is_some_and(|(start_depth, _): &(isize, DwarfAggregate)| depth <= *start_depth)
        {
            let Some((_, done)): Option<(isize, DwarfAggregate)> = pending.pop() else {
                break;
            };
            push_aggregate(aggregates, done);
        }
        let tag: gimli::DwTag = entry.tag();
        if let Some(kind) = aggregate_kind(tag) {
            if pending.len() < MAX_DWARF_AGGREGATE_DEPTH
                && aggregates.len().saturating_add(pending.len()) < MAX_DWARF_AGGREGATES
                && let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name, budget)
            {
                pending.push((
                    depth,
                    DwarfAggregate {
                        name,
                        kind,
                        byte_size: attr_udata(entry, gimli::DW_AT_byte_size),
                        members: Vec::new(),
                        bases: Vec::new(),
                        enumerators: Vec::new(),
                    },
                ));
            }
            if budget.string_limit_hit {
                return;
            }
            continue;
        }
        let Some((aggregate_depth, agg)): Option<&mut (isize, DwarfAggregate)> = pending.last_mut()
        else {
            continue;
        };
        if aggregate_depth.checked_add(1) != Some(depth) {
            continue;
        }
        if tag == gimli::DW_TAG_member {
            if budget.aggregate_items >= MAX_DWARF_AGGREGATE_ITEMS {
                return;
            }
            if let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name, budget) {
                let type_name: Option<String> = type_ref_name(dwarf, unit, entry, budget);
                if budget.exhausted() || !budget.take_aggregate_item() {
                    return;
                }
                agg.members.push(DwarfMember {
                    name,
                    type_name,
                    byte_offset: attr_udata(entry, gimli::DW_AT_data_member_location),
                });
            }
        } else if tag == gimli::DW_TAG_inheritance {
            if budget.aggregate_items >= MAX_DWARF_AGGREGATE_ITEMS {
                return;
            }
            if let Some(base) = type_ref_name(dwarf, unit, entry, budget) {
                if budget.exhausted() || !budget.take_aggregate_item() {
                    return;
                }
                agg.bases.push(base);
            }
        } else if tag == gimli::DW_TAG_enumerator
            && budget.aggregate_items >= MAX_DWARF_AGGREGATE_ITEMS
        {
            return;
        } else if tag == gimli::DW_TAG_enumerator
            && let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name, budget)
        {
            if !budget.take_aggregate_item() {
                return;
            }
            agg.enumerators.push(name);
        }
        if budget.string_limit_hit {
            return;
        }
    }
    if cursor_exhausted {
        while let Some((_, done)) = pending.pop() {
            push_aggregate(aggregates, done);
        }
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
    budget: &mut DwarfBudget,
) -> Option<String> {
    let value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> =
        entry.attr_value(gimli::DW_AT_type).ok()??;
    let offset: gimli::UnitOffset = match value {
        gimli::AttributeValue::UnitRef(o) => o,
        _ => return None,
    };
    resolve_type_name(dwarf, unit, offset, 0, budget)
}

fn resolve_type_name(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    offset: gimli::UnitOffset,
    depth: u8,
    budget: &mut DwarfBudget,
) -> Option<String> {
    if depth > 8 {
        return None;
    }
    if !budget.visit_die() {
        return None;
    }
    let target: gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>> =
        unit.entry(offset).ok()?;
    if let Some(name) = attr_string(dwarf, unit, &target, gimli::DW_AT_name, budget) {
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
    let name: String = resolve_type_name(dwarf, unit, inner_offset, depth + 1, budget)?;
    if prefix.is_empty() {
        return Some(name);
    }
    let rendered_len: usize = prefix.len().checked_add(name.len())?;
    if rendered_len > MAX_DWARF_STRING_LEN {
        budget.string_limit_hit = true;
        return None;
    }
    if !budget.reserve_string_bytes(prefix.len()) {
        return None;
    }
    Some(format!("{prefix}{name}"))
}

fn collect_unit(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    functions: &mut Vec<DwarfFunction>,
    budget: &mut DwarfBudget,
) {
    let mut entries: gimli::EntriesCursor<'_, '_, EndianSlice<'_, RunTimeEndian>> = unit.entries();
    let mut current: Option<DwarfFunction> = None;
    let mut func_depth: isize = isize::MIN;
    let mut depth: isize = 0;
    let mut seen_entry: bool = false;
    let mut cursor_exhausted: bool = false;

    loop {
        if !budget.visit_die() {
            break;
        }
        let (delta, entry): (
            isize,
            &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
        ) = match entries.next_dfs() {
            Ok(Some(item)) => item,
            Ok(None) => {
                cursor_exhausted = true;
                break;
            }
            Err(_) => break,
        };
        if (!seen_entry && delta != 0) || delta > 1 {
            break;
        }
        let Some(next_depth): Option<isize> = depth.checked_add(delta) else {
            break;
        };
        if next_depth < 0 {
            break;
        }
        depth = next_depth;
        seen_entry = true;
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
            if functions.len() >= MAX_DWARF_FUNCS {
                return;
            }
            let Some(low_pc): Option<u64> = attr_low_pc(dwarf, unit, entry) else {
                continue;
            };
            let name: Option<String> = match inherited_attr_string(
                dwarf,
                unit,
                entry,
                gimli::DW_AT_name,
                gimli::DW_TAG_subprogram,
                budget,
            ) {
                Ok(value) => value,
                Err(()) => continue,
            };
            let linkage_name: Option<String> = inherited_attr_string(
                dwarf,
                unit,
                entry,
                gimli::DW_AT_linkage_name,
                gimli::DW_TAG_subprogram,
                budget,
            )
            .ok()
            .flatten();
            if let Some(name) = name.or_else(|| linkage_name.clone()) {
                let decl_file: Option<String> =
                    inherited_decl_file(dwarf, unit, entry, gimli::DW_TAG_subprogram, budget)
                        .ok()
                        .flatten();
                if budget.string_limit_hit {
                    return;
                }
                current = Some(DwarfFunction {
                    name,
                    linkage_name,
                    high_pc: attr_high_pc(entry, Some(low_pc)),
                    low_pc: Some(low_pc),
                    decl_file,
                    decl_line: inherited_attr_udata(
                        unit,
                        entry,
                        gimli::DW_AT_decl_line,
                        gimli::DW_TAG_subprogram,
                    )
                    .ok()
                    .flatten(),
                    line_lo: None,
                    line_hi: None,
                    params: Vec::new(),
                });
                func_depth = depth;
            }
            if budget.string_limit_hit {
                return;
            }
            continue;
        }
        if let Some(func) = current.as_mut()
            && func_depth.checked_add(1) == Some(depth)
            && tag == gimli::DW_TAG_formal_parameter
        {
            if budget.function_params >= MAX_DWARF_FUNCTION_PARAMS {
                return;
            }
            if let Ok(Some(name)) = inherited_attr_string(
                dwarf,
                unit,
                entry,
                gimli::DW_AT_name,
                gimli::DW_TAG_formal_parameter,
                budget,
            ) {
                if !budget.take_function_param() {
                    return;
                }
                func.params.push(name);
            }
            if budget.string_limit_hit {
                return;
            }
        }
    }
    if cursor_exhausted && let Some(done) = current.take() {
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
    budget: &mut DwarfBudget,
) -> Option<String> {
    let value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> =
        entry.attr_value(attr).ok()??;
    let slice: EndianSlice<'_, RunTimeEndian> = dwarf.attr_string(unit, value).ok()?;
    decode_dwarf_string(slice, budget)
}

fn inherited_attr_string(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
    attr: gimli::DwAt,
    expected_tag: gimli::DwTag,
    budget: &mut DwarfBudget,
) -> DwarfAttrResult<String> {
    let Some(value): Option<gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>>> =
        inherited_attr_value(unit, entry, attr, expected_tag)?
    else {
        return Ok(None);
    };
    let slice: EndianSlice<'_, RunTimeEndian> = dwarf.attr_string(unit, value).map_err(|_| ())?;
    decode_dwarf_string(slice, budget).map(Some).ok_or(())
}

fn inherited_attr_udata(
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
    attr: gimli::DwAt,
    expected_tag: gimli::DwTag,
) -> DwarfAttrResult<u64> {
    let Some(value): Option<gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>>> =
        inherited_attr_value(unit, entry, attr, expected_tag)?
    else {
        return Ok(None);
    };
    attr_value_udata(value).map(Some).ok_or(())
}

fn inherited_attr_value<'data>(
    unit: &gimli::Unit<EndianSlice<'data, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'data, RunTimeEndian>>,
    attr: gimli::DwAt,
    expected_tag: gimli::DwTag,
) -> DwarfAttrResult<gimli::AttributeValue<EndianSlice<'data, RunTimeEndian>>> {
    if entry.tag() != expected_tag {
        return Ok(None);
    }
    match entry.attr_value(attr) {
        Ok(Some(value)) => return Ok(Some(value)),
        Ok(None) => {}
        Err(_) => return Err(()),
    }
    let mut queue: VecDeque<(gimli::UnitOffset, usize)> =
        VecDeque::with_capacity(MAX_DWARF_REFERENCE_VISITS);
    enqueue_references(entry, 1, &mut queue);
    let mut visited: Vec<gimli::UnitOffset> = Vec::with_capacity(MAX_DWARF_REFERENCE_VISITS);
    visited.push(entry.offset());
    resolve_attr_queue(unit, attr, expected_tag, &mut queue, &mut visited)
}

fn resolve_attr_queue<'data>(
    unit: &gimli::Unit<EndianSlice<'data, RunTimeEndian>>,
    attr: gimli::DwAt,
    expected_tag: gimli::DwTag,
    queue: &mut VecDeque<(gimli::UnitOffset, usize)>,
    visited: &mut Vec<gimli::UnitOffset>,
) -> DwarfAttrResult<gimli::AttributeValue<EndianSlice<'data, RunTimeEndian>>> {
    while visited.len() < MAX_DWARF_REFERENCE_VISITS
        && let Some((offset, depth)) = queue.pop_front()
    {
        if depth > MAX_DWARF_REFERENCE_DEPTH || visited.contains(&offset) {
            continue;
        }
        visited.push(offset);
        let Ok(target): Result<
            gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'data, RunTimeEndian>>,
            _,
        > = unit.entry(offset) else {
            continue;
        };
        if target.tag() != expected_tag {
            continue;
        }
        match target.attr_value(attr) {
            Ok(Some(value)) => return Ok(Some(value)),
            Ok(None) => {}
            Err(_) => return Err(()),
        }
        if depth < MAX_DWARF_REFERENCE_DEPTH {
            enqueue_references(&target, depth + 1, queue);
        }
    }
    Ok(None)
}

fn enqueue_references(
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
    depth: usize,
    queue: &mut VecDeque<(gimli::UnitOffset, usize)>,
) {
    for attr in [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification] {
        if queue.len() >= MAX_DWARF_REFERENCE_VISITS {
            return;
        }
        let Ok(Some(value)): Result<
            Option<gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>>>,
            _,
        > = entry.attr_value(attr) else {
            continue;
        };
        if let Some(offset) = unit_reference_offset(value) {
            queue.push_back((offset, depth));
        }
    }
}

const fn unit_reference_offset(
    value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>>,
) -> Option<gimli::UnitOffset> {
    match value {
        gimli::AttributeValue::UnitRef(offset) => Some(offset),
        _ => None,
    }
}

fn decode_dwarf_string(
    slice: EndianSlice<'_, RunTimeEndian>,
    budget: &mut DwarfBudget,
) -> Option<String> {
    let raw: &[u8] = slice.slice();
    if !budget.reserve_string(raw.len()) {
        return None;
    }
    let text: &str = std::str::from_utf8(raw).ok()?;
    Some(text.to_owned())
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
    attr_value_udata(value)
}

fn attr_value_udata(value: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>>) -> Option<u64> {
    match value {
        gimli::AttributeValue::Udata(v) | gimli::AttributeValue::Data8(v) => Some(v),
        gimli::AttributeValue::Data1(v) => Some(u64::from(v)),
        gimli::AttributeValue::Data2(v) => Some(u64::from(v)),
        gimli::AttributeValue::Data4(v) => Some(u64::from(v)),
        _ => None,
    }
}

fn inherited_decl_file(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, EndianSlice<'_, RunTimeEndian>>,
    expected_tag: gimli::DwTag,
    budget: &mut DwarfBudget,
) -> DwarfAttrResult<String> {
    let Some(value): Option<gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>>> =
        inherited_attr_value(unit, entry, gimli::DW_AT_decl_file, expected_tag)?
    else {
        return Ok(None);
    };
    let index: u64 = match value {
        gimli::AttributeValue::FileIndex(i) | gimli::AttributeValue::Udata(i) => i,
        _ => return Err(()),
    };
    let program: &gimli::IncompleteLineProgram<EndianSlice<'_, RunTimeEndian>> =
        unit.line_program.as_ref().ok_or(())?;
    let header: &gimli::LineProgramHeader<EndianSlice<'_, RunTimeEndian>> = program.header();
    let file: &gimli::FileEntry<EndianSlice<'_, RunTimeEndian>> = header.file(index).ok_or(())?;
    let path: gimli::AttributeValue<EndianSlice<'_, RunTimeEndian>> = file.path_name();
    let slice: EndianSlice<'_, RunTimeEndian> = dwarf.attr_string(unit, path).map_err(|_| ())?;
    decode_dwarf_string(slice, budget).map(Some).ok_or(())
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
    use std::collections::BTreeMap;
    use std::io::Write as _;

    use gimli::write::{
        AttributeValue as WriteAttributeValue, DwarfUnit, EndianVec, Sections, UnitEntryId,
    };
    use gimli::{Encoding, Format, LittleEndian, SectionId};

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).expect("zlib input must encode");
        encoder.finish().expect("zlib stream must finish")
    }

    fn add_named_die(
        dwarf: &mut DwarfUnit,
        parent: UnitEntryId,
        tag: gimli::DwTag,
        name: &str,
    ) -> UnitEntryId {
        let name_id: gimli::write::StringId = dwarf.strings.add(name.as_bytes().to_vec());
        let entry_id: UnitEntryId = dwarf.unit.add(parent, tag);
        dwarf
            .unit
            .get_mut(entry_id)
            .set(gimli::DW_AT_name, WriteAttributeValue::StringRef(name_id));
        entry_id
    }

    fn serialize_dwarf(dwarf: &mut DwarfUnit) -> BTreeMap<SectionId, Vec<u8>> {
        let mut sections: Sections<EndianVec<LittleEndian>> =
            Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).expect("dwarf write succeeds");
        let mut serialized: BTreeMap<SectionId, Vec<u8>> = BTreeMap::new();
        sections
            .for_each(
                |id: SectionId, data: &EndianVec<LittleEndian>| -> gimli::write::Result<()> {
                    serialized.insert(id, data.clone().into_vec());
                    Ok(())
                },
            )
            .expect("dwarf sections serialize");
        serialized
    }

    fn report_from_sections(sections: &BTreeMap<SectionId, Vec<u8>>) -> DwarfReport {
        let empty: Vec<u8> = Vec::new();
        let endian: RunTimeEndian = RunTimeEndian::Little;
        let load =
            |id: SectionId| -> std::result::Result<EndianSlice<'_, RunTimeEndian>, gimli::Error> {
                let data: &[u8] = sections.get(&id).unwrap_or(&empty);
                Ok(EndianSlice::new(data, endian))
            };
        let dwarf: Dwarf<EndianSlice<'_, RunTimeEndian>> =
            Dwarf::load(load).expect("dwarf sections load");
        walk_dwarf(&dwarf, false)
    }

    fn dwarf_unit() -> DwarfUnit {
        DwarfUnit::new(Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        })
    }

    #[test]
    fn dwarf_budget_enforces_each_limit() {
        let mut dies: DwarfBudget = DwarfBudget::new();
        dies.die_visits = MAX_DWARF_DIE_VISITS - 1;
        assert!(dies.visit_die());
        assert!(!dies.visit_die());

        let mut aggregates: DwarfBudget = DwarfBudget::new();
        aggregates.aggregate_items = MAX_DWARF_AGGREGATE_ITEMS - 1;
        assert!(aggregates.take_aggregate_item());
        assert!(!aggregates.take_aggregate_item());

        let mut params: DwarfBudget = DwarfBudget::new();
        params.function_params = MAX_DWARF_FUNCTION_PARAMS - 1;
        assert!(params.take_function_param());
        assert!(!params.take_function_param());

        let mut strings: DwarfBudget = DwarfBudget::new();
        strings.string_bytes = MAX_DWARF_STRING_BYTES - 3;
        assert!(strings.reserve_string(3));
        assert!(!strings.reserve_string(1));
        assert!(strings.string_limit_hit);
        let mut oversized: DwarfBudget = DwarfBudget::new();
        assert!(!oversized.reserve_string(MAX_DWARF_STRING_LEN + 1));
        assert!(oversized.string_limit_hit);
    }

    #[test]
    fn subprogram_metadata_follows_abstract_origin_and_specification_with_bounds() {
        let mut dwarf: DwarfUnit = dwarf_unit();
        let root: UnitEntryId = dwarf.unit.root();
        let abstract_subprogram: UnitEntryId =
            add_named_die(&mut dwarf, root, gimli::DW_TAG_subprogram, "abstract_fn");
        let linkage: gimli::write::StringId = dwarf.strings.add(b"mod.abstract_fn".to_vec());
        dwarf.unit.get_mut(abstract_subprogram).set(
            gimli::DW_AT_linkage_name,
            WriteAttributeValue::StringRef(linkage),
        );
        dwarf
            .unit
            .get_mut(abstract_subprogram)
            .set(gimli::DW_AT_decl_line, WriteAttributeValue::Udata(41));
        let abstract_param: UnitEntryId = add_named_die(
            &mut dwarf,
            abstract_subprogram,
            gimli::DW_TAG_formal_parameter,
            "value",
        );

        for (reference, address) in [
            (gimli::DW_AT_abstract_origin, 0x1000_u64),
            (gimli::DW_AT_specification, 0x2000_u64),
        ] {
            let concrete: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
            dwarf.unit.get_mut(concrete).set(
                gimli::DW_AT_low_pc,
                WriteAttributeValue::Address(gimli::write::Address::Constant(address)),
            );
            dwarf
                .unit
                .get_mut(concrete)
                .set(gimli::DW_AT_high_pc, WriteAttributeValue::Udata(16));
            dwarf
                .unit
                .get_mut(concrete)
                .set(reference, WriteAttributeValue::UnitRef(abstract_subprogram));
            let concrete_param: UnitEntryId =
                dwarf.unit.add(concrete, gimli::DW_TAG_formal_parameter);
            dwarf.unit.get_mut(concrete_param).set(
                gimli::DW_AT_abstract_origin,
                WriteAttributeValue::UnitRef(abstract_param),
            );
        }

        let direct: UnitEntryId =
            add_named_die(&mut dwarf, root, gimli::DW_TAG_subprogram, "direct_fn");
        dwarf.unit.get_mut(direct).set(
            gimli::DW_AT_low_pc,
            WriteAttributeValue::Address(gimli::write::Address::Constant(0x2800)),
        );
        dwarf.unit.get_mut(direct).set(
            gimli::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(abstract_subprogram),
        );

        let wrong_target: UnitEntryId =
            add_named_die(&mut dwarf, root, gimli::DW_TAG_base_type, "wrong_target");
        let wrong_reference: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
        dwarf.unit.get_mut(wrong_reference).set(
            gimli::DW_AT_low_pc,
            WriteAttributeValue::Address(gimli::write::Address::Constant(0x2900)),
        );
        dwarf.unit.get_mut(wrong_reference).set(
            gimli::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(wrong_target),
        );

        let malformed_direct: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
        dwarf.unit.get_mut(malformed_direct).set(
            gimli::DW_AT_low_pc,
            WriteAttributeValue::Address(gimli::write::Address::Constant(0x2a00)),
        );
        dwarf
            .unit
            .get_mut(malformed_direct)
            .set(gimli::DW_AT_name, WriteAttributeValue::Udata(7));
        dwarf.unit.get_mut(malformed_direct).set(
            gimli::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(abstract_subprogram),
        );

        let cycle_a: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
        let cycle_b: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
        dwarf.unit.get_mut(cycle_a).set(
            gimli::DW_AT_low_pc,
            WriteAttributeValue::Address(gimli::write::Address::Constant(0x3000)),
        );
        dwarf.unit.get_mut(cycle_a).set(
            gimli::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(cycle_b),
        );
        dwarf.unit.get_mut(cycle_b).set(
            gimli::DW_AT_specification,
            WriteAttributeValue::UnitRef(cycle_a),
        );

        let within_limit: UnitEntryId =
            add_named_die(&mut dwarf, root, gimli::DW_TAG_subprogram, "within_limit");
        let mut within_head: UnitEntryId = within_limit;
        for _ in 1..MAX_DWARF_REFERENCE_DEPTH {
            let next: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
            dwarf.unit.get_mut(next).set(
                gimli::DW_AT_abstract_origin,
                WriteAttributeValue::UnitRef(within_head),
            );
            within_head = next;
        }
        let within_concrete: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
        dwarf.unit.get_mut(within_concrete).set(
            gimli::DW_AT_low_pc,
            WriteAttributeValue::Address(gimli::write::Address::Constant(0x4000)),
        );
        dwarf.unit.get_mut(within_concrete).set(
            gimli::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(within_head),
        );

        let beyond_limit: UnitEntryId =
            add_named_die(&mut dwarf, root, gimli::DW_TAG_subprogram, "beyond_limit");
        let mut beyond_head: UnitEntryId = beyond_limit;
        for _ in 0..MAX_DWARF_REFERENCE_DEPTH {
            let next: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
            dwarf.unit.get_mut(next).set(
                gimli::DW_AT_abstract_origin,
                WriteAttributeValue::UnitRef(beyond_head),
            );
            beyond_head = next;
        }
        let beyond_concrete: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
        dwarf.unit.get_mut(beyond_concrete).set(
            gimli::DW_AT_low_pc,
            WriteAttributeValue::Address(gimli::write::Address::Constant(0x5000)),
        );
        dwarf.unit.get_mut(beyond_concrete).set(
            gimli::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(beyond_head),
        );

        let shortest_name: UnitEntryId =
            add_named_die(&mut dwarf, root, gimli::DW_TAG_subprogram, "shortest_path");
        let common: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
        dwarf.unit.get_mut(common).set(
            gimli::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(shortest_name),
        );
        let mut long_head: UnitEntryId = common;
        for _ in 1..MAX_DWARF_REFERENCE_DEPTH {
            let next: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
            dwarf.unit.get_mut(next).set(
                gimli::DW_AT_abstract_origin,
                WriteAttributeValue::UnitRef(long_head),
            );
            long_head = next;
        }
        let branching_concrete: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
        dwarf.unit.get_mut(branching_concrete).set(
            gimli::DW_AT_low_pc,
            WriteAttributeValue::Address(gimli::write::Address::Constant(0x6000)),
        );
        dwarf.unit.get_mut(branching_concrete).set(
            gimli::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(long_head),
        );
        dwarf.unit.get_mut(branching_concrete).set(
            gimli::DW_AT_specification,
            WriteAttributeValue::UnitRef(common),
        );

        let sections: BTreeMap<SectionId, Vec<u8>> = serialize_dwarf(&mut dwarf);
        let report: DwarfReport = report_from_sections(&sections);
        let inherited: Vec<&DwarfFunction> = report
            .functions
            .iter()
            .filter(|function: &&DwarfFunction| function.name == "abstract_fn")
            .collect();
        assert_eq!(inherited.len(), 2);
        for function in inherited {
            assert_eq!(function.linkage_name.as_deref(), Some("mod.abstract_fn"));
            assert_eq!(function.decl_line, Some(41));
            assert_eq!(function.params, ["value".to_owned()]);
        }
        let direct: &DwarfFunction = report
            .functions
            .iter()
            .find(|function: &&DwarfFunction| function.low_pc == Some(0x2800))
            .expect("directly named function recovered");
        assert_eq!(direct.name, "direct_fn");
        assert!(report.functions.iter().any(|function: &DwarfFunction| {
            function.low_pc == Some(0x4000) && function.name == "within_limit"
        }));
        assert!(report.functions.iter().any(|function: &DwarfFunction| {
            function.low_pc == Some(0x6000) && function.name == "shortest_path"
        }));
        assert!(report.functions.iter().all(|function: &DwarfFunction| {
            function.low_pc != Some(0x2900)
                && function.low_pc != Some(0x2a00)
                && function.low_pc != Some(0x3000)
                && function.low_pc != Some(0x5000)
        }));

        let unsupported: gimli::AttributeValue<EndianSlice<'static, RunTimeEndian>> =
            gimli::AttributeValue::DebugInfoRef(gimli::DebugInfoOffset(0));
        assert!(unit_reference_offset(unsupported).is_none());

        let empty: Vec<u8> = Vec::new();
        let endian: RunTimeEndian = RunTimeEndian::Little;
        let load =
            |id: SectionId| -> std::result::Result<EndianSlice<'_, RunTimeEndian>, gimli::Error> {
                let data: &[u8] = sections.get(&id).unwrap_or(&empty);
                Ok(EndianSlice::new(data, endian))
            };
        let read_dwarf: Dwarf<EndianSlice<'_, RunTimeEndian>> =
            Dwarf::load(load).expect("dwarf sections load");
        let header: gimli::UnitHeader<EndianSlice<'_, RunTimeEndian>> = read_dwarf
            .units()
            .next()
            .expect("unit header reads")
            .expect("unit header exists");
        let unit: gimli::Unit<EndianSlice<'_, RunTimeEndian>> =
            read_dwarf.unit(header).expect("unit reads");
        let mut invalid_queue: VecDeque<(gimli::UnitOffset, usize)> = (0..32)
            .map(|index: usize| (gimli::UnitOffset(usize::MAX - index), 1))
            .collect();
        let mut invalid_visited: Vec<gimli::UnitOffset> = vec![gimli::UnitOffset(0)];
        assert!(matches!(
            resolve_attr_queue(
                &unit,
                gimli::DW_AT_name,
                gimli::DW_TAG_subprogram,
                &mut invalid_queue,
                &mut invalid_visited,
            ),
            Ok(None)
        ));
        assert_eq!(invalid_visited.len(), MAX_DWARF_REFERENCE_VISITS);
    }

    #[test]
    fn nested_aggregates_keep_inner_and_outer_members() {
        let mut dwarf: DwarfUnit = dwarf_unit();
        let root: UnitEntryId = dwarf.unit.root();
        let scalar: UnitEntryId =
            add_named_die(&mut dwarf, root, gimli::DW_TAG_base_type, "Scalar");
        let outer: UnitEntryId =
            add_named_die(&mut dwarf, root, gimli::DW_TAG_structure_type, "Outer");
        let before: UnitEntryId = add_named_die(&mut dwarf, outer, gimli::DW_TAG_member, "before");
        dwarf
            .unit
            .get_mut(before)
            .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(scalar));
        let inner: UnitEntryId =
            add_named_die(&mut dwarf, outer, gimli::DW_TAG_structure_type, "Inner");
        let _: UnitEntryId = add_named_die(&mut dwarf, inner, gimli::DW_TAG_member, "inside");
        let _: UnitEntryId = add_named_die(&mut dwarf, outer, gimli::DW_TAG_member, "after");

        let sections: BTreeMap<SectionId, Vec<u8>> = serialize_dwarf(&mut dwarf);
        let report: DwarfReport = report_from_sections(&sections);
        let outer: &DwarfAggregate = report
            .aggregates
            .iter()
            .find(|aggregate: &&DwarfAggregate| aggregate.name == "Outer")
            .expect("outer aggregate recovered");
        let inner: &DwarfAggregate = report
            .aggregates
            .iter()
            .find(|aggregate: &&DwarfAggregate| aggregate.name == "Inner")
            .expect("inner aggregate recovered");
        assert_eq!(
            outer
                .members
                .iter()
                .map(|member: &DwarfMember| member.name.as_str())
                .collect::<Vec<&str>>(),
            ["before", "after"]
        );
        assert_eq!(outer.members[0].type_name.as_deref(), Some("Scalar"));
        assert_eq!(
            inner
                .members
                .iter()
                .map(|member: &DwarfMember| member.name.as_str())
                .collect::<Vec<&str>>(),
            ["inside"]
        );
    }

    #[test]
    fn aggregate_nesting_stops_at_depth_limit() {
        let mut dwarf: DwarfUnit = dwarf_unit();
        let mut parent: UnitEntryId = dwarf.unit.root();
        let mut aggregate_ids: Vec<UnitEntryId> = Vec::new();
        for index in 0..MAX_DWARF_AGGREGATE_DEPTH + 2 {
            let name: String = format!("Type{index}");
            let aggregate: UnitEntryId =
                add_named_die(&mut dwarf, parent, gimli::DW_TAG_structure_type, &name);
            aggregate_ids.push(aggregate);
            parent = aggregate;
        }
        for (index, aggregate) in aggregate_ids.into_iter().enumerate() {
            let name: String = format!("member{index}");
            let _: UnitEntryId = add_named_die(&mut dwarf, aggregate, gimli::DW_TAG_member, &name);
        }

        let sections: BTreeMap<SectionId, Vec<u8>> = serialize_dwarf(&mut dwarf);
        let report: DwarfReport = report_from_sections(&sections);
        assert_eq!(report.aggregates.len(), MAX_DWARF_AGGREGATE_DEPTH);
        assert!(
            report
                .aggregates
                .iter()
                .any(|aggregate: &DwarfAggregate| aggregate.name == "Type255")
        );
        assert!(
            report
                .aggregates
                .iter()
                .all(|aggregate: &DwarfAggregate| aggregate.name != "Type256")
        );
    }

    #[test]
    fn composed_type_name_above_limit_rejects_open_aggregate() {
        let mut dwarf: DwarfUnit = dwarf_unit();
        let root: UnitEntryId = dwarf.unit.root();
        let long_name: String = "x".repeat(MAX_DWARF_STRING_LEN);
        let base: UnitEntryId =
            add_named_die(&mut dwarf, root, gimli::DW_TAG_base_type, &long_name);
        let pointer: UnitEntryId = dwarf.unit.add(root, gimli::DW_TAG_pointer_type);
        dwarf
            .unit
            .get_mut(pointer)
            .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(base));
        let outer: UnitEntryId =
            add_named_die(&mut dwarf, root, gimli::DW_TAG_structure_type, "Outer");
        let member: UnitEntryId = add_named_die(&mut dwarf, outer, gimli::DW_TAG_member, "value");
        dwarf
            .unit
            .get_mut(member)
            .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(pointer));

        let sections: BTreeMap<SectionId, Vec<u8>> = serialize_dwarf(&mut dwarf);
        let report: DwarfReport = report_from_sections(&sections);
        assert!(
            report
                .aggregates
                .iter()
                .all(|aggregate: &DwarfAggregate| aggregate.name != "Outer")
        );
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
