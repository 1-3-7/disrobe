use std::collections::BTreeMap;

use gimli::{Dwarf, EndianSlice, Operation, RunTimeEndian};
use object::{Object, ObjectSection};

use crate::error::{Result, TypeRecError};
use crate::lattice::{Sign, Width};

const RBP_DWARF_REGISTER: u16 = 6;
const STANDARD_PROLOGUE: [u8; 4] = [0x55, 0x48, 0x89, 0xe5];
const CFA_TO_RBP: i64 = 16;
const MAX_UNITS: usize = 1 << 12;
const MAX_DIE_VISITS: usize = 1 << 20;
const MAX_TYPE_DEPTH: u8 = 16;
const MAX_VARS_PER_FUNCTION: usize = 1 << 12;

const DW_ATE_BOOLEAN: u64 = 0x02;
const DW_ATE_SIGNED: u64 = 0x05;
const DW_ATE_SIGNED_CHAR: u64 = 0x06;
const DW_ATE_UNSIGNED: u64 = 0x07;
const DW_ATE_UNSIGNED_CHAR: u64 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundTruthVar {
    pub name: String,
    pub rbp_disp: i64,
    pub width: Width,
    pub sign: Sign,
    pub scope_lo: u64,
    pub scope_hi: u64,
}

impl GroundTruthVar {
    #[must_use]
    pub const fn scope_overlaps(&self, lo: u64, hi: u64) -> bool {
        self.scope_lo < hi && lo < self.scope_hi
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundTruthField {
    pub offset: i64,
    pub width: Width,
    pub sign: Sign,
    pub is_pointer: bool,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundTruthAggregate {
    pub rbp_disp: i64,
    pub is_union: bool,
    pub type_name: String,
    pub fields: Vec<GroundTruthField>,
}

impl GroundTruthAggregate {
    #[must_use]
    pub fn field_slots(&self) -> std::collections::BTreeSet<(i64, Width)> {
        self.fields
            .iter()
            .filter(|field: &&GroundTruthField| field.width != Width::Unknown)
            .map(|field: &GroundTruthField| (field.offset, field.width))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundTruthFunction {
    pub name: String,
    pub low_pc: u64,
    pub high_pc: u64,
    pub vars: Vec<GroundTruthVar>,
    pub aggregates: Vec<GroundTruthAggregate>,
}

#[derive(Debug, Clone, Default)]
pub struct DebugImage {
    pub text_base: u64,
    pub text: Vec<u8>,
    pub functions: Vec<GroundTruthFunction>,
}

impl DebugImage {
    #[must_use]
    pub fn function_bytes(&self, function: &GroundTruthFunction) -> Option<&[u8]> {
        let start: usize = usize::try_from(function.low_pc.checked_sub(self.text_base)?).ok()?;
        let end: usize = usize::try_from(function.high_pc.checked_sub(self.text_base)?).ok()?;
        if end <= start {
            return None;
        }
        self.text.get(start..end)
    }
}

type Slice<'a> = EndianSlice<'a, RunTimeEndian>;

pub fn load(bytes: &[u8]) -> Result<DebugImage> {
    let file: object::File<'_> = object::File::parse(bytes)
        .map_err(|e: object::Error| TypeRecError::Object(e.to_string()))?;
    let (text_base, text): (u64, Vec<u8>) = read_text(&file)?;
    let sections: BTreeMap<String, Vec<u8>> = collect_debug_sections(&file);
    let functions: Vec<GroundTruthFunction> = if sections.contains_key(".debug_info") {
        walk_functions(&sections, &text, text_base)?
    } else {
        Vec::new()
    };
    Ok(DebugImage {
        text_base,
        text,
        functions,
    })
}

pub fn load_text(bytes: &[u8]) -> Result<(u64, Vec<u8>)> {
    let file: object::File<'_> = object::File::parse(bytes)
        .map_err(|e: object::Error| TypeRecError::Object(e.to_string()))?;
    read_text(&file)
}

fn read_text(file: &object::File<'_>) -> Result<(u64, Vec<u8>)> {
    let section: object::Section<'_, '_> =
        file.section_by_name(".text").ok_or(TypeRecError::NoText)?;
    let data: &[u8] = section
        .data()
        .map_err(|e: object::Error| TypeRecError::Object(e.to_string()))?;
    Ok((section.address(), data.to_vec()))
}

fn collect_debug_sections(file: &object::File<'_>) -> BTreeMap<String, Vec<u8>> {
    let mut sections: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for section in file.sections() {
        let Ok(name): core::result::Result<&str, _> = section.name() else {
            continue;
        };
        if !name.starts_with(".debug_") {
            continue;
        }
        if let Ok(data) = section.data() {
            sections.insert(name.to_owned(), data.to_vec());
        }
    }
    sections
}

fn walk_functions(
    sections: &BTreeMap<String, Vec<u8>>,
    text: &[u8],
    text_base: u64,
) -> Result<Vec<GroundTruthFunction>> {
    let empty: Vec<u8> = Vec::new();
    let load_section = |id: gimli::SectionId| -> core::result::Result<Slice<'_>, gimli::Error> {
        let data: &[u8] = sections.get(id.name()).unwrap_or(&empty);
        Ok(EndianSlice::new(data, RunTimeEndian::Little))
    };
    let dwarf: Dwarf<Slice<'_>> =
        Dwarf::load(load_section).map_err(|e: gimli::Error| TypeRecError::Dwarf(e.to_string()))?;

    let mut functions: Vec<GroundTruthFunction> = Vec::new();
    let mut die_budget: usize = MAX_DIE_VISITS;
    let mut units: gimli::DebugInfoUnitHeadersIter<Slice<'_>> = dwarf.units();
    let mut unit_count: usize = 0;
    while let Some(header) = units
        .next()
        .map_err(|e: gimli::Error| TypeRecError::Dwarf(e.to_string()))?
    {
        unit_count += 1;
        if unit_count > MAX_UNITS {
            break;
        }
        let Ok(unit): core::result::Result<gimli::Unit<Slice<'_>>, _> = dwarf.unit(header) else {
            continue;
        };
        collect_unit(
            &dwarf,
            &unit,
            &mut functions,
            &mut die_budget,
            text,
            text_base,
        );
        if die_budget == 0 {
            break;
        }
    }
    Ok(functions)
}

#[derive(Debug)]
struct FunctionCtx {
    function: GroundTruthFunction,
    frame_offset: i64,
    fn_depth: isize,
    low_pc: u64,
    high_pc: u64,
}

#[derive(Debug, Clone, Copy)]
struct LexScope {
    depth: isize,
    lo: u64,
    hi: u64,
}

fn collect_unit(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    functions: &mut Vec<GroundTruthFunction>,
    die_budget: &mut usize,
    text: &[u8],
    text_base: u64,
) {
    let mut entries: gimli::EntriesCursor<'_, '_, Slice<'_>> = unit.entries();
    let mut current: Option<FunctionCtx> = None;
    let mut scopes: Vec<LexScope> = Vec::new();
    let mut depth: isize = 0;
    loop {
        if *die_budget == 0 {
            break;
        }
        *die_budget -= 1;
        let (delta, entry): (isize, &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>) =
            match entries.next_dfs() {
                Ok(Some(item)) => item,
                _ => break,
            };
        depth += delta;
        while scopes
            .last()
            .is_some_and(|scope: &LexScope| scope.depth >= depth)
        {
            scopes.pop();
        }
        let close_current: bool = current
            .as_ref()
            .is_some_and(|ctx: &FunctionCtx| depth <= ctx.fn_depth);
        if close_current && let Some(ctx) = current.take() {
            push_function(functions, ctx.function);
            scopes.clear();
        }
        let tag: gimli::DwTag = entry.tag();
        if tag == gimli::DW_TAG_subprogram {
            if let Some(ctx) = current.take() {
                push_function(functions, ctx.function);
            }
            scopes.clear();
            if let Some((function, frame_offset)) =
                start_function(dwarf, unit, entry, text, text_base)
            {
                let low_pc: u64 = function.low_pc;
                let high_pc: u64 = function.high_pc;
                current = Some(FunctionCtx {
                    function,
                    frame_offset,
                    fn_depth: depth,
                    low_pc,
                    high_pc,
                });
            }
            continue;
        }
        if tag == gimli::DW_TAG_lexical_block
            && let Some(ctx) = current.as_ref()
            && let Some(low) = attr_low_pc(dwarf, unit, entry)
            && let Some(high) = attr_high_pc(entry, low)
        {
            let _ = ctx;
            scopes.push(LexScope {
                depth,
                lo: low,
                hi: high,
            });
            continue;
        }
        if tag == gimli::DW_TAG_formal_parameter || tag == gimli::DW_TAG_variable {
            let Some(ctx): Option<&mut FunctionCtx> = current.as_mut() else {
                continue;
            };
            if depth <= ctx.fn_depth || ctx.function.vars.len() >= MAX_VARS_PER_FUNCTION {
                continue;
            }
            let (scope_lo, scope_hi): (u64, u64) = scopes
                .last()
                .map_or((ctx.low_pc, ctx.high_pc), |scope: &LexScope| {
                    (scope.lo, scope.hi)
                });
            if let Some(var) =
                read_variable(dwarf, unit, entry, ctx.frame_offset, scope_lo, scope_hi)
            {
                ctx.function.vars.push(var);
            } else if let Some(aggregate) = read_aggregate(dwarf, unit, entry, ctx.frame_offset) {
                ctx.function.aggregates.push(aggregate);
            }
        }
    }
    if let Some(ctx) = current.take() {
        push_function(functions, ctx.function);
    }
}

fn push_function(functions: &mut Vec<GroundTruthFunction>, function: GroundTruthFunction) {
    if !function.vars.is_empty() || !function.aggregates.is_empty() {
        functions.push(function);
    }
}

fn start_function(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    text: &[u8],
    text_base: u64,
) -> Option<(GroundTruthFunction, i64)> {
    let low_pc: u64 = attr_low_pc(dwarf, unit, entry)?;
    let high_pc: u64 = attr_high_pc(entry, low_pc)?;
    let frame_offset: i64 = frame_base_rbp_offset(unit, entry, low_pc, text, text_base)?;
    let name: String = attr_string(dwarf, unit, entry, gimli::DW_AT_name).unwrap_or_default();
    Some((
        GroundTruthFunction {
            name,
            low_pc,
            high_pc,
            vars: Vec::new(),
            aggregates: Vec::new(),
        },
        frame_offset,
    ))
}

fn frame_base_rbp_offset(
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    low_pc: u64,
    text: &[u8],
    text_base: u64,
) -> Option<i64> {
    let value: gimli::AttributeValue<Slice<'_>> =
        entry.attr_value(gimli::DW_AT_frame_base).ok()??;
    let gimli::AttributeValue::Exprloc(expr) = value else {
        return None;
    };
    let mut ops: gimli::OperationIter<Slice<'_>> = expr.operations(unit.encoding());
    let first: Operation<Slice<'_>> = ops.next().ok()??;
    match first {
        Operation::CallFrameCFA => {
            let start: usize = usize::try_from(low_pc.checked_sub(text_base)?).ok()?;
            let window: &[u8] = text.get(start..start.checked_add(STANDARD_PROLOGUE.len())?)?;
            (window == STANDARD_PROLOGUE).then_some(CFA_TO_RBP)
        }
        Operation::Register { register } if register.0 == RBP_DWARF_REGISTER => Some(0),
        Operation::RegisterOffset {
            register, offset, ..
        } if register.0 == RBP_DWARF_REGISTER => Some(offset),
        _ => None,
    }
}

fn read_variable(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    frame_offset: i64,
    scope_lo: u64,
    scope_hi: u64,
) -> Option<GroundTruthVar> {
    let fbreg: i64 = fbreg_offset(unit, entry)?;
    let type_offset: gimli::UnitOffset = die_type_offset(entry)?;
    let (bytes, sign): (u8, Sign) = resolve_int_type(unit, type_offset, 0)?;
    let name: String = attr_string(dwarf, unit, entry, gimli::DW_AT_name).unwrap_or_default();
    Some(GroundTruthVar {
        name,
        rbp_disp: frame_offset.checked_add(fbreg)?,
        width: Width::from_bytes(bytes),
        sign,
        scope_lo,
        scope_hi,
    })
}

fn fbreg_offset(
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Option<i64> {
    let value: gimli::AttributeValue<Slice<'_>> =
        entry.attr_value(gimli::DW_AT_location).ok()??;
    let gimli::AttributeValue::Exprloc(expr) = value else {
        return None;
    };
    let mut ops: gimli::OperationIter<Slice<'_>> = expr.operations(unit.encoding());
    match ops.next().ok()?? {
        Operation::FrameOffset { offset } => Some(offset),
        _ => None,
    }
}

fn resolve_int_type(
    unit: &gimli::Unit<Slice<'_>>,
    offset: gimli::UnitOffset,
    depth: u8,
) -> Option<(u8, Sign)> {
    if depth > MAX_TYPE_DEPTH {
        return None;
    }
    let entry: gimli::DebuggingInformationEntry<'_, '_, Slice<'_>> = unit.entry(offset).ok()?;
    match entry.tag() {
        gimli::DW_TAG_base_type => {
            let byte_size: u64 = attr_udata(&entry, gimli::DW_AT_byte_size)?;
            let bytes: u8 = u8::try_from(byte_size).ok()?;
            let encoding: u64 = attr_udata(&entry, gimli::DW_AT_encoding)?;
            let sign: Sign = encoding_sign(encoding)?;
            Some((bytes, sign))
        }
        gimli::DW_TAG_typedef
        | gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type
        | gimli::DW_TAG_atomic_type => {
            let inner: gimli::UnitOffset = die_type_offset(&entry)?;
            resolve_int_type(unit, inner, depth + 1)
        }
        _ => None,
    }
}

const fn encoding_sign(encoding: u64) -> Option<Sign> {
    match encoding {
        DW_ATE_SIGNED | DW_ATE_SIGNED_CHAR => Some(Sign::Signed),
        DW_ATE_UNSIGNED | DW_ATE_UNSIGNED_CHAR | DW_ATE_BOOLEAN => Some(Sign::Unsigned),
        _ => None,
    }
}

const MAX_FIELDS: usize = 1 << 12;

#[derive(Debug, Clone, Copy)]
enum MemberType {
    Scalar { bytes: u8, sign: Sign },
    Pointer,
    Array { bytes: u8 },
    Aggregate { offset: gimli::UnitOffset },
    Unknown,
}

fn read_aggregate(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    frame_offset: i64,
) -> Option<GroundTruthAggregate> {
    let fbreg: i64 = fbreg_offset(unit, entry)?;
    let rbp_disp: i64 = frame_offset.checked_add(fbreg)?;
    let type_offset: gimli::UnitOffset = die_type_offset(entry)?;
    let outer: gimli::UnitOffset = strip_typedefs(unit, type_offset, 0)?;
    let outer_entry: gimli::DebuggingInformationEntry<'_, '_, Slice<'_>> =
        unit.entry(outer).ok()?;
    if outer_entry.tag() != gimli::DW_TAG_pointer_type {
        return None;
    }
    let pointee_raw: gimli::UnitOffset = die_type_offset(&outer_entry)?;
    let pointee: gimli::UnitOffset = strip_typedefs(unit, pointee_raw, 0)?;
    let pointee_entry: gimli::DebuggingInformationEntry<'_, '_, Slice<'_>> =
        unit.entry(pointee).ok()?;
    let mut fields: Vec<GroundTruthField> = Vec::new();
    let is_union: bool = pointee_entry.tag() == gimli::DW_TAG_union_type;
    match pointee_entry.tag() {
        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
            flatten_members(dwarf, unit, pointee, 0, &mut fields, 0);
        }
        gimli::DW_TAG_base_type => {
            let (bytes, sign): (u8, Sign) = base_width_sign(&pointee_entry)?;
            fields.push(GroundTruthField {
                offset: 0,
                width: Width::from_bytes(bytes),
                sign,
                is_pointer: false,
                name: String::new(),
            });
        }
        gimli::DW_TAG_pointer_type => {
            fields.push(GroundTruthField {
                offset: 0,
                width: Width::Qword,
                sign: Sign::Unknown,
                is_pointer: true,
                name: String::new(),
            });
        }
        gimli::DW_TAG_array_type => {
            let bytes: u8 = array_element_bytes(unit, pointee, 0)?;
            fields.push(GroundTruthField {
                offset: 0,
                width: Width::from_bytes(bytes),
                sign: Sign::Unknown,
                is_pointer: false,
                name: String::new(),
            });
        }
        _ => return None,
    }
    if fields.is_empty() {
        return None;
    }
    let type_name: String =
        attr_string(dwarf, unit, &pointee_entry, gimli::DW_AT_name).unwrap_or_default();
    Some(GroundTruthAggregate {
        rbp_disp,
        is_union,
        type_name,
        fields,
    })
}

fn strip_typedefs(
    unit: &gimli::Unit<Slice<'_>>,
    offset: gimli::UnitOffset,
    depth: u8,
) -> Option<gimli::UnitOffset> {
    if depth > MAX_TYPE_DEPTH {
        return None;
    }
    let entry: gimli::DebuggingInformationEntry<'_, '_, Slice<'_>> = unit.entry(offset).ok()?;
    match entry.tag() {
        gimli::DW_TAG_typedef
        | gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type
        | gimli::DW_TAG_atomic_type => {
            let inner: gimli::UnitOffset = die_type_offset(&entry)?;
            strip_typedefs(unit, inner, depth + 1)
        }
        _ => Some(offset),
    }
}

fn flatten_members(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    struct_offset: gimli::UnitOffset,
    base_offset: i64,
    out: &mut Vec<GroundTruthField>,
    depth: u8,
) {
    if depth > MAX_TYPE_DEPTH {
        return;
    }
    let Ok(mut tree): core::result::Result<gimli::EntriesTree<'_, '_, Slice<'_>>, _> =
        unit.entries_tree(Some(struct_offset))
    else {
        return;
    };
    let Ok(root): core::result::Result<gimli::EntriesTreeNode<'_, '_, '_, Slice<'_>>, _> =
        tree.root()
    else {
        return;
    };
    let mut children: gimli::EntriesTreeIter<'_, '_, '_, Slice<'_>> = root.children();
    while let Ok(Some(child)) = children.next() {
        if out.len() >= MAX_FIELDS {
            return;
        }
        let entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>> = child.entry();
        if entry.tag() != gimli::DW_TAG_member {
            continue;
        }
        let member_offset: i64 = base_offset.saturating_add(member_location(entry));
        let name: String = attr_string(dwarf, unit, entry, gimli::DW_AT_name).unwrap_or_default();
        let Some(type_offset): Option<gimli::UnitOffset> = die_type_offset(entry) else {
            continue;
        };
        match classify_member_type(unit, type_offset, depth) {
            MemberType::Scalar { bytes, sign } => out.push(GroundTruthField {
                offset: member_offset,
                width: Width::from_bytes(bytes),
                sign,
                is_pointer: false,
                name,
            }),
            MemberType::Pointer => out.push(GroundTruthField {
                offset: member_offset,
                width: Width::Qword,
                sign: Sign::Unknown,
                is_pointer: true,
                name,
            }),
            MemberType::Array { bytes } => out.push(GroundTruthField {
                offset: member_offset,
                width: Width::from_bytes(bytes),
                sign: Sign::Unknown,
                is_pointer: false,
                name,
            }),
            MemberType::Aggregate { offset } => {
                flatten_members(dwarf, unit, offset, member_offset, out, depth + 1);
            }
            MemberType::Unknown => {}
        }
    }
}

fn classify_member_type(
    unit: &gimli::Unit<Slice<'_>>,
    type_offset: gimli::UnitOffset,
    depth: u8,
) -> MemberType {
    let Some(stripped): Option<gimli::UnitOffset> = strip_typedefs(unit, type_offset, depth) else {
        return MemberType::Unknown;
    };
    let Ok(entry): core::result::Result<gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>, _> =
        unit.entry(stripped)
    else {
        return MemberType::Unknown;
    };
    match entry.tag() {
        gimli::DW_TAG_base_type => base_width_sign(&entry)
            .map_or(MemberType::Unknown, |(bytes, sign): (u8, Sign)| {
                MemberType::Scalar { bytes, sign }
            }),
        gimli::DW_TAG_enumeration_type => {
            enum_bytes(&entry).map_or(MemberType::Unknown, |bytes: u8| MemberType::Scalar {
                bytes,
                sign: Sign::Unknown,
            })
        }
        gimli::DW_TAG_pointer_type => MemberType::Pointer,
        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
            MemberType::Aggregate { offset: stripped }
        }
        gimli::DW_TAG_array_type => array_element_bytes(unit, stripped, depth)
            .map_or(MemberType::Unknown, |bytes: u8| MemberType::Array { bytes }),
        _ => MemberType::Unknown,
    }
}

fn enum_bytes(entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>) -> Option<u8> {
    let size: u64 = attr_udata(entry, gimli::DW_AT_byte_size)?;
    u8::try_from(size).ok()
}

fn array_element_bytes(
    unit: &gimli::Unit<Slice<'_>>,
    array_offset: gimli::UnitOffset,
    depth: u8,
) -> Option<u8> {
    let entry: gimli::DebuggingInformationEntry<'_, '_, Slice<'_>> =
        unit.entry(array_offset).ok()?;
    let element: gimli::UnitOffset = die_type_offset(&entry)?;
    match classify_member_type(unit, element, depth + 1) {
        MemberType::Scalar { bytes, .. } | MemberType::Array { bytes } => Some(bytes),
        MemberType::Pointer => Some(8),
        _ => None,
    }
}

fn base_width_sign(
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Option<(u8, Sign)> {
    let byte_size: u64 = attr_udata(entry, gimli::DW_AT_byte_size)?;
    let bytes: u8 = u8::try_from(byte_size).ok()?;
    let sign: Sign = attr_udata(entry, gimli::DW_AT_encoding)
        .and_then(encoding_sign)
        .unwrap_or(Sign::Unknown);
    Some((bytes, sign))
}

fn member_location(entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>) -> i64 {
    attr_udata(entry, gimli::DW_AT_data_member_location)
        .and_then(|value: u64| i64::try_from(value).ok())
        .unwrap_or(0)
}

fn die_type_offset(
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Option<gimli::UnitOffset> {
    match entry.attr_value(gimli::DW_AT_type).ok()?? {
        gimli::AttributeValue::UnitRef(offset) => Some(offset),
        _ => None,
    }
}

fn attr_string(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    attr: gimli::DwAt,
) -> Option<String> {
    let value: gimli::AttributeValue<Slice<'_>> = entry.attr_value(attr).ok()??;
    let slice: Slice<'_> = dwarf.attr_string(unit, value).ok()?;
    core::str::from_utf8(slice.slice()).ok().map(str::to_owned)
}

fn attr_udata(
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    attr: gimli::DwAt,
) -> Option<u64> {
    match entry.attr_value(attr).ok()?? {
        gimli::AttributeValue::Udata(v) | gimli::AttributeValue::Data8(v) => Some(v),
        gimli::AttributeValue::Data1(v) => Some(u64::from(v)),
        gimli::AttributeValue::Data2(v) => Some(u64::from(v)),
        gimli::AttributeValue::Data4(v) => Some(u64::from(v)),
        gimli::AttributeValue::Encoding(v) => Some(u64::from(v.0)),
        _ => None,
    }
}

fn attr_low_pc(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Option<u64> {
    match entry.attr_value(gimli::DW_AT_low_pc).ok()?? {
        gimli::AttributeValue::Addr(a) => Some(a),
        gimli::AttributeValue::DebugAddrIndex(index) => dwarf.address(unit, index).ok(),
        _ => None,
    }
}

fn attr_high_pc(
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    low_pc: u64,
) -> Option<u64> {
    match entry.attr_value(gimli::DW_AT_high_pc).ok()?? {
        gimli::AttributeValue::Addr(a) => Some(a),
        gimli::AttributeValue::Udata(offset) => low_pc.checked_add(offset),
        gimli::AttributeValue::Data1(offset) => low_pc.checked_add(u64::from(offset)),
        gimli::AttributeValue::Data2(offset) => low_pc.checked_add(u64::from(offset)),
        gimli::AttributeValue::Data4(offset) => low_pc.checked_add(u64::from(offset)),
        _ => None,
    }
}
