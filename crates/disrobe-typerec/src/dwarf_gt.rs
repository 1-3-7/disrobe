use std::collections::BTreeMap;

use gimli::{Dwarf, EndianSlice, RunTimeEndian};
use object::{Object, ObjectSection};

use crate::dwarf_location::{self, FrameBase, FrameSlot, LocationSurvey, PcRange, UnlocatedReason};
use crate::error::{Result, TypeRecError};
use crate::lattice::{Sign, Width};

const MAX_UNITS: usize = 1 << 12;
const MAX_DIE_VISITS: usize = 1 << 20;
const MAX_TYPE_DEPTH: u8 = 16;
const MAX_VARS_PER_FUNCTION: usize = 1 << 12;

const DW_ATE_BOOLEAN: u64 = 0x02;
const DW_ATE_FLOAT: u64 = 0x04;
const DW_ATE_SIGNED: u64 = 0x05;
const DW_ATE_SIGNED_CHAR: u64 = 0x06;
const DW_ATE_UNSIGNED: u64 = 0x07;
const DW_ATE_UNSIGNED_CHAR: u64 = 0x08;
const MAX_PARAMS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiClass {
    Integer,
    Sse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtReturn {
    Void,
    Integer,
    Sse,
    Sret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundTruthSignature {
    pub prototyped: bool,
    pub params: Vec<AbiClass>,
    pub variadic: bool,
    pub ret: GtReturn,
}

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
    pub scope_lo: u64,
    pub scope_hi: u64,
}

impl GroundTruthAggregate {
    #[must_use]
    pub const fn scope_overlaps(&self, lo: u64, hi: u64) -> bool {
        self.scope_lo < hi && lo < self.scope_hi
    }

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
    pub signature: Option<GroundTruthSignature>,
}

#[derive(Debug, Clone, Default)]
pub struct DebugImage {
    pub text_base: u64,
    pub text: Vec<u8>,
    pub functions: Vec<GroundTruthFunction>,
    pub locations: LocationSurvey,
}

impl DebugImage {
    #[must_use]
    pub fn function_bytes(&self, function: &GroundTruthFunction) -> Option<&[u8]> {
        dwarf_location::function_slice(
            &self.text,
            self.text_base,
            PcRange::new(function.low_pc, function.high_pc),
        )
    }

    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.functions
            .iter()
            .map(|function: &GroundTruthFunction| function.vars.len())
            .sum()
    }
}

type Slice<'a> = EndianSlice<'a, RunTimeEndian>;

pub fn load(bytes: &[u8]) -> Result<DebugImage> {
    let file: object::File<'_> = object::File::parse(bytes)
        .map_err(|e: object::Error| TypeRecError::Object(e.to_string()))?;
    let (text_base, text): (u64, Vec<u8>) = read_text(&file)?;
    let sections: BTreeMap<String, Vec<u8>> = collect_debug_sections(&file);
    let (functions, locations): (Vec<GroundTruthFunction>, LocationSurvey) =
        if sections.contains_key(".debug_info") {
            walk_functions(&sections, &text, text_base)?
        } else {
            (Vec::new(), LocationSurvey::default())
        };
    Ok(DebugImage {
        text_base,
        text,
        functions,
        locations,
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
) -> Result<(Vec<GroundTruthFunction>, LocationSurvey)> {
    let empty: Vec<u8> = Vec::new();
    let load_section = |id: gimli::SectionId| -> core::result::Result<Slice<'_>, gimli::Error> {
        let data: &[u8] = sections.get(id.name()).unwrap_or(&empty);
        Ok(EndianSlice::new(data, RunTimeEndian::Little))
    };
    let dwarf: Dwarf<Slice<'_>> =
        Dwarf::load(load_section).map_err(|e: gimli::Error| TypeRecError::Dwarf(e.to_string()))?;

    let mut functions: Vec<GroundTruthFunction> = Vec::new();
    let mut survey: LocationSurvey = LocationSurvey::default();
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
        survey.record_version(unit.encoding().version);
        collect_unit(
            &dwarf,
            &unit,
            &mut functions,
            &mut survey,
            &mut die_budget,
            text,
            text_base,
        );
        if die_budget == 0 {
            break;
        }
    }
    Ok((functions, survey))
}

#[derive(Debug)]
struct FunctionCtx {
    function: GroundTruthFunction,
    frame: FrameBase,
    fn_depth: isize,
    range: PcRange,
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
    survey: &mut LocationSurvey,
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
            survey.subprograms += 1;
            if let Some((function, frame)) = start_function(dwarf, unit, entry, text, text_base) {
                let range: PcRange = PcRange::new(function.low_pc, function.high_pc);
                current = Some(FunctionCtx {
                    function,
                    frame,
                    fn_depth: depth,
                    range,
                });
            } else {
                survey.subprograms_without_code += 1;
            }
            continue;
        }
        if matches!(
            tag,
            gimli::DW_TAG_lexical_block | gimli::DW_TAG_inlined_subroutine
        ) && current.is_some()
            && let Some(low) = attr_low_pc(dwarf, unit, entry)
            && let Some(high) = attr_high_pc(entry, low)
        {
            scopes.push(LexScope {
                depth,
                lo: low,
                hi: high,
            });
            continue;
        }
        if tag == gimli::DW_TAG_unspecified_parameters
            && let Some(ctx) = current.as_mut()
            && depth == ctx.fn_depth + 1
            && let Some(sig) = ctx.function.signature.as_mut()
        {
            sig.variadic = true;
        }
        if tag == gimli::DW_TAG_formal_parameter || tag == gimli::DW_TAG_variable {
            let Some(ctx): Option<&mut FunctionCtx> = current.as_mut() else {
                continue;
            };
            if tag == gimli::DW_TAG_formal_parameter && depth == ctx.fn_depth + 1 {
                let class: AbiClass = abi_class(unit, die_type_offset(entry));
                if let Some(sig) = ctx.function.signature.as_mut()
                    && sig.params.len() < MAX_PARAMS
                {
                    sig.params.push(class);
                }
            }
            if depth <= ctx.fn_depth {
                continue;
            }
            let scope: PcRange = scopes.last().map_or(ctx.range, |lexical: &LexScope| {
                PcRange::new(lexical.lo, lexical.hi)
            });
            record_declaration(dwarf, unit, entry, ctx, survey, scope);
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
) -> Option<(GroundTruthFunction, FrameBase)> {
    let low_pc: u64 = attr_low_pc(dwarf, unit, entry)?;
    let high_pc: u64 = attr_high_pc(entry, low_pc)?;
    let range: PcRange = PcRange::new(low_pc, high_pc);
    if range.is_empty() {
        return None;
    }
    let frame: FrameBase =
        dwarf_location::resolve_frame_base(dwarf, unit, entry, range, text, text_base);
    let name: String = attr_string(dwarf, unit, entry, gimli::DW_AT_name).unwrap_or_default();
    let signature: GroundTruthSignature = GroundTruthSignature {
        prototyped: attr_flag(entry, gimli::DW_AT_prototyped),
        params: Vec::new(),
        variadic: false,
        ret: return_class(unit, die_type_offset(entry)),
    };
    Some((
        GroundTruthFunction {
            name,
            low_pc,
            high_pc,
            vars: Vec::new(),
            aggregates: Vec::new(),
            signature: Some(signature),
        },
        frame,
    ))
}

fn attr_flag(
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    attr: gimli::DwAt,
) -> bool {
    match entry.attr_value(attr) {
        Ok(Some(gimli::AttributeValue::Flag(flag))) => flag,
        Ok(Some(_)) => true,
        _ => false,
    }
}

fn abi_class(unit: &gimli::Unit<Slice<'_>>, type_offset: Option<gimli::UnitOffset>) -> AbiClass {
    let Some(offset): Option<gimli::UnitOffset> = type_offset else {
        return AbiClass::Integer;
    };
    let Some(stripped): Option<gimli::UnitOffset> = strip_typedefs(unit, offset, 0) else {
        return AbiClass::Integer;
    };
    let Ok(entry): core::result::Result<gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>, _> =
        unit.entry(stripped)
    else {
        return AbiClass::Integer;
    };
    if entry.tag() == gimli::DW_TAG_base_type
        && attr_udata(&entry, gimli::DW_AT_encoding) == Some(DW_ATE_FLOAT)
    {
        AbiClass::Sse
    } else {
        AbiClass::Integer
    }
}

fn return_class(unit: &gimli::Unit<Slice<'_>>, type_offset: Option<gimli::UnitOffset>) -> GtReturn {
    let Some(offset): Option<gimli::UnitOffset> = type_offset else {
        return GtReturn::Void;
    };
    let Some(stripped): Option<gimli::UnitOffset> = strip_typedefs(unit, offset, 0) else {
        return GtReturn::Integer;
    };
    let Ok(entry): core::result::Result<gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>, _> =
        unit.entry(stripped)
    else {
        return GtReturn::Integer;
    };
    match entry.tag() {
        gimli::DW_TAG_base_type => {
            if attr_udata(&entry, gimli::DW_AT_encoding) == Some(DW_ATE_FLOAT) {
                GtReturn::Sse
            } else {
                GtReturn::Integer
            }
        }
        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type | gimli::DW_TAG_array_type => {
            match attr_udata(&entry, gimli::DW_AT_byte_size) {
                Some(1 | 2 | 4 | 8) => GtReturn::Integer,
                _ => GtReturn::Sret,
            }
        }
        _ => GtReturn::Integer,
    }
}

fn record_declaration(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    ctx: &mut FunctionCtx,
    survey: &mut LocationSurvey,
    scope: PcRange,
) {
    survey.record_declared();
    if ctx.function.vars.len() + ctx.function.aggregates.len() >= MAX_VARS_PER_FUNCTION {
        survey.record_unlocated(UnlocatedReason::VariableBudgetExhausted);
        return;
    }
    let slots: Vec<FrameSlot> =
        match dwarf_location::frame_slots(dwarf, unit, entry, &ctx.frame, ctx.range) {
            Ok(slots) => slots,
            Err(reason) => {
                survey.record_unlocated(reason);
                return;
            }
        };
    let scoped: Vec<FrameSlot> = slots
        .iter()
        .filter_map(|slot: &FrameSlot| {
            slot.range.intersect(scope).map(|range: PcRange| FrameSlot {
                rbp_disp: slot.rbp_disp,
                range,
            })
        })
        .collect();
    if scoped.is_empty() {
        survey.record_unlocated(UnlocatedReason::ScopeOutsideFrameWindow);
        return;
    }
    let Some(type_offset): Option<gimli::UnitOffset> = type_offset_through_origin(unit, entry, 0)
    else {
        survey.record_unlocated(UnlocatedReason::NoTypeAttribute);
        return;
    };
    let name: String = name_through_origin(dwarf, unit, entry, 0).unwrap_or_default();
    if let Some((bytes, sign)) = resolve_int_type(unit, type_offset, 0) {
        for slot in &scoped {
            ctx.function.vars.push(GroundTruthVar {
                name: name.clone(),
                rbp_disp: slot.rbp_disp,
                width: Width::from_bytes(bytes),
                sign,
                scope_lo: slot.range.lo,
                scope_hi: slot.range.hi,
            });
        }
        survey.record_located();
        return;
    }
    let Some(aggregate): Option<GroundTruthAggregate> =
        read_aggregate(dwarf, unit, type_offset, &scoped)
    else {
        survey.record_unlocated(UnlocatedReason::NonIntegerType);
        return;
    };
    for slot in &scoped {
        ctx.function.aggregates.push(GroundTruthAggregate {
            rbp_disp: slot.rbp_disp,
            scope_lo: slot.range.lo,
            scope_hi: slot.range.hi,
            ..aggregate.clone()
        });
    }
    survey.record_located();
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
    type_offset: gimli::UnitOffset,
    scoped: &[FrameSlot],
) -> Option<GroundTruthAggregate> {
    let first: &FrameSlot = scoped.first()?;
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
        rbp_disp: first.rbp_disp,
        is_union,
        type_name,
        fields,
        scope_lo: first.range.lo,
        scope_hi: first.range.hi,
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

fn die_reference(
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    attr: gimli::DwAt,
) -> Option<gimli::UnitOffset> {
    match entry.attr_value(attr).ok()?? {
        gimli::AttributeValue::UnitRef(offset) => Some(offset),
        _ => None,
    }
}

fn origin_of(
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Option<gimli::UnitOffset> {
    die_reference(entry, gimli::DW_AT_abstract_origin)
        .or_else(|| die_reference(entry, gimli::DW_AT_specification))
}

fn type_offset_through_origin(
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    depth: u8,
) -> Option<gimli::UnitOffset> {
    if let Some(offset) = die_type_offset(entry) {
        return Some(offset);
    }
    if depth >= MAX_TYPE_DEPTH {
        return None;
    }
    let origin: gimli::UnitOffset = origin_of(entry)?;
    let referenced: gimli::DebuggingInformationEntry<'_, '_, Slice<'_>> =
        unit.entry(origin).ok()?;
    type_offset_through_origin(unit, &referenced, depth + 1)
}

fn name_through_origin(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    depth: u8,
) -> Option<String> {
    if let Some(name) = attr_string(dwarf, unit, entry, gimli::DW_AT_name) {
        return Some(name);
    }
    if depth >= MAX_TYPE_DEPTH {
        return None;
    }
    let origin: gimli::UnitOffset = origin_of(entry)?;
    let referenced: gimli::DebuggingInformationEntry<'_, '_, Slice<'_>> =
        unit.entry(origin).ok()?;
    name_through_origin(dwarf, unit, &referenced, depth + 1)
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
