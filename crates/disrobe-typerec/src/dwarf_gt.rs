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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundTruthFunction {
    pub name: String,
    pub low_pc: u64,
    pub high_pc: u64,
    pub vars: Vec<GroundTruthVar>,
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

fn collect_unit(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    functions: &mut Vec<GroundTruthFunction>,
    die_budget: &mut usize,
    text: &[u8],
    text_base: u64,
) {
    let mut entries: gimli::EntriesCursor<'_, '_, Slice<'_>> = unit.entries();
    let mut current: Option<(GroundTruthFunction, i64, isize)> = None;
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
        let close_current: bool = current
            .as_ref()
            .is_some_and(|(_, _, fn_depth): &(GroundTruthFunction, i64, isize)| depth <= *fn_depth);
        if close_current && let Some((done, _, _)) = current.take() {
            push_function(functions, done);
        }
        let tag: gimli::DwTag = entry.tag();
        if tag == gimli::DW_TAG_subprogram {
            if let Some((done, _, _)) = current.take() {
                push_function(functions, done);
            }
            if let Some(built) = start_function(dwarf, unit, entry, text, text_base) {
                current = Some((built.0, built.1, depth));
            }
            continue;
        }
        if tag == gimli::DW_TAG_formal_parameter || tag == gimli::DW_TAG_variable {
            let Some((function, frame_offset, fn_depth)): Option<&mut (
                GroundTruthFunction,
                i64,
                isize,
            )> = current.as_mut() else {
                continue;
            };
            if depth != *fn_depth + 1 || function.vars.len() >= MAX_VARS_PER_FUNCTION {
                continue;
            }
            if let Some(var) = read_variable(dwarf, unit, entry, *frame_offset) {
                function.vars.push(var);
            }
        }
    }
    if let Some((done, _, _)) = current.take() {
        push_function(functions, done);
    }
}

fn push_function(functions: &mut Vec<GroundTruthFunction>, function: GroundTruthFunction) {
    if !function.vars.is_empty() {
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
