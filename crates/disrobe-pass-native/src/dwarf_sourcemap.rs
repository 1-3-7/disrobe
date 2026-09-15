#![allow(clippy::doc_markdown)]
use std::collections::BTreeMap;

use gimli::{Dwarf, EndianSlice, RunTimeEndian, UnitOffset};
use object::{Object, ObjectSection};
use serde::Serialize;

use crate::error::{Error, Result};

const SOURCEMAP_SCHEMA_VERSION: u32 = 1;

const TYPE_RESOLVE_MAX_DEPTH: u32 = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompileUnit {
    pub name: Option<String>,
    pub comp_dir: Option<String>,
    pub producer: Option<String>,
    pub low_pc: Option<u64>,
    pub unit_offset: u64,
    pub dwarf_version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineRow {
    pub pc: u64,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DwarfSourcemap {
    pub compile_units: Vec<CompileUnit>,
    pub line_rows: Vec<LineRow>,
}

impl DwarfSourcemap {
    #[must_use]
    pub fn to_sourcemap_json(&self) -> serde_json::Value {
        serde_json::json!({
            "version": SOURCEMAP_SCHEMA_VERSION,
            "function_count": self.compile_units.len(),
            "line_entries": self.line_rows.len(),
            "compile_units": &self.compile_units,
            "line_map": &self.line_rows,
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.compile_units.is_empty() && self.line_rows.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconstructedType {
    pub name: String,
    pub kind: TypeKind,
    pub byte_size: Option<u64>,
    pub members: Vec<TypeMember>,
    pub template_params: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TypeMember {
    pub name: String,
    pub type_name: String,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TypeKind {
    Base,
    Pointer,
    Reference,
    Structure,
    Class,
    Union,
    Enumeration,
    Array,
    Typedef,
    Const,
    Volatile,
    Subroutine,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TypeReconstruction {
    pub types: Vec<ReconstructedType>,
    pub coverage: CoverageScore,
    pub split_dwarf: SplitDwarfInfo,
}

impl TypeReconstruction {
    #[must_use]
    pub fn named_type_count(&self) -> usize {
        self.types
            .iter()
            .filter(|t: &&ReconstructedType| !t.name.contains("<anon>") && !t.name.is_empty())
            .count()
    }

    #[must_use]
    pub fn type_reconstruction_ratio(&self) -> f64 {
        if self.types.is_empty() {
            return 0.0;
        }
        self.named_type_count() as f64 / self.types.len() as f64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CoverageScore {
    pub text_size: u64,
    pub covered_bytes: u64,
}

impl CoverageScore {
    #[must_use]
    pub fn pct(&self) -> f64 {
        if self.text_size == 0 {
            return 0.0;
        }
        100.0 * self.covered_bytes as f64 / self.text_size as f64
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SplitDwarfInfo {
    pub has_skeleton_units: bool,

    pub dwo_names: Vec<String>,

    pub has_str_offsets: bool,
    pub has_addr_index: bool,
}

pub fn synthesize_dwarf_sourcemap(bytes: &[u8]) -> Result<DwarfSourcemap> {
    let object_file: object::File<'_> =
        object::File::parse(bytes).map_err(|_e: object::Error| Error::UnknownFormat)?;
    let endian: RunTimeEndian = if object_file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    if !has_debug_sections(&object_file) {
        return Err(Error::SignatureDb(
            "DWARF sourcemap: object carries no .debug_line/.debug_info sections".to_owned(),
        ));
    }

    let load_section =
        |id: gimli::SectionId| -> std::result::Result<EndianSlice<'_, RunTimeEndian>, gimli::Error> {
            let data: &[u8] = object_file
                .section_by_name(id.name())
                .and_then(|s: object::Section<'_, '_>| s.data().ok())
                .unwrap_or(&[]);
            Ok(EndianSlice::new(data, endian))
        };
    let dwarf: Dwarf<EndianSlice<'_, RunTimeEndian>> =
        Dwarf::load(load_section).map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?;

    let mut compile_units: Vec<CompileUnit> = Vec::new();
    let mut line_rows: Vec<LineRow> = Vec::new();

    let mut unit_headers: gimli::DebugInfoUnitHeadersIter<EndianSlice<'_, RunTimeEndian>> =
        dwarf.units();
    while let Some(header) = unit_headers
        .next()
        .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
    {
        let unit: gimli::Unit<EndianSlice<'_, RunTimeEndian>> = dwarf
            .unit(header)
            .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?;
        let unit_offset: u64 = header
            .offset()
            .as_debug_info_offset()
            .map_or(0, |o: gimli::DebugInfoOffset| o.0 as u64);
        let cu: CompileUnit = recover_compile_unit(&dwarf, &unit, unit_offset)?;
        compile_units.push(cu);
        collect_line_rows(&dwarf, &unit, &mut line_rows)?;
    }

    line_rows.sort_by_key(|r: &LineRow| r.pc);
    Ok(DwarfSourcemap {
        compile_units,
        line_rows,
    })
}

fn has_debug_sections(object_file: &object::File<'_>) -> bool {
    object_file.section_by_name(".debug_info").is_some()
        || object_file.section_by_name(".debug_line").is_some()
}

pub fn reconstruct_dwarf_types(bytes: &[u8]) -> Result<TypeReconstruction> {
    let object_file: object::File<'_> =
        object::File::parse(bytes).map_err(|_e: object::Error| Error::UnknownFormat)?;
    let endian: RunTimeEndian = if object_file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    if !has_debug_sections(&object_file) {
        return Err(Error::SignatureDb(
            "DWARF type recovery: object carries no .debug_info section".to_owned(),
        ));
    }
    let coverage: CoverageScore = compute_coverage_score(&object_file)?;
    let split_dwarf_sections: SplitDwarfSections = SplitDwarfSections {
        has_str_offsets: object_file.section_by_name(".debug_str_offsets").is_some()
            || object_file
                .section_by_name(".debug_str_offsets.dwo")
                .is_some(),
        has_addr_index: object_file.section_by_name(".debug_addr").is_some(),
    };

    let load_section =
        |id: gimli::SectionId| -> std::result::Result<EndianSlice<'_, RunTimeEndian>, gimli::Error> {
            let data: &[u8] = object_file
                .section_by_name(id.name())
                .and_then(|s: object::Section<'_, '_>| s.data().ok())
                .unwrap_or(&[]);
            Ok(EndianSlice::new(data, endian))
        };
    let dwarf: Dwarf<EndianSlice<'_, RunTimeEndian>> =
        Dwarf::load(load_section).map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?;

    let mut types: Vec<ReconstructedType> = Vec::new();
    let mut dwo_names: Vec<String> = Vec::new();

    let mut unit_headers: gimli::DebugInfoUnitHeadersIter<EndianSlice<'_, RunTimeEndian>> =
        dwarf.units();
    while let Some(header) = unit_headers
        .next()
        .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
    {
        let unit: gimli::Unit<EndianSlice<'_, RunTimeEndian>> = dwarf
            .unit(header)
            .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?;
        collect_dwo_name(&dwarf, &unit, &mut dwo_names)?;
        let index: TypeDieIndex = index_type_dies(&dwarf, &unit)?;
        for (offset, entry) in &index.entries {
            if !entry.is_renderable_root() {
                continue;
            }
            let rendered: ReconstructedType = render_named_type(&index, *offset);
            types.push(rendered);
        }
    }

    types.sort_by(|a: &ReconstructedType, b: &ReconstructedType| a.name.cmp(&b.name));
    types.dedup();

    Ok(TypeReconstruction {
        types,
        coverage,
        split_dwarf: SplitDwarfInfo {
            has_skeleton_units: !dwo_names.is_empty(),
            dwo_names,
            has_str_offsets: split_dwarf_sections.has_str_offsets,
            has_addr_index: split_dwarf_sections.has_addr_index,
        },
    })
}

struct SplitDwarfSections {
    has_str_offsets: bool,
    has_addr_index: bool,
}

fn compute_coverage_score(object_file: &object::File<'_>) -> Result<CoverageScore> {
    let text: Option<(u64, u64)> = object_file
        .section_by_name(".text")
        .map(|s: object::Section<'_, '_>| (s.address(), s.size()));
    let Some((text_lo, text_size)): Option<(u64, u64)> = text else {
        return Ok(CoverageScore {
            text_size: 0,
            covered_bytes: 0,
        });
    };
    let text_hi: u64 = text_lo.saturating_add(text_size);
    let endian: RunTimeEndian = if object_file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let load_section =
        |id: gimli::SectionId| -> std::result::Result<EndianSlice<'_, RunTimeEndian>, gimli::Error> {
            let data: &[u8] = object_file
                .section_by_name(id.name())
                .and_then(|s: object::Section<'_, '_>| s.data().ok())
                .unwrap_or(&[]);
            Ok(EndianSlice::new(data, endian))
        };
    let dwarf: Dwarf<EndianSlice<'_, RunTimeEndian>> =
        Dwarf::load(load_section).map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?;

    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut unit_headers: gimli::DebugInfoUnitHeadersIter<EndianSlice<'_, RunTimeEndian>> =
        dwarf.units();
    while let Some(header) = unit_headers
        .next()
        .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
    {
        let unit: gimli::Unit<EndianSlice<'_, RunTimeEndian>> = dwarf
            .unit(header)
            .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?;
        let Some(program): Option<gimli::IncompleteLineProgram<EndianSlice<'_, RunTimeEndian>>> =
            unit.line_program.clone()
        else {
            continue;
        };
        let mut rows: gimli::LineRows<
            EndianSlice<'_, RunTimeEndian>,
            gimli::IncompleteLineProgram<EndianSlice<'_, RunTimeEndian>>,
            usize,
        > = program.rows();
        let mut seq_start: Option<u64> = None;
        while let Some((_, row)) = rows
            .next_row()
            .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
        {
            if row.end_sequence() {
                if let Some(start) = seq_start.take() {
                    let lo: u64 = start.max(text_lo);
                    let hi: u64 = row.address().min(text_hi);
                    if hi > lo {
                        ranges.push((lo, hi));
                    }
                }
            } else if seq_start.is_none() {
                seq_start = Some(row.address());
            }
        }
    }
    let covered_bytes: u64 = merge_ranges_len(&mut ranges);
    Ok(CoverageScore {
        text_size,
        covered_bytes,
    })
}

fn merge_ranges_len(ranges: &mut [(u64, u64)]) -> u64 {
    if ranges.is_empty() {
        return 0;
    }
    ranges.sort_by_key(|r: &(u64, u64)| r.0);
    let mut total: u64 = 0;
    let (mut cur_lo, mut cur_hi): (u64, u64) = ranges[0];
    for &(lo, hi) in ranges.iter().skip(1) {
        if lo > cur_hi {
            total += cur_hi - cur_lo;
            cur_lo = lo;
            cur_hi = hi;
        } else {
            cur_hi = cur_hi.max(hi);
        }
    }
    total += cur_hi - cur_lo;
    total
}

struct TypeDieIndex {
    entries: BTreeMap<UnitOffset, TypeDie>,
}

#[derive(Debug, Clone)]
struct TypeDie {
    tag: gimli::DwTag,
    name: Option<String>,
    byte_size: Option<u64>,
    type_ref: Option<UnitOffset>,
    count: Option<u64>,
    members: Vec<MemberDie>,
    template_params: Vec<TemplateParamDie>,
}

#[derive(Debug, Clone)]
struct MemberDie {
    name: Option<String>,
    type_ref: Option<UnitOffset>,
    offset: Option<u64>,
}

#[derive(Debug, Clone)]
struct TemplateParamDie {
    name: Option<String>,
    type_ref: Option<UnitOffset>,
}

impl TypeDie {
    fn is_renderable_root(&self) -> bool {
        matches!(
            self.tag,
            gimli::DW_TAG_structure_type
                | gimli::DW_TAG_class_type
                | gimli::DW_TAG_union_type
                | gimli::DW_TAG_enumeration_type
                | gimli::DW_TAG_typedef
                | gimli::DW_TAG_base_type
        ) && self.name.is_some()
    }
}

fn index_type_dies(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
) -> Result<TypeDieIndex> {
    let mut entries: BTreeMap<UnitOffset, TypeDie> = BTreeMap::new();
    let mut cursor: gimli::EntriesCursor<'_, '_, EndianSlice<'_, RunTimeEndian>> = unit.entries();
    while let Some((_, die)) = cursor
        .next_dfs()
        .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
    {
        let tag: gimli::DwTag = die.tag();
        if !is_type_relevant_tag(tag) {
            continue;
        }
        let offset: UnitOffset = die.offset();
        let mut name: Option<String> = None;
        let mut byte_size: Option<u64> = None;
        let mut type_ref: Option<UnitOffset> = None;
        let mut upper_bound: Option<u64> = None;
        let mut count: Option<u64> = None;
        let mut data_member_location: Option<u64> = None;
        let mut attrs: gimli::AttrsIter<'_, '_, '_, EndianSlice<'_, RunTimeEndian>> = die.attrs();
        while let Some(attr) = attrs
            .next()
            .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
        {
            match attr.name() {
                gimli::DW_AT_name => name = attr_to_string(dwarf, unit, &attr),
                gimli::DW_AT_byte_size => byte_size = attr.udata_value(),
                gimli::DW_AT_type => type_ref = attr_unit_ref(&attr),
                gimli::DW_AT_upper_bound => upper_bound = attr.udata_value(),
                gimli::DW_AT_count => count = attr.udata_value(),
                gimli::DW_AT_data_member_location => data_member_location = attr.udata_value(),
                _ => {}
            }
        }
        match tag {
            gimli::DW_TAG_member => attach_member(
                &mut entries,
                MemberDie {
                    name,
                    type_ref,
                    offset: data_member_location,
                },
            ),
            gimli::DW_TAG_template_type_parameter | gimli::DW_TAG_template_value_parameter => {
                attach_template_param(&mut entries, TemplateParamDie { name, type_ref });
            }
            gimli::DW_TAG_subrange_type => {
                attach_subrange(&mut entries, upper_bound, count);
            }
            _ => {
                entries.insert(
                    offset,
                    TypeDie {
                        tag,
                        name,
                        byte_size,
                        type_ref,
                        count,
                        members: Vec::new(),
                        template_params: Vec::new(),
                    },
                );
            }
        }
    }
    Ok(TypeDieIndex { entries })
}

fn attach_member(entries: &mut BTreeMap<UnitOffset, TypeDie>, member: MemberDie) {
    if let Some((_, parent)) = entries.iter_mut().next_back() {
        parent.members.push(member);
    }
}

fn attach_template_param(entries: &mut BTreeMap<UnitOffset, TypeDie>, param: TemplateParamDie) {
    if let Some((_, parent)) = entries.iter_mut().next_back() {
        parent.template_params.push(param);
    }
}

fn attach_subrange(
    entries: &mut BTreeMap<UnitOffset, TypeDie>,
    upper_bound: Option<u64>,
    count: Option<u64>,
) {
    if let Some((_, parent)) = entries.iter_mut().next_back()
        && parent.tag == gimli::DW_TAG_array_type
    {
        if let Some(c) = count {
            parent.count = Some(c);
        } else if let Some(ub) = upper_bound {
            parent.count = Some(ub.saturating_add(1));
        }
    }
}

const fn is_type_relevant_tag(tag: gimli::DwTag) -> bool {
    matches!(
        tag,
        gimli::DW_TAG_base_type
            | gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type
            | gimli::DW_TAG_structure_type
            | gimli::DW_TAG_class_type
            | gimli::DW_TAG_union_type
            | gimli::DW_TAG_enumeration_type
            | gimli::DW_TAG_array_type
            | gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_subroutine_type
            | gimli::DW_TAG_member
            | gimli::DW_TAG_subrange_type
            | gimli::DW_TAG_template_type_parameter
            | gimli::DW_TAG_template_value_parameter
    )
}

fn attr_unit_ref(attr: &gimli::Attribute<EndianSlice<'_, RunTimeEndian>>) -> Option<UnitOffset> {
    match attr.value() {
        gimli::AttributeValue::UnitRef(off) => Some(off),
        _ => None,
    }
}

fn render_named_type(index: &TypeDieIndex, offset: UnitOffset) -> ReconstructedType {
    let Some(die): Option<&TypeDie> = index.entries.get(&offset) else {
        return ReconstructedType {
            name: "<unresolved>".to_owned(),
            kind: TypeKind::Unspecified,
            byte_size: None,
            members: Vec::new(),
            template_params: Vec::new(),
        };
    };
    let kind: TypeKind = tag_to_kind(die.tag);
    let name: String = render_type_ref(index, Some(offset), 0);
    let members: Vec<TypeMember> = die
        .members
        .iter()
        .map(|m: &MemberDie| TypeMember {
            name: m.name.clone().unwrap_or_else(|| "<anon>".to_owned()),
            type_name: render_type_ref(index, m.type_ref, 0),
            offset: m.offset,
        })
        .collect();
    let template_params: Vec<String> = die
        .template_params
        .iter()
        .map(|p: &TemplateParamDie| render_template_param(index, p, 0))
        .collect();
    ReconstructedType {
        name,
        kind,
        byte_size: die.byte_size,
        members,
        template_params,
    }
}

fn render_type_ref(index: &TypeDieIndex, type_ref: Option<UnitOffset>, depth: u32) -> String {
    if depth >= TYPE_RESOLVE_MAX_DEPTH {
        return "<recursion-limit>".to_owned();
    }
    let Some(off): Option<UnitOffset> = type_ref else {
        return "void".to_owned();
    };
    let Some(die): Option<&TypeDie> = index.entries.get(&off) else {
        return "<unresolved>".to_owned();
    };
    match die.tag {
        gimli::DW_TAG_base_type => die.name.clone().unwrap_or_else(|| "<anon>".to_owned()),
        gimli::DW_TAG_pointer_type => {
            format!("{} *", render_type_ref(index, die.type_ref, depth + 1))
        }
        gimli::DW_TAG_reference_type => {
            format!("{} &", render_type_ref(index, die.type_ref, depth + 1))
        }
        gimli::DW_TAG_rvalue_reference_type => {
            format!("{} &&", render_type_ref(index, die.type_ref, depth + 1))
        }
        gimli::DW_TAG_const_type => {
            format!("const {}", render_type_ref(index, die.type_ref, depth + 1))
        }
        gimli::DW_TAG_volatile_type => {
            format!(
                "volatile {}",
                render_type_ref(index, die.type_ref, depth + 1)
            )
        }
        gimli::DW_TAG_restrict_type => render_type_ref(index, die.type_ref, depth + 1),
        gimli::DW_TAG_array_type => {
            let elem: String = render_type_ref(index, die.type_ref, depth + 1);
            die.count
                .map_or_else(|| format!("{elem} []"), |n: u64| format!("{elem} [{n}]"))
        }
        gimli::DW_TAG_typedef => die
            .name
            .clone()
            .unwrap_or_else(|| render_type_ref(index, die.type_ref, depth + 1)),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => {
            render_composite(index, die, "struct", depth)
        }
        gimli::DW_TAG_union_type => render_composite(index, die, "union", depth),
        gimli::DW_TAG_enumeration_type => die.name.as_ref().map_or_else(
            || "enum <anon>".to_owned(),
            |n: &String| format!("enum {n}"),
        ),
        gimli::DW_TAG_subroutine_type => "fn(...)".to_owned(),
        _ => die.name.clone().unwrap_or_else(|| "<anon>".to_owned()),
    }
}

fn render_composite(index: &TypeDieIndex, die: &TypeDie, keyword: &str, depth: u32) -> String {
    let base: String = die.name.as_ref().map_or_else(
        || format!("{keyword} <anon>"),
        |n: &String| format!("{keyword} {n}"),
    );
    if die.template_params.is_empty() {
        return base;
    }
    let params: Vec<String> = die
        .template_params
        .iter()
        .map(|p: &TemplateParamDie| render_template_param(index, p, depth + 1))
        .collect();
    format!("{base}<{}>", params.join(", "))
}

fn render_template_param(index: &TypeDieIndex, param: &TemplateParamDie, depth: u32) -> String {
    match param.type_ref {
        Some(_) => render_type_ref(index, param.type_ref, depth),
        None => param.name.clone().unwrap_or_else(|| "<param>".to_owned()),
    }
}

const fn tag_to_kind(tag: gimli::DwTag) -> TypeKind {
    match tag {
        gimli::DW_TAG_pointer_type => TypeKind::Pointer,
        gimli::DW_TAG_reference_type | gimli::DW_TAG_rvalue_reference_type => TypeKind::Reference,
        gimli::DW_TAG_structure_type => TypeKind::Structure,
        gimli::DW_TAG_class_type => TypeKind::Class,
        gimli::DW_TAG_union_type => TypeKind::Union,
        gimli::DW_TAG_enumeration_type => TypeKind::Enumeration,
        gimli::DW_TAG_array_type => TypeKind::Array,
        gimli::DW_TAG_typedef => TypeKind::Typedef,
        gimli::DW_TAG_const_type => TypeKind::Const,
        gimli::DW_TAG_volatile_type => TypeKind::Volatile,
        gimli::DW_TAG_subroutine_type => TypeKind::Subroutine,
        gimli::DW_TAG_base_type => TypeKind::Base,
        _ => TypeKind::Unspecified,
    }
}

fn collect_dwo_name(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    out: &mut Vec<String>,
) -> Result<()> {
    let mut entries: gimli::EntriesCursor<'_, '_, EndianSlice<'_, RunTimeEndian>> = unit.entries();
    if let Some((_, root)) = entries
        .next_dfs()
        .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
    {
        let mut attrs: gimli::AttrsIter<'_, '_, '_, EndianSlice<'_, RunTimeEndian>> = root.attrs();
        while let Some(attr) = attrs
            .next()
            .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
        {
            if (attr.name() == gimli::DW_AT_dwo_name || attr.name() == gimli::DW_AT_GNU_dwo_name)
                && let Some(name) = attr_to_string(dwarf, unit, &attr)
            {
                out.push(name);
            }
        }
    }
    Ok(())
}

fn recover_compile_unit(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    unit_offset: u64,
) -> Result<CompileUnit> {
    let mut entries: gimli::EntriesCursor<'_, '_, EndianSlice<'_, RunTimeEndian>> = unit.entries();
    let dwarf_version: u16 = unit.header.version();
    let mut name: Option<String> = None;
    let mut comp_dir: Option<String> = None;
    let mut producer: Option<String> = None;
    let mut low_pc: Option<u64> = None;
    if let Some((_, root)) = entries
        .next_dfs()
        .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
    {
        let mut attrs: gimli::AttrsIter<'_, '_, '_, EndianSlice<'_, RunTimeEndian>> = root.attrs();
        while let Some(attr) = attrs
            .next()
            .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
        {
            match attr.name() {
                gimli::DW_AT_name => name = attr_to_string(dwarf, unit, &attr),
                gimli::DW_AT_comp_dir => comp_dir = attr_to_string(dwarf, unit, &attr),
                gimli::DW_AT_producer => producer = attr_to_string(dwarf, unit, &attr),
                gimli::DW_AT_low_pc => {
                    if let gimli::AttributeValue::Addr(a) = attr.value() {
                        low_pc = Some(a);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(CompileUnit {
        name,
        comp_dir,
        producer,
        low_pc,
        unit_offset,
        dwarf_version,
    })
}

fn attr_to_string(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    attr: &gimli::Attribute<EndianSlice<'_, RunTimeEndian>>,
) -> Option<String> {
    let slice: EndianSlice<'_, RunTimeEndian> = dwarf.attr_string(unit, attr.value()).ok()?;
    let bytes: &[u8] = slice.slice();
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn collect_line_rows(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    out: &mut Vec<LineRow>,
) -> Result<()> {
    let Some(program): Option<gimli::IncompleteLineProgram<EndianSlice<'_, RunTimeEndian>>> =
        unit.line_program.clone()
    else {
        return Ok(());
    };
    let mut rows: gimli::LineRows<
        EndianSlice<'_, RunTimeEndian>,
        gimli::IncompleteLineProgram<EndianSlice<'_, RunTimeEndian>>,
        usize,
    > = program.rows();
    while let Some((header, row)) = rows
        .next_row()
        .map_err(|e: gimli::Error| Error::Dwarf(e.to_string()))?
    {
        if row.end_sequence() {
            continue;
        }
        let file: String = resolve_file(dwarf, unit, header, row);
        let line: u32 = row
            .line()
            .map_or(0, |l: std::num::NonZeroU64| l.get() as u32);
        let column: u32 = match row.column() {
            gimli::ColumnType::LeftEdge => 0,
            gimli::ColumnType::Column(c) => c.get() as u32,
        };
        out.push(LineRow {
            pc: row.address(),
            file,
            line,
            column,
        });
    }
    Ok(())
}

fn resolve_file(
    dwarf: &Dwarf<EndianSlice<'_, RunTimeEndian>>,
    unit: &gimli::Unit<EndianSlice<'_, RunTimeEndian>>,
    header: &gimli::LineProgramHeader<EndianSlice<'_, RunTimeEndian>>,
    row: &gimli::LineRow,
) -> String {
    let Some(file): Option<&gimli::FileEntry<EndianSlice<'_, RunTimeEndian>>> = row.file(header)
    else {
        return String::new();
    };
    let mut path: String = String::new();
    if let Some(dir) = file.directory(header)
        && let Ok(slice) = dwarf.attr_string(unit, dir)
    {
        path.push_str(&String::from_utf8_lossy(slice.slice()));
        path.push('/');
    }
    if let Ok(slice) = dwarf.attr_string(unit, file.path_name()) {
        path.push_str(&String::from_utf8_lossy(slice.slice()));
    }
    path
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_object_input() {
        let err: Error = synthesize_dwarf_sourcemap(b"not an object file").unwrap_err();
        assert!(matches!(err, Error::UnknownFormat));
    }

    #[test]
    fn sourcemap_json_shape_is_v3_compatible() {
        let map: DwarfSourcemap = DwarfSourcemap {
            compile_units: vec![CompileUnit {
                name: Some("main.zig".to_owned()),
                comp_dir: Some("/src".to_owned()),
                producer: Some("zig 0.13".to_owned()),
                low_pc: Some(0x1000),
                unit_offset: 0,
                dwarf_version: 5,
            }],
            line_rows: vec![LineRow {
                pc: 0x1000,
                file: "/src/main.zig".to_owned(),
                line: 42,
                column: 5,
            }],
        };
        let json: serde_json::Value = map.to_sourcemap_json();
        assert_eq!(json["version"], 1);
        assert_eq!(json["line_entries"], 1);
        assert_eq!(json["compile_units"][0]["name"], "main.zig");
        assert_eq!(json["line_map"][0]["line"], 42);
    }

    #[test]
    fn empty_map_is_empty() {
        let map: DwarfSourcemap = DwarfSourcemap {
            compile_units: Vec::new(),
            line_rows: Vec::new(),
        };
        assert!(map.is_empty());
    }

    fn off(n: usize) -> UnitOffset {
        UnitOffset(n)
    }

    fn base(name: &str) -> TypeDie {
        TypeDie {
            tag: gimli::DW_TAG_base_type,
            name: Some(name.to_owned()),
            byte_size: Some(4),
            type_ref: None,
            count: None,
            members: Vec::new(),
            template_params: Vec::new(),
        }
    }

    fn derived(tag: gimli::DwTag, type_ref: Option<UnitOffset>, count: Option<u64>) -> TypeDie {
        TypeDie {
            tag,
            name: None,
            byte_size: None,
            type_ref,
            count,
            members: Vec::new(),
            template_params: Vec::new(),
        }
    }

    #[test]
    fn renders_pointer_and_const_and_array_chains() {
        let mut entries: BTreeMap<UnitOffset, TypeDie> = BTreeMap::new();
        entries.insert(off(1), base("int"));
        entries.insert(
            off(2),
            derived(gimli::DW_TAG_pointer_type, Some(off(1)), None),
        );
        entries.insert(
            off(3),
            derived(gimli::DW_TAG_const_type, Some(off(1)), None),
        );
        entries.insert(
            off(4),
            derived(gimli::DW_TAG_array_type, Some(off(1)), Some(16)),
        );
        let index: TypeDieIndex = TypeDieIndex { entries };
        assert_eq!(render_type_ref(&index, Some(off(2)), 0), "int *");
        assert_eq!(render_type_ref(&index, Some(off(3)), 0), "const int");
        assert_eq!(render_type_ref(&index, Some(off(4)), 0), "int [16]");
        assert_eq!(render_type_ref(&index, None, 0), "void");
    }

    #[test]
    fn renders_generic_struct_with_template_params() {
        let mut entries: BTreeMap<UnitOffset, TypeDie> = BTreeMap::new();
        entries.insert(off(1), base("u8"));
        let mut composite: TypeDie = TypeDie {
            tag: gimli::DW_TAG_structure_type,
            name: Some("Vec".to_owned()),
            byte_size: Some(24),
            type_ref: None,
            count: None,
            members: Vec::new(),
            template_params: vec![TemplateParamDie {
                name: Some("T".to_owned()),
                type_ref: Some(off(1)),
            }],
        };
        let off2: UnitOffset = off(2);
        entries.insert(off2, composite.clone());
        let index: TypeDieIndex = TypeDieIndex { entries };
        assert_eq!(render_type_ref(&index, Some(off2), 0), "struct Vec<u8>");
        composite.template_params[0].type_ref = None;
        let mut e2: BTreeMap<UnitOffset, TypeDie> = BTreeMap::new();
        e2.insert(off2, composite);
        let i2: TypeDieIndex = TypeDieIndex { entries: e2 };
        assert_eq!(render_type_ref(&i2, Some(off2), 0), "struct Vec<T>");
    }

    #[test]
    fn render_type_ref_terminates_on_cycle() {
        let mut entries: BTreeMap<UnitOffset, TypeDie> = BTreeMap::new();
        entries.insert(
            off(1),
            derived(gimli::DW_TAG_pointer_type, Some(off(2)), None),
        );
        entries.insert(
            off(2),
            derived(gimli::DW_TAG_pointer_type, Some(off(1)), None),
        );
        let index: TypeDieIndex = TypeDieIndex { entries };
        let rendered: String = render_type_ref(&index, Some(off(1)), 0);
        assert!(
            rendered.contains("<recursion-limit>"),
            "a self-referential pointer cycle must hit the depth guard, got {rendered}",
        );
    }

    #[test]
    fn merge_ranges_len_unions_overlaps() {
        let mut ranges: Vec<(u64, u64)> = vec![(0, 10), (5, 20), (30, 40)];
        assert_eq!(merge_ranges_len(&mut ranges), 30);
        let mut empty: Vec<(u64, u64)> = Vec::new();
        assert_eq!(merge_ranges_len(&mut empty), 0);
        let mut touching: Vec<(u64, u64)> = vec![(0, 10), (10, 20)];
        assert_eq!(merge_ranges_len(&mut touching), 20);
    }

    #[test]
    fn coverage_pct_and_ratio_are_bounded() {
        let cov: CoverageScore = CoverageScore {
            text_size: 200,
            covered_bytes: 150,
        };
        assert!((cov.pct() - 75.0).abs() < f64::EPSILON);
        let zero: CoverageScore = CoverageScore {
            text_size: 0,
            covered_bytes: 0,
        };
        assert!((zero.pct() - 0.0).abs() < f64::EPSILON);
    }
}
