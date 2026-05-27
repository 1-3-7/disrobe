use std::collections::BTreeMap;

use gimli::{
    AttributeValue, DebuggingInformationEntry, DwLang, Dwarf, EndianSlice, Reader, RunTimeEndian,
    Unit, UnitOffset,
};

use crate::dwarf::parse::DwarfSections;
use crate::error::{Error, Result};

pub type Endian = RunTimeEndian;
pub type Slice<'a> = EndianSlice<'a, Endian>;

#[derive(Debug, Default, Clone)]
pub struct CompileUnitInfo {
    pub producer: Option<String>,
    pub name: Option<String>,
    pub comp_dir: Option<String>,
    pub language: Option<String>,
    pub low_pc: Option<u64>,
    pub high_pc: Option<u64>,
    pub unit_offset: u64,
}

#[derive(Debug, Default, Clone)]
pub struct RawSubprogram {
    pub name: Option<String>,
    pub linkage_name: Option<String>,
    pub low_pc: Option<u64>,
    pub high_pc: Option<u64>,
    pub decl_file_index: Option<u64>,
    pub decl_line: Option<u32>,
    pub return_type_offset: Option<u64>,
    pub parameters: Vec<RawParameter>,
    pub variables: Vec<RawVariable>,
    pub die_offset: u64,
    pub unit_offset: u64,
}

#[derive(Debug, Default, Clone)]
pub struct RawParameter {
    pub name: Option<String>,
    pub type_offset: Option<u64>,
    pub decl_line: Option<u32>,
}

#[derive(Debug, Default, Clone)]
pub struct RawVariable {
    pub name: Option<String>,
    pub type_offset: Option<u64>,
    pub decl_line: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct UnitBundle {
    pub compile_unit: CompileUnitInfo,
    pub subprograms: Vec<RawSubprogram>,
    pub type_dies: BTreeMap<u64, RawTypeDie>,
}

#[derive(Debug, Clone)]
pub enum RawTypeDie {
    Base {
        name: Option<String>,
        encoding: Option<u16>,
        byte_size: Option<u64>,
    },
    Pointer {
        target_type_offset: Option<u64>,
        byte_size: Option<u64>,
    },
    Reference {
        target_type_offset: Option<u64>,
    },
    Const {
        target_type_offset: Option<u64>,
    },
    Volatile {
        target_type_offset: Option<u64>,
    },
    Typedef {
        name: Option<String>,
        target_type_offset: Option<u64>,
    },
    Structure {
        name: Option<String>,
        byte_size: Option<u64>,
        members: Vec<RawMember>,
    },
    Union {
        name: Option<String>,
        byte_size: Option<u64>,
        members: Vec<RawMember>,
    },
    Class {
        name: Option<String>,
        byte_size: Option<u64>,
        members: Vec<RawMember>,
    },
    Array {
        element_type_offset: Option<u64>,
        element_count: Option<u64>,
    },
    Enumeration {
        name: Option<String>,
        byte_size: Option<u64>,
        variants: BTreeMap<i64, String>,
    },
    Subroutine {
        return_type_offset: Option<u64>,
        parameters: Vec<RawParameter>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct RawMember {
    pub name: Option<String>,
    pub type_offset: Option<u64>,
    pub byte_offset: Option<u64>,
    pub bit_size: Option<u64>,
}

pub fn load_dwarf(sections: &DwarfSections) -> Result<Dwarf<Slice<'_>>> {
    let endian: Endian = RunTimeEndian::Little;
    let load = |section: gimli::SectionId| -> core::result::Result<Slice<'_>, gimli::Error> {
        let data: &[u8] = match section {
            gimli::SectionId::DebugInfo => &sections.info,
            gimli::SectionId::DebugAbbrev => &sections.abbrev,
            gimli::SectionId::DebugLine => &sections.line,
            gimli::SectionId::DebugStr => &sections.str_,
            gimli::SectionId::DebugStrOffsets => &sections.str_offsets,
            gimli::SectionId::DebugLineStr => &sections.line_str,
            gimli::SectionId::DebugRanges => &sections.ranges,
            gimli::SectionId::DebugRngLists => &sections.rnglists,
            gimli::SectionId::DebugPubNames => &sections.pubnames,
            gimli::SectionId::DebugPubTypes => &sections.pubtypes,
            gimli::SectionId::DebugAddr => &sections.addr,
            gimli::SectionId::DebugLoc => &sections.loc,
            gimli::SectionId::DebugLocLists => &sections.loclists,
            gimli::SectionId::DebugAranges => &sections.aranges,
            _ => &[],
        };
        Ok(EndianSlice::new(data, endian))
    };
    Dwarf::load(load).map_err(|e| Error::Parse(format!("dwarf load: {e}")))
}

pub fn walk_units(dwarf: &Dwarf<Slice<'_>>) -> Result<Vec<UnitBundle>> {
    let mut bundles: Vec<UnitBundle> = Vec::new();
    let mut iter: gimli::DebugInfoUnitHeadersIter<Slice<'_>> = dwarf.units();
    while let Some(header) = iter.next().map_err(map_gimli_err)? {
        let unit: Unit<Slice<'_>> = dwarf.unit(header).map_err(map_gimli_err)?;
        let unit_offset: u64 = match unit.header.offset() {
            gimli::UnitSectionOffset::DebugInfoOffset(offset) => offset.0 as u64,
            gimli::UnitSectionOffset::DebugTypesOffset(offset) => offset.0 as u64,
        };
        let bundle: UnitBundle = walk_unit(dwarf, &unit, unit_offset)?;
        bundles.push(bundle);
    }
    let mut types_iter: gimli::DebugTypesUnitHeadersIter<Slice<'_>> = dwarf.type_units();
    while let Some(header) = types_iter.next().map_err(map_gimli_err)? {
        let unit: Unit<Slice<'_>> = dwarf.unit(header).map_err(map_gimli_err)?;
        let unit_offset: u64 = match unit.header.offset() {
            gimli::UnitSectionOffset::DebugInfoOffset(offset) => offset.0 as u64,
            gimli::UnitSectionOffset::DebugTypesOffset(offset) => offset.0 as u64,
        };
        let bundle: UnitBundle = walk_unit(dwarf, &unit, unit_offset)?;
        bundles.push(bundle);
    }
    Ok(bundles)
}

fn walk_unit(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    unit_offset: u64,
) -> Result<UnitBundle> {
    let mut compile_unit: CompileUnitInfo = CompileUnitInfo {
        unit_offset,
        ..CompileUnitInfo::default()
    };
    let mut subprograms: Vec<RawSubprogram> = Vec::new();
    let mut type_dies: BTreeMap<u64, RawTypeDie> = BTreeMap::new();

    let mut entries: gimli::EntriesCursor<'_, '_, Slice<'_>> = unit.entries();
    while let Some((_, entry)) = entries.next_dfs().map_err(map_gimli_err)? {
        match entry.tag() {
            gimli::DW_TAG_compile_unit => {
                fill_compile_unit(dwarf, unit, entry, &mut compile_unit)?;
            }
            gimli::DW_TAG_subprogram => {
                if let Some(sub) = build_subprogram(dwarf, unit, entry, unit_offset)? {
                    subprograms.push(sub);
                }
            }
            gimli::DW_TAG_base_type => {
                let offset: u64 = entry.offset().to_unit_section_offset(unit).to_raw_offset();
                if let Some(die) = build_base_type(dwarf, unit, entry)? {
                    type_dies.insert(offset, die);
                }
            }
            gimli::DW_TAG_pointer_type => {
                let offset: u64 = entry.offset().to_unit_section_offset(unit).to_raw_offset();
                type_dies.insert(offset, build_pointer_type(unit, entry)?);
            }
            gimli::DW_TAG_reference_type | gimli::DW_TAG_rvalue_reference_type => {
                let offset: u64 = entry.offset().to_unit_section_offset(unit).to_raw_offset();
                type_dies.insert(
                    offset,
                    RawTypeDie::Reference {
                        target_type_offset: read_type_ref(unit, entry, gimli::DW_AT_type)?,
                    },
                );
            }
            gimli::DW_TAG_const_type => {
                let offset: u64 = entry.offset().to_unit_section_offset(unit).to_raw_offset();
                type_dies.insert(
                    offset,
                    RawTypeDie::Const {
                        target_type_offset: read_type_ref(unit, entry, gimli::DW_AT_type)?,
                    },
                );
            }
            gimli::DW_TAG_volatile_type => {
                let offset: u64 = entry.offset().to_unit_section_offset(unit).to_raw_offset();
                type_dies.insert(
                    offset,
                    RawTypeDie::Volatile {
                        target_type_offset: read_type_ref(unit, entry, gimli::DW_AT_type)?,
                    },
                );
            }
            gimli::DW_TAG_typedef => {
                let offset: u64 = entry.offset().to_unit_section_offset(unit).to_raw_offset();
                type_dies.insert(
                    offset,
                    RawTypeDie::Typedef {
                        name: read_name(dwarf, unit, entry)?,
                        target_type_offset: read_type_ref(unit, entry, gimli::DW_AT_type)?,
                    },
                );
            }
            _ => {}
        }
    }

    let aggregate_offsets: Vec<(UnitOffset, gimli::DwTag)> = collect_aggregate_offsets(unit)?;
    for (offset, tag) in aggregate_offsets {
        let raw_offset: u64 = offset.to_unit_section_offset(unit).to_raw_offset();
        let aggregate: RawTypeDie = build_aggregate_type(dwarf, unit, offset, tag)?;
        type_dies.insert(raw_offset, aggregate);
    }

    Ok(UnitBundle {
        compile_unit,
        subprograms,
        type_dies,
    })
}

fn collect_aggregate_offsets(unit: &Unit<Slice<'_>>) -> Result<Vec<(UnitOffset, gimli::DwTag)>> {
    let mut out: Vec<(UnitOffset, gimli::DwTag)> = Vec::new();
    let mut entries: gimli::EntriesCursor<'_, '_, Slice<'_>> = unit.entries();
    while let Some((_, entry)) = entries.next_dfs().map_err(map_gimli_err)? {
        match entry.tag() {
            gimli::DW_TAG_structure_type
            | gimli::DW_TAG_union_type
            | gimli::DW_TAG_class_type
            | gimli::DW_TAG_array_type
            | gimli::DW_TAG_enumeration_type
            | gimli::DW_TAG_subroutine_type => {
                out.push((entry.offset(), entry.tag()));
            }
            _ => {}
        }
    }
    Ok(out)
}

fn build_aggregate_type(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    offset: UnitOffset,
    tag: gimli::DwTag,
) -> Result<RawTypeDie> {
    let mut tree: gimli::EntriesTree<'_, '_, Slice<'_>> =
        unit.entries_tree(Some(offset)).map_err(map_gimli_err)?;
    let root: gimli::EntriesTreeNode<'_, '_, '_, Slice<'_>> = tree.root().map_err(map_gimli_err)?;
    let entry: &DebuggingInformationEntry<'_, '_, Slice<'_>> = root.entry();
    let name: Option<String> = read_name(dwarf, unit, entry)?;
    let byte_size: Option<u64> = read_byte_size(entry)?;

    match tag {
        gimli::DW_TAG_array_type => {
            let element_type_offset: Option<u64> = read_type_ref(unit, entry, gimli::DW_AT_type)?;
            let mut element_count: Option<u64> = None;
            let mut children = root.children();
            while let Some(child_node) = children.next().map_err(map_gimli_err)? {
                if child_node.entry().tag() == gimli::DW_TAG_subrange_type
                    && let Some(c) = read_subrange_count(child_node.entry())?
                {
                    element_count = Some(c);
                }
            }
            Ok(RawTypeDie::Array {
                element_type_offset,
                element_count,
            })
        }
        gimli::DW_TAG_enumeration_type => {
            let mut variants: BTreeMap<i64, String> = BTreeMap::new();
            let mut children = root.children();
            while let Some(child_node) = children.next().map_err(map_gimli_err)? {
                let child_entry: &DebuggingInformationEntry<'_, '_, Slice<'_>> = child_node.entry();
                if child_entry.tag() == gimli::DW_TAG_enumerator
                    && let (Some(value), Some(variant_name)) = (
                        read_const_value(child_entry)?,
                        read_name(dwarf, unit, child_entry)?,
                    )
                {
                    variants.insert(value, variant_name);
                }
            }
            Ok(RawTypeDie::Enumeration {
                name,
                byte_size,
                variants,
            })
        }
        gimli::DW_TAG_subroutine_type => {
            let return_type_offset: Option<u64> = read_type_ref(unit, entry, gimli::DW_AT_type)?;
            let mut parameters: Vec<RawParameter> = Vec::new();
            let mut children = root.children();
            while let Some(child_node) = children.next().map_err(map_gimli_err)? {
                if child_node.entry().tag() == gimli::DW_TAG_formal_parameter {
                    parameters.push(build_parameter(dwarf, unit, child_node.entry())?);
                }
            }
            Ok(RawTypeDie::Subroutine {
                return_type_offset,
                parameters,
            })
        }
        _ => {
            let mut members: Vec<RawMember> = Vec::new();
            let mut children = root.children();
            while let Some(child_node) = children.next().map_err(map_gimli_err)? {
                if child_node.entry().tag() == gimli::DW_TAG_member {
                    members.push(build_member(dwarf, unit, child_node.entry())?);
                }
            }
            Ok(match tag {
                gimli::DW_TAG_structure_type => RawTypeDie::Structure {
                    name,
                    byte_size,
                    members,
                },
                gimli::DW_TAG_union_type => RawTypeDie::Union {
                    name,
                    byte_size,
                    members,
                },
                gimli::DW_TAG_class_type => RawTypeDie::Class {
                    name,
                    byte_size,
                    members,
                },
                _ => unreachable!("aggregate tag handled above"),
            })
        }
    }
}

fn fill_compile_unit(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>,
    out: &mut CompileUnitInfo,
) -> Result<()> {
    out.producer = read_string_attr(dwarf, unit, entry, gimli::DW_AT_producer)?;
    out.name = read_string_attr(dwarf, unit, entry, gimli::DW_AT_name)?;
    out.comp_dir = read_string_attr(dwarf, unit, entry, gimli::DW_AT_comp_dir)?;
    out.language = read_language(entry)?;
    out.low_pc = read_address(entry, gimli::DW_AT_low_pc)?;
    out.high_pc = read_high_pc(entry, out.low_pc)?;
    Ok(())
}

fn build_subprogram(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>,
    unit_offset: u64,
) -> Result<Option<RawSubprogram>> {
    let name: Option<String> = read_string_attr(dwarf, unit, entry, gimli::DW_AT_name)?;
    let linkage_name: Option<String> =
        read_string_attr(dwarf, unit, entry, gimli::DW_AT_linkage_name)?;
    let low_pc: Option<u64> = read_address(entry, gimli::DW_AT_low_pc)?;
    let high_pc: Option<u64> = read_high_pc(entry, low_pc)?;
    let decl_file_index: Option<u64> = read_unsigned(entry, gimli::DW_AT_decl_file)?;
    let decl_line: Option<u32> =
        read_unsigned(entry, gimli::DW_AT_decl_line)?.and_then(|v: u64| u32::try_from(v).ok());
    let return_type_offset: Option<u64> = read_type_ref(unit, entry, gimli::DW_AT_type)?;
    let die_offset: u64 = entry.offset().to_unit_section_offset(unit).to_raw_offset();

    let mut parameters: Vec<RawParameter> = Vec::new();
    let mut variables: Vec<RawVariable> = Vec::new();
    let mut tree: gimli::EntriesTree<'_, '_, Slice<'_>> = unit
        .entries_tree(Some(entry.offset()))
        .map_err(map_gimli_err)?;
    let root: gimli::EntriesTreeNode<'_, '_, '_, Slice<'_>> = tree.root().map_err(map_gimli_err)?;
    let mut children = root.children();
    while let Some(child_node) = children.next().map_err(map_gimli_err)? {
        let child_entry: &DebuggingInformationEntry<'_, '_, Slice<'_>> = child_node.entry();
        match child_entry.tag() {
            gimli::DW_TAG_formal_parameter => {
                parameters.push(build_parameter(dwarf, unit, child_entry)?);
            }
            gimli::DW_TAG_variable => {
                variables.push(build_variable(dwarf, unit, child_entry)?);
            }
            _ => {}
        }
    }

    Ok(Some(RawSubprogram {
        name,
        linkage_name,
        low_pc,
        high_pc,
        decl_file_index,
        decl_line,
        return_type_offset,
        parameters,
        variables,
        die_offset,
        unit_offset,
    }))
}

fn build_parameter(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Result<RawParameter> {
    Ok(RawParameter {
        name: read_name(dwarf, unit, entry)?,
        type_offset: read_type_ref(unit, entry, gimli::DW_AT_type)?,
        decl_line: read_unsigned(entry, gimli::DW_AT_decl_line)?
            .and_then(|v: u64| u32::try_from(v).ok()),
    })
}

fn build_variable(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Result<RawVariable> {
    Ok(RawVariable {
        name: read_name(dwarf, unit, entry)?,
        type_offset: read_type_ref(unit, entry, gimli::DW_AT_type)?,
        decl_line: read_unsigned(entry, gimli::DW_AT_decl_line)?
            .and_then(|v: u64| u32::try_from(v).ok()),
    })
}

fn build_member(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Result<RawMember> {
    Ok(RawMember {
        name: read_name(dwarf, unit, entry)?,
        type_offset: read_type_ref(unit, entry, gimli::DW_AT_type)?,
        byte_offset: read_unsigned(entry, gimli::DW_AT_data_member_location)?,
        bit_size: read_unsigned(entry, gimli::DW_AT_bit_size)?,
    })
}

fn build_base_type(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Result<Option<RawTypeDie>> {
    let name: Option<String> = read_string_attr(dwarf, unit, entry, gimli::DW_AT_name)?;
    let encoding: Option<u16> = entry
        .attr_value(gimli::DW_AT_encoding)
        .map_err(map_gimli_err)?
        .and_then(|v: AttributeValue<Slice<'_>>| match v {
            AttributeValue::Encoding(e) => Some(u16::from(e.0)),
            _ => None,
        });
    let byte_size: Option<u64> = read_byte_size(entry)?;
    Ok(Some(RawTypeDie::Base {
        name,
        encoding,
        byte_size,
    }))
}

fn build_pointer_type(
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Result<RawTypeDie> {
    Ok(RawTypeDie::Pointer {
        target_type_offset: read_type_ref(unit, entry, gimli::DW_AT_type)?,
        byte_size: read_byte_size(entry)?,
    })
}

fn read_subrange_count(
    entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Result<Option<u64>> {
    if let Some(count) = read_unsigned(entry, gimli::DW_AT_count)? {
        return Ok(Some(count));
    }
    if let Some(upper) = read_unsigned(entry, gimli::DW_AT_upper_bound)? {
        return Ok(Some(upper.saturating_add(1)));
    }
    Ok(None)
}

fn read_const_value(entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>) -> Result<Option<i64>> {
    let Some(value): Option<AttributeValue<Slice<'_>>> = entry
        .attr_value(gimli::DW_AT_const_value)
        .map_err(map_gimli_err)?
    else {
        return Ok(None);
    };
    Ok(match value {
        AttributeValue::Sdata(v) => Some(v),
        AttributeValue::Udata(v) | AttributeValue::Data8(v) => i64::try_from(v).ok(),
        AttributeValue::Data1(v) => Some(i64::from(v)),
        AttributeValue::Data2(v) => Some(i64::from(v)),
        AttributeValue::Data4(v) => Some(i64::from(v)),
        _ => None,
    })
}

fn read_byte_size(entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>) -> Result<Option<u64>> {
    read_unsigned(entry, gimli::DW_AT_byte_size)
}

fn read_name<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<'_, '_, R>,
) -> Result<Option<String>> {
    read_string_attr(dwarf, unit, entry, gimli::DW_AT_name)
}

fn read_string_attr<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<'_, '_, R>,
    name: gimli::DwAt,
) -> Result<Option<String>> {
    let Some(value): Option<AttributeValue<R>> = entry.attr_value(name).map_err(map_gimli_err)?
    else {
        return Ok(None);
    };
    let bytes: R = dwarf.attr_string(unit, value).map_err(map_gimli_err)?;
    let s: String = Reader::to_string_lossy(&bytes)
        .map_err(map_gimli_err)?
        .into_owned();
    Ok(Some(s))
}

fn read_address(
    entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>,
    name: gimli::DwAt,
) -> Result<Option<u64>> {
    let Some(value): Option<AttributeValue<Slice<'_>>> =
        entry.attr_value(name).map_err(map_gimli_err)?
    else {
        return Ok(None);
    };
    Ok(match value {
        AttributeValue::Addr(a) => Some(a),
        AttributeValue::Udata(u) => Some(u),
        _ => None,
    })
}

fn read_high_pc(
    entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>,
    low_pc: Option<u64>,
) -> Result<Option<u64>> {
    let Some(value): Option<AttributeValue<Slice<'_>>> = entry
        .attr_value(gimli::DW_AT_high_pc)
        .map_err(map_gimli_err)?
    else {
        return Ok(None);
    };
    Ok(match value {
        AttributeValue::Addr(a) => Some(a),
        AttributeValue::Udata(u) => low_pc.map(|base: u64| base.saturating_add(u)),
        _ => None,
    })
}

fn read_unsigned(
    entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>,
    name: gimli::DwAt,
) -> Result<Option<u64>> {
    let Some(value): Option<AttributeValue<Slice<'_>>> =
        entry.attr_value(name).map_err(map_gimli_err)?
    else {
        return Ok(None);
    };
    Ok(match value {
        AttributeValue::Udata(u) | AttributeValue::Data8(u) | AttributeValue::FileIndex(u) => {
            Some(u)
        }
        AttributeValue::Data1(u) => Some(u64::from(u)),
        AttributeValue::Data2(u) => Some(u64::from(u)),
        AttributeValue::Data4(u) => Some(u64::from(u)),
        AttributeValue::Sdata(s) => u64::try_from(s).ok(),
        _ => None,
    })
}

fn read_type_ref(
    unit: &Unit<Slice<'_>>,
    entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>,
    name: gimli::DwAt,
) -> Result<Option<u64>> {
    let Some(value): Option<AttributeValue<Slice<'_>>> =
        entry.attr_value(name).map_err(map_gimli_err)?
    else {
        return Ok(None);
    };
    Ok(match value {
        AttributeValue::UnitRef(offset) => {
            Some(UnitOffset::to_unit_section_offset(&offset, unit).to_raw_offset())
        }
        AttributeValue::DebugInfoRef(offset) | AttributeValue::DebugInfoRefSup(offset) => {
            Some(offset.0 as u64)
        }
        _ => None,
    })
}

fn read_language(entry: &DebuggingInformationEntry<'_, '_, Slice<'_>>) -> Result<Option<String>> {
    let Some(value): Option<AttributeValue<Slice<'_>>> = entry
        .attr_value(gimli::DW_AT_language)
        .map_err(map_gimli_err)?
    else {
        return Ok(None);
    };
    let lang: DwLang = match value {
        AttributeValue::Language(l) => l,
        _ => return Ok(None),
    };
    Ok(Some(format!("{lang}")))
}

trait UnitSectionOffsetExt {
    fn to_raw_offset(self) -> u64;
}

impl UnitSectionOffsetExt for gimli::UnitSectionOffset<usize> {
    #[inline]
    fn to_raw_offset(self) -> u64 {
        match self {
            Self::DebugInfoOffset(o) => o.0 as u64,
            Self::DebugTypesOffset(o) => o.0 as u64,
        }
    }
}

#[inline]
fn map_gimli_err(err: gimli::Error) -> Error {
    Error::Parse(format!("dwarf: {err}"))
}
