use std::collections::BTreeSet;
use std::ops::Range;

use crate::classfile::ClassFile;
use crate::dex::{DEX_NO_INDEX, DexVersion, parse_header, parse_string_data};
use crate::error::{Error, Result};

const ACC_INTERFACE: u32 = 0x0200;
const ACC_ABSTRACT: u32 = 0x0400;
const MAX_DEX_HIERARCHY_NODES: usize = 16_384;
const MAX_DEX_HIERARCHY_EDGES: usize = 65_536;
const MAX_DEX_HIERARCHY_DECODED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HierarchyKind {
    Interface,
    Abstract,
    Concrete,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HierarchyNode {
    pub descriptor: String,
    pub kind: HierarchyKind,
    pub parents: Vec<String>,
}

pub fn classfile_hierarchy_node(class: &ClassFile) -> Result<HierarchyNode> {
    let descriptor: String = class_descriptor(class.this_class_name()?);
    let mut parents: Vec<String> = Vec::new();
    if class.super_class != 0 {
        parents.push(class_descriptor(class.class_name(class.super_class)?));
    }
    for interface in &class.interfaces {
        parents.push(class_descriptor(class.class_name(*interface)?));
    }
    parents.sort();
    parents.dedup();
    Ok(HierarchyNode {
        descriptor,
        kind: kind(u32::from(class.access_flags)),
        parents,
    })
}

pub fn dex_hierarchy_nodes(bytes: &[u8]) -> Result<Vec<HierarchyNode>> {
    let header = parse_header(bytes)?;
    if header.version == DexVersion::V041 {
        return Err(Error::BadBytecode {
            offset: 4,
            reason: "DEX 041 container-relative hierarchy offsets are unsupported",
        });
    }
    let count: usize = bounded_hierarchy_node_count(header.class_defs_size as usize)?;
    let data_start: usize = header.data_off as usize;
    let data_end: usize = checked_offset(data_start, header.data_size as usize)?;
    if !data_start.is_multiple_of(4) || data_end > bytes.len() {
        return Err(Error::BadBytecode {
            offset: data_start,
            reason: "DEX hierarchy data section is out of range",
        });
    }
    let table_ranges: [Option<Range<usize>>; 6] = [
        table_range(
            bytes,
            header.header_size,
            data_start,
            header.string_ids_off,
            header.string_ids_size,
            4,
        )?,
        table_range(
            bytes,
            header.header_size,
            data_start,
            header.type_ids_off,
            header.type_ids_size,
            4,
        )?,
        table_range(
            bytes,
            header.header_size,
            data_start,
            header.proto_ids_off,
            header.proto_ids_size,
            12,
        )?,
        table_range(
            bytes,
            header.header_size,
            data_start,
            header.field_ids_off,
            header.field_ids_size,
            8,
        )?,
        table_range(
            bytes,
            header.header_size,
            data_start,
            header.method_ids_off,
            header.method_ids_size,
            8,
        )?,
        table_range(
            bytes,
            header.header_size,
            data_start,
            header.class_defs_off,
            header.class_defs_size,
            32,
        )?,
    ];
    for (index, range) in table_ranges.iter().enumerate() {
        let Some(range) = range else { continue };
        if table_ranges[..index]
            .iter()
            .flatten()
            .any(|prior| ranges_overlap(prior, range))
        {
            return Err(Error::BadBytecode {
                offset: range.start,
                reason: "DEX hierarchy identifier tables overlap",
            });
        }
    }
    let mut reader: HierarchyDex<'_> = HierarchyDex {
        bytes,
        version: header.version,
        string_count: header.string_ids_size,
        string_base: header.string_ids_off as usize,
        type_count: header.type_ids_size,
        type_base: header.type_ids_off as usize,
        data_start,
        data_end,
        decoded_bytes: 0,
    };
    let mut nodes: Vec<HierarchyNode> = Vec::with_capacity(count);
    let mut edge_budget: usize = MAX_DEX_HIERARCHY_EDGES;
    for index in 0..count {
        let offset: usize = (header.class_defs_off as usize)
            .checked_add(index.checked_mul(32).ok_or(Error::BadBytecode {
                offset: header.class_defs_off as usize,
                reason: "DEX hierarchy class offset overflow",
            })?)
            .ok_or(Error::BadBytecode {
                offset: header.class_defs_off as usize,
                reason: "DEX hierarchy class offset overflow",
            })?;
        let class_index: u32 = read_u32(bytes, offset)?;
        let access_flags: u32 = read_u32(bytes, checked_offset(offset, 4)?)?;
        let super_offset: usize = checked_offset(offset, 8)?;
        let interfaces_field: usize = checked_offset(offset, 12)?;
        let super_index: u32 = read_u32(bytes, super_offset)?;
        let interfaces_offset: u32 = read_u32(bytes, interfaces_field)?;
        let descriptor: String = reader.type_name(class_index, offset)?;
        if !is_reference_descriptor(&descriptor, header.version) {
            return Err(Error::BadBytecode {
                offset,
                reason: "DEX hierarchy class descriptor is not a reference type",
            });
        }
        let mut parents: Vec<String> = Vec::new();
        if super_index != DEX_NO_INDEX {
            let parent: String = reader.type_name(super_index, super_offset)?;
            if !is_reference_descriptor(&parent, header.version) {
                return Err(Error::BadBytecode {
                    offset: super_offset,
                    reason: "DEX hierarchy superclass is not a reference type",
                });
            }
            spend_edge(&mut edge_budget, super_offset)?;
            parents.push(parent);
        }
        parents.extend(dex_interfaces(
            &mut reader,
            interfaces_offset,
            &mut edge_budget,
        )?);
        parents.sort();
        parents.dedup();
        nodes.push(HierarchyNode {
            descriptor,
            kind: kind(access_flags),
            parents,
        });
    }
    Ok(nodes)
}

const fn bounded_hierarchy_node_count(count: usize) -> Result<usize> {
    if count > MAX_DEX_HIERARCHY_NODES {
        return Err(Error::BadBytecode {
            offset: 0,
            reason: "DEX hierarchy class-definition budget is exhausted",
        });
    }
    Ok(count)
}

fn table_range(
    bytes: &[u8],
    header_size: u32,
    data_start: usize,
    offset: u32,
    count: u32,
    item_size: usize,
) -> Result<Option<Range<usize>>> {
    if count == 0 {
        if offset != 0 {
            return Err(Error::BadBytecode {
                offset: offset as usize,
                reason: "DEX hierarchy empty table has a nonzero offset",
            });
        }
        return Ok(None);
    }
    let base: usize = offset as usize;
    if !base.is_multiple_of(4) || base < header_size as usize {
        return Err(Error::BadBytecode {
            offset: base,
            reason: "DEX hierarchy table offset is invalid",
        });
    }
    let size: usize = (count as usize)
        .checked_mul(item_size)
        .ok_or(Error::BadBytecode {
            offset: base,
            reason: "DEX hierarchy table size overflows",
        })?;
    let end: usize = base.checked_add(size).ok_or(Error::BadBytecode {
        offset: base,
        reason: "DEX hierarchy table range overflows",
    })?;
    if end > bytes.len() || end > data_start {
        return Err(Error::BadBytecode {
            offset: base,
            reason: "DEX hierarchy table is out of range",
        });
    }
    Ok(Some(base..end))
}

const fn ranges_overlap(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}

struct HierarchyDex<'a> {
    bytes: &'a [u8],
    version: DexVersion,
    string_count: u32,
    string_base: usize,
    type_count: u32,
    type_base: usize,
    data_start: usize,
    data_end: usize,
    decoded_bytes: usize,
}

impl HierarchyDex<'_> {
    fn type_name(&mut self, index: u32, offset: usize) -> Result<String> {
        if index >= self.type_count {
            return Err(Error::BadBytecode {
                offset,
                reason: "DEX hierarchy type index is out of range",
            });
        }
        let type_offset: usize = self
            .type_base
            .checked_add((index as usize).checked_mul(4).ok_or(Error::BadBytecode {
                offset,
                reason: "DEX hierarchy type offset overflow",
            })?)
            .ok_or(Error::BadBytecode {
                offset,
                reason: "DEX hierarchy type offset overflow",
            })?;
        let string_index: u32 = read_u32(self.bytes, type_offset)?;
        if string_index >= self.string_count {
            return Err(Error::BadBytecode {
                offset: type_offset,
                reason: "DEX hierarchy descriptor string index is out of range",
            });
        }
        let string_offset: usize = self
            .string_base
            .checked_add(
                (string_index as usize)
                    .checked_mul(4)
                    .ok_or(Error::BadBytecode {
                        offset: type_offset,
                        reason: "DEX hierarchy string offset overflow",
                    })?,
            )
            .ok_or(Error::BadBytecode {
                offset: type_offset,
                reason: "DEX hierarchy string offset overflow",
            })?;
        let data_offset: usize = read_u32(self.bytes, string_offset)? as usize;
        if !(self.data_start..self.data_end).contains(&data_offset) {
            return Err(Error::BadBytecode {
                offset: string_offset,
                reason: "DEX hierarchy descriptor is outside the data section",
            });
        }
        let descriptor: String = parse_string_data(&self.bytes[..self.data_end], data_offset)?;
        if self.decoded_bytes.saturating_add(descriptor.len()) > MAX_DEX_HIERARCHY_DECODED_BYTES {
            return Err(Error::BadBytecode {
                offset: data_offset,
                reason: "DEX hierarchy decoded byte budget is exhausted",
            });
        }
        self.decoded_bytes += descriptor.len();
        Ok(descriptor)
    }
}

fn dex_interfaces(
    reader: &mut HierarchyDex<'_>,
    offset: u32,
    edge_budget: &mut usize,
) -> Result<Vec<String>> {
    if offset == 0 {
        return Ok(Vec::new());
    }
    let base: usize = offset as usize;
    if !base.is_multiple_of(4) || !(reader.data_start..reader.data_end).contains(&base) {
        return Err(Error::BadBytecode {
            offset: base,
            reason: "DEX interface list is not an aligned data-section item",
        });
    }
    let count: usize = read_u32(reader.bytes, base)? as usize;
    if count > *edge_budget {
        return Err(Error::BadBytecode {
            offset: base,
            reason: "DEX hierarchy interface edge budget is exhausted",
        });
    }
    let entries_end: usize = base
        .checked_add(4)
        .and_then(|start: usize| {
            count
                .checked_mul(2)
                .and_then(|size: usize| start.checked_add(size))
        })
        .ok_or(Error::BadBytecode {
            offset: base,
            reason: "DEX interface list size overflow",
        })?;
    if entries_end > reader.data_end {
        return Err(Error::BadBytecode {
            offset: base,
            reason: "DEX interface list is truncated",
        });
    }
    let mut interfaces: Vec<String> = Vec::with_capacity(count);
    let mut unique: BTreeSet<String> = BTreeSet::new();
    for index in 0..count {
        let entry: usize = checked_offset(
            checked_offset(base, 4)?,
            index.checked_mul(2).ok_or(Error::BadBytecode {
                offset: base,
                reason: "DEX interface list size overflow",
            })?,
        )?;
        let type_index: u32 = u32::from(read_u16(reader.bytes, entry)?);
        let interface: String = reader.type_name(type_index, entry)?;
        if !is_reference_descriptor(&interface, reader.version) {
            return Err(Error::BadBytecode {
                offset: entry,
                reason: "DEX hierarchy interface is not a reference type",
            });
        }
        if !unique.insert(interface.clone()) {
            return Err(Error::BadBytecode {
                offset: entry,
                reason: "DEX hierarchy interface list contains a duplicate type",
            });
        }
        spend_edge(edge_budget, entry)?;
        interfaces.push(interface);
    }
    Ok(interfaces)
}

const fn spend_edge(budget: &mut usize, offset: usize) -> Result<()> {
    if *budget == 0 {
        return Err(Error::BadBytecode {
            offset,
            reason: "DEX hierarchy interface edge budget is exhausted",
        });
    }
    *budget -= 1;
    Ok(())
}

fn checked_offset(base: usize, delta: usize) -> Result<usize> {
    base.checked_add(delta).ok_or(Error::BadBytecode {
        offset: base,
        reason: "DEX hierarchy offset overflow",
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end: usize = offset.checked_add(2).ok_or(Error::Truncated {
        offset,
        needed: 2,
        had: 0,
    })?;
    let Some(value) = bytes.get(offset..end) else {
        return Err(Error::Truncated {
            offset,
            needed: 2,
            had: bytes.len().saturating_sub(offset),
        });
    };
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end: usize = offset.checked_add(4).ok_or(Error::Truncated {
        offset,
        needed: 4,
        had: 0,
    })?;
    let Some(value) = bytes.get(offset..end) else {
        return Err(Error::Truncated {
            offset,
            needed: 4,
            had: bytes.len().saturating_sub(offset),
        });
    };
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn is_reference_descriptor(value: &str, version: DexVersion) -> bool {
    let Some(body) = value
        .strip_prefix('L')
        .and_then(|body: &str| body.strip_suffix(';'))
    else {
        return false;
    };
    !body.is_empty()
        && body.split('/').all(|component: &str| {
            !component.is_empty()
                && component
                    .chars()
                    .all(|character: char| is_dex_simple_name_char(character, version))
        })
}

const fn is_dex_simple_name_char(character: char, version: DexVersion) -> bool {
    let extended_spaces: bool = matches!(version, DexVersion::V040 | DexVersion::V041);
    matches!(
        character,
        'A'..='Z'
            | 'a'..='z'
            | '0'..='9'
            | '$'
            | '-'
            | '_'
            | '\u{00a1}'..='\u{1fff}'
            | '\u{2010}'..='\u{2027}'
            | '\u{2030}'..='\u{d7ff}'
            | '\u{e000}'..='\u{ffef}'
            | '\u{10000}'..='\u{10ffff}'
    ) || extended_spaces
        && matches!(
            character,
            ' ' | '\u{00a0}' | '\u{2000}'..='\u{200a}' | '\u{202f}'
        )
}

const fn kind(access_flags: u32) -> HierarchyKind {
    if access_flags & ACC_INTERFACE != 0 {
        HierarchyKind::Interface
    } else if access_flags & ACC_ABSTRACT != 0 {
        HierarchyKind::Abstract
    } else {
        HierarchyKind::Concrete
    }
}

fn class_descriptor(name: &str) -> String {
    format!("L{name};")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dex::parse;

    const DEX: &[u8] = include_bytes!("../tests/fixtures/implementors/Hierarchy-d8.dex");

    #[test]
    fn hierarchy_explicitly_rejects_dex_041() {
        let mut bytes = DEX.to_vec();
        bytes[4..7].copy_from_slice(b"041");
        assert!(dex_hierarchy_nodes(&bytes).is_err());
    }

    #[test]
    fn hierarchy_rejects_an_unaligned_type_list() {
        let mut bytes = DEX.to_vec();
        let dex = parse(&bytes).expect("fixture parses");
        let direct = dex
            .class_descriptors
            .iter()
            .position(|descriptor: &String| descriptor == "Limplementors/Direct;")
            .expect("direct class");
        let field = dex.header.class_defs_off as usize + direct * 32 + 12;
        let original = u32::from_le_bytes(bytes[field..field + 4].try_into().expect("offset"));
        bytes[field..field + 4].copy_from_slice(&(original + 1).to_le_bytes());
        assert!(dex_hierarchy_nodes(&bytes).is_err());
    }

    #[test]
    fn hierarchy_node_ceiling_is_checked_before_vector_allocation() {
        assert_eq!(bounded_hierarchy_node_count(16_384).ok(), Some(16_384));
        assert!(bounded_hierarchy_node_count(16_385).is_err());
    }

    #[test]
    fn hierarchy_preflights_the_class_definition_ceiling_before_parsing_pools() {
        let mut bytes = DEX.to_vec();
        bytes[96..100].copy_from_slice(&16_385u32.to_le_bytes());
        assert!(dex_hierarchy_nodes(&bytes).is_err());
    }

    #[test]
    fn dex_descriptors_follow_the_versioned_simple_name_grammar() {
        for descriptor in ["Lpkg/9Name;", "Lpkg/Name-Thing;", "Lpkg/\u{00a1};"] {
            assert!(is_reference_descriptor(descriptor, DexVersion::V035));
        }
        for descriptor in ["Lpkg/Name Thing;", "Lpkg/\u{00a0};"] {
            assert!(!is_reference_descriptor(descriptor, DexVersion::V039));
            assert!(is_reference_descriptor(descriptor, DexVersion::V040));
        }
        for descriptor in ["Lpkg/Name(Thing);", "Lpkg/\u{1b};", "Lpkg/\u{200b};"] {
            assert!(!is_reference_descriptor(descriptor, DexVersion::V040));
        }
    }

    #[test]
    fn hierarchy_does_not_parse_unrelated_method_pools() {
        let mut bytes = DEX.to_vec();
        let header = parse_header(&bytes).expect("header");
        assert!(header.method_ids_size > 0);
        let method_offset = header.method_ids_off as usize;
        bytes[method_offset..method_offset + 8].fill(0xff);
        assert_eq!(
            dex_hierarchy_nodes(&bytes).expect("hierarchy only").len(),
            5
        );
    }

    #[test]
    fn hierarchy_rejects_misaligned_zero_sized_and_overlapping_tables() {
        let mut misaligned = DEX.to_vec();
        misaligned[60..64].copy_from_slice(&1u32.to_le_bytes());
        assert!(dex_hierarchy_nodes(&misaligned).is_err());

        let mut empty_with_offset = DEX.to_vec();
        empty_with_offset[56..60].copy_from_slice(&0u32.to_le_bytes());
        assert!(dex_hierarchy_nodes(&empty_with_offset).is_err());

        let mut overlapping = DEX.to_vec();
        let string_offset = u32::from_le_bytes(overlapping[60..64].try_into().expect("offset"));
        overlapping[68..72].copy_from_slice(&string_offset.to_le_bytes());
        assert!(dex_hierarchy_nodes(&overlapping).is_err());
    }

    #[test]
    fn hierarchy_budget_depends_on_decoded_descriptors_not_file_padding() {
        let mut bytes = DEX.to_vec();
        bytes.resize(1024 * 1024, 0);
        assert_eq!(
            dex_hierarchy_nodes(&bytes)
                .expect("bounded hierarchy")
                .len(),
            5
        );
    }

    #[test]
    fn hierarchy_descriptor_cannot_extend_beyond_the_data_section() {
        let mut bytes = DEX.to_vec();
        let header = parse_header(&bytes).expect("header");
        let class_index = read_u32(&bytes, header.class_defs_off as usize).expect("class index");
        let type_offset = header.type_ids_off as usize + class_index as usize * 4;
        let string_index = read_u32(&bytes, type_offset).expect("string index");
        let string_offset = header.string_ids_off as usize + string_index as usize * 4;
        let data_offset = read_u32(&bytes, string_offset).expect("data offset");
        let truncated_data_size = data_offset + 1 - header.data_off;
        bytes[104..108].copy_from_slice(&truncated_data_size.to_le_bytes());
        assert!(dex_hierarchy_nodes(&bytes).is_err());
    }
}
