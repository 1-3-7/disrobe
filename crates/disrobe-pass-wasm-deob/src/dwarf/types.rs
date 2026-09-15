use std::collections::BTreeMap;

use serde::Serialize;

use crate::dwarf::unit::{RawMember, RawTypeDie, UnitBundle};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum BaseEncoding {
    Boolean,
    SignedInt,
    UnsignedInt,
    SignedChar,
    UnsignedChar,
    Float,
    Address,
    Utf,
    Other(u16),
}

impl BaseEncoding {
    #[inline]
    #[must_use]
    pub const fn from_dwarf(value: u16) -> Self {
        match value {
            0x02 => Self::Boolean,
            0x05 => Self::SignedInt,
            0x07 => Self::UnsignedInt,
            0x06 => Self::SignedChar,
            0x08 => Self::UnsignedChar,
            0x04 => Self::Float,
            0x01 => Self::Address,
            0x10 => Self::Utf,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RecoveredDwarfType {
    Base {
        name: Option<String>,
        encoding: BaseEncoding,
        byte_size: Option<u64>,
    },
    Pointer {
        target: Option<u64>,
        byte_size: Option<u64>,
    },
    Reference {
        target: Option<u64>,
    },
    Const {
        target: Option<u64>,
    },
    Volatile {
        target: Option<u64>,
    },
    Typedef {
        name: Option<String>,
        target: Option<u64>,
    },
    Structure {
        name: Option<String>,
        byte_size: Option<u64>,
        members: Vec<MemberRecord>,
    },
    Union {
        name: Option<String>,
        byte_size: Option<u64>,
        members: Vec<MemberRecord>,
    },
    Class {
        name: Option<String>,
        byte_size: Option<u64>,
        members: Vec<MemberRecord>,
    },
    Array {
        element: Option<u64>,
        length: Option<u64>,
    },
    Enumeration {
        name: Option<String>,
        byte_size: Option<u64>,
        variants: BTreeMap<i64, String>,
    },
    Subroutine {
        return_type: Option<u64>,
        parameter_types: Vec<Option<u64>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemberRecord {
    pub name: Option<String>,
    pub type_id: Option<u64>,
    pub byte_offset: Option<u64>,
    pub bit_size: Option<u64>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct DwarfTypeGraph {
    pub types: BTreeMap<u64, RecoveredDwarfType>,
}

impl DwarfTypeGraph {
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    #[must_use]
    pub fn resolve_chain(&self, mut id: u64, max_hops: usize) -> Option<&RecoveredDwarfType> {
        for _ in 0..max_hops {
            let entry: &RecoveredDwarfType = self.types.get(&id)?;
            match entry {
                RecoveredDwarfType::Typedef { target, .. }
                | RecoveredDwarfType::Const { target }
                | RecoveredDwarfType::Volatile { target } => match target {
                    Some(next) => id = *next,
                    None => return Some(entry),
                },
                _ => return Some(entry),
            }
        }
        self.types.get(&id)
    }
}

pub fn build(bundles: &[UnitBundle]) -> DwarfTypeGraph {
    let mut types: BTreeMap<u64, RecoveredDwarfType> = BTreeMap::new();
    for bundle in bundles {
        for (offset, raw) in &bundle.type_dies {
            types.insert(*offset, lower(raw));
        }
    }
    DwarfTypeGraph { types }
}

fn lower(raw: &RawTypeDie) -> RecoveredDwarfType {
    match raw {
        RawTypeDie::Base {
            name,
            encoding,
            byte_size,
        } => RecoveredDwarfType::Base {
            name: name.clone(),
            encoding: encoding.map_or(BaseEncoding::Other(0), BaseEncoding::from_dwarf),
            byte_size: *byte_size,
        },
        RawTypeDie::Pointer {
            target_type_offset,
            byte_size,
        } => RecoveredDwarfType::Pointer {
            target: *target_type_offset,
            byte_size: *byte_size,
        },
        RawTypeDie::Reference { target_type_offset } => RecoveredDwarfType::Reference {
            target: *target_type_offset,
        },
        RawTypeDie::Const { target_type_offset } => RecoveredDwarfType::Const {
            target: *target_type_offset,
        },
        RawTypeDie::Volatile { target_type_offset } => RecoveredDwarfType::Volatile {
            target: *target_type_offset,
        },
        RawTypeDie::Typedef {
            name,
            target_type_offset,
        } => RecoveredDwarfType::Typedef {
            name: name.clone(),
            target: *target_type_offset,
        },
        RawTypeDie::Structure {
            name,
            byte_size,
            members,
        } => RecoveredDwarfType::Structure {
            name: name.clone(),
            byte_size: *byte_size,
            members: members.iter().map(lower_member).collect::<Vec<_>>(),
        },
        RawTypeDie::Union {
            name,
            byte_size,
            members,
        } => RecoveredDwarfType::Union {
            name: name.clone(),
            byte_size: *byte_size,
            members: members.iter().map(lower_member).collect::<Vec<_>>(),
        },
        RawTypeDie::Class {
            name,
            byte_size,
            members,
        } => RecoveredDwarfType::Class {
            name: name.clone(),
            byte_size: *byte_size,
            members: members.iter().map(lower_member).collect::<Vec<_>>(),
        },
        RawTypeDie::Array {
            element_type_offset,
            element_count,
        } => RecoveredDwarfType::Array {
            element: *element_type_offset,
            length: *element_count,
        },
        RawTypeDie::Enumeration {
            name,
            byte_size,
            variants,
        } => RecoveredDwarfType::Enumeration {
            name: name.clone(),
            byte_size: *byte_size,
            variants: variants.clone(),
        },
        RawTypeDie::Subroutine {
            return_type_offset,
            parameters,
        } => RecoveredDwarfType::Subroutine {
            return_type: *return_type_offset,
            parameter_types: parameters.iter().map(|p| p.type_offset).collect::<Vec<_>>(),
        },
    }
}

#[inline]
fn lower_member(m: &RawMember) -> MemberRecord {
    MemberRecord {
        name: m.name.clone(),
        type_id: m.type_offset,
        byte_offset: m.byte_offset,
        bit_size: m.bit_size,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn base_encoding_known_values() {
        assert_eq!(BaseEncoding::from_dwarf(0x05), BaseEncoding::SignedInt);
        assert_eq!(BaseEncoding::from_dwarf(0x07), BaseEncoding::UnsignedInt);
        assert_eq!(BaseEncoding::from_dwarf(0x04), BaseEncoding::Float);
        assert_eq!(BaseEncoding::from_dwarf(0x99), BaseEncoding::Other(0x99));
    }

    #[test]
    fn empty_graph_resolve_returns_none() {
        let graph: DwarfTypeGraph = DwarfTypeGraph::default();
        assert!(graph.is_empty());
        assert!(graph.resolve_chain(0x42, 4).is_none());
    }

    #[test]
    fn typedef_chain_resolves_through_const() {
        let mut graph: DwarfTypeGraph = DwarfTypeGraph::default();
        graph.types.insert(
            1,
            RecoveredDwarfType::Base {
                name: Some("int".into()),
                encoding: BaseEncoding::SignedInt,
                byte_size: Some(4),
            },
        );
        graph
            .types
            .insert(2, RecoveredDwarfType::Const { target: Some(1) });
        graph.types.insert(
            3,
            RecoveredDwarfType::Typedef {
                name: Some("Alias".into()),
                target: Some(2),
            },
        );
        let resolved: &RecoveredDwarfType = graph.resolve_chain(3, 4).unwrap();
        assert!(matches!(
            resolved,
            RecoveredDwarfType::Base {
                encoding: BaseEncoding::SignedInt,
                ..
            }
        ));
    }

    #[test]
    fn resolve_chain_handles_max_hops() {
        let mut graph: DwarfTypeGraph = DwarfTypeGraph::default();
        graph.types.insert(
            1,
            RecoveredDwarfType::Typedef {
                name: None,
                target: Some(2),
            },
        );
        graph.types.insert(
            2,
            RecoveredDwarfType::Typedef {
                name: None,
                target: Some(1),
            },
        );
        let _ = graph.resolve_chain(1, 3);
    }
}
