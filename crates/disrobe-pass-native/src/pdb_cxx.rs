use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use pdb::FallibleIterator as _;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[allow(clippy::redundant_pub_crate)]
mod catalog;
#[allow(clippy::redundant_pub_crate)]
mod declarator;
#[allow(clippy::redundant_pub_crate)]
mod emit;
#[allow(clippy::redundant_pub_crate)]
mod functions;
#[allow(clippy::redundant_pub_crate)]
mod names;
#[allow(clippy::redundant_pub_crate)]
mod primitive;
#[allow(clippy::redundant_pub_crate)]
mod spelling;
mod validate;

pub use validate::{perturb_first_offset, render_static_assert_tu};

use catalog::{TypeCatalog, UdtFamily};
use emit::OpaqueRefs;
use names::{Deduper, sanitize_identifier};

pub(crate) fn pdb_err(e: pdb::Error) -> Error {
    Error::Pdb(e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdtTagKeyword {
    Struct,
    Class,
    Union,
}

impl UdtTagKeyword {
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Struct => "struct",
            Self::Class => "class",
            Self::Union => "union",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitfieldSpec {
    pub position: u8,
    pub length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmittedField {
    pub emitted_name: String,
    pub original_name: String,
    pub declaration: String,
    pub offset: u64,
    pub byte_size: Option<u64>,
    pub bitfield: Option<BitfieldSpec>,
    pub is_static: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmittedBase {
    pub base_name: String,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmittedUdt {
    pub type_index: u32,
    pub tag_keyword: UdtTagKeyword,
    pub emitted_name: String,
    pub original_name: String,
    pub byte_size: u64,
    pub bases: Vec<EmittedBase>,
    pub fields: Vec<EmittedField>,
    pub degraded: bool,
    pub depends_on: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmittedEnumerator {
    pub emitted_name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmittedEnum {
    pub type_index: u32,
    pub emitted_name: String,
    pub original_name: String,
    pub underlying_type_text: String,
    pub enumerators: Vec<EmittedEnumerator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmittedTypedef {
    pub emitted_name: String,
    pub declaration: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmittedGlobal {
    pub name: String,
    pub declaration: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmittedFunction {
    pub name: String,
    pub declaration: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RejectReason {
    InheritanceOrVirtualDispatch,
    AnonymousNestedAggregate,
    UnresolvableMember,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedType {
    pub type_index: u32,
    pub original_name: String,
    pub reason: RejectReason,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdbCxxReconstruction {
    pub udts: Vec<EmittedUdt>,
    pub enums: Vec<EmittedEnum>,
    pub typedefs: Vec<EmittedTypedef>,
    pub globals: Vec<EmittedGlobal>,
    pub functions: Vec<EmittedFunction>,
    pub opaque_enum_forward_decls: Vec<String>,
    pub rejected: Vec<RejectedType>,
    pub header_text: String,
}

fn is_compiler_generated_symbol(name: &str) -> bool {
    name.is_empty()
        || name.starts_with("??_")
        || name.starts_with('$')
        || name.starts_with("__ehhandler")
        || name.starts_with("__unwindfunclet")
        || name.starts_with("__GSHandlerCheck")
        || name.starts_with("__local_stdio")
}

pub fn reconstruct_pdb_cxx(bytes: &[u8]) -> Result<PdbCxxReconstruction> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut pdb_file: pdb::PDB<'_, Cursor<&[u8]>> = pdb::PDB::open(cursor).map_err(pdb_err)?;
    let type_info: pdb::TypeInformation<'_> = pdb_file.type_information().map_err(pdb_err)?;
    let catalog: TypeCatalog<'_> = TypeCatalog::build(&type_info)?;

    let mut opaque_refs: OpaqueRefs = Vec::new();
    let mut rejected: Vec<RejectedType> = Vec::new();
    let name_map: BTreeMap<u32, String> = assign_udt_names(&catalog);

    let mut enums: Vec<EmittedEnum> = Vec::new();
    for idx in catalog.defining_indices(UdtFamily::Enum) {
        let Ok(pdb::TypeData::Enumeration(e)) = catalog.get(idx) else {
            continue;
        };
        let Some(emitted_name) = name_map.get(&idx.0).cloned() else {
            continue;
        };
        let raw_name: String = e.name.to_string().into_owned();
        match emit::build_enum(&catalog, idx, &e, emitted_name, &mut opaque_refs) {
            Ok(built) => enums.push(built),
            Err((reason, detail)) => rejected.push(RejectedType {
                type_index: idx.0,
                original_name: raw_name,
                reason,
                detail,
            }),
        }
    }
    enums.sort_by_key(|e: &EmittedEnum| e.type_index);

    let mut udts: Vec<EmittedUdt> = Vec::new();
    for idx in catalog.defining_indices(UdtFamily::ClassLike) {
        let Ok(pdb::TypeData::Class(c)) = catalog.get(idx) else {
            continue;
        };
        let Some(emitted_name) = name_map.get(&idx.0).cloned() else {
            continue;
        };
        let raw_name: String = c.name.to_string().into_owned();
        match emit::build_class(&catalog, idx, &c, emitted_name, &name_map, &mut opaque_refs) {
            Ok(built) => udts.push(built),
            Err((reason, detail)) => rejected.push(RejectedType {
                type_index: idx.0,
                original_name: raw_name,
                reason,
                detail,
            }),
        }
    }
    for idx in catalog.defining_indices(UdtFamily::Union) {
        let Ok(pdb::TypeData::Union(u)) = catalog.get(idx) else {
            continue;
        };
        let Some(emitted_name) = name_map.get(&idx.0).cloned() else {
            continue;
        };
        let raw_name: String = u.name.to_string().into_owned();
        match emit::build_union(&catalog, idx, &u, emitted_name, &mut opaque_refs) {
            Ok(built) => udts.push(built),
            Err((reason, detail)) => rejected.push(RejectedType {
                type_index: idx.0,
                original_name: raw_name,
                reason,
                detail,
            }),
        }
    }
    udts = topologically_order_udts(udts);

    let mut typedefs: Vec<EmittedTypedef> = Vec::new();
    let mut globals: Vec<EmittedGlobal> = Vec::new();
    let mut functions: Vec<EmittedFunction> = Vec::new();
    let symbol_table: pdb::SymbolTable<'_> = pdb_file.global_symbols().map_err(pdb_err)?;
    let mut sym_iter: pdb::SymbolIter<'_> = symbol_table.iter();
    while let Some(symbol) = sym_iter.next().map_err(pdb_err)? {
        let Ok(data) = symbol.parse() else {
            continue;
        };
        match data {
            pdb::SymbolData::UserDefinedType(u)
                if !is_compiler_generated_symbol(&u.name.to_string()) =>
            {
                if let Some(td) = emit::build_typedef(&catalog, &u, &mut opaque_refs) {
                    typedefs.push(td);
                }
            }
            pdb::SymbolData::Data(d) if !is_compiler_generated_symbol(&d.name.to_string()) => {
                if let Some(g) = emit::build_global(&catalog, &d, &mut opaque_refs) {
                    globals.push(g);
                }
            }
            pdb::SymbolData::Procedure(p) if !is_compiler_generated_symbol(&p.name.to_string()) => {
                if let Some(f) = emit::build_function(&catalog, &p, &mut opaque_refs) {
                    functions.push(f);
                }
            }
            _ => {}
        }
    }

    let opaque_enum_names: BTreeSet<String> = opaque_refs
        .iter()
        .filter(|(family, _)| *family == UdtFamily::Enum)
        .map(|(_, name)| name.clone())
        .collect();
    let defined_enum_names: BTreeSet<&str> = enums
        .iter()
        .map(|e: &EmittedEnum| e.emitted_name.as_str())
        .collect();
    let opaque_enum_forward_decls: Vec<String> = opaque_enum_names
        .into_iter()
        .filter(|name: &String| !defined_enum_names.contains(name.as_str()))
        .collect();

    let header_text: String = render_header(
        &opaque_enum_forward_decls,
        &enums,
        &udts,
        &typedefs,
        &globals,
        &functions,
    );

    Ok(PdbCxxReconstruction {
        udts,
        enums,
        typedefs,
        globals,
        functions,
        opaque_enum_forward_decls,
        rejected,
        header_text,
    })
}

fn assign_udt_names(catalog: &TypeCatalog<'_>) -> BTreeMap<u32, String> {
    let mut name_dedup: Deduper = Deduper::new();
    let mut name_map: BTreeMap<u32, String> = BTreeMap::new();
    for family in [UdtFamily::Enum, UdtFamily::ClassLike, UdtFamily::Union] {
        for idx in catalog.defining_indices(family) {
            let raw_name: Option<String> = match catalog.get(idx) {
                Ok(pdb::TypeData::Enumeration(e)) if family == UdtFamily::Enum => {
                    Some(e.name.to_string().into_owned())
                }
                Ok(pdb::TypeData::Class(c)) if family == UdtFamily::ClassLike => {
                    Some(c.name.to_string().into_owned())
                }
                Ok(pdb::TypeData::Union(u)) if family == UdtFamily::Union => {
                    Some(u.name.to_string().into_owned())
                }
                _ => None,
            };
            if let Some(raw) = raw_name {
                let emitted: String = name_dedup.assign(&sanitize_identifier(&raw));
                name_map.insert(idx.0, emitted);
            }
        }
    }
    name_map
}

fn topologically_order_udts(mut udts: Vec<EmittedUdt>) -> Vec<EmittedUdt> {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    udts.sort_by_key(|u: &EmittedUdt| u.type_index);
    let present: BTreeSet<u32> = udts.iter().map(|u: &EmittedUdt| u.type_index).collect();

    let mut remaining_deps: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    let mut dependents: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for u in &udts {
        let deps: BTreeSet<u32> = u
            .depends_on
            .iter()
            .copied()
            .filter(|d: &u32| present.contains(d) && *d != u.type_index)
            .collect();
        for &d in &deps {
            dependents.entry(d).or_default().insert(u.type_index);
        }
        remaining_deps.insert(u.type_index, deps);
    }

    let mut queue: VecDeque<u32> = remaining_deps
        .iter()
        .filter(|(_, deps): &(&u32, &BTreeSet<u32>)| deps.is_empty())
        .map(|(&idx, _)| idx)
        .collect();
    let mut order: Vec<u32> = Vec::with_capacity(udts.len());
    let mut emitted: BTreeSet<u32> = BTreeSet::new();
    while let Some(idx) = queue.pop_front() {
        if !emitted.insert(idx) {
            continue;
        }
        order.push(idx);
        let Some(waiting) = dependents.get(&idx) else {
            continue;
        };
        let mut newly_ready: Vec<u32> = Vec::new();
        for &dependent_idx in waiting {
            let Some(deps) = remaining_deps.get_mut(&dependent_idx) else {
                continue;
            };
            deps.remove(&idx);
            if deps.is_empty() && !emitted.contains(&dependent_idx) {
                newly_ready.push(dependent_idx);
            }
        }
        newly_ready.sort_unstable();
        queue.extend(newly_ready);
    }
    for &idx in &present {
        if !emitted.contains(&idx) {
            order.push(idx);
        }
    }

    let mut by_index: BTreeMap<u32, EmittedUdt> = udts
        .into_iter()
        .map(|u: EmittedUdt| (u.type_index, u))
        .collect();
    order
        .into_iter()
        .filter_map(|idx: u32| by_index.remove(&idx))
        .collect()
}

fn render_header(
    opaque_enum_forward_decls: &[String],
    enums: &[EmittedEnum],
    udts: &[EmittedUdt],
    typedefs: &[EmittedTypedef],
    globals: &[EmittedGlobal],
    functions: &[EmittedFunction],
) -> String {
    let mut out: String = String::new();
    for name in opaque_enum_forward_decls {
        out.push_str(&format!("enum {name} : int;\n"));
    }
    for e in enums {
        out.push_str(&render_enum(e));
    }
    for u in udts {
        out.push_str(&render_udt(u));
    }
    for t in typedefs {
        out.push_str(&t.declaration);
        out.push('\n');
    }
    for g in globals {
        out.push_str(&g.declaration);
        out.push('\n');
    }
    for f in functions {
        out.push_str(&f.declaration);
        out.push('\n');
    }
    out
}

fn render_enum(e: &EmittedEnum) -> String {
    let mut out: String = format!("enum {} : {} {{\n", e.emitted_name, e.underlying_type_text);
    for enumerator in &e.enumerators {
        out.push_str(&format!(
            "    {} = {},\n",
            enumerator.emitted_name, enumerator.value
        ));
    }
    out.push_str("};\n");
    out
}

fn render_udt(u: &EmittedUdt) -> String {
    let base_clause: String = if u.bases.is_empty() {
        String::new()
    } else {
        let names: Vec<&str> = u
            .bases
            .iter()
            .map(|b: &EmittedBase| b.base_name.as_str())
            .collect();
        format!(" : public {}", names.join(", public "))
    };
    let mut out: String = format!(
        "{} {}{base_clause} {{\n",
        u.tag_keyword.keyword(),
        u.emitted_name
    );
    for field in &u.fields {
        out.push_str(&format!("    {};\n", field.declaration));
    }
    out.push_str("};\n");
    out
}
