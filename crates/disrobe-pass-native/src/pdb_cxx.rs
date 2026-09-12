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
mod procedures;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CvCallingConvention {
    NearC,
    FarC,
    NearPascal,
    FarPascal,
    NearFast,
    FarFast,
    NearStdCall,
    FarStdCall,
    NearSysCall,
    FarSysCall,
    ThisCall,
    MipsCall,
    Generic,
    AlphaCall,
    PpcCall,
    ShCall,
    ArmCall,
    Am33Call,
    TriCall,
    Sh5Call,
    M32rCall,
    ClrCall,
    Inline,
    NearVector,
    Swift,
    Unknown(u8),
}

impl CvCallingConvention {
    pub(crate) const fn from_raw(raw: u8) -> Self {
        match raw {
            0x00 => Self::NearC,
            0x01 => Self::FarC,
            0x02 => Self::NearPascal,
            0x03 => Self::FarPascal,
            0x04 => Self::NearFast,
            0x05 => Self::FarFast,
            0x07 => Self::NearStdCall,
            0x08 => Self::FarStdCall,
            0x09 => Self::NearSysCall,
            0x0a => Self::FarSysCall,
            0x0b => Self::ThisCall,
            0x0c => Self::MipsCall,
            0x0d => Self::Generic,
            0x0e => Self::AlphaCall,
            0x0f => Self::PpcCall,
            0x10 => Self::ShCall,
            0x11 => Self::ArmCall,
            0x12 => Self::Am33Call,
            0x13 => Self::TriCall,
            0x14 => Self::Sh5Call,
            0x15 => Self::M32rCall,
            0x16 => Self::ClrCall,
            0x17 => Self::Inline,
            0x18 => Self::NearVector,
            0x19 => Self::Swift,
            other => Self::Unknown(other),
        }
    }

    pub(crate) const fn raw(self) -> u8 {
        match self {
            Self::NearC => 0x00,
            Self::FarC => 0x01,
            Self::NearPascal => 0x02,
            Self::FarPascal => 0x03,
            Self::NearFast => 0x04,
            Self::FarFast => 0x05,
            Self::NearStdCall => 0x07,
            Self::FarStdCall => 0x08,
            Self::NearSysCall => 0x09,
            Self::FarSysCall => 0x0a,
            Self::ThisCall => 0x0b,
            Self::MipsCall => 0x0c,
            Self::Generic => 0x0d,
            Self::AlphaCall => 0x0e,
            Self::PpcCall => 0x0f,
            Self::ShCall => 0x10,
            Self::ArmCall => 0x11,
            Self::Am33Call => 0x12,
            Self::TriCall => 0x13,
            Self::Sh5Call => 0x14,
            Self::M32rCall => 0x15,
            Self::ClrCall => 0x16,
            Self::Inline => 0x17,
            Self::NearVector => 0x18,
            Self::Swift => 0x19,
            Self::Unknown(raw) => raw,
        }
    }

    pub(crate) const fn keyword(self) -> Option<&'static str> {
        match self {
            Self::NearC => Some("__cdecl"),
            Self::NearFast => Some("__fastcall"),
            Self::NearStdCall => Some("__stdcall"),
            Self::ThisCall => Some("__thiscall"),
            Self::NearVector => Some("__vectorcall"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmittedFunction {
    pub name: String,
    pub declaration: String,
    pub original_name: String,
    pub module: String,
    pub type_index: u32,
    pub return_type: String,
    pub parameters: Vec<String>,
    pub varargs: bool,
    pub calling_convention: CvCallingConvention,
    pub is_static: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FunctionRejectReason {
    MemberFunctionScope,
    IdIndexedProcedureRecord,
    UnknownCallingConvention,
    UnrepresentableCallingConvention,
    UnresolvedReturnType,
    UnresolvedParameterType,
    TypeIndexNotAFunction,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedFunction {
    pub original_name: String,
    pub module: String,
    pub type_index: u32,
    pub reason: FunctionRejectReason,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleStreamCoverage {
    pub modules_declared: usize,
    pub modules_beyond_bound: usize,
    pub modules_with_symbol_streams: usize,
    pub modules_without_symbol_streams: usize,
    pub modules_with_unreadable_symbols: usize,
    pub modules_truncated_by_unreadable_symbol: usize,
    pub modules_truncated_at_symbol_bound: usize,
    pub procedure_records_seen: usize,
    pub procedure_records_beyond_bound: usize,
    pub compiler_generated_records_skipped: usize,
    pub thunk_records_skipped: usize,
    pub inline_site_records_skipped: usize,
    pub separated_code_records_skipped: usize,
    pub duplicate_records_folded: usize,
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
    pub rejected_functions: Vec<RejectedFunction>,
    pub module_stream_coverage: ModuleStreamCoverage,
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
    let tpi_stream = pdb_file
        .raw_stream(pdb::StreamIndex(2))
        .map_err(pdb_err)?
        .ok_or_else(|| Error::Pdb("PDB has no TPI stream".to_owned()))?;
    validate_tpi_argument_lists(tpi_stream.as_slice())?;
    drop(tpi_stream);
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
            _ => {}
        }
    }

    let emitted_type_indices: BTreeSet<u32> = udts
        .iter()
        .map(|u: &EmittedUdt| u.type_index)
        .chain(enums.iter().map(|e: &EmittedEnum| e.type_index))
        .collect();
    let recovery: procedures::ProcedureRecovery = procedures::recover_module_procedures(
        &mut pdb_file,
        &catalog,
        &emitted_type_indices,
        &mut opaque_refs,
    )?;
    let functions: Vec<EmittedFunction> = recovery.functions;
    let rejected_functions: Vec<RejectedFunction> = recovery.rejected;
    let module_stream_coverage: ModuleStreamCoverage = recovery.coverage;

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
        rejected_functions,
        module_stream_coverage,
        header_text,
    })
}

const LF_ARGLIST: u16 = 0x1201;
const TPI_HEADER_MIN_BYTES: usize = 56;
const TPI_HEADER_MAX_BYTES: usize = 1024;

fn validate_tpi_argument_lists(stream: &[u8]) -> Result<()> {
    if stream.is_empty() {
        return Ok(());
    }
    let header_size: usize = read_tpi_u32(stream, 4, "header size")? as usize;
    if !(TPI_HEADER_MIN_BYTES..=TPI_HEADER_MAX_BYTES).contains(&header_size) {
        return Err(Error::Pdb(format!(
            "TPI header size {header_size} is outside {TPI_HEADER_MIN_BYTES}..={TPI_HEADER_MAX_BYTES}"
        )));
    }
    let record_bytes: usize = read_tpi_u32(stream, 16, "record byte count")? as usize;
    let records_end: usize = header_size.checked_add(record_bytes).ok_or_else(|| {
        Error::Pdb(format!(
            "TPI record range overflows: header {header_size}, records {record_bytes}"
        ))
    })?;
    if records_end != stream.len() {
        return Err(Error::Pdb(format!(
            "TPI declares {record_bytes} record bytes after a {header_size}-byte header, but the stream contains {} record bytes",
            stream.len().saturating_sub(header_size)
        )));
    }

    let mut offset: usize = header_size;
    while offset < records_end {
        let length: usize = usize::from(read_tpi_u16(stream, offset, "record length")?);
        if length < 2 {
            return Err(Error::Pdb(format!(
                "TPI record at byte {offset} has invalid length {length}"
            )));
        }
        let data_start: usize = offset
            .checked_add(2)
            .ok_or_else(|| Error::Pdb(format!("TPI record offset {offset} overflows")))?;
        let next: usize = data_start.checked_add(length).ok_or_else(|| {
            Error::Pdb(format!(
                "TPI record at byte {offset} overflows its length {length}"
            ))
        })?;
        if next > records_end {
            return Err(Error::Pdb(format!(
                "TPI record at byte {offset} declares {length} bytes beyond the {record_bytes}-byte record region"
            )));
        }
        let record: &[u8] = &stream[data_start..next];
        if read_u16(record, 0).is_some_and(|kind: u16| kind == LF_ARGLIST) {
            validate_argument_list(record, offset)?;
        }
        offset = next;
    }
    Ok(())
}

fn validate_argument_list(record: &[u8], offset: usize) -> Result<()> {
    let count: usize = read_tpi_u32(record, 2, "LF_ARGLIST entry count")? as usize;
    let body: &[u8] = record.get(6..).ok_or_else(|| {
        Error::Pdb(format!(
            "LF_ARGLIST at TPI byte {offset} is truncated before its entry count"
        ))
    })?;
    let available: usize = body.len() / 4;
    if count > available {
        return Err(Error::Pdb(format!(
            "LF_ARGLIST at TPI byte {offset} declares {count} entries but the record holds at most {available}"
        )));
    }
    let entry_bytes: usize = count.checked_mul(4).ok_or_else(|| {
        Error::Pdb(format!(
            "LF_ARGLIST at TPI byte {offset} entry count {count} overflows"
        ))
    })?;
    let trailing: &[u8] = body.get(entry_bytes..).ok_or_else(|| {
        Error::Pdb(format!(
            "LF_ARGLIST at TPI byte {offset} declares {count} entries beyond its record"
        ))
    })?;
    if !valid_codeview_padding(trailing) {
        return Err(Error::Pdb(format!(
            "LF_ARGLIST at TPI byte {offset} declares {count} entries but carries {} additional bytes",
            trailing.len()
        )));
    }
    Ok(())
}

fn valid_codeview_padding(bytes: &[u8]) -> bool {
    bytes.is_empty()
        || (bytes.len() <= 3
            && bytes.first().is_some_and(|first: &u8| {
                *first >= 0xf1 && usize::from(*first & 0x0f) == bytes.len()
            }))
}

fn read_tpi_u16(bytes: &[u8], offset: usize, field: &str) -> Result<u16> {
    read_u16(bytes, offset).ok_or_else(|| {
        Error::Pdb(format!(
            "TPI is truncated while reading {field} at byte {offset}"
        ))
    })
}

fn read_tpi_u32(bytes: &[u8], offset: usize, field: &str) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|slice: &[u8]| slice.try_into().ok())
        .ok_or_else(|| {
            Error::Pdb(format!(
                "TPI is truncated while reading {field} at byte {offset}"
            ))
        })?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn argument_list(count: u32, arguments: &[u32], padding: &[u8]) -> Vec<u8> {
        let mut record: Vec<u8> = Vec::new();
        record.extend_from_slice(&LF_ARGLIST.to_le_bytes());
        record.extend_from_slice(&count.to_le_bytes());
        for argument in arguments {
            record.extend_from_slice(&argument.to_le_bytes());
        }
        record.extend_from_slice(padding);
        record
    }

    fn tpi(records: &[Vec<u8>]) -> Vec<u8> {
        let record_bytes: usize = records
            .iter()
            .map(|record: &Vec<u8>| record.len() + 2)
            .sum();
        let mut stream: Vec<u8> = vec![0; TPI_HEADER_MIN_BYTES];
        stream[4..8].copy_from_slice(&(TPI_HEADER_MIN_BYTES as u32).to_le_bytes());
        stream[8..12].copy_from_slice(&0x1000_u32.to_le_bytes());
        stream[12..16].copy_from_slice(&(0x1000_u32 + records.len() as u32).to_le_bytes());
        stream[16..20].copy_from_slice(&(record_bytes as u32).to_le_bytes());
        for record in records {
            let length: u16 = u16::try_from(record.len()).expect("test record length");
            stream.extend_from_slice(&length.to_le_bytes());
            stream.extend_from_slice(record);
        }
        stream
    }

    #[test]
    fn argument_list_count_cannot_exceed_record_capacity() {
        for count in [2_u32, u32::from(u16::MAX), u32::MAX] {
            let stream: Vec<u8> = tpi(&[argument_list(count, &[0x1000], &[])]);
            let error: String = validate_tpi_argument_lists(&stream)
                .expect_err("oversized LF_ARGLIST must refuse")
                .to_string();
            assert!(error.contains("LF_ARGLIST"), "{error}");
            assert!(error.contains(&count.to_string()), "{error}");
            assert!(error.contains("at most 1"), "{error}");
        }
    }

    #[test]
    fn argument_list_requires_exact_entries_or_codeview_padding() {
        let valid: Vec<u8> = tpi(&[
            argument_list(0, &[], &[]),
            argument_list(1, &[0x1000], &[]),
            argument_list(1, &[0x1000], &[0xf3, 0, 0]),
        ]);
        validate_tpi_argument_lists(&valid).expect("valid argument lists");

        let extra_entry: Vec<u8> = tpi(&[argument_list(0, &[0x1000], &[])]);
        let error: String = validate_tpi_argument_lists(&extra_entry)
            .expect_err("undeclared argument entry must refuse")
            .to_string();
        assert!(error.contains("carries 4 additional bytes"), "{error}");

        let truncated: Vec<u8> = tpi(&[argument_list(1, &[], &[])]);
        let error: String = validate_tpi_argument_lists(&truncated)
            .expect_err("truncated argument list must refuse")
            .to_string();
        assert!(error.contains("at most 0"), "{error}");
    }

    #[test]
    fn argument_list_preflight_covers_the_entire_tpi_stream() {
        let mut stream: Vec<u8> = tpi(&[]);
        let trailing: Vec<u8> = argument_list(u32::MAX, &[0x1000], &[]);
        let trailing_length: u16 = u16::try_from(trailing.len()).expect("test record length");
        stream.extend_from_slice(&trailing_length.to_le_bytes());
        stream.extend_from_slice(&trailing);

        let error: String = validate_tpi_argument_lists(&stream)
            .expect_err("undeclared trailing TPI records must refuse")
            .to_string();
        assert!(error.contains("declares 0 record bytes"), "{error}");
        assert!(error.contains("contains 12 record bytes"), "{error}");
    }
}
