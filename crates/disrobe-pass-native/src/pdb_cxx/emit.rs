use std::collections::{BTreeMap, BTreeSet};

use crate::error::Result;
use crate::pdb_cxx::catalog::{TypeCatalog, UdtFamily};
use crate::pdb_cxx::functions::resolve_free_function_signature;
use crate::pdb_cxx::names::{Deduper, sanitize_identifier};
use crate::pdb_cxx::spelling::{self, ResolvedSpelling, SpellError};
use crate::pdb_cxx::{
    BitfieldSpec, EmittedBase, EmittedEnum, EmittedEnumerator, EmittedField, EmittedFunction,
    EmittedGlobal, EmittedTypedef, EmittedUdt, RejectReason, UdtTagKeyword,
};

const MAX_FIELDLIST_CHAIN: usize = 256;
const VFPTR_MEMBER_NAME: &str = "__vfptr";

pub(crate) type BuildFailure = (RejectReason, String);
pub(crate) type BuildResult<T> = std::result::Result<T, BuildFailure>;
pub(crate) type OpaqueRefs = Vec<(UdtFamily, String)>;

pub(crate) fn build_class(
    catalog: &TypeCatalog<'_>,
    idx: pdb::TypeIndex,
    c: &pdb::ClassType<'_>,
    emitted_name: String,
    name_map: &BTreeMap<u32, String>,
    opaque_out: &mut OpaqueRefs,
) -> BuildResult<EmittedUdt> {
    let Some(fieldlist_idx) = c.fields else {
        return Err((
            RejectReason::Malformed,
            "class has no field list".to_owned(),
        ));
    };
    let field_records: Vec<pdb::TypeData<'_>> =
        collect_fieldlist(catalog, fieldlist_idx).map_err(|e| {
            (
                RejectReason::Malformed,
                format!("field list unreadable: {e}"),
            )
        })?;
    let inheritance: Inheritance = collect_inheritance(catalog, name_map, &field_records)?;
    let tag_keyword: UdtTagKeyword = match c.kind {
        pdb::ClassKind::Class | pdb::ClassKind::Interface => UdtTagKeyword::Class,
        pdb::ClassKind::Struct => UdtTagKeyword::Struct,
    };
    let header: UdtHeader = UdtHeader {
        idx,
        tag_keyword,
        emitted_name,
        original_name: c.name.to_string().into_owned(),
        byte_size: c.size,
        packed: c.properties.packed(),
        bases: inheritance.bases,
        base_deps: inheritance.base_deps,
        synth_vfptr: inheritance.synth_vfptr,
    };
    build_fields(catalog, &field_records, header, opaque_out)
}

#[derive(Debug)]
struct Inheritance {
    bases: Vec<EmittedBase>,
    base_deps: Vec<u32>,
    synth_vfptr: bool,
}

fn collect_inheritance(
    catalog: &TypeCatalog<'_>,
    name_map: &BTreeMap<u32, String>,
    fields: &[pdb::TypeData<'_>],
) -> BuildResult<Inheritance> {
    let mut bases: Vec<EmittedBase> = Vec::new();
    let mut base_deps: Vec<u32> = Vec::new();
    let mut synth_vfptr: bool = false;
    for f in fields {
        match f {
            pdb::TypeData::VirtualBaseClass(_) => {
                return Err((
                    RejectReason::InheritanceOrVirtualDispatch,
                    "virtual (vbtable) base layout is not modeled".to_owned(),
                ));
            }
            pdb::TypeData::BaseClass(bc) => {
                let (base_def_idx, _base_data): (pdb::TypeIndex, pdb::TypeData<'_>) =
                    catalog.resolve(bc.base_class).map_err(|e| {
                        (
                            RejectReason::UnresolvableMember,
                            format!("base class type could not be resolved: {e}"),
                        )
                    })?;
                let Some(base_name) = name_map.get(&base_def_idx.0) else {
                    return Err((
                        RejectReason::UnresolvableMember,
                        "base class is not among the emitted user types".to_owned(),
                    ));
                };
                bases.push(EmittedBase {
                    base_name: base_name.clone(),
                    offset: u64::from(bc.offset),
                });
                base_deps.push(base_def_idx.0);
            }
            pdb::TypeData::VirtualFunctionTablePointer(_) => {
                synth_vfptr = true;
            }
            _ => {}
        }
    }
    if synth_vfptr && !bases.is_empty() {
        return Err((
            RejectReason::InheritanceOrVirtualDispatch,
            "class introduces its own vtable atop base classes (secondary vftable layout not modeled)"
                .to_owned(),
        ));
    }
    Ok(Inheritance {
        bases,
        base_deps,
        synth_vfptr,
    })
}

pub(crate) fn build_union(
    catalog: &TypeCatalog<'_>,
    idx: pdb::TypeIndex,
    u: &pdb::UnionType<'_>,
    emitted_name: String,
    opaque_out: &mut OpaqueRefs,
) -> BuildResult<EmittedUdt> {
    let field_records: Vec<pdb::TypeData<'_>> =
        collect_fieldlist(catalog, u.fields).map_err(|e| {
            (
                RejectReason::Malformed,
                format!("field list unreadable: {e}"),
            )
        })?;
    let header: UdtHeader = UdtHeader {
        idx,
        tag_keyword: UdtTagKeyword::Union,
        emitted_name,
        original_name: u.name.to_string().into_owned(),
        byte_size: u.size,
        packed: u.properties.packed(),
        bases: Vec::new(),
        base_deps: Vec::new(),
        synth_vfptr: false,
    };
    build_fields(catalog, &field_records, header, opaque_out)
}

#[derive(Debug)]
struct UdtHeader {
    idx: pdb::TypeIndex,
    tag_keyword: UdtTagKeyword,
    emitted_name: String,
    original_name: String,
    byte_size: u64,
    packed: bool,
    bases: Vec<EmittedBase>,
    base_deps: Vec<u32>,
    synth_vfptr: bool,
}

fn build_fields(
    catalog: &TypeCatalog<'_>,
    field_records: &[pdb::TypeData<'_>],
    header: UdtHeader,
    opaque_out: &mut OpaqueRefs,
) -> BuildResult<EmittedUdt> {
    let mut fields: Vec<EmittedField> = Vec::new();
    let mut degraded: bool = header.packed;
    let mut depends_on: Vec<u32> = header.base_deps.clone();
    let mut dedup: Deduper = Deduper::new();
    if header.synth_vfptr {
        let vfptr_name: String = dedup.assign(VFPTR_MEMBER_NAME);
        fields.push(EmittedField {
            emitted_name: vfptr_name.clone(),
            original_name: vfptr_name,
            declaration: "void **__vfptr".to_owned(),
            offset: 0,
            byte_size: Some(8),
            bitfield: None,
            is_static: false,
        });
    }
    for record in field_records {
        match record {
            pdb::TypeData::Member(m) => {
                let spelling: ResolvedSpelling = spelling::resolve_spelling(catalog, m.field_type)
                    .map_err(|e: SpellError| describe_member_failure(&m.name.to_string(), e))?;
                degraded |= spelling.degraded;
                opaque_out.extend(spelling.opaque_refs.iter().cloned());
                if let Some(dep) = spelling.value_dependency {
                    if dep == header.idx.0 {
                        return Err((
                            RejectReason::Malformed,
                            format!(
                                "member '{}' directly contains its own enclosing type by value",
                                m.name
                            ),
                        ));
                    }
                    depends_on.push(dep);
                }
                let raw_name: String = m.name.to_string().into_owned();
                let emitted_field_name: String = dedup.assign(&sanitize_identifier(&raw_name));
                let bitfield: Option<BitfieldSpec> = spelling
                    .bitfield
                    .map(|(position, length): (u8, u8)| BitfieldSpec { position, length });
                let declaration: String = bitfield.as_ref().map_or_else(
                    || spelling.declare(&emitted_field_name),
                    |bf: &BitfieldSpec| {
                        format!("{} : {}", spelling.declare(&emitted_field_name), bf.length)
                    },
                );
                fields.push(EmittedField {
                    emitted_name: emitted_field_name,
                    original_name: raw_name,
                    declaration,
                    offset: m.offset,
                    byte_size: spelling.byte_size,
                    bitfield,
                    is_static: false,
                });
            }
            pdb::TypeData::StaticMember(sm) => {
                let Ok(spelling) = spelling::resolve_spelling(catalog, sm.field_type) else {
                    continue;
                };
                opaque_out.extend(spelling.opaque_refs.iter().cloned());
                let raw_name: String = sm.name.to_string().into_owned();
                let emitted_field_name: String = dedup.assign(&sanitize_identifier(&raw_name));
                fields.push(EmittedField {
                    emitted_name: emitted_field_name.clone(),
                    original_name: raw_name,
                    declaration: format!("static {}", spelling.declare(&emitted_field_name)),
                    offset: 0,
                    byte_size: spelling.byte_size,
                    bitfield: None,
                    is_static: true,
                });
            }
            _ => {}
        }
    }
    depends_on.sort_unstable();
    depends_on.dedup();
    Ok(EmittedUdt {
        type_index: header.idx.0,
        tag_keyword: header.tag_keyword,
        emitted_name: header.emitted_name,
        original_name: header.original_name,
        byte_size: header.byte_size,
        bases: header.bases,
        fields,
        degraded,
        depends_on,
    })
}

fn describe_member_failure(field_name: &str, e: SpellError) -> BuildFailure {
    match e {
        SpellError::AnonymousAggregate => (
            RejectReason::AnonymousNestedAggregate,
            format!("member '{field_name}' has an anonymous nested struct/union type"),
        ),
        SpellError::Pdb(err) => (
            RejectReason::UnresolvableMember,
            format!("member '{field_name}' type could not be resolved: {err}"),
        ),
    }
}

pub(crate) fn build_enum(
    catalog: &TypeCatalog<'_>,
    idx: pdb::TypeIndex,
    e: &pdb::EnumerationType<'_>,
    emitted_name: String,
    opaque_out: &mut OpaqueRefs,
) -> BuildResult<EmittedEnum> {
    let underlying: ResolvedSpelling = spelling::resolve_spelling(catalog, e.underlying_type)
        .map_err(|err: SpellError| {
            (
                RejectReason::Malformed,
                format!(
                    "enum underlying type unresolvable: {}",
                    spell_error_text(&err)
                ),
            )
        })?;
    opaque_out.extend(underlying.opaque_refs.iter().cloned());
    let field_records: Vec<pdb::TypeData<'_>> =
        collect_fieldlist(catalog, e.fields).map_err(|err| {
            (
                RejectReason::Malformed,
                format!("enumerator list unreadable: {err}"),
            )
        })?;
    let mut enumerators: Vec<EmittedEnumerator> = Vec::new();
    let mut dedup: Deduper = Deduper::new();
    for f in field_records {
        if let pdb::TypeData::Enumerate(en) = f {
            let name: String = dedup.assign(&sanitize_identifier(&en.name.to_string()));
            enumerators.push(EmittedEnumerator {
                emitted_name: name,
                value: variant_literal(&en.value),
            });
        }
    }
    Ok(EmittedEnum {
        type_index: idx.0,
        emitted_name,
        original_name: e.name.to_string().into_owned(),
        underlying_type_text: underlying.base_text,
        enumerators,
    })
}

fn variant_literal(v: &pdb::Variant) -> String {
    if let pdb::Variant::U64(x) = v
        && *x > i64::MAX as u64
    {
        return format!("{x}ULL");
    }
    v.to_string()
}

fn spell_error_text(e: &SpellError) -> String {
    match e {
        SpellError::AnonymousAggregate => "references an anonymous aggregate".to_owned(),
        SpellError::Pdb(err) => err.to_string(),
    }
}

fn collect_fieldlist<'t>(
    catalog: &TypeCatalog<'t>,
    start: pdb::TypeIndex,
) -> Result<Vec<pdb::TypeData<'t>>> {
    let mut out: Vec<pdb::TypeData<'t>> = Vec::new();
    let mut cur: pdb::TypeIndex = start;
    let mut visited: BTreeSet<pdb::TypeIndex> = BTreeSet::new();
    for _ in 0..MAX_FIELDLIST_CHAIN {
        if !visited.insert(cur) {
            break;
        }
        let data: pdb::TypeData<'t> = catalog.get(cur)?;
        let pdb::TypeData::FieldList(list) = data else {
            break;
        };
        out.extend(list.fields);
        match list.continuation {
            Some(next) => cur = next,
            None => break,
        }
    }
    Ok(out)
}

pub(crate) fn build_global(
    catalog: &TypeCatalog<'_>,
    d: &pdb::DataSymbol<'_>,
    opaque_out: &mut OpaqueRefs,
) -> Option<EmittedGlobal> {
    if d.name.is_empty() {
        return None;
    }
    let spelling: ResolvedSpelling = spelling::resolve_spelling(catalog, d.type_index).ok()?;
    opaque_out.extend(spelling.opaque_refs.iter().cloned());
    let name: String = sanitize_identifier(&d.name.to_string());
    Some(EmittedGlobal {
        name: name.clone(),
        declaration: format!("extern {};", spelling.declare(&name)),
    })
}

pub(crate) fn build_function(
    catalog: &TypeCatalog<'_>,
    p: &pdb::ProcedureSymbol<'_>,
    opaque_out: &mut OpaqueRefs,
) -> Option<EmittedFunction> {
    if p.name.is_empty() {
        return None;
    }
    let spelling: ResolvedSpelling = resolve_free_function_signature(catalog, p.type_index).ok()?;
    opaque_out.extend(spelling.opaque_refs.iter().cloned());
    let name: String = sanitize_identifier(&p.name.to_string());
    Some(EmittedFunction {
        name: name.clone(),
        declaration: format!("{};", spelling.declare(&name)),
    })
}

pub(crate) fn build_typedef(
    catalog: &TypeCatalog<'_>,
    u: &pdb::UserDefinedTypeSymbol<'_>,
    opaque_out: &mut OpaqueRefs,
) -> Option<EmittedTypedef> {
    if u.name.is_empty() {
        return None;
    }
    let spelling: ResolvedSpelling = spelling::resolve_spelling(catalog, u.type_index).ok()?;
    opaque_out.extend(spelling.opaque_refs.iter().cloned());
    let name: String = sanitize_identifier(&u.name.to_string());
    Some(EmittedTypedef {
        emitted_name: name.clone(),
        declaration: format!("typedef {};", spelling.declare(&name)),
    })
}
