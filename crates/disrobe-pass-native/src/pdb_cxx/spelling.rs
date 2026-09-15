use crate::error::Error;
use crate::pdb_cxx::catalog::{TypeCatalog, UdtFamily};
use crate::pdb_cxx::declarator::build_declarator;
use crate::pdb_cxx::functions::{finish_member_function, finish_procedure};
use crate::pdb_cxx::names::sanitize_identifier;
use crate::pdb_cxx::primitive::finish_primitive;

pub(crate) const MAX_UNWRAP_DEPTH: u32 = 64;
pub(crate) const MAX_RECURSION_BUDGET: u32 = 24;
pub(crate) const NOTYPE_INDEX: pdb::TypeIndex = pdb::TypeIndex(0);

#[derive(Debug)]
pub(crate) enum SpellError {
    Pdb(Error),
    AnonymousAggregate,
}

impl From<Error> for SpellError {
    fn from(e: Error) -> Self {
        Self::Pdb(e)
    }
}

pub(crate) type SpellResult<T> = std::result::Result<T, SpellError>;

#[derive(Debug, Clone)]
pub(crate) enum TypeOp {
    Pointer {
        const_q: bool,
        volatile_q: bool,
    },
    LValueRef,
    RValueRef,
    MemberPointer {
        class_name: String,
        const_q: bool,
        volatile_q: bool,
    },
    Array(u64),
    Function {
        params: Vec<String>,
        varargs: bool,
        calling_convention: Option<&'static str>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedSpelling {
    pub(crate) base_text: String,
    pub(crate) ops: Vec<TypeOp>,
    pub(crate) byte_size: Option<u64>,
    pub(crate) degraded: bool,
    pub(crate) bitfield: Option<(u8, u8)>,
    pub(crate) opaque_refs: Vec<(UdtFamily, String)>,
    pub(crate) value_dependency: Option<u32>,
}

impl ResolvedSpelling {
    pub(crate) fn declare(&self, name: &str) -> String {
        let decl: String = build_declarator(&self.ops, name.to_owned());
        format!("{} {decl}", self.base_text)
    }

    pub(crate) fn declare_bare(&self) -> String {
        self.declare("").trim_end().to_owned()
    }
}

fn placeholder(
    ops: Vec<TypeOp>,
    opaque_refs: Vec<(UdtFamily, String)>,
    degraded: bool,
) -> ResolvedSpelling {
    ResolvedSpelling {
        base_text: "void".to_owned(),
        ops,
        byte_size: None,
        degraded,
        bitfield: None,
        opaque_refs,
        value_dependency: None,
    }
}

pub(crate) fn resolve_spelling(
    catalog: &TypeCatalog<'_>,
    index: pdb::TypeIndex,
) -> SpellResult<ResolvedSpelling> {
    resolve_spelling_bounded(catalog, index, MAX_RECURSION_BUDGET)
}

pub(crate) fn resolve_spelling_bounded(
    catalog: &TypeCatalog<'_>,
    index: pdb::TypeIndex,
    budget: u32,
) -> SpellResult<ResolvedSpelling> {
    let Some(next_budget) = budget.checked_sub(1) else {
        return Ok(placeholder(Vec::new(), Vec::new(), true));
    };
    let mut ops: Vec<TypeOp> = Vec::new();
    let mut cur: pdb::TypeIndex = index;
    let mut pending_const: bool = false;
    let mut pending_volatile: bool = false;
    let opaque_refs: Vec<(UdtFamily, String)> = Vec::new();
    for _ in 0..MAX_UNWRAP_DEPTH {
        let (resolved_index, data): (pdb::TypeIndex, pdb::TypeData<'_>) = catalog.resolve(cur)?;
        match data {
            pdb::TypeData::Primitive(p) => {
                return Ok(finish_primitive(
                    p,
                    ops,
                    pending_const,
                    pending_volatile,
                    opaque_refs,
                ));
            }
            pdb::TypeData::Modifier(m) => {
                pending_const |= m.constant;
                pending_volatile |= m.volatile;
                cur = m.underlying_type;
            }
            pdb::TypeData::Pointer(p) => {
                let const_q: bool = pending_const;
                let volatile_q: bool = pending_volatile;
                pending_const = false;
                pending_volatile = false;
                push_pointer_op(catalog, &mut ops, &p, const_q, volatile_q)?;
                cur = p.underlying_type;
            }
            pdb::TypeData::Bitfield(b) => {
                let mut inner: ResolvedSpelling =
                    resolve_spelling_bounded(catalog, b.underlying_type, next_budget)?;
                inner.bitfield = Some((b.position, b.length));
                return Ok(inner);
            }
            pdb::TypeData::Array(a) => {
                return finish_array(
                    catalog,
                    &a,
                    ops,
                    pending_const,
                    pending_volatile,
                    next_budget,
                    opaque_refs,
                );
            }
            pdb::TypeData::Procedure(proc) => {
                return finish_procedure(catalog, &proc, ops, next_budget, None, opaque_refs);
            }
            pdb::TypeData::MemberFunction(mf) => {
                return finish_member_function(catalog, &mf, ops, next_budget, None, opaque_refs);
            }
            pdb::TypeData::Class(c) => {
                return finish_class_reference(
                    &c,
                    resolved_index,
                    ops,
                    pending_const,
                    pending_volatile,
                    opaque_refs,
                );
            }
            pdb::TypeData::Union(u) => {
                return finish_union_reference(
                    resolved_index,
                    &u,
                    ops,
                    pending_const,
                    pending_volatile,
                    opaque_refs,
                );
            }
            pdb::TypeData::Enumeration(e) => {
                return finish_enum_reference(
                    catalog,
                    &e,
                    ops,
                    pending_const,
                    pending_volatile,
                    next_budget,
                    opaque_refs,
                );
            }
            _ => {
                return Ok(placeholder(ops, opaque_refs, true));
            }
        }
    }
    Ok(placeholder(ops, opaque_refs, true))
}

fn push_pointer_op(
    catalog: &TypeCatalog<'_>,
    ops: &mut Vec<TypeOp>,
    p: &pdb::PointerType,
    const_q: bool,
    volatile_q: bool,
) -> SpellResult<()> {
    match p.attributes.pointer_mode() {
        pdb::PointerMode::LValueReference => ops.push(TypeOp::LValueRef),
        pdb::PointerMode::RValueReference => ops.push(TypeOp::RValueRef),
        pdb::PointerMode::Member | pdb::PointerMode::MemberFunction => {
            let class_name: String = p.containing_class.map_or_else(
                || "void".to_owned(),
                |class_idx: pdb::TypeIndex| match catalog.resolve(class_idx) {
                    Ok((_, data)) => udt_raw_name(&data).map_or_else(
                        || "void".to_owned(),
                        |n: pdb::RawString<'_>| sanitize_identifier(&n.to_string()),
                    ),
                    Err(_) => "void".to_owned(),
                },
            );
            ops.push(TypeOp::MemberPointer {
                class_name,
                const_q,
                volatile_q,
            });
        }
        pdb::PointerMode::Pointer => ops.push(TypeOp::Pointer {
            const_q,
            volatile_q,
        }),
    }
    Ok(())
}

fn udt_raw_name<'t>(data: &pdb::TypeData<'t>) -> Option<pdb::RawString<'t>> {
    match data {
        pdb::TypeData::Class(c) => Some(c.name),
        pdb::TypeData::Union(u) => Some(u.name),
        pdb::TypeData::Enumeration(e) => Some(e.name),
        _ => None,
    }
}

pub(crate) fn apply_cv(text: String, const_q: bool, volatile_q: bool) -> String {
    let mut prefix: String = String::new();
    if const_q {
        prefix.push_str("const ");
    }
    if volatile_q {
        prefix.push_str("volatile ");
    }
    format!("{prefix}{text}")
}

fn finish_array(
    catalog: &TypeCatalog<'_>,
    a: &pdb::ArrayType,
    outer_ops: Vec<TypeOp>,
    const_q: bool,
    volatile_q: bool,
    budget: u32,
    mut opaque_refs: Vec<(UdtFamily, String)>,
) -> SpellResult<ResolvedSpelling> {
    let elem: ResolvedSpelling = resolve_spelling_bounded(catalog, a.element_type, budget)?;
    let value_dependency: Option<u32> = if outer_ops.is_empty() && elem.ops.is_empty() {
        elem.value_dependency
    } else {
        None
    };
    let counts: Vec<u64> = compute_array_dim_counts(&a.dimensions, elem.byte_size);
    let mut all_ops: Vec<TypeOp> = outer_ops;
    for count in counts.into_iter().rev() {
        all_ops.push(TypeOp::Array(count));
    }
    all_ops.extend(elem.ops);
    opaque_refs.extend(elem.opaque_refs);
    let total_bytes: Option<u64> = a.dimensions.last().map(|d: &u32| u64::from(*d));
    Ok(ResolvedSpelling {
        base_text: apply_cv(elem.base_text, const_q, volatile_q),
        ops: all_ops,
        byte_size: total_bytes,
        degraded: elem.degraded,
        bitfield: None,
        opaque_refs,
        value_dependency,
    })
}

fn compute_array_dim_counts(dims: &[u32], elem_size: Option<u64>) -> Vec<u64> {
    let Some(elem_size) = elem_size.filter(|s: &u64| *s > 0) else {
        return dims
            .last()
            .map_or_else(Vec::new, |d: &u32| vec![u64::from(*d)]);
    };
    let mut counts: Vec<u64> = Vec::with_capacity(dims.len());
    let mut prev: u64 = elem_size;
    for &d in dims {
        let d: u64 = u64::from(d);
        let count: u64 = d.checked_div(prev).unwrap_or(0);
        counts.push(count);
        prev = d;
    }
    counts
}

fn finish_class_reference(
    c: &pdb::ClassType<'_>,
    resolved_index: pdb::TypeIndex,
    ops: Vec<TypeOp>,
    const_q: bool,
    volatile_q: bool,
    mut opaque_refs: Vec<(UdtFamily, String)>,
) -> SpellResult<ResolvedSpelling> {
    if c.name.is_empty() {
        return Err(SpellError::AnonymousAggregate);
    }
    let keyword: &str = match c.kind {
        pdb::ClassKind::Class | pdb::ClassKind::Interface => "class",
        pdb::ClassKind::Struct => "struct",
    };
    let name: String = sanitize_identifier(&c.name.to_string());
    if c.properties.forward_reference() {
        opaque_refs.push((UdtFamily::ClassLike, name.clone()));
    }
    let value_dependency: Option<u32> = ops.is_empty().then_some(resolved_index.0);
    Ok(ResolvedSpelling {
        base_text: apply_cv(format!("{keyword} {name}"), const_q, volatile_q),
        ops,
        byte_size: Some(c.size),
        degraded: false,
        bitfield: None,
        opaque_refs,
        value_dependency,
    })
}

fn finish_union_reference(
    resolved_index: pdb::TypeIndex,
    u: &pdb::UnionType<'_>,
    ops: Vec<TypeOp>,
    const_q: bool,
    volatile_q: bool,
    mut opaque_refs: Vec<(UdtFamily, String)>,
) -> SpellResult<ResolvedSpelling> {
    if u.name.is_empty() {
        return Err(SpellError::AnonymousAggregate);
    }
    let name: String = sanitize_identifier(&u.name.to_string());
    if u.properties.forward_reference() {
        opaque_refs.push((UdtFamily::Union, name.clone()));
    }
    let value_dependency: Option<u32> = ops.is_empty().then_some(resolved_index.0);
    Ok(ResolvedSpelling {
        base_text: apply_cv(format!("union {name}"), const_q, volatile_q),
        ops,
        byte_size: Some(u.size),
        degraded: false,
        bitfield: None,
        opaque_refs,
        value_dependency,
    })
}

fn finish_enum_reference(
    catalog: &TypeCatalog<'_>,
    e: &pdb::EnumerationType<'_>,
    ops: Vec<TypeOp>,
    const_q: bool,
    volatile_q: bool,
    budget: u32,
    mut opaque_refs: Vec<(UdtFamily, String)>,
) -> SpellResult<ResolvedSpelling> {
    if e.name.is_empty() {
        return Err(SpellError::AnonymousAggregate);
    }
    let name: String = sanitize_identifier(&e.name.to_string());
    let underlying: ResolvedSpelling =
        resolve_spelling_bounded(catalog, e.underlying_type, budget)?;
    if e.properties.forward_reference() {
        opaque_refs.push((UdtFamily::Enum, name.clone()));
    }
    Ok(ResolvedSpelling {
        base_text: apply_cv(format!("enum {name}"), const_q, volatile_q),
        ops,
        byte_size: underlying.byte_size,
        degraded: false,
        bitfield: None,
        opaque_refs,
        value_dependency: None,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn array_dim_counts_match_multidim_worked_example() {
        let dims: [u32; 2] = [12, 24];
        let counts: Vec<u64> = compute_array_dim_counts(&dims, Some(4));
        assert_eq!(counts, vec![3, 2]);
    }

    #[test]
    fn array_dim_counts_handle_single_dimension() {
        let dims: [u32; 1] = [16];
        let counts: Vec<u64> = compute_array_dim_counts(&dims, Some(4));
        assert_eq!(counts, vec![4]);
    }
}
