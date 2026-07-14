use crate::error::Error;
use crate::pdb_cxx::catalog::{TypeCatalog, UdtFamily};
use crate::pdb_cxx::spelling::{
    MAX_RECURSION_BUDGET, NOTYPE_INDEX, ResolvedSpelling, SpellError, SpellResult, TypeOp,
    resolve_spelling_bounded,
};

pub(crate) fn finish_procedure(
    catalog: &TypeCatalog<'_>,
    proc: &pdb::ProcedureType,
    ops: Vec<TypeOp>,
    budget: u32,
    calling_convention: Option<&'static str>,
    mut opaque_refs: Vec<(UdtFamily, String)>,
) -> SpellResult<ResolvedSpelling> {
    let ret: ResolvedSpelling = match proc.return_type {
        Some(idx) => resolve_spelling_bounded(catalog, idx, budget)?,
        None => void_spelling(),
    };
    let (params, varargs): (Vec<String>, bool) =
        function_params(catalog, proc.argument_list, budget, &mut opaque_refs)?;
    let ResolvedSpelling {
        base_text,
        ops: ret_ops,
        degraded,
        opaque_refs: ret_opaque,
        ..
    } = ret;
    opaque_refs.extend(ret_opaque);
    let mut final_ops: Vec<TypeOp> = ops;
    final_ops.push(TypeOp::Function {
        params,
        varargs,
        calling_convention,
    });
    final_ops.extend(ret_ops);
    Ok(ResolvedSpelling {
        base_text,
        ops: final_ops,
        byte_size: None,
        degraded,
        bitfield: None,
        opaque_refs,
        value_dependency: None,
    })
}

pub(crate) fn finish_member_function(
    catalog: &TypeCatalog<'_>,
    mf: &pdb::MemberFunctionType,
    ops: Vec<TypeOp>,
    budget: u32,
    calling_convention: Option<&'static str>,
    mut opaque_refs: Vec<(UdtFamily, String)>,
) -> SpellResult<ResolvedSpelling> {
    let ret: ResolvedSpelling = resolve_spelling_bounded(catalog, mf.return_type, budget)?;
    let (params, varargs): (Vec<String>, bool) =
        function_params(catalog, mf.argument_list, budget, &mut opaque_refs)?;
    let ResolvedSpelling {
        base_text,
        ops: ret_ops,
        degraded,
        opaque_refs: ret_opaque,
        ..
    } = ret;
    opaque_refs.extend(ret_opaque);
    let mut final_ops: Vec<TypeOp> = ops;
    final_ops.push(TypeOp::Function {
        params,
        varargs,
        calling_convention,
    });
    final_ops.extend(ret_ops);
    Ok(ResolvedSpelling {
        base_text,
        ops: final_ops,
        byte_size: None,
        degraded,
        bitfield: None,
        opaque_refs,
        value_dependency: None,
    })
}

pub(crate) fn resolve_free_function_signature(
    catalog: &TypeCatalog<'_>,
    type_index: pdb::TypeIndex,
) -> SpellResult<ResolvedSpelling> {
    let data: pdb::TypeData<'_> = catalog.get(type_index)?;
    match data {
        pdb::TypeData::Procedure(proc) => {
            let cc: Option<&'static str> =
                calling_convention_keyword(proc.attributes.calling_convention());
            finish_procedure(
                catalog,
                &proc,
                Vec::new(),
                MAX_RECURSION_BUDGET,
                cc,
                Vec::new(),
            )
        }
        pdb::TypeData::MemberFunction(mf) => {
            let cc: Option<&'static str> =
                calling_convention_keyword(mf.attributes.calling_convention());
            finish_member_function(
                catalog,
                &mf,
                Vec::new(),
                MAX_RECURSION_BUDGET,
                cc,
                Vec::new(),
            )
        }
        _ => Err(SpellError::Pdb(Error::Pdb(
            "symbol type index does not refer to a function type".to_owned(),
        ))),
    }
}

fn calling_convention_keyword(code: u8) -> Option<&'static str> {
    match code {
        0x00 => Some("__cdecl"),
        0x04 => Some("__fastcall"),
        0x07 => Some("__stdcall"),
        0x0b => Some("__thiscall"),
        0x18 => Some("__vectorcall"),
        _ => None,
    }
}

fn void_spelling() -> ResolvedSpelling {
    ResolvedSpelling {
        base_text: "void".to_owned(),
        ops: Vec::new(),
        byte_size: None,
        degraded: false,
        bitfield: None,
        opaque_refs: Vec::new(),
        value_dependency: None,
    }
}

pub(crate) fn function_params(
    catalog: &TypeCatalog<'_>,
    arglist_index: pdb::TypeIndex,
    budget: u32,
    opaque_refs: &mut Vec<(UdtFamily, String)>,
) -> SpellResult<(Vec<String>, bool)> {
    let Some(next_budget) = budget.checked_sub(1) else {
        return Ok((Vec::new(), false));
    };
    let data: pdb::TypeData<'_> = catalog.get(arglist_index)?;
    let pdb::TypeData::ArgumentList(list) = data else {
        return Ok((Vec::new(), false));
    };
    let mut params: Vec<String> = Vec::with_capacity(list.arguments.len());
    let mut varargs: bool = false;
    let last: usize = list.arguments.len().saturating_sub(1);
    for (i, arg_idx) in list.arguments.iter().enumerate() {
        if *arg_idx == NOTYPE_INDEX && i == last {
            varargs = true;
            continue;
        }
        let resolved: ResolvedSpelling = resolve_spelling_bounded(catalog, *arg_idx, next_budget)?;
        opaque_refs.extend(resolved.opaque_refs.clone());
        params.push(resolved.declare_bare());
    }
    Ok((params, varargs))
}
