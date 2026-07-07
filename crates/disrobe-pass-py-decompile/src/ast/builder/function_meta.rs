use super::exprs::{
    DR_BUILD_CLASS_MARKER, DR_CODE_CONST_PREFIX, DR_NULL_MARKER, DR_TYPE_ALIAS_MARKER,
    DR_TYPEVAR_MARKER, StackSim, build_linear_stmts_sim, is_build_class_marker, load_local,
    load_name, local_name_at, name_at, object_to_const,
};
use super::postprocess::{
    BodyKind, parse_annotation_string, postprocess_body, strip_generator_stopiteration_raise,
    strip_module_docstring_stmt, strip_module_implicit_return,
};
use super::stmts::{
    PY_CO_FLAG_ASYNC_GENERATOR, PY_CO_FLAG_COROUTINE, PY_CO_FLAG_GENERATOR,
    function_args_from_code, last_significant_back, loads_none, resolve_jump_target,
    structure_stmts,
};
use super::try_with::is_forward_cond_jump;
use super::{
    CodeObjDepthGuard, DecodedStream, NestedCodeScope, class_docstring, decode_stream,
    decode_stream_with_offsets, enter_codeobj_depth, extract_docstring, future_annotations_active,
    pick_nested_version,
};
use crate::ast::node::{Arguments, ConstValue, Expr, ExprCtx, Stmt};
use crate::bytecode::opcode::{CanonicalOp, CmpOp, OpcodeMap, is_deref_local, map_for};
use crate::bytecode::version::PyVersion;
use crate::error::{DecompileError, Result};
use disrobe_py_marshal::{CodeObject, Object};

fn thread_class_annotations(mut body: Vec<Stmt>) -> Vec<Stmt> {
    let annotations: Vec<(String, Expr)> = body
        .iter()
        .find_map(|s: &Stmt| match s {
            Stmt::FunctionDef {
                name,
                body: fn_body,
                ..
            } if name == "__annotate_func__" => Some(class_annotation_pairs(fn_body)),
            _ => None,
        })
        .unwrap_or_default();
    if annotations.is_empty() {
        return body;
    }
    body.retain(
        |s: &Stmt| !matches!(s, Stmt::FunctionDef { name, .. } if name == "__annotate_func__"),
    );
    let mut threaded: Vec<Stmt> = Vec::with_capacity(body.len() + annotations.len());
    let mut consumed: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for (name, annotation) in &annotations {
        let existing: Option<usize> = body.iter().position(|s: &Stmt| match s {
            Stmt::Assign { targets, .. } => matches!(
                targets.as_slice(),
                [Expr::Name { id, .. }] if id == name
            ),
            _ => false,
        });
        match existing {
            Some(pos) => {
                consumed.insert(pos);
                let Stmt::Assign { value, line, .. }: Stmt = body[pos].clone() else {
                    continue;
                };
                threaded.push(Stmt::AnnAssign {
                    target: Expr::Name {
                        id: name.clone(),
                        ctx: ExprCtx::Store,
                        line: None,
                    },
                    annotation: annotation.clone(),
                    value: Some(value),
                    simple: true,
                    line,
                });
            }
            None => threaded.push(Stmt::AnnAssign {
                target: Expr::Name {
                    id: name.clone(),
                    ctx: ExprCtx::Store,
                    line: None,
                },
                annotation: annotation.clone(),
                value: None,
                simple: true,
                line: None,
            }),
        }
    }
    for (pos, stmt) in body.into_iter().enumerate() {
        if !consumed.contains(&pos) {
            threaded.push(stmt);
        }
    }
    threaded
}

pub(super) fn thread_module_annotations(mut body: Vec<Stmt>) -> Vec<Stmt> {
    let annotations: Vec<(String, Expr)> = body
        .iter()
        .find_map(|s: &Stmt| match s {
            Stmt::FunctionDef {
                name,
                body: fn_body,
                ..
            } if name == "__annotate__" => Some(module_annotation_pairs(fn_body)),
            _ => None,
        })
        .unwrap_or_default();
    if annotations.is_empty() {
        return body;
    }
    body.retain(|s: &Stmt| {
        !matches!(s, Stmt::FunctionDef { name, .. } if name == "__annotate__")
            && !is_conditional_annotations_membership(s)
    });
    let mut threaded: Vec<Stmt> = Vec::with_capacity(body.len() + annotations.len());
    for stmt in body {
        let upgrade: Option<(String, Expr)> = match &stmt {
            Stmt::Assign { targets, .. } => match targets.as_slice() {
                [Expr::Name { id, .. }] => annotations
                    .iter()
                    .find(|(name, _): &&(String, Expr)| name == id)
                    .map(|(name, annotation): &(String, Expr)| (name.clone(), annotation.clone())),
                _ => None,
            },
            _ => None,
        };
        match (upgrade, stmt) {
            (Some((name, annotation)), Stmt::Assign { value, line, .. }) => {
                threaded.push(Stmt::AnnAssign {
                    target: Expr::Name {
                        id: name,
                        ctx: ExprCtx::Store,
                        line: None,
                    },
                    annotation,
                    value: Some(value),
                    simple: true,
                    line,
                });
            }
            (_, stmt) => threaded.push(stmt),
        }
    }
    let assigned: std::collections::BTreeSet<&String> = threaded
        .iter()
        .filter_map(|s: &Stmt| match s {
            Stmt::AnnAssign {
                target: Expr::Name { id, .. },
                ..
            } => Some(id),
            _ => None,
        })
        .collect();
    let bare: Vec<Stmt> = annotations
        .iter()
        .filter(|(name, _): &&(String, Expr)| !assigned.contains(name))
        .map(|(name, annotation): &(String, Expr)| Stmt::AnnAssign {
            target: Expr::Name {
                id: name.clone(),
                ctx: ExprCtx::Store,
                line: None,
            },
            annotation: annotation.clone(),
            value: None,
            simple: true,
            line: None,
        })
        .collect();
    threaded.splice(0..0, bare);
    threaded
}

fn module_annotation_pairs(fn_body: &[Stmt]) -> Vec<(String, Expr)> {
    let mut pairs: Vec<(String, Expr)> = Vec::new();
    for stmt in fn_body {
        match stmt {
            Stmt::If { test, body, .. } if is_conditional_annotations_test(test) => {
                for inner in body {
                    if let Some(pair) = module_annotation_subscript_pair(inner) {
                        pairs.push(pair);
                    }
                }
            }
            _ => {
                if let Some(pair) = module_annotation_subscript_pair(stmt) {
                    pairs.push(pair);
                }
            }
        }
    }
    pairs
}

fn module_annotation_subscript_pair(stmt: &Stmt) -> Option<(String, Expr)> {
    let Stmt::Assign { targets, .. }: &Stmt = stmt else {
        return None;
    };
    let [
        Expr::Subscript {
            value: base, slice, ..
        },
    ]: &[Expr] = targets.as_slice()
    else {
        return None;
    };
    let Expr::Constant {
        value: ConstValue::Str(name),
        ..
    }: &Expr = slice.as_ref()
    else {
        return None;
    };
    Some((name.clone(), unstringify_annotation((**base).clone())))
}

fn is_conditional_annotations_test(test: &Expr) -> bool {
    let Expr::Compare {
        ops, comparators, ..
    }: &Expr = test
    else {
        return false;
    };
    matches!(ops.as_slice(), [CmpOp::In])
        && matches!(
            comparators.as_slice(),
            [Expr::Name { id, .. }] if id == "__conditional_annotations__"
        )
}

fn is_conditional_annotations_membership(s: &Stmt) -> bool {
    let Stmt::Expr(expr): &Stmt = s else {
        return false;
    };
    matches!(expr, Expr::Name { id, .. } if id == "__conditional_annotations__")
}

fn class_annotation_pairs(fn_body: &[Stmt]) -> Vec<(String, Expr)> {
    let mut pairs: Vec<(String, Expr)> = Vec::new();
    collect_class_annotation_pairs(fn_body, &mut pairs);
    pairs
}

fn collect_class_annotation_pairs(stmts: &[Stmt], pairs: &mut Vec<(String, Expr)>) {
    for stmt in stmts {
        match stmt {
            Stmt::If { body, orelse, .. } => {
                collect_class_annotation_pairs(body, pairs);
                collect_class_annotation_pairs(orelse, pairs);
            }
            Stmt::Assign { targets, value, .. } => {
                let [
                    Expr::Subscript {
                        value: base, slice, ..
                    },
                ]: &[Expr] = targets.as_slice()
                else {
                    continue;
                };
                if !is_class_annotation_base(base.as_ref()) {
                    continue;
                }
                let Expr::Constant {
                    value: ConstValue::Str(name),
                    ..
                }: &Expr = slice.as_ref()
                else {
                    continue;
                };
                pairs.push((name.clone(), unstringify_annotation(value.clone())));
            }
            _ => {}
        }
    }
}

fn is_class_annotation_base(base: &Expr) -> bool {
    match base {
        Expr::Name { id, .. } => id == "__classdict__",
        Expr::Dict { keys, values } => keys.is_empty() && values.is_empty(),
        _ => false,
    }
}

pub(super) fn try_build_class_def(
    parent: &CodeObject,
    value: &Expr,
    target_name: &str,
) -> Option<Stmt> {
    let Expr::Call {
        func,
        args,
        keywords,
    } = value
    else {
        return None;
    };
    if !is_build_class_marker(func) {
        return None;
    }
    if args.len() < 2 {
        return None;
    }
    let const_idx: u32 = nested_code_index(&args[0])?;
    let bases: Vec<Expr> = args.iter().skip(2).cloned().collect();
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let stream: DecodedStream = decode_stream_with_offsets(nested, opmap.as_ref(), &nested_version);
    let body_raw: Vec<Stmt> = {
        let _code_scope: NestedCodeScope = NestedCodeScope::enter();
        structure_stmts(nested, &stream, 0, stream.ops.len()).unwrap_or_default()
    };
    let stripped: Vec<Stmt> = strip_class_implicit(strip_module_implicit_return(
        strip_module_docstring_stmt(body_raw, nested),
    ));
    let processed: Vec<Stmt> =
        thread_class_annotations(postprocess_body(stripped, BodyKind::Class));
    let final_body: Vec<Stmt> = if processed.is_empty() {
        vec![Stmt::Pass]
    } else {
        processed
    };
    Some(Stmt::ClassDef {
        name: target_name.to_owned(),
        type_params: Vec::new(),
        bases,
        keywords: keywords.clone(),
        body: final_body,
        decorators: Vec::new(),
        docstring: class_docstring(nested, &stream.ops),
        line: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TypeParamKind {
    TypeVar,
    ParamSpec,
    TypeVarTuple,
}

pub(super) fn type_param_kind_from_intrinsic1(op: u8) -> Option<TypeParamKind> {
    match op {
        7 => Some(TypeParamKind::TypeVar),
        8 => Some(TypeParamKind::ParamSpec),
        9 => Some(TypeParamKind::TypeVarTuple),
        _ => None,
    }
}

pub(super) fn unwrap_evaluator_expr(parent: &CodeObject, marker: &Expr) -> Option<Expr> {
    let const_idx: u32 = nested_code_index(marker)?;
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(nested, opmap.as_ref(), &nested_version);
    if let Some(unpack) = starred_default_unpack_index(&ops) {
        let (_stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(nested, &ops[..unpack]).ok()?;
        let inner: Expr = residual.into_iter().next_back()?;
        return Some(Expr::Starred {
            value: Box::new(inner),
            ctx: ExprCtx::Load,
        });
    }
    let (stmts, residual): (Vec<Stmt>, Vec<Expr>) = build_linear_stmts_sim(nested, &ops).ok()?;
    stmts
        .into_iter()
        .rev()
        .find_map(|s: Stmt| match s {
            Stmt::Return(Some(e)) | Stmt::Expr(e) => Some(e),
            _ => None,
        })
        .or_else(|| residual.into_iter().next_back())
}

fn starred_default_unpack_index(ops: &[CanonicalOp]) -> Option<usize> {
    let ret: usize = ops
        .iter()
        .rposition(|op: &CanonicalOp| {
            matches!(op, CanonicalOp::Return | CanonicalOp::ReturnConst(_))
        })
        .unwrap_or(ops.len());
    let unpack: usize = (0..ret).rev().find(|&k: &usize| {
        !matches!(
            ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    })?;
    matches!(ops[unpack], CanonicalOp::UnpackSequence(1)).then_some(unpack)
}

pub(super) fn annotate_codeobj_dict(parent: &CodeObject, marker: &Expr) -> Option<Expr> {
    let const_idx: u32 = nested_code_index(marker)?;
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let name: &str = match &nested.name {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.as_str(),
        _ => "",
    };
    if name != "__annotate__" {
        return None;
    }
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(nested, opmap.as_ref(), &nested_version);
    let (stmts, residual): (Vec<Stmt>, Vec<Expr>) = build_linear_stmts_sim(nested, &ops).ok()?;
    stmts
        .into_iter()
        .rev()
        .find_map(|s: Stmt| match s {
            Stmt::Return(Some(e @ Expr::Dict { .. })) => Some(e),
            _ => None,
        })
        .or_else(|| {
            residual
                .into_iter()
                .rev()
                .find(|e: &Expr| matches!(e, Expr::Dict { .. }))
        })
}

fn encode_typevar_marker(kind: TypeParamKind, name: &str) -> String {
    let tag: char = match kind {
        TypeParamKind::TypeVar => 'T',
        TypeParamKind::ParamSpec => 'P',
        TypeParamKind::TypeVarTuple => 'V',
    };
    format!("{DR_TYPEVAR_MARKER}{tag}\u{1F}{name}__")
}

pub(super) fn build_typevar_marker(kind: TypeParamKind, name: &str, bound: Option<Expr>) -> Expr {
    let head: Expr = Expr::Name {
        id: encode_typevar_marker(kind, name),
        ctx: ExprCtx::Load,
        line: None,
    };
    match bound {
        Some(b) => Expr::Call {
            func: Box::new(head),
            args: vec![b],
            keywords: Vec::new(),
        },
        None => head,
    }
}

pub(super) fn is_typevar_marker(expr: &Expr) -> bool {
    let head: &Expr = match expr {
        Expr::Call { func, args, .. } if args.len() == 1 => func.as_ref(),
        other => other,
    };
    matches!(head, Expr::Name { id, .. } if id.starts_with(DR_TYPEVAR_MARKER))
}

pub(super) fn type_alias_marker_call(name: &str, value: Expr) -> Expr {
    Expr::Call {
        func: Box::new(Expr::Name {
            id: DR_TYPE_ALIAS_MARKER.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        args: vec![
            Expr::Constant {
                value: ConstValue::Str(name.to_owned()),
                line: None,
            },
            value,
        ],
        keywords: Vec::new(),
    }
}

pub(super) fn try_build_type_alias(value: &Expr, target_name: &str) -> Option<Stmt> {
    let Expr::Call { func, args, .. } = value else {
        return None;
    };
    if !matches!(func.as_ref(), Expr::Name { id, .. } if id == DR_TYPE_ALIAS_MARKER) {
        return None;
    }
    let alias_value: Expr = args.get(1).cloned()?;
    Some(Stmt::TypeAlias {
        name: target_name.to_owned(),
        type_params: Vec::new(),
        value: alias_value,
        line: None,
    })
}

fn is_generic_wrapper(wrapper: &CodeObject) -> bool {
    let nested_version: PyVersion = pick_nested_version(wrapper);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(wrapper, opmap.as_ref(), &nested_version);
    ops.iter().any(|op: &CanonicalOp| {
        matches!(
            op,
            CanonicalOp::CallIntrinsic2(4) | CanonicalOp::CallIntrinsic1(10)
        )
    })
}

fn collect_wrapper_type_params(
    wrapper: &CodeObject,
    ops: &[CanonicalOp],
) -> Vec<crate::ast::node::TypeParam> {
    use crate::ast::node::TypeParam;
    let mut params: Vec<TypeParam> = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        match op {
            CanonicalOp::CallIntrinsic1(code) => {
                let Some(kind): Option<TypeParamKind> = type_param_kind_from_intrinsic1(*code)
                else {
                    continue;
                };
                if let Some(name) = prev_load_const_str(wrapper, ops, i) {
                    params.push(match kind {
                        TypeParamKind::TypeVar => TypeParam::TypeVar {
                            name,
                            bound: None,
                            default: None,
                        },
                        TypeParamKind::ParamSpec => TypeParam::ParamSpec {
                            name,
                            default: None,
                        },
                        TypeParamKind::TypeVarTuple => TypeParam::TypeVarTuple {
                            name,
                            default: None,
                        },
                    });
                }
            }
            CanonicalOp::CallIntrinsic2(2 | 3) => {
                let eval_idx: Option<usize> = prev_make_function_const(ops, i);
                let bound: Option<Expr> = eval_idx
                    .and_then(|j: usize| match ops[j] {
                        CanonicalOp::LoadConst(slot) => Some(slot),
                        _ => None,
                    })
                    .and_then(|slot: u32| {
                        unwrap_evaluator_expr(
                            wrapper,
                            &Expr::Name {
                                id: format!("{DR_CODE_CONST_PREFIX}{slot}__"),
                                ctx: ExprCtx::Load,
                                line: None,
                            },
                        )
                    });
                if let Some(name) =
                    nearest_load_const_str_before(wrapper, ops, eval_idx.unwrap_or(i))
                {
                    params.push(TypeParam::TypeVar {
                        name,
                        bound,
                        default: None,
                    });
                }
            }
            CanonicalOp::CallIntrinsic2(5) => {
                let Some(default): Option<Expr> = prev_make_function_const(ops, i)
                    .and_then(|j: usize| match ops[j] {
                        CanonicalOp::LoadConst(slot) => Some(slot),
                        _ => None,
                    })
                    .and_then(|slot: u32| {
                        unwrap_evaluator_expr(
                            wrapper,
                            &Expr::Name {
                                id: format!("{DR_CODE_CONST_PREFIX}{slot}__"),
                                ctx: ExprCtx::Load,
                                line: None,
                            },
                        )
                    })
                else {
                    continue;
                };
                if let Some(param) = params.last_mut() {
                    match param {
                        TypeParam::TypeVar { default: slot, .. }
                        | TypeParam::ParamSpec { default: slot, .. }
                        | TypeParam::TypeVarTuple { default: slot, .. } => {
                            *slot = Some(default);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    params
}

fn prev_make_function_const(ops: &[CanonicalOp], idx: usize) -> Option<usize> {
    let mut k: usize = idx;
    while k > 0 {
        k -= 1;
        if matches!(ops[k], CanonicalOp::MakeFunction(_)) {
            let mut j: usize = k;
            while j > 0 {
                j -= 1;
                match ops[j] {
                    CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
                    CanonicalOp::LoadConst(_) => return Some(j),
                    _ => return None,
                }
            }
            return None;
        }
    }
    None
}

fn nearest_load_const_str_before(
    code: &CodeObject,
    ops: &[CanonicalOp],
    idx: usize,
) -> Option<String> {
    let mut k: usize = idx;
    while k > 0 {
        k -= 1;
        if let CanonicalOp::LoadConst(slot) = ops[k]
            && let Ok(Expr::Constant {
                value: ConstValue::Str(s),
                ..
            }) = load_const(code, slot, k)
        {
            return Some(s);
        }
    }
    None
}

fn prev_load_const_str(code: &CodeObject, ops: &[CanonicalOp], idx: usize) -> Option<String> {
    let mut k: usize = idx;
    while k > 0 {
        k -= 1;
        match ops[k] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::LoadConst(slot) => {
                return load_const(code, slot, k).ok().and_then(|e: Expr| match e {
                    Expr::Constant {
                        value: ConstValue::Str(s),
                        ..
                    } => Some(s),
                    _ => None,
                });
            }
            _ => return None,
        }
    }
    None
}

pub(super) fn try_build_generic_def(
    parent: &CodeObject,
    value: &Expr,
    target_name: &str,
) -> Option<Stmt> {
    let Expr::Call { func, args, .. } = value else {
        return None;
    };
    if args.len() > 1 {
        return None;
    }
    let const_idx: u32 = nested_code_index(func)?;
    let wrapper: &CodeObject = nested_code_object_at(parent, const_idx)?;
    if !is_generic_wrapper(wrapper) {
        return None;
    }
    let value_defaults: Vec<Expr> = args.first().map(value_default_tuple).unwrap_or_default();
    extract_generic(wrapper, target_name, &value_defaults)
}

fn value_default_tuple(arg: &Expr) -> Vec<Expr> {
    defaults_from_expr(arg.clone())
}

pub(super) fn try_build_decorated_generic_def(
    parent: &CodeObject,
    value: &Expr,
    target_name: &str,
) -> Option<Stmt> {
    let mut decorators: Vec<Expr> = Vec::new();
    let mut cursor: &Expr = value;
    loop {
        let Expr::Call {
            func,
            args,
            keywords,
        } = cursor
        else {
            return None;
        };
        if let Some(const_idx) = nested_code_index(func) {
            if decorators.is_empty() {
                return None;
            }
            if args.len() > 1 {
                return None;
            }
            let wrapper: &CodeObject = nested_code_object_at(parent, const_idx)?;
            if !is_generic_wrapper(wrapper) {
                return None;
            }
            let value_defaults: Vec<Expr> =
                args.first().map(value_default_tuple).unwrap_or_default();
            let mut def: Stmt = extract_generic(wrapper, target_name, &value_defaults)?;
            match &mut def {
                Stmt::ClassDef {
                    decorators: slot, ..
                }
                | Stmt::FunctionDef {
                    decorators: slot, ..
                } => *slot = decorators,
                _ => return None,
            }
            return Some(def);
        }
        if args.len() != 1 || !keywords.is_empty() {
            return None;
        }
        decorators.push((**func).clone());
        cursor = &args[0];
    }
}

pub(super) fn try_build_generic_type_alias(
    parent: &CodeObject,
    value: &Expr,
    target_name: &str,
) -> Option<Stmt> {
    let Expr::Call { func, args, .. } = value else {
        return None;
    };
    if !args.is_empty() {
        return None;
    }
    let const_idx: u32 = nested_code_index(func)?;
    let wrapper: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let nested_version: PyVersion = pick_nested_version(wrapper);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(wrapper, opmap.as_ref(), &nested_version);
    let alias_intrinsic: usize = ops
        .iter()
        .position(|op: &CanonicalOp| matches!(op, CanonicalOp::CallIntrinsic1(11)))?;
    let type_params: Vec<crate::ast::node::TypeParam> = collect_wrapper_type_params(wrapper, &ops);
    let eval_idx: usize = prev_make_function_const(&ops, alias_intrinsic)?;
    let eval_slot: u32 = match ops[eval_idx] {
        CanonicalOp::LoadConst(slot) => slot,
        _ => return None,
    };
    let alias_value: Expr = unwrap_evaluator_expr(
        wrapper,
        &Expr::Name {
            id: format!("{DR_CODE_CONST_PREFIX}{eval_slot}__"),
            ctx: ExprCtx::Load,
            line: None,
        },
    )?;
    Some(Stmt::TypeAlias {
        name: target_name.to_owned(),
        type_params,
        value: alias_value,
        line: None,
    })
}

fn extract_generic(
    wrapper: &CodeObject,
    target_name: &str,
    value_defaults: &[Expr],
) -> Option<Stmt> {
    let nested_version: PyVersion = pick_nested_version(wrapper);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(wrapper, opmap.as_ref(), &nested_version);
    let type_params: Vec<crate::ast::node::TypeParam> = collect_wrapper_type_params(wrapper, &ops);
    let is_class: bool = ops
        .iter()
        .any(|op: &CanonicalOp| matches!(op, CanonicalOp::CallIntrinsic1(10)));
    let inner_idx: u32 = generic_inner_code_index(wrapper, &ops, is_class)?;
    if is_class {
        extract_generic_class(wrapper, inner_idx, target_name, type_params)
    } else {
        extract_generic_function(wrapper, inner_idx, target_name, type_params, value_defaults)
    }
}

fn generic_inner_code_index(
    wrapper: &CodeObject,
    ops: &[CanonicalOp],
    is_class: bool,
) -> Option<u32> {
    if is_class {
        let build_class: usize = ops
            .iter()
            .position(|op: &CanonicalOp| matches!(op, CanonicalOp::LoadBuildClass))?;
        for (i, op) in ops.iter().enumerate().skip(build_class) {
            if matches!(op, CanonicalOp::MakeFunction(_))
                && let Some(j) = prev_load_const_code(wrapper, ops, i)
            {
                return Some(j);
            }
        }
        None
    } else {
        let set_tp: usize = ops
            .iter()
            .position(|op: &CanonicalOp| matches!(op, CanonicalOp::CallIntrinsic2(4)))?;
        let mut last_make: Option<usize> = None;
        for (i, op) in ops.iter().enumerate().take(set_tp) {
            if matches!(op, CanonicalOp::MakeFunction(_)) {
                last_make = Some(i);
            }
        }
        last_make.and_then(|i: usize| prev_load_const_code(wrapper, ops, i))
    }
}

fn prev_load_const_code(code: &CodeObject, ops: &[CanonicalOp], make_idx: usize) -> Option<u32> {
    let mut k: usize = make_idx;
    while k > 0 {
        k -= 1;
        if let CanonicalOp::LoadConst(slot) = ops[k]
            && nested_code_object_at(code, slot).is_some()
        {
            return Some(slot);
        }
    }
    None
}

fn extract_generic_function(
    wrapper: &CodeObject,
    inner_idx: u32,
    target_name: &str,
    type_params: Vec<crate::ast::node::TypeParam>,
    value_defaults: &[Expr],
) -> Option<Stmt> {
    let mut fn_def: Stmt =
        build_nested_function_def(wrapper, inner_idx, target_name.to_owned(), false)?;
    if let Some(meta) = generic_inner_function_meta(wrapper, inner_idx) {
        attach_fn_meta(&mut fn_def, &meta);
    }
    if let Stmt::FunctionDef {
        type_params: tp,
        args,
        ..
    } = &mut fn_def
    {
        *tp = type_params;
        if args.defaults.is_empty() && !value_defaults.is_empty() {
            args.defaults = value_defaults.to_vec();
        }
    }
    Some(fn_def)
}

fn generic_inner_function_meta(wrapper: &CodeObject, inner_idx: u32) -> Option<FunctionMeta> {
    let nested_version: PyVersion = pick_nested_version(wrapper);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(wrapper, opmap.as_ref(), &nested_version);
    let mut sim: StackSim = StackSim::new();
    let mut fn_meta: std::collections::BTreeMap<u32, FunctionMeta> =
        std::collections::BTreeMap::new();
    for (idx, op) in ops.iter().enumerate() {
        match op {
            CanonicalOp::LoadConst(i) => {
                if let Ok(e) = load_const(wrapper, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadName(i) | CanonicalOp::LoadGlobal(i) => {
                if let Ok(e) = load_name(wrapper, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadFromDictOrGlobals(i) => {
                let _mapping: Expr = sim.pop_or_synth(wrapper, idx);
                if let Ok(e) = load_name(wrapper, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadFast(i) | CanonicalOp::LoadFastAndClear(i) => {
                if let Ok(e) = load_local(wrapper, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadFastLoadFast(a, b) => {
                if let (Ok(ea), Ok(eb)) =
                    (load_local(wrapper, *a, idx), load_local(wrapper, *b, idx))
                {
                    sim.push(ea);
                    sim.push(eb);
                }
            }
            CanonicalOp::LoadSubscr => {
                let slice: Expr = sim.pop_or_synth(wrapper, idx);
                let value: Expr = sim.pop_or_synth(wrapper, idx);
                sim.push(Expr::Subscript {
                    value: Box::new(value),
                    slice: Box::new(slice),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::BinaryOp(op_kind) => {
                let right: Expr = sim.pop_or_synth(wrapper, idx);
                let left: Expr = sim.pop_or_synth(wrapper, idx);
                sim.push(Expr::BinOp {
                    left: Box::new(left),
                    op: *op_kind,
                    right: Box::new(right),
                });
            }
            CanonicalOp::BuildTuple(n) => {
                let elts: Vec<Expr> = sim.pop_n(*n as usize);
                sim.push(Expr::Tuple {
                    elts,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::MakeFunction(flags) => {
                let top: Option<Expr> = sim.try_pop();
                if let Some(marker) = top {
                    let meta: FunctionMeta = make_function_meta(*flags, &mut sim);
                    if let Some(ci) = nested_code_index(&marker) {
                        fn_meta.insert(ci, meta);
                    }
                    sim.push(marker);
                }
            }
            CanonicalOp::SetFunctionAttribute(flag) => {
                let func: Option<Expr> = sim.try_pop();
                let attr: Option<Expr> = sim.try_pop();
                if let (Some(f), Some(a)) = (&func, attr)
                    && let Some(ci) = nested_code_index(f)
                {
                    let entry: &mut FunctionMeta = fn_meta.entry(ci).or_default();
                    match flag {
                        1 => entry.defaults = defaults_from_expr(a),
                        2 => entry.kw_defaults = kwdefaults_from_expr(a),
                        4 => {
                            let (params, ret): (Vec<(String, Expr)>, Option<Expr>) =
                                annotations_from_expr(a);
                            entry.annotations = params;
                            entry.returns = ret;
                        }
                        16 => {
                            if let Some(dict) = annotate_codeobj_dict(wrapper, &a) {
                                let (params, ret): (Vec<(String, Expr)>, Option<Expr>) =
                                    annotations_from_expr(dict);
                                entry.annotations = params;
                                entry.returns = ret;
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(f) = func {
                    sim.push(f);
                }
            }
            CanonicalOp::Swap(n) => sim.swap(usize::from(*n)),
            CanonicalOp::Copy(n) => {
                if let Some(v) = sim.peek_at(usize::from(*n)) {
                    sim.push(v);
                }
            }
            CanonicalOp::StoreFast(_) => {
                let _ = sim.try_pop();
            }
            _ => {}
        }
    }
    fn_meta.remove(&inner_idx)
}

fn extract_generic_class(
    wrapper: &CodeObject,
    inner_idx: u32,
    target_name: &str,
    type_params: Vec<crate::ast::node::TypeParam>,
) -> Option<Stmt> {
    let explicit_bases: Vec<Expr> = collect_generic_class_bases(wrapper);
    let mut args: Vec<Expr> = vec![
        Expr::Name {
            id: format!("{DR_CODE_CONST_PREFIX}{inner_idx}__"),
            ctx: ExprCtx::Load,
            line: None,
        },
        Expr::Constant {
            value: ConstValue::Str(target_name.to_owned()),
            line: None,
        },
    ];
    args.extend(explicit_bases);
    let build_class_value: Expr = Expr::Call {
        func: Box::new(Expr::Name {
            id: DR_BUILD_CLASS_MARKER.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        args,
        keywords: Vec::new(),
    };
    let mut class_def: Stmt = try_build_class_def(wrapper, &build_class_value, target_name)?;
    if let Stmt::ClassDef {
        type_params: tp,
        body,
        ..
    } = &mut class_def
    {
        *tp = type_params;
        body.retain(|s: &Stmt| !is_type_params_setup_assign(s));
        if body.is_empty() {
            body.push(Stmt::Pass);
        }
    }
    Some(class_def)
}

fn collect_generic_class_bases(wrapper: &CodeObject) -> Vec<Expr> {
    let nested_version: PyVersion = pick_nested_version(wrapper);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(wrapper, opmap.as_ref(), &nested_version);
    let Some(subscript_idx): Option<usize> = ops
        .iter()
        .position(|op: &CanonicalOp| matches!(op, CanonicalOp::CallIntrinsic1(10)))
    else {
        return Vec::new();
    };
    let mut sim: StackSim = StackSim::new();
    for (idx, op) in ops.iter().enumerate().skip(subscript_idx + 1) {
        match op {
            CanonicalOp::LoadConst(i) => {
                if let Ok(e) = load_const(wrapper, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadSmallInt(v) => sim.push(Expr::Constant {
                value: ConstValue::Int(i128::from(*v)),
                line: None,
            }),
            CanonicalOp::LoadName(i)
            | CanonicalOp::LoadGlobal(i)
            | CanonicalOp::LoadFromDictOrGlobals(i) => {
                if let Ok(e) = load_name(wrapper, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadFast(i)
            | CanonicalOp::LoadFastAndClear(i)
            | CanonicalOp::LoadFromDictOrDeref(i) => {
                if let Ok(e) = load_local(wrapper, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadFastLoadFast(a, b) => {
                if let (Ok(ea), Ok(eb)) =
                    (load_local(wrapper, *a, idx), load_local(wrapper, *b, idx))
                {
                    sim.push(ea);
                    sim.push(eb);
                }
            }
            CanonicalOp::StoreFastLoadFast(_, b) => {
                let _ = sim.try_pop();
                if let Ok(e) = load_local(wrapper, *b, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadAttr(i) => {
                let value: Expr = sim.pop_or_synth(wrapper, idx);
                if let Ok(attr) = name_at(&wrapper.names, *i, idx, "name") {
                    sim.push(Expr::Attribute {
                        value: Box::new(value),
                        attr,
                        ctx: ExprCtx::Load,
                    });
                }
            }
            CanonicalOp::LoadSubscr => {
                let slice: Expr = sim.pop_or_synth(wrapper, idx);
                let value: Expr = sim.pop_or_synth(wrapper, idx);
                sim.push(Expr::Subscript {
                    value: Box::new(value),
                    slice: Box::new(slice),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::BuildTuple(n) => {
                let elts: Vec<Expr> = sim.pop_n(*n as usize);
                sim.push(Expr::Tuple {
                    elts,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::Copy(n) => {
                if let Some(v) = sim.peek_at(usize::from(*n)) {
                    sim.push(v);
                }
            }
            CanonicalOp::Swap(n) => sim.swap(usize::from(*n)),
            CanonicalOp::StoreFast(_) => {
                let _ = sim.try_pop();
            }
            CanonicalOp::CallFunction(_) => {
                let mut bases: Vec<Expr> = sim.stack.clone();
                if matches!(bases.last(), Some(Expr::Name { id, .. }) if id == ".generic_base") {
                    bases.pop();
                }
                return bases;
            }
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) => break,
            _ => {}
        }
    }
    Vec::new()
}

fn is_type_params_setup_assign(s: &Stmt) -> bool {
    let Stmt::Assign { targets, .. } = s else {
        return false;
    };
    let [Expr::Name { id, .. }] = targets.as_slice() else {
        return false;
    };
    matches!(id.as_str(), "__type_params__" | ".type_params")
}

fn strip_class_implicit(mut body: Vec<Stmt>) -> Vec<Stmt> {
    strip_class_prologue(&mut body);
    strip_class_scope_leaked(&mut body);
    body
}

fn strip_class_prologue(body: &mut Vec<Stmt>) {
    if matches!(body.first(), Some(s) if is_auto_module_prologue_assign(s)) {
        body.remove(0);
    }
    if matches!(body.first(), Some(s) if is_auto_qualname_prologue_assign(s)) {
        body.remove(0);
    }
}

fn is_auto_module_prologue_assign(s: &Stmt) -> bool {
    let Stmt::Assign { targets, value, .. } = s else {
        return false;
    };
    let [Expr::Name { id, .. }] = targets.as_slice() else {
        return false;
    };
    id == "__module__" && matches!(value, Expr::Name { id: rhs, .. } if rhs == "__name__")
}

fn is_auto_qualname_prologue_assign(s: &Stmt) -> bool {
    let Stmt::Assign { targets, value, .. } = s else {
        return false;
    };
    let [Expr::Name { id, .. }] = targets.as_slice() else {
        return false;
    };
    id == "__qualname__"
        && matches!(
            value,
            Expr::Constant {
                value: ConstValue::Str(_),
                ..
            }
        )
}

fn strip_class_scope_leaked(body: &mut Vec<Stmt>) {
    body.retain(|s: &Stmt| !is_class_setup_assign(s));
    while body.last().is_some_and(is_class_implicit_return) {
        body.pop();
    }
    for stmt in body.iter_mut() {
        strip_class_scope_in_stmt(stmt);
    }
}

fn strip_class_scope_in_stmt(stmt: &mut Stmt) {
    match stmt {
        Stmt::If { body, orelse, .. }
        | Stmt::For { body, orelse, .. }
        | Stmt::While { body, orelse, .. } => {
            strip_class_scope_leaked(body);
            strip_class_scope_leaked(orelse);
        }
        Stmt::With { body, .. } => strip_class_scope_leaked(body),
        Stmt::Try {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        }
        | Stmt::TryStar {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        } => {
            strip_class_scope_leaked(body);
            for handler in handlers.iter_mut() {
                strip_class_scope_leaked(&mut handler.body);
            }
            strip_class_scope_leaked(orelse);
            strip_class_scope_leaked(finalbody);
        }
        Stmt::Match { cases, .. } => {
            for case in cases.iter_mut() {
                strip_class_scope_leaked(&mut case.body);
            }
        }
        _ => {}
    }
}

fn is_class_implicit_return(s: &Stmt) -> bool {
    match s {
        Stmt::Return(None) => true,
        Stmt::Return(Some(value)) => match value {
            Expr::Constant {
                value: ConstValue::None,
                ..
            } => true,
            Expr::Name { id, .. } => {
                id == "__class__" || id == "__classcell__" || id == DR_NULL_MARKER
            }
            _ => false,
        },
        _ => false,
    }
}

fn is_class_setup_assign(s: &Stmt) -> bool {
    let Stmt::Assign { targets, value, .. }: &Stmt = s else {
        return false;
    };
    let [Expr::Name { id, .. }]: &[Expr] = targets.as_slice() else {
        return false;
    };
    match id.as_str() {
        "__doc__" => matches!(
            value,
            Expr::Constant {
                value: ConstValue::Str(_),
                ..
            }
        ),
        "__firstlineno__"
        | "__static_attributes__"
        | "__classcell__"
        | "__class__"
        | "__classdict__"
        | "__classdictcell__"
        | "__type_params__"
        | ".type_params" => true,
        _ => false,
    }
}

pub(super) fn update_last_import_from_asname(out: &mut [Stmt], attr: &str, asname: &str) {
    for stmt in out.iter_mut().rev() {
        if let Stmt::ImportFrom { names, .. } = stmt {
            for alias in names.iter_mut() {
                if alias.name == attr && alias.asname.is_none() {
                    alias.asname = Some(asname.to_owned());
                    return;
                }
            }
        }
    }
}

pub(super) fn load_const(code: &CodeObject, idx: u32, offset: usize) -> Result<Expr> {
    let obj: &Object = code
        .consts
        .get(idx as usize)
        .ok_or_else(|| DecompileError::AstDesync {
            offset,
            reason: format!("const index {idx} out of range"),
        })?;
    if matches!(obj, Object::Code(_)) {
        return Ok(Expr::Name {
            id: format!("{DR_CODE_CONST_PREFIX}{idx}__"),
            ctx: ExprCtx::Load,
            line: None,
        });
    }
    Ok(Expr::Constant {
        value: object_to_const(obj),
        line: None,
    })
}

#[derive(Debug, Clone, Default)]
pub(super) struct FunctionMeta {
    pub(super) defaults: Vec<Expr>,
    pub(super) kw_defaults: Vec<(String, Expr)>,
    pub(super) annotations: Vec<(String, Expr)>,
    pub(super) returns: Option<Expr>,
}

pub(super) fn make_function_meta(flags: u8, sim: &mut StackSim) -> FunctionMeta {
    let mut meta: FunctionMeta = FunctionMeta::default();
    if flags & 0x08 != 0 {
        let _closure: Option<Expr> = sim.try_pop();
    }
    if flags & 0x04 != 0
        && let Some(anns) = sim.try_pop()
    {
        let (params, ret): (Vec<(String, Expr)>, Option<Expr>) = annotations_from_expr(anns);
        meta.annotations = params;
        meta.returns = ret;
    }
    if flags & 0x02 != 0
        && let Some(kwd) = sim.try_pop()
    {
        meta.kw_defaults = kwdefaults_from_expr(kwd);
    }
    if flags & 0x01 != 0
        && let Some(defs) = sim.try_pop()
    {
        meta.defaults = defaults_from_expr(defs);
    }
    meta
}

pub(super) fn fold_set_function_attributes(
    code: &CodeObject,
    ops: &[CanonicalOp],
    from: usize,
    sim: &mut StackSim,
    meta: &mut FunctionMeta,
) -> usize {
    let mut cursor: usize = from;
    while let Some(op) = ops.get(cursor) {
        let flag: u8 = match op {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {
                cursor += 1;
                continue;
            }
            CanonicalOp::SetFunctionAttribute(flag) => *flag,
            _ => break,
        };
        cursor += 1;
        let Some(attr): Option<Expr> = sim.try_pop() else {
            continue;
        };
        match flag {
            1 => meta.defaults = defaults_from_expr(attr),
            2 => meta.kw_defaults = kwdefaults_from_expr(attr),
            4 => {
                let (params, ret): (Vec<(String, Expr)>, Option<Expr>) =
                    annotations_from_expr(attr);
                meta.annotations = params;
                meta.returns = ret;
            }
            16 => {
                if let Some(dict) = annotate_codeobj_dict(code, &attr) {
                    let (params, ret): (Vec<(String, Expr)>, Option<Expr>) =
                        annotations_from_expr(dict);
                    if !params.is_empty() {
                        meta.annotations = params;
                    }
                    if ret.is_some() {
                        meta.returns = ret;
                    }
                }
            }
            _ => {}
        }
    }
    cursor
}

pub(super) fn make_function_meta_legacy(packed: u32, sim: &mut StackSim) -> FunctionMeta {
    let mut meta: FunctionMeta = FunctionMeta::default();
    let pos_defaults: usize = (packed & 0xFF) as usize;
    let kw_defaults: usize = ((packed >> 8) & 0xFF) as usize;
    let num_annotations: usize = ((packed >> 16) & 0x7FFF) as usize;
    if num_annotations > 0 {
        let names: Option<Expr> = sim.try_pop();
        let mut values: Vec<Expr> = Vec::with_capacity(num_annotations);
        for _ in 0..num_annotations {
            if let Some(v) = sim.try_pop() {
                values.insert(0, v);
            }
        }
        if let Some(name_tuple) = names {
            let keys: Vec<String> = match name_tuple {
                Expr::Tuple { elts, .. } => elts
                    .into_iter()
                    .filter_map(|e: Expr| match e {
                        Expr::Constant {
                            value: ConstValue::Str(s),
                            ..
                        } => Some(s),
                        _ => None,
                    })
                    .collect(),
                Expr::Constant {
                    value: ConstValue::Tuple(parts),
                    ..
                } => parts
                    .into_iter()
                    .filter_map(|c: ConstValue| match c {
                        ConstValue::Str(s) => Some(s),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };
            for (name, value) in keys.into_iter().zip(values) {
                if name == "return" {
                    meta.returns = Some(value);
                } else {
                    meta.annotations.push((name, value));
                }
            }
        }
    }
    let mut kw_pairs: Vec<(String, Expr)> = Vec::with_capacity(kw_defaults);
    for _ in 0..kw_defaults {
        let value: Option<Expr> = sim.try_pop();
        let name: Option<Expr> = sim.try_pop();
        if let (
            Some(value),
            Some(Expr::Constant {
                value: ConstValue::Str(name),
                ..
            }),
        ) = (value, name)
        {
            kw_pairs.insert(0, (name, value));
        }
    }
    meta.kw_defaults = kw_pairs;
    let mut defaults: Vec<Expr> = Vec::with_capacity(pos_defaults);
    for _ in 0..pos_defaults {
        if let Some(v) = sim.try_pop() {
            defaults.insert(0, v);
        }
    }
    meta.defaults = defaults;
    meta
}

pub(super) fn annotations_from_expr(expr: Expr) -> (Vec<(String, Expr)>, Option<Expr>) {
    let pairs: Vec<(String, Expr)> = match expr {
        Expr::Dict { keys, values } => keys
            .into_iter()
            .zip(values)
            .filter_map(|(k, v): (Option<Expr>, Expr)| match k {
                Some(Expr::Constant {
                    value: ConstValue::Str(name),
                    ..
                }) => Some((name, v)),
                _ => None,
            })
            .collect(),
        Expr::Tuple { elts, .. } => {
            let mut out: Vec<(String, Expr)> = Vec::with_capacity(elts.len() / 2);
            let mut iter: std::vec::IntoIter<Expr> = elts.into_iter();
            while let (Some(k), Some(v)) = (iter.next(), iter.next()) {
                let Expr::Constant {
                    value: ConstValue::Str(name),
                    ..
                } = k
                else {
                    continue;
                };
                out.push((name, v));
            }
            out
        }
        Expr::Constant {
            value: ConstValue::Tuple(parts),
            line,
        } => {
            let mut out: Vec<(String, Expr)> = Vec::with_capacity(parts.len() / 2);
            let mut iter: std::vec::IntoIter<ConstValue> = parts.into_iter();
            while let (Some(k), Some(v)) = (iter.next(), iter.next()) {
                let ConstValue::Str(name) = k else {
                    continue;
                };
                out.push((name, Expr::Constant { value: v, line }));
            }
            out
        }
        _ => Vec::new(),
    };
    let mut params: Vec<(String, Expr)> = Vec::with_capacity(pairs.len());
    let mut returns: Option<Expr> = None;
    for (name, value) in pairs {
        let value: Expr = unstringify_annotation(value);
        if name == "return" {
            returns = Some(value);
        } else {
            params.push((name, value));
        }
    }
    (params, returns)
}

fn unstringify_annotation(value: Expr) -> Expr {
    if !future_annotations_active() {
        return value;
    }
    match value {
        Expr::Constant {
            value: ConstValue::Str(s),
            ..
        } => parse_annotation_string(&s),
        other => other,
    }
}

pub(super) fn defaults_from_expr(expr: Expr) -> Vec<Expr> {
    match expr {
        Expr::Tuple { elts, .. } => elts,
        Expr::Constant {
            value: ConstValue::Tuple(parts),
            line,
        } => parts
            .into_iter()
            .map(|c: ConstValue| Expr::Constant { value: c, line })
            .collect(),
        _ => Vec::new(),
    }
}

pub(super) fn kwdefaults_from_expr(expr: Expr) -> Vec<(String, Expr)> {
    match expr {
        Expr::Dict { keys, values } => keys
            .into_iter()
            .zip(values)
            .filter_map(|(k, v): (Option<Expr>, Expr)| match k {
                Some(Expr::Constant {
                    value: ConstValue::Str(name),
                    ..
                }) => Some((name, v)),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

pub(super) fn attach_fn_meta(stmt: &mut Stmt, meta: &FunctionMeta) {
    if let Stmt::FunctionDef { args, returns, .. } = stmt {
        let taken: Arguments = std::mem::take(args);
        *args = apply_function_meta(taken, meta);
        if returns.is_none() {
            returns.clone_from(&meta.returns);
        }
    }
}

fn apply_function_meta(mut args: Arguments, meta: &FunctionMeta) -> Arguments {
    if !meta.defaults.is_empty() {
        args.defaults.clone_from(&meta.defaults);
    }
    if !meta.kw_defaults.is_empty() {
        args.kw_defaults = args
            .kwonly
            .iter()
            .map(|kw_arg: &crate::ast::node::Arg| {
                meta.kw_defaults
                    .iter()
                    .find(|(n, _): &&(String, Expr)| *n == kw_arg.arg)
                    .map(|(_, e): &(String, Expr)| e.clone())
            })
            .collect();
    }
    if !meta.annotations.is_empty() {
        let apply: &dyn Fn(&mut crate::ast::node::Arg) = &|arg: &mut crate::ast::node::Arg| {
            if arg.annotation.is_some() {
                return;
            }
            if let Some((_, ann)) = meta
                .annotations
                .iter()
                .find(|(n, _): &&(String, Expr)| *n == arg.arg)
            {
                arg.annotation = Some(Box::new(ann.clone()));
            }
        };
        for arg in &mut args.posonly {
            apply(arg);
        }
        for arg in &mut args.args {
            apply(arg);
        }
        for arg in &mut args.kwonly {
            apply(arg);
        }
        if let Some(arg) = args.vararg.as_deref_mut() {
            apply(arg);
        }
        if let Some(arg) = args.kwarg.as_deref_mut() {
            apply(arg);
        }
    }
    args
}

pub(super) fn call_ex_args(args_iter: Expr) -> Vec<Expr> {
    match args_iter {
        Expr::Tuple { elts, .. } | Expr::List { elts, .. } => elts,
        Expr::Constant {
            value: ConstValue::Tuple(parts),
            line,
        } => parts
            .into_iter()
            .map(|c: ConstValue| Expr::Constant { value: c, line })
            .collect(),
        other => vec![starred(other)],
    }
}

pub(super) fn call_ex_kwargs(kwargs: Expr) -> Vec<crate::ast::node::Keyword> {
    let Expr::Dict { keys, values } = kwargs else {
        return vec![crate::ast::node::Keyword {
            arg: None,
            value: kwargs,
        }];
    };
    let mut out: Vec<crate::ast::node::Keyword> = Vec::with_capacity(keys.len());
    let mut display: Vec<(Option<Expr>, Expr)> = Vec::new();
    let flush_display = |display: &mut Vec<(Option<Expr>, Expr)>,
                         out: &mut Vec<crate::ast::node::Keyword>| {
        if display.is_empty() {
            return;
        }
        let (dk, dv): (Vec<Option<Expr>>, Vec<Expr>) = std::mem::take(display).into_iter().unzip();
        out.push(crate::ast::node::Keyword {
            arg: None,
            value: Expr::Dict {
                keys: dk,
                values: dv,
            },
        });
    };
    for (key, value) in keys.into_iter().zip(values) {
        match key {
            Some(Expr::Constant {
                value: ConstValue::Str(s),
                ..
            }) => {
                flush_display(&mut display, &mut out);
                out.push(crate::ast::node::Keyword {
                    arg: Some(s),
                    value,
                });
            }
            None => {
                flush_display(&mut display, &mut out);
                out.push(crate::ast::node::Keyword { arg: None, value });
            }
            Some(other) => display.push((Some(other), value)),
        }
    }
    flush_display(&mut display, &mut out);
    out
}

pub(super) fn starred(expr: Expr) -> Expr {
    match expr {
        Expr::Starred { .. } => expr,
        other => Expr::Starred {
            value: Box::new(other),
            ctx: ExprCtx::Load,
        },
    }
}

pub(super) fn build_legacy_call(
    code: &CodeObject,
    idx: usize,
    packed: u32,
    has_var: bool,
    has_kw: bool,
    sim: &mut StackSim,
) -> Expr {
    let npos: usize = (packed & 0xFF) as usize;
    let nkw: usize = ((packed >> 8) & 0xFF) as usize;
    let kwargs_double: Option<Expr> = if has_kw {
        Some(sim.pop_or_synth(code, idx))
    } else {
        None
    };
    let args_star: Option<Expr> = if has_var {
        Some(sim.pop_or_synth(code, idx))
    } else {
        None
    };
    let mut keywords: Vec<crate::ast::node::Keyword> =
        Vec::with_capacity(nkw + usize::from(has_kw));
    for _ in 0..nkw {
        let value: Expr = sim.pop_or_synth(code, idx);
        let name: Expr = sim.pop_or_synth(code, idx);
        let arg: Option<String> = match name {
            Expr::Constant {
                value: ConstValue::Str(s),
                ..
            } => Some(s),
            _ => None,
        };
        keywords.insert(0, crate::ast::node::Keyword { arg, value });
    }
    let mut args: Vec<Expr> = Vec::with_capacity(npos + usize::from(has_var));
    for _ in 0..npos {
        args.insert(0, sim.pop_or_synth(code, idx));
    }
    let (func, implicit_self): (Expr, Option<Expr>) = sim.pop_call_target(code, idx);
    if let Some(self_arg) = implicit_self {
        args.insert(0, self_arg);
    }
    if let Some(star) = args_star {
        args.push(starred(star));
    }
    if let Some(double) = kwargs_double {
        keywords.push(crate::ast::node::Keyword {
            arg: None,
            value: double,
        });
    }
    Expr::Call {
        func: Box::new(func),
        args,
        keywords,
    }
}

fn const_collection_elements(addition: &Expr) -> Option<Vec<Expr>> {
    let Expr::Constant { value, line }: &Expr = addition else {
        return None;
    };
    let (ConstValue::Tuple(items) | ConstValue::Frozenset(items)): &ConstValue = value else {
        return None;
    };
    Some(
        items
            .iter()
            .map(|c: &ConstValue| Expr::Constant {
                value: c.clone(),
                line: *line,
            })
            .collect(),
    )
}

pub(super) fn merge_extend(base: Option<Expr>, addition: Expr, is_mapping: bool) -> Expr {
    let Some(base): Option<Expr> = base else {
        return addition;
    };
    match base {
        Expr::List { mut elts, ctx } => {
            match const_collection_elements(&addition) {
                Some(spliced) => elts.extend(spliced),
                None => elts.push(starred(addition)),
            }
            Expr::List { elts, ctx }
        }
        Expr::Set(mut elts) => {
            match const_collection_elements(&addition) {
                Some(spliced) => elts.extend(spliced),
                None => elts.push(starred(addition)),
            }
            Expr::Set(elts)
        }
        Expr::Dict {
            mut keys,
            mut values,
        } if is_mapping => {
            match addition {
                Expr::Dict {
                    keys: add_keys,
                    values: add_values,
                } if add_keys.iter().all(Option::is_some) => {
                    keys.extend(add_keys);
                    values.extend(add_values);
                }
                other => {
                    keys.push(None);
                    values.push(other);
                }
            }
            Expr::Dict { keys, values }
        }
        other => other,
    }
}

pub(super) fn slice_bound(expr: Expr) -> Option<Box<Expr>> {
    match expr {
        Expr::Constant {
            value: ConstValue::None,
            ..
        } => None,
        other => Some(Box::new(other)),
    }
}

pub(super) fn pop_legacy_slice_bounds(
    sim: &mut StackSim,
    code: &CodeObject,
    idx: usize,
    variant: u8,
) -> (Option<Box<Expr>>, Option<Box<Expr>>) {
    let has_upper: bool = variant == 2 || variant == 3;
    let has_lower: bool = variant == 1 || variant == 3;
    let upper: Option<Box<Expr>> = if has_upper {
        slice_bound(sim.pop_or_synth(code, idx))
    } else {
        None
    };
    let lower: Option<Box<Expr>> = if has_lower {
        slice_bound(sim.pop_or_synth(code, idx))
    } else {
        None
    };
    (lower, upper)
}

pub(super) fn nested_code_index(expr: &Expr) -> Option<u32> {
    let Expr::Name { id, .. } = expr else {
        return None;
    };
    let s: &str = id.strip_prefix(DR_CODE_CONST_PREFIX)?.strip_suffix("__")?;
    s.parse::<u32>().ok()
}

pub(super) fn nested_code_object_at(code: &CodeObject, idx: u32) -> Option<&CodeObject> {
    let obj: &Object = code.consts.get(idx as usize)?;
    match obj {
        Object::Code(boxed) => Some(boxed.as_ref()),
        _ => None,
    }
}

pub(super) fn try_build_decorated_class_def(
    parent: &CodeObject,
    value: &Expr,
    target_name: &str,
) -> Option<Stmt> {
    let mut decorators: Vec<Expr> = Vec::new();
    let mut cursor: &Expr = value;
    loop {
        let Expr::Call {
            func,
            args,
            keywords,
        }: &Expr = cursor
        else {
            return None;
        };
        if is_build_class_marker(func) {
            if decorators.is_empty() {
                return None;
            }
            let mut class_def: Stmt = try_build_class_def(parent, cursor, target_name)?;
            let Stmt::ClassDef {
                decorators: slot, ..
            }: &mut Stmt = &mut class_def
            else {
                return None;
            };
            *slot = decorators;
            return Some(class_def);
        }
        if args.len() != 1 || !keywords.is_empty() {
            return None;
        }
        decorators.push((**func).clone());
        cursor = &args[0];
    }
}

pub(super) fn try_build_decorated_function_def(
    parent: &CodeObject,
    value: &Expr,
    target_name: &str,
    fn_meta: &std::collections::BTreeMap<u32, FunctionMeta>,
) -> Option<Stmt> {
    let mut decorators: Vec<Expr> = Vec::new();
    let mut cursor: &Expr = value;
    loop {
        match cursor {
            Expr::Call {
                func,
                args,
                keywords,
            } if args.len() == 1 && keywords.is_empty() => {
                if nested_code_index(&args[0]).is_some() {
                    let const_idx: u32 = nested_code_index(&args[0])?;
                    let Some(Stmt::FunctionDef {
                        name,
                        type_params,
                        args: fn_args,
                        body,
                        returns,
                        is_async,
                        docstring,
                        line,
                        ..
                    }): Option<Stmt> =
                        build_nested_function_def(parent, const_idx, target_name.to_owned(), false)
                    else {
                        return None;
                    };
                    let (fn_args, returns): (Arguments, Option<Expr>) =
                        match fn_meta.get(&const_idx) {
                            Some(meta) => (
                                apply_function_meta(fn_args, meta),
                                returns.or_else(|| meta.returns.clone()),
                            ),
                            None => (fn_args, returns),
                        };
                    decorators.push((**func).clone());
                    return Some(Stmt::FunctionDef {
                        name,
                        type_params,
                        args: fn_args,
                        body,
                        decorators,
                        returns,
                        is_async,
                        docstring,
                        line,
                    });
                }
                decorators.push((**func).clone());
                cursor = &args[0];
            }
            _ => return None,
        }
    }
}

pub(super) fn prepend_global_decls(
    code: &CodeObject,
    ops: &[CanonicalOp],
    body: Vec<Stmt>,
) -> Vec<Stmt> {
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (i, op) in ops.iter().enumerate() {
        if let CanonicalOp::StoreGlobal(n) = op
            && let Ok(name) = name_at(&code.names, *n, i, "name")
        {
            names.insert(name);
        }
    }
    let annotated: std::collections::BTreeSet<&str> = body
        .iter()
        .filter_map(|s: &Stmt| match s {
            Stmt::AnnAssign {
                target: Expr::Name { id, .. },
                ..
            } => Some(id.as_str()),
            _ => None,
        })
        .collect();
    names.retain(|n: &String| !annotated.contains(n.as_str()));
    if names.is_empty() {
        return body;
    }
    let insert_at: usize = body
        .iter()
        .position(
            |s: &Stmt| !matches!(s, Stmt::ImportFrom { module: Some(m), .. } if m == "__future__"),
        )
        .unwrap_or(body.len());
    let mut out: Vec<Stmt> = body;
    out.insert(insert_at, Stmt::Global(names.into_iter().collect()));
    out
}

const CO_FAST_FREE: u8 = 0x80;

fn collect_freevar_names(code: &CodeObject) -> std::collections::BTreeSet<String> {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for obj in &code.freevars {
        if let Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } = obj
        {
            out.insert(value.clone());
        }
    }
    if !code.localspluskinds.is_empty() && !code.localsplusnames.is_empty() {
        for (kind, obj) in code.localspluskinds.iter().zip(code.localsplusnames.iter()) {
            if *kind & CO_FAST_FREE == 0 {
                continue;
            }
            if let Object::String { value, .. }
            | Object::Unicode { value, .. }
            | Object::ShortAscii { value, .. } = obj
            {
                out.insert(value.clone());
            }
        }
    }
    out
}

pub(super) fn prepend_nonlocal_decls(
    code: &CodeObject,
    ops: &[CanonicalOp],
    body: Vec<Stmt>,
) -> Vec<Stmt> {
    let freevar_names: std::collections::BTreeSet<String> = collect_freevar_names(code);
    let mut assigned: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (i, op) in ops.iter().enumerate() {
        let CanonicalOp::StoreFast(raw) = op else {
            continue;
        };
        if !is_deref_local(*raw) {
            continue;
        }
        let Ok(name) = local_name_at(code, *raw, i) else {
            continue;
        };
        if freevar_names.contains(&name) {
            assigned.insert(name);
        }
    }
    if assigned.is_empty() {
        return body;
    }
    let mut out: Vec<Stmt> = Vec::with_capacity(body.len() + 1);
    out.push(Stmt::Nonlocal(assigned.into_iter().collect()));
    out.extend(body);
    out
}

fn function_trailing_return_is_explicit(code: &CodeObject, stream: &DecodedStream) -> bool {
    let len: usize = stream.ops.len();
    let Some(last): Option<usize> = last_significant_back(stream, 0, len) else {
        return false;
    };
    let return_site: usize = match stream.ops[last] {
        CanonicalOp::ReturnConst(_) if loads_none(code, &stream.ops[last]) => last,
        CanonicalOp::Return => {
            let Some(feeder): Option<usize> = last_significant_back(stream, 0, last) else {
                return false;
            };
            if !loads_none(code, &stream.ops[feeder]) {
                return false;
            }
            feeder
        }
        _ => return false,
    };
    let Some(&site_off): Option<&u32> = stream.offsets.get(return_site) else {
        return false;
    };
    let reached_by_forward_cond: bool = (0..return_site).any(|j: usize| {
        (is_forward_cond_jump(&stream.ops[j]) || stream.none_jump_kind.contains_key(&j))
            && stream
                .offsets
                .get(resolve_jump_target(stream, j, &stream.ops[j]).unwrap_or(usize::MAX))
                .is_some_and(|&t: &u32| t == site_off)
    });
    if !reached_by_forward_cond {
        return false;
    }
    last_significant_back(stream, 0, return_site).is_none_or(|prev: usize| {
        !matches!(
            stream.ops[prev],
            CanonicalOp::Return
                | CanonicalOp::ReturnConst(_)
                | CanonicalOp::Raise(_)
                | CanonicalOp::Reraise(_)
                | CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpBackward(_)
                | CanonicalOp::JumpBackwardNoInterrupt(_)
                | CanonicalOp::JumpAbsolute(_)
        )
    })
}

pub(super) fn build_nested_function_def(
    parent: &CodeObject,
    const_idx: u32,
    target_name: String,
    is_async_default: bool,
) -> Option<Stmt> {
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let stream: DecodedStream = decode_stream_with_offsets(nested, opmap.as_ref(), &nested_version);
    let is_async: bool = is_async_default
        || (nested.flags & (PY_CO_FLAG_COROUTINE | PY_CO_FLAG_ASYNC_GENERATOR)) != 0;
    let args: Arguments = function_args_from_code(nested);
    let _codeobj_guard: CodeObjDepthGuard = match enter_codeobj_depth() {
        Ok(guard) => guard,
        Err(_) => {
            return Some(Stmt::FunctionDef {
                name: target_name,
                type_params: Vec::new(),
                args,
                body: vec![Stmt::Pass],
                decorators: Vec::new(),
                returns: None,
                is_async,
                docstring: Some("decompile-error: code-object nesting too deep".to_owned()),
                line: None,
            });
        }
    };
    let structured: Result<Vec<Stmt>> = {
        let _code_scope: NestedCodeScope = NestedCodeScope::enter();
        structure_stmts(nested, &stream, 0, stream.ops.len())
    };
    let body_raw: Vec<Stmt> = match structured {
        Ok(body) => body,
        Err(err) => {
            return Some(Stmt::FunctionDef {
                name: target_name,
                type_params: Vec::new(),
                args,
                body: vec![Stmt::Pass],
                decorators: Vec::new(),
                returns: None,
                is_async,
                docstring: Some(format!("decompile-error: {err}")),
                line: None,
            });
        }
    };
    let docstring_stripped: Vec<Stmt> = strip_module_docstring_stmt(body_raw, nested);
    let stripped: Vec<Stmt> = if function_trailing_return_is_explicit(nested, &stream) {
        docstring_stripped
    } else {
        strip_module_implicit_return(docstring_stripped)
    };
    let mut fn_body: Vec<Stmt> = postprocess_body(stripped, BodyKind::Function);
    if (nested.flags & PY_CO_FLAG_GENERATOR) != 0
        && (nested.flags & PY_CO_FLAG_ASYNC_GENERATOR) == 0
    {
        strip_generator_stopiteration_raise(&mut fn_body);
    }
    let processed: Vec<Stmt> = prepend_nonlocal_decls(
        nested,
        &stream.ops,
        prepend_global_decls(nested, &stream.ops, fn_body),
    );
    let final_body: Vec<Stmt> = if processed.is_empty() {
        vec![Stmt::Pass]
    } else {
        processed
    };
    Some(Stmt::FunctionDef {
        name: target_name,
        type_params: Vec::new(),
        args,
        body: final_body,
        decorators: Vec::new(),
        returns: None,
        is_async,
        docstring: extract_docstring(nested),
        line: None,
    })
}

pub(super) fn try_build_lambda_expr(
    parent: &CodeObject,
    const_idx: u32,
    meta: &FunctionMeta,
) -> Option<Expr> {
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let name: &str = match &nested.name {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.as_str(),
        _ => return None,
    };
    if name != "<lambda>" {
        return None;
    }
    let _codeobj_guard: CodeObjDepthGuard = enter_codeobj_depth().ok()?;
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let ops: Vec<CanonicalOp> = decode_stream(nested, opmap.as_ref(), &nested_version);
    let body: Expr = if lambda_body_has_inlined_comprehension(&ops) {
        lambda_structured_body(nested, &nested_version)?
    } else {
        let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(nested, &ops).ok()?;
        stmts
            .into_iter()
            .rev()
            .find_map(|s: Stmt| match s {
                Stmt::Return(Some(e)) | Stmt::Expr(e) => Some(e),
                _ => None,
            })
            .or_else(|| residual.into_iter().next_back())
            .unwrap_or(Expr::Constant {
                value: ConstValue::None,
                line: None,
            })
    };
    let args: Arguments = apply_function_meta(function_args_from_code(nested), meta);
    Some(Expr::Lambda {
        args: Box::new(args),
        body: Box::new(body),
    })
}

fn lambda_body_has_inlined_comprehension(ops: &[CanonicalOp]) -> bool {
    let has_for_iter: bool = ops
        .iter()
        .any(|o: &CanonicalOp| matches!(o, CanonicalOp::ForIter(_)));
    let has_accumulator: bool = ops.iter().any(|o: &CanonicalOp| {
        matches!(
            o,
            CanonicalOp::ListAppend | CanonicalOp::SetAdd | CanonicalOp::MapAdd
        )
    });
    has_for_iter && has_accumulator
}

fn lambda_structured_body(nested: &CodeObject, nested_version: &PyVersion) -> Option<Expr> {
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let stream: DecodedStream = decode_stream_with_offsets(nested, opmap.as_ref(), nested_version);
    let _code_scope: NestedCodeScope = NestedCodeScope::enter();
    let stmts: Vec<Stmt> = structure_stmts(nested, &stream, 0, stream.ops.len()).ok()?;
    stmts.into_iter().rev().find_map(|s: Stmt| match s {
        Stmt::Return(Some(e)) | Stmt::Expr(e) => Some(e),
        _ => None,
    })
}
