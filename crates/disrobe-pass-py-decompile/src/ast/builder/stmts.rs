use super::branches::{
    CompoundIf, OrBodyGuard, build_shortcircuit_stack_expr, collect_value_boolop_merges,
    collect_value_boolop_sc, jump_taken_if_true, match_head_enclosed_by_loop,
    match_head_enclosed_by_try, region_contains_match_head, structure_break_on_false_continue,
    structure_guarded_break, structure_match, try_recover_compound_if, try_recover_or_body_guard,
    try_structure_compound_assert, try_structure_dup_consumer_ternary,
    try_structure_literal_wildcard_match, try_structure_return_ternary, try_structure_ternary_expr,
};
use super::comprehensions::{
    CompKind, ComprehensionParts, clause_filters_use_skip_form, comp_loop_target,
    comprehension_generators_in, slice_clamped,
};
use super::exprs::{
    DR_UNRECOVERED_TARGET, build_linear_stmts_sim, build_linear_stmts_sim_seed, chain_group_end,
    is_chain_cond_jump, is_modern_test_chain_link_jump, local_name_at, local_target,
    modern_test_chain_then_end, name_at, object_to_const, recover_chain_target,
};
use super::function_meta::prepend_nonlocal_decls;
use super::loops::{
    cond_expr_start, find_legacy_async_for_loop, find_loop, guard_matches_enclosed_while,
    leading_cond_arm_holds_loop, leading_guard_if_encloses_loop, legacy_async_for_enclosed_by_loop,
    legacy_async_for_enclosed_by_try, loop_enclosed_by_guard, loop_is_else_arm_of_leading_if,
    loop_structure_guarded_loop, non_empty, recover_for_target, structure_for_loop_with_iter,
    structure_loop, try_enclosed_by_loop,
};
use super::try_with::{
    LoopKind, LoopRegion, TryRegion, extend_window_over_split_handler, find_try_region,
    is_back_edge, is_forward_cond_jump, is_shortcircuit_cleanup_pop, is_value_boundary,
    is_value_form_shortcircuit, loop_inside_unpeeled_pre311_try, recover_return_at,
    region_is_linear, skip_await_poll, structure_try, trim_trailing_comp_cleanup,
    try_enclosed_by_leading_guard, try_structure_cold_sibling_try, try_structure_else_try,
    try_structure_empty_body_try, try_structure_guarded_try, try_structure_multibranch_guarded_try,
};
use super::{
    ActiveRegionGuard, DecodedStream, FrameDispatch, ScDesc, StructureDepthGuard, WIDE_STEP,
    active_version, class_docstring, enter_active_region, enter_structure_depth, extract_docstring,
    fallthrough_cond_test, loop_break_target, loop_continue_target, loop_exit_return,
    loop_exit_tail_range, loop_frame_has_header, negate_cond_expr, none_jump_test,
    none_jump_test_taken, with_boolop_context,
};
use crate::ast::node::{
    Arguments, Comprehension, ConstValue, ExceptHandler, Expr, ExprCtx, FormatConversion,
    MatchCase, Pattern, Stmt, TStrItem, WithItem,
};
use crate::bytecode::opcode::{CanonicalOp, CmpOp, is_deref_local};
use crate::bytecode::version::PyVersion;
use crate::error::Result;
use crate::frame_tree::{Frame, FrameKind};
use disrobe_py_marshal::{CodeObject, Object};

pub(super) fn build_frame(
    code: &CodeObject,
    frame: &Frame,
    ops: &[CanonicalOp],
) -> Result<Vec<Stmt>> {
    let dispatch: FrameDispatch = FrameDispatch::from_kind(frame.kind);
    match dispatch {
        FrameDispatch::Module => build_linear_stmts(code, ops),
        FrameDispatch::FunctionDef => build_function_def(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::Lambda => build_lambda(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::ClassDef => build_class_def(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::Try => build_try(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::With => build_with(code, frame, ops, false).map(|s: Stmt| vec![s]),
        FrameDispatch::AsyncWith => build_with(code, frame, ops, true).map(|s: Stmt| vec![s]),
        FrameDispatch::For => build_for(code, frame, ops, false).map(|s: Stmt| vec![s]),
        FrameDispatch::AsyncFor => build_for(code, frame, ops, true).map(|s: Stmt| vec![s]),
        FrameDispatch::While => build_while(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::IfChain => build_if_chain(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::Match => build_match(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::ExceptHandler => build_except_handler_body(code, frame, ops),
        FrameDispatch::FinallyClause => build_finally_body(code, frame, ops),
        FrameDispatch::ExceptGroup => build_try(code, frame, ops).map(|s: Stmt| vec![s]),
        FrameDispatch::Comprehension => {
            build_comprehension(code, frame, ops).map(|s: Stmt| vec![s])
        }
    }
}

fn slice_ops<'a>(frame: &Frame, ops: &'a [CanonicalOp]) -> &'a [CanonicalOp] {
    let lo: usize = frame.body_range.start as usize;
    let hi: usize = frame.body_range.end as usize;
    let cap: usize = ops.len();
    let lo: usize = lo.min(cap);
    let hi: usize = hi.min(cap).max(lo);
    &ops[lo..hi]
}

fn build_function_def(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    let body: Vec<Stmt> = prepend_nonlocal_decls(code, ops, body);
    let name: String = code_name(code);
    let is_async: bool = (code.flags & (PY_CO_FLAG_COROUTINE | PY_CO_FLAG_ASYNC_GENERATOR)) != 0;
    Ok(Stmt::FunctionDef {
        name,
        type_params: Vec::new(),
        args: function_args_from_code(code),
        body,
        decorators: Vec::new(),
        returns: None,
        is_async,
        docstring: extract_docstring(code),
        line: frame.line,
    })
}

fn build_lambda(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body_stmts: Vec<Stmt> = build_linear_stmts(code, slice_ops(frame, ops))?;
    let value: Expr = body_stmts
        .into_iter()
        .find_map(|s: Stmt| match s {
            Stmt::Return(Some(e)) | Stmt::Expr(e) => Some(e),
            _ => None,
        })
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });
    let args: Arguments = function_args_from_code(code);
    Ok(Stmt::Expr(Expr::Lambda {
        args: Box::new(args),
        body: Box::new(value),
    }))
}

fn build_class_def(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    let name: String = code_name(code);
    let bases: Vec<Expr> = collect_class_bases(code, ops, frame);
    Ok(Stmt::ClassDef {
        name,
        type_params: Vec::new(),
        bases,
        keywords: Vec::new(),
        body,
        decorators: Vec::new(),
        docstring: class_docstring(code, ops),
        line: frame.line,
    })
}

fn build_try(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body: Vec<Stmt> = build_linear_stmts(code, slice_ops(frame, ops))?;
    let mut handlers: Vec<ExceptHandler> = Vec::with_capacity(frame.handlers.len());
    for child in &frame.children {
        if child.kind == FrameKind::ExceptHandler {
            handlers.push(ExceptHandler {
                typ: None,
                name: None,
                body: build_frame(code, child, ops)?,
                line: child.line,
            });
        }
    }
    let mut finalbody: Vec<Stmt> = Vec::new();
    for child in &frame.children {
        if child.kind == FrameKind::FinallyClause {
            finalbody = build_frame(code, child, ops)?;
            break;
        }
    }
    let is_star: bool = frame
        .children
        .iter()
        .any(|c: &Frame| c.kind == FrameKind::ExceptGroup);
    if is_star {
        Ok(Stmt::TryStar {
            body,
            handlers,
            orelse: Vec::new(),
            finalbody,
            line: frame.line,
        })
    } else {
        Ok(Stmt::Try {
            body,
            handlers,
            orelse: Vec::new(),
            finalbody,
            line: frame.line,
        })
    }
}

fn build_with(
    code: &CodeObject,
    frame: &Frame,
    ops: &[CanonicalOp],
    is_async: bool,
) -> Result<Stmt> {
    let items: Vec<WithItem> = collect_with_items(code, ops, frame);
    let body: Vec<Stmt> = if frame.children.is_empty() {
        build_legacy_with_body(code, frame, ops)?
    } else {
        build_children_or_body(code, frame, ops)?
    };
    Ok(Stmt::With {
        items,
        body,
        is_async,
        line: frame.line,
    })
}

fn build_legacy_with_body(
    code: &CodeObject,
    frame: &Frame,
    ops: &[CanonicalOp],
) -> Result<Vec<Stmt>> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let start: usize = usize::from(matches!(
        body_ops.first(),
        Some(CanonicalOp::StoreFast(_) | CanonicalOp::StoreName(_) | CanonicalOp::Pop)
    ));
    let triple_idx: Option<usize> = legacy_with_exit_triple_start(body_ops, start);
    let Some(triple_idx): Option<usize> = triple_idx else {
        return build_linear_stmts(code, &body_ops[start..]);
    };
    let swap_idx: Option<usize> = (start..triple_idx).rev().find(|&k: &usize| {
        !matches!(
            body_ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    });
    let (body_end, has_return_idiom): (usize, bool) = match swap_idx {
        Some(swap) if matches!(body_ops[swap], CanonicalOp::Swap(2) | CanonicalOp::RotN(2)) => {
            let after_triple: usize = triple_idx + 3;
            (swap, legacy_with_returns_value(body_ops, after_triple))
        }
        _ => (triple_idx, false),
    };
    let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &body_ops[start..body_end])?;
    let mut out: Vec<Stmt> = stmts;
    if has_return_idiom && let Some(value) = residual.into_iter().next_back() {
        out.push(Stmt::Return(Some(value)));
    }
    Ok(out)
}

fn legacy_with_exit_triple_start(ops: &[CanonicalOp], from: usize) -> Option<usize> {
    let mut i: usize = from;
    while i + 2 < ops.len() {
        let load: bool = matches!(ops[i], CanonicalOp::LoadConst(_));
        if load {
            let next: bool = matches!(
                ops[i + 1],
                CanonicalOp::LoadConst(_) | CanonicalOp::Dup | CanonicalOp::Copy(_)
            );
            let after: bool = matches!(
                ops[i + 2],
                CanonicalOp::LoadConst(_) | CanonicalOp::Dup | CanonicalOp::Copy(_)
            );
            if next && after {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn legacy_with_returns_value(ops: &[CanonicalOp], from: usize) -> bool {
    let mut i: usize = from;
    while i < ops.len() {
        match &ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => i += 1,
            CanonicalOp::CallFunction(_) | CanonicalOp::CallFunctionKw(_) => {
                i += 1;
                break;
            }
            _ => return false,
        }
    }
    while i < ops.len() {
        match &ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => i += 1,
            CanonicalOp::Pop => {
                i += 1;
                break;
            }
            _ => return false,
        }
    }
    while i < ops.len() {
        match &ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => i += 1,
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) => return true,
            _ => return false,
        }
    }
    false
}

fn build_for(
    code: &CodeObject,
    frame: &Frame,
    ops: &[CanonicalOp],
    is_async: bool,
) -> Result<Stmt> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let (target, iter): (Expr, Expr) = extract_for_header(code, body_ops);
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    Ok(Stmt::For {
        target,
        iter,
        body,
        orelse: Vec::new(),
        is_async,
        line: frame.line,
    })
}

fn build_while(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let test: Expr = extract_loop_test(code, body_ops).unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    Ok(Stmt::While {
        test,
        body,
        orelse: Vec::new(),
        line: frame.line,
    })
}

fn build_if_chain(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let test: Expr = extract_loop_test(code, body_ops).unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    Ok(Stmt::If {
        test,
        body,
        orelse: Vec::new(),
        line: frame.line,
    })
}

fn build_match(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let subject: Expr = extract_loop_test(code, body_ops).unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    let mut cases: Vec<MatchCase> = Vec::with_capacity(frame.children.len().max(1));
    for child in &frame.children {
        let case_body: Vec<Stmt> = build_frame(code, child, ops)?;
        cases.push(MatchCase {
            pattern: Pattern::MatchAs {
                pattern: None,
                name: None,
            },
            guard: None,
            body: case_body,
        });
    }
    if cases.is_empty() {
        cases.push(MatchCase {
            pattern: Pattern::MatchAs {
                pattern: None,
                name: None,
            },
            guard: None,
            body: vec![Stmt::Pass],
        });
    }
    Ok(Stmt::Match {
        subject,
        cases,
        line: frame.line,
    })
}

fn build_except_handler_body(
    code: &CodeObject,
    frame: &Frame,
    ops: &[CanonicalOp],
) -> Result<Vec<Stmt>> {
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    if body.is_empty() {
        Ok(vec![Stmt::Pass])
    } else {
        Ok(body)
    }
}

fn build_finally_body(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Vec<Stmt>> {
    let body: Vec<Stmt> = build_children_or_body(code, frame, ops)?;
    if body.is_empty() {
        Ok(vec![Stmt::Pass])
    } else {
        Ok(body)
    }
}

fn build_comprehension(code: &CodeObject, frame: &Frame, ops: &[CanonicalOp]) -> Result<Stmt> {
    let body: Vec<Stmt> = build_linear_stmts(code, slice_ops(frame, ops))?;
    let elt: Expr = body
        .into_iter()
        .find_map(|s: Stmt| match s {
            Stmt::Return(Some(e)) | Stmt::Expr(e) => Some(e),
            _ => None,
        })
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });
    Ok(Stmt::Expr(Expr::ListComp {
        elt: Box::new(elt),
        generators: Vec::new(),
    }))
}

fn build_children_or_body(
    code: &CodeObject,
    frame: &Frame,
    ops: &[CanonicalOp],
) -> Result<Vec<Stmt>> {
    if frame.children.is_empty() {
        return build_linear_stmts(code, slice_ops(frame, ops));
    }
    let mut out: Vec<Stmt> = Vec::new();
    for child in &frame.children {
        match child.kind {
            FrameKind::ExceptHandler | FrameKind::FinallyClause | FrameKind::ExceptGroup => {}
            _ => out.extend(build_frame(code, child, ops)?),
        }
    }
    Ok(out)
}

const PY_CO_FLAG_VARARGS: i32 = 0x0004;
const PY_CO_FLAG_VARKEYWORDS: i32 = 0x0008;
pub(super) const PY_CO_FLAG_GENERATOR: i32 = 0x0020;
pub(super) const PY_CO_FLAG_COROUTINE: i32 = 0x0080;
pub(super) const PY_CO_FLAG_ASYNC_GENERATOR: i32 = 0x0200;

fn code_name(code: &CodeObject) -> String {
    match &code.name {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.clone(),
        _ => "<anonymous>".to_owned(),
    }
}

pub(super) fn function_args_from_code(code: &CodeObject) -> Arguments {
    let positional_count: usize = usize::try_from(code.argcount.max(0)).unwrap_or(0);
    let kwonly_count: usize = usize::try_from(code.kwonlyargcount.max(0)).unwrap_or(0);
    let raw_posonly: usize = usize::try_from(code.posonlyargcount.max(0)).unwrap_or(0);
    let posonly_count: usize = raw_posonly.min(positional_count);
    let var_source: &[Object] = if code.varnames.is_empty() {
        &code.localsplusnames
    } else {
        &code.varnames
    };
    let mut all_var_names: Vec<String> = Vec::with_capacity(positional_count + kwonly_count);
    for obj in var_source {
        if let Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } = obj
        {
            all_var_names.push(value.clone());
        } else {
            all_var_names.push(String::new());
        }
    }
    let posonly: Vec<crate::ast::node::Arg> = all_var_names
        .iter()
        .take(posonly_count)
        .map(|n: &String| crate::ast::node::Arg {
            arg: n.clone(),
            annotation: None,
            default: None,
            line: None,
        })
        .collect();
    let args: Vec<crate::ast::node::Arg> = all_var_names
        .iter()
        .skip(posonly_count)
        .take(positional_count - posonly_count)
        .map(|n: &String| crate::ast::node::Arg {
            arg: n.clone(),
            annotation: None,
            default: None,
            line: None,
        })
        .collect();
    let mut cursor: usize = positional_count;
    let kwonly: Vec<crate::ast::node::Arg> = all_var_names
        .iter()
        .skip(cursor)
        .take(kwonly_count)
        .map(|n: &String| crate::ast::node::Arg {
            arg: n.clone(),
            annotation: None,
            default: None,
            line: None,
        })
        .collect();
    cursor += kwonly_count;
    let vararg: Option<Box<crate::ast::node::Arg>> = if (code.flags & PY_CO_FLAG_VARARGS) != 0 {
        let slot: String = all_var_names.get(cursor).cloned().unwrap_or_default();
        cursor += 1;
        Some(Box::new(crate::ast::node::Arg {
            arg: slot,
            annotation: None,
            default: None,
            line: None,
        }))
    } else {
        None
    };
    let kwarg: Option<Box<crate::ast::node::Arg>> = if (code.flags & PY_CO_FLAG_VARKEYWORDS) != 0 {
        let slot: String = all_var_names.get(cursor).cloned().unwrap_or_default();
        Some(Box::new(crate::ast::node::Arg {
            arg: slot,
            annotation: None,
            default: None,
            line: None,
        }))
    } else {
        None
    };
    let kw_defaults: Vec<Option<Expr>> = vec![None; kwonly_count];
    Arguments {
        posonly,
        args,
        vararg,
        kwonly,
        kw_defaults,
        kwarg,
        defaults: Vec::new(),
    }
}

fn collect_class_bases(code: &CodeObject, ops: &[CanonicalOp], frame: &Frame) -> Vec<Expr> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let mut bases: Vec<Expr> = Vec::new();
    for op in body_ops {
        match op {
            CanonicalOp::LoadName(i)
            | CanonicalOp::LoadGlobal(i)
            | CanonicalOp::LoadFromDictOrGlobals(i) => {
                if let Ok(id) = name_at(&code.names, *i, 0, "name")
                    && id != "__build_class__"
                    && id != code_name(code)
                {
                    bases.push(Expr::Name {
                        id,
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                }
            }
            CanonicalOp::CallFunction(_) | CanonicalOp::CallFunctionKw(_) => break,
            _ => {}
        }
    }
    bases
}

fn collect_with_items(code: &CodeObject, ops: &[CanonicalOp], frame: &Frame) -> Vec<WithItem> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let mut items: Vec<WithItem> = Vec::new();
    let mut pending_ctx: Option<Expr> = None;
    for op in body_ops {
        match op {
            CanonicalOp::LoadName(i)
            | CanonicalOp::LoadGlobal(i)
            | CanonicalOp::LoadFromDictOrGlobals(i)
            | CanonicalOp::LoadFast(i) => {
                if let Ok(id) = name_at_either(code, *i) {
                    pending_ctx = Some(Expr::Name {
                        id,
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                }
            }
            CanonicalOp::BeforeWith | CanonicalOp::BeforeAsyncWith => {
                if let Some(ctx) = pending_ctx.take() {
                    items.push(WithItem {
                        context_expr: ctx,
                        optional_vars: None,
                    });
                }
            }
            CanonicalOp::StoreFast(i) => {
                if let Ok(id) = local_name_at(code, *i, 0)
                    && let Some(last) = items.last_mut()
                    && last.optional_vars.is_none()
                {
                    last.optional_vars = Some(Expr::Name {
                        id,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
                }
            }
            _ => {}
        }
    }
    if items.is_empty()
        && let Some(ctx) = pending_ctx
    {
        items.push(WithItem {
            context_expr: ctx,
            optional_vars: None,
        });
    }
    if items.is_empty() {
        items = legacy_with_items_from_prologue(code, ops, frame);
    }
    items
}

fn legacy_with_items_from_prologue(
    code: &CodeObject,
    ops: &[CanonicalOp],
    frame: &Frame,
) -> Vec<WithItem> {
    let body_ops: &[CanonicalOp] = slice_ops(frame, ops);
    let optional_vars: Option<Expr> = match body_ops.first() {
        Some(CanonicalOp::StoreFast(i)) => {
            local_name_at(code, *i, 0)
                .ok()
                .map(|id: String| Expr::Name {
                    id,
                    ctx: ExprCtx::Store,
                    line: None,
                })
        }
        Some(CanonicalOp::StoreName(i)) => {
            name_at(&code.names, *i, 0, "name")
                .ok()
                .map(|id: String| Expr::Name {
                    id,
                    ctx: ExprCtx::Store,
                    line: None,
                })
        }
        _ => None,
    };
    let prologue_end: usize = (frame.body_range.start as usize).min(ops.len());
    if prologue_end == 0 {
        return Vec::new();
    }
    let mut sim_ops: Vec<CanonicalOp> = ops[..prologue_end].to_vec();
    while let Some(last) = sim_ops.last()
        && matches!(
            last,
            CanonicalOp::Nop | CanonicalOp::Cache | CanonicalOp::ExtendedArg(_)
        )
    {
        sim_ops.pop();
    }
    let (_, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &sim_ops).unwrap_or_default();
    let context_expr: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    vec![WithItem {
        context_expr,
        optional_vars,
    }]
}

fn extract_for_header(code: &CodeObject, ops: &[CanonicalOp]) -> (Expr, Expr) {
    let mut iter: Option<Expr> = None;
    let mut target: Option<Expr> = None;
    for op in ops {
        match op {
            CanonicalOp::LoadName(i)
            | CanonicalOp::LoadGlobal(i)
            | CanonicalOp::LoadFromDictOrGlobals(i)
            | CanonicalOp::LoadFast(i)
                if iter.is_none() =>
            {
                if let Ok(id) = name_at_either(code, *i) {
                    iter = Some(Expr::Name {
                        id,
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                }
            }
            CanonicalOp::StoreFast(i) if target.is_none() => {
                if let Ok(id) = local_name_at(code, *i, 0) {
                    target = Some(Expr::Name {
                        id,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
                }
            }
            CanonicalOp::ForIter(_) => break,
            _ => {}
        }
    }
    let target: Expr = target.unwrap_or_else(|| Expr::Name {
        id: "_".to_owned(),
        ctx: ExprCtx::Store,
        line: None,
    });
    let iter: Expr = iter.unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    (target, iter)
}

fn extract_loop_test(code: &CodeObject, ops: &[CanonicalOp]) -> Option<Expr> {
    for op in ops {
        match op {
            CanonicalOp::LoadName(i)
            | CanonicalOp::LoadGlobal(i)
            | CanonicalOp::LoadFromDictOrGlobals(i)
            | CanonicalOp::LoadFast(i) => {
                let id: String = name_at_either(code, *i).ok()?;
                return Some(Expr::Name {
                    id,
                    ctx: ExprCtx::Load,
                    line: None,
                });
            }
            CanonicalOp::LoadConst(i) => {
                let value: ConstValue = code
                    .consts
                    .get(*i as usize)
                    .map_or(ConstValue::None, object_to_const);
                return Some(Expr::Constant { value, line: None });
            }
            _ => {}
        }
    }
    None
}

pub(super) fn build_tstr_expr(statics: Expr, interps: Expr) -> Expr {
    let static_strs: Vec<String> = match statics {
        Expr::Constant {
            value: ConstValue::Tuple(parts),
            ..
        } => parts
            .into_iter()
            .map(|c: ConstValue| match c {
                ConstValue::Str(s) => s,
                _ => String::new(),
            })
            .collect(),
        _ => Vec::new(),
    };
    let interp_exprs: Vec<Expr> = match interps {
        Expr::Tuple { elts, .. } => elts,
        Expr::Constant {
            value: ConstValue::Tuple(parts),
            ..
        } => parts
            .into_iter()
            .map(|c: ConstValue| Expr::Constant {
                value: c,
                line: None,
            })
            .collect(),
        single => vec![single],
    };
    let mut items: Vec<TStrItem> = Vec::with_capacity(static_strs.len() + interp_exprs.len());
    let mut interp_iter: std::vec::IntoIter<Expr> = interp_exprs.into_iter();
    for (i, part) in static_strs.iter().enumerate() {
        if i > 0
            && let Some(interp) = interp_iter.next()
        {
            items.push(formatted_to_tstr_item(interp));
        }
        if !part.is_empty() {
            items.push(TStrItem::Literal(part.clone()));
        }
    }
    for interp in interp_iter {
        items.push(formatted_to_tstr_item(interp));
    }
    Expr::TStr { items, line: None }
}

fn formatted_to_tstr_item(expr: Expr) -> TStrItem {
    match expr {
        Expr::TStr { mut items, .. } if items.len() == 1 => match items.pop() {
            Some(item @ TStrItem::Interp { .. }) => item,
            Some(TStrItem::Literal(s)) => TStrItem::Interp {
                value: Expr::Constant {
                    value: ConstValue::Str(s),
                    line: None,
                },
                expr_text: None,
                conversion: FormatConversion::None,
                format_spec: None,
            },
            None => unreachable!("len == 1 guarantees a single item"),
        },
        Expr::FormattedValue {
            value,
            conversion,
            format_spec,
            ..
        } => TStrItem::Interp {
            value: *value,
            expr_text: None,
            conversion,
            format_spec: format_spec.map(|b: Box<Expr>| *b),
        },
        other => TStrItem::Interp {
            value: other,
            expr_text: None,
            conversion: FormatConversion::None,
            format_spec: None,
        },
    }
}

pub(super) fn name_at_either(code: &CodeObject, idx: u32) -> Result<String> {
    if is_deref_local(idx) {
        return local_name_at(code, idx, 0);
    }
    if let Ok(s) = name_at(&code.names, idx, 0, "name") {
        return Ok(s);
    }
    if let Ok(s) = name_at(&code.varnames, idx, 0, "varname") {
        return Ok(s);
    }
    name_at(&code.localsplusnames, idx, 0, "localsplus")
}

#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::similar_names,
    clippy::match_same_arms
)]
pub(super) fn resolve_jump_target(
    stream: &DecodedStream,
    idx: usize,
    op: &CanonicalOp,
) -> Option<usize> {
    stream.offsets.get(idx)?;
    let next: u32 = stream
        .next_offsets
        .get(idx)
        .copied()
        .unwrap_or(stream.code_len);
    let jump_unit: u32 = if stream.instr_unit_jumps { 2 } else { 1 };
    let target_byte: u32 = match op {
        CanonicalOp::PopJumpIfFalseRel(a) | CanonicalOp::PopJumpIfTrueRel(a) => {
            next.saturating_add(a.saturating_mul(jump_unit))
        }
        CanonicalOp::PopJumpIfFalse(a) | CanonicalOp::PopJumpIfTrue(a)
            if stream.relative_cond_jumps =>
        {
            next.saturating_add(a.saturating_mul(jump_unit))
        }
        CanonicalOp::PopJumpIfFalseBackward(a) | CanonicalOp::PopJumpIfTrueBackward(a) => {
            next.saturating_sub(a.saturating_mul(jump_unit))
        }
        CanonicalOp::PopJumpIfFalse(a)
        | CanonicalOp::PopJumpIfTrue(a)
        | CanonicalOp::JumpIfTrueOrPop(a)
        | CanonicalOp::JumpIfFalseOrPop(a)
        | CanonicalOp::JumpAbsolute(a) => a.saturating_mul(jump_unit),
        CanonicalOp::Other(121, a) => u32::from(*a).saturating_mul(jump_unit),
        CanonicalOp::JumpForward(rel) => {
            let rel_u: u32 = u32::try_from(*rel).unwrap_or(0).saturating_mul(jump_unit);
            next.saturating_add(rel_u)
        }
        CanonicalOp::ForIter(rel) | CanonicalOp::ForLoopLegacy(rel) | CanonicalOp::Send(rel) => {
            let rel_u: u32 = rel.saturating_mul(jump_unit);
            next.saturating_add(rel_u)
        }
        CanonicalOp::JumpBackward(rel) | CanonicalOp::JumpBackwardNoInterrupt(rel) => {
            let rel_u: u32 = rel.saturating_mul(jump_unit);
            next.saturating_sub(rel_u)
        }
        CanonicalOp::ContinueLoop(a) => a.saturating_mul(jump_unit),
        _ => return None,
    };
    stream
        .index_for_offset(target_byte)
        .or_else(|| resolve_fused_extended_arg_target(stream, target_byte))
}

fn resolve_fused_extended_arg_target(stream: &DecodedStream, target_byte: u32) -> Option<usize> {
    if stream.instr_unit_jumps && !stream.wordcode {
        return None;
    }
    let idx: usize = stream.index_for_offset_ceil(target_byte)?;
    let op_offset: u32 = *stream.offsets.get(idx)?;
    let step: u32 = if stream.wordcode { 2 } else { 1 };
    if op_offset.saturating_sub(target_byte) <= step {
        Some(idx)
    } else {
        None
    }
}

fn legacy_with_cleanup_idx(stream: &DecodedStream, setup_idx: usize, rel: u32) -> Option<usize> {
    let setup_byte: u32 = *stream.offsets.get(setup_idx)?;
    let delta: u32 = if stream.instr_unit_jumps {
        rel.saturating_mul(2)
    } else {
        rel
    };
    let cleanup_byte: u32 = setup_byte
        .saturating_add(u32::try_from(WIDE_STEP).unwrap_or(2))
        .saturating_add(delta);
    stream.index_for_offset(cleanup_byte)
}

fn is_legacy_with_exit_triple(stream: &DecodedStream, start: usize, hi: usize) -> bool {
    let Some(first): Option<usize> = first_significant(stream, start, hi) else {
        return false;
    };
    if !matches!(stream.ops[first], CanonicalOp::LoadConst(_)) {
        return false;
    }
    let Some(dup_a): Option<usize> = first_significant(stream, first + 1, hi) else {
        return false;
    };
    if !matches!(stream.ops[dup_a], CanonicalOp::Dup) {
        return false;
    }
    let Some(dup_b): Option<usize> = first_significant(stream, dup_a + 1, hi) else {
        return false;
    };
    if !matches!(stream.ops[dup_b], CanonicalOp::Dup) {
        return false;
    }
    let Some(call): Option<usize> = first_significant(stream, dup_b + 1, hi) else {
        return false;
    };
    matches!(stream.ops[call], CanonicalOp::CallFunction(3))
}

fn legacy_with_post_cleanup_return(
    code: &CodeObject,
    stream: &DecodedStream,
    body_end: usize,
    region_end: usize,
) -> Result<Option<Stmt>> {
    if !is_legacy_with_exit_triple(stream, body_end, region_end) {
        return Ok(None);
    }
    let Some(call): Option<usize> = (body_end..region_end).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::CallFunction(_) | CanonicalOp::CallFunctionKw(_)
        )
    }) else {
        return Ok(None);
    };
    let Some(pop): Option<usize> = first_significant(stream, call + 1, region_end) else {
        return Ok(None);
    };
    if !matches!(stream.ops[pop], CanonicalOp::Pop) {
        return Ok(None);
    }
    let ret_start: usize = pop + 1;
    let Some(ret_idx): Option<usize> = (ret_start..region_end).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return | CanonicalOp::ReturnConst(_)
        )
    }) else {
        return Ok(None);
    };
    let guarded: bool = (ret_start..ret_idx).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::PushExcInfo | CanonicalOp::WithExceptStart
        ) || is_forward_cond_jump(&stream.ops[k])
    });
    if guarded {
        return Ok(None);
    }
    recover_return_at(code, stream, ret_start, region_end)
}

fn legacy_with_body_bound(
    stream: &DecodedStream,
    body_start: usize,
    region_end: usize,
) -> (usize, bool) {
    let mut depth: usize = 0;
    let mut k: usize = body_start;
    while k < region_end {
        match &stream.ops[k] {
            CanonicalOp::SetupWith(_) => {
                depth += 1;
                k += 1;
            }
            CanonicalOp::RotN(2 | 3) => {
                if depth == 0 {
                    return (k, true);
                }
                depth -= 1;
                k += 1;
            }
            CanonicalOp::LoadConst(_) if is_legacy_with_exit_triple(stream, k, region_end) => {
                if depth == 0 {
                    return (k, false);
                }
                depth -= 1;
                k += 1;
            }
            _ => k += 1,
        }
    }
    (region_end, false)
}

fn region_contains_setup_with(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| matches!(stream.ops[k], CanonicalOp::SetupWith(_)))
}

fn region_contains_setup_async_with(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| matches!(stream.ops[k], CanonicalOp::SetupAsyncWith))
}

fn structure_legacy_async_with(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<(Vec<Stmt>, usize)>> {
    let Some(setup_idx): Option<usize> =
        (lo..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::SetupAsyncWith))
    else {
        return Ok(None);
    };
    let Some(before_idx): Option<usize> = (lo..setup_idx)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::BeforeAsyncWith))
    else {
        return Ok(None);
    };
    let (head_stmts, head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..before_idx])?;
    let context_expr: Expr = head_residual
        .into_iter()
        .next_back()
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });
    let mut body_start: usize = setup_idx + 1;
    let mut optional_vars: Option<Expr> = None;
    match stream.ops.get(body_start) {
        Some(CanonicalOp::StoreFast(slot)) => {
            optional_vars = local_target(code, *slot, body_start).ok();
            body_start += 1;
        }
        Some(CanonicalOp::StoreName(slot)) => {
            optional_vars =
                name_at(&code.names, *slot, body_start, "name")
                    .ok()
                    .map(|id: String| Expr::Name {
                        id,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
            body_start += 1;
        }
        Some(CanonicalOp::Pop) => body_start += 1,
        _ => {}
    }
    let exit_await: usize = (body_start..hi)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAwaitable))
        .unwrap_or(hi);
    let mut body: Vec<Stmt> = structure_stmts(code, stream, body_start, exit_await)?;
    if let Some(ret) = legacy_async_with_trailing_return(code, stream, exit_await, hi)? {
        body.push(ret);
    }
    let with_stmt: Stmt = Stmt::With {
        items: vec![WithItem {
            context_expr,
            optional_vars,
        }],
        body: non_empty(body),
        is_async: true,
        line: None,
    };
    let mut out: Vec<Stmt> = head_stmts;
    out.push(with_stmt);
    Ok(Some((out, hi)))
}

fn legacy_async_with_trailing_return(
    code: &CodeObject,
    stream: &DecodedStream,
    exit_await: usize,
    hi: usize,
) -> Result<Option<Stmt>> {
    if exit_await >= hi || !matches!(stream.ops[exit_await], CanonicalOp::GetAwaitable) {
        return Ok(None);
    }
    let after_poll: usize = skip_await_poll(stream, exit_await + 1, hi);
    recover_return_at(code, stream, after_poll, hi)
}

fn structure_legacy_with(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<(Vec<Stmt>, usize)>> {
    let Some(setup_idx): Option<usize> =
        (lo..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::SetupWith(_)))
    else {
        return Ok(None);
    };
    let CanonicalOp::SetupWith(rel): CanonicalOp = stream.ops[setup_idx] else {
        return Ok(None);
    };
    let (head_stmts, head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..setup_idx])?;
    let context_expr: Expr = head_residual
        .into_iter()
        .next_back()
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });
    let mut body_start: usize = setup_idx + 1;
    let mut optional_vars: Option<Expr> = None;
    match stream.ops.get(body_start) {
        Some(CanonicalOp::StoreFast(slot)) => {
            optional_vars = local_target(code, *slot, body_start).ok();
            body_start += 1;
        }
        Some(CanonicalOp::StoreName(slot)) => {
            optional_vars =
                name_at(&code.names, *slot, body_start, "name")
                    .ok()
                    .map(|id: String| Expr::Name {
                        id,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
            body_start += 1;
        }
        Some(CanonicalOp::Pop) => {
            body_start += 1;
        }
        _ => {}
    }
    let cleanup_idx: usize =
        legacy_with_cleanup_idx(stream, setup_idx, rel).map_or(hi, |idx: usize| idx.min(hi));
    let region_end: usize = cleanup_idx.min(hi).max(body_start);
    let (body_end, is_return): (usize, bool) =
        legacy_with_body_bound(stream, body_start, region_end);
    let body: Vec<Stmt> = if is_return && !region_contains_setup_with(stream, body_start, body_end)
    {
        legacy_with_return_body(code, stream, body_start, body_end)?
    } else {
        let mut stmts: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
        if !region_contains_setup_with(stream, body_start, body_end)
            && let Some(ret) = legacy_with_post_cleanup_return(code, stream, body_end, region_end)?
        {
            stmts.push(ret);
        }
        stmts
    };
    let with_stmt: Stmt = Stmt::With {
        items: vec![WithItem {
            context_expr,
            optional_vars,
        }],
        body: non_empty(body),
        is_async: false,
        line: None,
    };
    let mut out: Vec<Stmt> = head_stmts;
    out.push(with_stmt);
    Ok(Some((out, hi)))
}

fn legacy_with_return_body(
    code: &CodeObject,
    stream: &DecodedStream,
    body_start: usize,
    body_end: usize,
) -> Result<Vec<Stmt>> {
    let has_branch: bool = (body_start..body_end).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t > k && t <= body_end)
    });
    if has_branch
        && let Some(stmts) = legacy_with_return_structured(code, stream, body_start, body_end)?
    {
        return Ok(stmts);
    }
    let (mut stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[body_start..body_end])?;
    if let Some(value) = residual.into_iter().next_back() {
        stmts.push(Stmt::Return(Some(value)));
    }
    Ok(stmts)
}

fn legacy_with_return_structured(
    code: &CodeObject,
    stream: &DecodedStream,
    body_start: usize,
    body_end: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(&pop_block): Option<&usize> = stream
        .pre311_pop_block_idx
        .range(body_start..body_end)
        .next_back()
    else {
        return Ok(None);
    };
    let gap_inert: bool = (pop_block + 1..body_end).all(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Nop
                | CanonicalOp::Cache
                | CanonicalOp::ExtendedArg(_)
                | CanonicalOp::RotN(_)
                | CanonicalOp::Swap(_)
        )
    });
    if !gap_inert {
        return Ok(None);
    }
    let mut patched: DecodedStream = stream.clone();
    patched.ops[pop_block] = CanonicalOp::Return;
    Ok(Some(structure_stmts(
        code,
        &patched,
        body_start,
        pop_block + 1,
    )?))
}

fn else_jump_exits_to_shared_join(
    stream: &DecodedStream,
    last: usize,
    target: usize,
    hi: usize,
) -> bool {
    let Some(join): Option<usize> = resolve_jump_target(stream, last, &stream.ops[last]) else {
        return false;
    };
    if join < hi || target >= hi {
        return false;
    }
    let is_loop_control: bool = loop_break_target().is_some_and(|exit: usize| join >= exit)
        || loop_continue_target().is_some_and(|header: usize| join <= header);
    !is_loop_control
}

fn elif_arm_continues_to_loop(
    stream: &DecodedStream,
    jump_idx: usize,
    body_end: usize,
    target: usize,
    hi: usize,
) -> Option<(usize, usize)> {
    if target >= hi || body_end <= jump_idx + 1 {
        return None;
    }
    let header: usize = loop_continue_target()?;
    let back: usize = (jump_idx + 1..body_end)
        .rev()
        .find(|&k: &usize| is_back_edge(&stream.ops[k]))?;
    if (back + 1..body_end).any(|k: usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::ExtendedArg(_)
                | CanonicalOp::Push(_)
        )
    }) {
        return None;
    }
    let lands_on_header: bool =
        resolve_jump_target(stream, back, &stream.ops[back]).is_some_and(|t: usize| t <= header);
    if !lands_on_header {
        return None;
    }
    let elif_lo: usize = first_significant(stream, back + 1, hi).unwrap_or(target);
    let elif_jump: usize = (elif_lo..hi).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    })?;
    let valid: bool = resolve_jump_target(stream, elif_jump, &stream.ops[elif_jump])
        .is_some_and(|t: usize| t > elif_jump && t <= hi);
    if !valid {
        return None;
    }
    let orelse_at: usize = (back + 1).min(body_end);
    Some((back, orelse_at))
}

fn structure_elif_chain_arm(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Vec<Stmt>> {
    let Some(first_cond): Option<usize> = (lo..hi).find(|&i: &usize| {
        is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
    }) else {
        return structure_stmts(code, stream, lo, hi);
    };
    let compound: Option<CompoundIf> = try_recover_compound_if(code, stream, lo, hi)?;
    let cond_at: usize = compound
        .as_ref()
        .map(|c: &CompoundIf| c.last_jump)
        .filter(|&last: &usize| last >= first_cond)
        .unwrap_or(first_cond);
    let Some(jump_target): Option<usize> =
        resolve_jump_target(stream, cond_at, &stream.ops[cond_at])
            .filter(|t: &usize| *t > cond_at && *t <= hi)
    else {
        return structure_stmts(code, stream, lo, hi);
    };
    let header: usize = match loop_continue_target() {
        Some(h) => h,
        None => return structure_stmts(code, stream, lo, hi),
    };
    let lands_on_header = |idx: usize| -> bool {
        is_back_edge(&stream.ops[idx])
            && resolve_jump_target(stream, idx, &stream.ops[idx])
                .is_some_and(|t: usize| t <= header)
    };
    let jump_skips_arm: bool = matches!(
        stream.ops[cond_at],
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
    );
    let (arm_body_start, arm_end, next_arm_start, sibling_tail_start): (
        usize,
        usize,
        usize,
        Option<usize>,
    ) = if jump_skips_arm {
        let arm_back: Option<usize> = (cond_at + 1..jump_target)
            .rev()
            .find(|&k: &usize| lands_on_header(k));
        match arm_back {
            Some(back) => (cond_at + 1, back, jump_target, None),
            None if arm_terminates(stream, cond_at + 1, jump_target) => {
                (cond_at + 1, jump_target, jump_target, None)
            }
            None => (cond_at + 1, jump_target, hi, Some(jump_target)),
        }
    } else {
        let pre_continue: bool = (cond_at + 1..jump_target).any(|k: usize| lands_on_header(k));
        if !pre_continue {
            return structure_stmts(code, stream, lo, hi);
        }
        let arm_back: Option<usize> = (jump_target..hi).find(|&k: &usize| lands_on_header(k));
        arm_back.map_or((jump_target, hi, hi, None), |b: usize| {
            (
                jump_target,
                b,
                first_significant(stream, b + 1, hi).unwrap_or(hi),
                None,
            )
        })
    };
    let (head, test): (Vec<Stmt>, Expr) = if let Some(c) = compound {
        (c.head, c.test)
    } else {
        let (head, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[lo..cond_at])?;
        let raw_test: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
            value: ConstValue::True,
            line: None,
        });
        let none_test: Option<Expr> = if jump_skips_arm {
            none_jump_test(stream, cond_at, raw_test.clone())
        } else {
            none_jump_test_taken(stream, cond_at, raw_test.clone())
        };
        (head, none_test.unwrap_or(raw_test))
    };
    let body: Vec<Stmt> = structure_stmts(code, stream, arm_body_start, arm_end)?;
    let body: Vec<Stmt> =
        rewrite_jump_to_break_continue(code, stream, body, arm_body_start, arm_end);
    let deeper: Vec<Stmt> = if next_arm_start < hi {
        structure_elif_chain_arm(code, stream, next_arm_start, hi)?
    } else {
        Vec::new()
    };
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body: non_empty(body),
        orelse: deeper,
        line: None,
    });
    if let Some(tail_start) = sibling_tail_start {
        out.extend(structure_stmts(code, stream, tail_start, hi)?);
    }
    Ok(out)
}

fn arm_terminates(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    then_terminating_jump(stream, lo, hi).is_some()
        || region_ends_in_hard_terminator(stream, lo, hi)
}

pub(super) fn then_terminating_jump(
    stream: &DecodedStream,
    then_lo: usize,
    body_end: usize,
) -> Option<usize> {
    let mut k: usize = body_end;
    while k > then_lo {
        k -= 1;
        match &stream.ops[k] {
            CanonicalOp::Push(_)
            | CanonicalOp::Nop
            | CanonicalOp::Cache
            | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_) => return Some(k),
            _ => return None,
        }
    }
    None
}

pub(super) fn then_continues_to_loop(
    stream: &DecodedStream,
    then_lo: usize,
    body_end: usize,
) -> Option<usize> {
    let header: usize = loop_continue_target()?;
    let mut k: usize = body_end;
    while k > then_lo {
        k -= 1;
        match &stream.ops[k] {
            CanonicalOp::Push(_)
            | CanonicalOp::Nop
            | CanonicalOp::Cache
            | CanonicalOp::ExtendedArg(_) => {}
            op if is_back_edge(op) => {
                return resolve_jump_target(stream, k, op)
                    .filter(|t: &usize| *t <= header)
                    .map(|_| k);
            }
            _ => return None,
        }
    }
    None
}

pub(super) fn chain_landing_pad_cleanup_len(
    stream: &DecodedStream,
    pad: usize,
    hi: usize,
) -> Option<usize> {
    let mut k: usize = pad;
    while k < hi && matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop) {
        k += 1;
    }
    if k < hi && matches!(stream.ops[k], CanonicalOp::Pop) {
        Some(k + 1 - pad)
    } else {
        None
    }
}

fn try_structure_modern_test_chain_if(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    guard: usize,
    final_target: usize,
) -> Result<Option<Vec<Stmt>>> {
    if !matches!(
        stream.ops[guard],
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
    ) {
        return Ok(None);
    }
    if let Some(stmts) =
        try_structure_chain_if_pad_interposed(code, stream, lo, hi, guard, final_target)?
    {
        return Ok(Some(stmts));
    }
    let Some(pad): Option<usize> = modern_test_chain_then_end(stream, guard, hi) else {
        return Ok(None);
    };
    if pad <= guard + 1 || pad >= final_target {
        return Ok(None);
    }
    let Some(cleanup): Option<usize> = chain_landing_pad_cleanup_len(stream, pad, hi) else {
        return Ok(None);
    };
    let then_lo: usize = guard + 1;
    if then_terminating_jump(stream, then_lo, pad).is_some()
        || !region_ends_in_hard_terminator(stream, then_lo, pad)
    {
        return Ok(None);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..guard])?;
    let raw_test: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let test: Expr = none_jump_test(stream, guard, raw_test.clone()).unwrap_or(raw_test);

    let else_lo: usize = pad + cleanup;
    let then_body: Vec<Stmt> = structure_stmts(code, stream, then_lo, pad)?;
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body: if then_body.is_empty() {
            vec![Stmt::Pass]
        } else {
            then_body
        },
        orelse: Vec::new(),
        line: None,
    });
    out.extend(structure_stmts(code, stream, else_lo, final_target)?);
    if !region_ends_in_hard_terminator(stream, else_lo, final_target) {
        out.extend(structure_stmts(code, stream, final_target, hi)?);
    }
    Ok(Some(out))
}

fn try_structure_chain_if_pad_interposed(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    guard: usize,
    final_target: usize,
) -> Result<Option<Vec<Stmt>>> {
    let then_lo: usize = guard + 1;
    let Some(jump_idx): Option<usize> = first_significant(stream, then_lo, final_target) else {
        return Ok(None);
    };
    if !matches!(
        stream.ops[jump_idx],
        CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
    ) {
        return Ok(None);
    }
    let Some(pad): Option<usize> = first_significant(stream, jump_idx + 1, final_target) else {
        return Ok(None);
    };
    let Some(cleanup): Option<usize> = chain_landing_pad_cleanup_len(stream, pad, final_target)
    else {
        return Ok(None);
    };
    if !chain_link_targets_pad(stream, lo, guard, pad) {
        return Ok(None);
    }
    let Some(body_label): Option<usize> =
        resolve_jump_target(stream, jump_idx, &stream.ops[jump_idx])
            .filter(|t: &usize| *t > pad && *t < final_target)
    else {
        return Ok(None);
    };
    let else_lo: usize = pad + cleanup;
    if else_lo > body_label || !region_ends_in_hard_terminator(stream, else_lo, body_label) {
        return Ok(None);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..guard])?;
    let raw_test: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let test: Expr = none_jump_test(stream, guard, raw_test.clone()).unwrap_or(raw_test);
    let then_body: Vec<Stmt> = structure_stmts(code, stream, body_label, final_target)?;
    if then_body.is_empty() {
        return Ok(None);
    }
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body: then_body,
        orelse: Vec::new(),
        line: None,
    });
    out.extend(structure_stmts(code, stream, final_target, hi)?);
    Ok(Some(out))
}

fn chain_link_targets_pad(stream: &DecodedStream, lo: usize, guard: usize, pad: usize) -> bool {
    (lo..guard).any(|k: usize| {
        is_modern_test_chain_link_jump(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k]) == Some(pad)
    })
}

pub(super) fn structure_stmts(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Vec<Stmt>> {
    let _depth_guard: StructureDepthGuard = enter_structure_depth()?;
    let len: usize = stream.ops.len();
    if lo > len || hi > len {
        return Err(crate::error::DecompileError::BlockOutOfRange { lo, hi, len });
    }
    let hi: usize = extend_window_over_split_handler(stream, lo, hi);
    if lo >= hi {
        return Ok(Vec::new());
    }
    let Some(_active_guard): Option<ActiveRegionGuard> = enter_active_region(lo, hi) else {
        let block: &[CanonicalOp] = stream.ops.get(lo..hi).unwrap_or_default();
        return Ok(build_linear_stmts(code, block).unwrap_or_default());
    };
    if let Some(stmts) = try_structure_inline_comprehension(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(stmts) = try_structure_inline_comprehension_noclear(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(stmts) = structure_fallthrough_continue_and_chain(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(stmts) = try_structure_inframe_listcomp(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if region_contains_setup_async_with(stream, lo, hi)
        && let Some((stmts, _consumed)) = structure_legacy_async_with(code, stream, lo, hi)?
    {
        return Ok(stmts);
    }
    if region_contains_setup_with(stream, lo, hi)
        && let Some((stmts, _consumed)) = structure_legacy_with(code, stream, lo, hi)?
    {
        return Ok(stmts);
    }
    if stream.supports_match()
        && region_contains_match_head(stream, lo, hi)
        && !match_head_enclosed_by_try(stream, lo, hi)
        && !match_head_enclosed_by_loop(stream, lo, hi)
        && let Some((stmts, _consumed)) = structure_match(code, stream, lo, hi)?
    {
        return Ok(stmts);
    }
    if let Some(stmts) = try_structure_literal_wildcard_match(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if stream.version.major() == 3
        && stream.version.minor() <= 7
        && let Some(loop_region) = find_legacy_async_for_loop(code, stream, lo, hi)
        && !legacy_async_for_enclosed_by_try(stream, lo, hi, &loop_region)
        && !legacy_async_for_enclosed_by_loop(stream, lo, hi, &loop_region)
    {
        return structure_loop(code, stream, lo, hi, &loop_region);
    }
    if let Some(stmts) = try_structure_guarded_try(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(stmts) = try_structure_multibranch_guarded_try(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if find_try_region(stream, lo, hi).is_none()
        && let Some(stmts) = try_structure_cold_sibling_try(code, stream, lo, hi)?
    {
        return Ok(stmts);
    }
    if find_try_region(stream, lo, hi).is_none()
        && let Some(stmts) = try_structure_empty_body_try(code, stream, lo, hi)?
    {
        return Ok(stmts);
    }
    if let Some(stmts) = try_structure_else_try(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(try_region) = find_try_region(stream, lo, hi)
        && !try_enclosed_by_loop(stream, lo, hi, &try_region)
        && !try_enclosed_by_leading_guard(stream, lo, hi, &try_region)
    {
        if let Some(stmts) = try_structure_loop_guard_before_try(code, stream, lo, hi, &try_region)?
        {
            return Ok(stmts);
        }
        return structure_try(code, stream, lo, hi, &try_region);
    }
    if let Some(stmts) = loop_structure_guarded_loop(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(loop_region) = find_loop(stream, lo, hi)
        && !leading_guard_if_encloses_loop(stream, lo, hi, &loop_region)
        && !loop_enclosed_by_guard(stream, lo, &loop_region)
        && !loop_is_else_arm_of_leading_if(stream, lo, hi, &loop_region)
        && !leading_cond_arm_holds_loop(stream, lo, &loop_region)
        && !loop_inside_unpeeled_pre311_try(stream, hi, &loop_region)
    {
        return structure_loop(code, stream, lo, hi, &loop_region);
    }
    if let Some(stmts) = structure_backward_continue_guard(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(stmts) = structure_or_chain_body_guard(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(stmts) = structure_compound_continue_guard(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(stmts) = structure_break_on_false_continue(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(stmts) = structure_guarded_break(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if matches!(stream.ops.get(hi - 1), Some(CanonicalOp::Return))
        && (lo..hi - 1).any(|i: usize| is_value_form_shortcircuit(&stream.ops, i))
        && !(lo..hi - 1).any(|i: usize| {
            is_forward_cond_jump(&stream.ops[i])
                && !is_chain_cond_jump(&stream.ops, i)
                && !is_value_form_shortcircuit(&stream.ops, i)
                && resolve_jump_target(stream, i, &stream.ops[i])
                    .is_some_and(|t: usize| t > i && t <= hi)
        })
        && let Some(expr) = build_shortcircuit_stack_expr(code, stream, lo, hi - 1)?
    {
        return Ok(vec![Stmt::Return(Some(expr))]);
    }
    if let Some(stmts) = try_structure_compound_assert(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    if let Some(stmts) = try_structure_trailing_guard(code, stream, lo, hi)? {
        return Ok(stmts);
    }
    let first_cond: Option<usize> = (lo..hi).find(|&i: &usize| {
        is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
            && resolve_jump_target(stream, i, &stream.ops[i])
                .is_some_and(|t: usize| t > i && t <= hi)
    });
    if let Some(first) = first_cond {
        let first_target: usize = resolve_jump_target(stream, first, &stream.ops[first])
            .filter(|t: &usize| *t > first && *t <= hi)
            .unwrap_or(hi);
        if let Some(stmts) = structure_guarded_continue(code, stream, lo, hi, first, first_target)?
        {
            return Ok(stmts);
        }
        if let Some(stmts) = try_structure_ternary_expr(code, stream, lo, hi, first, first_target)?
        {
            return Ok(stmts);
        }
        if let Some(stmts) =
            try_structure_dup_consumer_ternary(code, stream, lo, hi, first, first_target)?
        {
            return Ok(stmts);
        }
        if active_version()
            .is_some_and(|v: PyVersion| v.major() == 3 && (12..=13).contains(&v.minor()))
            && matches!(stream.ops.get(hi - 1), Some(CanonicalOp::Return))
            && let Some(stmts) =
                try_structure_return_ternary(code, stream, lo, hi, first, first_target)?
        {
            return Ok(stmts);
        }
        if let Some(stmts) =
            try_structure_below_test_terminating_arms(code, stream, lo, hi, first, first_target)?
        {
            return Ok(stmts);
        }
    }
    let compound: Option<CompoundIf> = try_recover_compound_if(code, stream, lo, hi)?;
    let cond_at: Option<usize> = compound
        .as_ref()
        .map(|c: &CompoundIf| c.last_jump)
        .or(first_cond);
    let compound_exit: Option<usize> = compound.as_ref().and_then(|c: &CompoundIf| c.exit_target);
    let Some(jump_idx): Option<usize> = cond_at else {
        let region: &[CanonicalOp] = &stream.ops[lo..hi];
        let merges: Vec<usize> = collect_value_boolop_merges(stream, lo, hi);
        let sc: Vec<ScDesc> = collect_value_boolop_sc(stream, lo, hi);
        return with_boolop_context(region, merges, sc, || build_linear_stmts(code, region));
    };
    let target: usize = compound_exit
        .filter(|t: &usize| *t > jump_idx && *t <= hi)
        .or_else(|| {
            resolve_jump_target(stream, jump_idx, &stream.ops[jump_idx])
                .filter(|t: &usize| *t > jump_idx && *t <= hi)
        })
        .unwrap_or(hi);

    if compound.is_none()
        && let Some(stmts) =
            try_structure_modern_test_chain_if(code, stream, lo, hi, jump_idx, target)?
    {
        return Ok(stmts);
    }

    let is_compound: bool = compound.is_some();
    let (head, raw_test): (Vec<Stmt>, Expr) = if let Some(c) = compound {
        (c.head, c.test)
    } else {
        let head_region: &[CanonicalOp] = &stream.ops[lo..jump_idx];
        let head_merges: Vec<usize> = collect_value_boolop_merges(stream, lo, jump_idx);
        let head_sc: Vec<ScDesc> = collect_value_boolop_sc(stream, lo, jump_idx);
        let (head, residual): (Vec<Stmt>, Vec<Expr>) =
            with_boolop_context(head_region, head_merges, head_sc, || {
                build_linear_stmts_sim(code, head_region)
            })?;
        let raw: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
            value: ConstValue::True,
            line: None,
        });
        (head, raw)
    };
    let negate: bool = is_compound
        || matches!(
            stream.ops[jump_idx],
            CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
        );
    let test: Expr = if is_compound {
        raw_test
    } else {
        none_jump_test(stream, jump_idx, raw_test.clone()).unwrap_or(raw_test)
    };

    let body_end: usize = target;
    let mut join: usize = target;
    let mut orelse_start: Option<usize> = None;
    let mut then_jump_at: Option<usize> = None;
    let mut else_via_continue: bool = false;
    if body_end > jump_idx + 1
        && let Some(last) = then_terminating_jump(stream, jump_idx + 1, body_end)
        && let CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_) = stream.ops[last]
        && let Some(j) = resolve_jump_target(stream, last, &stream.ops[last])
        && j > target
        && (j <= hi || else_jump_exits_to_shared_join(stream, last, target, hi))
    {
        join = j.min(hi);
        orelse_start = Some(last + 1);
        then_jump_at = Some(last);
    }
    let mut elif_body_end: usize = body_end;
    if orelse_start.is_none()
        && let Some((back, orelse_at)) =
            elif_arm_continues_to_loop(stream, jump_idx, body_end, target, hi)
    {
        join = hi;
        orelse_start = Some(orelse_at);
        elif_body_end = back;
        else_via_continue = true;
    }
    let bare_continue_back: Option<usize> = if orelse_start.is_none() && then_jump_at.is_none() {
        then_continues_to_loop(stream, jump_idx + 1, target).filter(|_| target < hi)
    } else {
        None
    };
    let then_arm_is_bare_continue: bool = bare_continue_back.is_some();
    if let Some(back) = bare_continue_back {
        join = hi;
        orelse_start = Some(target);
        then_jump_at = Some(back);
    }
    let then_arm_is_fallthrough: bool = negate || stream.none_jump_kind.contains_key(&jump_idx);
    if orelse_start.is_none()
        && then_arm_is_fallthrough
        && target < hi
        && region_ends_in_hard_terminator(stream, jump_idx + 1, body_end)
        && !then_arm_opens_handler_after(stream, jump_idx + 1, target)
        && let Some(else_end) =
            hard_terminator_else_end(code, stream, lo, hi, jump_idx, body_end, target)
        && target < else_end
    {
        join = hi;
        orelse_start = Some(target);
    }
    let body_real_end: usize = then_jump_at.unwrap_or(if else_via_continue {
        elif_body_end
    } else {
        body_end
    });
    let fallthrough: Vec<Stmt> = structure_stmts(code, stream, jump_idx + 1, body_real_end)?;
    let fallthrough: Vec<Stmt> = if else_via_continue {
        fallthrough
    } else {
        rewrite_jump_to_break_continue(code, stream, fallthrough, jump_idx + 1, body_real_end)
    };
    let jumped: Vec<Stmt> = match orelse_start {
        Some(s) if else_via_continue => structure_elif_chain_arm(code, stream, s, join)?,
        Some(s) => structure_stmts(code, stream, s, join)?,
        None => Vec::new(),
    };
    let jumped: Vec<Stmt> = match orelse_start {
        Some(_) if else_via_continue => jumped,
        Some(s) => rewrite_jump_to_break_continue(code, stream, jumped, s, join),
        None => jumped,
    };
    let none_jump: bool = stream.none_jump_kind.contains_key(&jump_idx);
    let positive_test: Expr =
        none_jump_test_taken(stream, jump_idx, test.clone()).unwrap_or_else(|| test.clone());
    let keep_positive_continue_guard: bool = then_arm_is_bare_continue
        && !negate
        && !none_jump
        && jump_taken_if_true(stream, jump_idx)
        && test_is_polarity_sensitive(&positive_test)
        && !jumped.is_empty();
    let negated_single_branch: bool =
        !negate && orelse_start.is_none() && !fallthrough.is_empty() && !none_jump;
    let negated_both_arms: bool = !negate && !none_jump && orelse_start.is_some();
    let (test, body, orelse): (Expr, Vec<Stmt>, Vec<Stmt>) = if keep_positive_continue_guard {
        (positive_test, jumped, Vec::new())
    } else if negated_single_branch || negated_both_arms {
        (
            Expr::UnaryOp {
                op: crate::bytecode::opcode::UnaryOp::Not,
                operand: Box::new(test),
            },
            fallthrough,
            jumped,
        )
    } else if negate || none_jump {
        (test, fallthrough, jumped)
    } else {
        (test, jumped, fallthrough)
    };

    let tail: Vec<Stmt> = structure_stmts(code, stream, join, hi)?;

    let empty_pass_body: bool = target == jump_idx + 1 && orelse_start.is_none();
    let mut out: Vec<Stmt> = head;
    if body.is_empty() && orelse.is_empty() && !empty_pass_body {
        out.push(Stmt::Expr(test));
    } else if orelse.is_empty() && guard_matches_enclosed_while(&body, &test) {
        out.extend(body);
    } else {
        out.push(Stmt::If {
            test,
            body: if body.is_empty() {
                vec![Stmt::Pass]
            } else {
                body
            },
            orelse,
            line: None,
        });
    }
    out.extend(tail);
    Ok(out)
}

fn try_structure_trailing_guard(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(guard): Option<usize> = (lo..hi).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
    }) else {
        return Ok(None);
    };
    let Some(target): Option<usize> = resolve_jump_target(stream, guard, &stream.ops[guard]) else {
        return Ok(None);
    };
    if target <= hi || guard + 1 >= hi {
        return Ok(None);
    }
    if try_recover_compound_if(code, stream, lo, hi)?.is_some() {
        return Ok(None);
    }
    let head_region: &[CanonicalOp] = &stream.ops[lo..guard];
    let head_merges: Vec<usize> = collect_value_boolop_merges(stream, lo, guard);
    let head_sc: Vec<ScDesc> = collect_value_boolop_sc(stream, lo, guard);
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        with_boolop_context(head_region, head_merges, head_sc, || {
            build_linear_stmts_sim(code, head_region)
        })?;
    let Some(raw_test): Option<Expr> = residual.into_iter().next_back() else {
        return Ok(None);
    };
    let body: Vec<Stmt> = structure_stmts(code, stream, guard + 1, hi)?;
    if body.is_empty() {
        return Ok(None);
    }
    let is_none_jump: bool = stream.none_jump_kind.contains_key(&guard);
    let test: Expr = none_jump_test(stream, guard, raw_test.clone()).unwrap_or(raw_test);
    let test: Expr = if is_none_jump
        || matches!(
            stream.ops[guard],
            CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfFalseRel(_)
                | CanonicalOp::PopJumpIfFalseBackward(_)
        ) {
        test
    } else {
        negate_cond_expr(test)
    };
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body,
        orelse: Vec::new(),
        line: None,
    });
    Ok(Some(out))
}

fn build_linear_stmts(code: &CodeObject, ops: &[CanonicalOp]) -> Result<Vec<Stmt>> {
    build_linear_stmts_sim(code, ops).map(|(stmts, _residual): (Vec<Stmt>, Vec<Expr>)| stmts)
}

pub(super) fn is_yield_from_send_pattern(ops: &[CanonicalOp], yield_idx: usize) -> bool {
    let mut k: usize = yield_idx;
    let mut saw_send: bool = false;
    let mut saw_const_none: bool = false;
    let mut saw_get_iter: bool = false;
    while k > 0 {
        k -= 1;
        match &ops[k] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::Send(_) if !saw_send => saw_send = true,
            CanonicalOp::LoadConst(_) | CanonicalOp::LoadCommonConst(7)
                if saw_send && !saw_const_none =>
            {
                saw_const_none = true;
            }
            CanonicalOp::GetIter if saw_send && saw_const_none && !saw_get_iter => {
                saw_get_iter = true;
                break;
            }
            _ => break,
        }
    }
    saw_send && saw_const_none && saw_get_iter
}

pub(super) fn is_pre23_statement_yield() -> bool {
    active_version().is_some_and(|v: PyVersion| {
        let (maj, min): (u8, u8) = (v.major(), v.minor());
        maj < 2 || (maj == 2 && min < 3)
    })
}

pub(super) fn is_await_poll_yield(ops: &[CanonicalOp], yield_idx: usize) -> bool {
    let mut k: usize = yield_idx + 1;
    let mut saw_resume: bool = false;
    let mut saw_back_jump: bool = false;
    while k < ops.len() {
        match &ops[k] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::Resume(_) if !saw_resume => saw_resume = true,
            CanonicalOp::JumpBackwardNoInterrupt(_) if saw_resume && !saw_back_jump => {
                saw_back_jump = true;
            }
            CanonicalOp::EndSend | CanonicalOp::CleanupThrow if saw_back_jump => return true,
            _ => return false,
        }
        k += 1;
    }
    false
}

pub(super) fn filter_async_gen_return(code: &CodeObject, value: Option<Expr>) -> Option<Expr> {
    if code.flags & PY_CO_FLAG_ASYNC_GENERATOR == 0 {
        return value;
    }
    match value {
        Some(Expr::Constant {
            value: ConstValue::None,
            ..
        })
        | None => None,
        other => other,
    }
}

fn is_peephole_break_return(stream: &DecodedStream, body: &[Stmt], lo: usize, hi: usize) -> bool {
    let [Stmt::Return(Some(value))]: &[Stmt] = body else {
        return false;
    };
    let Some(exit_return): Option<Expr> = loop_exit_return() else {
        return false;
    };
    if *value != exit_return {
        return false;
    }
    let Some(first): Option<usize> = (lo..hi).find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    }) else {
        return false;
    };
    matches!(stream.ops[first], CanonicalOp::Pop)
}

pub(super) fn rewrite_legacy_async_for_body(
    stream: &DecodedStream,
    body: Vec<Stmt>,
    body_start: usize,
    region: &LoopRegion,
) -> Vec<Stmt> {
    if body.iter().any(|s: &Stmt| !matches!(s, Stmt::Pass)) {
        return body;
    }
    if body_start == 0 || !stream.pre311_end_finally_idx.contains(&(body_start - 1)) {
        return body;
    }
    let has_break: bool =
        (body_start..region.body_end).any(|k: usize| stream.pre311_break_loop_idx.contains(&k));
    if has_break {
        return vec![Stmt::Break];
    }
    let is_continue: bool = (body_start..region.body_end).any(|k: usize| {
        is_back_edge(&stream.ops[k])
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t <= region.header)
    });
    if is_continue {
        return vec![Stmt::Continue];
    }
    body
}

fn append_pre311_break_loop(
    stream: &DecodedStream,
    body: &[Stmt],
    lo: usize,
    hi: usize,
) -> Option<Vec<Stmt>> {
    let last_idx: usize = (lo..hi).rev().find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::ExtendedArg(_)
        )
    })?;
    if !stream.pre311_break_loop_idx.contains(&last_idx) {
        return None;
    }
    if matches!(
        body.last(),
        Some(Stmt::Break | Stmt::Continue | Stmt::Return(_) | Stmt::Raise { .. })
    ) {
        return None;
    }
    let mut out: Vec<Stmt> = body.to_vec();
    out.push(Stmt::Break);
    Some(out)
}

pub(super) fn append_handler_loop_jump(
    stream: &DecodedStream,
    body: Vec<Stmt>,
    lo: usize,
    hi: usize,
) -> Vec<Stmt> {
    let Some(jump): Option<Stmt> = trailing_loop_jump_stmt(stream, lo, hi) else {
        return body;
    };
    if matches!(
        body.last(),
        Some(Stmt::Break | Stmt::Continue | Stmt::Return(_) | Stmt::Raise { .. })
    ) {
        return body;
    }
    if body.iter().all(|s: &Stmt| matches!(s, Stmt::Pass)) {
        return vec![jump];
    }
    let mut out: Vec<Stmt> = body;
    out.push(jump);
    out
}

#[deny(clippy::indexing_slicing)]
fn trailing_loop_jump_stmt(stream: &DecodedStream, lo: usize, hi: usize) -> Option<Stmt> {
    let last_idx: usize = (lo..hi).rev().find(|&k: &usize| {
        stream.ops.get(k).is_some_and(|op: &CanonicalOp| {
            !matches!(
                op,
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        })
    })?;
    let last_op: &CanonicalOp = stream.ops.get(last_idx)?;
    if !matches!(
        last_op,
        CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
    ) {
        return None;
    }
    let target: usize = resolve_jump_target(stream, last_idx, last_op)?;
    if loop_continue_target().is_some_and(|header: usize| target == header) {
        return Some(Stmt::Continue);
    }
    if loop_break_target().is_some_and(|exit: usize| target >= exit && target > last_idx) {
        return Some(Stmt::Break);
    }
    if target < last_idx && loop_frame_has_header(target) {
        return Some(Stmt::Break);
    }
    None
}

#[deny(clippy::indexing_slicing)]
fn trailing_loop_break_stmt(stream: &DecodedStream, lo: usize, hi: usize) -> Option<Stmt> {
    let last_idx: usize = (lo..hi).rev().find(|&k: &usize| {
        stream.ops.get(k).is_some_and(|op: &CanonicalOp| {
            !matches!(
                op,
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        })
    })?;
    let last_op: &CanonicalOp = stream.ops.get(last_idx)?;
    if matches!(
        last_op,
        CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
    ) {
        let target: usize = resolve_jump_target(stream, last_idx, last_op)?;
        if loop_break_target().is_some_and(|exit: usize| target >= exit && target > last_idx) {
            return Some(Stmt::Break);
        }
    }
    if matches!(
        last_op,
        CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
            | CanonicalOp::JumpAbsolute(_)
    ) {
        let target: usize = resolve_jump_target(stream, last_idx, last_op)?;
        if loop_continue_target() == Some(target) {
            return None;
        }
        if target < last_idx && loop_frame_has_header(target) {
            return Some(Stmt::Break);
        }
    }
    None
}

#[deny(clippy::indexing_slicing)]
fn significant_run(stream: &DecodedStream, lo: usize, hi: usize) -> Vec<usize> {
    (lo..hi)
        .filter(|&k: &usize| {
            stream.ops.get(k).is_some_and(|op: &CanonicalOp| {
                !matches!(
                    op,
                    CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
                )
            })
        })
        .collect()
}

#[deny(clippy::indexing_slicing)]
fn is_straightline_terminator_tail(stream: &DecodedStream, idxs: &[usize]) -> bool {
    let Some(&last): Option<&usize> = idxs.last() else {
        return false;
    };
    if !matches!(
        stream.ops.get(last),
        Some(CanonicalOp::Return | CanonicalOp::ReturnConst(_) | CanonicalOp::Raise(_))
    ) {
        return false;
    }
    idxs.iter().all(|&k: &usize| {
        stream.ops.get(k).is_some_and(|op: &CanonicalOp| {
            !is_back_edge(op)
                && !is_forward_cond_jump(op)
                && !matches!(
                    op,
                    CanonicalOp::JumpForward(_)
                        | CanonicalOp::JumpAbsolute(_)
                        | CanonicalOp::JumpBackward(_)
                        | CanonicalOp::JumpBackwardNoInterrupt(_)
                )
        })
    })
}

#[deny(clippy::indexing_slicing)]
fn ops_equal_run(stream: &DecodedStream, a: &[usize], b: &[usize]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b.iter()).all(|(&x, &y): (&usize, &usize)| {
            matches!(
                (stream.ops.get(x), stream.ops.get(y)),
                (Some(px), Some(py)) if px == py
            )
        })
}

#[deny(clippy::indexing_slicing)]
fn rewrite_inlined_break_tail(
    code: &CodeObject,
    stream: &DecodedStream,
    body: &[Stmt],
    lo: usize,
    hi: usize,
) -> Option<Vec<Stmt>> {
    loop_break_target()?;
    let (t0, t1): (usize, usize) = loop_exit_tail_range()?;
    if hi > t0 {
        return None;
    }
    let tail_idxs: Vec<usize> = significant_run(stream, t0, t1);
    if !is_straightline_terminator_tail(stream, &tail_idxs) {
        return None;
    }
    if matches!(body.last(), Some(Stmt::Break | Stmt::Continue) | None) {
        return None;
    }
    let pop_at: usize = (lo..hi).rev().find(|&p: &usize| {
        matches!(stream.ops.get(p), Some(CanonicalOp::Pop))
            && !is_shortcircuit_cleanup_pop(stream, p)
            && ops_equal_run(stream, &significant_run(stream, p + 1, hi), &tail_idxs)
    })?;
    if pop_at <= lo {
        return None;
    }
    let prefix: Vec<Stmt> = structure_stmts(code, stream, lo, pop_at).ok()?;
    if matches!(
        prefix.last(),
        Some(Stmt::Break | Stmt::Continue | Stmt::Return(_) | Stmt::Raise { .. })
    ) {
        return None;
    }
    let mut out: Vec<Stmt> = prefix;
    out.push(Stmt::Break);
    Some(out)
}

#[deny(clippy::indexing_slicing)]
fn rewrite_jump_to_break_continue(
    code: &CodeObject,
    stream: &DecodedStream,
    body: Vec<Stmt>,
    lo: usize,
    hi: usize,
) -> Vec<Stmt> {
    if let Some(appended) = append_pre311_break_loop(stream, &body, lo, hi) {
        return appended;
    }
    if is_peephole_break_return(stream, &body, lo, hi) {
        return vec![Stmt::Break];
    }
    if let Some(rewritten) = rewrite_inlined_break_tail(code, stream, &body, lo, hi) {
        return rewritten;
    }
    if body.iter().any(|s: &Stmt| !matches!(s, Stmt::Pass)) {
        if !matches!(
            body.last(),
            Some(Stmt::Break | Stmt::Continue | Stmt::Return(_) | Stmt::Raise { .. })
        ) && let Some(brk) = trailing_loop_break_stmt(stream, lo, hi)
        {
            let mut out: Vec<Stmt> = body;
            out.push(brk);
            return out;
        }
        return body;
    }
    let last: Option<usize> = (lo..hi).rev().find(|&k: &usize| {
        stream.ops.get(k).is_some_and(|op: &CanonicalOp| {
            !matches!(
                op,
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        })
    });
    let Some(last_idx): Option<usize> = last else {
        return body;
    };
    let Some(last_op): Option<&CanonicalOp> = stream.ops.get(last_idx) else {
        return body;
    };
    if !matches!(
        last_op,
        CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
    ) {
        return body;
    }
    let Some(target): Option<usize> = resolve_jump_target(stream, last_idx, last_op) else {
        return body;
    };
    let break_at: Option<usize> = loop_break_target();
    let continue_at: Option<usize> = loop_continue_target();
    if let Some(exit) = break_at
        && target >= exit
    {
        return vec![Stmt::Break];
    }
    if let Some(header) = continue_at
        && target == header
    {
        return vec![Stmt::Continue];
    }
    if continue_at != Some(target) && target < last_idx && loop_frame_has_header(target) {
        return vec![Stmt::Break];
    }
    body
}

#[derive(Debug, Clone, Copy)]
pub(super) struct InlineComp {
    pub(super) clear_idx: usize,
    accumulator: usize,
    for_iter: usize,
    pub(super) end_for: usize,
}

pub(super) fn detect_inline_comprehension(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Option<InlineComp> {
    let clear_idx: usize =
        (lo..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::LoadFastAndClear(_)))?;
    let accumulator: usize = (clear_idx + 1..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::BuildList(0) | CanonicalOp::BuildSet(0) | CanonicalOp::BuildMap(0)
        )
    })?;
    let header: usize = (accumulator + 1..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::ForIter(_) | CanonicalOp::GetAnext
        )
    })?;
    let end_for: usize = match stream.ops[header] {
        CanonicalOp::ForIter(_) => resolve_jump_target(stream, header, &stream.ops[header])
            .filter(|t: &usize| *t > header && *t <= hi)?,
        _ => (header + 1..hi)
            .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::EndAsyncFor))
            .map(|e: usize| (e + 1).min(hi))?,
    };
    Some(InlineComp {
        clear_idx,
        accumulator,
        for_iter: header,
        end_for,
    })
}

fn detect_nested_inline_comp(
    stream: &DecodedStream,
    body_start: usize,
    outer_end_for: usize,
) -> Option<InlineComp> {
    let accumulator: usize = (body_start..outer_end_for).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::BuildList(0) | CanonicalOp::BuildSet(0) | CanonicalOp::BuildMap(0)
        )
    })?;
    let header: usize = (accumulator + 1..outer_end_for).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::ForIter(_) | CanonicalOp::GetAnext
        )
    })?;
    let end_for: usize = match stream.ops[header] {
        CanonicalOp::ForIter(_) => resolve_jump_target(stream, header, &stream.ops[header])
            .filter(|t: &usize| *t > header && *t <= outer_end_for)?,
        _ => (header + 1..outer_end_for)
            .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::EndAsyncFor))
            .map(|e: usize| (e + 1).min(outer_end_for))?,
    };
    let for_iter: usize = header;
    let clear_idx: usize = (body_start..accumulator)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::LoadFastAndClear(_)))
        .unwrap_or(body_start);
    Some(InlineComp {
        clear_idx,
        accumulator,
        for_iter,
        end_for,
    })
}

fn inline_comp_element(
    code: &CodeObject,
    stream: &DecodedStream,
    for_iter: usize,
    end_for: usize,
    kind: CompKind,
) -> ComprehensionParts {
    let parts: ComprehensionParts =
        extract_inline_comp_parts(code, stream, for_iter, end_for, kind);
    let (_, after_target): (Expr, usize) = comp_loop_target(code, stream, for_iter + 1);
    if let Some(nested) = detect_nested_inline_comp(stream, after_target, end_for)
        && let Some(nested_elt) = inline_comp_expr(code, stream, &nested)
    {
        return ComprehensionParts {
            target: parts.target,
            elt: nested_elt,
            key_value: None,
            ifs: parts.ifs,
        };
    }
    parts
}

fn inline_comp_expr(code: &CodeObject, stream: &DecodedStream, comp: &InlineComp) -> Option<Expr> {
    let kind: CompKind = match stream.ops[comp.accumulator] {
        CanonicalOp::BuildSet(_) => CompKind::Set,
        CanonicalOp::BuildMap(_) => CompKind::Dict,
        _ => CompKind::List,
    };
    let iter_search_lo: usize = comp.clear_idx.saturating_sub(4);
    let iter_end: usize = (iter_search_lo..comp.for_iter)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter))
        .filter(|&k: &usize| k <= comp.clear_idx + 1)
        .unwrap_or(comp.clear_idx);
    let iter_start: usize = (iter_search_lo.saturating_sub(8)..iter_end)
        .rev()
        .find(|&k: &usize| is_value_boundary(&stream.ops[k]))
        .map_or(iter_search_lo, |b: usize| b + 1)
        .min(iter_end);
    let (_, iter_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, slice_clamped(&stream.ops, iter_start, iter_end)).ok()?;
    let iter: Expr = iter_residual
        .into_iter()
        .next_back()
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });
    let ComprehensionParts {
        target,
        elt,
        key_value,
        ifs,
    }: ComprehensionParts = inline_comp_element(code, stream, comp.for_iter, comp.end_for, kind);
    let nested_bound: usize = detect_nested_inline_comp(stream, comp.for_iter + 1, comp.end_for)
        .map_or(comp.end_for, |n: InlineComp| n.clear_idx);
    let head_is_async: bool = matches!(stream.ops.get(comp.for_iter), Some(CanonicalOp::GetAnext));
    let mut generators: Vec<Comprehension> = comprehension_generators_in(
        code,
        stream,
        kind,
        iter.clone(),
        comp.for_iter,
        nested_bound,
    );
    if generators.is_empty() {
        let ifs_own_line: bool =
            !ifs.is_empty() && clause_filters_use_skip_form(stream, comp.for_iter, nested_bound);
        generators.push(Comprehension {
            target,
            iter,
            ifs,
            is_async: head_is_async,
            ifs_own_line,
        });
    }
    Some(comp_expr_from_parts(kind, elt, key_value, generators))
}

fn comp_expr_from_parts(
    kind: CompKind,
    elt: Expr,
    key_value: Option<(Expr, Expr)>,
    generators: Vec<Comprehension>,
) -> Expr {
    match kind {
        CompKind::List => Expr::ListComp {
            elt: Box::new(elt),
            generators,
        },
        CompKind::Set => Expr::SetComp {
            elt: Box::new(elt),
            generators,
        },
        CompKind::Gen => Expr::GeneratorExp {
            elt: Box::new(elt),
            generators,
        },
        CompKind::Dict => {
            let (k, v): (Expr, Expr) = key_value.unwrap_or((
                elt,
                Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                },
            ));
            Expr::DictComp {
                key: Box::new(k),
                value: Box::new(v),
                generators,
            }
        }
    }
}

fn comp_preceded_by_branch(stream: &DecodedStream, lo: usize, comp: &InlineComp) -> bool {
    (lo..comp.clear_idx).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t > k && (t <= comp.clear_idx || t > comp.end_for))
    })
}

fn comp_preceded_by_loop(stream: &DecodedStream, lo: usize, comp: &InlineComp) -> bool {
    (lo..comp.clear_idx).any(|h: usize| {
        matches!(stream.ops[h], CanonicalOp::ForIter(_))
            && (h + 1..comp.clear_idx).any(|b: usize| {
                is_back_edge(&stream.ops[b])
                    && resolve_jump_target(stream, b, &stream.ops[b]) == Some(h)
            })
    })
}

fn append_op_for(kind: CompKind) -> CanonicalOp {
    match kind {
        CompKind::Set => CanonicalOp::SetAdd,
        CompKind::Dict => CanonicalOp::MapAdd,
        _ => CanonicalOp::ListAppend,
    }
}

fn detect_inline_comprehension_noclear(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Option<InlineComp> {
    if stream.version.major() != 3 || stream.version.minor() < 12 {
        return None;
    }
    if (lo..hi).any(|k: usize| matches!(stream.ops[k], CanonicalOp::LoadFastAndClear(_))) {
        return None;
    }
    let accumulator: usize = (lo..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::BuildList(0) | CanonicalOp::BuildSet(0) | CanonicalOp::BuildMap(0)
        )
    })?;
    let swap: usize = first_significant(stream, accumulator + 1, hi)?;
    if !matches!(stream.ops[swap], CanonicalOp::Swap(2)) {
        return None;
    }
    let header: usize = first_significant(stream, swap + 1, hi)?;
    if !matches!(stream.ops[header], CanonicalOp::ForIter(_)) {
        return None;
    }
    let end_for: usize = resolve_jump_target(stream, header, &stream.ops[header])
        .filter(|t: &usize| *t > header && *t <= hi)?;
    let kind: CompKind = match stream.ops[accumulator] {
        CanonicalOp::BuildSet(_) => CompKind::Set,
        CanonicalOp::BuildMap(_) => CompKind::Dict,
        _ => CompKind::List,
    };
    let want: CanonicalOp = append_op_for(kind);
    if !(header + 1..end_for).any(|k: usize| stream.ops[k] == want) {
        return None;
    }
    Some(InlineComp {
        clear_idx: accumulator,
        accumulator,
        for_iter: header,
        end_for,
    })
}

fn try_structure_inline_comprehension_noclear(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(comp): Option<InlineComp> = detect_inline_comprehension_noclear(stream, lo, hi) else {
        return Ok(None);
    };
    if comp_preceded_by_branch(stream, lo, &comp) {
        return Ok(None);
    }
    if let Some(region) = find_try_region(stream, lo, hi)
        && region.try_start > lo
        && region.try_start <= comp.accumulator
        && comp.accumulator < region.handler_start
        && !try_enclosed_by_loop(stream, lo, hi, &region)
    {
        return Ok(None);
    }
    let kind: CompKind = match stream.ops[comp.accumulator] {
        CanonicalOp::BuildSet(_) => CompKind::Set,
        CanonicalOp::BuildMap(_) => CompKind::Dict,
        _ => CompKind::List,
    };
    let get_iter: usize = (lo..comp.accumulator)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter))
        .unwrap_or(comp.accumulator);
    let (head, mut iter_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..get_iter])?;
    let iter: Expr = iter_residual.pop().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    let pre_residual: Vec<Expr> = iter_residual;
    let ComprehensionParts {
        target,
        elt,
        key_value,
        ifs,
    }: ComprehensionParts = inline_comp_element(code, stream, comp.for_iter, comp.end_for, kind);
    let nested_bound: usize = detect_nested_inline_comp(stream, comp.for_iter + 1, comp.end_for)
        .map_or(comp.end_for, |n: InlineComp| n.clear_idx);
    let mut generators: Vec<Comprehension> = comprehension_generators_in(
        code,
        stream,
        kind,
        iter.clone(),
        comp.for_iter,
        nested_bound,
    );
    if generators.is_empty() {
        generators.push(Comprehension {
            target,
            iter,
            ifs,
            is_async: false,
            ifs_own_line: false,
        });
    }
    let result: Expr = comp_expr_from_parts(kind, elt, key_value, generators);
    let mut out: Vec<Stmt> = head;
    let tail_stmts: Vec<Stmt> =
        consume_inline_comp_result(code, stream, result, comp.end_for, &[], hi, pre_residual)?;
    out.extend(tail_stmts);
    Ok(Some(out))
}

fn try_structure_inline_comprehension(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(comp): Option<InlineComp> = detect_inline_comprehension(stream, lo, hi) else {
        return Ok(None);
    };
    if let Some(region) = find_try_region(stream, lo, hi)
        && region.try_start > lo
        && region.try_start <= comp.clear_idx
        && comp.clear_idx < region.handler_start
        && !try_enclosed_by_loop(stream, lo, hi, &region)
    {
        return Ok(None);
    }
    if comp_preceded_by_branch(stream, lo, &comp) {
        return Ok(None);
    }
    if comp_preceded_by_loop(stream, lo, &comp) {
        return Ok(None);
    }
    let kind: CompKind = match stream.ops[comp.accumulator] {
        CanonicalOp::BuildSet(_) => CompKind::Set,
        CanonicalOp::BuildMap(_) => CompKind::Dict,
        _ => CompKind::List,
    };
    let iter_end: usize = (lo..comp.clear_idx)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter))
        .unwrap_or(comp.clear_idx);
    let (head, mut iter_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..iter_end])?;
    let iter: Expr = iter_residual.pop().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    let pre_residual: Vec<Expr> = iter_residual;
    let ComprehensionParts {
        target,
        elt,
        key_value,
        ifs,
    }: ComprehensionParts = inline_comp_element(code, stream, comp.for_iter, comp.end_for, kind);
    let nested_bound: usize = detect_nested_inline_comp(stream, comp.for_iter + 1, comp.end_for)
        .map_or(comp.end_for, |n: InlineComp| n.clear_idx);
    let head_is_async: bool = matches!(stream.ops.get(comp.for_iter), Some(CanonicalOp::GetAnext));
    let mut generators: Vec<Comprehension> = comprehension_generators_in(
        code,
        stream,
        kind,
        iter.clone(),
        comp.for_iter,
        nested_bound,
    );
    if generators.is_empty() {
        generators.push(Comprehension {
            target,
            iter,
            ifs,
            is_async: head_is_async,
            ifs_own_line: false,
        });
    }
    let result: Expr = comp_expr_from_parts(kind, elt, key_value, generators);
    let clear_slots: Vec<u32> = (lo..comp.accumulator)
        .filter_map(|k: usize| match stream.ops[k] {
            CanonicalOp::LoadFastAndClear(slot) => Some(slot),
            _ => None,
        })
        .collect();
    let mut out: Vec<Stmt> = head;
    let tail_stmts: Vec<Stmt> = consume_inline_comp_result(
        code,
        stream,
        result,
        comp.end_for,
        &clear_slots,
        hi,
        pre_residual,
    )?;
    out.extend(tail_stmts);
    Ok(Some(out))
}

#[derive(Debug, Clone, Copy)]
pub(super) struct OpenCodedAnyAll {
    pub(super) builtin: &'static str,
    pub(super) fallback_start: usize,
}

fn open_coded_builtin_for(name: &str, slot: u8) -> Option<&'static str> {
    match (name, slot) {
        ("tuple", 2) => Some("tuple"),
        ("all", 3) => Some("all"),
        ("any", 4) => Some("any"),
        _ => None,
    }
}

pub(super) fn detect_open_coded_any_all_guard(
    code: &CodeObject,
    stream: &DecodedStream,
    idx: usize,
    hi: usize,
) -> Option<(&'static str, usize)> {
    let name: String = match stream.ops[idx] {
        CanonicalOp::LoadGlobal(slot)
        | CanonicalOp::LoadName(slot)
        | CanonicalOp::LoadFromDictOrGlobals(slot) => name_at_either(code, slot).ok()?,
        CanonicalOp::LoadFast(slot) => local_name_at(code, slot, idx).ok()?,
        CanonicalOp::LoadFastLoadFast(_, callable_slot) => {
            local_name_at(code, callable_slot, idx).ok()?
        }
        _ => return None,
    };
    let copy_idx: usize = first_significant(stream, idx + 1, hi)?;
    if !matches!(stream.ops[copy_idx], CanonicalOp::Copy(1)) {
        return None;
    }
    let const_idx: usize = first_significant(stream, copy_idx + 1, hi)?;
    let CanonicalOp::LoadCommonConst(common_slot): CanonicalOp = stream.ops[const_idx] else {
        return None;
    };
    let builtin: &'static str = open_coded_builtin_for(name.as_str(), common_slot)?;
    let is_idx: usize = first_significant(stream, const_idx + 1, hi)?;
    if !matches!(stream.ops[is_idx], CanonicalOp::Compare(CmpOp::Is)) {
        return None;
    }
    let jump_idx: usize = first_significant(stream, is_idx + 1, hi)?;
    if !matches!(
        stream.ops[jump_idx],
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
    ) {
        return None;
    }
    let fallback: usize = resolve_jump_target(stream, jump_idx, &stream.ops[jump_idx])
        .filter(|t: &usize| *t > jump_idx && *t <= hi)?;
    Some((builtin, fallback))
}

pub(super) fn recover_open_coded_call(
    code: &CodeObject,
    stream: &DecodedStream,
    idiom: &OpenCodedAnyAll,
    hi: usize,
) -> Result<Option<(Expr, usize)>> {
    let seed_name = || -> Expr {
        Expr::Name {
            id: idiom.builtin.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }
    };
    for cand in (idiom.fallback_start..hi)
        .filter(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CallFunction(1)))
    {
        let (_, residual): (Vec<Stmt>, Vec<Expr>) = build_linear_stmts_sim_seed(
            code,
            &stream.ops[idiom.fallback_start..=cand],
            vec![seed_name()],
        )?;
        if residual.len() == 1
            && let Some(Expr::Call { func, .. }) = residual.last()
            && matches!(func.as_ref(), Expr::Name { id, .. } if id == idiom.builtin)
        {
            return Ok(Some((
                residual.into_iter().next_back().unwrap_or_else(seed_name),
                cand,
            )));
        }
    }
    Ok(None)
}

fn inframe_listcomp_at(stream: &DecodedStream, idx: usize, hi: usize) -> Option<(usize, usize)> {
    if !matches!(stream.ops.get(idx), Some(CanonicalOp::BuildList(0))) {
        return None;
    }
    let for_iter: usize =
        (idx + 1..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::ForIter(_)))?;
    let get_iter: usize = (idx + 1..for_iter)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter))?;
    if (idx + 1..get_iter).any(|k: usize| is_value_boundary(&stream.ops[k])) {
        return None;
    }
    let end_for: usize = resolve_jump_target(stream, for_iter, &stream.ops[for_iter])
        .filter(|t: &usize| *t > for_iter && *t <= hi)?;
    let has_append: bool =
        (for_iter + 1..end_for).any(|k: usize| matches!(stream.ops[k], CanonicalOp::ListAppend));
    if !has_append {
        return None;
    }
    Some((for_iter, end_for))
}

fn try_structure_inframe_listcomp(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    if stream.version.major() >= 3 {
        return Ok(None);
    }
    let Some(comp_start): Option<usize> =
        (lo..hi).find(|&k: &usize| inframe_listcomp_at(stream, k, hi).is_some())
    else {
        return Ok(None);
    };
    let Some((for_iter, end_for)): Option<(usize, usize)> =
        inframe_listcomp_at(stream, comp_start, hi)
    else {
        return Ok(None);
    };

    let (head, head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..comp_start])?;

    let get_iter: usize = (comp_start + 1..for_iter)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter))
        .unwrap_or(comp_start);
    let iter_start: usize = (comp_start..get_iter)
        .rev()
        .find(|&k: &usize| is_value_boundary(&stream.ops[k]))
        .map_or(comp_start + 1, |b: usize| b + 1)
        .min(get_iter);
    let (_, iter_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, slice_clamped(&stream.ops, iter_start, get_iter))?;
    let iter: Expr = iter_residual
        .into_iter()
        .next_back()
        .unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        });

    let ComprehensionParts {
        target,
        elt,
        key_value,
        ifs,
    }: ComprehensionParts =
        extract_inline_comp_parts(code, stream, for_iter, end_for, CompKind::List);
    let mut generators: Vec<Comprehension> = comprehension_generators_in(
        code,
        stream,
        CompKind::List,
        iter.clone(),
        for_iter,
        end_for,
    );
    if generators.is_empty() {
        generators.push(Comprehension {
            target,
            iter,
            ifs,
            is_async: false,
            ifs_own_line: false,
        });
    }
    let comp: Expr = comp_expr_from_parts(CompKind::List, elt, key_value, generators);

    let consumer_end: usize = (end_for..hi)
        .find(|&k: &usize| inframe_listcomp_at(stream, k, hi).is_some())
        .unwrap_or(hi);
    let mut seed: Vec<Expr> = head_residual;
    seed.push(comp);
    let (consumed, _residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &stream.ops[end_for..consumer_end], seed)?;

    let mut out: Vec<Stmt> = head;
    out.extend(consumed);
    out.extend(structure_stmts(code, stream, consumer_end, hi)?);
    Ok(Some(out))
}

fn extract_inline_comp_parts(
    code: &CodeObject,
    stream: &DecodedStream,
    for_iter: usize,
    end_for: usize,
    kind: CompKind,
) -> ComprehensionParts {
    let target_at: usize = for_iter + 1;
    let (target, body_start): (Expr, usize) = match stream.ops.get(target_at) {
        Some(CanonicalOp::BuildTuple(_)) => recover_tuple_target(code, stream, target_at, end_for),
        _ => single_store_target(code, &stream.ops, target_at)
            .unwrap_or_else(|| (placeholder_target(), target_at + 1)),
    };
    let mut ifs: Vec<Expr> = Vec::new();
    let mut elt: Option<Expr> = None;
    let mut key_value: Option<(Expr, Expr)> = None;
    let mut elt_start: usize = body_start;
    let mut i: usize = body_start;
    while i < end_for {
        match &stream.ops[i] {
            CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalseBackward(_)
            | CanonicalOp::PopJumpIfTrueBackward(_) => {
                let cond_end: usize = i;
                let expr_start: usize = cond_expr_start(stream, cond_end, body_start);
                let (_, residual): (Vec<Stmt>, Vec<Expr>) =
                    build_linear_stmts_sim(code, &stream.ops[expr_start..cond_end])
                        .unwrap_or_default();
                if let Some(cond) = residual.into_iter().next_back() {
                    let keep_when_true: bool = inline_filter_keeps_when_true(stream, cond_end);
                    ifs.push(if keep_when_true {
                        cond
                    } else {
                        Expr::UnaryOp {
                            op: crate::bytecode::opcode::UnaryOp::Not,
                            operand: Box::new(cond),
                        }
                    });
                }
                let append: usize = (cond_end + 1..end_for)
                    .find(|&k: &usize| {
                        matches!(
                            stream.ops[k],
                            CanonicalOp::ListAppend | CanonicalOp::SetAdd | CanonicalOp::MapAdd
                        )
                    })
                    .unwrap_or(end_for);
                let fallthrough: Option<usize> = first_significant(stream, cond_end + 1, append)
                    .filter(|&k: &usize| !is_back_edge(&stream.ops[k]));
                i = fallthrough.unwrap_or_else(|| {
                    resolve_jump_target(stream, cond_end, &stream.ops[cond_end])
                        .filter(|&t: &usize| t > cond_end && t < append)
                        .unwrap_or(append)
                });
                elt_start = i;
            }
            CanonicalOp::ListAppend | CanonicalOp::SetAdd => {
                let (_, residual): (Vec<Stmt>, Vec<Expr>) =
                    build_linear_stmts_sim(code, &stream.ops[elt_start..i]).unwrap_or_default();
                elt = residual.into_iter().next_back();
                break;
            }
            CanonicalOp::MapAdd => {
                let (_, mut residual): (Vec<Stmt>, Vec<Expr>) =
                    build_linear_stmts_sim(code, &stream.ops[elt_start..i]).unwrap_or_default();
                let v: Option<Expr> = residual.pop();
                let k: Option<Expr> = residual.pop();
                if let (Some(kk), Some(vv)) = (k, v) {
                    elt = Some(kk.clone());
                    key_value = Some((kk, vv));
                }
                break;
            }
            _ => i += 1,
        }
    }
    let _ = kind;
    ComprehensionParts {
        target,
        elt: elt.unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        }),
        key_value,
        ifs,
    }
}

fn expand_fused_target_ops(ops: &[CanonicalOp], start: usize) -> (Vec<CanonicalOp>, Vec<usize>) {
    let mut expanded: Vec<CanonicalOp> = Vec::with_capacity(ops.len() - start);
    let mut map: Vec<usize> = Vec::with_capacity(ops.len() - start);
    for (offset, op) in ops[start..].iter().enumerate() {
        let src: usize = start + offset;
        match op {
            CanonicalOp::StoreFastStoreFast(a, b) => {
                expanded.push(CanonicalOp::StoreFast(*a));
                map.push(src);
                expanded.push(CanonicalOp::StoreFast(*b));
                map.push(src);
            }
            CanonicalOp::StoreFastLoadFast(a, b) => {
                expanded.push(CanonicalOp::StoreFast(*a));
                map.push(src);
                expanded.push(CanonicalOp::LoadFast(*b));
                map.push(src);
            }
            CanonicalOp::LoadFastLoadFast(a, b) => {
                expanded.push(CanonicalOp::LoadFast(*a));
                map.push(src);
                expanded.push(CanonicalOp::LoadFast(*b));
                map.push(src);
            }
            other => {
                expanded.push(other.clone());
                map.push(src);
            }
        }
    }
    map.push(ops.len());
    (expanded, map)
}

pub(super) fn collect_unpack_targets(
    code: &CodeObject,
    ops: &[CanonicalOp],
    start: usize,
    n: usize,
) -> Option<(Vec<Expr>, usize)> {
    if n == 0 {
        return None;
    }
    let (expanded, map): (Vec<CanonicalOp>, Vec<usize>) = expand_fused_target_ops(ops, start);
    let (targets, exp_consumed): (Vec<Expr>, usize) =
        collect_unpack_targets_expanded(code, &expanded, 0, n)?;
    let src_after: usize = *map.get(exp_consumed)?;
    Some((targets, src_after - start))
}

fn collect_unpack_targets_expanded(
    code: &CodeObject,
    ops: &[CanonicalOp],
    start: usize,
    n: usize,
) -> Option<(Vec<Expr>, usize)> {
    let mut targets: Vec<Expr> = Vec::with_capacity(n);
    let mut i: usize = start;
    let mut consumed: usize = 0;
    while consumed < n && i < ops.len() {
        match &ops[i] {
            CanonicalOp::StoreFast(slot) => {
                targets.push(local_target(code, *slot, i).ok()?);
                consumed += 1;
            }
            CanonicalOp::StoreName(slot) | CanonicalOp::StoreGlobal(slot) => {
                let name: String = name_at(&code.names, *slot, i, "name").ok()?;
                targets.push(Expr::Name {
                    id: name,
                    ctx: ExprCtx::Store,
                    line: None,
                });
                consumed += 1;
            }
            CanonicalOp::StoreAttr(_) | CanonicalOp::StoreSubscr | CanonicalOp::StoreSlice => {
                let group_end: usize = chain_group_end(ops, i)?;
                targets.push(recover_chain_target(code, ops, i, group_end)?);
                consumed += 1;
                i = group_end;
                continue;
            }
            CanonicalOp::UnpackSequence(0) => {
                targets.push(Expr::Tuple {
                    elts: Vec::new(),
                    ctx: ExprCtx::Store,
                });
                consumed += 1;
            }
            CanonicalOp::UnpackSequence(m) => {
                let (inner, skip): (Vec<Expr>, usize) =
                    collect_unpack_targets_expanded(code, ops, i + 1, *m as usize)?;
                targets.push(Expr::Tuple {
                    elts: inner,
                    ctx: ExprCtx::Store,
                });
                consumed += 1;
                i = i + 1 + skip;
                continue;
            }
            CanonicalOp::UnpackEx(arg) => {
                let before: usize = (arg & 0xFF) as usize;
                let after: usize = (arg >> 8) as usize;
                let total: usize = before + after + 1;
                let (mut inner, skip): (Vec<Expr>, usize) =
                    collect_unpack_targets_expanded(code, ops, i + 1, total)?;
                if before < inner.len() {
                    let starred: Expr = inner.remove(before);
                    inner.insert(
                        before,
                        Expr::Starred {
                            value: Box::new(starred),
                            ctx: ExprCtx::Store,
                        },
                    );
                }
                targets.push(Expr::Tuple {
                    elts: inner,
                    ctx: ExprCtx::Store,
                });
                consumed += 1;
                i = i + 1 + skip;
                continue;
            }
            CanonicalOp::Pop => {
                targets.push(next_store_dup_target(code, ops, i + 1)?);
                consumed += 1;
            }
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            _ => {
                let group_end: usize = chain_group_end(ops, i)?;
                let target: Expr = recover_chain_target(code, ops, i, group_end)?;
                targets.push(target);
                consumed += 1;
                i = group_end;
                continue;
            }
        }
        i += 1;
    }
    if consumed != n {
        return None;
    }
    Some((targets, i - start))
}

fn next_store_dup_target(code: &CodeObject, ops: &[CanonicalOp], from: usize) -> Option<Expr> {
    let mut i: usize = from;
    while i < ops.len() {
        match &ops[i] {
            CanonicalOp::Pop
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_) => {
                i += 1;
            }
            CanonicalOp::StoreFast(slot) => return local_target(code, *slot, i).ok(),
            CanonicalOp::StoreName(slot) | CanonicalOp::StoreGlobal(slot) => {
                return Some(Expr::Name {
                    id: name_at(&code.names, *slot, i, "name").ok()?,
                    ctx: ExprCtx::Store,
                    line: None,
                });
            }
            _ => return None,
        }
    }
    None
}

pub(super) fn merge_or_push_delete(out: &mut Vec<Stmt>, target: Expr) {
    if let Some(Stmt::Delete(prev)) = out.last_mut() {
        prev.push(target);
    } else {
        out.push(Stmt::Delete(vec![target]));
    }
}

pub(super) fn placeholder_target() -> Expr {
    Expr::Name {
        id: DR_UNRECOVERED_TARGET.to_owned(),
        ctx: ExprCtx::Store,
        line: None,
    }
}

pub(super) fn single_store_target(
    code: &CodeObject,
    ops: &[CanonicalOp],
    start: usize,
) -> Option<(Expr, usize)> {
    match ops.get(start)? {
        CanonicalOp::StoreFast(slot) => Some((local_target(code, *slot, start).ok()?, start + 1)),
        CanonicalOp::StoreName(slot) | CanonicalOp::StoreGlobal(slot) => Some((
            Expr::Name {
                id: name_at(&code.names, *slot, start, "name").ok()?,
                ctx: ExprCtx::Store,
                line: None,
            },
            start + 1,
        )),
        CanonicalOp::StoreFastLoadFast(slot, _) => {
            Some((local_target(code, *slot, start).ok()?, start))
        }
        CanonicalOp::UnpackSequence(0) => Some((
            Expr::Tuple {
                elts: Vec::new(),
                ctx: ExprCtx::Store,
            },
            start + 1,
        )),
        CanonicalOp::UnpackSequence(n) => {
            let (targets, skip): (Vec<Expr>, usize) =
                collect_unpack_targets(code, ops, start + 1, *n as usize)?;
            Some((
                Expr::Tuple {
                    elts: targets,
                    ctx: ExprCtx::Store,
                },
                start + 1 + skip,
            ))
        }
        CanonicalOp::UnpackEx(arg) => {
            let before: usize = (arg & 0xFF) as usize;
            let after: usize = (arg >> 8) as usize;
            let total: usize = before + after + 1;
            let (mut elts, skip): (Vec<Expr>, usize) =
                collect_unpack_targets(code, ops, start + 1, total)?;
            if before < elts.len() {
                let starred: Expr = elts.remove(before);
                elts.insert(
                    before,
                    Expr::Starred {
                        value: Box::new(starred),
                        ctx: ExprCtx::Store,
                    },
                );
            }
            Some((
                Expr::Tuple {
                    elts,
                    ctx: ExprCtx::Store,
                },
                start + 1 + skip,
            ))
        }
        _ => {
            let group_end: usize = chain_group_end(ops, start)?;
            Some((
                recover_chain_target(code, ops, start, group_end)?,
                group_end,
            ))
        }
    }
}

pub(super) fn recover_tuple_target(
    code: &CodeObject,
    stream: &DecodedStream,
    at: usize,
    hi: usize,
) -> (Expr, usize) {
    let region: LoopRegion = LoopRegion {
        kind: LoopKind::For,
        header: at.saturating_sub(1),
        body_start: at,
        body_end: hi,
        back_edge: hi,
        exit: hi,
        infinite: false,
    };
    recover_for_target(code, stream, &region).unwrap_or_else(|| (placeholder_target(), at + 1))
}

fn inline_filter_keeps_when_true(stream: &DecodedStream, cond_idx: usize) -> bool {
    let jumps_to_continue: bool = resolve_jump_target(stream, cond_idx, &stream.ops[cond_idx])
        .and_then(|t: usize| {
            first_significant(stream, t, stream.ops.len())
                .map(|s: usize| is_back_edge(&stream.ops[s]))
        })
        .unwrap_or(false);
    let fallthrough_is_continue: bool = first_significant(stream, cond_idx + 1, stream.ops.len())
        .is_some_and(|s: usize| is_back_edge(&stream.ops[s]));
    match stream.ops[cond_idx] {
        CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfTrueBackward(_) => {
            !jumps_to_continue && fallthrough_is_continue
        }
        _ => jumps_to_continue || !fallthrough_is_continue,
    }
}

fn inframe_comp_result_discarded(stream: &DecodedStream, end_for: usize, consumer: usize) -> bool {
    let mut structural_pops_seen: u8 = 0u8;
    for op in &stream.ops[end_for..consumer] {
        match op {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::Pop if structural_pops_seen < 2 => structural_pops_seen += 1,
            CanonicalOp::Pop => return true,
            _ => return false,
        }
    }
    false
}

fn consume_inline_comp_result(
    code: &CodeObject,
    stream: &DecodedStream,
    result: Expr,
    end_for: usize,
    clear_slots: &[u32],
    hi: usize,
    pre_residual: Vec<Expr>,
) -> Result<Vec<Stmt>> {
    let hi: usize = trim_trailing_comp_cleanup(stream, end_for, hi);
    let is_restore_noise = |op: &CanonicalOp| -> bool {
        matches!(
            op,
            CanonicalOp::Swap(_) | CanonicalOp::Pop | CanonicalOp::Cache | CanonicalOp::Nop
        ) || matches!(op, CanonicalOp::StoreFast(s) if clear_slots.contains(s))
    };
    let mut consumer: usize = end_for;
    while consumer < hi && is_restore_noise(&stream.ops[consumer]) {
        consumer += 1;
    }
    let tail_after = |stream: &DecodedStream, mut j: usize| -> usize {
        while j < hi && is_restore_noise(&stream.ops[j]) {
            j += 1;
        }
        j
    };
    let result_discarded: bool = inframe_comp_result_discarded(stream, end_for, consumer);
    if pre_residual.is_empty() {
        match stream.ops.get(consumer) {
            Some(CanonicalOp::Return | CanonicalOp::ReturnConst(_)) => {
                return Ok(vec![Stmt::Return(Some(result))]);
            }
            Some(CanonicalOp::StoreFast(slot)) => {
                let target: Expr = local_target(code, *slot, consumer)?;
                let mut out: Vec<Stmt> = vec![Stmt::Assign {
                    targets: vec![target],
                    value: result,
                    type_comment: None,
                    line: None,
                }];
                out.extend(structure_stmts(
                    code,
                    stream,
                    tail_after(stream, consumer + 1),
                    hi,
                )?);
                return Ok(out);
            }
            Some(CanonicalOp::StoreName(slot) | CanonicalOp::StoreGlobal(slot)) => {
                let target: Expr = Expr::Name {
                    id: name_at(&code.names, *slot, consumer, "name")?,
                    ctx: ExprCtx::Store,
                    line: None,
                };
                let mut out: Vec<Stmt> = vec![Stmt::Assign {
                    targets: vec![target],
                    value: result,
                    type_comment: None,
                    line: None,
                }];
                out.extend(structure_stmts(
                    code,
                    stream,
                    tail_after(stream, consumer + 1),
                    hi,
                )?);
                return Ok(out);
            }
            Some(CanonicalOp::GetIter | CanonicalOp::GetAiter)
                if matches!(
                    first_significant(stream, consumer + 1, hi).map(|k: usize| &stream.ops[k]),
                    Some(CanonicalOp::ForIter(_))
                ) =>
            {
                if let Some(stmts) =
                    structure_for_loop_with_iter(code, stream, result.clone(), consumer, hi)?
                {
                    return Ok(stmts);
                }
            }
            _ if result_discarded => {
                let mut out: Vec<Stmt> = vec![Stmt::Expr(result)];
                out.extend(structure_stmts(code, stream, consumer, hi)?);
                return Ok(out);
            }
            _ => {}
        }
    }
    let mut seed: Vec<Expr> = pre_residual;
    seed.push(result);
    let comp_cap: usize = (consumer..hi)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::LoadFastAndClear(_)))
        .map_or(hi, |next_comp: usize| {
            (consumer..next_comp)
                .rev()
                .find(|&k: &usize| {
                    matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter)
                })
                .map_or(next_comp, |get_iter: usize| {
                    inline_comp_consumer_boundary(stream, consumer, get_iter)
                })
        });
    let consumer_end: usize =
        comp_cap.min(comp_tail_controlflow_boundary(stream, consumer, comp_cap));
    let (consumed, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &stream.ops[consumer..consumer_end], seed)?;
    let mut out: Vec<Stmt> = if consumed.is_empty() {
        residual
            .into_iter()
            .next_back()
            .map(Stmt::Expr)
            .into_iter()
            .collect()
    } else {
        consumed
    };
    out.extend(structure_stmts(code, stream, consumer_end, hi)?);
    Ok(out)
}

fn inline_comp_consumer_boundary(
    stream: &DecodedStream,
    consumer: usize,
    get_iter: usize,
) -> usize {
    let mut k: usize = get_iter;
    while k > consumer {
        match stream.ops[k - 1] {
            CanonicalOp::LoadFast(_)
            | CanonicalOp::LoadName(_)
            | CanonicalOp::LoadGlobal(_)
            | CanonicalOp::LoadFromDictOrGlobals(_)
            | CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadCommonConst(_)
            | CanonicalOp::LoadAttr(_)
            | CanonicalOp::Push(_)
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_) => k -= 1,
            _ => break,
        }
    }
    k
}

fn comp_tail_controlflow_boundary(stream: &DecodedStream, consumer: usize, hi: usize) -> usize {
    let Some(jump): Option<usize> = (consumer..hi).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t > k && t <= hi)
    }) else {
        return hi;
    };
    let mut boundary: usize = consumer;
    for k in consumer..jump {
        if matches!(
            stream.ops[k],
            CanonicalOp::StoreFast(_)
                | CanonicalOp::StoreName(_)
                | CanonicalOp::StoreGlobal(_)
                | CanonicalOp::StoreAttr(_)
                | CanonicalOp::StoreSubscr
                | CanonicalOp::StoreFastLoadFast(_, _)
                | CanonicalOp::StoreFastStoreFast(_, _)
        ) {
            boundary = k + 1;
        }
    }
    boundary
}

pub(super) fn first_significant(stream: &DecodedStream, from: usize, hi: usize) -> Option<usize> {
    (from..hi).find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    })
}

#[inline]
pub(super) fn is_await_null_slot(ops: &[CanonicalOp], idx: usize) -> bool {
    let mut k: usize = idx;
    while k > 0 {
        k -= 1;
        match &ops[k] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::GetAwaitable => return true,
            _ => return false,
        }
    }
    false
}

fn try_structure_below_test_terminating_arms(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    jump_idx: usize,
    target: usize,
) -> Result<Option<Vec<Stmt>>> {
    if target <= jump_idx + 1 || target >= hi {
        return Ok(None);
    }
    if !matches!(
        stream.ops[jump_idx],
        CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfFalseRel(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
    ) {
        return Ok(None);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..jump_idx])?;
    if !head.is_empty() || residual.len() < 2 {
        return Ok(None);
    }
    if !region_is_linear(stream, jump_idx + 1, target)
        || !region_is_linear(stream, target, hi)
        || !region_ends_in_hard_terminator(stream, jump_idx + 1, target)
        || !region_ends_in_hard_terminator(stream, target, hi)
    {
        return Ok(None);
    }
    let mut below: Vec<Expr> = residual;
    let raw_test: Expr = below.pop().unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let (then_stmts, then_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &stream.ops[jump_idx + 1..target], below.clone())?;
    let (else_stmts, else_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &stream.ops[target..hi], below)?;
    if !then_residual.is_empty()
        || !else_residual.is_empty()
        || then_stmts.is_empty()
        || else_stmts.is_empty()
    {
        return Ok(None);
    }
    let none_jump: bool = stream.none_jump_kind.contains_key(&jump_idx);
    let negate: bool = matches!(
        stream.ops[jump_idx],
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
    );
    let test: Expr = none_jump_test(stream, jump_idx, raw_test.clone()).unwrap_or(raw_test);
    let (body, orelse): (Vec<Stmt>, Vec<Stmt>) = if negate || none_jump {
        (then_stmts, else_stmts)
    } else {
        (else_stmts, then_stmts)
    };
    if body.len() == 1
        && orelse.len() == 1
        && let Some(folded) = merge_terminating_ternary(&test, &body[0], &orelse[0])
    {
        return Ok(Some(vec![folded]));
    }
    Ok(Some(vec![Stmt::If {
        test,
        body,
        orelse,
        line: None,
    }]))
}

fn merge_terminating_ternary(test: &Expr, a: &Stmt, b: &Stmt) -> Option<Stmt> {
    match (a, b) {
        (
            Stmt::Raise {
                exc: Some(ea),
                cause: ca,
                line,
            },
            Stmt::Raise {
                exc: Some(eb),
                cause: cb,
                ..
            },
        ) if ca == cb => {
            let (merged, diffs): (Expr, usize) = merge_ternary_expr(test, ea, eb)?;
            (diffs == 1).then(|| Stmt::Raise {
                exc: Some(merged),
                cause: ca.clone(),
                line: *line,
            })
        }
        (Stmt::Return(Some(ea)), Stmt::Return(Some(eb))) => {
            let (merged, diffs): (Expr, usize) = merge_ternary_expr(test, ea, eb)?;
            (diffs == 1).then_some(Stmt::Return(Some(merged)))
        }
        _ => None,
    }
}

fn merge_ternary_expr(test: &Expr, a: &Expr, b: &Expr) -> Option<(Expr, usize)> {
    if a == b {
        return Some((a.clone(), 0));
    }
    match (a, b) {
        (
            Expr::Call {
                func: fa,
                args: aa,
                keywords: ka,
            },
            Expr::Call {
                func: fb,
                args: ab,
                keywords: kb,
            },
        ) if aa.len() == ab.len() && ka == kb => {
            let (merged_func, mut diffs): (Expr, usize) = merge_ternary_expr(test, fa, fb)?;
            let mut merged_args: Vec<Expr> = Vec::with_capacity(aa.len());
            for (xa, xb) in aa.iter().zip(ab.iter()) {
                let (m, d): (Expr, usize) = merge_ternary_expr(test, xa, xb)?;
                diffs += d;
                merged_args.push(m);
            }
            Some((
                Expr::Call {
                    func: Box::new(merged_func),
                    args: merged_args,
                    keywords: ka.clone(),
                },
                diffs,
            ))
        }
        (
            Expr::Attribute {
                value: va,
                attr: na,
                ctx: cx,
            },
            Expr::Attribute {
                value: vb,
                attr: nb,
                ctx: cb,
            },
        ) if na == nb && cx == cb => {
            let (merged, diffs): (Expr, usize) = merge_ternary_expr(test, va, vb)?;
            Some((
                Expr::Attribute {
                    value: Box::new(merged),
                    attr: na.clone(),
                    ctx: *cx,
                },
                diffs,
            ))
        }
        _ => Some((
            Expr::IfExp {
                test: Box::new(test.clone()),
                body: Box::new(a.clone()),
                orelse: Box::new(b.clone()),
            },
            1,
        )),
    }
}

pub(super) fn region_ends_in_hard_terminator(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    last_significant_back(stream, lo, hi).is_some_and(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return
                | CanonicalOp::ReturnConst(_)
                | CanonicalOp::Raise(_)
                | CanonicalOp::Reraise(_)
        )
    })
}

pub(super) fn last_significant_back(stream: &DecodedStream, lo: usize, hi: usize) -> Option<usize> {
    (lo..hi).rev().find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    })
}

pub(super) fn loads_none(code: &CodeObject, op: &CanonicalOp) -> bool {
    matches!(op, CanonicalOp::LoadConst(idx) | CanonicalOp::ReturnConst(idx)
        if matches!(code.consts.get(*idx as usize), Some(Object::None)))
}

fn dead_none_epilogue_start(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Option<usize> {
    let last: usize = last_significant_back(stream, lo, hi)?;
    let epilogue_start: usize = match stream.ops[last] {
        CanonicalOp::ReturnConst(idx)
            if matches!(code.consts.get(idx as usize), Some(Object::None)) =>
        {
            last
        }
        CanonicalOp::Return => {
            let prev: usize = last_significant_back(stream, lo, last)?;
            if !loads_none(code, &stream.ops[prev]) {
                return None;
            }
            prev
        }
        _ => return None,
    };
    region_ends_in_hard_terminator(stream, lo, epilogue_start).then_some(epilogue_start)
}

fn then_arm_opens_handler_after(stream: &DecodedStream, then_lo: usize, target: usize) -> bool {
    let (Some(&then_off), Some(&target_off)): (Option<&u32>, Option<&u32>) =
        (stream.offsets.get(then_lo), stream.offsets.get(target))
    else {
        return false;
    };
    stream
        .exception_table
        .iter()
        .any(|e: &crate::bytecode::flow::ExceptionTableEntry| {
            e.start >= then_off && e.start < target_off && e.target >= target_off
        })
}

fn hard_terminator_else_end(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    jump_idx: usize,
    body_end: usize,
    target: usize,
) -> Option<usize> {
    if active_version().is_some_and(|v: PyVersion| (v.major(), v.minor()) >= (3, 12)) {
        let else_terminates: bool = region_ends_in_hard_terminator(stream, target, hi);
        if else_terminates
            && (shares_duplicated_tail(code, stream, jump_idx + 1, body_end, target, hi)
                || (then_arm_ends_in_inlined_none_return(code, stream, jump_idx + 1, body_end)
                    && region_ends_in_raise(stream, target, hi)))
        {
            return Some(hi);
        }
        return None;
    }
    dead_none_epilogue_start(code, stream, lo, hi).filter(|&epilogue_start: &usize| {
        region_ends_in_hard_terminator(stream, target, epilogue_start)
    })
}

fn region_ends_in_raise(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    last_significant_back(stream, lo, hi)
        .is_some_and(|k: usize| matches!(stream.ops[k], CanonicalOp::Raise(_)))
}

fn then_arm_ends_in_inlined_none_return(
    code: &CodeObject,
    stream: &DecodedStream,
    then_lo: usize,
    then_hi: usize,
) -> bool {
    let Some(last): Option<usize> = last_significant_back(stream, then_lo, then_hi) else {
        return false;
    };
    let ends_in_none: bool = match stream.ops[last] {
        CanonicalOp::ReturnConst(_) => loads_none(code, &stream.ops[last]),
        CanonicalOp::Return => last_significant_back(stream, then_lo, last)
            .is_some_and(|prev: usize| loads_none(code, &stream.ops[prev])),
        _ => false,
    };
    ends_in_none && then_arm_unconditionally_terminates(stream, then_lo, then_hi)
}

fn then_arm_unconditionally_terminates(
    stream: &DecodedStream,
    then_lo: usize,
    then_hi: usize,
) -> bool {
    !(then_lo..then_hi).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t > k && t <= then_hi)
    })
}

fn shares_duplicated_tail(
    code: &CodeObject,
    stream: &DecodedStream,
    then_lo: usize,
    then_hi: usize,
    else_lo: usize,
    else_hi: usize,
) -> bool {
    let then_tail: Vec<usize> = significant_indices_back(stream, then_lo, then_hi);
    let else_tail: Vec<usize> = significant_indices_back(stream, else_lo, else_hi);
    let mut matched: Vec<&CanonicalOp> = Vec::new();
    for (a, b) in then_tail.iter().zip(else_tail.iter()) {
        if stream.ops[*a] != stream.ops[*b] {
            break;
        }
        matched.push(&stream.ops[*a]);
    }
    let genuine_none_else: bool = then_tail.len() > matched.len()
        && else_tail.len() > matched.len()
        && region_all_paths_terminate(stream, then_lo, then_hi);
    match matched.as_slice() {
        [op @ CanonicalOp::ReturnConst(_), ..] => !loads_none(code, op) || genuine_none_else,
        [CanonicalOp::Raise(_) | CanonicalOp::Reraise(_), _, ..] => true,
        [CanonicalOp::Return, value, ..] => !loads_none(code, value) || genuine_none_else,
        _ => false,
    }
}

fn region_all_paths_terminate(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    if lo >= hi || hi > stream.ops.len() {
        return false;
    }
    let mut visited: Vec<bool> = vec![false; hi - lo];
    let mut work: Vec<usize> = vec![lo];
    while let Some(idx) = work.pop() {
        if idx < lo || idx >= hi {
            return false;
        }
        let slot: usize = idx - lo;
        if visited[slot] {
            continue;
        }
        visited[slot] = true;
        match &stream.ops[idx] {
            CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
            | CanonicalOp::Raise(_)
            | CanonicalOp::Reraise(_) => {}
            op @ (CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)) => {
                match resolve_jump_target(stream, idx, op) {
                    Some(target) => work.push(target),
                    None => return false,
                }
            }
            op => match resolve_jump_target(stream, idx, op) {
                Some(target) => {
                    work.push(target);
                    work.push(idx + 1);
                }
                None => work.push(idx + 1),
            },
        }
    }
    true
}

fn significant_indices_back(stream: &DecodedStream, lo: usize, hi: usize) -> Vec<usize> {
    (lo..hi)
        .rev()
        .filter(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        })
        .collect()
}

fn guard_head_and_test(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    jump_idx: usize,
) -> Result<Option<(Vec<Stmt>, Expr)>> {
    let test_start: usize = cond_expr_start(stream, jump_idx, lo);
    let prefix_has_branch: bool = test_start > lo
        && (lo..test_start).any(|i: usize| {
            is_forward_cond_jump(&stream.ops[i])
                && !is_chain_cond_jump(&stream.ops, i)
                && !is_value_form_shortcircuit(&stream.ops, i)
                && resolve_jump_target(stream, i, &stream.ops[i])
                    .is_some_and(|t: usize| t > i && t <= test_start)
        });
    if prefix_has_branch {
        let head: Vec<Stmt> = structure_stmts(code, stream, lo, test_start)?;
        let (extra, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[test_start..jump_idx])?;
        if extra.is_empty()
            && let Some(test) = residual.into_iter().next_back()
        {
            return Ok(Some((head, test)));
        }
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..jump_idx])?;
    Ok(residual
        .into_iter()
        .next_back()
        .map(|test: Expr| (head, test)))
}

fn structure_backward_continue_guard(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(continue_target): Option<usize> = loop_continue_target() else {
        return Ok(None);
    };
    let Some(jump_idx): Option<usize> = (lo..hi).find(|&i: &usize| {
        matches!(
            stream.ops[i],
            CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::PopJumpIfFalseBackward(_)
                | CanonicalOp::PopJumpIfTrueBackward(_)
        ) && resolve_jump_target(stream, i, &stream.ops[i])
            .is_some_and(|t: usize| t <= continue_target + 1 && t <= lo)
    }) else {
        return Ok(None);
    };
    let Some((head, test)): Option<(Vec<Stmt>, Expr)> =
        guard_head_and_test(code, stream, lo, jump_idx)?
    else {
        return Ok(None);
    };
    let test: Expr = fallthrough_cond_test(stream, jump_idx, test);
    let body_end: usize = trim_body_back_edge(stream, jump_idx + 1, hi);
    let body: Vec<Stmt> = structure_stmts(code, stream, jump_idx + 1, body_end)?;
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body: non_empty(body),
        orelse: Vec::new(),
        line: None,
    });
    out.extend(structure_stmts(code, stream, body_end, hi)?);
    Ok(Some(out))
}

fn region_is_only_continue_back_edge(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    header: usize,
) -> bool {
    let Some(edge): Option<usize> = first_significant(stream, lo, hi) else {
        return false;
    };
    if !is_back_edge(&stream.ops[edge]) {
        return false;
    }
    if first_significant(stream, edge + 1, hi).is_some() {
        return false;
    }
    resolve_jump_target(stream, edge, &stream.ops[edge]).is_some_and(|t: usize| t <= header)
}

fn loop_body_guard_polarity_applies() -> bool {
    active_version().is_some_and(|v: PyVersion| (v.major(), v.minor()) >= (3, 10))
}

fn leading_continue_guard_before(
    stream: &DecodedStream,
    lo: usize,
    boundary: usize,
    continue_target: usize,
) -> Option<(usize, usize)> {
    let guard: usize = (lo..boundary).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
    })?;
    let target: usize =
        resolve_jump_target(stream, guard, &stream.ops[guard]).filter(|t: &usize| *t > guard)?;
    let skip: usize = first_significant(stream, guard + 1, target)?;
    if !is_back_edge(&stream.ops[skip]) {
        return None;
    }
    let back: usize = resolve_jump_target(stream, skip, &stream.ops[skip])?;
    (back < guard && back <= continue_target).then_some((guard, target))
}

fn try_structure_loop_guard_before_try(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &TryRegion,
) -> Result<Option<Vec<Stmt>>> {
    if region.is_with() || region.is_finally() || !loop_body_guard_polarity_applies() {
        return Ok(None);
    }
    let Some(continue_target): Option<usize> = loop_continue_target() else {
        return Ok(None);
    };
    let or_guard_encloses: bool = matches!(
        try_recover_or_body_guard(code, stream, lo, hi, continue_target),
        Ok(Some(ref guard)) if guard.body_start <= region.try_start
    );
    if or_guard_encloses && let Some(stmts) = structure_or_chain_body_guard(code, stream, lo, hi)? {
        return Ok(Some(stmts));
    }
    if let Some((guard, target)) =
        leading_continue_guard_before(stream, lo, region.try_start, continue_target)
        && let Some(stmts) = structure_guarded_continue(code, stream, lo, hi, guard, target)?
    {
        return Ok(Some(stmts));
    }
    Ok(None)
}

fn structure_or_chain_body_guard(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    if !loop_body_guard_polarity_applies() {
        return Ok(None);
    }
    let Some(header): Option<usize> = loop_continue_target() else {
        return Ok(None);
    };
    let Some(guard): Option<OrBodyGuard> = try_recover_or_body_guard(code, stream, lo, hi, header)?
    else {
        return Ok(None);
    };
    let body_end: usize = trim_body_back_edge(stream, guard.body_start, hi);
    if (body_end..hi).any(|k: usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        ) && !is_back_edge(&stream.ops[k])
    }) {
        return Ok(None);
    }
    let body: Vec<Stmt> = structure_stmts(code, stream, guard.body_start, body_end)?;
    let mut out: Vec<Stmt> = guard.head;
    out.push(Stmt::If {
        test: guard.test,
        body: non_empty(body),
        orelse: Vec::new(),
        line: None,
    });
    Ok(Some(out))
}

fn structure_compound_continue_guard(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(header): Option<usize> = loop_continue_target() else {
        return Ok(None);
    };
    let Some(compound): Option<CompoundIf> = try_recover_compound_if(code, stream, lo, hi)? else {
        return Ok(None);
    };
    let Some(body_target): Option<usize> =
        resolve_jump_target(stream, compound.last_jump, &stream.ops[compound.last_jump])
            .filter(|t: &usize| *t > compound.last_jump && *t <= hi)
    else {
        return Ok(None);
    };
    if !region_is_only_continue_back_edge(stream, compound.last_jump + 1, body_target, header) {
        return Ok(None);
    }
    let mut out: Vec<Stmt> = compound.head;
    out.push(Stmt::If {
        test: compound.test,
        body: vec![Stmt::Continue],
        orelse: Vec::new(),
        line: None,
    });
    out.extend(structure_stmts(code, stream, body_target, hi)?);
    Ok(Some(out))
}

struct FallthroughGuard {
    jump: usize,
    next: usize,
}

fn guard_entry_index(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    let bound: usize = hi.min(stream.ops.len());
    (from..bound)
        .find(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Push(_)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
            )
        })
        .unwrap_or(from)
}

fn op_is_fallthrough_guard(stream: &DecodedStream, i: usize, hi: usize) -> bool {
    is_forward_cond_jump(&stream.ops[i])
        && !is_chain_cond_jump(&stream.ops, i)
        && !is_value_form_shortcircuit(&stream.ops, i)
        && first_significant(stream, i + 1, hi).is_some_and(|e: usize| is_back_edge(&stream.ops[e]))
}

fn collect_fallthrough_continue_chain(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    header: usize,
) -> Option<(Vec<FallthroughGuard>, usize)> {
    let mut guards: Vec<FallthroughGuard> = Vec::new();
    let mut value_lo: usize = lo;
    loop {
        let jump: usize = (value_lo..hi).find(|&i: &usize| {
            is_forward_cond_jump(&stream.ops[i])
                && !is_chain_cond_jump(&stream.ops, i)
                && !is_value_form_shortcircuit(&stream.ops, i)
        })?;
        let target: usize = resolve_jump_target(stream, jump, &stream.ops[jump])
            .filter(|t: &usize| *t > jump && *t <= hi)?;
        let edge: usize = first_significant(stream, jump + 1, hi)?;
        if !is_back_edge(&stream.ops[edge]) {
            return None;
        }
        let back: usize = resolve_jump_target(stream, edge, &stream.ops[edge])?;
        if back > header {
            return None;
        }
        let after_edge: usize = first_significant(stream, edge + 1, hi)?;
        if guard_entry_index(stream, target, hi) != guard_entry_index(stream, after_edge, hi) {
            return None;
        }
        guards.push(FallthroughGuard {
            jump,
            next: after_edge,
        });
        if (after_edge..hi).any(|i: usize| op_is_fallthrough_guard(stream, i, hi)) {
            value_lo = after_edge;
            continue;
        }
        return Some((guards, after_edge));
    }
}

fn structure_fallthrough_continue_and_chain(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    use crate::ast::node::BoolOpKind;
    let Some(header): Option<usize> = loop_continue_target() else {
        return Ok(None);
    };
    let Some((guards, body_start)): Option<(Vec<FallthroughGuard>, usize)> =
        collect_fallthrough_continue_chain(stream, lo, hi, header)
    else {
        return Ok(None);
    };
    if guards.len() < 2 {
        return Ok(None);
    }
    let (head, head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..guards[0].jump])?;
    let mut operands: Vec<Expr> = Vec::with_capacity(guards.len());
    for (n, guard) in guards.iter().enumerate() {
        let value: Expr = if n == 0 {
            let [only]: &[Expr] = head_residual.as_slice() else {
                return Ok(None);
            };
            only.clone()
        } else {
            let region: &[CanonicalOp] = &stream.ops[guards[n - 1].next..guard.jump];
            let (stmts, residual): (Vec<Stmt>, Vec<Expr>) = build_linear_stmts_sim(code, region)?;
            if !stmts.is_empty() {
                return Ok(None);
            }
            let Ok([only]): std::result::Result<[Expr; 1], Vec<Expr>> = residual.try_into() else {
                return Ok(None);
            };
            only
        };
        let taken: Expr = none_jump_test_taken(stream, guard.jump, value.clone()).unwrap_or(value);
        let operand: Expr = if jump_taken_if_true(stream, guard.jump) {
            taken
        } else {
            negate_cond_expr(taken)
        };
        operands.push(operand);
    }
    let test: Expr = Expr::BoolOp {
        op: BoolOpKind::And,
        values: operands,
    };
    let body_end: usize = trim_body_back_edge(stream, body_start, hi);
    let body: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body: non_empty(body),
        orelse: Vec::new(),
        line: None,
    });
    out.extend(structure_stmts(code, stream, body_end, hi)?);
    Ok(Some(out))
}

fn structure_guarded_continue(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    jump_idx: usize,
    target: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(skip_idx): Option<usize> = first_significant(stream, jump_idx + 1, target) else {
        return Ok(None);
    };
    if !is_back_edge(&stream.ops[skip_idx]) {
        return Ok(None);
    }
    let Some(back_target): Option<usize> =
        resolve_jump_target(stream, skip_idx, &stream.ops[skip_idx])
    else {
        return Ok(None);
    };
    if back_target >= jump_idx {
        return Ok(None);
    }
    let after_skip: usize = first_significant(stream, skip_idx + 1, hi).unwrap_or(hi);
    let join_norm: usize = first_significant(stream, target, hi).unwrap_or(hi);
    if after_skip != join_norm && target != hi {
        return Ok(None);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..jump_idx])?;
    let test: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let body_end: usize = trim_body_back_edge(stream, target, hi);
    let rest: Vec<Stmt> = structure_stmts(code, stream, target, body_end)?;
    let rest: Vec<Stmt> = rewrite_jump_to_break_continue(code, stream, rest, target, body_end);
    let guard_test: Expr = fallthrough_cond_test(stream, jump_idx, test.clone());
    let body_is_loop_tail: bool = (body_end..hi).all(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        ) || is_back_edge(&stream.ops[k])
    });
    let positive_test: Expr =
        none_jump_test_taken(stream, jump_idx, test.clone()).unwrap_or_else(|| test.clone());
    let mut out: Vec<Stmt> = head;
    if loop_body_guard_polarity_applies()
        && jump_taken_if_true(stream, jump_idx)
        && body_is_loop_tail
        && loop_continue_target().is_some()
        && !rest.is_empty()
        && test_is_polarity_sensitive(&positive_test)
        && rest.iter().all(stmt_is_continue_guard_safe)
        && !region_ends_in_hard_terminator(stream, target, body_end)
    {
        out.push(Stmt::If {
            test: positive_test,
            body: non_empty(rest),
            orelse: Vec::new(),
            line: None,
        });
        out.extend(structure_stmts(code, stream, body_end, hi)?);
        return Ok(Some(out));
    }
    if loop_continue_target().is_some() {
        out.push(Stmt::If {
            test: guard_test,
            body: vec![Stmt::Continue],
            orelse: Vec::new(),
            line: None,
        });
        out.extend(rest);
    } else {
        out.push(Stmt::If {
            test: negate_cond_expr(guard_test),
            body: non_empty(rest),
            orelse: Vec::new(),
            line: None,
        });
    }
    out.extend(structure_stmts(code, stream, body_end, hi)?);
    Ok(Some(out))
}

pub(super) fn test_is_polarity_sensitive(test: &Expr) -> bool {
    match test {
        Expr::Compare {
            ops, comparators, ..
        } => ops
            .iter()
            .zip(comparators)
            .any(|(op, cmp): (&CmpOp, &Expr)| match op {
                CmpOp::In | CmpOp::NotIn => true,
                CmpOp::Is | CmpOp::IsNot => !matches!(
                    cmp,
                    Expr::Constant {
                        value: ConstValue::None,
                        ..
                    }
                ),
                _ => false,
            }),
        _ => false,
    }
}

fn stmt_is_continue_guard_safe(stmt: &Stmt) -> bool {
    !matches!(
        stmt,
        Stmt::Return(_) | Stmt::Raise { .. } | Stmt::Break | Stmt::Continue
    )
}

fn back_edge_breaks_to_enclosing_loop(stream: &DecodedStream, idx: usize) -> bool {
    let Some(target): Option<usize> = resolve_jump_target(stream, idx, &stream.ops[idx]) else {
        return false;
    };
    if loop_continue_target() == Some(target) {
        return false;
    }
    target < idx && loop_frame_has_header(target)
}

fn trim_body_back_edge(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut end: usize = hi;
    while end > lo
        && matches!(
            stream.ops.get(end - 1),
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_))
        )
    {
        end -= 1;
    }
    if end > lo
        && is_back_edge(&stream.ops[end - 1])
        && !back_edge_breaks_to_enclosing_loop(stream, end - 1)
    {
        end -= 1;
    }
    end.max(lo)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod block_range_repro {
    use super::super::{DecodedStream, LoopFrame, pop_loop_frame, push_loop_frame};
    use super::{rewrite_jump_to_break_continue, significant_run, structure_stmts};
    use crate::bytecode::opcode::CanonicalOp;
    use crate::bytecode::version::PyVersion;
    use crate::error::DecompileError;
    use disrobe_py_marshal::{CodeEra, CodeObject};

    fn stream_with_ops(n: usize) -> DecodedStream {
        let ops: Vec<CanonicalOp> = vec![CanonicalOp::Nop; n];
        let offsets: Vec<u32> = (0..n).map(|i: usize| (i as u32) * 2).collect();
        let next_offsets: Vec<u32> = (0..n).map(|i: usize| (i as u32 + 1) * 2).collect();
        DecodedStream {
            ops,
            offsets,
            next_offsets,
            code_len: (n as u32) * 2,
            lines: vec![None; n],
            wordcode: true,
            instr_unit_jumps: true,
            relative_cond_jumps: true,
            exception_table: Vec::new(),
            pre311_end_finally_idx: std::collections::BTreeSet::new(),
            pre311_pop_block_idx: std::collections::BTreeSet::new(),
            pre311_break_loop_idx: std::collections::BTreeSet::new(),
            setup_loop_end: std::collections::BTreeMap::new(),
            none_jump_kind: std::collections::BTreeMap::new(),
            version: PyVersion::V3_12,
        }
    }

    #[test]
    fn significant_run_ignores_out_of_range_block() {
        let stream: DecodedStream = stream_with_ops(34);
        let run: Vec<usize> = significant_run(&stream, 162, 200);
        assert!(
            run.is_empty(),
            "out-of-range block must yield no significant ops, not panic"
        );
    }

    #[test]
    fn structure_stmts_rejects_out_of_range_block() {
        let stream: DecodedStream = stream_with_ops(34);
        let code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        let result: crate::error::Result<Vec<crate::ast::node::Stmt>> =
            structure_stmts(&code, &stream, 0, 162);
        assert!(
            matches!(
                result,
                Err(DecompileError::BlockOutOfRange {
                    lo: 0,
                    hi: 162,
                    len: 34
                })
            ),
            "expected typed BlockOutOfRange, got {result:?}"
        );
    }

    #[test]
    fn stale_loop_frame_tail_range_does_not_panic() {
        let stream: DecodedStream = stream_with_ops(34);
        let code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        push_loop_frame(LoopFrame {
            header: 0,
            exit: 34,
            exit_return: None,
            exit_tail_range: Some((162, 200)),
        });
        let body: Vec<crate::ast::node::Stmt> = vec![crate::ast::node::Stmt::Pass];
        let out: Vec<crate::ast::node::Stmt> =
            rewrite_jump_to_break_continue(&code, &stream, body, 0, stream.ops.len());
        pop_loop_frame();
        assert_eq!(
            out.len(),
            1,
            "a foreign loop-frame tail range must be declined, leaving the body intact"
        );
    }
}
