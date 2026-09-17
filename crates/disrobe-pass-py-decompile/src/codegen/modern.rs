use crate::ast::node::{Expr, Stmt};
use crate::bytecode::version::PyVersion;
use crate::codegen::async_emit::{
    emit_async_for, emit_async_function_def, emit_async_with, emit_await, render_arguments,
};
use crate::codegen::except_group_emit::emit_try_star;
use crate::codegen::fstring_emit::emit_fstring;
use crate::codegen::match_emit::emit_match;
use crate::codegen::modern_expr_render::render_expr;
use crate::codegen::tstring_emit::emit_tstring;
use crate::codegen::type_params_emit::{
    emit_class_def_with_type_params, emit_function_def_with_type_params, emit_type_alias,
};
use crate::codegen::walrus_emit::emit_walrus;

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn emit_modern_stmt(stmt: &Stmt, indent: u32, version: &PyVersion) -> Option<String> {
    match stmt {
        Stmt::Match { subject, cases, .. } => Some(emit_match(subject, cases, indent, version)),
        Stmt::TryStar {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        } => Some(emit_try_star(
            body, handlers, orelse, finalbody, indent, version,
        )),
        Stmt::TypeAlias {
            name,
            type_params,
            value,
            ..
        } => Some(emit_type_alias(name, type_params, value, indent, version)),
        Stmt::FunctionDef {
            name,
            type_params,
            args,
            body,
            decorators,
            returns,
            is_async,
            ..
        } => {
            if *is_async {
                Some(emit_async_function_def(
                    name,
                    type_params,
                    args,
                    body,
                    decorators,
                    returns.as_ref(),
                    indent,
                    version,
                ))
            } else if type_params.is_empty() {
                None
            } else {
                let args_rendered: String = render_arguments(args, version);
                Some(emit_function_def_with_type_params(
                    name,
                    type_params,
                    &args_rendered,
                    returns.as_ref(),
                    body,
                    decorators,
                    indent,
                    version,
                ))
            }
        }
        Stmt::ClassDef {
            name,
            type_params,
            bases,
            body,
            decorators,
            ..
        } => {
            if type_params.is_empty() {
                None
            } else {
                let bases_rendered: String = bases
                    .iter()
                    .map(|b: &Expr| render_expr(b, version))
                    .collect::<Vec<String>>()
                    .join(", ");
                Some(emit_class_def_with_type_params(
                    name,
                    type_params,
                    &bases_rendered,
                    body,
                    decorators,
                    indent,
                    version,
                ))
            }
        }
        Stmt::With {
            items,
            body,
            is_async,
            ..
        } if *is_async => Some(emit_async_with(items, body, indent, version)),
        Stmt::For {
            target,
            iter,
            body,
            orelse,
            is_async,
            ..
        } if *is_async => Some(emit_async_for(target, iter, body, orelse, indent, version)),
        _ => None,
    }
}

#[must_use]
pub fn emit_modern_expr(expr: &Expr, version: &PyVersion) -> Option<String> {
    match expr {
        Expr::NamedExpr { target, value } => Some(emit_walrus(target, value, version)),
        Expr::JoinedStr { values, .. } => Some(emit_fstring(values, version)),
        Expr::TStr { items, .. } => Some(emit_tstring(items, version)),
        Expr::Await(inner) => Some(emit_await(inner, version)),
        Expr::Yield(opt) => Some(opt.as_deref().map_or_else(
            || "yield".to_owned(),
            |e: &Expr| format!("yield {}", render_expr(e, version)),
        )),
        Expr::YieldFrom(inner) => Some(format!("yield from {}", render_expr(inner, version))),
        _ => None,
    }
}
