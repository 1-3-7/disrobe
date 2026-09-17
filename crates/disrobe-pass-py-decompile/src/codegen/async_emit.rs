use std::fmt::Write as _;

use crate::ast::node::{Arg, Arguments, Expr, Stmt, TypeParam, WithItem};
use crate::bytecode::version::PyVersion;
use crate::codegen::modern_expr_render::{indent_str, render_body, render_expr};
use crate::codegen::type_params_emit::emit_type_params;

#[must_use]
pub fn emit_async_function_def(
    name: &str,
    type_params: &[TypeParam],
    args: &Arguments,
    body: &[Stmt],
    decorators: &[Expr],
    returns: Option<&Expr>,
    indent: u32,
    version: &PyVersion,
) -> String {
    let prefix: String = indent_str(indent);
    let mut out: String = String::new();
    for dec in decorators {
        let _ = writeln!(out, "{prefix}@{}", render_expr(dec, version));
    }
    let tp: String = emit_type_params(type_params, version);
    let arglist: String = render_arguments(args, version);
    let ret: String = returns.map_or(String::new(), |r: &Expr| {
        format!(" -> {}", render_expr(r, version))
    });
    let _ = writeln!(out, "{prefix}async def {name}{tp}({arglist}){ret}:");
    out.push_str(&render_body(body, indent + 1, version));
    out
}

#[must_use]
pub fn emit_async_with(
    items: &[WithItem],
    body: &[Stmt],
    indent: u32,
    version: &PyVersion,
) -> String {
    let prefix: String = indent_str(indent);
    let item_list: String = items
        .iter()
        .map(|wi: &WithItem| render_with_item(wi, version))
        .collect::<Vec<String>>()
        .join(", ");
    let header: String = format!("{prefix}async with {item_list}:");
    let body_str: String = render_body(body, indent + 1, version);
    format!("{header}\n{body_str}")
}

#[must_use]
pub fn emit_async_for(
    target: &Expr,
    iter: &Expr,
    body: &[Stmt],
    orelse: &[Stmt],
    indent: u32,
    version: &PyVersion,
) -> String {
    let prefix: String = indent_str(indent);
    let header: String = format!(
        "{prefix}async for {} in {}:",
        render_expr(target, version),
        render_expr(iter, version)
    );
    let body_str: String = render_body(body, indent + 1, version);
    if orelse.is_empty() {
        format!("{header}\n{body_str}")
    } else {
        let else_str: String = render_body(orelse, indent + 1, version);
        format!("{header}\n{body_str}\n{prefix}else:\n{else_str}")
    }
}

#[must_use]
pub fn emit_await(value: &Expr, version: &PyVersion) -> String {
    format!("await {}", render_expr(value, version))
}

#[must_use]
fn render_with_item(item: &WithItem, version: &PyVersion) -> String {
    item.optional_vars.as_ref().map_or_else(
        || render_expr(&item.context_expr, version),
        |v: &Expr| {
            format!(
                "{} as {}",
                render_expr(&item.context_expr, version),
                render_expr(v, version)
            )
        },
    )
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_arguments(args: &Arguments, version: &PyVersion) -> String {
    let mut parts: Vec<String> = Vec::new();
    let pos_offset: usize = args.posonly.len();
    let defaults_start: usize = (pos_offset + args.args.len()).saturating_sub(args.defaults.len());
    for (i, a) in args.posonly.iter().chain(args.args.iter()).enumerate() {
        let piece: String = render_param(a, i, defaults_start, &args.defaults, version);
        parts.push(piece);
        if i + 1 == pos_offset {
            parts.push("/".to_owned());
        }
    }
    if let Some(va) = args.vararg.as_deref() {
        parts.push(format!("*{}", va.arg));
    } else if !args.kwonly.is_empty() {
        parts.push("*".to_owned());
    }
    for (i, a) in args.kwonly.iter().enumerate() {
        let mut piece: String = a.arg.clone();
        if let Some(ann) = a.annotation.as_deref() {
            piece.push_str(": ");
            piece.push_str(&render_expr(ann, version));
        }
        if let Some(Some(def)) = args.kw_defaults.get(i) {
            piece.push_str(if a.annotation.is_some() { " = " } else { "=" });
            piece.push_str(&render_expr(def, version));
        }
        parts.push(piece);
    }
    if let Some(kw) = args.kwarg.as_deref() {
        parts.push(format!("**{}", kw.arg));
    }
    parts.join(", ")
}

#[must_use]
fn render_param(
    a: &Arg,
    i: usize,
    defaults_start: usize,
    defaults: &[Expr],
    version: &PyVersion,
) -> String {
    let mut piece: String = a.arg.clone();
    if let Some(ann) = a.annotation.as_deref() {
        piece.push_str(": ");
        piece.push_str(&render_expr(ann, version));
    }
    if i >= defaults_start {
        let idx: usize = i - defaults_start;
        if let Some(def) = defaults.get(idx) {
            piece.push_str(if a.annotation.is_some() { " = " } else { "=" });
            piece.push_str(&render_expr(def, version));
        }
    }
    piece
}

#[must_use]
pub fn supports_async(version: &PyVersion) -> bool {
    version.supports_async()
}
