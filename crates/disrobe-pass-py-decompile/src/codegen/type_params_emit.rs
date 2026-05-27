use std::fmt::Write as _;

use crate::ast::node::{Expr, Stmt, TypeParam};
use crate::bytecode::version::PyVersion;
use crate::codegen::modern_expr_render::{indent_str, render_body, render_expr};

#[must_use]
pub fn emit_type_params(params: &[TypeParam], version: &PyVersion) -> String {
    if params.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = params
        .iter()
        .map(|p: &TypeParam| render_type_param(p, version))
        .collect();
    format!("[{}]", parts.join(", "))
}

#[must_use]
pub fn render_type_param(p: &TypeParam, version: &PyVersion) -> String {
    match p {
        TypeParam::TypeVar {
            name,
            bound,
            default,
        } => render_typevar(name, bound.as_ref(), default.as_ref(), version),
        TypeParam::ParamSpec { name, default } => default.as_ref().map_or_else(
            || format!("**{name}"),
            |d: &Expr| format!("**{name} = {}", render_expr(d, version)),
        ),
        TypeParam::TypeVarTuple { name, default } => default.as_ref().map_or_else(
            || format!("*{name}"),
            |d: &Expr| format!("*{name} = {}", render_expr(d, version)),
        ),
    }
}

#[must_use]
fn render_typevar(
    name: &str,
    bound: Option<&Expr>,
    default: Option<&Expr>,
    version: &PyVersion,
) -> String {
    let mut out: String = name.to_owned();
    if let Some(b) = bound {
        out.push_str(": ");
        out.push_str(&render_expr(b, version));
    }
    if let Some(d) = default {
        out.push_str(" = ");
        out.push_str(&render_expr(d, version));
    }
    out
}

#[must_use]
pub fn emit_type_alias(
    name: &str,
    type_params: &[TypeParam],
    value: &Expr,
    indent: u32,
    version: &PyVersion,
) -> String {
    let prefix: String = indent_str(indent);
    let tp: String = emit_type_params(type_params, version);
    format!("{prefix}type {name}{tp} = {}", render_expr(value, version))
}

#[must_use]
pub fn emit_function_def_with_type_params(
    name: &str,
    type_params: &[TypeParam],
    args_rendered: &str,
    returns: Option<&Expr>,
    body: &[Stmt],
    decorators: &[Expr],
    indent: u32,
    version: &PyVersion,
) -> String {
    let prefix: String = indent_str(indent);
    let mut out: String = String::new();
    for dec in decorators {
        let _ = writeln!(out, "{prefix}@{}", render_expr(dec, version));
    }
    let tp: String = emit_type_params(type_params, version);
    let ret: String = returns.map_or(String::new(), |r: &Expr| {
        format!(" -> {}", render_expr(r, version))
    });
    let _ = writeln!(out, "{prefix}def {name}{tp}({args_rendered}){ret}:");
    out.push_str(&render_body(body, indent + 1, version));
    out
}

#[must_use]
pub fn emit_class_def_with_type_params(
    name: &str,
    type_params: &[TypeParam],
    bases_rendered: &str,
    body: &[Stmt],
    decorators: &[Expr],
    indent: u32,
    version: &PyVersion,
) -> String {
    let prefix: String = indent_str(indent);
    let mut out: String = String::new();
    for dec in decorators {
        let _ = writeln!(out, "{prefix}@{}", render_expr(dec, version));
    }
    let tp: String = emit_type_params(type_params, version);
    let head: String = if bases_rendered.is_empty() {
        format!("{prefix}class {name}{tp}:")
    } else {
        format!("{prefix}class {name}{tp}({bases_rendered}):")
    };
    let _ = writeln!(out, "{head}");
    out.push_str(&render_body(body, indent + 1, version));
    out
}

#[must_use]
pub fn supports_pep_695(version: &PyVersion) -> bool {
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    maj > 3 || (maj == 3 && min >= 12)
}

#[must_use]
pub fn supports_pep_696(version: &PyVersion) -> bool {
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    maj > 3 || (maj == 3 && min >= 13)
}
