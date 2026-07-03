#![allow(
    clippy::too_many_lines,
    clippy::option_if_let_else,
    clippy::cognitive_complexity
)]

use crate::ast::node::{Alias, Arguments, Expr, Stmt, TypeParam, WithItem};
use crate::bytecode::version::PyVersion;
use crate::codegen::DefaultEmitter;
use crate::codegen::expr::{
    Precedence, aug_symbol, emit_arguments, emit_assign_target, emit_assign_tuple_bare, emit_expr,
    emit_type_params, is_simultaneous_tuple_assign,
};
use crate::codegen::flow;
use crate::codegen::format_docstring_literal;
use crate::codegen::name_demangle;
use crate::codegen::version_dispatch;

#[must_use]
pub fn emit_stmt(em: &DefaultEmitter, s: &Stmt, indent: u32, version: &PyVersion) -> String {
    let pad: String = em.indent_str(indent);
    match s {
        Stmt::FunctionDef {
            name,
            type_params,
            args,
            body,
            decorators,
            returns,
            is_async,
            docstring,
            ..
        } => emit_function_def(
            em,
            &pad,
            indent,
            name,
            type_params,
            args,
            body,
            decorators,
            returns.as_ref(),
            *is_async,
            docstring.as_deref(),
            version,
        ),
        Stmt::ClassDef {
            name,
            type_params,
            bases,
            keywords,
            body,
            decorators,
            docstring,
            ..
        } => emit_class_def(
            em,
            &pad,
            indent,
            name,
            type_params,
            bases,
            keywords,
            body,
            decorators,
            docstring.as_deref(),
            version,
        ),
        Stmt::Return(value) => match value {
            None => format!("{pad}return"),
            Some(e) => format!(
                "{pad}return {}",
                emit_expr(em, e, version, Precedence::Lowest)
            ),
        },
        Stmt::Delete(targets) => {
            let parts: Vec<String> = targets
                .iter()
                .map(|t: &Expr| emit_expr(em, t, version, Precedence::Lowest))
                .collect();
            format!("{pad}del {}", parts.join(", "))
        }
        Stmt::Assign { targets, value, .. } => {
            let bare: bool = is_simultaneous_tuple_assign(targets, value);
            let mut out: String = String::new();
            out.push_str(&pad);
            for t in targets {
                if bare {
                    out.push_str(&emit_assign_tuple_bare(em, t, version));
                } else {
                    out.push_str(&emit_assign_target(em, t, version));
                }
                out.push_str(" = ");
            }
            if bare {
                out.push_str(&emit_assign_tuple_bare(em, value, version));
            } else {
                out.push_str(&emit_expr(em, value, version, Precedence::Lowest));
            }
            out
        }
        Stmt::AugAssign {
            target, op, value, ..
        } => format!(
            "{pad}{} {} {}",
            emit_expr(em, target, version, Precedence::Lowest),
            aug_symbol(*op),
            emit_expr(em, value, version, Precedence::Lowest)
        ),
        Stmt::AnnAssign {
            target,
            annotation,
            value,
            ..
        } => match value {
            Some(v) => format!(
                "{pad}{}: {} = {}",
                emit_expr(em, target, version, Precedence::Lowest),
                emit_expr(em, annotation, version, Precedence::Lowest),
                emit_expr(em, v, version, Precedence::Lowest)
            ),
            None => format!(
                "{pad}{}: {}",
                emit_expr(em, target, version, Precedence::Lowest),
                emit_expr(em, annotation, version, Precedence::Lowest)
            ),
        },
        Stmt::TypeAlias {
            name,
            type_params,
            value,
            ..
        } => {
            let tps: String = emit_type_params(em, type_params, version);
            format!(
                "{pad}type {name}{tps} = {}",
                emit_expr(em, value, version, Precedence::Lowest)
            )
        }
        Stmt::For {
            target,
            iter,
            body,
            orelse,
            is_async,
            ..
        } => flow::emit_for(
            em, &pad, indent, target, iter, body, orelse, *is_async, version,
        ),
        Stmt::While {
            test, body, orelse, ..
        } => flow::emit_while(em, &pad, indent, test, body, orelse, version),
        Stmt::If {
            test, body, orelse, ..
        } => flow::emit_if_chain(em, &pad, indent, test, body, orelse, version),
        Stmt::With {
            items,
            body,
            is_async,
            ..
        } => emit_with(em, &pad, indent, items, body, *is_async, version),
        Stmt::Match { subject, cases, .. } => {
            flow::emit_match(em, &pad, indent, subject, cases, version)
        }
        Stmt::Raise { exc, cause, .. } => {
            emit_raise(em, &pad, exc.as_ref(), cause.as_ref(), version)
        }
        Stmt::Try {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        } => flow::emit_try(
            em, &pad, indent, body, handlers, orelse, finalbody, false, version,
        ),
        Stmt::TryStar {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        } => flow::emit_try(
            em, &pad, indent, body, handlers, orelse, finalbody, true, version,
        ),
        Stmt::Assert { test, msg, .. } => match msg {
            None => format!(
                "{pad}assert {}",
                emit_expr(em, test, version, Precedence::Lowest)
            ),
            Some(m) => format!(
                "{pad}assert {}, {}",
                emit_expr(em, test, version, Precedence::Lowest),
                emit_expr(em, m, version, Precedence::Lowest)
            ),
        },
        Stmt::Import(aliases) => format!("{pad}import {}", emit_aliases(aliases)),
        Stmt::ImportFrom {
            module,
            names,
            level,
            ..
        } => {
            let dots: String = ".".repeat(*level as usize);
            let module_part: String = module.clone().unwrap_or_default();
            format!(
                "{pad}from {dots}{module_part} import {}",
                emit_aliases(names)
            )
        }
        Stmt::Global(names) => format!("{pad}global {}", names.join(", ")),
        Stmt::Nonlocal(names) => format!("{pad}nonlocal {}", names.join(", ")),
        Stmt::Expr(e) => match e {
            Expr::Yield(inner) => match inner {
                None => format!("{pad}yield"),
                Some(v) => {
                    format!(
                        "{pad}yield {}",
                        emit_expr(em, v, version, Precedence::Lowest)
                    )
                }
            },
            Expr::YieldFrom(inner) => format!(
                "{pad}yield from {}",
                emit_expr(em, inner, version, Precedence::Lowest)
            ),
            _ => format!("{pad}{}", emit_expr(em, e, version, Precedence::Lowest)),
        },
        Stmt::Pass => format!("{pad}pass"),
        Stmt::Break => format!("{pad}break"),
        Stmt::Continue => format!("{pad}continue"),
    }
}

#[must_use]
pub fn emit_block(em: &DefaultEmitter, body: &[Stmt], indent: u32, version: &PyVersion) -> String {
    if body.is_empty() {
        return format!("{}pass", em.indent_str(indent));
    }
    let mut out: String = String::new();
    let len: usize = body.len();
    for (i, s) in body.iter().enumerate() {
        out.push_str(&emit_stmt(em, s, indent, version));
        if i + 1 < len {
            out.push('\n');
        }
    }
    out
}

#[must_use]
fn emit_aliases(aliases: &[Alias]) -> String {
    aliases
        .iter()
        .map(|a: &Alias| match &a.asname {
            Some(asn) => format!("{} as {asn}", a.name),
            None => a.name.clone(),
        })
        .collect::<Vec<String>>()
        .join(", ")
}

#[must_use]
fn emit_decorators(
    em: &DefaultEmitter,
    decorators: &[Expr],
    pad: &str,
    version: &PyVersion,
) -> String {
    let mut out: String = String::new();
    for d in decorators {
        out.push_str(pad);
        out.push('@');
        out.push_str(&emit_expr(em, d, version, Precedence::Lowest));
        out.push('\n');
    }
    out
}

#[allow(clippy::too_many_arguments)]
#[must_use]
fn emit_function_def(
    em: &DefaultEmitter,
    pad: &str,
    indent: u32,
    name: &str,
    type_params: &[TypeParam],
    args: &Arguments,
    body: &[Stmt],
    decorators: &[Expr],
    returns: Option<&Expr>,
    is_async: bool,
    docstring: Option<&str>,
    version: &PyVersion,
) -> String {
    let mut out: String = emit_decorators(em, decorators, pad, version);
    out.push_str(pad);
    if is_async && version_dispatch::supports_async(version) {
        out.push_str("async ");
    }
    out.push_str("def ");
    out.push_str(name);
    if version_dispatch::supports_pep_695(version) {
        out.push_str(&emit_type_params(em, type_params, version));
    }
    out.push('(');
    out.push_str(&emit_arguments(em, args, version));
    out.push(')');
    if let Some(ret) = returns {
        out.push_str(" -> ");
        out.push_str(&emit_expr(em, ret, version, Precedence::Lowest));
    }
    out.push_str(":\n");
    if let Some(doc) = docstring {
        out.push_str(&em.indent_str(indent + 1));
        out.push_str(&format_docstring_literal(doc, em.use_double_quotes));
        if !body.is_empty() {
            out.push('\n');
        }
    }
    out.push_str(&emit_block(em, body, indent + 1, version));
    out
}

#[allow(clippy::too_many_arguments)]
#[must_use]
fn emit_class_def(
    em: &DefaultEmitter,
    pad: &str,
    indent: u32,
    name: &str,
    type_params: &[TypeParam],
    bases: &[Expr],
    keywords: &[crate::ast::node::Keyword],
    body: &[Stmt],
    decorators: &[Expr],
    docstring: Option<&str>,
    version: &PyVersion,
) -> String {
    let mut out: String = emit_decorators(em, decorators, pad, version);
    out.push_str(pad);
    out.push_str("class ");
    out.push_str(name);
    if version_dispatch::supports_pep_695(version) {
        out.push_str(&emit_type_params(em, type_params, version));
    }
    let has_bases: bool = !bases.is_empty() || !keywords.is_empty();
    if has_bases {
        out.push('(');
        let mut parts: Vec<String> = Vec::with_capacity(bases.len() + keywords.len());
        for b in bases {
            parts.push(emit_expr(em, b, version, Precedence::Lowest));
        }
        for kw in keywords {
            match &kw.arg {
                Some(n) => parts.push(format!(
                    "{n}={}",
                    emit_expr(em, &kw.value, version, Precedence::Lowest)
                )),
                None => parts.push(format!(
                    "**{}",
                    emit_expr(em, &kw.value, version, Precedence::Unary)
                )),
            }
        }
        out.push_str(&parts.join(", "));
        out.push(')');
    }
    out.push_str(":\n");
    if let Some(doc) = docstring {
        out.push_str(&em.indent_str(indent + 1));
        out.push_str(&format_docstring_literal(doc, em.use_double_quotes));
        if !body.is_empty() {
            out.push('\n');
        }
    }
    let demangled: Vec<Stmt> = name_demangle::demangle_class_body(name, body);
    out.push_str(&emit_block(em, &demangled, indent + 1, version));
    out
}

#[must_use]
fn emit_with(
    em: &DefaultEmitter,
    pad: &str,
    indent: u32,
    items: &[WithItem],
    body: &[Stmt],
    is_async: bool,
    version: &PyVersion,
) -> String {
    let mut head: String = pad.to_owned();
    if is_async && version_dispatch::supports_async(version) {
        head.push_str("async ");
    }
    head.push_str("with ");
    let item_parts: Vec<String> = items
        .iter()
        .map(|it: &WithItem| emit_with_item(em, it, version))
        .collect();
    let joined: String = item_parts.join(", ");
    let line_len: usize = head.len() + joined.len() + 1;
    let needs_parens: bool =
        version_dispatch::supports_parenthesized_with(version) && line_len > 80 && items.len() > 1;
    if needs_parens {
        head.push('(');
        head.push_str(&joined);
        head.push(')');
    } else {
        head.push_str(&joined);
    }
    head.push_str(":\n");
    head.push_str(&emit_block(em, body, indent + 1, version));
    head
}

#[must_use]
fn emit_with_item(em: &DefaultEmitter, item: &WithItem, version: &PyVersion) -> String {
    let ctx: String = emit_expr(em, &item.context_expr, version, Precedence::Lowest);
    match &item.optional_vars {
        Some(v) => format!("{ctx} as {}", emit_expr(em, v, version, Precedence::Lowest)),
        None => ctx,
    }
}

#[must_use]
fn emit_raise(
    em: &DefaultEmitter,
    pad: &str,
    exc: Option<&Expr>,
    cause: Option<&Expr>,
    version: &PyVersion,
) -> String {
    match (exc, cause) {
        (None, _) => format!("{pad}raise"),
        (Some(e), None) => format!(
            "{pad}raise {}",
            emit_expr(em, e, version, Precedence::Lowest)
        ),
        (Some(e), Some(c)) => format!(
            "{pad}raise {} from {}",
            emit_expr(em, e, version, Precedence::Lowest),
            emit_expr(em, c, version, Precedence::Lowest)
        ),
    }
}
