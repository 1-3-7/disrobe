#![allow(
    clippy::match_same_arms,
    clippy::too_many_lines,
    clippy::option_if_let_else
)]

use crate::ast::node::{ExceptHandler, Expr, MatchCase, Pattern, Stmt};
use crate::bytecode::version::PyVersion;
use crate::codegen::DefaultEmitter;
use crate::codegen::expr::{Precedence, emit_expr};
use crate::codegen::stmt::emit_block;
use crate::codegen::version_dispatch;

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn emit_for(
    em: &DefaultEmitter,
    pad: &str,
    indent: u32,
    target: &Expr,
    iter: &Expr,
    body: &[Stmt],
    orelse: &[Stmt],
    is_async: bool,
    version: &PyVersion,
) -> String {
    let mut head: String = pad.to_owned();
    if is_async && version_dispatch::supports_async(version) {
        head.push_str("async ");
    }
    head.push_str("for ");
    head.push_str(&emit_expr(em, target, version, Precedence::Lowest));
    head.push_str(" in ");
    head.push_str(&emit_expr(em, iter, version, Precedence::Lowest));
    head.push_str(":\n");
    head.push_str(&emit_block(em, body, indent + 1, version));
    if !orelse.is_empty() {
        head.push('\n');
        head.push_str(pad);
        head.push_str("else:\n");
        head.push_str(&emit_block(em, orelse, indent + 1, version));
    }
    head
}

#[must_use]
pub fn emit_while(
    em: &DefaultEmitter,
    pad: &str,
    indent: u32,
    test: &Expr,
    body: &[Stmt],
    orelse: &[Stmt],
    version: &PyVersion,
) -> String {
    let mut head: String = format!(
        "{pad}while {}:\n",
        emit_expr(em, test, version, Precedence::Lowest)
    );
    head.push_str(&emit_block(em, body, indent + 1, version));
    if !orelse.is_empty() {
        head.push('\n');
        head.push_str(pad);
        head.push_str("else:\n");
        head.push_str(&emit_block(em, orelse, indent + 1, version));
    }
    head
}

#[must_use]
pub fn emit_if_chain(
    em: &DefaultEmitter,
    pad: &str,
    indent: u32,
    test: &Expr,
    body: &[Stmt],
    orelse: &[Stmt],
    version: &PyVersion,
) -> String {
    let mut out: String = format!(
        "{pad}if {}:\n",
        emit_expr(em, test, version, Precedence::Lowest)
    );
    out.push_str(&emit_block(em, body, indent + 1, version));
    let mut current: &[Stmt] = orelse;
    loop {
        match current {
            [] => break,
            [only] if matches!(only, Stmt::If { .. }) => {
                let Stmt::If {
                    test: t,
                    body: b,
                    orelse: o,
                    ..
                } = only
                else {
                    break;
                };
                out.push('\n');
                out.push_str(pad);
                out.push_str("elif ");
                out.push_str(&emit_expr(em, t, version, Precedence::Lowest));
                out.push_str(":\n");
                out.push_str(&emit_block(em, b, indent + 1, version));
                current = o;
            }
            rest => {
                out.push('\n');
                out.push_str(pad);
                out.push_str("else:\n");
                out.push_str(&emit_block(em, rest, indent + 1, version));
                break;
            }
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn emit_try(
    em: &DefaultEmitter,
    pad: &str,
    indent: u32,
    body: &[Stmt],
    handlers: &[ExceptHandler],
    orelse: &[Stmt],
    finalbody: &[Stmt],
    is_try_star: bool,
    version: &PyVersion,
) -> String {
    let mut out: String = format!("{pad}try:\n");
    out.push_str(&emit_block(em, body, indent + 1, version));
    let except_kw: &str = if is_try_star { "except*" } else { "except" };
    for h in handlers {
        out.push('\n');
        out.push_str(pad);
        out.push_str(except_kw);
        match (&h.typ, &h.name) {
            (Some(t), Some(n)) => {
                out.push(' ');
                out.push_str(&emit_expr(em, t, version, Precedence::Lowest));
                out.push_str(" as ");
                out.push_str(n);
            }
            (Some(t), None) => {
                out.push(' ');
                out.push_str(&emit_expr(em, t, version, Precedence::Lowest));
            }
            (None, _) => {}
        }
        out.push_str(":\n");
        out.push_str(&emit_block(em, &h.body, indent + 1, version));
    }
    if !orelse.is_empty() {
        out.push('\n');
        out.push_str(pad);
        out.push_str("else:\n");
        out.push_str(&emit_block(em, orelse, indent + 1, version));
    }
    if !finalbody.is_empty() {
        out.push('\n');
        out.push_str(pad);
        out.push_str("finally:\n");
        out.push_str(&emit_block(em, finalbody, indent + 1, version));
    }
    out
}

#[must_use]
pub fn emit_match(
    em: &DefaultEmitter,
    pad: &str,
    indent: u32,
    subject: &Expr,
    cases: &[MatchCase],
    version: &PyVersion,
) -> String {
    let mut out: String = format!(
        "{pad}match {}:\n",
        emit_expr(em, subject, version, Precedence::Lowest)
    );
    let case_pad: String = em.indent_str(indent + 1);
    for c in cases {
        out.push_str(&case_pad);
        out.push_str("case ");
        out.push_str(&emit_pattern(em, &c.pattern, version));
        if let Some(g) = &c.guard {
            out.push_str(" if ");
            out.push_str(&emit_expr(em, g, version, Precedence::Lowest));
        }
        out.push_str(":\n");
        out.push_str(&emit_block(em, &c.body, indent + 2, version));
        out.push('\n');
    }
    out
}

#[must_use]
fn emit_pattern(em: &DefaultEmitter, p: &Pattern, version: &PyVersion) -> String {
    match p {
        Pattern::MatchValue(e) => emit_expr(em, e, version, Precedence::Lowest),
        Pattern::MatchSingleton(c) => match c {
            crate::ast::node::ConstValue::None => "None".to_owned(),
            crate::ast::node::ConstValue::True => "True".to_owned(),
            crate::ast::node::ConstValue::False => "False".to_owned(),
            _ => "_".to_owned(),
        },
        Pattern::MatchSequence(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|q: &Pattern| emit_pattern(em, q, version))
                .collect();
            format!("[{}]", parts.join(", "))
        }
        Pattern::MatchMapping {
            keys,
            patterns,
            rest,
        } => {
            let mut parts: Vec<String> = Vec::with_capacity(keys.len() + 1);
            for (k, pat) in keys.iter().zip(patterns.iter()) {
                parts.push(format!(
                    "{}: {}",
                    emit_expr(em, k, version, Precedence::Lowest),
                    emit_pattern(em, pat, version)
                ));
            }
            if let Some(r) = rest {
                parts.push(format!("**{r}"));
            }
            format!("{{{}}}", parts.join(", "))
        }
        Pattern::MatchClass {
            cls,
            patterns,
            kwd_attrs,
            kwd_patterns,
        } => {
            let cls_s: String = emit_expr(em, cls, version, Precedence::PostfixCall);
            let mut parts: Vec<String> = patterns
                .iter()
                .map(|q: &Pattern| emit_pattern(em, q, version))
                .collect();
            for (a, p) in kwd_attrs.iter().zip(kwd_patterns.iter()) {
                parts.push(format!("{a}={}", emit_pattern(em, p, version)));
            }
            format!("{cls_s}({})", parts.join(", "))
        }
        Pattern::MatchStar(name) => match name {
            Some(n) => format!("*{n}"),
            None => "*_".to_owned(),
        },
        Pattern::MatchAs { pattern, name } => match (pattern, name) {
            (Some(inner), Some(n)) => format!("{} as {n}", emit_pattern(em, inner, version)),
            (None, Some(n)) => n.clone(),
            (Some(inner), None) => emit_pattern(em, inner, version),
            (None, None) => "_".to_owned(),
        },
        Pattern::MatchOr(alts) => {
            let parts: Vec<String> = alts
                .iter()
                .map(|q: &Pattern| emit_pattern(em, q, version))
                .collect();
            parts.join(" | ")
        }
    }
}
