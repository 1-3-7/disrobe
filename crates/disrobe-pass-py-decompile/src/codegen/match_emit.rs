use crate::ast::node::{Expr, MatchCase, Pattern};
use crate::bytecode::version::PyVersion;
use crate::codegen::modern_expr_render::{indent_str, render_body, render_const, render_expr};

#[must_use]
pub fn emit_match(subject: &Expr, cases: &[MatchCase], indent: u32, version: &PyVersion) -> String {
    let head: String = format!(
        "{}match {}:",
        indent_str(indent),
        render_expr(subject, version)
    );
    let mut out: String = head;
    for case in cases {
        out.push('\n');
        out.push_str(&emit_case(case, indent + 1, version));
    }
    out
}

#[must_use]
fn emit_case(case: &MatchCase, indent: u32, version: &PyVersion) -> String {
    let prefix: String = indent_str(indent);
    let pat: String = render_pattern(&case.pattern, version);
    let guard: String = case.guard.as_ref().map_or(String::new(), |g: &Expr| {
        format!(" if {}", render_expr(g, version))
    });
    let header: String = format!("{prefix}case {pat}{guard}:");
    let body: String = render_body(&case.body, indent + 1, version);
    format!("{header}\n{body}")
}

#[must_use]
pub fn render_pattern(pat: &Pattern, version: &PyVersion) -> String {
    match pat {
        Pattern::MatchValue(expr) => render_expr(expr, version),
        Pattern::MatchSingleton(c) => render_const(c),
        Pattern::MatchSequence(items) => {
            let inner: String = items
                .iter()
                .map(|p: &Pattern| render_pattern(p, version))
                .collect::<Vec<String>>()
                .join(", ");
            format!("[{inner}]")
        }
        Pattern::MatchMapping {
            keys,
            patterns,
            rest,
        } => render_mapping(keys, patterns, rest.as_deref(), version),
        Pattern::MatchClass {
            cls,
            patterns,
            kwd_attrs,
            kwd_patterns,
        } => render_class(cls, patterns, kwd_attrs, kwd_patterns, version),
        Pattern::MatchStar(name) => name
            .as_ref()
            .map_or_else(|| "*_".to_owned(), |n: &String| format!("*{n}")),
        Pattern::MatchAs { pattern, name } => match (pattern, name) {
            (Some(inner), Some(n)) => format!("{} as {n}", render_pattern(inner, version)),
            (None, Some(n)) => n.clone(),
            (Some(inner), None) => render_pattern(inner, version),
            (None, None) => "_".to_owned(),
        },
        Pattern::MatchOr(alts) => alts
            .iter()
            .map(|p: &Pattern| render_pattern(p, version))
            .collect::<Vec<String>>()
            .join(" | "),
    }
}

#[must_use]
fn render_mapping(
    keys: &[Expr],
    patterns: &[Pattern],
    rest: Option<&str>,
    version: &PyVersion,
) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(keys.len() + usize::from(rest.is_some()));
    for (k, p) in keys.iter().zip(patterns.iter()) {
        parts.push(format!(
            "{}: {}",
            render_mapping_key(k, version),
            render_pattern(p, version)
        ));
    }
    if let Some(r) = rest {
        parts.push(format!("**{r}"));
    }
    format!("{{{}}}", parts.join(", "))
}

#[must_use]
fn render_mapping_key(key: &Expr, version: &PyVersion) -> String {
    match key {
        Expr::Constant { value, .. } => render_const(value),
        other => render_expr(other, version),
    }
}

#[must_use]
fn render_class(
    cls: &Expr,
    patterns: &[Pattern],
    kwd_attrs: &[String],
    kwd_patterns: &[Pattern],
    version: &PyVersion,
) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(patterns.len() + kwd_attrs.len());
    for p in patterns {
        parts.push(render_pattern(p, version));
    }
    for (attr, pat) in kwd_attrs.iter().zip(kwd_patterns.iter()) {
        parts.push(format!("{attr}={}", render_pattern(pat, version)));
    }
    format!("{}({})", render_expr(cls, version), parts.join(", "))
}
