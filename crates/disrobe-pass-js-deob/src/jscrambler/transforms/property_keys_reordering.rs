use core::cmp::Reverse;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Expression, ObjectExpression, ObjectProperty, ObjectPropertyKind, Program, PropertyKey,
    PropertyKind, Statement,
};
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};

use super::walk::{walk_expression, walk_expressions_in_statement, walk_nested_statements};
use super::{TransformOpts, TransformOutput, TransformStats};
use crate::error::{Error, Result};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    analyze(source).map_or(0, |plan: ReversePlan| plan.targets.len())
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let Some(plan): Option<ReversePlan> = analyze(source) else {
        let stats: TransformStats = TransformStats {
            errors: vec!["parse-failed".to_owned()],
            ..TransformStats::default()
        };
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    };
    apply(source, &plan)
}

pub(in crate::jscrambler) fn reverse_strict(
    source: &str,
    _opts: &TransformOpts,
) -> Result<TransformOutput> {
    let Some(plan): Option<ReversePlan> = analyze(source) else {
        return Err(Error::OxcParse(
            "propertyKeysReordering: source did not parse as JavaScript".to_owned(),
        ));
    };
    Ok(apply(source, &plan))
}

#[derive(Debug, Clone)]
struct Target {
    object_span: Span,
    ordered_props: Vec<String>,
}

#[derive(Debug, Default)]
struct ReversePlan {
    targets: Vec<Target>,
}

fn analyze(source: &str) -> Option<ReversePlan> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return None;
    }
    let program: &Program<'_> = &parsed.program;
    let mut targets: Vec<Target> = Vec::new();
    for stmt in &program.body {
        collect_targets(stmt, source, &mut targets);
    }
    Some(ReversePlan { targets })
}

fn collect_targets(stmt: &Statement<'_>, source: &str, out: &mut Vec<Target>) {
    walk_nested_statements(stmt, &mut |inner: &Statement<'_>| {
        collect_targets(inner, source, out);
    });
    walk_expressions_in_statement(stmt, &mut |expr: &Expression<'_>| {
        if let Expression::ObjectExpression(obj) = expr
            && let Some(target) = canonicalize(obj, source)
        {
            out.push(target);
        }
    });
}

fn canonicalize(obj: &ObjectExpression<'_>, source: &str) -> Option<Target> {
    if obj.properties.len() < 2 {
        return None;
    }
    let mut entries: Vec<(String, String)> = Vec::with_capacity(obj.properties.len());
    let mut keys_seen: Vec<String> = Vec::new();
    for prop_kind in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop): &ObjectPropertyKind<'_> = prop_kind else {
            return None;
        };
        if prop.kind != PropertyKind::Init || prop.method || prop.computed {
            return None;
        }
        let key: String = static_key(&prop.key)?;
        if keys_seen.contains(&key) {
            return None;
        }
        keys_seen.push(key.clone());
        if !value_is_reorder_safe(&prop.value) {
            return None;
        }
        let rendered: String = render_property(prop, source)?;
        entries.push((key, rendered));
    }

    let original: Vec<String> = entries
        .iter()
        .map(|e: &(String, String)| e.0.clone())
        .collect();
    entries.sort_by(|a: &(String, String), b: &(String, String)| a.0.cmp(&b.0));
    let sorted: Vec<String> = entries
        .iter()
        .map(|e: &(String, String)| e.0.clone())
        .collect();
    if original == sorted {
        return None;
    }
    Some(Target {
        object_span: obj.span,
        ordered_props: entries.into_iter().map(|e: (String, String)| e.1).collect(),
    })
}

fn static_key(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.as_str().to_owned()),
        PropertyKey::StringLiteral(s) => Some(s.value.as_str().to_owned()),
        PropertyKey::NumericLiteral(n) => Some(n.value.to_string()),
        _ => None,
    }
}

fn render_property(prop: &ObjectProperty<'_>, source: &str) -> Option<String> {
    let text: &str = prop.span.source_text(source).trim();
    if text.is_empty() || text.contains('\n') {
        return None;
    }
    Some(text.to_owned())
}

fn value_is_reorder_safe(expr: &Expression<'_>) -> bool {
    let mut safe: bool = true;
    walk_expression(expr, &mut |inner: &Expression<'_>| {
        let node_ok: bool = matches!(
            inner,
            Expression::BooleanLiteral(_)
                | Expression::NullLiteral(_)
                | Expression::NumericLiteral(_)
                | Expression::BigIntLiteral(_)
                | Expression::RegExpLiteral(_)
                | Expression::StringLiteral(_)
                | Expression::TemplateLiteral(_)
                | Expression::Identifier(_)
                | Expression::ThisExpression(_)
                | Expression::ArrayExpression(_)
                | Expression::ObjectExpression(_)
                | Expression::StaticMemberExpression(_)
                | Expression::ComputedMemberExpression(_)
                | Expression::ParenthesizedExpression(_)
                | Expression::UnaryExpression(_)
                | Expression::BinaryExpression(_)
                | Expression::LogicalExpression(_)
                | Expression::ConditionalExpression(_)
                | Expression::FunctionExpression(_)
                | Expression::ArrowFunctionExpression(_)
        );
        if !node_ok {
            safe = false;
        }
    });
    safe
}

fn apply(source: &str, plan: &ReversePlan) -> TransformOutput {
    let mut stats: TransformStats = TransformStats {
        matched: plan.targets.len(),
        ..TransformStats::default()
    };
    if plan.targets.is_empty() {
        return TransformOutput::noop(source);
    }
    let mut edits: Vec<(Span, String)> = Vec::new();
    for target in &plan.targets {
        edits.push((target.object_span, render_object(target)));
    }
    edits.sort_by_key(|e: &(Span, String)| Reverse(e.0.start));
    let mut out: String = source.to_owned();
    let mut last_start: usize = out.len() + 1;
    for (span, replacement) in &edits {
        let start: usize = span.start as usize;
        let end: usize = span.end as usize;
        if start > end || end > last_start || end > out.len() {
            continue;
        }
        if !out.is_char_boundary(start) || !out.is_char_boundary(end) {
            continue;
        }
        out.replace_range(start..end, replacement);
        last_start = start;
        stats.reversed += 1;
    }
    TransformOutput { source: out, stats }
}

fn render_object(target: &Target) -> String {
    let mut out: String = String::from("{ ");
    for (i, prop) in target.ordered_props.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(prop);
    }
    out.push_str(" }");
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_finds_reordered_keys() {
        let src: &str = "var o = {b: 1, a: 2};";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn canonicalizes_keys_alphabetically() {
        let src: &str = "var o = {c: 1, a: 2, b: 3};";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.stats.reversed >= 1);
        let a_pos: usize = out.source.find("a: 2").unwrap();
        let b_pos: usize = out.source.find("b: 3").unwrap();
        let c_pos: usize = out.source.find("c: 1").unwrap();
        assert!(a_pos < b_pos);
        assert!(b_pos < c_pos);
    }

    #[test]
    fn no_op_on_already_sorted() {
        let src: &str = "var o = {a: 1, b: 2};";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }

    #[test]
    fn skips_object_with_side_effecting_value() {
        let src: &str = "var o = {b: f(), a: 2};";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(
            out.stats.reversed, 0,
            "a value that may have observable side effects must not be reordered:\n{}",
            out.source
        );
    }

    #[test]
    fn skips_object_with_getter() {
        let src: &str = "var o = {get b() { return 1; }, a: 2};";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 0);
    }

    #[test]
    fn returns_typed_error_in_strict_mode_on_parse_failure() {
        let res: Result<TransformOutput> = reverse_strict("var o = {", &TransformOpts::default());
        assert!(res.is_err());
    }

    #[test]
    fn clean_source_is_noop_not_error() {
        let res: Result<TransformOutput> = reverse_strict("var x = 1;", &TransformOpts::default());
        assert!(res.is_ok());
    }

    #[test]
    fn skips_block_statement_braces() {
        let src: &str = "function f() { var x = 1; return x; }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
