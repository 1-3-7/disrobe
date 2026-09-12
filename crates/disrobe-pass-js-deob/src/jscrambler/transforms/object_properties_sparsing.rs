use core::cmp::Reverse;
use std::collections::BTreeSet;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentExpression, AssignmentOperator, AssignmentTarget, BindingPatternKind, Expression,
    Program, Statement,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};

use super::walk::walk_expression;
use super::{TransformOpts, TransformOutput, TransformStats};
use crate::error::{Error, Result};
use crate::jscrambler::scanner::is_valid_js_ident;

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    analyze(source).map_or(0, |plan: ReversePlan| plan.groups.len())
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
            "objectPropertiesSparsing: source did not parse as JavaScript".to_owned(),
        ));
    };
    Ok(apply(source, &plan))
}

#[derive(Debug, Clone)]
struct PropAssign {
    key: String,
    value_text: String,
    statement_span: Span,
}

#[derive(Debug, Clone)]
struct Group {
    init_span: Span,
    decl_keyword: String,
    object_name: String,
    props: Vec<PropAssign>,
}

#[derive(Debug, Default)]
struct ReversePlan {
    groups: Vec<Group>,
}

fn analyze(source: &str) -> Option<ReversePlan> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return None;
    }
    let program: &Program<'_> = &parsed.program;
    let mut groups: Vec<Group> = Vec::new();
    collect_in_block(&program.body, source, &mut groups);
    Some(ReversePlan { groups })
}

fn collect_in_block(stmts: &[Statement<'_>], source: &str, out: &mut Vec<Group>) {
    let mut idx: usize = 0;
    while idx < stmts.len() {
        if let Some((group, consumed)) = try_group_at(stmts, idx, source) {
            if group.props.len() >= 2 {
                out.push(group);
            }
            idx += consumed.max(1);
        } else {
            recurse_children(&stmts[idx], source, out);
            idx += 1;
        }
    }
}

fn try_group_at(stmts: &[Statement<'_>], start: usize, source: &str) -> Option<(Group, usize)> {
    let Statement::VariableDeclaration(decl): &Statement<'_> = &stmts[start] else {
        return None;
    };
    if decl.declarations.len() != 1 {
        return None;
    }
    let declarator: &oxc_ast::ast::VariableDeclarator<'_> = &decl.declarations[0];
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let Some(Expression::ObjectExpression(obj)): Option<&Expression<'_>> = declarator.init.as_ref()
    else {
        return None;
    };
    if !obj.properties.is_empty() {
        return None;
    }
    let object_name: String = binding.name.as_str().to_owned();
    let decl_keyword: String = decl.kind.as_str().to_owned();

    let mut props: Vec<PropAssign> = Vec::new();
    let mut seen_keys: BTreeSet<String> = BTreeSet::new();
    let mut cursor: usize = start + 1;
    while cursor < stmts.len() {
        let Some(prop): Option<PropAssign> =
            match_property_assignment(&stmts[cursor], &object_name, source)
        else {
            break;
        };
        if seen_keys.contains(&prop.key) {
            break;
        }
        seen_keys.insert(prop.key.clone());
        props.push(prop);
        cursor += 1;
    }

    if props.len() < 2 {
        return None;
    }
    let consumed: usize = cursor - start;
    Some((
        Group {
            init_span: decl.span,
            decl_keyword,
            object_name,
            props,
        },
        consumed,
    ))
}

fn match_property_assignment(
    stmt: &Statement<'_>,
    object_name: &str,
    source: &str,
) -> Option<PropAssign> {
    let Statement::ExpressionStatement(expr_stmt): &Statement<'_> = stmt else {
        return None;
    };
    let Expression::AssignmentExpression(assign): &Expression<'_> = &expr_stmt.expression else {
        return None;
    };
    if assign.operator != AssignmentOperator::Assign {
        return None;
    }
    let key: String = static_assignment_key(assign, object_name)?;
    if references_name(&assign.right, object_name) {
        return None;
    }
    let value_text: &str = assign.right.span().source_text(source).trim();
    if value_text.is_empty() {
        return None;
    }
    Some(PropAssign {
        key,
        value_text: value_text.to_owned(),
        statement_span: expr_stmt.span,
    })
}

fn static_assignment_key(assign: &AssignmentExpression<'_>, object_name: &str) -> Option<String> {
    match &assign.left {
        AssignmentTarget::StaticMemberExpression(member) => {
            let Expression::Identifier(obj) = &member.object else {
                return None;
            };
            if obj.name.as_str() != object_name {
                return None;
            }
            Some(member.property.name.as_str().to_owned())
        }
        AssignmentTarget::ComputedMemberExpression(member) => {
            let Expression::Identifier(obj) = &member.object else {
                return None;
            };
            if obj.name.as_str() != object_name {
                return None;
            }
            match &member.expression {
                Expression::StringLiteral(s) => Some(s.value.as_str().to_owned()),
                _ => None,
            }
        }
        _ => None,
    }
}

fn references_name(expr: &Expression<'_>, name: &str) -> bool {
    let mut found: bool = false;
    walk_expression(expr, &mut |inner: &Expression<'_>| {
        if let Expression::Identifier(ident) = inner
            && ident.name.as_str() == name
        {
            found = true;
        }
    });
    found
}

fn recurse_children(stmt: &Statement<'_>, source: &str, out: &mut Vec<Group>) {
    match stmt {
        Statement::BlockStatement(block) => collect_in_block(&block.body, source, out),
        Statement::FunctionDeclaration(func) => {
            if let Some(body) = func.body.as_ref() {
                collect_in_block(&body.statements, source, out);
            }
        }
        Statement::IfStatement(s) => {
            recurse_children(&s.consequent, source, out);
            if let Some(alt) = s.alternate.as_ref() {
                recurse_children(alt, source, out);
            }
        }
        Statement::ForStatement(s) => recurse_children(&s.body, source, out),
        Statement::ForInStatement(s) => recurse_children(&s.body, source, out),
        Statement::ForOfStatement(s) => recurse_children(&s.body, source, out),
        Statement::WhileStatement(s) => recurse_children(&s.body, source, out),
        Statement::DoWhileStatement(s) => recurse_children(&s.body, source, out),
        Statement::TryStatement(s) => {
            collect_in_block(&s.block.body, source, out);
            if let Some(handler) = s.handler.as_ref() {
                collect_in_block(&handler.body.body, source, out);
            }
            if let Some(finalizer) = s.finalizer.as_ref() {
                collect_in_block(&finalizer.body, source, out);
            }
        }
        Statement::SwitchStatement(s) => {
            for case in &s.cases {
                collect_in_block(&case.consequent, source, out);
            }
        }
        _ => {}
    }
}

fn apply(source: &str, plan: &ReversePlan) -> TransformOutput {
    let mut stats: TransformStats = TransformStats {
        matched: plan.groups.len(),
        ..TransformStats::default()
    };
    if plan.groups.is_empty() {
        return TransformOutput::noop(source);
    }
    let mut edits: Vec<(Span, String)> = Vec::new();
    for group in &plan.groups {
        edits.push((group.init_span, render_literal(group)));
        for prop in &group.props {
            edits.push((prop.statement_span, String::new()));
        }
    }
    edits.sort_by_key(|e: &(Span, String)| Reverse(e.0.start));
    let mut out: String = source.to_owned();
    let mut last_start: usize = out.len() + 1;
    let mut applied_groups: usize = 0;
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
        if !replacement.is_empty() {
            applied_groups += 1;
        }
    }
    stats.reversed = applied_groups;
    TransformOutput { source: out, stats }
}

fn render_literal(group: &Group) -> String {
    let mut lit: String = format!("{} {} = {{ ", group.decl_keyword, group.object_name);
    for (i, prop) in group.props.iter().enumerate() {
        if i > 0 {
            lit.push_str(", ");
        }
        if is_valid_js_ident(&prop.key) {
            lit.push_str(&prop.key);
        } else {
            lit.push('"');
            lit.push_str(&prop.key);
            lit.push('"');
        }
        lit.push_str(": ");
        lit.push_str(&prop.value_text);
    }
    lit.push_str(" };");
    lit
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_finds_sparsed_object() {
        let src: &str = "var o = {}; o.a = 1; o.b = 2;";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn collapses_two_props_into_literal() {
        let src: &str = "var o = {};\no.a = 1;\no.b = 2;\n";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.stats.reversed >= 1);
        assert!(out.source.contains("a: 1"));
        assert!(out.source.contains("b: 2"));
        assert!(!out.source.contains("o.a"));
    }

    #[test]
    fn skips_single_prop_object() {
        let src: &str = "var o = {}; o.a = 1;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 0);
    }

    #[test]
    fn stops_run_on_self_reference() {
        let src: &str = "var o = {};\no.a = 1;\no.b = o.a;\no.c = 3;\n";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(
            out.source.contains("o.b = o.a"),
            "an assignment whose RHS reads the object must not be folded:\n{}",
            out.source
        );
    }

    #[test]
    fn returns_typed_error_in_strict_mode_on_parse_failure() {
        let res: Result<TransformOutput> = reverse_strict("var = ;", &TransformOpts::default());
        assert!(res.is_err());
    }

    #[test]
    fn clean_source_is_noop_not_error() {
        let res: Result<TransformOutput> = reverse_strict("var x = 1;", &TransformOpts::default());
        assert!(res.is_ok());
    }
}
