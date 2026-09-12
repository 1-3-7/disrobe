use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BinaryOperator, ConditionalExpression, Expression, IdentifierReference, LogicalOperator,
    Program, Statement, UnaryOperator,
};
use oxc_parser::Parser;
use oxc_semantic::{Semantic, SemanticBuilder};
use oxc_span::{GetSpan, SourceType};

use super::{
    Edit, RuleOutcome, edit_overlaps_comments, repeated_checked_identifiers,
    same_repeatable_binding,
};

#[derive(Debug, Clone, Default)]
pub(super) struct NullishCoalescingStats {
    pub(super) coalesces_rebuilt: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, NullishCoalescingStats) {
    recover_with_binding_proof(source)
}

pub(super) fn recover_preset_env(source: &str) -> (RuleOutcome, NullishCoalescingStats) {
    recover_with_binding_proof(source)
}

fn recover_with_binding_proof(source: &str) -> (RuleOutcome, NullishCoalescingStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = match SourceType::from_path("input.js") {
        Ok(value) => value,
        Err(_) => return (RuleOutcome::empty(), NullishCoalescingStats::default()),
    };
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), NullishCoalescingStats::default());
    }
    let program: &Program<'_> = &parsed.program;
    let semantic_return: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(program);
    if !semantic_return.errors.is_empty() {
        return (RuleOutcome::empty(), NullishCoalescingStats::default());
    }
    let semantic: Semantic<'_> = semantic_return.semantic;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: NullishCoalescingStats = NullishCoalescingStats::default();
    for stmt in &program.body {
        walk_statement(stmt, source, &mut edits, &mut stats, &semantic);
    }
    edits.retain(|edit: &Edit| !edit_overlaps_comments(edit, &program.comments));
    stats.coalesces_rebuilt = edits.len();

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn walk_statement(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut NullishCoalescingStats,
    semantic: &Semantic<'_>,
) {
    match stmt {
        Statement::ExpressionStatement(s) => {
            walk_expression(&s.expression, source, edits, stats, semantic);
        }
        Statement::ReturnStatement(s) => {
            if let Some(arg) = s.argument.as_ref() {
                walk_expression(arg, source, edits, stats, semantic);
            }
        }
        Statement::VariableDeclaration(s) => {
            for d in &s.declarations {
                if let Some(init) = d.init.as_ref() {
                    walk_expression(init, source, edits, stats, semantic);
                }
            }
        }
        Statement::IfStatement(s) => {
            walk_expression(&s.test, source, edits, stats, semantic);
            walk_statement(&s.consequent, source, edits, stats, semantic);
            if let Some(alt) = s.alternate.as_ref() {
                walk_statement(alt, source, edits, stats, semantic);
            }
        }
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                walk_statement(inner, source, edits, stats, semantic);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(test) = s.test.as_ref() {
                walk_expression(test, source, edits, stats, semantic);
            }
            walk_statement(&s.body, source, edits, stats, semantic);
        }
        Statement::WhileStatement(s) => {
            walk_expression(&s.test, source, edits, stats, semantic);
            walk_statement(&s.body, source, edits, stats, semantic);
        }
        Statement::DoWhileStatement(s) => {
            walk_expression(&s.test, source, edits, stats, semantic);
            walk_statement(&s.body, source, edits, stats, semantic);
        }
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, source, edits, stats, semantic);
                }
            }
        }
        Statement::ThrowStatement(s) => {
            walk_expression(&s.argument, source, edits, stats, semantic);
        }
        Statement::SwitchStatement(s) => {
            walk_expression(&s.discriminant, source, edits, stats, semantic);
            for case in &s.cases {
                for inner in &case.consequent {
                    walk_statement(inner, source, edits, stats, semantic);
                }
            }
        }
        _ => {}
    }
}

fn walk_expression(
    expr: &Expression<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut NullishCoalescingStats,
    semantic: &Semantic<'_>,
) {
    if let Expression::ConditionalExpression(cond) = expr
        && let Some(edit) = try_coalesce(cond, source, semantic)
    {
        edits.push(edit);
        stats.coalesces_rebuilt += 1;
        return;
    }
    match expr {
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, source, edits, stats, semantic);
            walk_expression(&c.consequent, source, edits, stats, semantic);
            walk_expression(&c.alternate, source, edits, stats, semantic);
        }
        Expression::BinaryExpression(b) => {
            walk_expression(&b.left, source, edits, stats, semantic);
            walk_expression(&b.right, source, edits, stats, semantic);
        }
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, source, edits, stats, semantic);
            walk_expression(&b.right, source, edits, stats, semantic);
        }
        Expression::ParenthesizedExpression(p) => {
            walk_expression(&p.expression, source, edits, stats, semantic);
        }
        Expression::CallExpression(c) => {
            for arg in &c.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, source, edits, stats, semantic);
                }
            }
        }
        Expression::AssignmentExpression(a) => {
            walk_expression(&a.right, source, edits, stats, semantic);
        }
        Expression::SequenceExpression(s) => {
            for inner in &s.expressions {
                walk_expression(inner, source, edits, stats, semantic);
            }
        }
        Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(inner) = el.as_expression() {
                    walk_expression(inner, source, edits, stats, semantic);
                }
            }
        }
        Expression::ObjectExpression(obj) => {
            for prop in &obj.properties {
                if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop {
                    walk_expression(&p.value, source, edits, stats, semantic);
                }
            }
        }
        Expression::FunctionExpression(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, source, edits, stats, semantic);
                }
            }
        }
        Expression::ArrowFunctionExpression(a) => {
            for inner in &a.body.statements {
                walk_statement(inner, source, edits, stats, semantic);
            }
        }
        _ => {}
    }
}

fn try_coalesce(
    cond: &ConditionalExpression<'_>,
    source: &str,
    semantic: &Semantic<'_>,
) -> Option<Edit> {
    let test: &Expression<'_> = unwrap_paren(&cond.test);
    let consequent: &Expression<'_> = unwrap_paren(&cond.consequent);
    let alternate: &Expression<'_> = unwrap_paren(&cond.alternate);

    if let Some(checked) = null_or_undefined(test, source) {
        if reference_matches(checked, alternate, source, test, semantic) {
            return Some(build(checked, consequent, cond, source));
        }
        return None;
    }
    if let Some(checked) = not_null_and_not_undefined(test, source) {
        if reference_matches(checked, consequent, source, test, semantic) {
            return Some(build(checked, alternate, cond, source));
        }
        return None;
    }
    None
}

fn build(
    checked_src: &str,
    fallback: &Expression<'_>,
    cond: &ConditionalExpression<'_>,
    source: &str,
) -> Edit {
    let fallback_src: &str = fallback.span().source_text(source);
    let fallback_wrapped: String = if needs_parens_as_coalesce_rhs(fallback) {
        format!("({fallback_src})")
    } else {
        fallback_src.to_owned()
    };
    Edit {
        start: cond.span.start as usize,
        end: cond.span.end as usize,
        replacement: format!("{checked_src} ?? {fallback_wrapped}"),
    }
}

fn not_null_and_not_undefined<'a>(test: &'a Expression<'a>, source: &'a str) -> Option<&'a str> {
    let Expression::LogicalExpression(logical): &Expression<'_> = test else {
        return None;
    };
    if logical.operator != LogicalOperator::And {
        return None;
    }
    let left_ref: &str = strict_not_null(&logical.left, source)?;
    let right_ref: &str = strict_not_undefined(&logical.right, source)?;
    if left_ref == right_ref {
        Some(left_ref)
    } else {
        None
    }
}

fn null_or_undefined<'a>(test: &'a Expression<'a>, source: &'a str) -> Option<&'a str> {
    let Expression::LogicalExpression(logical): &Expression<'_> = test else {
        return None;
    };
    if logical.operator != LogicalOperator::Or {
        return None;
    }
    let left_ref: &str = strict_is_null(&logical.left, source)?;
    let right_ref: &str = strict_is_undefined(&logical.right, source)?;
    if left_ref == right_ref {
        Some(left_ref)
    } else {
        None
    }
}

fn strict_is_null<'a>(expr: &'a Expression<'a>, source: &'a str) -> Option<&'a str> {
    strict_compare(expr, source, BinaryOperator::StrictEquality, NullKind::Null)
}

fn strict_is_undefined<'a>(expr: &'a Expression<'a>, source: &'a str) -> Option<&'a str> {
    strict_compare(
        expr,
        source,
        BinaryOperator::StrictEquality,
        NullKind::Undefined,
    )
}

fn strict_not_null<'a>(expr: &'a Expression<'a>, source: &'a str) -> Option<&'a str> {
    strict_compare(
        expr,
        source,
        BinaryOperator::StrictInequality,
        NullKind::Null,
    )
}

fn strict_not_undefined<'a>(expr: &'a Expression<'a>, source: &'a str) -> Option<&'a str> {
    strict_compare(
        expr,
        source,
        BinaryOperator::StrictInequality,
        NullKind::Undefined,
    )
}

enum NullKind {
    Null,
    Undefined,
}

fn strict_compare<'a>(
    expr: &'a Expression<'a>,
    source: &'a str,
    op: BinaryOperator,
    kind: NullKind,
) -> Option<&'a str> {
    let Expression::BinaryExpression(bin): &Expression<'_> = expr else {
        return None;
    };
    if bin.operator != op {
        return None;
    }
    let matches_kind = |e: &Expression<'_>| -> bool {
        match kind {
            NullKind::Null => is_null_literal(e),
            NullKind::Undefined => is_void_undefined(e),
        }
    };
    if matches_kind(&bin.right) && matches!(&bin.left, Expression::Identifier(_)) {
        return Some(bin.left.span().source_text(source));
    }
    if matches_kind(&bin.left) && matches!(&bin.right, Expression::Identifier(_)) {
        return Some(bin.right.span().source_text(source));
    }
    None
}

fn reference_matches(
    checked_src: &str,
    candidate: &Expression<'_>,
    source: &str,
    test: &Expression<'_>,
    semantic: &Semantic<'_>,
) -> bool {
    let Expression::Identifier(candidate_identifier) = candidate else {
        return false;
    };
    let Some((first, second)): Option<(&IdentifierReference<'_>, &IdentifierReference<'_>)> =
        repeated_checked_identifiers(test)
    else {
        return false;
    };
    same_repeatable_binding(first, second, candidate_identifier, semantic)
        && candidate.span().source_text(source) == checked_src
}

const fn is_null_literal(expr: &Expression<'_>) -> bool {
    matches!(expr, Expression::NullLiteral(_))
}

fn is_void_undefined(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::UnaryExpression(unary)
            if unary.operator == UnaryOperator::Void
                && matches!(
                    &unary.argument,
                    Expression::NumericLiteral(_) | Expression::StringLiteral(_)
                )
    )
}

const fn needs_parens_as_coalesce_rhs(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::LogicalExpression(_)
            | Expression::ConditionalExpression(_)
            | Expression::SequenceExpression(_)
            | Expression::AssignmentExpression(_)
    )
}

fn unwrap_paren<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(p) => unwrap_paren(&p.expression),
        other => other,
    }
}
