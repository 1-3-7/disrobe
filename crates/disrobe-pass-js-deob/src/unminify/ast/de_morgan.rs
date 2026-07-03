use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, LogicalOperator, Program, Statement, UnaryOperator};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct DeMorganStats {
    pub(super) and_negations: usize,
    pub(super) or_negations: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, DeMorganStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), DeMorganStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: DeMorganStats = DeMorganStats::default();
    for stmt in &program.body {
        walk_statement(stmt, source, &mut edits, &mut stats);
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn walk_statement(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut DeMorganStats,
) {
    match stmt {
        Statement::ExpressionStatement(s) => walk_expression(&s.expression, source, edits, stats),
        Statement::ReturnStatement(s) => {
            if let Some(arg) = s.argument.as_ref() {
                walk_expression(arg, source, edits, stats);
            }
        }
        Statement::VariableDeclaration(s) => {
            for d in &s.declarations {
                if let Some(init) = d.init.as_ref() {
                    walk_expression(init, source, edits, stats);
                }
            }
        }
        Statement::IfStatement(s) => {
            walk_expression(&s.test, source, edits, stats);
            walk_statement(&s.consequent, source, edits, stats);
            if let Some(alt) = s.alternate.as_ref() {
                walk_statement(alt, source, edits, stats);
            }
        }
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                walk_statement(inner, source, edits, stats);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(test) = s.test.as_ref() {
                walk_expression(test, source, edits, stats);
            }
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::WhileStatement(s) => {
            walk_expression(&s.test, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::DoWhileStatement(s) => {
            walk_expression(&s.test, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, source, edits, stats);
                }
            }
        }
        Statement::ThrowStatement(s) => walk_expression(&s.argument, source, edits, stats),
        Statement::SwitchStatement(s) => {
            walk_expression(&s.discriminant, source, edits, stats);
            for case in &s.cases {
                for inner in &case.consequent {
                    walk_statement(inner, source, edits, stats);
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
    stats: &mut DeMorganStats,
) {
    if let Some(edit) = try_de_morgan(expr, source, stats) {
        edits.push(edit);
        return;
    }
    match expr {
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, source, edits, stats);
            walk_expression(&b.right, source, edits, stats);
        }
        Expression::BinaryExpression(b) => {
            walk_expression(&b.left, source, edits, stats);
            walk_expression(&b.right, source, edits, stats);
        }
        Expression::ParenthesizedExpression(p) => {
            walk_expression(&p.expression, source, edits, stats);
        }
        Expression::UnaryExpression(u) => walk_expression(&u.argument, source, edits, stats),
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, source, edits, stats);
            walk_expression(&c.consequent, source, edits, stats);
            walk_expression(&c.alternate, source, edits, stats);
        }
        Expression::CallExpression(c) => {
            for arg in &c.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, source, edits, stats);
                }
            }
        }
        Expression::AssignmentExpression(a) => walk_expression(&a.right, source, edits, stats),
        Expression::SequenceExpression(s) => {
            for inner in &s.expressions {
                walk_expression(inner, source, edits, stats);
            }
        }
        _ => {}
    }
}

fn try_de_morgan(expr: &Expression<'_>, source: &str, stats: &mut DeMorganStats) -> Option<Edit> {
    let Expression::UnaryExpression(unary): &Expression<'_> = expr else {
        return None;
    };
    if unary.operator != UnaryOperator::LogicalNot {
        return None;
    }
    let inner: &Expression<'_> = unwrap_paren(&unary.argument);
    let Expression::LogicalExpression(logical): &Expression<'_> = inner else {
        return None;
    };
    let flipped: &str = match logical.operator {
        LogicalOperator::And => "||",
        LogicalOperator::Or => "&&",
        LogicalOperator::Coalesce => return None,
    };
    if !is_side_effect_free(&logical.left) || !is_side_effect_free(&logical.right) {
        return None;
    }
    let left_neg: String = negate(&logical.left, source);
    let right_neg: String = negate(&logical.right, source);
    match logical.operator {
        LogicalOperator::And => stats.and_negations += 1,
        LogicalOperator::Or => stats.or_negations += 1,
        LogicalOperator::Coalesce => {}
    }
    Some(Edit {
        start: unary.span.start as usize,
        end: unary.span.end as usize,
        replacement: format!("{left_neg} {flipped} {right_neg}"),
    })
}

fn unwrap_paren<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(p) => unwrap_paren(&p.expression),
        other => other,
    }
}

fn negate(expr: &Expression<'_>, source: &str) -> String {
    let target: &Expression<'_> = unwrap_paren(expr);
    let text: &str = target.span().source_text(source);
    if is_atomic(target) {
        format!("!{text}")
    } else {
        format!("!({text})")
    }
}

const fn is_atomic(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::Identifier(_)
            | Expression::StaticMemberExpression(_)
            | Expression::ComputedMemberExpression(_)
            | Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::ThisExpression(_)
    )
}

fn is_side_effect_free(expr: &Expression<'_>) -> bool {
    match unwrap_paren(expr) {
        Expression::Identifier(_)
        | Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::ThisExpression(_) => true,
        Expression::UnaryExpression(u) => {
            !matches!(u.operator, UnaryOperator::Delete) && is_side_effect_free(&u.argument)
        }
        Expression::BinaryExpression(b) => {
            is_side_effect_free(&b.left) && is_side_effect_free(&b.right)
        }
        Expression::LogicalExpression(b) => {
            is_side_effect_free(&b.left) && is_side_effect_free(&b.right)
        }
        Expression::StaticMemberExpression(m) => is_side_effect_free(&m.object),
        Expression::ComputedMemberExpression(m) => {
            is_side_effect_free(&m.object) && is_side_effect_free(&m.expression)
        }
        Expression::ConditionalExpression(c) => {
            is_side_effect_free(&c.test)
                && is_side_effect_free(&c.consequent)
                && is_side_effect_free(&c.alternate)
        }
        _ => false,
    }
}
