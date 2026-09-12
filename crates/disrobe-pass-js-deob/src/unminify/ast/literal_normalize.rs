use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BinaryOperator, Expression, NumberBase, Program, Statement, UnaryExpression, UnaryOperator,
};
use oxc_parser::Parser;
use oxc_span::SourceType;

use super::{
    Edit, RuleOutcome, edit_overlaps_comments, undefined_init::undefined_lookup_is_stable,
};

#[derive(Debug, Clone, Default)]
pub(super) struct LiteralNormalizeStats {
    pub(super) boolean_shorthands: usize,
    pub(super) void_undefineds: usize,
    pub(super) double_not_coercions: usize,
    pub(super) string_concat_folds: usize,
    pub(super) numeric_folds: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, LiteralNormalizeStats) {
    let mut stats: LiteralNormalizeStats = LiteralNormalizeStats::default();
    let mut current: String = source.to_owned();

    while let Some((next, fired)) = single_pass(&current) {
        if next == current || !reparses(&next) {
            break;
        }
        current = next;
        stats.boolean_shorthands += fired.boolean_shorthands;
        stats.void_undefineds += fired.void_undefineds;
        stats.double_not_coercions += fired.double_not_coercions;
        stats.string_concat_folds += fired.string_concat_folds;
        stats.numeric_folds += fired.numeric_folds;
    }

    if current == source {
        return (RuleOutcome::empty(), stats);
    }
    (
        RuleOutcome {
            edits: vec![Edit {
                start: 0,
                end: source.len(),
                replacement: current,
            }],
        },
        stats,
    )
}

fn single_pass(source: &str) -> Option<(String, LiteralNormalizeStats)> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return None;
    }
    let program: &Program<'_> = &parsed.program;
    let allow_void_undefined: bool = undefined_lookup_is_stable(program);

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: LiteralNormalizeStats = LiteralNormalizeStats::default();
    for (index, stmt) in program.body.iter().enumerate() {
        walk_statement(
            stmt,
            &mut edits,
            &mut stats,
            allow_void_undefined,
            index == 0,
        );
    }
    if edits.is_empty()
        || edits
            .iter()
            .any(|edit: &Edit| edit_overlaps_comments(edit, &program.comments))
    {
        return None;
    }
    let next: String = apply_local_edits(source, &edits)?;
    Some((next, stats))
}

fn walk_statement(
    stmt: &Statement<'_>,
    edits: &mut Vec<Edit>,
    stats: &mut LiteralNormalizeStats,
    allow_void_undefined: bool,
    directive_position: bool,
) {
    match stmt {
        Statement::ExpressionStatement(s) => {
            walk_expression(
                &s.expression,
                edits,
                stats,
                allow_void_undefined,
                directive_position,
            );
        }
        Statement::ReturnStatement(s) => {
            if let Some(arg) = s.argument.as_ref() {
                walk_expression(arg, edits, stats, allow_void_undefined, false);
            }
        }
        Statement::ThrowStatement(s) => {
            walk_expression(&s.argument, edits, stats, allow_void_undefined, false);
        }
        Statement::VariableDeclaration(s) => {
            for d in &s.declarations {
                if let Some(init) = d.init.as_ref() {
                    walk_expression(init, edits, stats, allow_void_undefined, false);
                }
            }
        }
        Statement::IfStatement(s) => {
            walk_expression(&s.test, edits, stats, allow_void_undefined, false);
            walk_statement(&s.consequent, edits, stats, allow_void_undefined, false);
            if let Some(alt) = s.alternate.as_ref() {
                walk_statement(alt, edits, stats, allow_void_undefined, false);
            }
        }
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                walk_statement(inner, edits, stats, allow_void_undefined, false);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(test) = s.test.as_ref() {
                walk_expression(test, edits, stats, allow_void_undefined, false);
            }
            if let Some(update) = s.update.as_ref() {
                walk_expression(update, edits, stats, allow_void_undefined, false);
            }
            walk_statement(&s.body, edits, stats, allow_void_undefined, false);
        }
        Statement::WhileStatement(s) => {
            walk_expression(&s.test, edits, stats, allow_void_undefined, false);
            walk_statement(&s.body, edits, stats, allow_void_undefined, false);
        }
        Statement::DoWhileStatement(s) => {
            walk_expression(&s.test, edits, stats, allow_void_undefined, false);
            walk_statement(&s.body, edits, stats, allow_void_undefined, false);
        }
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                for (index, inner) in body.statements.iter().enumerate() {
                    walk_statement(inner, edits, stats, allow_void_undefined, index == 0);
                }
            }
        }
        Statement::SwitchStatement(s) => {
            walk_expression(&s.discriminant, edits, stats, allow_void_undefined, false);
            for case in &s.cases {
                if let Some(test) = case.test.as_ref() {
                    walk_expression(test, edits, stats, allow_void_undefined, false);
                }
                for inner in &case.consequent {
                    walk_statement(inner, edits, stats, allow_void_undefined, false);
                }
            }
        }
        _ => {}
    }
}

fn walk_expression(
    expr: &Expression<'_>,
    edits: &mut Vec<Edit>,
    stats: &mut LiteralNormalizeStats,
    allow_void_undefined: bool,
    directive_position: bool,
) {
    if let Expression::UnaryExpression(unary) = expr {
        if let Some(edit) = try_boolean_shorthand(unary) {
            edits.push(edit);
            stats.boolean_shorthands += 1;
            return;
        }
        if allow_void_undefined && let Some(edit) = try_void_undefined(unary) {
            edits.push(edit);
            stats.void_undefineds += 1;
            return;
        }
        walk_expression(&unary.argument, edits, stats, allow_void_undefined, false);
        return;
    }
    if let Expression::BinaryExpression(bin) = expr {
        if !directive_position && let Some(edit) = try_string_concat(expr) {
            edits.push(edit);
            stats.string_concat_folds += 1;
            return;
        }
        if let Some(edit) = try_numeric_fold(expr) {
            edits.push(edit);
            stats.numeric_folds += 1;
            return;
        }
        walk_expression(&bin.left, edits, stats, allow_void_undefined, false);
        walk_expression(&bin.right, edits, stats, allow_void_undefined, false);
        return;
    }
    match expr {
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, edits, stats, allow_void_undefined, false);
            walk_expression(&b.right, edits, stats, allow_void_undefined, false);
        }
        Expression::ParenthesizedExpression(p) => {
            walk_expression(&p.expression, edits, stats, allow_void_undefined, false);
        }
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, edits, stats, allow_void_undefined, false);
            walk_expression(&c.consequent, edits, stats, allow_void_undefined, false);
            walk_expression(&c.alternate, edits, stats, allow_void_undefined, false);
        }
        Expression::CallExpression(c) => {
            walk_expression(&c.callee, edits, stats, allow_void_undefined, false);
            for arg in &c.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, edits, stats, allow_void_undefined, false);
                }
            }
        }
        Expression::NewExpression(n) => {
            for arg in &n.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, edits, stats, allow_void_undefined, false);
                }
            }
        }
        Expression::AssignmentExpression(a) => {
            walk_expression(&a.right, edits, stats, allow_void_undefined, false);
        }
        Expression::SequenceExpression(s) => {
            for inner in &s.expressions {
                walk_expression(inner, edits, stats, allow_void_undefined, false);
            }
        }
        Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(inner) = el.as_expression() {
                    walk_expression(inner, edits, stats, allow_void_undefined, false);
                }
            }
        }
        Expression::TemplateLiteral(t) => {
            for inner in &t.expressions {
                walk_expression(inner, edits, stats, allow_void_undefined, false);
            }
        }
        _ => {}
    }
}

fn try_boolean_shorthand(unary: &UnaryExpression<'_>) -> Option<Edit> {
    if unary.operator != UnaryOperator::LogicalNot {
        return None;
    }
    let Expression::NumericLiteral(num): &Expression<'_> = &unary.argument else {
        return None;
    };
    let replacement: &str = if is_exact(num.value, 0.0) {
        "true"
    } else if is_exact(num.value, 1.0) {
        "false"
    } else {
        return None;
    };
    Some(Edit {
        start: unary.span.start as usize,
        end: unary.span.end as usize,
        replacement: replacement.to_owned(),
    })
}

fn try_void_undefined(unary: &UnaryExpression<'_>) -> Option<Edit> {
    if unary.operator != UnaryOperator::Void {
        return None;
    }
    if !is_side_effect_free(&unary.argument) {
        return None;
    }
    Some(Edit {
        start: unary.span.start as usize,
        end: unary.span.end as usize,
        replacement: "undefined".to_owned(),
    })
}

fn try_string_concat(expr: &Expression<'_>) -> Option<Edit> {
    let Expression::BinaryExpression(bin): &Expression<'_> = expr else {
        return None;
    };
    if bin.operator != BinaryOperator::Addition {
        return None;
    }
    let Expression::StringLiteral(left): &Expression<'_> = &bin.left else {
        return None;
    };
    let Expression::StringLiteral(right): &Expression<'_> = &bin.right else {
        return None;
    };
    let merged: String = format!("{}{}", left.value.as_str(), right.value.as_str());
    let rendered: String = render_string_literal(&merged);
    Some(Edit {
        start: bin.span.start as usize,
        end: bin.span.end as usize,
        replacement: rendered,
    })
}

fn try_numeric_fold(expr: &Expression<'_>) -> Option<Edit> {
    let Expression::BinaryExpression(bin): &Expression<'_> = expr else {
        return None;
    };
    let left: f64 = integer_literal(&bin.left)?;
    let right: f64 = integer_literal(&bin.right)?;
    let folded: f64 = match bin.operator {
        BinaryOperator::Addition => left + right,
        BinaryOperator::Subtraction => left - right,
        BinaryOperator::Multiplication => left * right,
        BinaryOperator::Division => {
            if right == 0.0 {
                return None;
            }
            left / right
        }
        _ => return None,
    };
    if !folded.is_finite() || folded.fract() != 0.0 {
        return None;
    }
    if folded.abs() > 9_007_199_254_740_992.0 {
        return None;
    }
    let rendered: String = if folded == 0.0 && folded.is_sign_negative() {
        "-0".to_owned()
    } else {
        format!("{}", folded as i64)
    };
    Some(Edit {
        start: bin.span.start as usize,
        end: bin.span.end as usize,
        replacement: rendered,
    })
}

fn integer_literal(expr: &Expression<'_>) -> Option<f64> {
    match expr {
        Expression::NumericLiteral(num)
            if matches!(num.base, NumberBase::Decimal | NumberBase::Hex)
                && num.value.fract() == 0.0 =>
        {
            Some(num.value)
        }
        Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::UnaryNegation => {
            integer_literal(&unary.argument).map(|v: f64| -v)
        }
        _ => None,
    }
}

const fn is_side_effect_free(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::BigIntLiteral(_)
    )
}

const fn is_exact(value: f64, target: f64) -> bool {
    value.to_bits() == target.to_bits()
}

fn render_string_literal(value: &str) -> String {
    let mut out: String = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

fn apply_local_edits(source: &str, edits: &[Edit]) -> Option<String> {
    super::splice_edits(source, edits)
}

fn reparses(source: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}
