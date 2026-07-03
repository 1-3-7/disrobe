use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, CallExpression, Expression, MemberExpression, Program, Statement};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct ArgumentSpreadStats {
    pub(super) apply_calls_spread: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ArgumentSpreadStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), ArgumentSpreadStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: ArgumentSpreadStats = ArgumentSpreadStats::default();
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
    stats: &mut ArgumentSpreadStats,
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
    stats: &mut ArgumentSpreadStats,
) {
    if let Expression::CallExpression(call) = expr
        && let Some(edit) = try_apply_spread(call, source)
    {
        edits.push(edit);
        stats.apply_calls_spread += 1;
        return;
    }
    match expr {
        Expression::CallExpression(c) => {
            walk_expression(&c.callee, source, edits, stats);
            for arg in &c.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, source, edits, stats);
                }
            }
        }
        Expression::ParenthesizedExpression(p) => {
            walk_expression(&p.expression, source, edits, stats);
        }
        Expression::BinaryExpression(b) => {
            walk_expression(&b.left, source, edits, stats);
            walk_expression(&b.right, source, edits, stats);
        }
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, source, edits, stats);
            walk_expression(&b.right, source, edits, stats);
        }
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, source, edits, stats);
            walk_expression(&c.consequent, source, edits, stats);
            walk_expression(&c.alternate, source, edits, stats);
        }
        Expression::AssignmentExpression(a) => walk_expression(&a.right, source, edits, stats),
        Expression::SequenceExpression(s) => {
            for inner in &s.expressions {
                walk_expression(inner, source, edits, stats);
            }
        }
        Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(inner) = el.as_expression() {
                    walk_expression(inner, source, edits, stats);
                }
            }
        }
        Expression::ObjectExpression(obj) => {
            for prop in &obj.properties {
                if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop {
                    walk_expression(&p.value, source, edits, stats);
                }
            }
        }
        Expression::FunctionExpression(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, source, edits, stats);
                }
            }
        }
        Expression::ArrowFunctionExpression(a) => {
            for inner in &a.body.statements {
                walk_statement(inner, source, edits, stats);
            }
        }
        _ => {}
    }
}

fn try_apply_spread(call: &CallExpression<'_>, source: &str) -> Option<Edit> {
    let member: &MemberExpression<'_> = call.callee.as_member_expression()?;
    let MemberExpression::StaticMemberExpression(sm) = member else {
        return None;
    };
    if sm.property.name.as_str() != "apply" {
        return None;
    }
    if call.arguments.len() != 2 {
        return None;
    }
    let this_arg: &Expression<'_> = call.arguments[0].as_expression()?;
    if !is_nullish(this_arg) {
        return None;
    }
    let Argument::SpreadElement(_) = &call.arguments[1] else {
        let arr_arg: &Expression<'_> = call.arguments[1].as_expression()?;
        if !is_safe_args_source(arr_arg) {
            return None;
        }
        let fn_src: &str = sm.object.span().source_text(source);
        if !is_plain_callee(&sm.object) {
            return None;
        }
        let arr_src: &str = arr_arg.span().source_text(source);
        return Some(Edit {
            start: call.span.start as usize,
            end: call.span.end as usize,
            replacement: format!("{fn_src}(...{arr_src})"),
        });
    };
    None
}

fn is_nullish(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(id) => id.name.as_str() == "undefined",
        Expression::UnaryExpression(u) => {
            u.operator == oxc_ast::ast::UnaryOperator::Void
                && matches!(
                    &u.argument,
                    Expression::NumericLiteral(_) | Expression::StringLiteral(_)
                )
        }
        _ => false,
    }
}

const fn is_plain_callee(expr: &Expression<'_>) -> bool {
    matches!(expr, Expression::Identifier(_))
}

const fn is_safe_args_source(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::Identifier(_)
            | Expression::ArrayExpression(_)
            | Expression::StaticMemberExpression(_)
            | Expression::ComputedMemberExpression(_)
            | Expression::CallExpression(_)
    )
}
