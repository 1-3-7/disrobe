use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Program, SequenceExpression, Statement};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct IndirectCallStats {
    pub(super) calls_simplified: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, IndirectCallStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), IndirectCallStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: IndirectCallStats = IndirectCallStats::default();
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
    stats: &mut IndirectCallStats,
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
    stats: &mut IndirectCallStats,
) {
    if let Expression::CallExpression(call) = expr
        && let Some(edit) = try_indirect(call, source)
    {
        edits.push(edit);
        stats.calls_simplified += 1;
        for arg in &call.arguments {
            if let Some(inner) = arg.as_expression() {
                walk_expression(inner, source, edits, stats);
            }
        }
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

fn try_indirect(call: &oxc_ast::ast::CallExpression<'_>, source: &str) -> Option<Edit> {
    let callee: &Expression<'_> = unwrap_paren(&call.callee);
    let Expression::SequenceExpression(seq): &Expression<'_> = callee else {
        return None;
    };
    let real_callee: &Expression<'_> = guard_zero_then_member(seq)?;
    let callee_src: &str = real_callee.span().source_text(source);
    let args_src: String = call_arguments_source(call, source)?;
    Some(Edit {
        start: call.span.start as usize,
        end: call.span.end as usize,
        replacement: format!("{callee_src}({args_src})"),
    })
}

fn guard_zero_then_member<'a>(seq: &'a SequenceExpression<'a>) -> Option<&'a Expression<'a>> {
    if seq.expressions.len() != 2 {
        return None;
    }
    let first: &Expression<'_> = &seq.expressions[0];
    let Expression::NumericLiteral(num): &Expression<'_> = first else {
        return None;
    };
    if num.value != 0.0 {
        return None;
    }
    let second: &Expression<'_> = &seq.expressions[1];
    match second {
        Expression::StaticMemberExpression(_) | Expression::ComputedMemberExpression(_) => {
            Some(second)
        }
        _ => None,
    }
}

fn call_arguments_source(call: &oxc_ast::ast::CallExpression<'_>, source: &str) -> Option<String> {
    let open: usize = call.callee.span().end as usize;
    let close: usize = call.span.end as usize;
    let slice: &str = source.get(open..close)?;
    let lparen: usize = slice.find('(')?;
    let inner_start: usize = open + lparen + 1;
    let inner_end: usize = close.checked_sub(1)?;
    let inner: &str = source.get(inner_start..inner_end)?;
    Some(inner.trim().to_owned())
}

fn unwrap_paren<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(p) => unwrap_paren(&p.expression),
        other => other,
    }
}
