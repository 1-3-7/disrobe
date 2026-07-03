use oxc_allocator::Allocator;
use oxc_ast::ast::{BinaryExpression, BinaryOperator, Expression, Program, Statement};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct TemplateLiteralStats {
    pub(super) chains_rebuilt: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, TemplateLiteralStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), TemplateLiteralStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: TemplateLiteralStats = TemplateLiteralStats::default();
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
    stats: &mut TemplateLiteralStats,
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
        Statement::ForInStatement(s) => {
            walk_expression(&s.right, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::ForOfStatement(s) => {
            walk_expression(&s.right, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::TryStatement(s) => {
            for inner in &s.block.body {
                walk_statement(inner, source, edits, stats);
            }
            if let Some(handler) = s.handler.as_ref() {
                for inner in &handler.body.body {
                    walk_statement(inner, source, edits, stats);
                }
            }
            if let Some(finalizer) = s.finalizer.as_ref() {
                for inner in &finalizer.body {
                    walk_statement(inner, source, edits, stats);
                }
            }
        }
        Statement::LabeledStatement(s) => walk_statement(&s.body, source, edits, stats),
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
    stats: &mut TemplateLiteralStats,
) {
    if let Expression::BinaryExpression(bin) = expr
        && bin.operator == BinaryOperator::Addition
        && let Some(edit) = try_template(bin, source)
    {
        edits.push(edit);
        stats.chains_rebuilt += 1;
        return;
    }
    match expr {
        Expression::BinaryExpression(b) => {
            walk_expression(&b.left, source, edits, stats);
            walk_expression(&b.right, source, edits, stats);
        }
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, source, edits, stats);
            walk_expression(&b.right, source, edits, stats);
        }
        Expression::ParenthesizedExpression(p) => {
            walk_expression(&p.expression, source, edits, stats);
        }
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

enum Part<'a> {
    Literal(&'a str),
    Interp(&'a Expression<'a>),
}

fn try_template<'a>(bin: &'a BinaryExpression<'a>, source: &str) -> Option<Edit> {
    let mut parts: Vec<Part<'a>> = Vec::new();
    flatten_addition(&bin.left, &mut parts);
    flatten_addition(&bin.right, &mut parts);
    let leftmost_is_string: bool = matches!(parts.first(), Some(Part::Literal(_)));
    if !leftmost_is_string {
        return None;
    }
    let has_interp: bool = parts
        .iter()
        .any(|p: &Part<'_>| matches!(p, Part::Interp(_)));
    if !has_interp {
        return None;
    }
    if parts
        .iter()
        .any(|p: &Part<'_>| matches!(p, Part::Interp(e) if !is_simple_interp(e)))
    {
        return None;
    }
    let body: String = render_template(&parts, source)?;
    Some(Edit {
        start: bin.span.start as usize,
        end: bin.span.end as usize,
        replacement: format!("`{body}`"),
    })
}

fn flatten_addition<'a>(expr: &'a Expression<'a>, out: &mut Vec<Part<'a>>) {
    if let Expression::BinaryExpression(bin) = expr
        && bin.operator == BinaryOperator::Addition
    {
        flatten_addition(&bin.left, out);
        flatten_addition(&bin.right, out);
        return;
    }
    if let Expression::StringLiteral(s) = expr {
        out.push(Part::Literal(s.value.as_str()));
        return;
    }
    if let Expression::ParenthesizedExpression(p) = expr {
        out.push(Part::Interp(&p.expression));
        return;
    }
    out.push(Part::Interp(expr));
}

const fn is_simple_interp(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::Identifier(_)
            | Expression::StaticMemberExpression(_)
            | Expression::ComputedMemberExpression(_)
            | Expression::CallExpression(_)
            | Expression::NumericLiteral(_)
            | Expression::ThisExpression(_)
    )
}

fn render_template(parts: &[Part<'_>], source: &str) -> Option<String> {
    let mut out: String = String::new();
    for part in parts {
        match part {
            Part::Literal(raw) => {
                for ch in raw.chars() {
                    match ch {
                        '`' => out.push_str("\\`"),
                        '\\' => out.push_str("\\\\"),
                        '$' => out.push_str("\\$"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        other => out.push(other),
                    }
                }
            }
            Part::Interp(expr) => {
                let text: &str = expr.span().source_text(source);
                if text.contains('`') {
                    return None;
                }
                out.push_str("${");
                out.push_str(text);
                out.push('}');
            }
        }
    }
    Some(out)
}
