use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Expression, Function, ObjectProperty, ObjectPropertyKind, Program, PropertyKey, PropertyKind,
    Statement,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct ObjectShorthandStats {
    pub(super) value_shorthands: usize,
    pub(super) method_shorthands: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ObjectShorthandStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), ObjectShorthandStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: ObjectShorthandStats = ObjectShorthandStats::default();
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
    stats: &mut ObjectShorthandStats,
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
    stats: &mut ObjectShorthandStats,
) {
    match expr {
        Expression::ObjectExpression(obj) => {
            for prop in &obj.properties {
                match prop {
                    ObjectPropertyKind::ObjectProperty(p) => {
                        if let Some(edit) = try_shorthand(p, source, stats) {
                            edits.push(edit);
                        }
                        walk_expression(&p.value, source, edits, stats);
                    }
                    ObjectPropertyKind::SpreadProperty(s) => {
                        walk_expression(&s.argument, source, edits, stats);
                    }
                }
            }
        }
        Expression::ArrayExpression(arr) => {
            for el in &arr.elements {
                if let Some(inner) = el.as_expression() {
                    walk_expression(inner, source, edits, stats);
                }
            }
        }
        Expression::ParenthesizedExpression(p) => {
            walk_expression(&p.expression, source, edits, stats);
        }
        Expression::CallExpression(c) => {
            for arg in &c.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, source, edits, stats);
                }
            }
        }
        Expression::AssignmentExpression(a) => walk_expression(&a.right, source, edits, stats),
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, source, edits, stats);
            walk_expression(&c.consequent, source, edits, stats);
            walk_expression(&c.alternate, source, edits, stats);
        }
        Expression::SequenceExpression(s) => {
            for inner in &s.expressions {
                walk_expression(inner, source, edits, stats);
            }
        }
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, source, edits, stats);
            walk_expression(&b.right, source, edits, stats);
        }
        Expression::BinaryExpression(b) => {
            walk_expression(&b.left, source, edits, stats);
            walk_expression(&b.right, source, edits, stats);
        }
        _ => {}
    }
}

fn try_shorthand(
    prop: &ObjectProperty<'_>,
    source: &str,
    stats: &mut ObjectShorthandStats,
) -> Option<Edit> {
    if prop.kind != PropertyKind::Init || prop.computed || prop.shorthand || prop.method {
        return None;
    }
    let key_name: &str = static_key_name(&prop.key)?;

    if let Expression::Identifier(id) = &prop.value {
        if id.name.as_str() == key_name {
            stats.value_shorthands += 1;
            return Some(Edit {
                start: prop.span.start as usize,
                end: prop.span.end as usize,
                replacement: key_name.to_owned(),
            });
        }
        return None;
    }

    if let Expression::FunctionExpression(func) = &prop.value {
        return method_shorthand(prop, func, key_name, source, stats);
    }

    None
}

fn method_shorthand(
    prop: &ObjectProperty<'_>,
    func: &Function<'_>,
    key_name: &str,
    source: &str,
    stats: &mut ObjectShorthandStats,
) -> Option<Edit> {
    if func.id.is_some() {
        return None;
    }
    let body: &oxc_ast::ast::FunctionBody<'_> = func.body.as_ref()?;
    let params_text: &str = func.params.span().source_text(source);
    let body_text: &str = body.span().source_text(source);

    let mut prefix: String = String::new();
    if func.r#async {
        prefix.push_str("async ");
    }
    if func.generator {
        prefix.push('*');
    }

    let replacement: String = format!("{prefix}{key_name}{params_text} {body_text}");
    stats.method_shorthands += 1;
    Some(Edit {
        start: prop.span.start as usize,
        end: prop.span.end as usize,
        replacement,
    })
}

fn static_key_name<'a>(key: &'a PropertyKey<'a>) -> Option<&'a str> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.as_str()),
        _ => None,
    }
}
