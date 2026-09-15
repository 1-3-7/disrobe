use oxc_allocator::Allocator;
use oxc_ast::ast::{
    CallExpression, Expression, ObjectExpression, ObjectPropertyKind, Program, PropertyKey,
    PropertyKind, Statement,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct JsxAutomaticStats {
    pub(super) elements_restored: usize,
    pub(super) fragments_restored: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, JsxAutomaticStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.jsx").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), JsxAutomaticStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: JsxAutomaticStats = JsxAutomaticStats::default();
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
    stats: &mut JsxAutomaticStats,
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
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
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
    stats: &mut JsxAutomaticStats,
) {
    if let Expression::CallExpression(call) = expr
        && is_jsx_runtime_call(call)
        && let Some(jsx) = render_call(call, source, stats)
    {
        edits.push(Edit {
            start: call.span.start as usize,
            end: call.span.end as usize,
            replacement: jsx,
        });
        return;
    }
    match expr {
        Expression::ParenthesizedExpression(p) => {
            walk_expression(&p.expression, source, edits, stats);
        }
        Expression::ArrowFunctionExpression(a) => {
            for inner in &a.body.statements {
                walk_statement(inner, source, edits, stats);
            }
        }
        Expression::FunctionExpression(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, source, edits, stats);
                }
            }
        }
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, source, edits, stats);
            walk_expression(&c.consequent, source, edits, stats);
            walk_expression(&c.alternate, source, edits, stats);
        }
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, source, edits, stats);
            walk_expression(&b.right, source, edits, stats);
        }
        Expression::CallExpression(c) => {
            for arg in &c.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, source, edits, stats);
                }
            }
        }
        Expression::AssignmentExpression(a) => walk_expression(&a.right, source, edits, stats),
        _ => {}
    }
}

fn is_jsx_runtime_call(call: &CallExpression<'_>) -> bool {
    match &call.callee {
        Expression::Identifier(id) => is_jsx_name(id.name.as_str()),
        Expression::StaticMemberExpression(sm) => is_jsx_name(sm.property.name.as_str()),
        _ => false,
    }
}

fn is_jsx_name(name: &str) -> bool {
    matches!(
        name,
        "_jsx" | "_jsxs" | "_jsxDEV" | "jsx" | "jsxs" | "jsxDEV"
    )
}

fn render_call(
    call: &CallExpression<'_>,
    source: &str,
    stats: &mut JsxAutomaticStats,
) -> Option<String> {
    if call.arguments.len() < 2 {
        return None;
    }
    let type_arg: &Expression<'_> = call.arguments[0].as_expression()?;
    let props_arg: &Expression<'_> = call.arguments[1].as_expression()?;
    let Expression::ObjectExpression(props): &Expression<'_> = props_arg else {
        return None;
    };

    let tag: Tag = classify_tag(type_arg, source)?;
    let (attrs, children_expr): (Vec<String>, Option<&Expression<'_>>) =
        split_props(props, source)?;

    let mut children: Vec<String> = Vec::new();
    if let Some(child_expr) = children_expr {
        collect_children(child_expr, source, stats, &mut children)?;
    }

    let rendered: String = match tag {
        Tag::Fragment => {
            if !attrs.is_empty() {
                return None;
            }
            stats.fragments_restored += 1;
            let inner: String = children.concat();
            format!("<>{inner}</>")
        }
        Tag::Named(name) => {
            stats.elements_restored += 1;
            let attr_text: String = if attrs.is_empty() {
                String::new()
            } else {
                format!(" {}", attrs.join(" "))
            };
            if children.is_empty() {
                format!("<{name}{attr_text} />")
            } else {
                let inner: String = children.concat();
                format!("<{name}{attr_text}>{inner}</{name}>")
            }
        }
    };
    Some(rendered)
}

enum Tag {
    Named(String),
    Fragment,
}

fn classify_tag(expr: &Expression<'_>, source: &str) -> Option<Tag> {
    match expr {
        Expression::StringLiteral(s) => {
            let name: &str = s.value.as_str();
            if is_html_tag_name(name) {
                Some(Tag::Named(name.to_owned()))
            } else {
                None
            }
        }
        Expression::Identifier(id) => {
            let name: &str = id.name.as_str();
            if name == "Fragment" || name == "_Fragment" {
                Some(Tag::Fragment)
            } else if is_component_name(name) {
                Some(Tag::Named(name.to_owned()))
            } else {
                None
            }
        }
        Expression::StaticMemberExpression(sm) => {
            if sm.property.name.as_str() == "Fragment" {
                return Some(Tag::Fragment);
            }
            let text: &str = sm.span.source_text(source);
            if is_member_component(text) {
                Some(Tag::Named(text.to_owned()))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn split_props<'a>(
    props: &'a ObjectExpression<'a>,
    source: &str,
) -> Option<(Vec<String>, Option<&'a Expression<'a>>)> {
    let mut attrs: Vec<String> = Vec::new();
    let mut children: Option<&Expression<'_>> = None;
    for prop in &props.properties {
        match prop {
            ObjectPropertyKind::ObjectProperty(p) => {
                if p.kind != PropertyKind::Init || p.computed || p.method {
                    return None;
                }
                let PropertyKey::StaticIdentifier(key_id) = &p.key else {
                    return None;
                };
                let key: &str = key_id.name.as_str();
                if key == "children" {
                    children = Some(&p.value);
                    continue;
                }
                if !is_jsx_attr_name(key) {
                    return None;
                }
                attrs.push(render_attr(key, &p.value, source));
            }
            ObjectPropertyKind::SpreadProperty(s) => {
                let inner: &str = s.argument.span().source_text(source);
                attrs.push(format!("{{...{inner}}}"));
            }
        }
    }
    Some((attrs, children))
}

fn render_attr(key: &str, value: &Expression<'_>, source: &str) -> String {
    match value {
        Expression::StringLiteral(s) => {
            let raw: &str = s.value.as_str();
            if raw.contains('"') {
                format!("{key}={{{}}}", s.span.source_text(source))
            } else {
                format!("{key}=\"{raw}\"")
            }
        }
        Expression::BooleanLiteral(b) if b.value => key.to_owned(),
        _ => {
            let text: &str = value.span().source_text(source);
            format!("{key}={{{text}}}")
        }
    }
}

fn collect_children(
    expr: &Expression<'_>,
    source: &str,
    stats: &mut JsxAutomaticStats,
    out: &mut Vec<String>,
) -> Option<()> {
    if let Expression::ArrayExpression(arr) = expr {
        for el in &arr.elements {
            let child: &Expression<'_> = el.as_expression()?;
            out.push(render_child(child, source, stats)?);
        }
        return Some(());
    }
    out.push(render_child(expr, source, stats)?);
    Some(())
}

fn render_child(
    expr: &Expression<'_>,
    source: &str,
    stats: &mut JsxAutomaticStats,
) -> Option<String> {
    if let Expression::CallExpression(call) = expr
        && is_jsx_runtime_call(call)
    {
        return render_call(call, source, stats);
    }
    if let Expression::StringLiteral(s) = expr {
        return Some(render_text_child(
            s.value.as_str(),
            s.span.source_text(source),
        ));
    }
    let text: &str = expr.span().source_text(source);
    Some(format!("{{{text}}}"))
}

fn render_text_child(value: &str, raw_literal: &str) -> String {
    let safe: bool = !value.is_empty()
        && !value.contains(['{', '}', '<', '>'])
        && value.trim() == value
        && !value.contains('\n');
    if safe {
        value.to_owned()
    } else {
        format!("{{{raw_literal}}}")
    }
}

fn is_html_tag_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '-')
}

fn is_component_name(name: &str) -> bool {
    name.chars().next().is_some_and(char::is_uppercase)
        && name
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn is_member_component(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '$')
        && !text.contains("..")
}

fn is_jsx_attr_name(name: &str) -> bool {
    let mut chars: std::str::Chars<'_> = name.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}
