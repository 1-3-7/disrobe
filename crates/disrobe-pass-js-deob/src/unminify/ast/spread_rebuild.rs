use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, Expression, MemberExpression, ObjectPropertyKind, Program, Statement,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::babel_materializer::MaterializerFacts;
use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct SpreadRebuildStats {
    pub(super) array_spreads: usize,
    pub(super) object_spreads: usize,
    pub(super) array_destructures: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, SpreadRebuildStats) {
    let mut stats: SpreadRebuildStats = SpreadRebuildStats::default();
    let mut current: String = source.to_owned();

    while let Some((next, fired)) = single_pass(&current) {
        if next == current || !reparses(&next) {
            break;
        }
        current = next;
        stats.array_spreads += fired.array_spreads;
        stats.object_spreads += fired.object_spreads;
        stats.array_destructures += fired.array_destructures;
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

fn single_pass(source: &str) -> Option<(String, SpreadRebuildStats)> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return None;
    }
    let program: &Program<'_> = &parsed.program;

    let facts: MaterializerFacts = MaterializerFacts::collect(source, program);
    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: SpreadRebuildStats = SpreadRebuildStats::default();

    for stmt in &program.body {
        walk_statement(stmt, source, &facts, &mut edits, &mut stats);
    }

    if edits.is_empty() {
        return None;
    }
    let next: String = apply_local_edits(source, &edits)?;
    Some((next, stats))
}

fn walk_statement(
    stmt: &Statement<'_>,
    source: &str,
    facts: &MaterializerFacts,
    edits: &mut Vec<Edit>,
    stats: &mut SpreadRebuildStats,
) {
    if let Statement::VariableDeclaration(decl) = stmt {
        if let Some(edit) = try_sliced_to_array(decl, source, stats) {
            edits.push(edit);
            return;
        }
        for declarator in &decl.declarations {
            if let Some(init) = declarator.init.as_ref() {
                walk_expression(init, source, facts, edits, stats);
            }
        }
        return;
    }
    match stmt {
        Statement::ExpressionStatement(s) => {
            walk_expression(&s.expression, source, facts, edits, stats);
        }
        Statement::ReturnStatement(s) => {
            if let Some(arg) = s.argument.as_ref() {
                walk_expression(arg, source, facts, edits, stats);
            }
        }
        Statement::IfStatement(s) => {
            walk_expression(&s.test, source, facts, edits, stats);
            walk_statement(&s.consequent, source, facts, edits, stats);
            if let Some(alt) = s.alternate.as_ref() {
                walk_statement(alt, source, facts, edits, stats);
            }
        }
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                walk_statement(inner, source, facts, edits, stats);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(test) = s.test.as_ref() {
                walk_expression(test, source, facts, edits, stats);
            }
            walk_statement(&s.body, source, facts, edits, stats);
        }
        Statement::WhileStatement(s) => {
            walk_expression(&s.test, source, facts, edits, stats);
            walk_statement(&s.body, source, facts, edits, stats);
        }
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, source, facts, edits, stats);
                }
            }
        }
        Statement::ThrowStatement(s) => walk_expression(&s.argument, source, facts, edits, stats),
        Statement::SwitchStatement(s) => {
            walk_expression(&s.discriminant, source, facts, edits, stats);
            for case in &s.cases {
                for inner in &case.consequent {
                    walk_statement(inner, source, facts, edits, stats);
                }
            }
        }
        _ => {}
    }
}

fn walk_expression(
    expr: &Expression<'_>,
    source: &str,
    facts: &MaterializerFacts,
    edits: &mut Vec<Edit>,
    stats: &mut SpreadRebuildStats,
) {
    if let Some(edit) = try_array_spread(expr, source, facts, stats) {
        edits.push(edit);
        return;
    }
    if let Some(edit) = try_object_spread(expr, source, stats) {
        edits.push(edit);
        return;
    }
    match expr {
        Expression::CallExpression(c) => {
            walk_expression(&c.callee, source, facts, edits, stats);
            for arg in &c.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, source, facts, edits, stats);
                }
            }
        }
        Expression::BinaryExpression(b) => {
            walk_expression(&b.left, source, facts, edits, stats);
            walk_expression(&b.right, source, facts, edits, stats);
        }
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, source, facts, edits, stats);
            walk_expression(&b.right, source, facts, edits, stats);
        }
        Expression::ParenthesizedExpression(p) => {
            walk_expression(&p.expression, source, facts, edits, stats);
        }
        Expression::UnaryExpression(u) => walk_expression(&u.argument, source, facts, edits, stats),
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, source, facts, edits, stats);
            walk_expression(&c.consequent, source, facts, edits, stats);
            walk_expression(&c.alternate, source, facts, edits, stats);
        }
        Expression::AssignmentExpression(a) => {
            walk_expression(&a.right, source, facts, edits, stats);
        }
        Expression::SequenceExpression(s) => {
            for inner in &s.expressions {
                walk_expression(inner, source, facts, edits, stats);
            }
        }
        Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(inner) = el.as_expression() {
                    walk_expression(inner, source, facts, edits, stats);
                }
            }
        }
        Expression::ObjectExpression(o) => {
            for prop in &o.properties {
                if let ObjectPropertyKind::ObjectProperty(p) = prop {
                    walk_expression(&p.value, source, facts, edits, stats);
                }
            }
        }
        _ => {}
    }
}

fn try_array_spread(
    expr: &Expression<'_>,
    source: &str,
    facts: &MaterializerFacts,
    stats: &mut SpreadRebuildStats,
) -> Option<Edit> {
    let Expression::CallExpression(call): &Expression<'_> = expr else {
        return None;
    };
    let helper_name: bool = call_callee_name(&call.callee).is_some_and(|name: &str| {
        matches!(name, "_toConsumableArray" | "_spread") && facts.is_verified(name)
    });
    if helper_name && call.arguments.len() == 1 && !facts.encloses(call.span.start) {
        let arg: &Expression<'_> = call.arguments[0].as_expression()?;
        let arg_src: &str = arg.span().source_text(source);
        stats.array_spreads += 1;
        return Some(Edit {
            start: call.span.start as usize,
            end: call.span.end as usize,
            replacement: format!("[...{arg_src}]"),
        });
    }
    try_concat_spread(call, source, stats)
}

fn try_concat_spread(
    call: &oxc_ast::ast::CallExpression<'_>,
    source: &str,
    stats: &mut SpreadRebuildStats,
) -> Option<Edit> {
    let member: &MemberExpression<'_> = call.callee.as_member_expression()?;
    let MemberExpression::StaticMemberExpression(sm): &MemberExpression<'_> = member else {
        return None;
    };
    if sm.property.name.as_str() != "concat" {
        return None;
    }
    let Expression::ArrayExpression(base): &Expression<'_> = &sm.object else {
        return None;
    };
    if !base.elements.is_empty() {
        return None;
    }
    if call.arguments.is_empty() {
        return None;
    }
    for arg in &call.arguments {
        if argument_is_array_helper(arg) {
            return None;
        }
    }
    let mut parts: Vec<String> = Vec::with_capacity(call.arguments.len());
    for arg in &call.arguments {
        match arg {
            Argument::SpreadElement(spread) => {
                let inner_src: &str = spread.argument.span().source_text(source);
                parts.push(format!("...{inner_src}"));
            }
            Argument::ArrayExpression(inline) => {
                let body: &str = inline.span().source_text(source);
                let trimmed: &str = body.trim();
                let inner_body: &str = trimmed
                    .strip_prefix('[')
                    .and_then(|s: &str| s.strip_suffix(']'))?
                    .trim();
                if !inner_body.is_empty() {
                    parts.push(inner_body.to_owned());
                }
            }
            other => {
                let inner: &Expression<'_> = other.as_expression()?;
                let inner_src: &str = inner.span().source_text(source);
                parts.push(format!("...{inner_src}"));
            }
        }
    }
    if parts.is_empty() {
        return None;
    }
    stats.array_spreads += 1;
    Some(Edit {
        start: call.span.start as usize,
        end: call.span.end as usize,
        replacement: format!("[{}]", parts.join(", ")),
    })
}

fn argument_is_array_helper(arg: &Argument<'_>) -> bool {
    let Some(Expression::CallExpression(call)) = arg.as_expression().map(strip_paren) else {
        return false;
    };
    matches!(
        call_callee_name(&call.callee),
        Some("_toConsumableArray" | "_spread" | "_arrayWithoutHoles")
    )
}

fn strip_paren<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(p) => strip_paren(&p.expression),
        other => other,
    }
}

fn try_object_spread(
    expr: &Expression<'_>,
    source: &str,
    stats: &mut SpreadRebuildStats,
) -> Option<Edit> {
    let Expression::CallExpression(call): &Expression<'_> = expr else {
        return None;
    };
    let callee_name: &str = call_callee_name(&call.callee).or_else(|| object_assign_name(call))?;
    let is_assign: bool = callee_name == "Object.assign";
    if !is_assign && !matches!(callee_name, "_objectSpread" | "_objectSpread2" | "_extends") {
        return None;
    }
    if call.arguments.is_empty() {
        return None;
    }
    let first: &Expression<'_> = call.arguments[0].as_expression()?;
    let Expression::ObjectExpression(leading): &Expression<'_> = first else {
        return None;
    };
    if is_assign && !leading.properties.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = Vec::with_capacity(call.arguments.len());
    if let Some(body) = inline_object_body(first, source) {
        if !body.is_empty() {
            parts.push(body);
        }
    } else {
        return None;
    }
    for arg in call.arguments.iter().skip(1) {
        let inner: &Expression<'_> = arg.as_expression()?;
        if let Some(body) = inline_object_body(inner, source) {
            if !body.is_empty() {
                parts.push(body);
            }
        } else {
            let inner_src: &str = inner.span().source_text(source);
            parts.push(format!("...{inner_src}"));
        }
    }
    if parts.is_empty() {
        return None;
    }
    stats.object_spreads += 1;
    Some(Edit {
        start: call.span.start as usize,
        end: call.span.end as usize,
        replacement: format!("{{ {} }}", parts.join(", ")),
    })
}

fn inline_object_body(expr: &Expression<'_>, source: &str) -> Option<String> {
    let Expression::ObjectExpression(obj): &Expression<'_> = expr else {
        return None;
    };
    for prop in &obj.properties {
        if let ObjectPropertyKind::ObjectProperty(p) = prop
            && p.computed
        {
            return None;
        }
    }
    let body: &str = obj.span().source_text(source);
    let trimmed: &str = body.trim();
    let inner_body: &str = trimmed
        .strip_prefix('{')
        .and_then(|s: &str| s.strip_suffix('}'))?
        .trim();
    Some(inner_body.to_owned())
}

fn object_assign_name(call: &oxc_ast::ast::CallExpression<'_>) -> Option<&'static str> {
    let member: &MemberExpression<'_> = call.callee.as_member_expression()?;
    let MemberExpression::StaticMemberExpression(sm): &MemberExpression<'_> = member else {
        return None;
    };
    if sm.property.name.as_str() != "assign" {
        return None;
    }
    let Expression::Identifier(obj): &Expression<'_> = &sm.object else {
        return None;
    };
    if obj.name.as_str() == "Object" {
        Some("Object.assign")
    } else {
        None
    }
}

fn try_sliced_to_array(
    decl: &oxc_ast::ast::VariableDeclaration<'_>,
    source: &str,
    stats: &mut SpreadRebuildStats,
) -> Option<Edit> {
    if decl.declarations.len() < 2 {
        return None;
    }
    let head: &oxc_ast::ast::VariableDeclarator<'_> = &decl.declarations[0];
    let oxc_ast::ast::BindingPatternKind::BindingIdentifier(ref_binding) = &head.id.kind else {
        return None;
    };
    let ref_name: &str = ref_binding.name.as_str();
    let init: &Expression<'_> = head.init.as_ref()?;
    let Expression::CallExpression(call): &Expression<'_> = init else {
        return None;
    };
    let callee_name: &str = call_callee_name(&call.callee)?;
    if callee_name != "_slicedToArray" {
        return None;
    }
    if call.arguments.len() != 2 {
        return None;
    }
    let source_arg: &Expression<'_> = call.arguments.first().and_then(Argument::as_expression)?;
    if !is_simple_source(source_arg) {
        return None;
    }
    let count_arg: &Expression<'_> = call.arguments[1].as_expression()?;
    let Expression::NumericLiteral(count): &Expression<'_> = count_arg else {
        return None;
    };
    let n: usize = count.value as usize;
    if n == 0 || (count.value - n as f64).abs() > f64::EPSILON || n > 16 {
        return None;
    }
    if decl.declarations.len() != n + 1 {
        return None;
    }
    let mut names: Vec<String> = Vec::with_capacity(n);
    for (index, tail) in decl.declarations.iter().skip(1).enumerate() {
        let oxc_ast::ast::BindingPatternKind::BindingIdentifier(name_binding) = &tail.id.kind
        else {
            return None;
        };
        let read_index: usize = name_index_reads(tail.init.as_ref(), ref_name)?;
        if read_index != index {
            return None;
        }
        names.push(name_binding.name.as_str().to_owned());
    }
    let src_text: &str = source_arg.span().source_text(source);
    stats.array_destructures += 1;
    Some(Edit {
        start: head.id.span().start as usize,
        end: decl.declarations[decl.declarations.len() - 1].span().end as usize,
        replacement: format!("[{}] = {src_text}", names.join(", ")),
    })
}

fn name_index_reads(init: Option<&Expression<'_>>, ref_name: &str) -> Option<usize> {
    let Expression::ComputedMemberExpression(member): &Expression<'_> = init? else {
        return None;
    };
    let Expression::Identifier(obj): &Expression<'_> = &member.object else {
        return None;
    };
    if obj.name.as_str() != ref_name {
        return None;
    }
    let Expression::NumericLiteral(index): &Expression<'_> = &member.expression else {
        return None;
    };
    let value: usize = index.value as usize;
    if (index.value - value as f64).abs() > f64::EPSILON {
        return None;
    }
    Some(value)
}

const fn is_simple_source(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::Identifier(_)
            | Expression::ArrayExpression(_)
            | Expression::StaticMemberExpression(_)
            | Expression::ComputedMemberExpression(_)
    )
}

fn call_callee_name<'a>(callee: &'a Expression<'a>) -> Option<&'a str> {
    match callee {
        Expression::Identifier(id) => Some(id.name.as_str()),
        _ => None,
    }
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
