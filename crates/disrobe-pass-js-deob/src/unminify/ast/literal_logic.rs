use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentOperator, BinaryExpression, BinaryOperator, Expression, Program, Statement,
    UnaryOperator,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct LiteralLogicStats {
    pub(super) infinity_folds: usize,
    pub(super) typeof_undefined: usize,
    pub(super) yoda_flips: usize,
    pub(super) json_parse_folds: usize,
    pub(super) object_merges: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, LiteralLogicStats) {
    let mut stats: LiteralLogicStats = LiteralLogicStats::default();
    let mut current: String = source.to_owned();

    while let Some((next, fired)) = single_pass(&current) {
        if next == current || !reparses(&next) {
            break;
        }
        current = next;
        stats.infinity_folds += fired.infinity_folds;
        stats.typeof_undefined += fired.typeof_undefined;
        stats.yoda_flips += fired.yoda_flips;
        stats.json_parse_folds += fired.json_parse_folds;
        stats.object_merges += fired.object_merges;
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

fn single_pass(source: &str) -> Option<(String, LiteralLogicStats)> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return None;
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: LiteralLogicStats = LiteralLogicStats::default();

    collect_expression_edits(program, source, &mut edits, &mut stats);
    if edits.is_empty() {
        collect_object_merge_edits(program.body.as_slice(), source, &mut edits, &mut stats);
    }

    if edits.is_empty() {
        return None;
    }
    let next: String = apply_local_edits(source, &edits)?;
    Some((next, stats))
}

fn collect_expression_edits(
    program: &Program<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut LiteralLogicStats,
) {
    for stmt in &program.body {
        walk_statement(stmt, source, edits, stats);
    }
}

fn walk_statement(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut LiteralLogicStats,
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
    stats: &mut LiteralLogicStats,
) {
    if let Some(edit) = try_infinity(expr) {
        edits.push(edit);
        stats.infinity_folds += 1;
        return;
    }
    if let Some(edit) = try_json_parse(expr) {
        edits.push(edit);
        stats.json_parse_folds += 1;
        return;
    }
    if let Expression::BinaryExpression(bin) = expr {
        if let Some(edit) = try_typeof_undefined(bin, source) {
            edits.push(edit);
            stats.typeof_undefined += 1;
            return;
        }
        if let Some(edit) = try_yoda(bin, source) {
            edits.push(edit);
            stats.yoda_flips += 1;
            return;
        }
        walk_expression(&bin.left, source, edits, stats);
        walk_expression(&bin.right, source, edits, stats);
        return;
    }
    match expr {
        Expression::LogicalExpression(b) => {
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

fn try_infinity(expr: &Expression<'_>) -> Option<Edit> {
    let Expression::BinaryExpression(bin): &Expression<'_> = expr else {
        return None;
    };
    if bin.operator != BinaryOperator::Division {
        return None;
    }
    if !is_numeric_zero(&bin.right) {
        return None;
    }
    if numeric_one_value(&bin.left) == Some(false) {
        return Some(Edit {
            start: bin.span.start as usize,
            end: bin.span.end as usize,
            replacement: "Infinity".to_owned(),
        });
    }
    if numeric_one_value(&bin.left) == Some(true) {
        return Some(Edit {
            start: bin.span.start as usize,
            end: bin.span.end as usize,
            replacement: "-Infinity".to_owned(),
        });
    }
    None
}

const fn is_exact(value: f64, target: f64) -> bool {
    value.to_bits() == target.to_bits()
}

fn numeric_one_value(expr: &Expression<'_>) -> Option<bool> {
    match expr {
        Expression::NumericLiteral(n) if is_exact(n.value, 1.0) => Some(false),
        Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
            match &u.argument {
                Expression::NumericLiteral(n) if is_exact(n.value, 1.0) => Some(true),
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_numeric_zero(expr: &Expression<'_>) -> bool {
    matches!(expr, Expression::NumericLiteral(n) if is_exact(n.value, 0.0))
}

fn try_typeof_undefined(bin: &BinaryExpression<'_>, source: &str) -> Option<Edit> {
    if !matches!(
        bin.operator,
        BinaryOperator::Equality
            | BinaryOperator::StrictEquality
            | BinaryOperator::Inequality
            | BinaryOperator::StrictInequality
    ) {
        return None;
    }
    let negated: bool = matches!(
        bin.operator,
        BinaryOperator::Inequality | BinaryOperator::StrictInequality
    );
    let typeof_on_left: bool = is_typeof(&bin.left) && is_undefined_string(&bin.right);
    let typeof_on_right: bool = is_typeof(&bin.right) && is_undefined_string(&bin.left);
    let typeof_side: &Expression<'_> = if typeof_on_left {
        &bin.left
    } else if typeof_on_right {
        &bin.right
    } else {
        return None;
    };
    let typeof_src: &str = typeof_side.span().source_text(source);
    let canonical: &str = if negated { "!==" } else { "===" };
    let is_strict: bool = matches!(
        bin.operator,
        BinaryOperator::StrictEquality | BinaryOperator::StrictInequality
    );
    if typeof_on_left && is_strict {
        return None;
    }
    Some(Edit {
        start: bin.span.start as usize,
        end: bin.span.end as usize,
        replacement: format!("{typeof_src} {canonical} \"undefined\""),
    })
}

fn is_typeof(expr: &Expression<'_>) -> bool {
    matches!(expr, Expression::UnaryExpression(u) if u.operator == UnaryOperator::Typeof)
}

fn is_undefined_string(expr: &Expression<'_>) -> bool {
    matches!(expr, Expression::StringLiteral(s) if s.value.as_str() == "undefined")
}

fn try_yoda(bin: &BinaryExpression<'_>, source: &str) -> Option<Edit> {
    let op: &str = match bin.operator {
        BinaryOperator::Equality => "==",
        BinaryOperator::StrictEquality => "===",
        BinaryOperator::Inequality => "!=",
        BinaryOperator::StrictInequality => "!==",
        _ => return None,
    };
    if !is_simple_literal(&bin.left) {
        return None;
    }
    if is_simple_literal(&bin.right) {
        return None;
    }
    if is_typeof(&bin.right) && is_undefined_string(&bin.left) {
        return None;
    }
    let left_src: &str = bin.left.span().source_text(source);
    let right_src: &str = bin.right.span().source_text(source);
    Some(Edit {
        start: bin.span.start as usize,
        end: bin.span.end as usize,
        replacement: format!("{right_src} {op} {left_src}"),
    })
}

const fn is_simple_literal(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
    )
}

fn try_json_parse(expr: &Expression<'_>) -> Option<Edit> {
    let Expression::CallExpression(call): &Expression<'_> = expr else {
        return None;
    };
    let member: &oxc_ast::ast::MemberExpression<'_> = call.callee.as_member_expression()?;
    let oxc_ast::ast::MemberExpression::StaticMemberExpression(sm): &oxc_ast::ast::MemberExpression<'_> =
        member
    else {
        return None;
    };
    if sm.property.name.as_str() != "parse" {
        return None;
    }
    let Expression::Identifier(obj): &Expression<'_> = &sm.object else {
        return None;
    };
    if obj.name.as_str() != "JSON" {
        return None;
    }
    if call.arguments.len() != 1 {
        return None;
    }
    let Some(Expression::StringLiteral(arg)): Option<&Expression<'_>> =
        call.arguments[0].as_expression()
    else {
        return None;
    };
    let parsed: serde_json::Value = serde_json::from_str(arg.value.as_str()).ok()?;
    if !parsed.is_object() && !parsed.is_array() {
        return None;
    }
    let rendered: String = serde_json::to_string(&parsed).ok()?;
    let replacement: String = if parsed.is_object() {
        format!("({rendered})")
    } else {
        rendered
    };
    Some(Edit {
        start: call.span.start as usize,
        end: call.span.end as usize,
        replacement,
    })
}

fn collect_object_merge_edits(
    statements: &[Statement<'_>],
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut LiteralLogicStats,
) {
    let mut index: usize = 0;
    while index < statements.len() {
        let consumed: Option<usize> = try_merge_run(statements, index, source, edits, stats);
        if let Some(step) = consumed {
            index += step;
            continue;
        }
        index += 1;
    }
}

fn try_merge_run(
    statements: &[Statement<'_>],
    start: usize,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut LiteralLogicStats,
) -> Option<usize> {
    let Statement::VariableDeclaration(decl): &Statement<'_> = &statements[start] else {
        return None;
    };
    if decl.declarations.len() != 1 {
        return None;
    }
    let declarator: &oxc_ast::ast::VariableDeclarator<'_> = &decl.declarations[0];
    let oxc_ast::ast::BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return None;
    };
    let obj_name: &str = binding.name.as_str();
    let Some(Expression::ObjectExpression(empty)): Option<&Expression<'_>> =
        declarator.init.as_ref()
    else {
        return None;
    };
    if !empty.properties.is_empty() {
        return None;
    }

    let mut props: Vec<(String, String)> = Vec::new();
    let mut cursor: usize = start + 1;
    while cursor < statements.len() {
        let Some((key, value_src)): Option<(String, String)> =
            match_simple_assign(&statements[cursor], obj_name, source)
        else {
            break;
        };
        props.push((key, value_src));
        cursor += 1;
    }
    if props.is_empty() {
        return None;
    }

    let mut rendered: String = String::new();
    rendered.push_str(decl.kind.as_str());
    rendered.push(' ');
    rendered.push_str(obj_name);
    rendered.push_str(" = {");
    for (i, (key, value)) in props.iter().enumerate() {
        if i > 0 {
            rendered.push(',');
        }
        rendered.push(' ');
        rendered.push_str(key);
        rendered.push_str(": ");
        rendered.push_str(value);
    }
    rendered.push_str(" };");

    let replace_span: Span = Span::new(
        statements[start].span().start,
        statements[cursor - 1].span().end,
    );
    edits.push(Edit {
        start: replace_span.start as usize,
        end: replace_span.end as usize,
        replacement: rendered,
    });
    stats.object_merges += 1;
    Some(cursor - start)
}

fn match_simple_assign(
    stmt: &Statement<'_>,
    obj_name: &str,
    source: &str,
) -> Option<(String, String)> {
    let Statement::ExpressionStatement(expr_stmt): &Statement<'_> = stmt else {
        return None;
    };
    let Expression::AssignmentExpression(assign): &Expression<'_> = &expr_stmt.expression else {
        return None;
    };
    if assign.operator != AssignmentOperator::Assign {
        return None;
    }
    let oxc_ast::ast::AssignmentTarget::StaticMemberExpression(member) = &assign.left else {
        return None;
    };
    let Expression::Identifier(target): &Expression<'_> = &member.object else {
        return None;
    };
    if target.name.as_str() != obj_name {
        return None;
    }
    let key: &str = member.property.name.as_str();
    if !is_valid_identifier(key) {
        return None;
    }
    if expression_reads_identifier(&assign.right, obj_name) {
        return None;
    }
    let value_src: String = assign.right.span().source_text(source).to_owned();
    Some((key.to_owned(), value_src))
}

fn is_valid_identifier(name: &str) -> bool {
    let mut chars: std::str::Chars<'_> = name.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn expression_reads_identifier(expr: &Expression<'_>, name: &str) -> bool {
    match expr {
        Expression::Identifier(id) => id.name.as_str() == name,
        Expression::BinaryExpression(b) => {
            expression_reads_identifier(&b.left, name)
                || expression_reads_identifier(&b.right, name)
        }
        Expression::LogicalExpression(b) => {
            expression_reads_identifier(&b.left, name)
                || expression_reads_identifier(&b.right, name)
        }
        Expression::UnaryExpression(u) => expression_reads_identifier(&u.argument, name),
        Expression::ParenthesizedExpression(p) => expression_reads_identifier(&p.expression, name),
        Expression::ConditionalExpression(c) => {
            expression_reads_identifier(&c.test, name)
                || expression_reads_identifier(&c.consequent, name)
                || expression_reads_identifier(&c.alternate, name)
        }
        Expression::CallExpression(c) => {
            let callee_reads: bool = match &c.callee {
                Expression::Identifier(id) => id.name.as_str() == name,
                other => expression_reads_identifier(other, name),
            };
            callee_reads
                || c.arguments.iter().any(|arg| {
                    arg.as_expression()
                        .is_some_and(|inner| expression_reads_identifier(inner, name))
                })
        }
        Expression::StaticMemberExpression(m) => expression_reads_identifier(&m.object, name),
        Expression::ComputedMemberExpression(m) => {
            expression_reads_identifier(&m.object, name)
                || expression_reads_identifier(&m.expression, name)
        }
        Expression::ObjectExpression(o) => o.properties.iter().any(|prop| match prop {
            oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) => {
                expression_reads_identifier(&p.value, name)
            }
            oxc_ast::ast::ObjectPropertyKind::SpreadProperty(s) => {
                expression_reads_identifier(&s.argument, name)
            }
        }),
        Expression::ArrayExpression(a) => a.elements.iter().any(|el| {
            el.as_expression()
                .is_some_and(|inner| expression_reads_identifier(inner, name))
        }),
        _ => false,
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
