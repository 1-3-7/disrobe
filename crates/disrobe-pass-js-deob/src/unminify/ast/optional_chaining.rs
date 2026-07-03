use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BinaryExpression, BinaryOperator, ConditionalExpression, Expression, LogicalOperator, Program,
    Statement, UnaryOperator,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct OptionalChainingStats {
    pub(super) chains_rebuilt: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, OptionalChainingStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), OptionalChainingStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: OptionalChainingStats = OptionalChainingStats::default();
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
    stats: &mut OptionalChainingStats,
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
    stats: &mut OptionalChainingStats,
) {
    if let Expression::ConditionalExpression(cond) = expr
        && let Some(edit) = try_optional(cond, source)
    {
        edits.push(edit);
        stats.chains_rebuilt += 1;
        return;
    }
    match expr {
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, source, edits, stats);
            walk_expression(&c.consequent, source, edits, stats);
            walk_expression(&c.alternate, source, edits, stats);
        }
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

fn try_optional(cond: &ConditionalExpression<'_>, source: &str) -> Option<Edit> {
    let test: &Expression<'_> = unwrap_paren(&cond.test);
    let consequent: &Expression<'_> = unwrap_paren(&cond.consequent);
    let alternate: &Expression<'_> = unwrap_paren(&cond.alternate);

    let (checked_src, member_branch): (&str, &Expression<'_>) =
        if let Some(checked) = nullish_check(test, source) {
            if !is_undefined(consequent) {
                return None;
            }
            (checked, alternate)
        } else if let Some(checked) = non_nullish_check(test, source) {
            if !is_undefined(alternate) {
                return None;
            }
            (checked, consequent)
        } else {
            return None;
        };

    let access: Access<'_> = receiver_access(member_branch)?;
    if access.receiver_src(source) != checked_src {
        return None;
    }
    let rewritten: String = access.render_optional(source)?;
    Some(Edit {
        start: cond.span.start as usize,
        end: cond.span.end as usize,
        replacement: rewritten,
    })
}

enum Access<'a> {
    Static {
        object: &'a Expression<'a>,
        property: &'a str,
    },
    Computed {
        object: &'a Expression<'a>,
        index: &'a Expression<'a>,
    },
    Call {
        callee_member: &'a Expression<'a>,
        args_src_span: (usize, usize),
    },
}

impl<'a> Access<'a> {
    fn receiver_src(&self, source: &'a str) -> &'a str {
        match self {
            Access::Static { object, .. } | Access::Computed { object, .. } => {
                object.span().source_text(source)
            }
            Access::Call { callee_member, .. } => callee_member.span().source_text(source),
        }
    }

    fn render_optional(&self, source: &str) -> Option<String> {
        match self {
            Access::Static { object, property } => {
                let obj_src: &str = object.span().source_text(source);
                Some(format!("{obj_src}?.{property}"))
            }
            Access::Computed { object, index } => {
                let obj_src: &str = object.span().source_text(source);
                let idx_src: &str = index.span().source_text(source);
                Some(format!("{obj_src}?.[{idx_src}]"))
            }
            Access::Call {
                callee_member,
                args_src_span,
            } => {
                let callee_src: &str = callee_member.span().source_text(source);
                let args: &str = source.get(args_src_span.0..args_src_span.1)?;
                Some(format!("{callee_src}?.({args})"))
            }
        }
    }
}

fn receiver_access<'a>(expr: &'a Expression<'a>) -> Option<Access<'a>> {
    match expr {
        Expression::StaticMemberExpression(sm) => Some(Access::Static {
            object: &sm.object,
            property: sm.property.name.as_str(),
        }),
        Expression::ComputedMemberExpression(cm) => Some(Access::Computed {
            object: &cm.object,
            index: &cm.expression,
        }),
        Expression::CallExpression(call) => {
            if !call.callee.is_member_expression() {
                return None;
            }
            let open: usize = call.callee.span().end as usize;
            let close: usize = call.span.end as usize;
            Some(Access::Call {
                callee_member: &call.callee,
                args_src_span: (open, close),
            })
        }
        _ => None,
    }
}

fn nullish_check<'a>(test: &'a Expression<'a>, source: &'a str) -> Option<&'a str> {
    if let Expression::BinaryExpression(bin) = test
        && bin.operator == BinaryOperator::Equality
    {
        return null_operand(bin, source);
    }
    let Expression::LogicalExpression(logical): &Expression<'_> = test else {
        return None;
    };
    if logical.operator != LogicalOperator::Or {
        return None;
    }
    let left: &str = strict_eq(&logical.left, source, NullKind::Null)?;
    let right: &str = strict_eq(&logical.right, source, NullKind::Undefined)?;
    if left == right { Some(left) } else { None }
}

fn non_nullish_check<'a>(test: &'a Expression<'a>, source: &'a str) -> Option<&'a str> {
    if let Expression::BinaryExpression(bin) = test
        && bin.operator == BinaryOperator::Inequality
    {
        return null_operand(bin, source);
    }
    let Expression::LogicalExpression(logical): &Expression<'_> = test else {
        return None;
    };
    if logical.operator != LogicalOperator::And {
        return None;
    }
    let left: &str = strict_neq(&logical.left, source, NullKind::Null)?;
    let right: &str = strict_neq(&logical.right, source, NullKind::Undefined)?;
    if left == right { Some(left) } else { None }
}

fn null_operand<'a>(bin: &'a BinaryExpression<'a>, source: &'a str) -> Option<&'a str> {
    if is_null_literal(&bin.right) && is_pure_reference(&bin.left) {
        return Some(bin.left.span().source_text(source));
    }
    if is_null_literal(&bin.left) && is_pure_reference(&bin.right) {
        return Some(bin.right.span().source_text(source));
    }
    None
}

enum NullKind {
    Null,
    Undefined,
}

fn strict_eq<'a>(expr: &'a Expression<'a>, source: &'a str, kind: NullKind) -> Option<&'a str> {
    strict_cmp(expr, source, BinaryOperator::StrictEquality, kind)
}

fn strict_neq<'a>(expr: &'a Expression<'a>, source: &'a str, kind: NullKind) -> Option<&'a str> {
    strict_cmp(expr, source, BinaryOperator::StrictInequality, kind)
}

fn strict_cmp<'a>(
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
            NullKind::Undefined => is_undefined(e),
        }
    };
    if matches_kind(&bin.right) && is_pure_reference(&bin.left) {
        return Some(bin.left.span().source_text(source));
    }
    if matches_kind(&bin.left) && is_pure_reference(&bin.right) {
        return Some(bin.right.span().source_text(source));
    }
    None
}

const fn is_null_literal(expr: &Expression<'_>) -> bool {
    matches!(expr, Expression::NullLiteral(_))
}

fn is_undefined(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::Identifier(id) => id.name.as_str() == "undefined",
        Expression::UnaryExpression(u) => {
            u.operator == UnaryOperator::Void
                && matches!(
                    &u.argument,
                    Expression::NumericLiteral(_) | Expression::StringLiteral(_)
                )
        }
        _ => false,
    }
}

const fn is_pure_reference(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::Identifier(_) | Expression::StaticMemberExpression(_)
    )
}

fn unwrap_paren<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(p) => unwrap_paren(&p.expression),
        other => other,
    }
}
