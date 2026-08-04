use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BinaryOperator, ConditionalExpression, Expression, IdentifierReference, LogicalOperator,
    Program, Statement, UnaryOperator,
};
use oxc_parser::Parser;
use oxc_semantic::{Semantic, SemanticBuilder};
use oxc_span::{GetSpan, SourceType};

use super::{
    Edit, RuleOutcome, edit_overlaps_comments, repeated_checked_identifiers,
    same_repeatable_binding,
};

#[derive(Debug, Clone, Default)]
pub(super) struct OptionalChainingStats {
    pub(super) chains_rebuilt: usize,
}

#[derive(Clone, Copy)]
enum RecoveryMode {
    General,
    PresetEnv,
}

impl RecoveryMode {
    const fn requires_static_receiver(self) -> bool {
        matches!(self, Self::PresetEnv)
    }
}

pub(super) fn recover(source: &str) -> (RuleOutcome, OptionalChainingStats) {
    recover_with_mode(source, RecoveryMode::General)
}

pub(super) fn recover_preset_env(source: &str) -> (RuleOutcome, OptionalChainingStats) {
    recover_with_mode(source, RecoveryMode::PresetEnv)
}

fn recover_with_mode(source: &str, mode: RecoveryMode) -> (RuleOutcome, OptionalChainingStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = match SourceType::from_path("input.js") {
        Ok(value) => value,
        Err(_) => return (RuleOutcome::empty(), OptionalChainingStats::default()),
    };
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), OptionalChainingStats::default());
    }
    let program: &Program<'_> = &parsed.program;
    let semantic_return: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(program);
    if !semantic_return.errors.is_empty() {
        return (RuleOutcome::empty(), OptionalChainingStats::default());
    }
    let semantic: Semantic<'_> = semantic_return.semantic;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: OptionalChainingStats = OptionalChainingStats::default();
    for stmt in &program.body {
        walk_statement(stmt, source, &mut edits, &mut stats, mode, &semantic);
    }
    edits.retain(|edit: &Edit| !edit_overlaps_comments(edit, &program.comments));
    stats.chains_rebuilt = edits.len();

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
    mode: RecoveryMode,
    semantic: &Semantic<'_>,
) {
    match stmt {
        Statement::ExpressionStatement(s) => {
            walk_expression(&s.expression, source, edits, stats, mode, semantic);
        }
        Statement::ReturnStatement(s) => {
            if let Some(arg) = s.argument.as_ref() {
                walk_expression(arg, source, edits, stats, mode, semantic);
            }
        }
        Statement::VariableDeclaration(s) => {
            for d in &s.declarations {
                if let Some(init) = d.init.as_ref() {
                    walk_expression(init, source, edits, stats, mode, semantic);
                }
            }
        }
        Statement::IfStatement(s) => {
            walk_expression(&s.test, source, edits, stats, mode, semantic);
            walk_statement(&s.consequent, source, edits, stats, mode, semantic);
            if let Some(alt) = s.alternate.as_ref() {
                walk_statement(alt, source, edits, stats, mode, semantic);
            }
        }
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                walk_statement(inner, source, edits, stats, mode, semantic);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(test) = s.test.as_ref() {
                walk_expression(test, source, edits, stats, mode, semantic);
            }
            walk_statement(&s.body, source, edits, stats, mode, semantic);
        }
        Statement::WhileStatement(s) => {
            walk_expression(&s.test, source, edits, stats, mode, semantic);
            walk_statement(&s.body, source, edits, stats, mode, semantic);
        }
        Statement::DoWhileStatement(s) => {
            walk_expression(&s.test, source, edits, stats, mode, semantic);
            walk_statement(&s.body, source, edits, stats, mode, semantic);
        }
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, source, edits, stats, mode, semantic);
                }
            }
        }
        Statement::ThrowStatement(s) => {
            walk_expression(&s.argument, source, edits, stats, mode, semantic);
        }
        Statement::SwitchStatement(s) => {
            walk_expression(&s.discriminant, source, edits, stats, mode, semantic);
            for case in &s.cases {
                for inner in &case.consequent {
                    walk_statement(inner, source, edits, stats, mode, semantic);
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
    mode: RecoveryMode,
    semantic: &Semantic<'_>,
) {
    if let Expression::ConditionalExpression(cond) = expr
        && let Some(edit) = try_optional(cond, source, mode, semantic)
    {
        edits.push(edit);
        stats.chains_rebuilt += 1;
        return;
    }
    match expr {
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, source, edits, stats, mode, semantic);
            walk_expression(&c.consequent, source, edits, stats, mode, semantic);
            walk_expression(&c.alternate, source, edits, stats, mode, semantic);
        }
        Expression::BinaryExpression(b) => {
            walk_expression(&b.left, source, edits, stats, mode, semantic);
            walk_expression(&b.right, source, edits, stats, mode, semantic);
        }
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, source, edits, stats, mode, semantic);
            walk_expression(&b.right, source, edits, stats, mode, semantic);
        }
        Expression::ParenthesizedExpression(p) => {
            walk_expression(&p.expression, source, edits, stats, mode, semantic);
        }
        Expression::CallExpression(c) => {
            for arg in &c.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, source, edits, stats, mode, semantic);
                }
            }
        }
        Expression::AssignmentExpression(a) => {
            walk_expression(&a.right, source, edits, stats, mode, semantic);
        }
        Expression::SequenceExpression(s) => {
            for inner in &s.expressions {
                walk_expression(inner, source, edits, stats, mode, semantic);
            }
        }
        Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(inner) = el.as_expression() {
                    walk_expression(inner, source, edits, stats, mode, semantic);
                }
            }
        }
        Expression::ObjectExpression(obj) => {
            for prop in &obj.properties {
                if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop {
                    walk_expression(&p.value, source, edits, stats, mode, semantic);
                }
            }
        }
        Expression::FunctionExpression(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, source, edits, stats, mode, semantic);
                }
            }
        }
        Expression::ArrowFunctionExpression(a) => {
            for inner in &a.body.statements {
                walk_statement(inner, source, edits, stats, mode, semantic);
            }
        }
        _ => {}
    }
}

fn try_optional(
    cond: &ConditionalExpression<'_>,
    source: &str,
    mode: RecoveryMode,
    semantic: &Semantic<'_>,
) -> Option<Edit> {
    let test: &Expression<'_> = unwrap_paren(&cond.test);
    let consequent: &Expression<'_> = unwrap_paren(&cond.consequent);
    let alternate: &Expression<'_> = unwrap_paren(&cond.alternate);

    let (checked_src, member_branch): (&str, &Expression<'_>) =
        if let Some(checked) = nullish_check(test, source) {
            if !is_void_undefined(consequent) {
                return None;
            }
            (checked, alternate)
        } else if let Some(checked) = non_nullish_check(test, source) {
            if !is_void_undefined(alternate) {
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
    {
        let receiver: &IdentifierReference<'_> = access.binding_identifier(mode)?;
        let (first, second): (&IdentifierReference<'_>, &IdentifierReference<'_>) =
            repeated_checked_identifiers(test)?;
        if !same_repeatable_binding(first, second, receiver, semantic) {
            return None;
        }
    }
    let rewritten: String = access.render_optional(source);
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
}

impl<'a> Access<'a> {
    fn binding_identifier(&self, mode: RecoveryMode) -> Option<&IdentifierReference<'a>> {
        match self {
            Self::Static {
                object: Expression::Identifier(identifier),
                ..
            } => Some(identifier),
            Self::Computed {
                object: Expression::Identifier(identifier),
                ..
            } if !mode.requires_static_receiver() => Some(identifier),
            _ => None,
        }
    }

    fn receiver_src(&self, source: &'a str) -> &'a str {
        match self {
            Access::Static { object, .. } | Access::Computed { object, .. } => {
                object.span().source_text(source)
            }
        }
    }

    fn render_optional(&self, source: &str) -> String {
        match self {
            Access::Static { object, property } => {
                let obj_src: &str = object.span().source_text(source);
                format!("{obj_src}?.{property}")
            }
            Access::Computed { object, index } => {
                let obj_src: &str = object.span().source_text(source);
                let idx_src: &str = index.span().source_text(source);
                format!("{obj_src}?.[{idx_src}]")
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
        _ => None,
    }
}

fn nullish_check<'a>(test: &'a Expression<'a>, source: &'a str) -> Option<&'a str> {
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
            NullKind::Undefined => is_void_undefined(e),
        }
    };
    if matches_kind(&bin.right) && matches!(&bin.left, Expression::Identifier(_)) {
        return Some(bin.left.span().source_text(source));
    }
    if matches_kind(&bin.left) && matches!(&bin.right, Expression::Identifier(_)) {
        return Some(bin.right.span().source_text(source));
    }
    None
}

const fn is_null_literal(expr: &Expression<'_>) -> bool {
    matches!(expr, Expression::NullLiteral(_))
}

fn is_void_undefined(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::UnaryExpression(unary)
            if unary.operator == UnaryOperator::Void
                && matches!(
                    &unary.argument,
                    Expression::NumericLiteral(_) | Expression::StringLiteral(_)
                )
    )
}

fn unwrap_paren<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(p) => unwrap_paren(&p.expression),
        other => other,
    }
}
