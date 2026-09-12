use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentOperator, AssignmentTarget, Expression, ObjectPropertyKind, Program, Statement,
    VariableDeclarationKind,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct SpreadCloneStats {
    pub(super) clones_merged: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, SpreadCloneStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), SpreadCloneStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: SpreadCloneStats = SpreadCloneStats::default();
    scan_block(program.body.as_slice(), source, &mut edits, &mut stats);

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn scan_block(
    statements: &[Statement<'_>],
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut SpreadCloneStats,
) {
    let mut index: usize = 0;
    while index + 1 < statements.len() {
        if try_merge(
            &statements[index],
            &statements[index + 1],
            source,
            edits,
            stats,
        ) {
            index += 2;
            continue;
        }
        descend(&statements[index], source, edits, stats);
        index += 1;
    }
    if let Some(last) = statements.last() {
        descend(last, source, edits, stats);
    }
}

fn descend(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut SpreadCloneStats,
) {
    match stmt {
        Statement::BlockStatement(s) => scan_block(s.body.as_slice(), source, edits, stats),
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                scan_block(body.statements.as_slice(), source, edits, stats);
            }
        }
        Statement::IfStatement(s) => {
            descend(&s.consequent, source, edits, stats);
            if let Some(alt) = s.alternate.as_ref() {
                descend(alt, source, edits, stats);
            }
        }
        Statement::ForStatement(s) => descend(&s.body, source, edits, stats),
        Statement::ForInStatement(s) => descend(&s.body, source, edits, stats),
        Statement::ForOfStatement(s) => descend(&s.body, source, edits, stats),
        Statement::WhileStatement(s) => descend(&s.body, source, edits, stats),
        Statement::DoWhileStatement(s) => descend(&s.body, source, edits, stats),
        Statement::TryStatement(s) => {
            scan_block(s.block.body.as_slice(), source, edits, stats);
            if let Some(handler) = s.handler.as_ref() {
                scan_block(handler.body.body.as_slice(), source, edits, stats);
            }
            if let Some(finalizer) = s.finalizer.as_ref() {
                scan_block(finalizer.body.as_slice(), source, edits, stats);
            }
        }
        Statement::LabeledStatement(s) => descend(&s.body, source, edits, stats),
        _ => {}
    }
}

fn try_merge(
    first: &Statement<'_>,
    second: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut SpreadCloneStats,
) -> bool {
    let Some(clone): Option<CloneDecl<'_>> = match_spread_clone(first) else {
        return false;
    };
    let Some(assign): Option<IndexAssign<'_>> = match_index_assign(second) else {
        return false;
    };
    if assign.object_name != clone.target_name {
        return false;
    }
    if !is_pure(assign.key) || !is_pure(assign.value) {
        return false;
    }
    if references_name(assign.key, clone.target_name)
        || references_name(assign.value, clone.target_name)
    {
        return false;
    }
    let key_src: &str = assign.key.span().source_text(source);
    let value_src: &str = assign.value.span().source_text(source);
    let spread_src: &str = clone.spread_arg_src(source);
    let merged_object: String = format!("{{...{spread_src}, [{key_src}]: {value_src}}}");

    edits.push(Edit {
        start: clone.object_span_start as usize,
        end: clone.object_span_end as usize,
        replacement: merged_object,
    });
    edits.push(Edit {
        start: second.span().start as usize,
        end: second.span().end as usize,
        replacement: String::new(),
    });
    stats.clones_merged += 1;
    true
}

struct CloneDecl<'a> {
    target_name: &'a str,
    object_span_start: u32,
    object_span_end: u32,
    spread_arg_start: u32,
    spread_arg_end: u32,
}

impl<'a> CloneDecl<'a> {
    fn spread_arg_src(&self, source: &'a str) -> &'a str {
        source
            .get(self.spread_arg_start as usize..self.spread_arg_end as usize)
            .map_or("", |inner: &str| inner)
    }
}

struct IndexAssign<'a> {
    object_name: &'a str,
    key: &'a Expression<'a>,
    value: &'a Expression<'a>,
}

fn match_spread_clone<'a>(stmt: &'a Statement<'a>) -> Option<CloneDecl<'a>> {
    let (target_name, init): (&'a str, &'a Expression<'a>) = match stmt {
        Statement::VariableDeclaration(decl) => {
            if !matches!(
                decl.kind,
                VariableDeclarationKind::Var
                    | VariableDeclarationKind::Let
                    | VariableDeclarationKind::Const
            ) {
                return None;
            }
            if decl.declarations.len() != 1 {
                return None;
            }
            let declarator: &'a oxc_ast::ast::VariableDeclarator<'a> = &decl.declarations[0];
            let oxc_ast::ast::BindingPatternKind::BindingIdentifier(ident) = &declarator.id.kind
            else {
                return None;
            };
            (ident.name.as_str(), declarator.init.as_ref()?)
        }
        Statement::ExpressionStatement(expr_stmt) => {
            let Expression::AssignmentExpression(assign) = &expr_stmt.expression else {
                return None;
            };
            if !matches!(assign.operator, AssignmentOperator::Assign) {
                return None;
            }
            let AssignmentTarget::AssignmentTargetIdentifier(ident) = &assign.left else {
                return None;
            };
            (ident.name.as_str(), &assign.right)
        }
        _ => return None,
    };
    let Expression::ObjectExpression(object) = init else {
        return None;
    };
    if object.properties.len() != 1 {
        return None;
    }
    let ObjectPropertyKind::SpreadProperty(spread) = &object.properties[0] else {
        return None;
    };
    if !is_pure(&spread.argument) {
        return None;
    }
    Some(CloneDecl {
        target_name,
        object_span_start: object.span.start,
        object_span_end: object.span.end,
        spread_arg_start: spread.argument.span().start,
        spread_arg_end: spread.argument.span().end,
    })
}

fn match_index_assign<'a>(stmt: &'a Statement<'a>) -> Option<IndexAssign<'a>> {
    let Statement::ExpressionStatement(expr_stmt) = stmt else {
        return None;
    };
    let Expression::AssignmentExpression(assign) = &expr_stmt.expression else {
        return None;
    };
    if !matches!(assign.operator, AssignmentOperator::Assign) {
        return None;
    }
    let AssignmentTarget::ComputedMemberExpression(member) = &assign.left else {
        return None;
    };
    let Expression::Identifier(object) = &member.object else {
        return None;
    };
    Some(IndexAssign {
        object_name: object.name.as_str(),
        key: &member.expression,
        value: &assign.right,
    })
}

fn is_pure(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::Identifier(_)
        | Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::ThisExpression(_) => true,
        Expression::ParenthesizedExpression(p) => is_pure(&p.expression),
        Expression::UnaryExpression(u) => {
            !matches!(u.operator, oxc_ast::ast::UnaryOperator::Delete) && is_pure(&u.argument)
        }
        Expression::StaticMemberExpression(m) => is_pure(&m.object),
        Expression::ComputedMemberExpression(m) => is_pure(&m.object) && is_pure(&m.expression),
        Expression::TemplateLiteral(t) => t.expressions.iter().all(is_pure),
        Expression::BinaryExpression(b) => is_pure(&b.left) && is_pure(&b.right),
        Expression::LogicalExpression(l) => is_pure(&l.left) && is_pure(&l.right),
        Expression::ConditionalExpression(c) => {
            is_pure(&c.test) && is_pure(&c.consequent) && is_pure(&c.alternate)
        }
        _ => false,
    }
}

fn references_name(expr: &Expression<'_>, name: &str) -> bool {
    match expr {
        Expression::Identifier(ident) => ident.name.as_str() == name,
        Expression::ParenthesizedExpression(p) => references_name(&p.expression, name),
        Expression::UnaryExpression(u) => references_name(&u.argument, name),
        Expression::StaticMemberExpression(m) => references_name(&m.object, name),
        Expression::ComputedMemberExpression(m) => {
            references_name(&m.object, name) || references_name(&m.expression, name)
        }
        Expression::TemplateLiteral(t) => t.expressions.iter().any(|e| references_name(e, name)),
        Expression::BinaryExpression(b) => {
            references_name(&b.left, name) || references_name(&b.right, name)
        }
        Expression::LogicalExpression(l) => {
            references_name(&l.left, name) || references_name(&l.right, name)
        }
        Expression::ConditionalExpression(c) => {
            references_name(&c.test, name)
                || references_name(&c.consequent, name)
                || references_name(&c.alternate, name)
        }
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> (String, usize) {
        let (outcome, stats): (RuleOutcome, super::SpreadCloneStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        (out, stats.clones_merged)
    }

    #[test]
    fn merges_var_clone_then_index_assign() {
        let (out, merged): (String, usize) = apply("var l = {...tt}; l[k] = v;");
        assert_eq!(merged, 1, "got: {out}");
        assert!(out.contains("{...tt, [k]: v}"), "got: {out}");
        assert!(
            !out.contains("l[k] = v"),
            "index assign must be gone: {out}"
        );
    }

    #[test]
    fn merges_assignment_form() {
        let (out, merged): (String, usize) = apply("l = {...tt}; l[k] = v;");
        assert_eq!(merged, 1, "got: {out}");
        assert!(out.contains("{...tt, [k]: v}"), "got: {out}");
    }

    #[test]
    fn skips_when_value_calls_a_function() {
        let (_out, merged): (String, usize) = apply("var l = {...tt}; l[k] = compute();");
        assert_eq!(merged, 0, "call has a side effect; must not merge");
    }

    #[test]
    fn skips_when_value_references_clone_target() {
        let (_out, merged): (String, usize) = apply("var l = {...tt}; l[k] = l;");
        assert_eq!(merged, 0, "value referencing the clone must not merge");
    }

    #[test]
    fn skips_when_key_has_update_side_effect() {
        let (_out, merged): (String, usize) = apply("var l = {...tt}; l[i++] = v;");
        assert_eq!(
            merged, 0,
            "update-expression key has a side effect; must not merge"
        );
    }

    #[test]
    fn skips_object_with_extra_properties() {
        let (_out, merged): (String, usize) = apply("var l = {...tt, a: 1}; l[k] = v;");
        assert_eq!(merged, 0, "object is not a pure clone; must not merge");
    }
}
