use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, LogicalOperator, Program, Statement};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_field_names)]
pub(super) struct ConditionalStatementStats {
    pub(super) ternary_to_if: usize,
    pub(super) and_to_if: usize,
    pub(super) or_to_if: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ConditionalStatementStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), ConditionalStatementStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: ConditionalStatementStats = ConditionalStatementStats::default();
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
    stats: &mut ConditionalStatementStats,
) {
    if let Statement::ExpressionStatement(s) = stmt
        && let Some(edit) = rewrite_expression_statement(&s.expression, stmt, source, stats)
    {
        edits.push(edit);
        return;
    }
    match stmt {
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                walk_statement(inner, source, edits, stats);
            }
        }
        Statement::IfStatement(s) => {
            walk_statement(&s.consequent, source, edits, stats);
            if let Some(alt) = s.alternate.as_ref() {
                walk_statement(alt, source, edits, stats);
            }
        }
        Statement::ForStatement(s) => walk_statement(&s.body, source, edits, stats),
        Statement::ForInStatement(s) => walk_statement(&s.body, source, edits, stats),
        Statement::ForOfStatement(s) => walk_statement(&s.body, source, edits, stats),
        Statement::WhileStatement(s) => walk_statement(&s.body, source, edits, stats),
        Statement::DoWhileStatement(s) => walk_statement(&s.body, source, edits, stats),
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, source, edits, stats);
                }
            }
        }
        Statement::SwitchStatement(s) => {
            for case in &s.cases {
                for inner in &case.consequent {
                    walk_statement(inner, source, edits, stats);
                }
            }
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
        _ => {}
    }
}

fn rewrite_expression_statement(
    expr: &Expression<'_>,
    stmt: &Statement<'_>,
    source: &str,
    stats: &mut ConditionalStatementStats,
) -> Option<Edit> {
    match expr {
        Expression::ConditionalExpression(cond) => {
            let test_src: &str = cond.test.span().source_text(source);
            let cons_src: &str = cond.consequent.span().source_text(source);
            let alt_src: &str = cond.alternate.span().source_text(source);
            stats.ternary_to_if += 1;
            Some(Edit {
                start: stmt.span().start as usize,
                end: stmt.span().end as usize,
                replacement: format!("if ({test_src}) {cons_src}; else {alt_src};"),
            })
        }
        Expression::LogicalExpression(logical) => {
            let test_src: &str = logical.left.span().source_text(source);
            let body_src: &str = logical.right.span().source_text(source);
            match logical.operator {
                LogicalOperator::And => {
                    stats.and_to_if += 1;
                    Some(Edit {
                        start: stmt.span().start as usize,
                        end: stmt.span().end as usize,
                        replacement: format!("if ({test_src}) {body_src};"),
                    })
                }
                LogicalOperator::Or => {
                    stats.or_to_if += 1;
                    Some(Edit {
                        start: stmt.span().start as usize,
                        end: stmt.span().end as usize,
                        replacement: format!("if (!({test_src})) {body_src};"),
                    })
                }
                LogicalOperator::Coalesce => None,
            }
        }
        _ => None,
    }
}
