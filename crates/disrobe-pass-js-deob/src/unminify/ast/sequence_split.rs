use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Program, Statement};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct SequenceSplitStats {
    pub(super) statement_splits: usize,
    pub(super) return_splits: usize,
    pub(super) if_test_hoists: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, SequenceSplitStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), SequenceSplitStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: SequenceSplitStats = SequenceSplitStats::default();
    walk_statement_list(program.body.as_slice(), source, &mut edits, &mut stats);

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn walk_statement_list(
    statements: &[Statement<'_>],
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut SequenceSplitStats,
) {
    for stmt in statements {
        split_in_list_position(stmt, source, edits, stats);
        descend_only(stmt, source, edits, stats);
    }
}

fn split_in_list_position(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut SequenceSplitStats,
) {
    match stmt {
        Statement::ExpressionStatement(s) => {
            let Expression::SequenceExpression(seq): &Expression<'_> = &s.expression else {
                return;
            };
            if seq.expressions.len() < 2 {
                return;
            }
            let mut pieces: Vec<String> = Vec::with_capacity(seq.expressions.len());
            for expr in &seq.expressions {
                pieces.push(format!("{};", expr.span().source_text(source)));
            }
            edits.push(Edit {
                start: stmt.span().start as usize,
                end: stmt.span().end as usize,
                replacement: pieces.join("\n"),
            });
            stats.statement_splits += 1;
        }
        Statement::ReturnStatement(s) => {
            let Some(Expression::SequenceExpression(seq)) = s.argument.as_ref() else {
                return;
            };
            if seq.expressions.len() < 2 {
                return;
            }
            let count: usize = seq.expressions.len();
            let mut pieces: Vec<String> = Vec::with_capacity(count);
            for (index, expr) in seq.expressions.iter().enumerate() {
                let text: &str = expr.span().source_text(source);
                if index + 1 == count {
                    pieces.push(format!("return {text};"));
                } else {
                    pieces.push(format!("{text};"));
                }
            }
            edits.push(Edit {
                start: stmt.span().start as usize,
                end: stmt.span().end as usize,
                replacement: pieces.join("\n"),
            });
            stats.return_splits += 1;
        }
        Statement::IfStatement(s) => {
            let Expression::SequenceExpression(seq): &Expression<'_> = &s.test else {
                return;
            };
            if seq.expressions.len() < 2 {
                return;
            }
            let count: usize = seq.expressions.len();
            let Some(last): Option<&Expression<'_>> = seq.expressions.last() else {
                return;
            };
            let mut prelude: Vec<String> = Vec::with_capacity(count);
            for expr in seq.expressions.iter().take(count - 1) {
                prelude.push(format!("{};", expr.span().source_text(source)));
            }
            let test_text: &str = last.span().source_text(source);
            let test_span: oxc_span::Span = s.test.span();
            let prelude_text: String = prelude.join("\n");
            edits.push(Edit {
                start: stmt.span().start as usize,
                end: test_span.end as usize,
                replacement: format!("{prelude_text}\nif ({test_text}"),
            });
            stats.if_test_hoists += 1;
        }
        _ => {}
    }
}

fn descend_only(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut SequenceSplitStats,
) {
    match stmt {
        Statement::BlockStatement(s) => {
            walk_statement_list(s.body.as_slice(), source, edits, stats);
        }
        Statement::IfStatement(s) => {
            descend_single_body(&s.consequent, source, edits, stats);
            if let Some(alt) = s.alternate.as_ref() {
                descend_single_body(alt, source, edits, stats);
            }
        }
        Statement::ForStatement(s) => descend_single_body(&s.body, source, edits, stats),
        Statement::ForInStatement(s) => descend_single_body(&s.body, source, edits, stats),
        Statement::ForOfStatement(s) => descend_single_body(&s.body, source, edits, stats),
        Statement::WhileStatement(s) => descend_single_body(&s.body, source, edits, stats),
        Statement::DoWhileStatement(s) => descend_single_body(&s.body, source, edits, stats),
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                walk_statement_list(body.statements.as_slice(), source, edits, stats);
            }
        }
        Statement::SwitchStatement(s) => {
            for case in &s.cases {
                walk_statement_list(case.consequent.as_slice(), source, edits, stats);
            }
        }
        Statement::TryStatement(s) => {
            walk_statement_list(s.block.body.as_slice(), source, edits, stats);
            if let Some(handler) = s.handler.as_ref() {
                walk_statement_list(handler.body.body.as_slice(), source, edits, stats);
            }
            if let Some(finalizer) = s.finalizer.as_ref() {
                walk_statement_list(finalizer.body.as_slice(), source, edits, stats);
            }
        }
        Statement::LabeledStatement(s) => descend_single_body(&s.body, source, edits, stats),
        _ => {}
    }
}

fn descend_single_body(
    body: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut SequenceSplitStats,
) {
    descend_only(body, source, edits, stats);
}
