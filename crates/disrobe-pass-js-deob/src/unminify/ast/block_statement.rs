use oxc_allocator::Allocator;
use oxc_ast::ast::{Program, Statement};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct BlockStatementStats {
    pub(super) bodies_wrapped: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, BlockStatementStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), BlockStatementStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: BlockStatementStats = BlockStatementStats::default();
    for stmt in &program.body {
        walk_statement(stmt, source, &mut edits, &mut stats);
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn wrap(
    body: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut BlockStatementStats,
) {
    if matches!(
        body,
        Statement::BlockStatement(_) | Statement::EmptyStatement(_)
    ) {
        return;
    }
    let inner: &str = body.span().source_text(source);
    edits.push(Edit {
        start: body.span().start as usize,
        end: body.span().end as usize,
        replacement: format!("{{ {inner} }}"),
    });
    stats.bodies_wrapped += 1;
}

fn walk_statement(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut BlockStatementStats,
) {
    match stmt {
        Statement::IfStatement(s) => {
            wrap(&s.consequent, source, edits, stats);
            walk_statement(&s.consequent, source, edits, stats);
            if let Some(alt) = s.alternate.as_ref() {
                if !matches!(alt, Statement::IfStatement(_)) {
                    wrap(alt, source, edits, stats);
                }
                walk_statement(alt, source, edits, stats);
            }
        }
        Statement::ForStatement(s) => {
            wrap(&s.body, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::ForInStatement(s) => {
            wrap(&s.body, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::ForOfStatement(s) => {
            wrap(&s.body, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::WhileStatement(s) => {
            wrap(&s.body, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::DoWhileStatement(s) => {
            wrap(&s.body, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                walk_statement(inner, source, edits, stats);
            }
        }
        Statement::LabeledStatement(s) => walk_statement(&s.body, source, edits, stats),
        Statement::FunctionDeclaration(func) => {
            if let Some(body) = func.body.as_ref() {
                for inner in &body.statements {
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
        Statement::SwitchStatement(s) => {
            for case in &s.cases {
                for inner in &case.consequent {
                    walk_statement(inner, source, edits, stats);
                }
            }
        }
        _ => {}
    }
}
