use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, IfStatement, Program, Statement, UnaryOperator};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct MergeElseIfStats {
    pub(super) merges: usize,
    pub(super) inversions: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, MergeElseIfStats) {
    let mut stats: MergeElseIfStats = MergeElseIfStats::default();
    let mut current: String = source.to_owned();

    while let Some(next) = single_merge(&current, &mut stats) {
        if next == current || !reparses(&next) {
            break;
        }
        current = next;
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

fn single_merge(source: &str, stats: &mut MergeElseIfStats) -> Option<String> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return None;
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let before: usize = stats.merges;
    for stmt in &program.body {
        walk_statement(stmt, source, &mut edits, stats);
        if !edits.is_empty() {
            break;
        }
    }
    if edits.is_empty() {
        stats.merges = before;
        return None;
    }
    apply_local_edits(source, &edits)
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

fn walk_statement(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut MergeElseIfStats,
) {
    if !edits.is_empty() {
        return;
    }
    match stmt {
        Statement::IfStatement(if_stmt) => {
            try_merge(if_stmt, source, edits, stats);
            if !edits.is_empty() {
                return;
            }
            try_invert(if_stmt, source, edits, stats);
            if !edits.is_empty() {
                return;
            }
            walk_statement(&if_stmt.consequent, source, edits, stats);
            if let Some(alt) = if_stmt.alternate.as_ref() {
                walk_statement(alt, source, edits, stats);
            }
        }
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                walk_statement(inner, source, edits, stats);
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

fn try_invert(
    if_stmt: &IfStatement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut MergeElseIfStats,
) {
    let Some(alt): Option<&Statement<'_>> = if_stmt.alternate.as_ref() else {
        return;
    };
    let Expression::UnaryExpression(unary): &Expression<'_> = &if_stmt.test else {
        return;
    };
    if !matches!(unary.operator, UnaryOperator::LogicalNot) {
        return;
    }
    let inner_test: &Expression<'_> = unary.argument.get_inner_expression();
    let condition: &str = inner_test.span().source_text(source);
    let cons_src: &str = block_text(&if_stmt.consequent, source);
    let alt_src: &str = block_text(alt, source);
    let new_consequent: String = if matches!(alt, Statement::BlockStatement(_)) {
        alt_src.to_owned()
    } else {
        format!("{{ {alt_src} }}")
    };
    let rendered: String = format!("if ({condition}) {new_consequent} else {cons_src}");
    edits.push(Edit {
        start: if_stmt.span.start as usize,
        end: if_stmt.span.end as usize,
        replacement: rendered,
    });
    stats.inversions += 1;
}

fn block_text<'a>(stmt: &Statement<'_>, source: &'a str) -> &'a str {
    stmt.span().source_text(source)
}

fn try_merge(
    if_stmt: &IfStatement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut MergeElseIfStats,
) {
    let Some(alt): Option<&Statement<'_>> = if_stmt.alternate.as_ref() else {
        return;
    };
    let Statement::BlockStatement(block): &Statement<'_> = alt else {
        return;
    };
    if block.body.len() != 1 {
        return;
    }
    let Statement::IfStatement(inner): &Statement<'_> = &block.body[0] else {
        return;
    };
    let inner_src: &str = inner.span.source_text(source);
    edits.push(Edit {
        start: alt.span().start as usize,
        end: alt.span().end as usize,
        replacement: inner_src.to_owned(),
    });
    stats.merges += 1;
}
