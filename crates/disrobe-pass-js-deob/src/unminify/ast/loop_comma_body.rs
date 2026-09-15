use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Program, Statement};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct LoopCommaBodyStats {
    pub(super) loop_bodies_split: usize,
    pub(super) branch_bodies_split: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, LoopCommaBodyStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), LoopCommaBodyStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: LoopCommaBodyStats = LoopCommaBodyStats::default();
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
    stats: &mut LoopCommaBodyStats,
) {
    match stmt {
        Statement::ForStatement(s) => {
            split_loop_body(&s.body, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::ForInStatement(s) => {
            split_loop_body(&s.body, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::ForOfStatement(s) => {
            split_loop_body(&s.body, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::WhileStatement(s) => {
            split_loop_body(&s.body, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::DoWhileStatement(s) => {
            split_loop_body(&s.body, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::IfStatement(s) => {
            split_branch_body(&s.consequent, source, edits, stats);
            walk_statement(&s.consequent, source, edits, stats);
            if let Some(alt) = s.alternate.as_ref() {
                if !matches!(alt, Statement::IfStatement(_)) {
                    split_branch_body(alt, source, edits, stats);
                }
                walk_statement(alt, source, edits, stats);
            }
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

fn split_loop_body(
    body: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut LoopCommaBodyStats,
) {
    if let Some(edit) = comma_body_edit(body, source) {
        edits.push(edit);
        stats.loop_bodies_split += 1;
    }
}

fn split_branch_body(
    body: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut LoopCommaBodyStats,
) {
    if let Some(edit) = comma_body_edit(body, source) {
        edits.push(edit);
        stats.branch_bodies_split += 1;
    }
}

fn comma_body_edit(body: &Statement<'_>, source: &str) -> Option<Edit> {
    let Statement::ExpressionStatement(expr_stmt): &Statement<'_> = body else {
        return None;
    };
    let Expression::SequenceExpression(seq): &Expression<'_> = &expr_stmt.expression else {
        return None;
    };
    if seq.expressions.len() < 2 {
        return None;
    }
    let mut pieces: Vec<String> = Vec::with_capacity(seq.expressions.len());
    for expr in &seq.expressions {
        pieces.push(format!("{};", expr.span().source_text(source)));
    }
    Some(Edit {
        start: body.span().start as usize,
        end: body.span().end as usize,
        replacement: format!("{{ {} }}", pieces.join(" ")),
    })
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::LoopCommaBodyStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit: &&Edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn for_comma_body_splits_into_block() {
        let source: &str = "for (var i = 0; i < n; i++) a(i), b(i);";
        let (_outcome, stats): (RuleOutcome, super::LoopCommaBodyStats) = recover(source);
        assert_eq!(stats.loop_bodies_split, 1);
        let out: String = apply(source);
        assert!(out.contains("{ a(i); b(i); }"), "got: {out}");
    }

    #[test]
    fn while_comma_body_splits() {
        let source: &str = "while (p) x++, y--;";
        let (_outcome, stats): (RuleOutcome, super::LoopCommaBodyStats) = recover(source);
        assert_eq!(stats.loop_bodies_split, 1);
        let out: String = apply(source);
        assert!(out.contains("{ x++; y--; }"), "got: {out}");
    }

    #[test]
    fn if_comma_body_splits() {
        let source: &str = "if (c) a(), b();";
        let (_outcome, stats): (RuleOutcome, super::LoopCommaBodyStats) = recover(source);
        assert_eq!(stats.branch_bodies_split, 1);
        let out: String = apply(source);
        assert!(out.contains("{ a(); b(); }"), "got: {out}");
    }

    #[test]
    fn already_blocked_body_is_untouched() {
        let source: &str = "for (var i = 0; i < n; i++) { a(i); b(i); }";
        let (_outcome, stats): (RuleOutcome, super::LoopCommaBodyStats) = recover(source);
        assert_eq!(stats.loop_bodies_split, 0);
    }

    #[test]
    fn single_expression_body_is_untouched() {
        let source: &str = "for (var i = 0; i < n; i++) a(i);";
        let (_outcome, stats): (RuleOutcome, super::LoopCommaBodyStats) = recover(source);
        assert_eq!(stats.loop_bodies_split, 0);
    }

    #[test]
    fn for_update_comma_is_left_untouched() {
        let source: &str = "for (var i = 0; i < n; a(), i++) log(i);";
        let (_outcome, stats): (RuleOutcome, super::LoopCommaBodyStats) = recover(source);
        assert_eq!(stats.loop_bodies_split, 0);
        assert_eq!(stats.branch_bodies_split, 0);
    }

    #[test]
    fn nested_loop_comma_bodies_both_split() {
        let source: &str =
            "for (var i = 0; i < n; i++) for (var j = 0; j < m; j++) a(i, j), b(i, j);";
        let (_outcome, stats): (RuleOutcome, super::LoopCommaBodyStats) = recover(source);
        assert_eq!(stats.loop_bodies_split, 1);
        let out: String = apply(source);
        assert!(out.contains("{ a(i, j); b(i, j); }"), "got: {out}");
    }

    #[test]
    fn for_of_comma_body_splits() {
        let source: &str = "for (const x of xs) a(x), b(x);";
        let (_outcome, stats): (RuleOutcome, super::LoopCommaBodyStats) = recover(source);
        assert_eq!(stats.loop_bodies_split, 1);
        let out: String = apply(source);
        assert!(out.contains("{ a(x); b(x); }"), "got: {out}");
    }
}
