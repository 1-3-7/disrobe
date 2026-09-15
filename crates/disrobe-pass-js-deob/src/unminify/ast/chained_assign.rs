use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentExpression, AssignmentOperator, AssignmentTarget, Expression, Program, Statement,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct ChainedAssignStats {
    pub(super) chains_split: usize,
    pub(super) assignments_emitted: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ChainedAssignStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), ChainedAssignStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: ChainedAssignStats = ChainedAssignStats::default();
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
    stats: &mut ChainedAssignStats,
) {
    for stmt in statements {
        split_in_list_position(stmt, source, edits, stats);
        descend(stmt, source, edits, stats);
    }
}

fn split_in_list_position(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut ChainedAssignStats,
) {
    let Statement::ExpressionStatement(s) = stmt else {
        return;
    };
    let Expression::AssignmentExpression(assign) = &s.expression else {
        return;
    };
    let Some(chain): Option<Split<'_>> = split_chain(assign) else {
        return;
    };

    let inner: &str = chain.inner_target;
    let value_src: &str = chain.value.span().source_text(source);
    let mut pieces: Vec<String> = Vec::with_capacity(chain.outer_targets.len() + 1);
    pieces.push(format!("{inner} = {value_src};"));
    for target in chain.outer_targets.iter().rev() {
        pieces.push(format!("{target} = {inner};"));
    }
    stats.assignments_emitted += pieces.len();
    edits.push(Edit {
        start: stmt.span().start as usize,
        end: stmt.span().end as usize,
        replacement: pieces.join("\n"),
    });
    stats.chains_split += 1;
}

struct Split<'a> {
    outer_targets: Vec<&'a str>,
    inner_target: &'a str,
    value: &'a Expression<'a>,
}

fn split_chain<'a>(assign: &'a AssignmentExpression<'a>) -> Option<Split<'a>> {
    if assign.operator != AssignmentOperator::Assign {
        return None;
    }
    let first_target: &str = plain_identifier_target(&assign.left)?;
    let mut outer_targets: Vec<&str> = vec![first_target];

    let mut current: &AssignmentExpression<'a> = assign;
    loop {
        match &current.right {
            Expression::AssignmentExpression(next) => {
                if next.operator != AssignmentOperator::Assign {
                    return None;
                }
                let target: &str = plain_identifier_target(&next.left)?;
                outer_targets.push(target);
                current = next;
            }
            value => {
                if outer_targets.len() < 2 {
                    return None;
                }
                let inner_target: &str = outer_targets.pop()?;
                return Some(Split {
                    outer_targets,
                    inner_target,
                    value,
                });
            }
        }
    }
}

fn plain_identifier_target<'a>(target: &'a AssignmentTarget<'a>) -> Option<&'a str> {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(id) => Some(id.name.as_str()),
        _ => None,
    }
}

fn descend(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut ChainedAssignStats,
) {
    match stmt {
        Statement::BlockStatement(s) => {
            walk_statement_list(s.body.as_slice(), source, edits, stats);
        }
        Statement::IfStatement(s) => {
            descend_single(&s.consequent, source, edits, stats);
            if let Some(alt) = s.alternate.as_ref() {
                descend_single(alt, source, edits, stats);
            }
        }
        Statement::ForStatement(s) => descend_single(&s.body, source, edits, stats),
        Statement::ForInStatement(s) => descend_single(&s.body, source, edits, stats),
        Statement::ForOfStatement(s) => descend_single(&s.body, source, edits, stats),
        Statement::WhileStatement(s) => descend_single(&s.body, source, edits, stats),
        Statement::DoWhileStatement(s) => descend_single(&s.body, source, edits, stats),
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
        Statement::LabeledStatement(s) => descend_single(&s.body, source, edits, stats),
        _ => {}
    }
}

fn descend_single(
    body: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut ChainedAssignStats,
) {
    if let Statement::BlockStatement(_) = body {
        descend(body, source, edits, stats);
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::recover;
    use crate::unminify::ast::{Edit, RuleOutcome};

    fn apply(source: &str) -> String {
        let (outcome, _stats): (RuleOutcome, super::ChainedAssignStats) = recover(source);
        let mut sorted: Vec<&Edit> = outcome.edits.iter().collect();
        sorted.sort_by_key(|edit| core::cmp::Reverse(edit.start));
        let mut out: String = source.to_owned();
        for edit in sorted {
            out.replace_range(edit.start..edit.end, &edit.replacement);
        }
        out
    }

    #[test]
    fn three_way_chain_splits() {
        let out: String = apply("a=b=c=compute();");
        assert_eq!(out, "c = compute();\nb = c;\na = c;");
    }

    #[test]
    fn two_way_chain_splits() {
        let out: String = apply("x=y=0;");
        assert_eq!(out, "y = 0;\nx = y;");
    }

    #[test]
    fn single_assignment_not_touched() {
        let (outcome, _stats): (RuleOutcome, super::ChainedAssignStats) = recover("a = 1;");
        assert!(outcome.edits.is_empty());
    }

    #[test]
    fn compound_operator_blocks_split() {
        let (outcome, _stats): (RuleOutcome, super::ChainedAssignStats) = recover("a = b += 1;");
        assert!(
            outcome.edits.is_empty(),
            "a compound inner assignment must not be split"
        );
    }

    #[test]
    fn member_target_blocks_split() {
        let (outcome, _stats): (RuleOutcome, super::ChainedAssignStats) = recover("a.x=b=0;");
        assert!(
            outcome.edits.is_empty(),
            "member outer targets are out of scope and must be left alone"
        );
    }

    #[test]
    fn member_inner_target_blocks_split() {
        let (outcome, _stats): (RuleOutcome, super::ChainedAssignStats) = recover("a=o.x=1;");
        assert!(
            outcome.edits.is_empty(),
            "an inner member target cannot be reused as a pure source"
        );
    }

    #[test]
    fn identifier_source_chain_splits() {
        let out: String = apply("a=b=o.x;");
        assert_eq!(out, "b = o.x;\na = b;");
    }

    #[test]
    fn value_position_chain_not_touched() {
        let (outcome, _stats): (RuleOutcome, super::ChainedAssignStats) =
            recover("var z = (a = b = 1);");
        assert!(
            outcome.edits.is_empty(),
            "a chain in initializer value position is not a statement chain"
        );
    }
}
