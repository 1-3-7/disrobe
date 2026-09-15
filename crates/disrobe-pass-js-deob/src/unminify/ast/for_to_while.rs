use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, ForStatement, Program, Statement};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct ForToWhileStats {
    pub(super) loops_converted: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, ForToWhileStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), ForToWhileStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: ForToWhileStats = ForToWhileStats::default();
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
    stats: &mut ForToWhileStats,
) {
    match stmt {
        Statement::ForStatement(f) => {
            if let Some(edit) = try_convert(f, source) {
                edits.push(edit);
                stats.loops_converted += 1;
            }
            walk_statement(&f.body, source, edits, stats);
        }
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
        Statement::WhileStatement(s) => walk_statement(&s.body, source, edits, stats),
        Statement::DoWhileStatement(s) => walk_statement(&s.body, source, edits, stats),
        Statement::ForInStatement(s) => walk_statement(&s.body, source, edits, stats),
        Statement::ForOfStatement(s) => walk_statement(&s.body, source, edits, stats),
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

fn try_convert(f: &ForStatement<'_>, source: &str) -> Option<Edit> {
    if f.init.is_some() || f.update.is_some() {
        return None;
    }
    let body: &Statement<'_> = &f.body;
    let body_src: &str = body.span().source_text(source);
    let header: String = f.test.as_ref().map_or_else(
        || "while (true)".to_owned(),
        |test: &Expression<'_>| {
            let test_src: &str = test.span().source_text(source);
            format!("while ({test_src})")
        },
    );
    Some(Edit {
        start: f.span.start as usize,
        end: f.span.end as usize,
        replacement: format!("{header} {body_src}"),
    })
}
