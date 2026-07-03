use oxc_allocator::Allocator;
use oxc_ast::ast::{Program, Statement, VariableDeclaration, VariableDeclarationKind};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct SplitVarStats {
    pub(super) declarations_split: usize,
    pub(super) declarators_emitted: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, SplitVarStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), SplitVarStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: SplitVarStats = SplitVarStats::default();
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
    stats: &mut SplitVarStats,
) {
    for stmt in statements {
        if let Statement::VariableDeclaration(decl) = stmt {
            split_declaration(decl, source, edits, stats);
        }
        descend(stmt, source, edits, stats);
    }
}

fn split_declaration(
    decl: &VariableDeclaration<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut SplitVarStats,
) {
    if decl.declare || decl.declarations.len() < 2 {
        return;
    }
    let keyword: &str = match decl.kind {
        VariableDeclarationKind::Var => "var",
        VariableDeclarationKind::Let => "let",
        VariableDeclarationKind::Const => "const",
        _ => return,
    };
    let mut pieces: Vec<String> = Vec::with_capacity(decl.declarations.len());
    for declarator in &decl.declarations {
        let text: &str = declarator.span().source_text(source);
        pieces.push(format!("{keyword} {text};"));
    }
    edits.push(Edit {
        start: decl.span.start as usize,
        end: decl.span.end as usize,
        replacement: pieces.join("\n"),
    });
    stats.declarations_split += 1;
    stats.declarators_emitted += decl.declarations.len();
}

fn descend(stmt: &Statement<'_>, source: &str, edits: &mut Vec<Edit>, stats: &mut SplitVarStats) {
    match stmt {
        Statement::BlockStatement(s) => {
            walk_statement_list(s.body.as_slice(), source, edits, stats);
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
        Statement::LabeledStatement(s) => descend(&s.body, source, edits, stats),
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
        _ => {}
    }
}
