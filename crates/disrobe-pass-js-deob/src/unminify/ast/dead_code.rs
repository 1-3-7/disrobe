use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Expression, IfStatement, ImportDeclaration, ImportDeclarationSpecifier, ImportOrExportKind,
    Program, Statement,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};

use super::{Edit, RuleOutcome};

#[derive(Debug, Clone, Default)]
pub(super) struct DeadCodeStats {
    pub(super) constant_if_folds: usize,
    pub(super) unreachable_drops: usize,
    pub(super) import_merges: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, DeadCodeStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), DeadCodeStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: DeadCodeStats = DeadCodeStats::default();

    collect_constant_if(program.body.as_slice(), source, &mut edits, &mut stats);
    if edits.is_empty() {
        collect_unreachable(program.body.as_slice(), source, &mut edits, &mut stats);
    }
    if edits.is_empty() {
        collect_import_merges(program.body.as_slice(), source, &mut edits, &mut stats);
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn collect_constant_if(
    statements: &[Statement<'_>],
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut DeadCodeStats,
) {
    for stmt in statements {
        if let Statement::IfStatement(if_stmt) = stmt
            && let Some(edit) = try_constant_if(if_stmt, source, stats)
        {
            edits.push(edit);
            continue;
        }
        walk_into_blocks(stmt, source, edits, stats, collect_constant_if);
    }
}

fn try_constant_if(
    if_stmt: &IfStatement<'_>,
    source: &str,
    stats: &mut DeadCodeStats,
) -> Option<Edit> {
    let cond: bool = constant_truth(&if_stmt.test)?;
    let span: Span = if_stmt.span;
    if cond {
        let kept: &str = if_stmt.consequent.span().source_text(source);
        stats.constant_if_folds += 1;
        return Some(Edit {
            start: span.start as usize,
            end: span.end as usize,
            replacement: brace_wrap(&if_stmt.consequent, kept),
        });
    }
    stats.constant_if_folds += 1;
    let replacement: String = if_stmt.alternate.as_ref().map_or_else(
        || ";".to_owned(),
        |alt| brace_wrap(alt, alt.span().source_text(source)),
    );
    Some(Edit {
        start: span.start as usize,
        end: span.end as usize,
        replacement,
    })
}

fn brace_wrap(stmt: &Statement<'_>, text: &str) -> String {
    if matches!(stmt, Statement::BlockStatement(_)) {
        text.to_owned()
    } else {
        format!("{{ {text} }}")
    }
}

fn constant_truth(expr: &Expression<'_>) -> Option<bool> {
    match expr {
        Expression::BooleanLiteral(b) => Some(b.value),
        Expression::ParenthesizedExpression(p) => constant_truth(&p.expression),
        _ => None,
    }
}

fn collect_unreachable(
    statements: &[Statement<'_>],
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut DeadCodeStats,
) {
    if let Some(cut) = first_dead_index(statements) {
        let start: u32 = statements[cut].span().start;
        let end: u32 = statements[statements.len() - 1].span().end;
        edits.push(Edit {
            start: start as usize,
            end: end as usize,
            replacement: String::new(),
        });
        stats.unreachable_drops += 1;
        return;
    }
    for stmt in statements {
        walk_into_blocks(stmt, source, edits, stats, collect_unreachable);
    }
}

fn first_dead_index(statements: &[Statement<'_>]) -> Option<usize> {
    let mut terminator: Option<usize> = None;
    for (i, stmt) in statements.iter().enumerate() {
        if is_terminator(stmt) {
            terminator = Some(i);
            break;
        }
    }
    let cut: usize = terminator? + 1;
    if cut >= statements.len() {
        return None;
    }
    if statements[cut..].iter().all(is_safely_droppable) {
        Some(cut)
    } else {
        None
    }
}

const fn is_terminator(stmt: &Statement<'_>) -> bool {
    matches!(
        stmt,
        Statement::ReturnStatement(_)
            | Statement::ThrowStatement(_)
            | Statement::BreakStatement(_)
            | Statement::ContinueStatement(_)
    )
}

const fn is_safely_droppable(stmt: &Statement<'_>) -> bool {
    matches!(
        stmt,
        Statement::ExpressionStatement(_)
            | Statement::ReturnStatement(_)
            | Statement::ThrowStatement(_)
            | Statement::BreakStatement(_)
            | Statement::ContinueStatement(_)
            | Statement::EmptyStatement(_)
    )
}

fn walk_into_blocks(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut DeadCodeStats,
    recurse: fn(&[Statement<'_>], &str, &mut Vec<Edit>, &mut DeadCodeStats),
) {
    match stmt {
        Statement::BlockStatement(s) => recurse(s.body.as_slice(), source, edits, stats),
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                recurse(body.statements.as_slice(), source, edits, stats);
            }
        }
        Statement::IfStatement(s) => {
            walk_into_blocks(&s.consequent, source, edits, stats, recurse);
            if let Some(alt) = s.alternate.as_ref() {
                walk_into_blocks(alt, source, edits, stats, recurse);
            }
        }
        Statement::ForStatement(s) => walk_into_blocks(&s.body, source, edits, stats, recurse),
        Statement::WhileStatement(s) => walk_into_blocks(&s.body, source, edits, stats, recurse),
        Statement::DoWhileStatement(s) => walk_into_blocks(&s.body, source, edits, stats, recurse),
        Statement::SwitchStatement(s) => {
            for case in &s.cases {
                recurse(case.consequent.as_slice(), source, edits, stats);
            }
        }
        _ => {}
    }
}

fn collect_import_merges(
    statements: &[Statement<'_>],
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut DeadCodeStats,
) {
    let named_imports: Vec<(usize, &ImportDeclaration<'_>)> = statements
        .iter()
        .enumerate()
        .filter_map(|(i, stmt)| match stmt {
            Statement::ImportDeclaration(decl) if is_named_only(decl) => Some((i, decl.as_ref())),
            _ => None,
        })
        .collect();

    let mut grouped: std::collections::BTreeMap<&str, Vec<(usize, &ImportDeclaration<'_>)>> =
        std::collections::BTreeMap::new();
    for (i, decl) in named_imports {
        grouped
            .entry(decl.source.value.as_str())
            .or_default()
            .push((i, decl));
    }

    for (_source_name, group) in grouped {
        if group.len() < 2 {
            continue;
        }
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut merged: Vec<String> = Vec::new();
        for (_i, decl) in &group {
            let Some(specs): Option<&oxc_allocator::Vec<'_, ImportDeclarationSpecifier<'_>>> =
                decl.specifiers.as_ref()
            else {
                continue;
            };
            for spec in specs {
                let ImportDeclarationSpecifier::ImportSpecifier(named) = spec else {
                    continue;
                };
                let local: &str = named.local.name.as_str();
                if seen.insert(local.to_owned()) {
                    merged.push(named.span.source_text(source).to_owned());
                }
            }
        }
        if merged.is_empty() {
            continue;
        }
        let (first_index, first_decl): (usize, &ImportDeclaration<'_>) = group[0];
        let source_text: &str = first_decl.source.span().source_text(source);
        let rewritten: String = format!("import {{ {} }} from {};", merged.join(", "), source_text);
        edits.push(Edit {
            start: first_decl.span.start as usize,
            end: first_decl.span.end as usize,
            replacement: rewritten,
        });
        for (i, decl) in &group {
            if *i == first_index {
                continue;
            }
            edits.push(Edit {
                start: decl.span.start as usize,
                end: decl.span.end as usize,
                replacement: String::new(),
            });
        }
        stats.import_merges += 1;
    }
}

fn is_named_only(decl: &ImportDeclaration<'_>) -> bool {
    if decl.import_kind != ImportOrExportKind::Value || decl.with_clause.is_some() {
        return false;
    }
    let Some(specs): Option<&oxc_allocator::Vec<'_, ImportDeclarationSpecifier<'_>>> =
        decl.specifiers.as_ref()
    else {
        return false;
    };
    if specs.is_empty() {
        return false;
    }
    specs.iter().all(|spec| match spec {
        ImportDeclarationSpecifier::ImportSpecifier(named) => {
            named.import_kind == ImportOrExportKind::Value
        }
        _ => false,
    })
}
