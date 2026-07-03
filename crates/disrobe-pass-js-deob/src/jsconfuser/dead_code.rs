use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use oxc_allocator::Allocator;
use oxc_ast::ast as oast;
use oxc_parser::Parser;
use oxc_span::SourceType;
use serde::Serialize;

use super::scanner::apply_splice_edits;

#[derive(Debug, Clone, Serialize)]
pub struct DeadCodeReversalResult {
    pub branches_removed: usize,
    pub dead_functions_removed: usize,
    pub rewritten_source: String,
}

#[derive(Default)]
struct Analysis {
    empty_functions: BTreeSet<String>,
    function_decl_spans: BTreeMap<String, Range<usize>>,
    dead_guards: Vec<DeadGuard>,
    references: Vec<(String, Range<usize>)>,
}

struct DeadGuard {
    span: Range<usize>,
    dummy: String,
    called: Option<String>,
}

#[must_use]
pub fn reverse_dead_code(source: &str) -> DeadCodeReversalResult {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return passthrough(source);
    }
    let mut analysis: Analysis = Analysis::default();
    analyze_block(&parsed.program.body, &mut analysis);

    let removable_guards: Vec<&DeadGuard> = analysis
        .dead_guards
        .iter()
        .filter(|g: &&DeadGuard| analysis.empty_functions.contains(&g.dummy))
        .collect();
    if removable_guards.is_empty() {
        return passthrough(source);
    }

    let guard_spans: Vec<Range<usize>> = removable_guards
        .iter()
        .map(|g: &&DeadGuard| g.span.clone())
        .collect();

    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    for span in &guard_spans {
        edits.push((span.clone(), Some(String::new())));
    }

    let mut dead_names: BTreeSet<String> = BTreeSet::new();
    for guard in &removable_guards {
        dead_names.insert(guard.dummy.clone());
        if let Some(called) = &guard.called {
            dead_names.insert(called.clone());
        }
    }

    let mut dead_functions_removed: usize = 0;
    for name in &dead_names {
        let Some(decl_span): Option<&Range<usize>> = analysis.function_decl_spans.get(name) else {
            continue;
        };
        let live_refs: usize = analysis
            .references
            .iter()
            .filter(|(ref_name, ref_span): &&(String, Range<usize>)| {
                ref_name == name
                    && !span_within(ref_span, decl_span)
                    && !span_within_any(ref_span, &guard_spans)
            })
            .count();
        if live_refs == 0 {
            edits.push((decl_span.clone(), Some(String::new())));
            dead_functions_removed += 1;
        }
    }

    let (rewritten, _applied): (String, usize) = apply_splice_edits(source, &mut edits);
    if !reparses(&rewritten) {
        return passthrough(source);
    }

    DeadCodeReversalResult {
        branches_removed: guard_spans.len(),
        dead_functions_removed,
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str) -> DeadCodeReversalResult {
    DeadCodeReversalResult {
        branches_removed: 0,
        dead_functions_removed: 0,
        rewritten_source: source.to_owned(),
    }
}

fn reparses(source: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    !parsed.panicked && parsed.errors.is_empty()
}

const fn span_within(inner: &Range<usize>, outer: &Range<usize>) -> bool {
    inner.start >= outer.start && inner.end <= outer.end
}

fn span_within_any(inner: &Range<usize>, outers: &[Range<usize>]) -> bool {
    outers.iter().any(|o: &Range<usize>| span_within(inner, o))
}

const fn span_range(span: oxc_span::Span) -> Range<usize> {
    span.start as usize..span.end as usize
}

fn analyze_block(stmts: &[oast::Statement<'_>], analysis: &mut Analysis) {
    for stmt in stmts {
        analyze_stmt(stmt, analysis);
    }
}

fn analyze_stmt(stmt: &oast::Statement<'_>, analysis: &mut Analysis) {
    match stmt {
        oast::Statement::FunctionDeclaration(func) => {
            if let Some(id) = &func.id {
                let name: String = id.name.to_string();
                analysis
                    .function_decl_spans
                    .insert(name.clone(), span_range(func.span));
                if function_body_is_empty(func) {
                    analysis.empty_functions.insert(name);
                }
            }
            if let Some(body) = &func.body {
                analyze_block(&body.statements, analysis);
            }
        }
        oast::Statement::IfStatement(if_stmt) => {
            if let Some(guard) = match_dead_guard(if_stmt) {
                analysis.dead_guards.push(guard);
            }
            collect_references_expr(&if_stmt.test, analysis);
            analyze_stmt(&if_stmt.consequent, analysis);
            if let Some(alt) = &if_stmt.alternate {
                analyze_stmt(alt, analysis);
            }
        }
        oast::Statement::BlockStatement(block) => analyze_block(&block.body, analysis),
        oast::Statement::ExpressionStatement(es) => {
            collect_references_expr(&es.expression, analysis);
        }
        oast::Statement::VariableDeclaration(decl) => {
            for d in &decl.declarations {
                if let Some(init) = &d.init {
                    collect_references_expr(init, analysis);
                }
            }
        }
        oast::Statement::ReturnStatement(rs) => {
            if let Some(arg) = &rs.argument {
                collect_references_expr(arg, analysis);
            }
        }
        oast::Statement::ForStatement(fs) => {
            if let Some(test) = &fs.test {
                collect_references_expr(test, analysis);
            }
            if let Some(update) = &fs.update {
                collect_references_expr(update, analysis);
            }
            analyze_stmt(&fs.body, analysis);
        }
        oast::Statement::WhileStatement(ws) => {
            collect_references_expr(&ws.test, analysis);
            analyze_stmt(&ws.body, analysis);
        }
        oast::Statement::DoWhileStatement(ws) => {
            collect_references_expr(&ws.test, analysis);
            analyze_stmt(&ws.body, analysis);
        }
        oast::Statement::SwitchStatement(sw) => {
            collect_references_expr(&sw.discriminant, analysis);
            for case in &sw.cases {
                if let Some(test) = &case.test {
                    collect_references_expr(test, analysis);
                }
                analyze_block(&case.consequent, analysis);
            }
        }
        oast::Statement::TryStatement(tr) => {
            analyze_block(&tr.block.body, analysis);
            if let Some(handler) = &tr.handler {
                analyze_block(&handler.body.body, analysis);
            }
            if let Some(finalizer) = &tr.finalizer {
                analyze_block(&finalizer.body, analysis);
            }
        }
        oast::Statement::LabeledStatement(ls) => analyze_stmt(&ls.body, analysis),
        oast::Statement::WithStatement(ws) => {
            collect_references_expr(&ws.object, analysis);
            analyze_stmt(&ws.body, analysis);
        }
        oast::Statement::ForInStatement(fs) => {
            collect_references_expr(&fs.right, analysis);
            analyze_stmt(&fs.body, analysis);
        }
        oast::Statement::ForOfStatement(fs) => {
            collect_references_expr(&fs.right, analysis);
            analyze_stmt(&fs.body, analysis);
        }
        oast::Statement::ThrowStatement(ts) => collect_references_expr(&ts.argument, analysis),
        _ => {}
    }
}

fn function_body_is_empty(func: &oast::Function<'_>) -> bool {
    func.body.as_ref().is_none_or(|b| {
        b.statements
            .iter()
            .all(|s: &oast::Statement<'_>| matches!(s, oast::Statement::EmptyStatement(_)))
    })
}

fn match_dead_guard(if_stmt: &oast::IfStatement<'_>) -> Option<DeadGuard> {
    if if_stmt.alternate.is_some() {
        return None;
    }
    let oast::Expression::BinaryExpression(bin) = &if_stmt.test else {
        return None;
    };
    if bin.operator != oast::BinaryOperator::In {
        return None;
    }
    if !matches!(&bin.left, oast::Expression::StringLiteral(_)) {
        return None;
    }
    let oast::Expression::Identifier(dummy_ref) = &bin.right else {
        return None;
    };
    let dummy: String = dummy_ref.name.to_string();
    let called: Option<String> = guard_call_target(&if_stmt.consequent);
    Some(DeadGuard {
        span: span_range(if_stmt.span),
        dummy,
        called,
    })
}

fn guard_call_target(consequent: &oast::Statement<'_>) -> Option<String> {
    let stmt: &oast::Statement<'_> = match consequent {
        oast::Statement::BlockStatement(block) => {
            let non_empty: Vec<&oast::Statement<'_>> = block
                .body
                .iter()
                .filter(|s: &&oast::Statement<'_>| !matches!(s, oast::Statement::EmptyStatement(_)))
                .collect();
            if non_empty.len() != 1 {
                return None;
            }
            non_empty[0]
        }
        other => other,
    };
    let oast::Statement::ExpressionStatement(es) = stmt else {
        return None;
    };
    let oast::Expression::CallExpression(call) = &es.expression else {
        return None;
    };
    if !call.arguments.is_empty() {
        return None;
    }
    let oast::Expression::Identifier(callee) = &call.callee else {
        return None;
    };
    Some(callee.name.to_string())
}

fn collect_references_expr(expr: &oast::Expression<'_>, analysis: &mut Analysis) {
    match expr {
        oast::Expression::Identifier(id) => {
            analysis
                .references
                .push((id.name.to_string(), span_range(id.span)));
        }
        oast::Expression::CallExpression(call) => {
            collect_references_expr(&call.callee, analysis);
            for arg in &call.arguments {
                if let Some(e) = arg.as_expression() {
                    collect_references_expr(e, analysis);
                }
            }
        }
        oast::Expression::NewExpression(new) => {
            collect_references_expr(&new.callee, analysis);
            for arg in &new.arguments {
                if let Some(e) = arg.as_expression() {
                    collect_references_expr(e, analysis);
                }
            }
        }
        oast::Expression::StaticMemberExpression(m) => collect_references_expr(&m.object, analysis),
        oast::Expression::ComputedMemberExpression(m) => {
            collect_references_expr(&m.object, analysis);
            collect_references_expr(&m.expression, analysis);
        }
        oast::Expression::BinaryExpression(b) => {
            collect_references_expr(&b.left, analysis);
            collect_references_expr(&b.right, analysis);
        }
        oast::Expression::LogicalExpression(l) => {
            collect_references_expr(&l.left, analysis);
            collect_references_expr(&l.right, analysis);
        }
        oast::Expression::UnaryExpression(u) => collect_references_expr(&u.argument, analysis),
        oast::Expression::UpdateExpression(u) => {
            if let Some(member) = u.argument.as_member_expression() {
                collect_references_member(member, analysis);
            } else if let oast::SimpleAssignmentTarget::AssignmentTargetIdentifier(id) = &u.argument
            {
                analysis
                    .references
                    .push((id.name.to_string(), span_range(id.span)));
            }
        }
        oast::Expression::ConditionalExpression(c) => {
            collect_references_expr(&c.test, analysis);
            collect_references_expr(&c.consequent, analysis);
            collect_references_expr(&c.alternate, analysis);
        }
        oast::Expression::AssignmentExpression(a) => {
            if let Some(member) = a.left.as_member_expression() {
                collect_references_member(member, analysis);
            } else if let oast::AssignmentTarget::AssignmentTargetIdentifier(id) = &a.left {
                analysis
                    .references
                    .push((id.name.to_string(), span_range(id.span)));
            }
            collect_references_expr(&a.right, analysis);
        }
        oast::Expression::SequenceExpression(s) => {
            for e in &s.expressions {
                collect_references_expr(e, analysis);
            }
        }
        oast::Expression::ParenthesizedExpression(p) => {
            collect_references_expr(&p.expression, analysis);
        }
        oast::Expression::ArrayExpression(a) => {
            for el in &a.elements {
                if let Some(e) = el.as_expression() {
                    collect_references_expr(e, analysis);
                }
            }
        }
        oast::Expression::ObjectExpression(o) => {
            for prop in &o.properties {
                if let oast::ObjectPropertyKind::ObjectProperty(p) = prop {
                    collect_references_expr(&p.value, analysis);
                }
            }
        }
        oast::Expression::FunctionExpression(f) => {
            if let Some(body) = &f.body {
                analyze_block(&body.statements, analysis);
            }
        }
        oast::Expression::ArrowFunctionExpression(a) => {
            analyze_block(&a.body.statements, analysis);
        }
        oast::Expression::TemplateLiteral(t) => {
            for e in &t.expressions {
                collect_references_expr(e, analysis);
            }
        }
        oast::Expression::AwaitExpression(a) => collect_references_expr(&a.argument, analysis),
        _ => {}
    }
}

fn collect_references_member(member: &oast::MemberExpression<'_>, analysis: &mut Analysis) {
    match member {
        oast::MemberExpression::ComputedMemberExpression(m) => {
            collect_references_expr(&m.object, analysis);
            collect_references_expr(&m.expression, analysis);
        }
        oast::MemberExpression::StaticMemberExpression(m) => {
            collect_references_expr(&m.object, analysis);
        }
        oast::MemberExpression::PrivateFieldExpression(m) => {
            collect_references_expr(&m.object, analysis);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_in_dummy_guard_and_dead_function() {
        let src: &str = "if(\"X\" in dummy){dead1()}\nfunction dead1(){console.log('nope')}\nfunction dummy(){}\nconsole.log('real');";
        let r: DeadCodeReversalResult = reverse_dead_code(src);
        assert_eq!(r.branches_removed, 1);
        assert!(r.dead_functions_removed >= 1);
        assert!(!r.rewritten_source.contains("dead1"));
        assert!(r.rewritten_source.contains("console.log('real')"));
    }

    #[test]
    fn leaves_real_in_guard_with_real_object() {
        let src: &str = "var obj = {X: 1};\nif(\"X\" in obj){ run(); }\n";
        let r: DeadCodeReversalResult = reverse_dead_code(src);
        assert_eq!(r.branches_removed, 0);
        assert_eq!(r.rewritten_source, src);
    }

    #[test]
    fn keeps_dead_fn_if_referenced_elsewhere() {
        let src: &str =
            "if(\"X\" in dummy){shared()}\nfunction shared(){}\nfunction dummy(){}\nshared();";
        let r: DeadCodeReversalResult = reverse_dead_code(src);
        assert_eq!(r.branches_removed, 1);
        assert!(
            r.rewritten_source.contains("function shared"),
            "shared is still called at top level and must be kept:\n{}",
            r.rewritten_source
        );
    }
}
