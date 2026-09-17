use core::cmp::Reverse;
use std::collections::BTreeMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BindingPatternKind, CallExpression, Expression, Function, Program, Statement,
    VariableDeclaration,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};

use super::walk::for_each_expression_deep;
use super::{TransformOpts, TransformOutput, TransformStats};
use crate::error::{Error, Result};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    analyze(source).map_or(0, |plan: ReversePlan| plan.candidates.len())
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let Some(plan): Option<ReversePlan> = analyze(source) else {
        let stats: TransformStats = TransformStats {
            errors: vec!["parse-failed".to_owned()],
            ..TransformStats::default()
        };
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    };
    apply(source, &plan)
}

pub(in crate::jscrambler) fn reverse_strict(
    source: &str,
    _opts: &TransformOpts,
) -> Result<TransformOutput> {
    let Some(plan): Option<ReversePlan> = analyze(source) else {
        return Err(Error::OxcParse(
            "functionOutlining: source did not parse as JavaScript".to_owned(),
        ));
    };
    Ok(apply(source, &plan))
}

#[derive(Debug, Clone)]
struct Candidate {
    decl_span: Span,
    call_span: Span,
    body_expr: String,
}

#[derive(Debug, Default)]
struct ReversePlan {
    candidates: Vec<Candidate>,
}

fn analyze(source: &str) -> Option<ReversePlan> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return None;
    }
    let program: &Program<'_> = &parsed.program;

    let mut outlined: BTreeMap<String, OutlinedFn> = BTreeMap::new();
    for stmt in &program.body {
        collect_outlined(stmt, source, &mut outlined);
    }
    if outlined.is_empty() {
        return Some(ReversePlan::default());
    }

    let mut usage: BTreeMap<String, Vec<Usage>> = BTreeMap::new();
    for stmt in &program.body {
        collect_usages(stmt, &outlined, &mut usage);
    }

    let mut candidates: Vec<Candidate> = Vec::new();
    for (name, info) in &outlined {
        let Some(uses): Option<&Vec<Usage>> = usage.get(name) else {
            continue;
        };
        let deduped: Vec<Usage> = dedupe_usages(uses);
        let outside_decl: Vec<&Usage> = deduped
            .iter()
            .filter(|u: &&Usage| !span_within(u.span, info.decl_span))
            .collect();
        if outside_decl.len() != 1 {
            continue;
        }
        let single: &Usage = outside_decl[0];
        if !single.is_zero_arg_callee {
            continue;
        }
        candidates.push(Candidate {
            decl_span: info.decl_span,
            call_span: single.call_span,
            body_expr: info.body_expr.clone(),
        });
    }
    candidates.sort_by_key(|c: &Candidate| c.decl_span.start);
    Some(ReversePlan { candidates })
}

fn apply(source: &str, plan: &ReversePlan) -> TransformOutput {
    let mut stats: TransformStats = TransformStats {
        matched: plan.candidates.len(),
        ..TransformStats::default()
    };
    if plan.candidates.is_empty() {
        return TransformOutput::noop(source);
    }
    let mut edits: Vec<(Span, String)> = Vec::new();
    for candidate in &plan.candidates {
        edits.push((candidate.call_span, format!("({})", candidate.body_expr)));
        edits.push((candidate.decl_span, String::new()));
    }
    edits.sort_by_key(|e: &(Span, String)| Reverse(e.0.start));
    let mut out: String = source.to_owned();
    let mut last_start: usize = out.len() + 1;
    for (span, replacement) in &edits {
        let start: usize = span.start as usize;
        let end: usize = span.end as usize;
        if start > end || end > last_start || end > out.len() {
            continue;
        }
        if !out.is_char_boundary(start) || !out.is_char_boundary(end) {
            continue;
        }
        out.replace_range(start..end, replacement);
        last_start = start;
        stats.reversed += 1;
    }
    TransformOutput { source: out, stats }
}

#[derive(Debug, Clone)]
struct OutlinedFn {
    decl_span: Span,
    body_expr: String,
}

fn collect_outlined(stmt: &Statement<'_>, source: &str, out: &mut BTreeMap<String, OutlinedFn>) {
    match stmt {
        Statement::FunctionDeclaration(func) => {
            if let Some((name, info)) = outlined_from_function(func, func.span, source) {
                out.insert(name, info);
            }
        }
        Statement::VariableDeclaration(decl) => collect_outlined_var(decl, source, out),
        _ => {}
    }
}

fn collect_outlined_var(
    decl: &VariableDeclaration<'_>,
    source: &str,
    out: &mut BTreeMap<String, OutlinedFn>,
) {
    if decl.declarations.len() != 1 {
        return;
    }
    let declarator: &oxc_ast::ast::VariableDeclarator<'_> = &decl.declarations[0];
    let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
        return;
    };
    let Some(Expression::FunctionExpression(func)): Option<&Expression<'_>> =
        declarator.init.as_ref()
    else {
        return;
    };
    let Some(expr): Option<String> = single_return_expr(func, source) else {
        return;
    };
    out.insert(
        binding.name.as_str().to_owned(),
        OutlinedFn {
            decl_span: decl.span,
            body_expr: expr,
        },
    );
}

fn outlined_from_function(
    func: &Function<'_>,
    decl_span: Span,
    source: &str,
) -> Option<(String, OutlinedFn)> {
    let name: &str = func.id.as_ref()?.name.as_str();
    let expr: String = single_return_expr(func, source)?;
    Some((
        name.to_owned(),
        OutlinedFn {
            decl_span,
            body_expr: expr,
        },
    ))
}

fn single_return_expr(func: &Function<'_>, source: &str) -> Option<String> {
    if !func.params.items.is_empty() || func.params.rest.is_some() {
        return None;
    }
    if func.generator || func.r#async {
        return None;
    }
    let body: &oxc_ast::ast::FunctionBody<'_> = func.body.as_ref()?;
    if body.statements.len() != 1 {
        return None;
    }
    let Statement::ReturnStatement(ret): &Statement<'_> = &body.statements[0] else {
        return None;
    };
    let argument: &Expression<'_> = ret.argument.as_ref()?;
    let text: &str = argument.span().source_text(source).trim();
    if text.is_empty() || text.contains('\n') {
        return None;
    }
    Some(text.to_owned())
}

#[derive(Debug, Clone, Copy)]
struct Usage {
    span: Span,
    call_span: Span,
    is_zero_arg_callee: bool,
}

fn collect_usages(
    stmt: &Statement<'_>,
    names: &BTreeMap<String, OutlinedFn>,
    usage: &mut BTreeMap<String, Vec<Usage>>,
) {
    for_each_expression_deep(stmt, &mut |expr: &Expression<'_>| {
        record_expression(expr, names, usage);
    });
}

fn record_expression(
    expr: &Expression<'_>,
    names: &BTreeMap<String, OutlinedFn>,
    usage: &mut BTreeMap<String, Vec<Usage>>,
) {
    match expr {
        Expression::CallExpression(call) => record_call(call, names, usage),
        Expression::Identifier(ident) => {
            let name: &str = ident.name.as_str();
            if names.contains_key(name) {
                usage.entry(name.to_owned()).or_default().push(Usage {
                    span: ident.span,
                    call_span: ident.span,
                    is_zero_arg_callee: false,
                });
            }
        }
        _ => {}
    }
}

fn record_call(
    call: &CallExpression<'_>,
    names: &BTreeMap<String, OutlinedFn>,
    usage: &mut BTreeMap<String, Vec<Usage>>,
) {
    let Expression::Identifier(callee): &Expression<'_> = &call.callee else {
        return;
    };
    let name: &str = callee.name.as_str();
    if !names.contains_key(name) {
        return;
    }
    let is_zero_arg: bool = call.arguments.is_empty() && !call.optional;
    usage.entry(name.to_owned()).or_default().push(Usage {
        span: callee.span,
        call_span: call.span,
        is_zero_arg_callee: is_zero_arg,
    });
}

fn dedupe_usages(uses: &[Usage]) -> Vec<Usage> {
    let mut by_start: Vec<Usage> = Vec::new();
    for usage in uses {
        match by_start
            .iter_mut()
            .find(|u: &&mut Usage| u.span.start == usage.span.start)
        {
            Some(existing) if usage.is_zero_arg_callee => *existing = *usage,
            Some(_) => {}
            None => by_start.push(*usage),
        }
    }
    by_start
}

const fn span_within(inner: Span, outer: Span) -> bool {
    inner.start >= outer.start && inner.end <= outer.end
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_finds_single_callsite_outlined_function() {
        let src: &str = "function _outlined1(){return 42;} var x = _outlined1();";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn inlines_single_callsite_outlined_function() {
        let src: &str = "function _o1(){return 42;} var x = _o1();";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.stats.reversed >= 1);
        assert!(out.source.contains("(42)"));
        assert!(!out.source.contains("_o1()"));
    }

    #[test]
    fn skips_multi_callsite_function() {
        let src: &str = "function _o2(){return 1;} var a = _o2(); var b = _o2();";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 0);
    }

    #[test]
    fn handles_var_function_form() {
        let src: &str = "var _o3 = function(){return globalThis;}; var g = _o3();";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.stats.reversed >= 1);
        assert!(out.source.contains("(globalThis)"));
    }

    #[test]
    fn skips_non_eager_reference() {
        let src: &str = "function _o5(){return 7;} var ref = _o5; var x = _o5();";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(
            out.stats.reversed, 0,
            "a function also stored as a value must not be inlined"
        );
    }

    #[test]
    fn skips_callsite_with_arguments() {
        let src: &str = "function _o6(){return 7;} var x = _o6(1);";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 0);
    }

    #[test]
    fn counts_references_inside_nested_function_bodies() {
        let src: &str =
            "function _o7(){return 7;} var a = _o7(); var f = function(){ return _o7(); };";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(
            out.stats.reversed, 0,
            "a second call inside a nested function expression must be counted, blocking inline:\n{}",
            out.source
        );
    }

    #[test]
    fn returns_typed_error_in_strict_mode_on_parse_failure() {
        let res: Result<TransformOutput> = reverse_strict("function (", &TransformOpts::default());
        assert!(res.is_err());
    }

    #[test]
    fn reverse_is_noop_when_nothing_matches() {
        let src: &str = "var x = 1;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
        assert_eq!(out.stats.matched, 0);
    }
}
