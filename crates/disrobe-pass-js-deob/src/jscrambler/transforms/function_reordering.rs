use core::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Program, Statement};
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};

use super::walk::for_each_expression_deep;
use super::{TransformOpts, TransformOutput, TransformStats};
use crate::error::{Error, Result};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let Some(plan): Option<ReversePlan> = analyze(source) else {
        return 0;
    };
    usize::from(plan.reordered)
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
            "functionReordering: source did not parse as JavaScript".to_owned(),
        ));
    };
    Ok(apply(source, &plan))
}

#[derive(Debug, Clone)]
struct FnDecl {
    name: String,
    span: Span,
    refers_to: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct ReversePlan {
    decls: Vec<FnDecl>,
    order: Vec<usize>,
    reordered: bool,
}

fn analyze(source: &str) -> Option<ReversePlan> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return None;
    }
    let program: &Program<'_> = &parsed.program;

    let mut decls: Vec<FnDecl> = Vec::new();
    let mut decl_indices: Vec<usize> = Vec::new();
    for (index, stmt) in program.body.iter().enumerate() {
        if let Statement::FunctionDeclaration(func) = stmt
            && let Some(id) = func.id.as_ref()
        {
            decls.push(FnDecl {
                name: id.name.as_str().to_owned(),
                span: func.span,
                refers_to: BTreeSet::new(),
            });
            decl_indices.push(index);
        }
    }
    if decls.len() < 2 {
        return Some(ReversePlan::default());
    }
    if !is_contiguous(&decl_indices) {
        return Some(ReversePlan::default());
    }

    let names: BTreeSet<String> = decls.iter().map(|d: &FnDecl| d.name.clone()).collect();
    for stmt in &program.body {
        let Statement::FunctionDeclaration(func) = stmt else {
            continue;
        };
        let Some(id) = func.id.as_ref() else {
            continue;
        };
        let owner: String = id.name.as_str().to_owned();
        let mut refs: BTreeSet<String> = BTreeSet::new();
        collect_referenced_names(stmt, &names, &owner, &mut refs);
        if let Some(decl) = decls.iter_mut().find(|d: &&mut FnDecl| d.name == owner) {
            decl.refers_to = refs;
        }
    }

    let order: Vec<usize> = dependency_order(&decls);
    let identity: Vec<usize> = (0..decls.len()).collect();
    Some(ReversePlan {
        reordered: order != identity,
        decls,
        order,
    })
}

fn collect_referenced_names(
    stmt: &Statement<'_>,
    names: &BTreeSet<String>,
    owner: &str,
    out: &mut BTreeSet<String>,
) {
    for_each_expression_deep(stmt, &mut |expr: &Expression<'_>| {
        if let Expression::Identifier(ident) = expr {
            let name: &str = ident.name.as_str();
            if name != owner && names.contains(name) {
                out.insert(name.to_owned());
            }
        }
    });
}

const fn is_contiguous(indices: &[usize]) -> bool {
    match (indices.first(), indices.last()) {
        (Some(&first), Some(&last)) => last - first + 1 == indices.len(),
        _ => false,
    }
}

fn dependency_order(decls: &[FnDecl]) -> Vec<usize> {
    let name_to_idx: BTreeMap<&str, usize> = decls
        .iter()
        .enumerate()
        .map(|(i, d): (usize, &FnDecl)| (d.name.as_str(), i))
        .collect();
    let mut indeg: Vec<usize> = vec![0; decls.len()];
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); decls.len()];
    for (i, d) in decls.iter().enumerate() {
        for referenced in &d.refers_to {
            if let Some(&j) = name_to_idx.get(referenced.as_str())
                && j != i
            {
                adj[j].push(i);
                indeg[i] += 1;
            }
        }
    }
    let mut ready: BinaryHeap<Reverse<usize>> = (0..decls.len())
        .filter(|i: &usize| indeg[*i] == 0)
        .map(Reverse)
        .collect();
    let mut out: Vec<usize> = Vec::with_capacity(decls.len());
    while let Some(Reverse(node)) = ready.pop() {
        out.push(node);
        for &m in &adj[node] {
            indeg[m] -= 1;
            if indeg[m] == 0 {
                ready.push(Reverse(m));
            }
        }
    }
    if out.len() != decls.len() {
        return (0..decls.len()).collect();
    }
    out
}

fn apply(source: &str, plan: &ReversePlan) -> TransformOutput {
    let mut stats: TransformStats = TransformStats::default();
    if !plan.reordered || plan.decls.len() < 2 {
        return TransformOutput::noop(source);
    }
    stats.matched = 1;
    let first_start: usize = plan.decls[0].span.start as usize;
    let last_end: usize = plan
        .decls
        .last()
        .map_or(0, |d: &FnDecl| d.span.end as usize);
    if first_start >= last_end || last_end > source.len() {
        return TransformOutput::noop(source);
    }

    let mut rebuilt: String = String::new();
    for (position, &target) in plan.order.iter().enumerate() {
        let span: Span = plan.decls[target].span;
        let snippet: &str = span.source_text(source).trim();
        rebuilt.push_str(snippet);
        if position + 1 != plan.order.len() {
            rebuilt.push('\n');
        }
    }

    let mut out: String = String::with_capacity(source.len());
    out.push_str(&source[..first_start]);
    out.push_str(&rebuilt);
    out.push_str(&source[last_end..]);
    stats.reversed = 1;
    TransformOutput { source: out, stats }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn no_op_on_single_function() {
        let src: &str = "function a(){}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }

    #[test]
    fn reorders_when_deps_inverted() {
        let src: &str = "function b(){return a();}\nfunction a(){return 1;}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        let a_pos: usize = out.source.find("function a(").unwrap();
        let b_pos: usize = out.source.find("function b(").unwrap();
        assert!(
            a_pos < b_pos,
            "callee a must precede caller b:\n{}",
            out.source
        );
    }

    #[test]
    fn keeps_order_when_already_ordered() {
        let src: &str = "function a(){return 1;}\nfunction b(){return a();}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }

    #[test]
    fn returns_typed_error_in_strict_mode_on_parse_failure() {
        let res: Result<TransformOutput> = reverse_strict("function (", &TransformOpts::default());
        assert!(res.is_err());
    }

    #[test]
    fn empty_source_is_noop_not_error() {
        let res: Result<TransformOutput> = reverse_strict("", &TransformOpts::default());
        assert!(res.is_ok());
        assert_eq!(res.unwrap().source, "");
    }

    #[test]
    fn detect_flags_misordered_pair() {
        let src: &str = "function b(){return a();}\nfunction a(){return 1;}";
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn non_eager_reference_still_orders_dependency() {
        let src: &str = "function b(){var r = a; return r();}\nfunction a(){return 1;}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        let a_pos: usize = out.source.find("function a(").unwrap();
        let b_pos: usize = out.source.find("function b(").unwrap();
        assert!(
            a_pos < b_pos,
            "a referenced non-eagerly by b must still be ordered first:\n{}",
            out.source
        );
    }

    #[test]
    fn does_not_reorder_across_interleaved_statement() {
        let src: &str = "function b(){return a();}\nvar between = 1;\nfunction a(){return 1;}";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(
            out.source, src,
            "reordering must not splice across a non-function statement and drop it:\n{}",
            out.source
        );
    }
}
