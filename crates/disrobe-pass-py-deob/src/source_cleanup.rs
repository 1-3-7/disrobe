use ruff_python_ast::{ModModule, Stmt, StmtClassDef, StmtFor, StmtFunctionDef, StmtIf, StmtWhile};
use ruff_python_codegen::{Generator, Stylist};
use ruff_python_parser::{Mode, ParseOptions, parse};
use serde::Serialize;

use crate::constant_fold::{self, FoldStats};
use crate::dead_branch;
use crate::error::{Error, Result};
use crate::fstring_recover;
use crate::junk_fn;
use crate::unrename;

const MAX_OUTER_PASSES: usize = 8;

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct CleanupStats {
    pub outer_passes: usize,
    pub fold_replacements: usize,
    pub if_eliminated: usize,
    pub while_eliminated: usize,
    pub branches_pruned: usize,
    pub unrename_replacements: usize,
    pub fstrings_recovered: usize,
    pub junk_fns_removed: usize,
    pub converged: bool,
}

pub fn cleanup_source(source: &str) -> Result<(String, CleanupStats)> {
    let mut current: String = source.to_owned();
    let mut stats: CleanupStats = CleanupStats::default();

    for outer in 0..MAX_OUTER_PASSES {
        stats.outer_passes = outer + 1;
        let parsed: ruff_python_parser::Parsed<ruff_python_ast::Mod> =
            parse(&current, ParseOptions::from(Mode::Module))
                .map_err(|e| Error::AstCleanup(format!("ruff parse failed: {e}")))?;
        let stylist: Stylist<'_> = Stylist::from_tokens(parsed.tokens(), &current);
        let mut module: ModModule = match parsed.into_syntax() {
            ruff_python_ast::Mod::Module(m) => m,
            ruff_python_ast::Mod::Expression(_) => {
                return Err(Error::AstCleanup(
                    "expected Module, got Expression".to_owned(),
                ));
            }
        };

        let fold_stats: FoldStats = walk_and_fold(&mut module);
        let unrename_stats: unrename::UnrenameStats = unrename::rewrite_getattr_calls(&mut module);
        let fstring_count: usize = fstring_recover::recover(&mut module);
        let prune_stats: dead_branch::PruneStats = dead_branch::prune(&mut module.body);
        let junk_count: usize = junk_fn::prune_junk_functions(&mut module);

        let mut emitted: String = String::with_capacity(current.len());
        let mut first: bool = true;
        for stmt in &module.body {
            if !first {
                emitted.push('\n');
            }
            first = false;
            let chunk: String = Generator::from(&stylist).stmt(stmt);
            emitted.push_str(&chunk);
        }

        stats.fold_replacements += fold_stats.replacements;
        stats.if_eliminated += prune_stats.if_eliminated;
        stats.while_eliminated += prune_stats.while_eliminated;
        stats.branches_pruned += prune_stats.branches_pruned;
        stats.unrename_replacements += unrename_stats.calls_rewritten;
        stats.fstrings_recovered += fstring_count;
        stats.junk_fns_removed += junk_count;

        let changed: bool = fold_stats.replacements > 0
            || prune_stats.if_eliminated > 0
            || prune_stats.while_eliminated > 0
            || prune_stats.branches_pruned > 0
            || unrename_stats.calls_rewritten > 0
            || fstring_count > 0
            || junk_count > 0;

        current = emitted;
        if !changed {
            stats.converged = true;
            break;
        }
    }
    Ok((current, stats))
}

fn walk_and_fold(module: &mut ModModule) -> FoldStats {
    let mut combined: FoldStats = FoldStats::default();
    fold_stmts(&mut module.body, &mut combined);
    combined
}

fn fold_stmts(stmts: &mut [Stmt], combined: &mut FoldStats) {
    for stmt in stmts.iter_mut() {
        fold_stmt(stmt, combined);
    }
}

fn fold_stmt(stmt: &mut Stmt, combined: &mut FoldStats) {
    use ruff_python_ast::Stmt as S;
    match stmt {
        S::Expr(e) => merge(combined, constant_fold::fold(&mut e.value)),
        S::Assign(a) => {
            for target in &mut a.targets {
                merge(combined, constant_fold::fold(target));
            }
            merge(combined, constant_fold::fold(&mut a.value));
        }
        S::AugAssign(a) => {
            merge(combined, constant_fold::fold(&mut a.target));
            merge(combined, constant_fold::fold(&mut a.value));
        }
        S::AnnAssign(a) => {
            merge(combined, constant_fold::fold(&mut a.target));
            merge(combined, constant_fold::fold(&mut a.annotation));
            if let Some(v) = a.value.as_mut() {
                merge(combined, constant_fold::fold(v));
            }
        }
        S::Return(r) => {
            if let Some(v) = r.value.as_mut() {
                merge(combined, constant_fold::fold(v));
            }
        }
        S::If(StmtIf {
            test,
            body,
            elif_else_clauses,
            ..
        }) => {
            merge(combined, constant_fold::fold(test));
            fold_stmts(body, combined);
            for clause in elif_else_clauses.iter_mut() {
                if let Some(t) = clause.test.as_mut() {
                    merge(combined, constant_fold::fold(t));
                }
                fold_stmts(&mut clause.body, combined);
            }
        }
        S::While(StmtWhile {
            test, body, orelse, ..
        }) => {
            merge(combined, constant_fold::fold(test));
            fold_stmts(body, combined);
            fold_stmts(orelse, combined);
        }
        S::For(StmtFor {
            target,
            iter,
            body,
            orelse,
            ..
        }) => {
            merge(combined, constant_fold::fold(target));
            merge(combined, constant_fold::fold(iter));
            fold_stmts(body, combined);
            fold_stmts(orelse, combined);
        }
        S::FunctionDef(StmtFunctionDef { body, .. }) | S::ClassDef(StmtClassDef { body, .. }) => {
            fold_stmts(body, combined);
        }
        _ => {}
    }
}

#[inline]
fn merge(target: &mut FoldStats, addition: FoldStats) {
    target.passes = target.passes.max(addition.passes);
    target.replacements += addition.replacements;
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn run(src: &str) -> String {
        let Ok((out, _stats)): Result<(String, CleanupStats)> = cleanup_source(src) else {
            panic!("cleanup_source failed for: {src}");
        };
        out
    }

    #[test]
    fn chr_concat_collapses_to_literal() {
        let out: String = run("x = chr(72) + chr(101) + chr(108) + chr(108) + chr(111)\n");
        assert!(
            out.contains("\"Hello\"") || out.contains("'Hello'"),
            "got: {out}"
        );
    }

    #[test]
    fn arith_collapses() {
        let out: String = run("x = 5 + 3 * 2\n");
        assert!(out.contains("11"), "got: {out}");
    }

    #[test]
    fn if_false_eliminated() {
        let out: String = run("if False:\n    a = 1\nelse:\n    b = 2\n");
        assert!(
            !out.contains("a = 1"),
            "if-false body should be removed; got: {out}"
        );
        assert!(out.contains("b = 2"), "else body should remain; got: {out}");
    }

    #[test]
    fn if_true_inlines_body() {
        let out: String = run("if True:\n    a = 1\nelse:\n    b = 2\n");
        assert!(
            out.contains("a = 1"),
            "if-true body must remain; got: {out}"
        );
        assert!(
            !out.contains("b = 2"),
            "else branch must be dropped; got: {out}"
        );
    }

    #[test]
    fn bytes_fromhex_collapses() {
        let out: String = run("data = bytes.fromhex(\"48656c6c6f\")\n");
        assert!(
            out.contains("Hello") || out.contains("b'"),
            "expected b'Hello' literal; got: {out}"
        );
    }

    #[test]
    fn while_false_dropped() {
        let out: String = run("while False:\n    print(1)\nx = 2\n");
        assert!(!out.contains("print(1)"), "got: {out}");
        assert!(out.contains("x = 2"), "got: {out}");
    }
}
