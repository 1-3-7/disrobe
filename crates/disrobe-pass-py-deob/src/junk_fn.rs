use std::collections::{BTreeMap, BTreeSet};

use ruff_python_ast::visitor::{Visitor, walk_expr, walk_stmt};
use ruff_python_ast::{
    Expr, ExprBytesLiteral, ExprName, ExprStringLiteral, ModModule, Stmt, StmtAssign,
    StmtAugAssign, StmtFunctionDef,
};

const EXPORT_NAME: &str = "__all__";

pub(crate) fn prune_junk_functions(module: &mut ModModule) -> usize {
    let candidates: BTreeSet<String> = candidate_definitions(&module.body);
    if candidates.is_empty() {
        return 0;
    }
    let exported: BTreeSet<String> = exported_names(&module.body);
    let references: BTreeMap<String, usize> = NameReferenceCounter::run(module, &candidates);

    let mut removable: BTreeSet<String> = BTreeSet::new();
    for name in &candidates {
        if exported.contains(name) {
            continue;
        }
        if references.get(name).copied().unwrap_or(0) == 0 {
            removable.insert(name.clone());
        }
    }
    if removable.is_empty() {
        return 0;
    }

    let original_len: usize = module.body.len();
    module
        .body
        .retain(|stmt| !is_removable_def(stmt, &removable));
    original_len - module.body.len()
}

fn candidate_definitions(body: &[Stmt]) -> BTreeSet<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for stmt in body {
        if let Stmt::FunctionDef(def) = stmt
            && is_eligible_def(def)
        {
            *counts.entry(def.name.as_str().to_owned()).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .filter_map(|(name, count)| (count == 1).then_some(name))
        .collect()
}

#[inline]
fn is_eligible_def(def: &StmtFunctionDef) -> bool {
    let name: &str = def.name.as_str();
    if name.starts_with("__") || name == "main" {
        return false;
    }
    if !def.decorator_list.is_empty() {
        return false;
    }
    if def.is_async {
        return false;
    }
    true
}

fn exported_names(body: &[Stmt]) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for stmt in body {
        let assigned_value: &Expr = match stmt {
            Stmt::Assign(StmtAssign { targets, value, .. }) => {
                if targets.len() != 1 {
                    continue;
                }
                let Expr::Name(ExprName { id, .. }) = &targets[0] else {
                    continue;
                };
                if id.as_str() != EXPORT_NAME {
                    continue;
                }
                value
            }
            Stmt::AugAssign(StmtAugAssign { target, value, .. }) => {
                let Expr::Name(ExprName { id, .. }) = target.as_ref() else {
                    continue;
                };
                if id.as_str() != EXPORT_NAME {
                    continue;
                }
                value
            }
            _ => continue,
        };
        collect_export_strings(assigned_value, &mut out);
    }
    out
}

fn collect_export_strings(expr: &Expr, out: &mut BTreeSet<String>) {
    match expr {
        Expr::List(list) => {
            for e in &list.elts {
                collect_export_strings(e, out);
            }
        }
        Expr::Tuple(tuple) => {
            for e in &tuple.elts {
                collect_export_strings(e, out);
            }
        }
        Expr::StringLiteral(ExprStringLiteral { value, .. }) => {
            out.insert(value.to_str().to_owned());
        }
        Expr::BytesLiteral(ExprBytesLiteral { value, .. }) => {
            for chunk in value {
                if let Ok(s) = std::str::from_utf8(&chunk.value) {
                    out.insert(s.to_owned());
                }
            }
        }
        _ => {}
    }
}

#[derive(Debug)]
struct NameReferenceCounter<'a> {
    interesting: &'a BTreeSet<String>,
    counts: BTreeMap<String, usize>,
    skip_def_for: Option<&'a str>,
}

impl<'a> NameReferenceCounter<'a> {
    fn run(module: &'a ModModule, interesting: &'a BTreeSet<String>) -> BTreeMap<String, usize> {
        let mut counter: Self = Self {
            interesting,
            counts: BTreeMap::new(),
            skip_def_for: None,
        };
        for stmt in &module.body {
            counter.visit_stmt(stmt);
        }
        counter.counts
    }
}

impl<'a> Visitor<'a> for NameReferenceCounter<'a> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        if let Stmt::FunctionDef(def) = stmt
            && self.interesting.contains(def.name.as_str())
        {
            let outer: Option<&'a str> = self.skip_def_for;
            self.skip_def_for = Some(def.name.as_str());
            for child in &def.body {
                self.visit_stmt(child);
            }
            for arg in def
                .parameters
                .args
                .iter()
                .chain(def.parameters.kwonlyargs.iter())
            {
                if let Some(d) = arg.default.as_deref() {
                    self.visit_expr(d);
                }
            }
            self.skip_def_for = outer;
            return;
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        if let Expr::Name(ExprName { id, .. }) = expr {
            let name: &str = id.as_str();
            if self.interesting.contains(name) && self.skip_def_for != Some(name) {
                *self.counts.entry(name.to_owned()).or_default() += 1;
            }
        }
        walk_expr(self, expr);
    }
}

#[inline]
fn is_removable_def(stmt: &Stmt, removable: &BTreeSet<String>) -> bool {
    let Stmt::FunctionDef(def) = stmt else {
        return false;
    };
    if !def.decorator_list.is_empty() {
        return false;
    }
    removable.contains(def.name.as_str())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use crate::source_cleanup::cleanup_source;

    fn run(src: &str) -> String {
        let Ok((out, _stats)): crate::error::Result<(String, crate::source_cleanup::CleanupStats)> =
            cleanup_source(src)
        else {
            panic!("cleanup failed: {src}");
        };
        out
    }

    #[test]
    fn removes_uncalled_function() {
        let src: &str = "def junk():\n    return 1\n\nprint('hi')\n";
        let out: String = run(src);
        assert!(
            !out.contains("def junk"),
            "junk fn should be removed: {out}"
        );
        assert!(out.contains("print"), "main code preserved: {out}");
    }

    #[test]
    fn keeps_called_function() {
        let src: &str = "def useful():\n    return 1\n\nuseful()\n";
        let out: String = run(src);
        assert!(out.contains("def useful"), "called fn must stay: {out}");
    }

    #[test]
    fn keeps_exported_function() {
        let src: &str = "__all__ = ['api']\n\ndef api():\n    return 1\n";
        let out: String = run(src);
        assert!(out.contains("def api"), "exported fn must stay: {out}");
    }

    #[test]
    fn keeps_decorated_function() {
        let src: &str = "import functools\n\n@functools.lru_cache\ndef cached():\n    return 1\n\nprint('go')\n";
        let out: String = run(src);
        assert!(out.contains("def cached"), "decorated fn must stay: {out}");
    }

    #[test]
    fn keeps_dunder_function() {
        let src: &str = "def __init_subclass__():\n    pass\n\nprint('x')\n";
        let out: String = run(src);
        assert!(out.contains("__init_subclass__"), "dunder must stay: {out}");
    }

    #[test]
    fn removes_self_referential_only() {
        let src: &str = "def lonely():\n    return lonely\n\nprint('x')\n";
        let out: String = run(src);
        assert!(
            !out.contains("def lonely"),
            "self-only fn must be removed: {out}"
        );
    }

    #[test]
    fn keeps_main_function() {
        let src: &str = "def main():\n    pass\n\nprint('x')\n";
        let out: String = run(src);
        assert!(out.contains("def main"), "main fn must stay: {out}");
    }

    #[test]
    fn removes_unused_among_multiple() {
        let src: &str = "def alpha():\n    return 1\n\ndef beta():\n    return 2\n\nbeta()\n";
        let out: String = run(src);
        assert!(!out.contains("def alpha"), "alpha must go: {out}");
        assert!(out.contains("def beta"), "beta must stay: {out}");
    }
}
