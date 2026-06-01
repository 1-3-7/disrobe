use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use ruff_python_ast::ExprContext;
use ruff_python_ast::name::Name;
use ruff_python_ast::visitor::transformer::{Transformer, walk_expr as walk_expr_mut};
use ruff_python_ast::visitor::{Visitor, walk_expr, walk_stmt};
use ruff_python_ast::{
    AtomicNodeIndex, Expr, ExprAttribute, ExprCall, ExprDict, ExprList, ExprName,
    ExprNumberLiteral, ExprStringLiteral, ExprSubscript, ExprTuple, ModModule, Number, Stmt,
    StmtAnnAssign, StmtAssign, StmtAugAssign, StmtDelete, StmtFor,
};
use ruff_text_size::Ranged;
use serde::Serialize;

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct UnrenameStats {
    pub calls_rewritten: usize,
    pub tables_used: usize,
    pub tables_invalidated: usize,
}

#[derive(Debug, Clone)]
enum ResolvedTable {
    Tuple(Vec<String>),
    Dict(BTreeMap<String, String>),
}

type Tables = BTreeMap<String, ResolvedTable>;

const BUILTIN_ALLOWLIST: &[&str] = &[
    "print",
    "len",
    "str",
    "int",
    "float",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "isinstance",
    "hasattr",
    "getattr",
    "setattr",
    "delattr",
    "callable",
    "type",
    "repr",
    "id",
    "range",
    "enumerate",
    "zip",
    "map",
    "filter",
    "sorted",
    "reversed",
    "abs",
    "min",
    "max",
    "sum",
    "all",
    "any",
    "open",
    "input",
    "ord",
    "chr",
    "hex",
    "oct",
    "bin",
    "hash",
    "iter",
    "next",
    "vars",
    "dir",
    "globals",
    "locals",
];

const MUTATING_METHODS: &[&str] = &[
    "append",
    "extend",
    "insert",
    "pop",
    "clear",
    "update",
    "remove",
    "sort",
    "reverse",
    "popitem",
    "setdefault",
    "__setitem__",
    "__delitem__",
];

pub(crate) fn rewrite_getattr_calls(module: &mut ModModule) -> UnrenameStats {
    let mut tables: Tables = collect_tables(&module.body);
    let initial: usize = tables.len();

    let mut invalidated: BTreeSet<String> = duplicate_top_level_names(&module.body);
    {
        let mut visitor: InvalidationVisitor<'_> = InvalidationVisitor {
            tables: &tables,
            invalidated: &mut invalidated,
        };
        for stmt in &module.body {
            visitor.visit_stmt(stmt);
        }
    }
    for name in &invalidated {
        tables.remove(name);
    }
    let tables_invalidated: usize = initial - tables.len();

    let rewriter: Rewriter<'_> = Rewriter {
        tables: &tables,
        used: RefCell::new(BTreeSet::new()),
        count: Cell::new(0),
    };
    for stmt in &mut module.body {
        rewriter.visit_stmt(stmt);
    }

    UnrenameStats {
        calls_rewritten: rewriter.count.get(),
        tables_used: rewriter.used.into_inner().len(),
        tables_invalidated,
    }
}

fn collect_tables(body: &[Stmt]) -> Tables {
    let mut out: Tables = BTreeMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for stmt in body {
        let Stmt::Assign(StmtAssign { targets, value, .. }) = stmt else {
            continue;
        };
        if targets.len() != 1 {
            continue;
        }
        let Expr::Name(ExprName { id, .. }) = &targets[0] else {
            continue;
        };
        let key: String = id.as_str().to_owned();
        if !seen.insert(key.clone()) {
            continue;
        }
        if let Some(table) = literal_table(value) {
            out.insert(key, table);
        }
    }
    out
}

fn duplicate_top_level_names(body: &[Stmt]) -> BTreeSet<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for stmt in body {
        let Stmt::Assign(StmtAssign { targets, .. }) = stmt else {
            continue;
        };
        if targets.len() != 1 {
            continue;
        }
        if let Expr::Name(ExprName { id, .. }) = &targets[0] {
            *counts.entry(id.as_str().to_owned()).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .filter_map(|(k, v)| (v > 1).then_some(k))
        .collect()
}

fn literal_table(value: &Expr) -> Option<ResolvedTable> {
    match value {
        Expr::Tuple(ExprTuple { elts, .. }) => {
            let items: Option<Vec<String>> = elts
                .iter()
                .map(|e| match e {
                    Expr::StringLiteral(ExprStringLiteral { value, .. }) => {
                        Some(value.to_str().to_owned())
                    }
                    _ => None,
                })
                .collect();
            items.map(ResolvedTable::Tuple)
        }
        Expr::Dict(ExprDict { items, .. }) => {
            let mut map: BTreeMap<String, String> = BTreeMap::new();
            for item in items {
                let key: &Expr = item.key.as_ref()?;
                let Expr::StringLiteral(ExprStringLiteral { value: k, .. }) = key else {
                    return None;
                };
                let Expr::StringLiteral(ExprStringLiteral { value: v, .. }) = &item.value else {
                    return None;
                };
                map.insert(k.to_str().to_owned(), v.to_str().to_owned());
            }
            Some(ResolvedTable::Dict(map))
        }
        _ => None,
    }
}

#[derive(Debug)]
struct InvalidationVisitor<'a> {
    tables: &'a Tables,
    invalidated: &'a mut BTreeSet<String>,
}

impl InvalidationVisitor<'_> {
    fn mark(&mut self, name: &str) {
        if self.tables.contains_key(name) {
            self.invalidated.insert(name.to_owned());
        }
    }

    fn mark_subscript_or_attr_target(&mut self, target: &Expr) {
        if let Expr::Subscript(ExprSubscript { value, .. })
        | Expr::Attribute(ExprAttribute { value, .. }) = target
            && let Expr::Name(ExprName { id, .. }) = value.as_ref()
        {
            self.mark(id.as_str());
        }
    }

    fn mark_target_for_assign_like(&mut self, target: &Expr) {
        match target {
            Expr::Subscript(_) | Expr::Attribute(_) => self.mark_subscript_or_attr_target(target),
            Expr::Tuple(ExprTuple { elts, .. }) | Expr::List(ExprList { elts, .. }) => {
                for e in elts {
                    self.mark_target_for_assign_like(e);
                }
            }
            _ => {}
        }
    }
}

impl<'a> Visitor<'a> for InvalidationVisitor<'a> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::Assign(StmtAssign { targets, .. }) => {
                for target in targets {
                    self.mark_target_for_assign_like(target);
                }
            }
            Stmt::AugAssign(StmtAugAssign { target, .. })
            | Stmt::AnnAssign(StmtAnnAssign { target, .. }) => {
                if let Expr::Name(ExprName { id, .. }) = target.as_ref() {
                    self.mark(id.as_str());
                }
                self.mark_subscript_or_attr_target(target);
            }
            Stmt::Delete(StmtDelete { targets, .. }) => {
                for t in targets {
                    if let Expr::Name(ExprName { id, .. }) = t {
                        self.mark(id.as_str());
                    }
                    self.mark_subscript_or_attr_target(t);
                }
            }
            Stmt::For(StmtFor { target, .. }) => {
                if let Expr::Name(ExprName { id, .. }) = target.as_ref() {
                    self.mark(id.as_str());
                }
            }
            _ => {}
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        if let Expr::Call(ExprCall { func, .. }) = expr
            && let Expr::Attribute(ExprAttribute { value, attr, .. }) = func.as_ref()
            && let Expr::Name(ExprName { id, .. }) = value.as_ref()
            && MUTATING_METHODS.contains(&attr.as_str())
        {
            self.mark(id.as_str());
        }
        walk_expr(self, expr);
    }
}

#[derive(Debug)]
struct Rewriter<'a> {
    tables: &'a Tables,
    used: RefCell<BTreeSet<String>>,
    count: Cell<usize>,
}

impl Transformer for Rewriter<'_> {
    fn visit_expr(&self, expr: &mut Expr) {
        walk_expr_mut(self, expr);
        if let Expr::Call(call) = expr
            && let Some(resolved) = self.try_resolve_getattr_call(call)
        {
            *expr = resolved;
            self.count.set(self.count.get() + 1);
        }
    }
}

impl Rewriter<'_> {
    fn try_resolve_getattr_call(&self, call: &ExprCall) -> Option<Expr> {
        let Expr::Name(ExprName { id, .. }) = call.func.as_ref() else {
            return None;
        };
        if id.as_str() != "getattr" {
            return None;
        }
        if !call.arguments.keywords.is_empty() || call.arguments.args.len() != 2 {
            return None;
        }
        let Expr::Name(ExprName { id: first_id, .. }) = call.arguments.args.first()? else {
            return None;
        };
        let first_name: &str = first_id.as_str();
        if first_name != "__builtins__" && first_name != "builtins" {
            return None;
        }
        let second: &Expr = call.arguments.args.get(1)?;
        let resolved_name: String = self.resolve_attr_name(second)?;
        if !BUILTIN_ALLOWLIST.contains(&resolved_name.as_str()) {
            return None;
        }

        let new_func: Expr = Expr::Name(ExprName {
            range: call.func.range(),
            node_index: AtomicNodeIndex::default(),
            id: Name::new(&resolved_name),
            ctx: ExprContext::Load,
        });
        let mut new_args: ruff_python_ast::Arguments = call.arguments.clone();
        new_args.args = call.arguments.args.iter().skip(2).cloned().collect();

        Some(Expr::Call(ExprCall {
            range: call.range,
            node_index: AtomicNodeIndex::default(),
            func: Box::new(new_func),
            arguments: new_args,
        }))
    }

    fn resolve_attr_name(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::StringLiteral(ExprStringLiteral { value, .. }) => Some(value.to_str().to_owned()),
            Expr::Subscript(ExprSubscript { value, slice, .. }) => {
                let Expr::Name(ExprName { id, .. }) = value.as_ref() else {
                    return None;
                };
                let table: &ResolvedTable = self.tables.get(id.as_str())?;
                let resolved: String = match (table, slice.as_ref()) {
                    (
                        ResolvedTable::Tuple(items),
                        Expr::NumberLiteral(ExprNumberLiteral {
                            value: Number::Int(n),
                            ..
                        }),
                    ) => {
                        let idx: usize = n.to_string().parse().ok()?;
                        items.get(idx).cloned()
                    }
                    (
                        ResolvedTable::Dict(map),
                        Expr::StringLiteral(ExprStringLiteral { value: key, .. }),
                    ) => map.get(key.to_str()).cloned(),
                    _ => None,
                }?;
                self.used.borrow_mut().insert(id.as_str().to_owned());
                Some(resolved)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use crate::source_cleanup::cleanup_source;

    fn run(src: &str) -> String {
        let Ok((out, _stats)): crate::error::Result<(String, crate::source_cleanup::CleanupStats)> =
            cleanup_source(src)
        else {
            panic!("cleanup failed for: {src}");
        };
        out
    }

    #[test]
    fn direct_getattr_with_string_literal() {
        let out: String = run("getattr(__builtins__, 'print')('hi')\n");
        assert!(
            out.contains("print(") && !out.contains("getattr"),
            "got: {out}"
        );
        assert!(out.contains("'hi'") || out.contains("\"hi\""), "got: {out}");
    }

    #[test]
    fn tuple_subscript_resolution() {
        let out: String = run("_T = ('print', 'len')\ngetattr(__builtins__, _T[0])('x')\n");
        assert!(
            out.contains("print(") && !out.contains("getattr"),
            "got: {out}"
        );
    }

    #[test]
    fn dict_subscript_resolution() {
        let out: String = run("_M = {'p': 'print'}\ngetattr(__builtins__, _M['p'])('x')\n");
        assert!(
            out.contains("print(") && !out.contains("getattr"),
            "got: {out}"
        );
    }

    #[test]
    fn reassigned_table_not_resolved() {
        let out: String =
            run("_T = ('print',)\n_T = ('NOT REAL',)\ngetattr(__builtins__, _T[0])('x')\n");
        assert!(
            out.contains("getattr"),
            "must NOT rewrite when table reassigned; got: {out}"
        );
    }
}
