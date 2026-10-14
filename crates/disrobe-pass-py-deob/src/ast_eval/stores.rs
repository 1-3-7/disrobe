use std::collections::{BTreeMap, BTreeSet};

use ruff_python_ast::visitor::{Visitor, walk_expr, walk_pattern, walk_stmt};
use ruff_python_ast::{
    ExceptHandler, Expr, ExprContext, ExprName, Pattern, PatternMatchAs, PatternMatchMapping,
    PatternMatchStar, Stmt,
};

#[derive(Default)]
struct StoreCounter {
    counts: BTreeMap<String, usize>,
    unstable: BTreeSet<String>,
    escaping: BTreeSet<String>,
    nested_depth: usize,
}

impl StoreCounter {
    fn store(&mut self, name: &str) {
        if self.nested_depth == 0 {
            *self.counts.entry(name.to_owned()).or_default() += 1;
        }
    }

    fn unstable(&mut self, name: &str) {
        self.unstable.insert(name.to_owned());
    }

    fn escape(&mut self, expr: &Expr) {
        let target: &Expr = match expr {
            Expr::Starred(starred) => &starred.value,
            other => other,
        };
        if let Expr::Name(name) = target {
            self.escaping.insert(name.id.as_str().to_owned());
        }
    }
}

pub(super) struct ScopeNames {
    pub(super) unstable: BTreeSet<String>,
    pub(super) escaping: BTreeSet<String>,
}

impl<'a> Visitor<'a> for StoreCounter {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::FunctionDef(def) => {
                self.store(def.name.as_str());
                self.nested_depth += 1;
                walk_stmt(self, stmt);
                self.nested_depth -= 1;
                return;
            }
            Stmt::ClassDef(class) => {
                self.store(class.name.as_str());
                self.nested_depth += 1;
                walk_stmt(self, stmt);
                self.nested_depth -= 1;
                return;
            }
            Stmt::Global(global) => {
                for name in &global.names {
                    self.unstable(name.as_str());
                }
            }
            Stmt::Nonlocal(nonlocal) => {
                for name in &nonlocal.names {
                    self.unstable(name.as_str());
                }
            }
            Stmt::AugAssign(augmented) => {
                if let Expr::Name(target) = augmented.target.as_ref() {
                    self.unstable(target.id.as_str());
                }
            }
            Stmt::Import(import) => {
                for alias in &import.names {
                    let bound: &str = alias.asname.as_ref().map_or_else(
                        || alias.name.split('.').next().unwrap_or_default(),
                        |asname| asname.as_str(),
                    );
                    self.store(bound);
                }
            }
            Stmt::ImportFrom(import) => {
                for alias in &import.names {
                    let bound: &str = alias
                        .asname
                        .as_ref()
                        .map_or_else(|| alias.name.as_str(), |asname| asname.as_str());
                    self.store(bound);
                }
            }
            Stmt::Try(attempt) => {
                for handler in &attempt.handlers {
                    let ExceptHandler::ExceptHandler(handler) = handler;
                    if let Some(name) = handler.name.as_ref() {
                        self.store(name.as_str());
                    }
                }
            }
            _ => {}
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        match expr {
            Expr::Name(ExprName { id, ctx, .. }) => match ctx {
                ExprContext::Store => self.store(id.as_str()),
                ExprContext::Del => self.unstable(id.as_str()),
                ExprContext::Load | ExprContext::Invalid => {}
            },
            Expr::Lambda(_) => {
                self.nested_depth += 1;
                walk_expr(self, expr);
                self.nested_depth -= 1;
                return;
            }
            Expr::Named(named) => {
                if let Expr::Name(target) = named.target.as_ref() {
                    self.unstable(target.id.as_str());
                }
            }
            Expr::Attribute(access) => self.escape(&access.value),
            Expr::Subscript(subscript) if subscript.ctx != ExprContext::Load => {
                self.escape(&subscript.value);
            }
            Expr::Call(call) => {
                for argument in &call.arguments.args {
                    self.escape(argument);
                }
                for keyword in &call.arguments.keywords {
                    self.escape(&keyword.value);
                }
            }
            _ => {}
        }
        walk_expr(self, expr);
    }

    fn visit_pattern(&mut self, pattern: &'a Pattern) {
        match pattern {
            Pattern::MatchAs(PatternMatchAs {
                name: Some(name), ..
            })
            | Pattern::MatchStar(PatternMatchStar {
                name: Some(name), ..
            })
            | Pattern::MatchMapping(PatternMatchMapping {
                rest: Some(name), ..
            }) => self.store(name.as_str()),
            _ => {}
        }
        walk_pattern(self, pattern);
    }
}

pub(super) fn scope_names(body: &[Stmt]) -> ScopeNames {
    let mut counter: StoreCounter = StoreCounter::default();
    for stmt in body {
        counter.visit_stmt(stmt);
    }
    let mut unstable: BTreeSet<String> = counter.unstable;
    unstable.extend(
        counter
            .counts
            .into_iter()
            .filter(|(_, count): &(String, usize)| *count > 1)
            .map(|(name, _): (String, usize)| name),
    );
    ScopeNames {
        unstable,
        escaping: counter.escaping,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use ruff_python_parser::parse_module;

    use super::*;

    fn names(source: &str) -> ScopeNames {
        scope_names(&parse_module(source).expect("parses").into_syntax().body)
    }

    fn unstable(source: &str) -> BTreeSet<String> {
        names(source).unstable
    }

    #[test]
    fn mutations_through_methods_items_and_calls_escape() {
        let escaping: BTreeSet<String> =
            names("a = []\na.append(1)\nb = {}\nb['k'] = 1\nc = []\nf(c)\nd = []\nprint(d[0])\n")
                .escaping;
        for name in ["a", "b", "c"] {
            assert!(escaping.contains(name), "{name}: {escaping:?}");
        }
        assert!(!escaping.contains("d"), "{escaping:?}");
    }

    #[test]
    fn rebinding_forms_make_a_name_unstable() {
        let names: BTreeSet<String> = unstable(
            "a = 1\nb = 1\nb += 1\nc = 1\nfor c in []: pass\nd = 1\ndef f():\n    global d\n    d = 2\ne = 1\ndel e\nif (g := 1): pass\nh = 1\n",
        );
        for name in ["b", "c", "d", "e", "g"] {
            assert!(names.contains(name), "{name} must be unstable: {names:?}");
        }
        assert!(!names.contains("a") && !names.contains("h"), "{names:?}");
    }

    #[test]
    fn locals_of_nested_functions_do_not_count_against_the_module() {
        let names: BTreeSet<String> = unstable("x = 1\ndef f():\n    x = 2\n    return x\n");
        assert!(!names.contains("x"), "{names:?}");
    }
}
