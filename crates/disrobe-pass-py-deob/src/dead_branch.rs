use ruff_python_ast::{
    ElifElseClause, Expr, ExprBooleanLiteral, ExprNumberLiteral, Number, Stmt, StmtIf,
};

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PruneStats {
    pub(crate) if_eliminated: usize,
    pub(crate) while_eliminated: usize,
    pub(crate) branches_pruned: usize,
}

pub(crate) fn prune(items: &mut Vec<Stmt>) -> PruneStats {
    let mut report: PruneStats = PruneStats::default();
    let mut output: Vec<Stmt> = Vec::with_capacity(items.len());
    for stmt in items.drain(..) {
        match resolve(stmt, &mut report) {
            Resolved::Keep(s) => output.push(s),
            Resolved::Inline(more) => output.extend(more),
            Resolved::Drop => {}
        }
    }
    *items = output;
    report
}

#[derive(Debug)]
enum Resolved {
    Keep(Stmt),
    Inline(Vec<Stmt>),
    Drop,
}

fn resolve(stmt: Stmt, stats: &mut PruneStats) -> Resolved {
    match stmt {
        Stmt::If(mut s) => match truthiness(&s.test) {
            Some(true) => {
                stats.if_eliminated += 1;
                stats.branches_pruned += s.elif_else_clauses.len();
                let mut body: Vec<Stmt> = s.body;
                prune(&mut body);
                Resolved::Inline(body)
            }
            Some(false) => {
                stats.if_eliminated += 1;
                pick_falsey_branch(s, stats)
            }
            None => {
                prune(&mut s.body);
                for clause in &mut s.elif_else_clauses {
                    prune(&mut clause.body);
                }
                Resolved::Keep(Stmt::If(s))
            }
        },
        Stmt::While(mut s) => {
            if matches!(truthiness(&s.test), Some(false)) {
                stats.while_eliminated += 1;
                Resolved::Drop
            } else {
                prune(&mut s.body);
                Resolved::Keep(Stmt::While(s))
            }
        }
        other => Resolved::Keep(other),
    }
}

fn pick_falsey_branch(mut s: StmtIf, stats: &mut PruneStats) -> Resolved {
    let mut idx: usize = 0;
    while idx < s.elif_else_clauses.len() {
        let truthy: Option<bool> = s.elif_else_clauses[idx].test.as_ref().and_then(truthiness);
        match truthy {
            Some(true) => {
                let mut body: Vec<Stmt> = std::mem::take(&mut s.elif_else_clauses[idx].body);
                prune(&mut body);
                return Resolved::Inline(body);
            }
            Some(false) => {
                stats.branches_pruned += 1;
                idx += 1;
            }
            None if s.elif_else_clauses[idx].test.is_none() => {
                let mut body: Vec<Stmt> = std::mem::take(&mut s.elif_else_clauses[idx].body);
                prune(&mut body);
                return Resolved::Inline(body);
            }
            None => return rebuild_if_from(s, idx),
        }
    }
    Resolved::Drop
}

fn rebuild_if_from(mut s: StmtIf, idx: usize) -> Resolved {
    let mut remaining: Vec<ElifElseClause> = s.elif_else_clauses.split_off(idx);
    let mut head: ElifElseClause = remaining.remove(0);
    let Some(new_test): Option<Expr> = head.test.take() else {
        return Resolved::Keep(Stmt::If(s));
    };
    let mut new_body: Vec<Stmt> = std::mem::take(&mut head.body);
    prune(&mut new_body);
    for clause in &mut remaining {
        prune(&mut clause.body);
    }
    s.test = Box::new(new_test);
    s.body = new_body;
    s.elif_else_clauses = remaining;
    Resolved::Keep(Stmt::If(s))
}

#[inline]
fn truthiness(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::BooleanLiteral(ExprBooleanLiteral { value, .. }) => Some(*value),
        Expr::NoneLiteral(_) => Some(false),
        Expr::NumberLiteral(ExprNumberLiteral { value, .. }) => match value {
            Number::Int(int) => Some(int.to_string() != "0"),
            Number::Float(f) => Some(*f != 0.0),
            Number::Complex { real, imag } => Some(*real != 0.0 || *imag != 0.0),
        },
        Expr::StringLiteral(s) => Some(!s.value.is_empty()),
        Expr::BytesLiteral(b) => Some(b.value.iter().any(|chunk| !chunk.value.is_empty())),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use ruff_python_ast::Mod;
    use ruff_python_parser::{Mode, ParseOptions, parse};

    use super::*;

    fn prune_source(src: &str) -> Vec<Stmt> {
        let parsed: ruff_python_parser::Parsed<Mod> =
            parse(src, ParseOptions::from(Mode::Module)).expect("parse");
        let Mod::Module(module) = parsed.into_syntax() else {
            panic!("expected a module");
        };
        let mut body: Vec<Stmt> = module.body;
        prune(&mut body);
        body
    }

    #[test]
    fn unresolved_elif_with_trailing_else_is_kept_not_collapsed() {
        let out: Vec<Stmt> =
            prune_source("if False:\n    a = 1\nelif x:\n    b = 2\nelse:\n    c = 3\n");
        assert_eq!(out.len(), 1, "expected a single rebuilt if, got {out:?}");
        let Stmt::If(s) = &out[0] else {
            panic!("the unresolved elif must be rebuilt into an if, got {out:?}");
        };
        assert!(
            matches!(s.test.as_ref(), Expr::Name(_)),
            "the rebuilt if test must be the unresolved elif condition"
        );
        assert_eq!(
            s.elif_else_clauses.len(),
            1,
            "the trailing else must be preserved on the rebuilt if"
        );
    }

    #[test]
    fn falsey_if_with_taken_elif_inlines_only_that_branch() {
        let out: Vec<Stmt> =
            prune_source("if False:\n    a = 1\nelif True:\n    b = 2\nelse:\n    c = 3\n");
        assert_eq!(out.len(), 1, "the True elif body is inlined: {out:?}");
        assert!(
            matches!(&out[0], Stmt::Assign(_)),
            "expected the inlined b = 2 assignment, got {out:?}"
        );
    }
}
