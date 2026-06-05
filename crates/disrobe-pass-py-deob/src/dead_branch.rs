use ruff_python_ast::{Expr, ExprBooleanLiteral, ExprNumberLiteral, Number, Stmt, StmtIf};

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
                pick_falsey_branch(&mut s, stats)
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

fn pick_falsey_branch(s: &mut StmtIf, stats: &mut PruneStats) -> Resolved {
    for clause in &mut s.elif_else_clauses {
        let truthy: Option<bool> = clause.test.as_ref().and_then(truthiness);
        match truthy {
            Some(true) => {
                let mut body: Vec<Stmt> = std::mem::take(&mut clause.body);
                prune(&mut body);
                return Resolved::Inline(body);
            }
            Some(false) => {
                stats.branches_pruned += 1;
            }
            None => {
                if clause.test.is_none() {
                    let mut body: Vec<Stmt> = std::mem::take(&mut clause.body);
                    prune(&mut body);
                    return Resolved::Inline(body);
                }
                stats.branches_pruned += 1;
            }
        }
    }
    Resolved::Drop
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
