use crate::body_lift::expr::{CaseArm, Expr, FnClause, Stmt};
use crate::body_lift::stmts_reference_var;

#[must_use]
pub fn reconstruct_clauses(arity: u32, stmts: &[Stmt]) -> Option<Vec<FnClause>> {
    let [Stmt::Return(Expr::Case { subject, arms })] = stmts else {
        return None;
    };
    let arg: u32 = dispatch_arg(subject, arity)?;
    if arms.len() < 2 || all_wildcards(arms) {
        return None;
    }
    let arg_var: String = format!("X{arg}");
    for arm in arms {
        if binds_arg(&arm.pattern, &arg_var) {
            continue;
        }
        let guard_refs: bool = arm
            .guard
            .as_ref()
            .is_some_and(|g: &Expr| stmts_reference_var(&[Stmt::Expr(g.clone())], &arg_var));
        if stmts_reference_var(&arm.body, &arg_var) || guard_refs {
            return None;
        }
    }
    let clauses: Vec<FnClause> = arms
        .iter()
        .map(|arm: &CaseArm| FnClause {
            patterns: clause_patterns(arity, arg, arm),
            guard: arm.guard.clone(),
            body: arm.body.clone(),
        })
        .collect();
    Some(clauses)
}

fn binds_arg(pattern: &Expr, arg_var: &str) -> bool {
    matches!(pattern, Expr::Var(v) if v == arg_var)
}

fn dispatch_arg(subject: &Expr, arity: u32) -> Option<u32> {
    match subject {
        Expr::Var(name) => arg_index(name).filter(|&i: &u32| i < arity),
        _ => None,
    }
}

fn arg_index(name: &str) -> Option<u32> {
    name.strip_prefix('X')
        .and_then(|r: &str| r.parse::<u32>().ok())
}

fn clause_patterns(arity: u32, arg: u32, arm: &CaseArm) -> Vec<Expr> {
    (0..arity)
        .map(|i: u32| {
            if i == arg {
                arm.pattern.clone()
            } else {
                Expr::Var(format!("X{i}"))
            }
        })
        .collect()
}

fn all_wildcards(arms: &[CaseArm]) -> bool {
    arms.iter()
        .all(|a: &CaseArm| matches!(&a.pattern, Expr::Var(v) if v == "_"))
}
