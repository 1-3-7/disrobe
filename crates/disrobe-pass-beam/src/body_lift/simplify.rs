use std::collections::BTreeMap;

use crate::body_lift::expr::{AfterClause, CaseArm, CatchArm, Expr, IfArm, Stmt};

/// Cleans a freshly-lifted statement list.
///
/// Inlines single-use synthetic temp bindings (`V0`, `V1`, ...) into their unique
/// use site and demotes never-used call bindings to bare expression statements,
/// yielding idiomatic Erlang.
#[must_use]
pub fn simplify_body(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    count_stmts(&stmts, &mut counts);
    let mut defs: BTreeMap<String, Expr> = BTreeMap::new();
    inline_pass(stmts, &counts, &mut defs)
}

fn is_temp(name: &str) -> bool {
    name.strip_prefix('V')
        .is_some_and(|rest: &str| !rest.is_empty() && rest.bytes().all(|b: u8| b.is_ascii_digit()))
}

fn count_stmts(stmts: &[Stmt], counts: &mut BTreeMap<String, u32>) {
    for stmt in stmts {
        match stmt {
            Stmt::Return(e) | Stmt::Expr(e) => count_expr(e, counts),
            Stmt::Bind { value, .. } | Stmt::Match { value, .. } => count_expr(value, counts),
            Stmt::Send { dest, msg } => {
                count_expr(dest, counts);
                count_expr(msg, counts);
            }
            Stmt::Comment(_) => {}
        }
    }
}

#[allow(clippy::too_many_lines)]
fn count_expr(expr: &Expr, counts: &mut BTreeMap<String, u32>) {
    match expr {
        Expr::Var(name) => {
            if is_temp(name) {
                *counts.entry(name.clone()).or_insert(0) += 1;
            }
        }
        Expr::Atom(_)
        | Expr::Nil
        | Expr::Int(_)
        | Expr::BigInt { .. }
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CharLit(_)
        | Expr::BinaryLit(_)
        | Expr::Raw(_) => {}
        Expr::Tuple(items) => count_each(items, counts),
        Expr::List { elements, tail } => {
            count_each(elements, counts);
            count_expr(tail, counts);
        }
        Expr::Cons { head, tail } => {
            count_expr(head, counts);
            count_expr(tail, counts);
        }
        Expr::Map { pairs } | Expr::MapPattern { pairs } | Expr::MapUpdate { pairs, .. } => {
            if let Expr::MapUpdate { base, .. } = expr {
                count_expr(base, counts);
            }
            for (k, v) in pairs {
                count_expr(k, counts);
                count_expr(v, counts);
            }
        }
        Expr::TupleElement { tuple, .. } => count_expr(tuple, counts),
        Expr::RecordUpdate { base, updates } => {
            count_expr(base, counts);
            for (_, value) in updates {
                count_expr(value, counts);
            }
        }
        Expr::Call { args, .. } | Expr::Guard { args, .. } => count_each(args, counts),
        Expr::BinOp { lhs, rhs, .. } => {
            count_expr(lhs, counts);
            count_expr(rhs, counts);
        }
        Expr::UnOp { operand, .. } => count_expr(operand, counts),
        Expr::MakeFun { env, .. } => count_each(env, counts),
        Expr::CallFun { fun, args } => {
            count_expr(fun, counts);
            count_each(args, counts);
        }
        Expr::BinaryConstruct(segments) => {
            for seg in segments {
                count_expr(&seg.value, counts);
                if let Some(size) = &seg.size {
                    count_expr(size, counts);
                }
            }
        }
        Expr::Catch(inner) => count_expr(inner, counts),
        Expr::Case { subject, arms } => {
            count_expr(subject, counts);
            for arm in arms {
                count_arm(arm, counts);
            }
        }
        Expr::If { arms } => {
            for arm in arms {
                count_expr(&arm.guard, counts);
                count_stmts(&arm.body, counts);
            }
        }
        Expr::Receive { arms, after } => {
            for arm in arms {
                count_arm(arm, counts);
            }
            if let Some(after) = after {
                count_expr(&after.timeout, counts);
                count_stmts(&after.body, counts);
            }
        }
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => {
            count_stmts(body, counts);
            for arm in of_arms {
                count_arm(arm, counts);
            }
            for arm in catch_arms {
                count_expr(&arm.pattern, counts);
                count_stmts(&arm.body, counts);
            }
            count_stmts(after, counts);
        }
        Expr::Block(stmts) => count_stmts(stmts, counts),
    }
}

fn count_each(items: &[Expr], counts: &mut BTreeMap<String, u32>) {
    for e in items {
        count_expr(e, counts);
    }
}

fn count_arm(arm: &CaseArm, counts: &mut BTreeMap<String, u32>) {
    if let Some(g) = &arm.guard {
        count_expr(g, counts);
    }
    count_stmts(&arm.body, counts);
}

fn inline_pass(
    stmts: Vec<Stmt>,
    counts: &BTreeMap<String, u32>,
    defs: &mut BTreeMap<String, Expr>,
) -> Vec<Stmt> {
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        match stmt {
            Stmt::Bind { pattern, value } => {
                let value: Expr = subst_expr(value, counts, defs);
                if let Expr::Var(name) = &pattern
                    && is_temp(name)
                {
                    match counts.get(name).copied().unwrap_or(0) {
                        0 => out.push(Stmt::Expr(value)),
                        1 => {
                            defs.insert(name.clone(), value);
                        }
                        _ => out.push(Stmt::Bind {
                            pattern: Expr::Var(rename_temp(name)),
                            value,
                        }),
                    }
                } else {
                    out.push(Stmt::Bind {
                        pattern: subst_pattern(pattern),
                        value,
                    });
                }
            }
            Stmt::Match { pattern, value } => out.push(Stmt::Match {
                pattern: subst_pattern(pattern),
                value: subst_expr(value, counts, defs),
            }),
            Stmt::Return(e) => out.push(Stmt::Return(subst_expr(e, counts, defs))),
            Stmt::Expr(e) => out.push(Stmt::Expr(subst_expr(e, counts, defs))),
            Stmt::Send { dest, msg } => out.push(Stmt::Send {
                dest: subst_expr(dest, counts, defs),
                msg: subst_expr(msg, counts, defs),
            }),
            Stmt::Comment(c) => out.push(Stmt::Comment(c)),
        }
    }
    out
}

fn rename_temp(name: &str) -> String {
    format!("T{}", name.trim_start_matches('V'))
}

fn subst_pattern(pattern: Expr) -> Expr {
    match pattern {
        Expr::Var(name) if is_temp(&name) => Expr::Var(rename_temp(&name)),
        other => other,
    }
}

fn subst_stmts(
    stmts: Vec<Stmt>,
    counts: &BTreeMap<String, u32>,
    defs: &BTreeMap<String, Expr>,
) -> Vec<Stmt> {
    let mut scoped: BTreeMap<String, Expr> = defs.clone();
    inline_pass(stmts, counts, &mut scoped)
}

#[allow(clippy::too_many_lines)]
fn subst_expr(expr: Expr, counts: &BTreeMap<String, u32>, defs: &BTreeMap<String, Expr>) -> Expr {
    match expr {
        Expr::Var(name) => {
            if let Some(replacement) = defs.get(&name) {
                replacement.clone()
            } else if is_temp(&name) {
                Expr::Var(rename_temp(&name))
            } else {
                Expr::Var(name)
            }
        }
        Expr::Tuple(items) => Expr::Tuple(map_exprs(items, counts, defs)),
        Expr::List { elements, tail } => Expr::List {
            elements: map_exprs(elements, counts, defs),
            tail: Box::new(subst_expr(*tail, counts, defs)),
        },
        Expr::Cons { head, tail } => Expr::Cons {
            head: Box::new(subst_expr(*head, counts, defs)),
            tail: Box::new(subst_expr(*tail, counts, defs)),
        },
        Expr::Map { pairs } => Expr::Map {
            pairs: map_pairs(pairs, counts, defs),
        },
        Expr::MapPattern { pairs } => Expr::MapPattern {
            pairs: map_pairs(pairs, counts, defs),
        },
        Expr::MapUpdate { base, exact, pairs } => Expr::MapUpdate {
            base: Box::new(subst_expr(*base, counts, defs)),
            exact,
            pairs: map_pairs(pairs, counts, defs),
        },
        Expr::TupleElement { tuple, index } => Expr::TupleElement {
            tuple: Box::new(subst_expr(*tuple, counts, defs)),
            index,
        },
        Expr::RecordUpdate { base, updates } => Expr::RecordUpdate {
            base: Box::new(subst_expr(*base, counts, defs)),
            updates: updates
                .into_iter()
                .map(|(index, value): (u32, Expr)| (index, subst_expr(value, counts, defs)))
                .collect(),
        },
        Expr::Call { target, args } => Expr::Call {
            target,
            args: map_exprs(args, counts, defs),
        },
        Expr::Guard { name, args } => Expr::Guard {
            name,
            args: map_exprs(args, counts, defs),
        },
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: Box::new(subst_expr(*lhs, counts, defs)),
            rhs: Box::new(subst_expr(*rhs, counts, defs)),
        },
        Expr::UnOp { op, operand } => Expr::UnOp {
            op,
            operand: Box::new(subst_expr(*operand, counts, defs)),
        },
        Expr::MakeFun { name, arity, env } => Expr::MakeFun {
            name,
            arity,
            env: map_exprs(env, counts, defs),
        },
        Expr::CallFun { fun, args } => Expr::CallFun {
            fun: Box::new(subst_expr(*fun, counts, defs)),
            args: map_exprs(args, counts, defs),
        },
        Expr::BinaryConstruct(segments) => Expr::BinaryConstruct(
            segments
                .into_iter()
                .map(|mut seg| {
                    seg.value = Box::new(subst_expr(*seg.value, counts, defs));
                    seg.size = seg.size.map(|s| Box::new(subst_expr(*s, counts, defs)));
                    seg
                })
                .collect(),
        ),
        Expr::Catch(inner) => Expr::Catch(Box::new(subst_expr(*inner, counts, defs))),
        Expr::Case { subject, arms } => Expr::Case {
            subject: Box::new(subst_expr(*subject, counts, defs)),
            arms: arms
                .into_iter()
                .map(|a| subst_arm(a, counts, defs))
                .collect(),
        },
        Expr::If { arms } => Expr::If {
            arms: arms
                .into_iter()
                .map(|a: IfArm| IfArm {
                    guard: subst_expr(a.guard, counts, defs),
                    body: subst_stmts(a.body, counts, defs),
                })
                .collect(),
        },
        Expr::Receive { arms, after } => Expr::Receive {
            arms: arms
                .into_iter()
                .map(|a| subst_arm(a, counts, defs))
                .collect(),
            after: after.map(|a| {
                Box::new(AfterClause {
                    timeout: subst_expr(a.timeout, counts, defs),
                    body: subst_stmts(a.body, counts, defs),
                })
            }),
        },
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => Expr::Try {
            body: subst_stmts(body, counts, defs),
            of_arms: of_arms
                .into_iter()
                .map(|a| subst_arm(a, counts, defs))
                .collect(),
            catch_arms: catch_arms
                .into_iter()
                .map(|a: CatchArm| CatchArm {
                    class: a.class,
                    pattern: subst_expr(a.pattern, counts, defs),
                    stacktrace: a.stacktrace,
                    body: subst_stmts(a.body, counts, defs),
                })
                .collect(),
            after: subst_stmts(after, counts, defs),
        },
        Expr::Block(stmts) => Expr::Block(subst_stmts(stmts, counts, defs)),
        other => other,
    }
}

fn subst_arm(
    arm: CaseArm,
    counts: &BTreeMap<String, u32>,
    defs: &BTreeMap<String, Expr>,
) -> CaseArm {
    CaseArm {
        pattern: arm.pattern,
        guard: arm.guard.map(|g: Expr| subst_expr(g, counts, defs)),
        body: subst_stmts(arm.body, counts, defs),
    }
}

fn map_exprs(
    items: Vec<Expr>,
    counts: &BTreeMap<String, u32>,
    defs: &BTreeMap<String, Expr>,
) -> Vec<Expr> {
    items
        .into_iter()
        .map(|e: Expr| subst_expr(e, counts, defs))
        .collect()
}

fn map_pairs(
    pairs: Vec<(Expr, Expr)>,
    counts: &BTreeMap<String, u32>,
    defs: &BTreeMap<String, Expr>,
) -> Vec<(Expr, Expr)> {
    pairs
        .into_iter()
        .map(|(k, v): (Expr, Expr)| (subst_expr(k, counts, defs), subst_expr(v, counts, defs)))
        .collect()
}
