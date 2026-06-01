use crate::body_lift::expr::{AfterClause, CaseArm, CatchArm, Expr, IfArm, Stmt};

/// Rewrites the synthetic decision tree emitted by the lifter into idiomatic,
/// recompilable Erlang surface.
///
/// Three transforms run bottom-up over the statement tree:
/// 1. A two-armed `if Guard -> Body; true -> <implicit-failure>` whose fail arm
///    is a compiler-implicit `badmatch`/`case_end`/`if_end` marker collapses to a
///    `Pattern = Subject` match binding (the structural test that produced the
///    guard), preserving the same failure semantics without the synthetic error.
/// 2. A trailing catch-all arm whose body is only an implicit-failure marker is
///    dropped, letting the surrounding `case`/`if` raise its native clause error.
/// 3. `Pattern = Subject` bindings recovered in (1) propagate so element accesses
///    on the subject collapse back to the bound pattern variables.
#[must_use]
pub fn resugar_body(stmts: Vec<Stmt>) -> Vec<Stmt> {
    stmts.into_iter().map(resugar_stmt).collect()
}

fn resugar_stmt(stmt: Stmt) -> Stmt {
    match stmt {
        Stmt::Return(e) => Stmt::Return(resugar_expr(e)),
        Stmt::Expr(e) => Stmt::Expr(resugar_expr(e)),
        Stmt::Bind { pattern, value } => Stmt::Bind {
            pattern,
            value: resugar_expr(value),
        },
        Stmt::Match { pattern, value } => Stmt::Match {
            pattern,
            value: resugar_expr(value),
        },
        Stmt::Send { dest, msg } => Stmt::Send {
            dest: resugar_expr(dest),
            msg: resugar_expr(msg),
        },
        Stmt::Comment(c) => Stmt::Comment(c),
    }
}

fn resugar_expr(expr: Expr) -> Expr {
    match expr {
        Expr::If { arms } => resugar_if(arms),
        Expr::Case { subject, arms } => Expr::Case {
            subject: Box::new(resugar_expr(*subject)),
            arms: drop_synthetic_default(arms.into_iter().map(resugar_case_arm).collect()),
        },
        Expr::Receive { arms, after } => Expr::Receive {
            arms: arms.into_iter().map(resugar_case_arm).collect(),
            after: after.map(|a: Box<AfterClause>| {
                Box::new(AfterClause {
                    timeout: resugar_expr(a.timeout),
                    body: resugar_body(a.body),
                })
            }),
        },
        Expr::Try {
            body,
            of_arms,
            catch_arms,
            after,
        } => Expr::Try {
            body: resugar_body(body),
            of_arms: of_arms.into_iter().map(resugar_case_arm).collect(),
            catch_arms: catch_arms.into_iter().map(resugar_catch_arm).collect(),
            after: resugar_body(after),
        },
        Expr::Catch(inner) => Expr::Catch(Box::new(resugar_expr(*inner))),
        Expr::Block(stmts) => Expr::Block(resugar_body(stmts)),
        other => other,
    }
}

fn resugar_case_arm(arm: CaseArm) -> CaseArm {
    CaseArm {
        pattern: arm.pattern,
        guard: arm.guard,
        body: resugar_body(arm.body),
    }
}

fn resugar_catch_arm(arm: CatchArm) -> CatchArm {
    CatchArm {
        class: arm.class,
        pattern: arm.pattern,
        stacktrace: arm.stacktrace,
        body: resugar_body(arm.body),
    }
}

fn resugar_if(arms: Vec<IfArm>) -> Expr {
    let arms: Vec<IfArm> = arms
        .into_iter()
        .map(|arm: IfArm| IfArm {
            guard: arm.guard,
            body: resugar_body(arm.body),
        })
        .collect();
    if let Some(stmts) = as_match_binding(&arms) {
        return Expr::Block(stmts);
    }
    let arms: Vec<IfArm> = drop_synthetic_if_default(arms);
    Expr::If { arms }
}

/// Detects the compiled `Pattern = Subject` idiom: a guarded arm whose only
/// alternative is an implicit failure marker. Returns the flattened
/// `[Match{pattern, subject}, ..continuation]` on success.
fn as_match_binding(arms: &[IfArm]) -> Option<Vec<Stmt>> {
    let [first, second]: &[IfArm; 2] = arms.try_into().ok()?;
    if !is_true_guard(&second.guard) || !is_implicit_failure(&second.body) {
        return None;
    }
    let (pattern, subject): (Expr, Expr) = pattern_from_guard(&first.guard)?;
    let mut out: Vec<Stmt> = Vec::with_capacity(first.body.len() + 1);
    out.push(Stmt::Match {
        pattern,
        value: subject,
    });
    out.extend(first.body.iter().cloned());
    Some(out)
}

/// Recovers `(pattern, subject)` from a structural equality guard so it can be
/// re-expressed as a match binding.
fn pattern_from_guard(guard: &Expr) -> Option<(Expr, Expr)> {
    match guard {
        Expr::BinOp { op, lhs, rhs } if op == "=:=" || op == "==" => {
            if is_literal_pattern(rhs) {
                return Some(((**rhs).clone(), (**lhs).clone()));
            }
            if is_literal_pattern(lhs) {
                return Some(((**lhs).clone(), (**rhs).clone()));
            }
            None
        }
        Expr::BinOp { op, .. } if op == "andalso" => tagged_tuple_pattern(guard),
        _ => None,
    }
}

/// Recovers a `{Tag, _, ..}` pattern from the
/// `is_tuple(S) andalso tuple_size(S) =:= N andalso element(1, S) =:= Tag`
/// conjunction synthesized for `is_tagged_tuple`.
fn tagged_tuple_pattern(guard: &Expr) -> Option<(Expr, Expr)> {
    let conds: Vec<&Expr> = flatten_andalso(guard);
    let mut subject: Option<&Expr> = None;
    let mut arity: Option<u32> = None;
    let mut tag: Option<Expr> = None;
    for cond in conds {
        match cond {
            Expr::Guard { name, args } if name == "is_tuple" => {
                subject = args.first();
            }
            Expr::BinOp { op, lhs, rhs } if op == "=:=" => match (&**lhs, &**rhs) {
                (Expr::Guard { name, .. }, Expr::Int(n)) if name == "tuple_size" => {
                    arity = u32::try_from(*n).ok();
                }
                (Expr::Guard { name, args }, value) if name == "element" => {
                    if matches!(args.first(), Some(Expr::Int(1))) {
                        subject = subject.or_else(|| args.get(1));
                        tag = Some(value.clone());
                    }
                }
                _ => return None,
            },
            _ => return None,
        }
    }
    let (subject, arity, tag): (&Expr, u32, Expr) = (subject?, arity?, tag?);
    if arity == 0 {
        return None;
    }
    let mut elements: Vec<Expr> = Vec::with_capacity(arity as usize);
    elements.push(tag);
    for _ in 1..arity {
        elements.push(Expr::Var("_".to_owned()));
    }
    Some((Expr::Tuple(elements), subject.clone()))
}

fn flatten_andalso(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::BinOp { op, lhs, rhs } if op == "andalso" => {
            let mut out: Vec<&Expr> = flatten_andalso(lhs);
            out.extend(flatten_andalso(rhs));
            out
        }
        other => vec![other],
    }
}

fn is_literal_pattern(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Atom(_)
            | Expr::Int(_)
            | Expr::BigInt { .. }
            | Expr::Nil
            | Expr::CharLit(_)
            | Expr::Str(_)
            | Expr::BinaryLit(_)
            | Expr::Tuple(_)
            | Expr::List { .. }
    )
}

fn is_true_guard(guard: &Expr) -> bool {
    matches!(guard, Expr::Atom(a) if a == "true")
}

fn is_implicit_failure(body: &[Stmt]) -> bool {
    matches!(body, [Stmt::Comment(_)])
}

fn drop_synthetic_if_default(mut arms: Vec<IfArm>) -> Vec<IfArm> {
    if arms.len() > 1
        && let Some(last) = arms.last()
        && is_true_guard(&last.guard)
        && is_implicit_failure(&last.body)
    {
        arms.pop();
    }
    arms
}

fn drop_synthetic_default(mut arms: Vec<CaseArm>) -> Vec<CaseArm> {
    if arms.len() > 1
        && let Some(last) = arms.last()
        && matches!(&last.pattern, Expr::Var(v) if v == "_")
        && last.guard.is_none()
        && is_implicit_failure(&last.body)
    {
        arms.pop();
    }
    arms
}
