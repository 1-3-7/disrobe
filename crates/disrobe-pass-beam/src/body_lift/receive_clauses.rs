use super::combine_guard;
use super::expr::{CaseArm, Expr, Stmt, is_guard_bif};

const MAX_ARMS: usize = 32;
const MAX_CONJUNCTS: usize = 24;
const MAX_TREE_DEPTH: u32 = 24;
const MAX_TERM_DEPTH: u32 = 16;

const GUARD_BINARY_OPS: &[&str] = &[
    "==", "/=", "=<", "<", ">=", ">", "=:=", "=/=", "+", "-", "*", "/", "div", "rem", "band",
    "bor", "bxor", "bsl", "bsr", "and", "or", "xor", "andalso", "orelse",
];

const GUARD_UNARY_OPS: &[&str] = &["not", "-", "+", "bnot"];

pub(super) enum ReceiveArms {
    Split(Vec<CaseArm>),
    SingleClause,
    Unsplittable,
}

pub(super) fn split_receive_arms(body: &[Stmt], message: &str) -> ReceiveArms {
    let Some(decision): Option<&Expr> = single_decision(body) else {
        return ReceiveArms::SingleClause;
    };
    let mut paths: Vec<(Vec<Expr>, Vec<Stmt>)> = Vec::new();
    if collect(decision, &Vec::new(), &mut paths, 0).is_none() {
        return ReceiveArms::Unsplittable;
    }
    if paths.is_empty() || paths.len() > MAX_ARMS {
        return ReceiveArms::Unsplittable;
    }
    let mut arms: Vec<CaseArm> = Vec::with_capacity(paths.len());
    for (conditions, arm_body) in paths {
        if conditions.len() > MAX_CONJUNCTS {
            return ReceiveArms::Unsplittable;
        }
        if !conditions
            .iter()
            .all(|condition: &Expr| is_guard_safe(condition, 0))
        {
            return ReceiveArms::Unsplittable;
        }
        arms.push(CaseArm {
            pattern: Expr::Var(message.to_owned()),
            guard: (!conditions.is_empty()).then(|| combine_guard(conditions)),
            body: arm_body,
        });
    }
    ReceiveArms::Split(arms)
}

fn single_decision(body: &[Stmt]) -> Option<&Expr> {
    let [Stmt::Return(expr) | Stmt::Expr(expr)] = body else {
        return None;
    };
    matches!(expr, Expr::If { .. } | Expr::Case { .. }).then_some(expr)
}

fn collect(
    expr: &Expr,
    prefix: &[Expr],
    out: &mut Vec<(Vec<Expr>, Vec<Stmt>)>,
    depth: u32,
) -> Option<bool> {
    if depth > MAX_TREE_DEPTH || out.len() > MAX_ARMS {
        return None;
    }
    match expr {
        Expr::If { arms } => {
            let mut exclusions: Exclusions = Exclusions::default();
            let mut total: bool = false;
            for arm in arms {
                let unconditional: bool = matches!(&arm.guard, Expr::Atom(a) if a == "true");
                let mut conditions: Vec<Expr> = prefix.to_vec();
                conditions.extend(exclusions.conditions.iter().cloned());
                if !unconditional {
                    conditions.push(arm.guard.clone());
                }
                let before: usize = out.len();
                let covered: bool = descend(&arm.body, conditions, out, depth)?;
                if exclusions.unsafe_to_reevaluate && out.len() > before {
                    return None;
                }
                if unconditional {
                    total = covered;
                    break;
                }
                if !covered {
                    exclusions.add(arm.guard.clone());
                }
            }
            Some(total)
        }
        Expr::Case { subject, arms } => {
            if !is_guard_safe(subject, 0) {
                return None;
            }
            let mut exclusions: Exclusions = Exclusions::default();
            let mut total: bool = false;
            for arm in arms {
                if arm.guard.is_some() {
                    return None;
                }
                match &arm.pattern {
                    Expr::Var(_) => {
                        let mut conditions: Vec<Expr> = prefix.to_vec();
                        conditions.extend(exclusions.conditions.iter().cloned());
                        let before: usize = out.len();
                        total = descend(&arm.body, conditions, out, depth)?;
                        if exclusions.unsafe_to_reevaluate && out.len() > before {
                            return None;
                        }
                        break;
                    }
                    pattern if is_literal(pattern, 0) => {
                        let condition: Expr = Expr::BinOp {
                            op: "=:=".to_owned(),
                            lhs: subject.clone(),
                            rhs: Box::new(pattern.clone()),
                        };
                        let mut conditions: Vec<Expr> = prefix.to_vec();
                        conditions.extend(exclusions.conditions.iter().cloned());
                        conditions.push(condition.clone());
                        let before: usize = out.len();
                        let covered: bool = descend(&arm.body, conditions, out, depth)?;
                        if exclusions.unsafe_to_reevaluate && out.len() > before {
                            return None;
                        }
                        if !covered {
                            exclusions.add(condition);
                        }
                    }
                    _ => return None,
                }
            }
            Some(total)
        }
        _ => None,
    }
}

#[derive(Default)]
struct Exclusions {
    conditions: Vec<Expr>,
    unsafe_to_reevaluate: bool,
}

impl Exclusions {
    fn add(&mut self, condition: Expr) {
        if !cannot_raise(&condition, 0) {
            self.unsafe_to_reevaluate = true;
        }
        self.conditions.push(negate(condition));
    }
}

fn descend(
    body: &[Stmt],
    conditions: Vec<Expr>,
    out: &mut Vec<(Vec<Expr>, Vec<Stmt>)>,
    depth: u32,
) -> Option<bool> {
    if body.is_empty() {
        return Some(false);
    }
    if let [Stmt::Return(inner) | Stmt::Expr(inner)] = body
        && matches!(inner, Expr::If { .. } | Expr::Case { .. })
    {
        return collect(inner, &conditions, out, depth + 1);
    }
    if out.len() >= MAX_ARMS {
        return None;
    }
    out.push((conditions, body.to_vec()));
    Some(true)
}

fn negate(condition: Expr) -> Expr {
    Expr::UnOp {
        op: "not".to_owned(),
        operand: Box::new(condition),
    }
}

const TOTAL_COMPARISONS: &[&str] = &["==", "/=", "=<", "<", ">=", ">", "=:=", "=/="];

const TOTAL_CONNECTIVES: &[&str] = &["andalso", "orelse", "and", "or", "xor"];

const TYPE_TESTS: &[&str] = &[
    "is_atom",
    "is_binary",
    "is_bitstring",
    "is_boolean",
    "is_float",
    "is_function",
    "is_integer",
    "is_list",
    "is_map",
    "is_number",
    "is_pid",
    "is_port",
    "is_reference",
    "is_tuple",
];

fn cannot_raise(condition: &Expr, depth: u32) -> bool {
    if depth > MAX_TERM_DEPTH {
        return false;
    }
    match condition {
        Expr::Atom(name) => name == "true" || name == "false",
        Expr::BinOp { op, lhs, rhs } if TOTAL_COMPARISONS.contains(&op.as_str()) => {
            never_raises_as_term(lhs, depth + 1) && never_raises_as_term(rhs, depth + 1)
        }
        Expr::BinOp { op, lhs, rhs } if TOTAL_CONNECTIVES.contains(&op.as_str()) => {
            cannot_raise(lhs, depth + 1) && cannot_raise(rhs, depth + 1)
        }
        Expr::UnOp { op, operand } if op == "not" => cannot_raise(operand, depth + 1),
        Expr::Guard { name, args } if TYPE_TESTS.contains(&name.as_str()) => args
            .iter()
            .all(|arg: &Expr| never_raises_as_term(arg, depth + 1)),
        Expr::Call { target, args } if TYPE_TESTS.contains(&target.as_str()) => args
            .iter()
            .all(|arg: &Expr| never_raises_as_term(arg, depth + 1)),
        _ => false,
    }
}

fn never_raises_as_term(expr: &Expr, depth: u32) -> bool {
    if depth > MAX_TERM_DEPTH {
        return false;
    }
    match expr {
        Expr::Var(_)
        | Expr::Atom(_)
        | Expr::Nil
        | Expr::Int(_)
        | Expr::BigInt { .. }
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CharLit(_)
        | Expr::BinaryLit(_) => true,
        Expr::Tuple(items) => items
            .iter()
            .all(|item: &Expr| never_raises_as_term(item, depth + 1)),
        Expr::List { elements, tail } => {
            elements
                .iter()
                .all(|item: &Expr| never_raises_as_term(item, depth + 1))
                && never_raises_as_term(tail, depth + 1)
        }
        Expr::Cons { head, tail } => {
            never_raises_as_term(head, depth + 1) && never_raises_as_term(tail, depth + 1)
        }
        _ => cannot_raise(expr, depth + 1),
    }
}

fn is_literal(expr: &Expr, depth: u32) -> bool {
    if depth > MAX_TERM_DEPTH {
        return false;
    }
    match expr {
        Expr::Atom(_)
        | Expr::Nil
        | Expr::Int(_)
        | Expr::BigInt { .. }
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CharLit(_)
        | Expr::BinaryLit(_) => true,
        Expr::Tuple(items) => items.iter().all(|item: &Expr| is_literal(item, depth + 1)),
        Expr::List { elements, tail } => {
            elements
                .iter()
                .all(|item: &Expr| is_literal(item, depth + 1))
                && is_literal(tail, depth + 1)
        }
        Expr::Cons { head, tail } => is_literal(head, depth + 1) && is_literal(tail, depth + 1),
        _ => false,
    }
}

fn is_guard_safe(expr: &Expr, depth: u32) -> bool {
    if depth > MAX_TERM_DEPTH {
        return false;
    }
    match expr {
        Expr::Var(_)
        | Expr::Atom(_)
        | Expr::Nil
        | Expr::Int(_)
        | Expr::BigInt { .. }
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CharLit(_)
        | Expr::BinaryLit(_) => true,
        Expr::Tuple(items) => items
            .iter()
            .all(|item: &Expr| is_guard_safe(item, depth + 1)),
        Expr::List { elements, tail } => {
            elements
                .iter()
                .all(|item: &Expr| is_guard_safe(item, depth + 1))
                && is_guard_safe(tail, depth + 1)
        }
        Expr::Cons { head, tail } => {
            is_guard_safe(head, depth + 1) && is_guard_safe(tail, depth + 1)
        }
        Expr::TupleElement { tuple, .. } => is_guard_safe(tuple, depth + 1),
        Expr::BinOp { op, lhs, rhs } => {
            GUARD_BINARY_OPS.contains(&op.as_str())
                && is_guard_safe(lhs, depth + 1)
                && is_guard_safe(rhs, depth + 1)
        }
        Expr::UnOp { op, operand } => {
            GUARD_UNARY_OPS.contains(&op.as_str()) && is_guard_safe(operand, depth + 1)
        }
        Expr::Guard { name, args } => {
            is_guard_bif(name) && args.iter().all(|arg: &Expr| is_guard_safe(arg, depth + 1))
        }
        Expr::Call { target, args } => {
            !target.contains(':')
                && is_guard_bif(target)
                && args.iter().all(|arg: &Expr| is_guard_safe(arg, depth + 1))
        }
        _ => false,
    }
}
