use std::collections::BTreeMap;

use crate::expr::{Expr, Width};
use crate::rules::engine::apply_root;
use crate::rules::error::LoadError;
use crate::rules::schema::{Condition, Pattern, Rule, RuleSet};
use crate::verify::verify_equivalent;

pub(super) fn grade(rule: &Rule) -> Result<(), LoadError> {
    for bits in &rule.widths {
        let Some(width): Option<Width> = Width::from_bits(u32::from(*bits)) else {
            return Err(LoadError::EquivalenceRejected {
                rule: rule.name.clone(),
                width: *bits,
            });
        };
        let Some(input): Option<Expr> = witness_input(rule, width) else {
            return Err(LoadError::EquivalenceRejected {
                rule: rule.name.clone(),
                width: *bits,
            });
        };
        let one_rule: RuleSet = RuleSet {
            commutative_match: false,
            rules: vec![rule.clone()],
        };
        let Some(hit) = apply_root(&one_rule, &input, width) else {
            return Err(LoadError::EquivalenceRejected {
                rule: rule.name.clone(),
                width: *bits,
            });
        };
        if !verify_equivalent(&input, &hit.result, width).is_proven() {
            return Err(LoadError::EquivalenceRejected {
                rule: rule.name.clone(),
                width: *bits,
            });
        }
    }
    Ok(())
}

fn witness_input(rule: &Rule, width: Width) -> Option<Expr> {
    let mut captures: BTreeMap<String, Expr> = BTreeMap::new();
    let mut next_variable: u32 = 0;
    collect_captures(&rule.pattern, &mut captures, &mut next_variable);
    for condition in &rule.when {
        match condition {
            Condition::IsZero { expr } => {
                captures.insert(expr.clone(), Expr::konst(0));
            }
            Condition::IsNonZero { expr } | Condition::IsOne { expr } => {
                captures.insert(expr.clone(), Expr::konst(1));
            }
            Condition::IsAllOnes { expr } => {
                captures.insert(expr.clone(), Expr::konst(width.mask()));
            }
            Condition::Equal { left, right } => {
                let value: Expr = captures.get(left)?.clone();
                captures.insert(right.clone(), value);
            }
            Condition::Complement { left, right } => {
                let value: Expr = captures.get(left)?.clone();
                captures.insert(right.clone(), Expr::not(value));
            }
        }
    }
    instantiate_pattern(&rule.pattern, &captures, width)
}

fn collect_captures(
    pattern: &Pattern,
    captures: &mut BTreeMap<String, Expr>,
    next_variable: &mut u32,
) {
    match pattern {
        Pattern::AnyExpr { bind } => {
            captures.entry(bind.clone()).or_insert_with(|| {
                let value: Expr = Expr::var(*next_variable);
                *next_variable += 1;
                value
            });
        }
        Pattern::AnyConst { bind } => {
            captures
                .entry(bind.clone())
                .or_insert_with(|| Expr::konst(0));
        }
        Pattern::Const { .. } | Pattern::Var { .. } => {}
        Pattern::Unary { operand, .. } => collect_captures(operand, captures, next_variable),
        Pattern::Binary { left, right, .. } => {
            collect_captures(left, captures, next_variable);
            collect_captures(right, captures, next_variable);
        }
        Pattern::Ite {
            cond,
            then,
            otherwise,
        } => {
            collect_captures(cond, captures, next_variable);
            collect_captures(then, captures, next_variable);
            collect_captures(otherwise, captures, next_variable);
        }
        Pattern::Slice { inner, .. } => collect_captures(inner, captures, next_variable),
        Pattern::Compose { low, high, .. } => {
            collect_captures(low, captures, next_variable);
            collect_captures(high, captures, next_variable);
        }
    }
}

fn instantiate_pattern(
    pattern: &Pattern,
    captures: &BTreeMap<String, Expr>,
    width: Width,
) -> Option<Expr> {
    match pattern {
        Pattern::AnyExpr { bind } => captures.get(bind).cloned(),
        Pattern::AnyConst { bind } => captures
            .get(bind)
            .filter(|expr: &&Expr| matches!(expr, Expr::Const(_)))
            .cloned(),
        Pattern::Const { value } => Some(Expr::konst(*value & width.mask())),
        Pattern::Var { index } => Some(Expr::var(*index)),
        Pattern::Unary { op, operand } => Some(Expr::Unary(
            op.to_mba(),
            Box::new(instantiate_pattern(operand, captures, width)?),
        )),
        Pattern::Binary { op, left, right } => Some(Expr::Binary(
            op.to_mba(),
            Box::new(instantiate_pattern(left, captures, width)?),
            Box::new(instantiate_pattern(right, captures, width)?),
        )),
        Pattern::Ite {
            cond,
            then,
            otherwise,
        } => Some(Expr::ite(
            instantiate_pattern(cond, captures, width)?,
            instantiate_pattern(then, captures, width)?,
            instantiate_pattern(otherwise, captures, width)?,
        )),
        Pattern::Slice { inner, lo, hi } => Some(Expr::slice(
            instantiate_pattern(inner, captures, width)?,
            *lo,
            *hi,
        )),
        Pattern::Compose {
            low,
            high,
            low_bits,
        } => Some(Expr::compose(
            instantiate_pattern(low, captures, width)?,
            instantiate_pattern(high, captures, width)?,
            *low_bits,
        )),
    }
}
