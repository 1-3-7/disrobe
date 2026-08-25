use std::collections::BTreeMap;

use crate::expr::{Expr, Width};
use crate::rules::error::ApplyError;
use crate::rules::schema::{Binary, Condition, Pattern, Rule, RuleSet, Template};

const MAX_TEMPLATE_NODES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Capture {
    Subtree(Expr),
    Const(u64),
}

#[derive(Debug, Default)]
struct Bindings {
    map: BTreeMap<String, Capture>,
}

impl Bindings {
    fn bind(&mut self, name: &str, capture: Capture) -> bool {
        if let Some(existing) = self.map.get(name) {
            return existing == &capture;
        }
        self.map.insert(name.to_owned(), capture);
        true
    }

    fn subtree(&self, name: &str) -> Option<&Expr> {
        match self.map.get(name) {
            Some(Capture::Subtree(expr)) => Some(expr),
            _ => None,
        }
    }

    fn const_value(&self, name: &str) -> Option<u64> {
        match self.map.get(name) {
            Some(Capture::Const(value)) => Some(*value),
            _ => None,
        }
    }

    fn any(&self, name: &str) -> Option<Expr> {
        match self.map.get(name) {
            Some(Capture::Subtree(expr)) => Some(expr.clone()),
            Some(Capture::Const(value)) => Some(Expr::Const(*value)),
            None => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHit {
    pub rule: String,
    pub result: Expr,
}

#[must_use]
pub fn apply_root(rules: &RuleSet, expr: &Expr, width: Width) -> Option<RuleHit> {
    for rule in &rules.rules {
        if !rule.widths.contains(&(width.bits() as u8)) {
            continue;
        }
        if let Some(result) = try_rule(rule, expr, width, rules.commutative_match) {
            return Some(RuleHit {
                rule: rule.name.clone(),
                result,
            });
        }
    }
    None
}

#[must_use]
pub fn rewrite_fixpoint(rules: &RuleSet, expr: &Expr, width: Width, max_passes: u32) -> Expr {
    let mut current: Expr = canonical_const(expr, width);
    for _ in 0..max_passes {
        let next: Expr = rewrite_once(rules, &current, width);
        if next == current {
            return current;
        }
        current = next;
    }
    current
}

fn rewrite_once(rules: &RuleSet, expr: &Expr, width: Width) -> Expr {
    let descended: Expr = match expr {
        Expr::Const(value) => Expr::Const(value & width.mask()),
        Expr::Var(index) => Expr::Var(*index),
        Expr::Unary(op, inner) => Expr::Unary(*op, Box::new(rewrite_once(rules, inner, width))),
        Expr::Binary(op, left, right) => Expr::Binary(
            *op,
            Box::new(rewrite_once(rules, left, width)),
            Box::new(rewrite_once(rules, right, width)),
        ),
        Expr::Ite(cond, then, otherwise) => Expr::Ite(
            Box::new(rewrite_once(rules, cond, width)),
            Box::new(rewrite_once(rules, then, width)),
            Box::new(rewrite_once(rules, otherwise, width)),
        ),
        Expr::Slice(inner, lo, hi) => {
            Expr::Slice(Box::new(rewrite_once(rules, inner, width)), *lo, *hi)
        }
        Expr::Compose(low, high, low_bits) => Expr::Compose(
            Box::new(rewrite_once(rules, low, width)),
            Box::new(rewrite_once(rules, high, width)),
            *low_bits,
        ),
        Expr::Mem(addr, load_width) => {
            Expr::Mem(Box::new(rewrite_once(rules, addr, width)), *load_width)
        }
    };
    match apply_root(rules, &descended, width) {
        Some(hit) => hit.result,
        None => descended,
    }
}

fn canonical_const(expr: &Expr, width: Width) -> Expr {
    match expr {
        Expr::Const(value) => Expr::Const(value & width.mask()),
        Expr::Var(index) => Expr::Var(*index),
        Expr::Unary(op, inner) => Expr::Unary(*op, Box::new(canonical_const(inner, width))),
        Expr::Binary(op, left, right) => Expr::Binary(
            *op,
            Box::new(canonical_const(left, width)),
            Box::new(canonical_const(right, width)),
        ),
        Expr::Ite(cond, then, otherwise) => Expr::Ite(
            Box::new(canonical_const(cond, width)),
            Box::new(canonical_const(then, width)),
            Box::new(canonical_const(otherwise, width)),
        ),
        Expr::Slice(inner, lo, hi) => {
            Expr::Slice(Box::new(canonical_const(inner, width)), *lo, *hi)
        }
        Expr::Compose(low, high, low_bits) => Expr::Compose(
            Box::new(canonical_const(low, width)),
            Box::new(canonical_const(high, width)),
            *low_bits,
        ),
        Expr::Mem(addr, load_width) => {
            Expr::Mem(Box::new(canonical_const(addr, width)), *load_width)
        }
    }
}

fn try_rule(rule: &Rule, expr: &Expr, width: Width, commutative: bool) -> Option<Expr> {
    let mut bindings: Bindings = Bindings::default();
    if match_pattern(&rule.pattern, expr, &mut bindings, width, commutative)
        && conditions_hold(&rule.when, &bindings, width)
    {
        return instantiate(&rule.rewrite, &bindings, width).ok();
    }
    None
}

fn match_pattern(
    pattern: &Pattern,
    expr: &Expr,
    bindings: &mut Bindings,
    width: Width,
    commutative: bool,
) -> bool {
    match pattern {
        Pattern::AnyExpr { bind } => bindings.bind(bind, Capture::Subtree(expr.clone())),
        Pattern::AnyConst { bind } => match expr {
            Expr::Const(value) => bindings.bind(bind, Capture::Const(value & width.mask())),
            _ => false,
        },
        Pattern::Const { value } => {
            matches!(expr, Expr::Const(actual) if (actual & width.mask()) == (value & width.mask()))
        }
        Pattern::Var { index } => matches!(expr, Expr::Var(actual) if actual == index),
        Pattern::Unary { op, operand } => match expr {
            Expr::Unary(actual, inner) if *actual == op.to_mba() => {
                match_pattern(operand, inner, bindings, width, commutative)
            }
            _ => false,
        },
        Pattern::Binary { op, left, right } => match expr {
            Expr::Binary(actual, lhs, rhs) if *actual == op.to_mba() => {
                match_binary(*op, left, right, lhs, rhs, bindings, width, commutative)
            }
            _ => false,
        },
        Pattern::Ite {
            cond,
            then,
            otherwise,
        } => match expr {
            Expr::Ite(actual_cond, actual_then, actual_otherwise) => {
                match_pattern(cond, actual_cond, bindings, width, commutative)
                    && match_pattern(then, actual_then, bindings, width, commutative)
                    && match_pattern(otherwise, actual_otherwise, bindings, width, commutative)
            }
            _ => false,
        },
        Pattern::Slice { inner, lo, hi } => match expr {
            Expr::Slice(actual_inner, actual_lo, actual_hi)
                if actual_lo == lo && actual_hi == hi =>
            {
                match_pattern(inner, actual_inner, bindings, width, commutative)
            }
            _ => false,
        },
    }
}

fn match_binary(
    op: Binary,
    left: &Pattern,
    right: &Pattern,
    lhs: &Expr,
    rhs: &Expr,
    bindings: &mut Bindings,
    width: Width,
    commutative: bool,
) -> bool {
    let mut forward: Bindings = clone_bindings(bindings);
    if match_pattern(left, lhs, &mut forward, width, commutative)
        && match_pattern(right, rhs, &mut forward, width, commutative)
    {
        *bindings = forward;
        return true;
    }
    if commutative && binary_op_is_commutative(op) {
        let mut swapped: Bindings = clone_bindings(bindings);
        if match_pattern(left, rhs, &mut swapped, width, commutative)
            && match_pattern(right, lhs, &mut swapped, width, commutative)
        {
            *bindings = swapped;
            return true;
        }
    }
    false
}

const fn binary_op_is_commutative(op: Binary) -> bool {
    matches!(
        op,
        Binary::Add | Binary::Mul | Binary::And | Binary::Or | Binary::Xor
    )
}

fn clone_bindings(bindings: &Bindings) -> Bindings {
    Bindings {
        map: bindings.map.clone(),
    }
}

fn conditions_hold(conditions: &[Condition], bindings: &Bindings, width: Width) -> bool {
    conditions
        .iter()
        .all(|condition: &Condition| condition_holds(condition, bindings, width))
}

fn condition_holds(condition: &Condition, bindings: &Bindings, width: Width) -> bool {
    match condition {
        Condition::IsZero { expr } => const_or_subtree_const(expr, bindings, width)
            .is_some_and(|value: u64| (value & width.mask()) == 0),
        Condition::IsNonZero { expr } => const_or_subtree_const(expr, bindings, width)
            .is_some_and(|value: u64| (value & width.mask()) != 0),
        Condition::IsOne { expr } => const_or_subtree_const(expr, bindings, width)
            .is_some_and(|value: u64| (value & width.mask()) == 1),
        Condition::IsAllOnes { expr } => const_or_subtree_const(expr, bindings, width)
            .is_some_and(|value: u64| (value & width.mask()) == width.mask()),
        Condition::Equal { left, right } => match (bindings.any(left), bindings.any(right)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
        Condition::Complement { left, right } => {
            match (bindings.subtree(left), bindings.subtree(right)) {
                (Some(a), Some(b)) => is_complement(a, b, width),
                _ => false,
            }
        }
    }
}

fn const_or_subtree_const(name: &str, bindings: &Bindings, width: Width) -> Option<u64> {
    if let Some(value) = bindings.const_value(name) {
        return Some(value & width.mask());
    }
    match bindings.subtree(name) {
        Some(Expr::Const(value)) => Some(value & width.mask()),
        _ => None,
    }
}

fn is_complement(left: &Expr, right: &Expr, width: Width) -> bool {
    complement_of(left, width).as_ref() == Some(right)
        || complement_of(right, width).as_ref() == Some(left)
}

fn complement_of(expr: &Expr, width: Width) -> Option<Expr> {
    use crate::expr::{BinOp, UnOp};
    match expr {
        Expr::Unary(UnOp::Not, inner) => Some((**inner).clone()),
        Expr::Binary(BinOp::Xor, left, right) => match (&**left, &**right) {
            (Expr::Const(mask), other) | (other, Expr::Const(mask))
                if (mask & width.mask()) == width.mask() =>
            {
                Some(other.clone())
            }
            _ => None,
        },
        _ => None,
    }
}

fn instantiate(template: &Template, bindings: &Bindings, width: Width) -> Result<Expr, ApplyError> {
    instantiate_bounded(template, bindings, width, &mut 0)
}

fn instantiate_bounded(
    template: &Template,
    bindings: &Bindings,
    width: Width,
    budget: &mut usize,
) -> Result<Expr, ApplyError> {
    *budget += 1;
    if *budget > MAX_TEMPLATE_NODES {
        return Err(ApplyError::DepthExceeded(MAX_TEMPLATE_NODES));
    }
    match template {
        Template::Use { expr } => bindings
            .any(expr)
            .ok_or_else(|| ApplyError::MissingCapture(expr.clone())),
        Template::Const { value } => Ok(Expr::Const(value & width.mask())),
        Template::AllOnes => Ok(Expr::Const(width.mask())),
        Template::Unary { op, operand } => {
            let inner: Expr = instantiate_bounded(operand, bindings, width, budget)?;
            Ok(Expr::Unary(op.to_mba(), Box::new(inner)))
        }
        Template::Binary { op, left, right } => {
            let lhs: Expr = instantiate_bounded(left, bindings, width, budget)?;
            let rhs: Expr = instantiate_bounded(right, bindings, width, budget)?;
            Ok(Expr::Binary(op.to_mba(), Box::new(lhs), Box::new(rhs)))
        }
        Template::SliceConst { expr, lo, hi } => {
            let value: u64 =
                bindings
                    .const_value(expr)
                    .ok_or_else(|| ApplyError::CaptureKindMismatch {
                        capture: expr.clone(),
                    })?;
            Ok(Expr::Const(slice_constant(value, *lo, *hi, width)))
        }
    }
}

const fn slice_constant(value: u64, lo: u32, hi: u32, width: Width) -> u64 {
    let span: u32 = hi.saturating_sub(lo);
    let mask: u64 = if span == 0 {
        0
    } else if span >= 64 {
        u64::MAX
    } else {
        (1u64 << span) - 1
    };
    let shifted: u64 = if lo >= 64 { 0 } else { value >> lo };
    (shifted & mask) & width.mask()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn commutative_match_does_not_swap_non_commutative_ops() {
        let rules: RuleSet = RuleSet {
            commutative_match: true,
            rules: vec![Rule {
                name: "sub_zero".to_owned(),
                widths: vec![8],
                proof: "shared_equivalence".to_owned(),
                source: "test".to_owned(),
                pattern: Pattern::Binary {
                    op: Binary::Sub,
                    left: Box::new(Pattern::AnyExpr {
                        bind: "x".to_owned(),
                    }),
                    right: Box::new(Pattern::Const { value: 0 }),
                },
                when: Vec::new(),
                rewrite: Template::Use {
                    expr: "x".to_owned(),
                },
            }],
        };
        let input: Expr = Expr::sub(Expr::konst(0), Expr::var(0));
        let hit: Option<RuleHit> = apply_root(&rules, &input, Width::W8);
        assert!(hit.is_none());
    }

    #[test]
    fn rule_does_not_apply_outside_its_declared_widths() {
        let rules: RuleSet = RuleSet {
            commutative_match: false,
            rules: vec![Rule {
                name: "add_zero".to_owned(),
                widths: vec![8],
                proof: "shared_equivalence".to_owned(),
                source: "test".to_owned(),
                pattern: Pattern::Binary {
                    op: Binary::Add,
                    left: Box::new(Pattern::AnyExpr {
                        bind: "x".to_owned(),
                    }),
                    right: Box::new(Pattern::Const { value: 0 }),
                },
                when: Vec::new(),
                rewrite: Template::Use {
                    expr: "x".to_owned(),
                },
            }],
        };
        let input: Expr = Expr::add(Expr::var(0), Expr::konst(0));
        assert!(apply_root(&rules, &input, Width::W16).is_none());
        assert!(apply_root(&rules, &input, Width::W8).is_some());
    }
}
