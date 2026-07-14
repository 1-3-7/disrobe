use crate::expr::{Expr, Width};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CmpOp {
    Eq,
    Ne,
    UnsignedLt,
    UnsignedLe,
    UnsignedGt,
    UnsignedGe,
    SignedLt,
    SignedLe,
    SignedGt,
    SignedGe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Compare { op: CmpOp, left: Expr, right: Expr },
    Nonzero(Expr),
    Or(Box<Self>, Box<Self>),
    And(Box<Self>, Box<Self>),
}

#[allow(
    clippy::should_implement_trait,
    reason = "predicate builders mirror comparison operators; PartialEq::eq has different semantics and a different signature"
)]
impl Predicate {
    #[must_use]
    pub const fn eq(left: Expr, right: Expr) -> Self {
        Self::Compare {
            op: CmpOp::Eq,
            left,
            right,
        }
    }

    #[must_use]
    pub const fn ne(left: Expr, right: Expr) -> Self {
        Self::Compare {
            op: CmpOp::Ne,
            left,
            right,
        }
    }

    #[must_use]
    pub const fn nonzero(inner: Expr) -> Self {
        Self::Nonzero(inner)
    }

    #[must_use]
    pub fn or(left: Self, right: Self) -> Self {
        Self::Or(Box::new(left), Box::new(right))
    }

    #[must_use]
    pub fn and(left: Self, right: Self) -> Self {
        Self::And(Box::new(left), Box::new(right))
    }

    #[must_use]
    pub fn depth(&self) -> usize {
        let mut max_depth: usize = 0;
        let mut stack: Vec<(&Self, usize)> = vec![(self, 1)];
        while let Some((node, level)) = stack.pop() {
            match node {
                Self::Nonzero(inner) => max_depth = max_depth.max(level + inner.depth()),
                Self::Compare { left, right, .. } => {
                    max_depth = max_depth.max(level + left.depth().max(right.depth()));
                }
                Self::Or(left, right) | Self::And(left, right) => {
                    stack.push((left, level + 1));
                    stack.push((right, level + 1));
                }
            }
        }
        max_depth
    }

    #[must_use]
    pub fn node_count(&self) -> usize {
        let mut total: usize = 0;
        let mut stack: Vec<&Self> = vec![self];
        loop {
            let node: Option<&Self> = stack.pop();
            let Some(node) = node else {
                break;
            };
            total = total.saturating_add(1);
            match node {
                Self::Nonzero(inner) => {
                    total = total.saturating_add(inner.node_count());
                }
                Self::Compare { left, right, .. } => {
                    total = total
                        .saturating_add(left.node_count())
                        .saturating_add(right.node_count());
                }
                Self::Or(left, right) | Self::And(left, right) => {
                    stack.push(left);
                    stack.push(right);
                }
            }
        }
        total
    }

    #[must_use]
    pub fn evaluate(&self, env: &[u64], width: Width) -> bool {
        match self {
            Self::Nonzero(inner) => inner.eval(env, width) != 0,
            Self::Compare { op, left, right } => {
                let lhs: u64 = left.eval(env, width);
                let rhs: u64 = right.eval(env, width);
                compare(*op, lhs, rhs, width)
            }
            Self::Or(left, right) => left.evaluate(env, width) || right.evaluate(env, width),
            Self::And(left, right) => left.evaluate(env, width) && right.evaluate(env, width),
        }
    }

    fn collect_vars(&self, into: &mut std::collections::BTreeSet<u32>) {
        match self {
            Self::Nonzero(inner) => inner.collect_vars(into),
            Self::Compare { left, right, .. } => {
                left.collect_vars(into);
                right.collect_vars(into);
            }
            Self::Or(left, right) | Self::And(left, right) => {
                left.collect_vars(into);
                right.collect_vars(into);
            }
        }
    }

    #[must_use]
    pub fn compact(&self) -> Self {
        let used: std::collections::BTreeSet<u32> = {
            let mut set: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
            self.collect_vars(&mut set);
            set
        };
        let remap: std::collections::BTreeMap<u32, u32> = used
            .into_iter()
            .enumerate()
            .map(|(dense, original): (usize, u32)| (original, dense as u32))
            .collect();
        self.remap_vars(&remap)
    }

    pub(crate) fn remap_vars(&self, remap: &std::collections::BTreeMap<u32, u32>) -> Self {
        match self {
            Self::Nonzero(inner) => Self::Nonzero(inner.remap_vars(remap)),
            Self::Compare { op, left, right } => Self::Compare {
                op: *op,
                left: left.remap_vars(remap),
                right: right.remap_vars(remap),
            },
            Self::Or(left, right) => Self::or(left.remap_vars(remap), right.remap_vars(remap)),
            Self::And(left, right) => Self::and(left.remap_vars(remap), right.remap_vars(remap)),
        }
    }
}

const fn compare(op: CmpOp, lhs: u64, rhs: u64, width: Width) -> bool {
    match op {
        CmpOp::Eq => lhs == rhs,
        CmpOp::Ne => lhs != rhs,
        CmpOp::UnsignedLt => lhs < rhs,
        CmpOp::UnsignedLe => lhs <= rhs,
        CmpOp::UnsignedGt => lhs > rhs,
        CmpOp::UnsignedGe => lhs >= rhs,
        CmpOp::SignedLt => sign_extend(lhs, width) < sign_extend(rhs, width),
        CmpOp::SignedLe => sign_extend(lhs, width) <= sign_extend(rhs, width),
        CmpOp::SignedGt => sign_extend(lhs, width) > sign_extend(rhs, width),
        CmpOp::SignedGe => sign_extend(lhs, width) >= sign_extend(rhs, width),
    }
}

const fn sign_extend(value: u64, width: Width) -> i64 {
    let bits: u32 = width.bits();
    if bits >= 64 {
        return value as i64;
    }
    let shift: u32 = 64 - bits;
    ((value << shift) as i64) >> shift
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueVerdict {
    AlwaysTrue { verified_width: Width, lifted: bool },
    AlwaysFalse { verified_width: Width, lifted: bool },
    DataDependent,
    OutOfBudget,
}

impl OpaqueVerdict {
    #[must_use]
    pub const fn is_opaque(self) -> bool {
        matches!(self, Self::AlwaysTrue { .. } | Self::AlwaysFalse { .. })
    }

    #[must_use]
    pub const fn constant_value(self) -> Option<bool> {
        match self {
            Self::AlwaysTrue { .. } => Some(true),
            Self::AlwaysFalse { .. } => Some(false),
            Self::DataDependent | Self::OutOfBudget => None,
        }
    }
}

const MAX_OPAQUE_VARS: u32 = 3;
const MAX_EXHAUSTIBLE: Width = Width::W16;
const BIT_BUDGET: u32 = 22;
const EXHAUSTIBLE_WIDTHS: [Width; 5] = [Width::W16, Width::W8, Width::W4, Width::W2, Width::W1];

#[must_use]
fn budgeted_eval_width(requested: Width, var_count: u32) -> Option<(Width, bool)> {
    if var_count == 0 {
        let capped: Width = if requested.is_exhaustible() {
            requested
        } else {
            MAX_EXHAUSTIBLE
        };
        return Some((capped, capped.bits() < requested.bits()));
    }
    let ceiling_bits: u32 = if requested.is_exhaustible() {
        requested.bits()
    } else {
        MAX_EXHAUSTIBLE.bits()
    };
    EXHAUSTIBLE_WIDTHS
        .into_iter()
        .find(|candidate: &Width| {
            candidate.bits() <= ceiling_bits
                && candidate.bits().saturating_mul(var_count) <= BIT_BUDGET
        })
        .map(|chosen: Width| (chosen, chosen.bits() < requested.bits()))
}

#[must_use]
pub fn classify(predicate: &Predicate, width: Width) -> OpaqueVerdict {
    if predicate.depth() > crate::expr::MAX_MBA_DEPTH {
        return OpaqueVerdict::OutOfBudget;
    }
    if let Some(verdict) = classify_compound(predicate, width) {
        let verdict: OpaqueVerdict = verdict;
        return verdict;
    }
    let used: std::collections::BTreeSet<u32> = {
        let mut set: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        predicate.collect_vars(&mut set);
        set
    };
    let Ok(var_count): Result<u32, _> = u32::try_from(used.len()) else {
        #[cfg(feature = "smt-verify")]
        {
            let verdict: OpaqueVerdict = crate::verify::classify_predicate(predicate, width);
            if !matches!(verdict, OpaqueVerdict::OutOfBudget) {
                return verdict;
            }
        }
        return OpaqueVerdict::OutOfBudget;
    };
    if var_count > MAX_OPAQUE_VARS {
        #[cfg(feature = "smt-verify")]
        {
            let verdict: OpaqueVerdict = crate::verify::classify_predicate(predicate, width);
            if !matches!(verdict, OpaqueVerdict::OutOfBudget) {
                return verdict;
            }
        }
        return OpaqueVerdict::OutOfBudget;
    }
    let predicate: Predicate = predicate.compact();
    let predicate: &Predicate = &predicate;

    let Some((eval_width, lifted)): Option<(Width, bool)> = budgeted_eval_width(width, var_count)
    else {
        #[cfg(feature = "smt-verify")]
        {
            let verdict: OpaqueVerdict = crate::verify::classify_predicate(predicate, width);
            if !matches!(verdict, OpaqueVerdict::OutOfBudget) {
                return verdict;
            }
        }
        return OpaqueVerdict::OutOfBudget;
    };

    let mut env: Vec<u64> = vec![0; var_count as usize];
    let total: u128 = domain_size(eval_width, var_count);
    if total > crate::expr::MAX_EXHAUSTIVE_EVALS {
        #[cfg(feature = "smt-verify")]
        {
            let verdict: OpaqueVerdict = crate::verify::classify_predicate(predicate, width);
            if !matches!(verdict, OpaqueVerdict::OutOfBudget) {
                return verdict;
            }
        }
        return OpaqueVerdict::OutOfBudget;
    }
    let mut seen_true: bool = false;
    let mut seen_false: bool = false;
    for index in 0..total {
        decode_assignment(index, eval_width, &mut env);
        if predicate.evaluate(&env, eval_width) {
            seen_true = true;
        } else {
            seen_false = true;
        }
        if seen_true && seen_false {
            return OpaqueVerdict::DataDependent;
        }
    }
    match (seen_true, seen_false) {
        (true, false) => OpaqueVerdict::AlwaysTrue {
            verified_width: eval_width,
            lifted,
        },
        (false, true) => OpaqueVerdict::AlwaysFalse {
            verified_width: eval_width,
            lifted,
        },
        _ => OpaqueVerdict::DataDependent,
    }
}

fn classify_compound(predicate: &Predicate, width: Width) -> Option<OpaqueVerdict> {
    let (Predicate::Or(left, right) | Predicate::And(left, right)): &Predicate = predicate else {
        return None;
    };
    let is_or: bool = matches!(predicate, Predicate::Or(..));
    let lv: OpaqueVerdict = classify(left, width);
    let rv: OpaqueVerdict = classify(right, width);
    let lc: Option<bool> = lv.constant_value();
    let rc: Option<bool> = rv.constant_value();
    let verdict: OpaqueVerdict = match (lc, rc) {
        (Some(a), Some(b)) => {
            let value: bool = if is_or { a || b } else { a && b };
            constant_verdict(value, lv, rv)
        }
        (Some(true), None) | (None, Some(true)) if is_or => constant_verdict(true, lv, rv),
        (Some(false), None) | (None, Some(false)) if !is_or => constant_verdict(false, lv, rv),
        _ if matches!(lv, OpaqueVerdict::OutOfBudget)
            || matches!(rv, OpaqueVerdict::OutOfBudget) =>
        {
            OpaqueVerdict::OutOfBudget
        }
        _ => OpaqueVerdict::DataDependent,
    };
    Some(verdict)
}

const fn constant_verdict(value: bool, left: OpaqueVerdict, right: OpaqueVerdict) -> OpaqueVerdict {
    let lifted: bool = verdict_lifted(left) || verdict_lifted(right);
    let verified_width: Width = narrower_width(left, right);
    if value {
        OpaqueVerdict::AlwaysTrue {
            verified_width,
            lifted,
        }
    } else {
        OpaqueVerdict::AlwaysFalse {
            verified_width,
            lifted,
        }
    }
}

const fn verdict_lifted(verdict: OpaqueVerdict) -> bool {
    matches!(
        verdict,
        OpaqueVerdict::AlwaysTrue { lifted: true, .. }
            | OpaqueVerdict::AlwaysFalse { lifted: true, .. }
    )
}

const fn verdict_width(verdict: OpaqueVerdict) -> Option<Width> {
    match verdict {
        OpaqueVerdict::AlwaysTrue { verified_width, .. }
        | OpaqueVerdict::AlwaysFalse { verified_width, .. } => Some(verified_width),
        OpaqueVerdict::DataDependent | OpaqueVerdict::OutOfBudget => None,
    }
}

const fn narrower_width(left: OpaqueVerdict, right: OpaqueVerdict) -> Width {
    match (verdict_width(left), verdict_width(right)) {
        (Some(a), Some(b)) => {
            if a.bits() <= b.bits() {
                a
            } else {
                b
            }
        }
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => Width::W16,
    }
}

fn domain_size(width: Width, var_count: u32) -> u128 {
    let modulus: u128 = width.modulus();
    let mut acc: u128 = 1;
    for _ in 0..var_count {
        acc = acc.saturating_mul(modulus);
    }
    acc
}

fn decode_assignment(mut index: u128, width: Width, env: &mut [u64]) {
    let modulus: u128 = width.modulus();
    for slot in env.iter_mut() {
        *slot = (index % modulus) as u64;
        index /= modulus;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchFold {
    KeepConsequent,
    KeepAlternate,
    Unresolved,
}

#[must_use]
pub fn fold_branch(predicate: &Predicate, width: Width) -> BranchFold {
    match classify(predicate, width).constant_value() {
        Some(true) => BranchFold::KeepConsequent,
        Some(false) => BranchFold::KeepAlternate,
        None => BranchFold::Unresolved,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn x_squared_plus_x() -> Expr {
        Expr::add(Expr::mul(Expr::var(0), Expr::var(0)), Expr::var(0))
    }

    #[test]
    fn two_divides_x_squared_plus_x_is_always_true() {
        let predicate: Predicate = Predicate::eq(
            Expr::and(x_squared_plus_x(), Expr::konst(1)),
            Expr::konst(0),
        );
        let verdict: OpaqueVerdict = classify(&predicate, Width::W8);
        assert!(matches!(verdict, OpaqueVerdict::AlwaysTrue { .. }));
        assert_eq!(verdict.constant_value(), Some(true));
    }

    #[test]
    fn x_squared_minus_x_is_always_even() {
        let body: Expr = Expr::sub(Expr::mul(Expr::var(0), Expr::var(0)), Expr::var(0));
        let predicate: Predicate = Predicate::eq(Expr::and(body, Expr::konst(1)), Expr::konst(0));
        let verdict: OpaqueVerdict = classify(&predicate, Width::W8);
        assert!(matches!(verdict, OpaqueVerdict::AlwaysTrue { .. }));
    }

    #[test]
    fn seven_y_squared_minus_one_never_equals_x_squared() {
        let lhs: Expr = Expr::sub(
            Expr::mul(Expr::konst(7), Expr::mul(Expr::var(1), Expr::var(1))),
            Expr::konst(1),
        );
        let rhs: Expr = Expr::mul(Expr::var(0), Expr::var(0));
        let predicate: Predicate = Predicate::ne(lhs, rhs);
        let verdict: OpaqueVerdict = classify(&predicate, Width::W8);
        assert!(
            matches!(verdict, OpaqueVerdict::AlwaysTrue { .. }),
            "7y^2 - 1 != x^2 should be always-true, got {verdict:?}"
        );
    }

    #[test]
    fn genuine_predicate_is_data_dependent() {
        let predicate: Predicate = Predicate::eq(Expr::var(0), Expr::konst(7));
        let verdict: OpaqueVerdict = classify(&predicate, Width::W8);
        assert_eq!(verdict, OpaqueVerdict::DataDependent);
        assert!(!verdict.is_opaque());
    }

    #[test]
    fn genuine_inequality_not_removed() {
        let predicate: Predicate = Predicate::Compare {
            op: CmpOp::UnsignedLt,
            left: Expr::var(0),
            right: Expr::konst(100),
        };
        let verdict: OpaqueVerdict = classify(&predicate, Width::W8);
        assert_eq!(verdict, OpaqueVerdict::DataDependent);
        assert_eq!(fold_branch(&predicate, Width::W8), BranchFold::Unresolved);
    }

    #[test]
    fn always_false_predicate_keeps_alternate() {
        let predicate: Predicate = Predicate::eq(
            Expr::and(Expr::var(0), Expr::not(Expr::var(0))),
            Expr::konst(1),
        );
        let verdict: OpaqueVerdict = classify(&predicate, Width::W8);
        assert!(matches!(verdict, OpaqueVerdict::AlwaysFalse { .. }));
        assert_eq!(
            fold_branch(&predicate, Width::W8),
            BranchFold::KeepAlternate
        );
    }

    #[test]
    fn wide_width_lifts_and_flags() {
        let predicate: Predicate = Predicate::eq(
            Expr::and(x_squared_plus_x(), Expr::konst(1)),
            Expr::konst(0),
        );
        let verdict: OpaqueVerdict = classify(&predicate, Width::W64);
        match verdict {
            OpaqueVerdict::AlwaysTrue {
                verified_width,
                lifted,
            } => {
                assert_eq!(verified_width, Width::W16);
                assert!(lifted);
            }
            other => panic!("expected lifted AlwaysTrue, got {other:?}"),
        }
    }

    #[test]
    fn three_var_w16_is_budgeted_not_hanging() {
        let body: Expr = Expr::add(
            Expr::add(Expr::var(0), Expr::var(1)),
            Expr::mul(Expr::var(2), Expr::konst(0)),
        );
        let predicate: Predicate = Predicate::eq(Expr::and(body, Expr::konst(0)), Expr::konst(0));
        let verdict: OpaqueVerdict = classify(&predicate, Width::W16);
        match verdict {
            OpaqueVerdict::AlwaysTrue {
                verified_width,
                lifted,
            } => {
                assert_eq!(verified_width, Width::W4);
                assert!(lifted);
            }
            other => panic!("expected budgeted lifted AlwaysTrue at W4, got {other:?}"),
        }
    }

    #[test]
    fn budgeted_eval_width_caps_total_bit_work() {
        for (requested, var_count) in [
            (Width::W16, 1u32),
            (Width::W16, 2),
            (Width::W16, 3),
            (Width::W64, 1),
            (Width::W64, 3),
            (Width::W8, 3),
        ] {
            let chosen: Option<(Width, bool)> = budgeted_eval_width(requested, var_count);
            let (width, _lifted): (Width, bool) =
                chosen.expect("budget must resolve a width for var_count <= 3");
            assert!(
                width.bits().saturating_mul(var_count) <= BIT_BUDGET,
                "chosen width {width:?} x {var_count} exceeds the {BIT_BUDGET}-bit budget"
            );
            assert!(width.bits() <= MAX_EXHAUSTIBLE.bits());
        }
    }

    #[test]
    fn two_var_w16_lifts_into_budget() {
        let predicate: Predicate = Predicate::eq(
            Expr::and(Expr::sub(Expr::var(0), Expr::var(0)), Expr::var(1)),
            Expr::konst(0),
        );
        let verdict: OpaqueVerdict = classify(&predicate, Width::W16);
        match verdict {
            OpaqueVerdict::AlwaysTrue {
                verified_width,
                lifted,
            } => {
                assert_eq!(verified_width, Width::W8);
                assert!(lifted);
            }
            other => panic!("expected budgeted lifted AlwaysTrue at W8, got {other:?}"),
        }
    }

    #[cfg(feature = "smt-verify")]
    #[test]
    fn bdd_classifies_four_var_constant_predicate() {
        let zero: Expr = Expr::sub(Expr::var(0), Expr::var(0));
        let live_bits: Expr = Expr::or(
            Expr::or(Expr::var(1), Expr::var(2)),
            Expr::or(Expr::var(3), Expr::var(4)),
        );
        let predicate: Predicate = Predicate::eq(Expr::and(zero, live_bits), Expr::konst(0));
        let verdict: OpaqueVerdict = classify(&predicate, Width::W64);
        assert_eq!(
            verdict,
            OpaqueVerdict::AlwaysTrue {
                verified_width: Width::W64,
                lifted: false
            }
        );
    }

    #[cfg(feature = "smt-verify")]
    #[test]
    fn bdd_keeps_four_var_data_dependent_predicate() {
        let predicate: Predicate = Predicate::eq(
            Expr::xor(Expr::var(0), Expr::var(1)),
            Expr::xor(Expr::var(2), Expr::var(3)),
        );
        let verdict: OpaqueVerdict = classify(&predicate, Width::W64);
        assert_eq!(verdict, OpaqueVerdict::DataDependent);
    }

    #[test]
    fn signed_comparison_distinguishes_from_unsigned() {
        let signed: Predicate = Predicate::Compare {
            op: CmpOp::SignedLt,
            left: Expr::konst(0xFF),
            right: Expr::konst(0x01),
        };
        assert!(signed.evaluate(&[], Width::W8));
        let unsigned: Predicate = Predicate::Compare {
            op: CmpOp::UnsignedLt,
            left: Expr::konst(0xFF),
            right: Expr::konst(0x01),
        };
        assert!(!unsigned.evaluate(&[], Width::W8));
    }
}
