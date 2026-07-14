use crate::expr::{BinOp, Expr, UnOp, Width};
use crate::rules::apply_migrated;

const MAX_REWRITE_PASSES: u32 = 64;

#[must_use]
pub fn canonicalize(expr: &Expr, width: Width) -> Expr {
    let mut current: Expr = expr.clone();
    for _ in 0..MAX_REWRITE_PASSES {
        let next: Expr = rewrite_once(&current, width);
        if next == current {
            return current;
        }
        current = next;
    }
    current
}

fn rewrite_once(expr: &Expr, width: Width) -> Expr {
    match expr {
        Expr::Const(value) => Expr::Const(value & width.mask()),
        Expr::Var(index) => Expr::Var(*index),
        Expr::Unary(op, inner) => {
            let inner: Expr = rewrite_once(inner, width);
            rewrite_unary(*op, inner, width)
        }
        Expr::Binary(op, left, right) => {
            let left: Expr = rewrite_once(left, width);
            let right: Expr = rewrite_once(right, width);
            rewrite_binary(*op, left, right, width)
        }
        Expr::Ite(cond, then, otherwise) => {
            let cond: Expr = rewrite_once(cond, width);
            let then: Expr = rewrite_once(then, width);
            let otherwise: Expr = rewrite_once(otherwise, width);
            rewrite_ite(cond, then, otherwise)
        }
        Expr::Slice(inner, lo, hi) => {
            let inner: Expr = rewrite_once(inner, width);
            rewrite_slice(inner, *lo, *hi, width)
        }
        Expr::Compose(low, high, low_bits) => {
            let low: Expr = rewrite_once(low, width);
            let high: Expr = rewrite_once(high, width);
            rewrite_compose(low, high, *low_bits, width)
        }
        Expr::Mem(addr, load_width) => Expr::mem(rewrite_once(addr, width), *load_width),
    }
}

fn rewrite_ite(cond: Expr, then: Expr, otherwise: Expr) -> Expr {
    if let Expr::Const(value) = cond {
        return if value != 0 { then } else { otherwise };
    }
    if then == otherwise {
        return then;
    }
    Expr::ite(cond, then, otherwise)
}

fn rewrite_slice(inner: Expr, lo: u32, hi: u32, width: Width) -> Expr {
    if let Expr::Const(value) = inner {
        let span: u32 = hi.saturating_sub(lo);
        let mask: u64 = sub_mask(span);
        return Expr::Const(((value >> lo) & mask) & width.mask());
    }
    Expr::slice(inner, lo, hi)
}

fn rewrite_compose(low: Expr, high: Expr, low_bits: u32, width: Width) -> Expr {
    if let (Expr::Const(lo_val), Expr::Const(hi_val)) = (&low, &high) {
        let lo_part: u64 = lo_val & sub_mask(low_bits);
        let hi_part: u64 = if low_bits >= 64 {
            0
        } else {
            hi_val.wrapping_shl(low_bits)
        };
        return Expr::Const((lo_part | hi_part) & width.mask());
    }
    Expr::compose(low, high, low_bits)
}

const fn sub_mask(bits: u32) -> u64 {
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn rewrite_unary(op: UnOp, inner: Expr, width: Width) -> Expr {
    if let Expr::Const(value) = inner {
        let folded: u64 = match op {
            UnOp::Neg => value.wrapping_neg(),
            UnOp::Not => !value,
        };
        return Expr::Const(folded & width.mask());
    }
    let node: Expr = Expr::Unary(op, Box::new(inner));
    if let Some(rewritten) = apply_migrated(&node, width) {
        return rewritten;
    }
    let Expr::Unary(op, inner): Expr = node else {
        unreachable!("node was constructed as a unary expression")
    };
    let inner: Expr = *inner;
    match (op, &inner) {
        (UnOp::Neg, Expr::Unary(UnOp::Neg, deep)) => (**deep).clone(),
        (UnOp::Neg, Expr::Unary(UnOp::Not, deep)) => Expr::add((**deep).clone(), Expr::konst(1)),
        (UnOp::Not, Expr::Unary(UnOp::Neg, deep)) => Expr::sub((**deep).clone(), Expr::konst(1)),
        _ => Expr::Unary(op, Box::new(inner)),
    }
}

fn rewrite_binary(op: BinOp, left: Expr, right: Expr, width: Width) -> Expr {
    if let (Expr::Const(lhs), Expr::Const(rhs)) = (&left, &right) {
        return Expr::Const(fold_const(op, *lhs, *rhs, width) & width.mask());
    }
    let node: Expr = Expr::Binary(op, Box::new(left), Box::new(right));
    if let Some(rewritten) = apply_migrated(&node, width) {
        return rewritten;
    }
    let Expr::Binary(op, left, right): Expr = node else {
        unreachable!("node was constructed as a binary expression")
    };
    let (left, right): (Expr, Expr) = (*left, *right);
    if matches!(op, BinOp::Add | BinOp::Sub) {
        let node: Expr = Expr::Binary(op, Box::new(left), Box::new(right));
        if let Some(collected) = collect_affine(&node, width) {
            return collected;
        }
        let Expr::Binary(op, left, right): Expr = node else {
            unreachable!("node was constructed as a binary expression")
        };
        let (left, right): (Expr, Expr) = (*left, *right);
        return match op {
            BinOp::Add => rewrite_add(left, right, width),
            BinOp::Sub => rewrite_sub(left, right, width),
            _ => unreachable!("op is Add or Sub in this arm"),
        };
    }
    let (left, right): (Expr, Expr) = order_commutative(op, left, right);
    match op {
        BinOp::Add => rewrite_add(left, right, width),
        BinOp::Sub => rewrite_sub(left, right, width),
        BinOp::Mul => rewrite_mul(left, right, width),
        BinOp::And => rewrite_and(left, right, width),
        BinOp::Or => rewrite_or(left, right, width),
        BinOp::Xor => rewrite_xor(left, right, width),
        BinOp::Shl => rewrite_shift(BinOp::Shl, left, right, width),
        BinOp::Shr => rewrite_shift(BinOp::Shr, left, right, width),
    }
}

struct AffineTerm {
    coeff: i128,
    atom: Expr,
}

fn collect_affine(node: &Expr, width: Width) -> Option<Expr> {
    let mut terms: Vec<AffineTerm> = Vec::new();
    let mut constant: i128 = 0;
    flatten_affine(node, 1, width, &mut terms, &mut constant);
    if terms.len() < 2 {
        return None;
    }

    let modulus: i128 = width.modulus() as i128;
    let mut merged: Vec<AffineTerm> = Vec::new();
    let mut combined: bool = false;
    for term in terms {
        if let Some(slot) = merged
            .iter_mut()
            .find(|existing: &&mut AffineTerm| existing.atom == term.atom)
        {
            slot.coeff = (slot.coeff + term.coeff).rem_euclid(modulus);
            combined = true;
        } else {
            merged.push(AffineTerm {
                coeff: term.coeff.rem_euclid(modulus),
                atom: term.atom,
            });
        }
    }
    if !combined {
        return None;
    }

    merged.sort_by_key(|term: &AffineTerm| order_key(&term.atom));
    let rebuilt: Expr = rebuild_affine(&merged, constant.rem_euclid(modulus), width);
    Some(rebuilt)
}

fn flatten_affine(
    expr: &Expr,
    sign: i128,
    width: Width,
    terms: &mut Vec<AffineTerm>,
    constant: &mut i128,
) {
    match expr {
        Expr::Const(value) => {
            *constant += sign * i128::from(*value & width.mask());
        }
        Expr::Binary(BinOp::Add, left, right) => {
            flatten_affine(left, sign, width, terms, constant);
            flatten_affine(right, sign, width, terms, constant);
        }
        Expr::Binary(BinOp::Sub, left, right) => {
            flatten_affine(left, sign, width, terms, constant);
            flatten_affine(right, -sign, width, terms, constant);
        }
        Expr::Unary(UnOp::Neg, inner) => {
            flatten_affine(inner, -sign, width, terms, constant);
        }
        other => {
            let (coeff, atom): (i128, Expr) = split_coefficient(other, width);
            terms.push(AffineTerm {
                coeff: sign * coeff,
                atom,
            });
        }
    }
}

fn split_coefficient(expr: &Expr, width: Width) -> (i128, Expr) {
    match expr {
        Expr::Binary(BinOp::Mul, left, right) => match (&**left, &**right) {
            (Expr::Const(value), other) | (other, Expr::Const(value)) => {
                (i128::from(*value & width.mask()), other.clone())
            }
            _ => (1, expr.clone()),
        },
        Expr::Binary(BinOp::Shl, left, right) => match &**right {
            Expr::Const(amount) if *amount < u64::from(width.bits()) => {
                (1i128 << amount, (**left).clone())
            }
            _ => (1, expr.clone()),
        },
        _ => (1, expr.clone()),
    }
}

fn rebuild_affine(terms: &[AffineTerm], constant: i128, width: Width) -> Expr {
    let modulus: i128 = width.modulus() as i128;
    let mut acc: Option<Expr> = None;
    for term in terms {
        if term.coeff == 0 {
            continue;
        }
        let (magnitude, negative): (i128, bool) = if term.coeff * 2 > modulus {
            (modulus - term.coeff, true)
        } else {
            (term.coeff, false)
        };
        let scaled: Expr = if magnitude == 1 {
            term.atom.clone()
        } else {
            Expr::mul(Expr::konst(magnitude as u64), term.atom.clone())
        };
        acc = Some(match acc {
            None if negative => Expr::neg(scaled),
            None => scaled,
            Some(current) if negative => Expr::sub(current, scaled),
            Some(current) => Expr::add(current, scaled),
        });
    }
    if constant != 0 {
        let (magnitude, negative): (i128, bool) = if constant * 2 > modulus {
            (modulus - constant, true)
        } else {
            (constant, false)
        };
        let value: Expr = Expr::konst(magnitude as u64);
        acc = Some(match acc {
            None if negative => Expr::neg(value),
            None => value,
            Some(current) if negative => Expr::sub(current, value),
            Some(current) => Expr::add(current, value),
        });
    }
    acc.unwrap_or(Expr::Const(0))
}

const fn is_commutative(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Add | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
    )
}

fn order_commutative(op: BinOp, left: Expr, right: Expr) -> (Expr, Expr) {
    if is_commutative(op) && order_key(&right) < order_key(&left) {
        (right, left)
    } else {
        (left, right)
    }
}

pub(crate) fn order_key(expr: &Expr) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    encode_key(expr, &mut out);
    out
}

fn encode_key(expr: &Expr, out: &mut Vec<u64>) {
    match expr {
        Expr::Const(value) => {
            out.push(0);
            out.push(*value);
        }
        Expr::Var(index) => {
            out.push(1);
            out.push(u64::from(*index));
        }
        Expr::Unary(op, inner) => {
            out.push(2);
            out.push(match op {
                UnOp::Neg => 0,
                UnOp::Not => 1,
            });
            encode_key(inner, out);
        }
        Expr::Binary(op, left, right) => {
            out.push(3);
            out.push(binop_tag(*op));
            encode_key(left, out);
            encode_key(right, out);
        }
        Expr::Ite(cond, then, otherwise) => {
            out.push(4);
            encode_key(cond, out);
            encode_key(then, out);
            encode_key(otherwise, out);
        }
        Expr::Slice(inner, lo, hi) => {
            out.push(5);
            out.push(u64::from(*lo));
            out.push(u64::from(*hi));
            encode_key(inner, out);
        }
        Expr::Compose(low, high, low_bits) => {
            out.push(6);
            out.push(u64::from(*low_bits));
            encode_key(low, out);
            encode_key(high, out);
        }
        Expr::Mem(addr, width) => {
            out.push(7);
            out.push(u64::from(width.bits()));
            encode_key(addr, out);
        }
    }
}

const fn binop_tag(op: BinOp) -> u64 {
    match op {
        BinOp::Add => 0,
        BinOp::Sub => 1,
        BinOp::Mul => 2,
        BinOp::And => 3,
        BinOp::Or => 4,
        BinOp::Xor => 5,
        BinOp::Shl => 6,
        BinOp::Shr => 7,
    }
}

fn fold_const(op: BinOp, lhs: u64, rhs: u64, width: Width) -> u64 {
    match op {
        BinOp::Add => lhs.wrapping_add(rhs),
        BinOp::Sub => lhs.wrapping_sub(rhs),
        BinOp::Mul => lhs.wrapping_mul(rhs),
        BinOp::And => lhs & rhs,
        BinOp::Or => lhs | rhs,
        BinOp::Xor => lhs ^ rhs,
        BinOp::Shl => shift_left(lhs, rhs, width),
        BinOp::Shr => shift_right(lhs & width.mask(), rhs, width),
    }
}

fn rewrite_add(left: Expr, right: Expr, _width: Width) -> Expr {
    if let Expr::Unary(UnOp::Neg, inner) = &right {
        return Expr::sub(left, (**inner).clone());
    }
    if let Expr::Unary(UnOp::Neg, inner) = &left {
        return Expr::sub(right, (**inner).clone());
    }
    Expr::add(left, right)
}

fn rewrite_sub(left: Expr, right: Expr, _width: Width) -> Expr {
    if is_zero(&right) {
        return left;
    }
    if let Expr::Unary(UnOp::Neg, inner) = &right {
        return Expr::add(left, (**inner).clone());
    }
    Expr::sub(left, right)
}

fn rewrite_mul(left: Expr, right: Expr, _width: Width) -> Expr {
    if is_one(&left) {
        return right;
    }
    if is_one(&right) {
        return left;
    }
    Expr::mul(left, right)
}

fn rewrite_and(left: Expr, right: Expr, width: Width) -> Expr {
    if is_zero(&left) || is_zero(&right) {
        return Expr::konst(0);
    }
    if is_all_ones(&left, width) {
        return right;
    }
    if is_all_ones(&right, width) {
        return left;
    }
    if left == right {
        return left;
    }
    if is_complement(&left, &right, width) {
        return Expr::konst(0);
    }
    if absorbs(BinOp::Or, &left, &right) {
        return left;
    }
    if absorbs(BinOp::Or, &right, &left) {
        return right;
    }
    Expr::and(left, right)
}

fn rewrite_or(left: Expr, right: Expr, width: Width) -> Expr {
    if is_zero(&left) {
        return right;
    }
    if is_zero(&right) {
        return left;
    }
    if is_all_ones(&left, width) || is_all_ones(&right, width) {
        return Expr::Const(width.mask());
    }
    if left == right {
        return left;
    }
    if is_complement(&left, &right, width) {
        return Expr::Const(width.mask());
    }
    if absorbs(BinOp::And, &left, &right) {
        return left;
    }
    if absorbs(BinOp::And, &right, &left) {
        return right;
    }
    Expr::or(left, right)
}

fn rewrite_xor(left: Expr, right: Expr, width: Width) -> Expr {
    if is_zero(&left) {
        return right;
    }
    if is_zero(&right) {
        return left;
    }
    if left == right {
        return Expr::konst(0);
    }
    if is_complement(&left, &right, width) {
        return Expr::Const(width.mask());
    }
    Expr::xor(left, right)
}

fn rewrite_shift(op: BinOp, left: Expr, right: Expr, width: Width) -> Expr {
    if is_zero(&right) {
        return left;
    }
    if is_zero(&left) {
        return Expr::konst(0);
    }
    if op == BinOp::Shl
        && let Expr::Const(amount) = right
    {
        if amount >= u64::from(width.bits()) {
            return Expr::konst(0);
        }
        let factor: u64 = (1u64 << amount) & width.mask();
        return Expr::mul(Expr::konst(factor), left);
    }
    Expr::Binary(op, Box::new(left), Box::new(right))
}

const fn is_zero(expr: &Expr) -> bool {
    matches!(expr, Expr::Const(0))
}

const fn is_one(expr: &Expr) -> bool {
    matches!(expr, Expr::Const(1))
}

fn is_all_ones(expr: &Expr, width: Width) -> bool {
    matches!(expr, Expr::Const(value) if (value & width.mask()) == width.mask())
}

fn absorbs(inner_op: BinOp, outer: &Expr, candidate: &Expr) -> bool {
    matches!(
        candidate,
        Expr::Binary(op, left, right)
            if *op == inner_op && (outer == &**left || outer == &**right)
    )
}

fn is_complement(left: &Expr, right: &Expr, width: Width) -> bool {
    complement_of(left, width).as_ref() == Some(right)
        || complement_of(right, width).as_ref() == Some(left)
}

fn complement_of(expr: &Expr, width: Width) -> Option<Expr> {
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

fn shift_left(value: u64, amount: u64, width: Width) -> u64 {
    let bits: u64 = u64::from(width.bits());
    if amount >= bits {
        0
    } else {
        value.wrapping_shl(amount as u32)
    }
}

fn shift_right(value: u64, amount: u64, width: Width) -> u64 {
    let bits: u64 = u64::from(width.bits());
    if amount >= bits {
        0
    } else {
        value.wrapping_shr(amount as u32)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::expr::equivalent_exhaustive;

    fn assert_equivalent(original: &Expr, width: Width, var_count: u32) -> Expr {
        let simplified: Expr = canonicalize(original, width);
        assert!(
            equivalent_exhaustive(original, &simplified, width, var_count),
            "canonicalize changed semantics: `{original}` -> `{simplified}`"
        );
        simplified
    }

    #[test]
    fn fold_pure_constants() {
        let expr: Expr = Expr::add(Expr::konst(200), Expr::konst(100));
        let out: Expr = canonicalize(&expr, Width::W8);
        assert_eq!(out, Expr::konst(44));
    }

    #[test]
    fn identity_add_zero() {
        let expr: Expr = Expr::add(Expr::var(0), Expr::konst(0));
        let out: Expr = assert_equivalent(&expr, Width::W8, 1);
        assert_eq!(out, Expr::var(0));
    }

    #[test]
    fn xor_self_is_zero() {
        let expr: Expr = Expr::xor(Expr::var(0), Expr::var(0));
        let out: Expr = assert_equivalent(&expr, Width::W8, 1);
        assert_eq!(out, Expr::konst(0));
    }

    #[test]
    fn and_with_complement_is_zero() {
        let expr: Expr = Expr::and(Expr::var(0), Expr::not(Expr::var(0)));
        let out: Expr = assert_equivalent(&expr, Width::W8, 1);
        assert_eq!(out, Expr::konst(0));
    }

    #[test]
    fn or_with_complement_is_all_ones() {
        let expr: Expr = Expr::or(Expr::var(0), Expr::not(Expr::var(0)));
        let out: Expr = assert_equivalent(&expr, Width::W8, 1);
        assert_eq!(out, Expr::konst(0xFF));
    }

    #[test]
    fn double_not_cancels() {
        let expr: Expr = Expr::not(Expr::not(Expr::var(0)));
        let out: Expr = assert_equivalent(&expr, Width::W8, 1);
        assert_eq!(out, Expr::var(0));
    }

    #[test]
    fn xor_all_ones_is_not() {
        let expr: Expr = Expr::xor(Expr::var(0), Expr::konst(0xFF));
        let out: Expr = assert_equivalent(&expr, Width::W8, 1);
        assert_eq!(out, Expr::not(Expr::var(0)));
    }

    #[test]
    fn mul_by_zero_is_zero() {
        let expr: Expr = Expr::mul(Expr::var(0), Expr::konst(0));
        let out: Expr = assert_equivalent(&expr, Width::W8, 1);
        assert_eq!(out, Expr::konst(0));
    }

    #[test]
    fn xor_self_folds_structurally() {
        let expr: Expr = Expr::xor(Expr::var(0), Expr::var(0));
        for width in [Width::W8, Width::W16, Width::W32, Width::W64] {
            let out: Expr = canonicalize(&expr, width);
            assert_eq!(out, Expr::konst(0), "x ^ x must fold to 0 at {width:?}");
        }
    }

    #[test]
    fn or_absorbs_and() {
        let expr: Expr = Expr::or(Expr::var(0), Expr::and(Expr::var(0), Expr::var(1)));
        let out: Expr = assert_equivalent(&expr, Width::W8, 2);
        assert_eq!(out, Expr::var(0));
        assert_eq!(canonicalize(&expr, Width::W64), Expr::var(0));
    }

    #[test]
    fn or_absorbs_and_reversed_outer() {
        let expr: Expr = Expr::or(Expr::and(Expr::var(1), Expr::var(0)), Expr::var(0));
        let out: Expr = assert_equivalent(&expr, Width::W8, 2);
        assert_eq!(out, Expr::var(0));
    }

    #[test]
    fn and_absorbs_or() {
        let expr: Expr = Expr::and(Expr::var(0), Expr::or(Expr::var(0), Expr::var(1)));
        let out: Expr = assert_equivalent(&expr, Width::W8, 2);
        assert_eq!(out, Expr::var(0));
        assert_eq!(canonicalize(&expr, Width::W64), Expr::var(0));
    }

    #[test]
    fn and_absorbs_or_reversed_outer() {
        let expr: Expr = Expr::and(Expr::or(Expr::var(1), Expr::var(0)), Expr::var(0));
        let out: Expr = assert_equivalent(&expr, Width::W8, 2);
        assert_eq!(out, Expr::var(0));
    }

    #[test]
    fn absorption_does_not_misfire_on_unrelated_operand() {
        let expr: Expr = Expr::or(Expr::var(0), Expr::and(Expr::var(1), Expr::var(2)));
        let out: Expr = assert_equivalent(&expr, Width::W8, 3);
        assert_ne!(out, Expr::var(0));
    }

    #[test]
    fn nested_chain_collapses() {
        let expr: Expr = Expr::sub(
            Expr::add(Expr::var(0), Expr::konst(0)),
            Expr::xor(Expr::var(1), Expr::var(1)),
        );
        let out: Expr = assert_equivalent(&expr, Width::W8, 2);
        assert_eq!(out, Expr::var(0));
    }
}
