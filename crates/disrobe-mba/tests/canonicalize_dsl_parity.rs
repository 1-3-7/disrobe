#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_mba::{BinOp, Expr, UnOp, Width, canonicalize, equivalent_exhaustive};

const MAX_REWRITE_PASSES: u32 = 64;

fn reference_canonicalize(expr: &Expr, width: Width) -> Expr {
    let mut current: Expr = expr.clone();
    for _ in 0..MAX_REWRITE_PASSES {
        let next: Expr = reference_rewrite_once(&current, width);
        if next == current {
            return current;
        }
        current = next;
    }
    current
}

fn reference_rewrite_once(expr: &Expr, width: Width) -> Expr {
    match expr {
        Expr::Const(value) => Expr::Const(value & width.mask()),
        Expr::Var(index) => Expr::Var(*index),
        Expr::Unary(op, inner) => {
            let inner: Expr = reference_rewrite_once(inner, width);
            reference_rewrite_unary(*op, inner, width)
        }
        Expr::Binary(op, left, right) => {
            let left: Expr = reference_rewrite_once(left, width);
            let right: Expr = reference_rewrite_once(right, width);
            reference_rewrite_binary(*op, left, right, width)
        }
        Expr::Ite(cond, then, otherwise) => {
            let cond: Expr = reference_rewrite_once(cond, width);
            let then: Expr = reference_rewrite_once(then, width);
            let otherwise: Expr = reference_rewrite_once(otherwise, width);
            if let Expr::Const(value) = cond {
                if value != 0 { then } else { otherwise }
            } else if then == otherwise {
                then
            } else {
                Expr::ite(cond, then, otherwise)
            }
        }
        Expr::Slice(inner, lo, hi) => {
            let inner: Expr = reference_rewrite_once(inner, width);
            if let Expr::Const(value) = inner {
                let span: u32 = hi.saturating_sub(*lo);
                Expr::Const(((value >> lo) & reference_sub_mask(span)) & width.mask())
            } else {
                Expr::slice(inner, *lo, *hi)
            }
        }
        Expr::Compose(low, high, low_bits) => {
            let low: Expr = reference_rewrite_once(low, width);
            let high: Expr = reference_rewrite_once(high, width);
            if let (Expr::Const(lo_val), Expr::Const(hi_val)) = (&low, &high) {
                let lo_part: u64 = lo_val & reference_sub_mask(*low_bits);
                let hi_part: u64 = if *low_bits >= 64 {
                    0
                } else {
                    hi_val.wrapping_shl(*low_bits)
                };
                Expr::Const((lo_part | hi_part) & width.mask())
            } else {
                Expr::compose(low, high, *low_bits)
            }
        }
        Expr::Mem(addr, load_width) => Expr::mem(reference_rewrite_once(addr, width), *load_width),
    }
}

const fn reference_sub_mask(bits: u32) -> u64 {
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn reference_rewrite_unary(op: UnOp, inner: Expr, width: Width) -> Expr {
    if let Expr::Const(value) = inner {
        let folded: u64 = match op {
            UnOp::Neg => value.wrapping_neg(),
            UnOp::Not => !value,
        };
        return Expr::Const(folded & width.mask());
    }
    match (op, &inner) {
        (UnOp::Not, Expr::Unary(UnOp::Not, deep)) | (UnOp::Neg, Expr::Unary(UnOp::Neg, deep)) => {
            (**deep).clone()
        }
        (UnOp::Neg, Expr::Unary(UnOp::Not, deep)) => Expr::add((**deep).clone(), Expr::konst(1)),
        (UnOp::Not, Expr::Unary(UnOp::Neg, deep)) => Expr::sub((**deep).clone(), Expr::konst(1)),
        _ => Expr::Unary(op, Box::new(inner)),
    }
}

fn reference_rewrite_binary(op: BinOp, left: Expr, right: Expr, width: Width) -> Expr {
    if let (Expr::Const(lhs), Expr::Const(rhs)) = (&left, &right) {
        return Expr::Const(reference_fold_const(op, *lhs, *rhs, width) & width.mask());
    }
    if matches!(op, BinOp::Add | BinOp::Sub) {
        let node: Expr = Expr::Binary(op, Box::new(left), Box::new(right));
        if let Some(collected) = reference_collect_affine(&node, width) {
            return collected;
        }
        let Expr::Binary(op, left, right): Expr = node else {
            unreachable!("node was constructed as a binary expression")
        };
        let (left, right): (Expr, Expr) = (*left, *right);
        return match op {
            BinOp::Add => reference_rewrite_add(left, right),
            BinOp::Sub => reference_rewrite_sub(left, right),
            _ => unreachable!("op is Add or Sub in this arm"),
        };
    }
    let (left, right): (Expr, Expr) = reference_order_commutative(op, left, right);
    match op {
        BinOp::Add => reference_rewrite_add(left, right),
        BinOp::Sub => reference_rewrite_sub(left, right),
        BinOp::Mul => reference_rewrite_mul(left, right),
        BinOp::And => reference_rewrite_and(left, right, width),
        BinOp::Or => reference_rewrite_or(left, right, width),
        BinOp::Xor => reference_rewrite_xor(left, right, width),
        BinOp::Shl => reference_rewrite_shift(BinOp::Shl, left, right, width),
        BinOp::Shr => reference_rewrite_shift(BinOp::Shr, left, right, width),
    }
}

const fn reference_is_commutative(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Add | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
    )
}

fn reference_order_commutative(op: BinOp, left: Expr, right: Expr) -> (Expr, Expr) {
    if reference_is_commutative(op) && reference_order_key(&right) < reference_order_key(&left) {
        (right, left)
    } else {
        (left, right)
    }
}

fn reference_order_key(expr: &Expr) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    reference_encode_key(expr, &mut out);
    out
}

fn reference_encode_key(expr: &Expr, out: &mut Vec<u64>) {
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
            reference_encode_key(inner, out);
        }
        Expr::Binary(op, left, right) => {
            out.push(3);
            out.push(reference_binop_tag(*op));
            reference_encode_key(left, out);
            reference_encode_key(right, out);
        }
        Expr::Ite(cond, then, otherwise) => {
            out.push(4);
            reference_encode_key(cond, out);
            reference_encode_key(then, out);
            reference_encode_key(otherwise, out);
        }
        Expr::Slice(inner, lo, hi) => {
            out.push(5);
            out.push(u64::from(*lo));
            out.push(u64::from(*hi));
            reference_encode_key(inner, out);
        }
        Expr::Compose(low, high, low_bits) => {
            out.push(6);
            out.push(u64::from(*low_bits));
            reference_encode_key(low, out);
            reference_encode_key(high, out);
        }
        Expr::Mem(addr, width) => {
            out.push(7);
            out.push(u64::from(width.bits()));
            reference_encode_key(addr, out);
        }
    }
}

const fn reference_binop_tag(op: BinOp) -> u64 {
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

fn reference_fold_const(op: BinOp, lhs: u64, rhs: u64, width: Width) -> u64 {
    match op {
        BinOp::Add => lhs.wrapping_add(rhs),
        BinOp::Sub => lhs.wrapping_sub(rhs),
        BinOp::Mul => lhs.wrapping_mul(rhs),
        BinOp::And => lhs & rhs,
        BinOp::Or => lhs | rhs,
        BinOp::Xor => lhs ^ rhs,
        BinOp::Shl => reference_shift_left(lhs, rhs, width),
        BinOp::Shr => reference_shift_right(lhs & width.mask(), rhs, width),
    }
}

struct ReferenceAffineTerm {
    coeff: i128,
    atom: Expr,
}

fn reference_collect_affine(node: &Expr, width: Width) -> Option<Expr> {
    let mut terms: Vec<ReferenceAffineTerm> = Vec::new();
    let mut constant: i128 = 0;
    reference_flatten_affine(node, 1, width, &mut terms, &mut constant);
    if terms.len() < 2 {
        return None;
    }

    let modulus: i128 = width.modulus() as i128;
    let mut merged: Vec<ReferenceAffineTerm> = Vec::new();
    let mut combined: bool = false;
    for term in terms {
        if let Some(slot) = merged
            .iter_mut()
            .find(|existing: &&mut ReferenceAffineTerm| existing.atom == term.atom)
        {
            slot.coeff = (slot.coeff + term.coeff).rem_euclid(modulus);
            combined = true;
        } else {
            merged.push(ReferenceAffineTerm {
                coeff: term.coeff.rem_euclid(modulus),
                atom: term.atom,
            });
        }
    }
    if !combined {
        return None;
    }

    merged.sort_by_key(|term: &ReferenceAffineTerm| reference_order_key(&term.atom));
    Some(reference_rebuild_affine(
        &merged,
        constant.rem_euclid(modulus),
        width,
    ))
}

fn reference_flatten_affine(
    expr: &Expr,
    sign: i128,
    width: Width,
    terms: &mut Vec<ReferenceAffineTerm>,
    constant: &mut i128,
) {
    match expr {
        Expr::Const(value) => {
            *constant += sign * i128::from(*value & width.mask());
        }
        Expr::Binary(BinOp::Add, left, right) => {
            reference_flatten_affine(left, sign, width, terms, constant);
            reference_flatten_affine(right, sign, width, terms, constant);
        }
        Expr::Binary(BinOp::Sub, left, right) => {
            reference_flatten_affine(left, sign, width, terms, constant);
            reference_flatten_affine(right, -sign, width, terms, constant);
        }
        Expr::Unary(UnOp::Neg, inner) => {
            reference_flatten_affine(inner, -sign, width, terms, constant);
        }
        other => {
            let (coeff, atom): (i128, Expr) = reference_split_coefficient(other, width);
            terms.push(ReferenceAffineTerm {
                coeff: sign * coeff,
                atom,
            });
        }
    }
}

fn reference_split_coefficient(expr: &Expr, width: Width) -> (i128, Expr) {
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

fn reference_rebuild_affine(terms: &[ReferenceAffineTerm], constant: i128, width: Width) -> Expr {
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

fn reference_rewrite_add(left: Expr, right: Expr) -> Expr {
    if reference_is_zero(&left) {
        return right;
    }
    if reference_is_zero(&right) {
        return left;
    }
    if let Expr::Unary(UnOp::Neg, inner) = &right {
        return Expr::sub(left, (**inner).clone());
    }
    if let Expr::Unary(UnOp::Neg, inner) = &left {
        return Expr::sub(right, (**inner).clone());
    }
    Expr::add(left, right)
}

fn reference_rewrite_sub(left: Expr, right: Expr) -> Expr {
    if reference_is_zero(&right) {
        return left;
    }
    if left == right {
        return Expr::konst(0);
    }
    if let Expr::Unary(UnOp::Neg, inner) = &right {
        return Expr::add(left, (**inner).clone());
    }
    Expr::sub(left, right)
}

fn reference_rewrite_mul(left: Expr, right: Expr) -> Expr {
    if reference_is_zero(&left) || reference_is_zero(&right) {
        return Expr::konst(0);
    }
    if reference_is_one(&left) {
        return right;
    }
    if reference_is_one(&right) {
        return left;
    }
    Expr::mul(left, right)
}

fn reference_rewrite_and(left: Expr, right: Expr, width: Width) -> Expr {
    if reference_is_zero(&left) || reference_is_zero(&right) {
        return Expr::konst(0);
    }
    if reference_is_all_ones(&left, width) {
        return right;
    }
    if reference_is_all_ones(&right, width) {
        return left;
    }
    if left == right {
        return left;
    }
    if reference_is_complement(&left, &right, width) {
        return Expr::konst(0);
    }
    if reference_absorbs(BinOp::Or, &left, &right) {
        return left;
    }
    if reference_absorbs(BinOp::Or, &right, &left) {
        return right;
    }
    Expr::and(left, right)
}

fn reference_rewrite_or(left: Expr, right: Expr, width: Width) -> Expr {
    if reference_is_zero(&left) {
        return right;
    }
    if reference_is_zero(&right) {
        return left;
    }
    if reference_is_all_ones(&left, width) || reference_is_all_ones(&right, width) {
        return Expr::Const(width.mask());
    }
    if left == right {
        return left;
    }
    if reference_is_complement(&left, &right, width) {
        return Expr::Const(width.mask());
    }
    if reference_absorbs(BinOp::And, &left, &right) {
        return left;
    }
    if reference_absorbs(BinOp::And, &right, &left) {
        return right;
    }
    Expr::or(left, right)
}

fn reference_rewrite_xor(left: Expr, right: Expr, width: Width) -> Expr {
    if reference_is_zero(&left) {
        return right;
    }
    if reference_is_zero(&right) {
        return left;
    }
    if left == right {
        return Expr::konst(0);
    }
    if reference_is_all_ones(&right, width) {
        return Expr::not(left);
    }
    if reference_is_all_ones(&left, width) {
        return Expr::not(right);
    }
    if reference_is_complement(&left, &right, width) {
        return Expr::Const(width.mask());
    }
    Expr::xor(left, right)
}

fn reference_rewrite_shift(op: BinOp, left: Expr, right: Expr, width: Width) -> Expr {
    if reference_is_zero(&right) {
        return left;
    }
    if reference_is_zero(&left) {
        return Expr::konst(0);
    }
    if op == BinOp::Shr
        && let Expr::Const(amount) = right
        && amount >= u64::from(width.bits())
    {
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

fn reference_absorbs(inner_op: BinOp, outer: &Expr, candidate: &Expr) -> bool {
    matches!(
        candidate,
        Expr::Binary(op, left, right)
            if *op == inner_op && (outer == &**left || outer == &**right)
    )
}

const fn reference_is_zero(expr: &Expr) -> bool {
    matches!(expr, Expr::Const(0))
}

const fn reference_is_one(expr: &Expr) -> bool {
    matches!(expr, Expr::Const(1))
}

fn reference_is_all_ones(expr: &Expr, width: Width) -> bool {
    matches!(expr, Expr::Const(value) if (value & width.mask()) == width.mask())
}

fn reference_is_complement(left: &Expr, right: &Expr, width: Width) -> bool {
    reference_complement_of(left, width).as_ref() == Some(right)
        || reference_complement_of(right, width).as_ref() == Some(left)
}

fn reference_complement_of(expr: &Expr, width: Width) -> Option<Expr> {
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

fn reference_shift_left(value: u64, amount: u64, width: Width) -> u64 {
    let bits: u64 = u64::from(width.bits());
    if amount >= bits {
        0
    } else {
        value.wrapping_shl(amount as u32)
    }
}

fn reference_shift_right(value: u64, amount: u64, width: Width) -> u64 {
    let bits: u64 = u64::from(width.bits());
    if amount >= bits {
        0
    } else {
        value.wrapping_shr(amount as u32)
    }
}

fn full_const_leaves() -> Vec<Expr> {
    let mut out: Vec<Expr> = vec![Expr::var(0), Expr::var(1)];
    for value in 0u64..=255 {
        out.push(Expr::konst(value));
    }
    out
}

fn representative_leaves() -> Vec<Expr> {
    [
        Expr::var(0),
        Expr::var(1),
        Expr::konst(0),
        Expr::konst(1),
        Expr::konst(2),
        Expr::konst(0x0F),
        Expr::konst(0x7F),
        Expr::konst(0xFE),
        Expr::konst(0xFF),
        Expr::konst(0xFFFF),
    ]
    .to_vec()
}

const BIN_OPS: [BinOp; 8] = [
    BinOp::Add,
    BinOp::Sub,
    BinOp::Mul,
    BinOp::And,
    BinOp::Or,
    BinOp::Xor,
    BinOp::Shl,
    BinOp::Shr,
];

const UN_OPS: [UnOp; 2] = [UnOp::Neg, UnOp::Not];

fn assert_identical(expr: &Expr, width: Width) {
    let production: Expr = canonicalize(expr, width);
    let reference: Expr = reference_canonicalize(expr, width);
    assert_eq!(
        production, reference,
        "dsl-wired canonicalize `{production}` diverged from frozen reference `{reference}` for input `{expr}`"
    );
}

#[test]
fn binary_full_byte_domain_sweep_matches_reference_w8() {
    let leaves: Vec<Expr> = full_const_leaves();
    for op in BIN_OPS {
        for left in &leaves {
            for right in &leaves {
                let expr: Expr = Expr::Binary(op, Box::new(left.clone()), Box::new(right.clone()));
                assert_identical(&expr, Width::W8);
            }
        }
    }
}

#[test]
fn unary_over_binary_sweep_matches_reference_w8() {
    let leaves: Vec<Expr> = representative_leaves();
    for un in UN_OPS {
        for op in BIN_OPS {
            for left in &leaves {
                for right in &leaves {
                    let inner: Expr =
                        Expr::Binary(op, Box::new(left.clone()), Box::new(right.clone()));
                    let expr: Expr = Expr::Unary(un, Box::new(inner));
                    assert_identical(&expr, Width::W8);
                }
            }
        }
    }
}

#[test]
fn nested_binary_sweep_matches_reference_w8() {
    let leaves: Vec<Expr> = representative_leaves();
    for outer in BIN_OPS {
        for inner_op in BIN_OPS {
            for inner_left in &leaves {
                for inner_right in &leaves {
                    let inner: Expr = Expr::Binary(
                        inner_op,
                        Box::new(inner_left.clone()),
                        Box::new(inner_right.clone()),
                    );
                    for tail in &leaves {
                        let expr: Expr =
                            Expr::Binary(outer, Box::new(inner.clone()), Box::new(tail.clone()));
                        assert_identical(&expr, Width::W8);
                        let mirror: Expr =
                            Expr::Binary(outer, Box::new(tail.clone()), Box::new(inner.clone()));
                        assert_identical(&mirror, Width::W8);
                    }
                }
            }
        }
    }
}

#[test]
fn double_unary_sweep_matches_reference_w8() {
    let leaves: Vec<Expr> = full_const_leaves();
    for outer in UN_OPS {
        for inner in UN_OPS {
            for leaf in &leaves {
                let expr: Expr =
                    Expr::Unary(outer, Box::new(Expr::Unary(inner, Box::new(leaf.clone()))));
                assert_identical(&expr, Width::W8);
            }
        }
    }
}

#[test]
fn binary_sweep_matches_reference_other_widths() {
    let leaves: Vec<Expr> = representative_leaves();
    for width in [
        Width::W1,
        Width::W2,
        Width::W4,
        Width::W16,
        Width::W32,
        Width::W64,
    ] {
        for op in BIN_OPS {
            for left in &leaves {
                for right in &leaves {
                    let expr: Expr =
                        Expr::Binary(op, Box::new(left.clone()), Box::new(right.clone()));
                    assert_identical(&expr, width);
                }
            }
        }
    }
}

#[test]
fn migrated_identities_stay_semantics_preserving() {
    let cases: [(Expr, u32); 6] = [
        (Expr::add(Expr::var(0), Expr::konst(0)), 1),
        (Expr::mul(Expr::var(0), Expr::konst(0)), 1),
        (Expr::sub(Expr::var(0), Expr::var(0)), 1),
        (Expr::xor(Expr::var(0), Expr::var(0)), 1),
        (Expr::xor(Expr::var(0), Expr::konst(0xFF)), 1),
        (Expr::not(Expr::not(Expr::var(0))), 1),
    ];
    for (input, var_count) in cases {
        let out: Expr = canonicalize(&input, Width::W8);
        assert!(
            equivalent_exhaustive(&input, &out, Width::W8, var_count),
            "canonicalize changed semantics: `{input}` -> `{out}`"
        );
    }
}
