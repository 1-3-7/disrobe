#![doc = "Polynomial MBA reduction over Z/2^n by exact multivariate expansion."]
#![doc = ""]
#![doc = "A polynomial mixed-boolean-arithmetic expression is a sum of products of"]
#![doc = "bitwise terms over a ring (addition, subtraction, negation, multiplication, and"]
#![doc = "shift-by-constant). Each maximal bitwise subterm is abstracted to a fresh"]
#![doc = "indeterminate, the expression is expanded distributively into a multivariate"]
#![doc = "polynomial whose coefficients live in Z/2^n, and the coefficients are reduced"]
#![doc = "modulo 2^n. When every surviving monomial has degree at most one the expression"]
#![doc = "equals an affine combination of those bitwise terms over Z/2^n, and that affine"]
#![doc = "form is emitted. Because distributive expansion and coefficient reduction modulo"]
#![doc = "2^n are exact ring homomorphisms, the emitted form is equal to the input over"]
#![doc = "Z/2^n at the exact operand width; this is a per-width proof that does not"]
#![doc = "transfer across widths. Right shift and division are not ring operations and are"]
#![doc = "left untouched. A monomial of degree two or higher that survives reduction is a"]
#![doc = "genuine nonlinearity at this width and the expression is left untouched."]

use crate::expr::{BinOp, Expr, UnOp, Width};
use crate::linear_solver::{scaled_atom_term, sum_terms};
use std::collections::BTreeMap;

pub const MAX_POLY_MBA_VARS: u32 = 4;

const MAX_POLY_ATOMS: usize = 24;
const MAX_POLY_MONOMIALS: usize = 8192;

type MonomialKey = Vec<(usize, u32)>;
type Polynomial = BTreeMap<MonomialKey, u128>;

#[must_use]
pub fn solve_polynomial_mba(expr: &Expr, width: Width, var_count: u32) -> Option<Expr> {
    if var_count == 0 || var_count > MAX_POLY_MBA_VARS {
        return None;
    }
    if !is_ring_polynomial(expr) || !contains_genuine_product(expr) {
        return None;
    }
    let normalized: Expr = crate::rewrite::canonicalize(expr, width);
    let mask: u128 = u128::from(width.mask());
    let mut atoms: Vec<Expr> = Vec::new();
    let poly: Polynomial = expand(&normalized, &mut atoms, mask)?;

    let mut terms: Vec<Expr> = Vec::new();
    for (monomial, coeff) in &poly {
        let reduced: u128 = coeff & mask;
        if reduced == 0 {
            continue;
        }
        if total_degree(monomial) > 1 {
            return None;
        }
        let atom: Option<Expr> = match monomial.first() {
            None => None,
            Some((atom_index, _)) => Some(atoms.get(*atom_index)?.clone()),
        };
        let term: Expr = scaled_atom_term(reduced as i128, atom, width)?;
        terms.push(term);
    }

    let candidate: Expr = if terms.is_empty() {
        Expr::konst(0)
    } else {
        sum_terms(terms)
    };

    let mut check_atoms: Vec<Expr> = Vec::new();
    let candidate_poly: Polynomial = expand(&candidate, &mut check_atoms, mask)?;
    if !polynomials_equal(&candidate_poly, &check_atoms, &poly, &atoms, mask) {
        return None;
    }
    Some(candidate)
}

fn total_degree(monomial: &MonomialKey) -> u32 {
    monomial
        .iter()
        .map(|(_, exponent): &(usize, u32)| *exponent)
        .sum()
}

fn is_ring_polynomial(expr: &Expr) -> bool {
    match expr {
        Expr::Const(_)
        | Expr::Var(_)
        | Expr::Unary(UnOp::Not, _)
        | Expr::Binary(BinOp::And | BinOp::Or | BinOp::Xor, _, _) => true,
        Expr::Unary(UnOp::Neg, inner) => is_ring_polynomial(inner),
        Expr::Binary(BinOp::Add | BinOp::Sub | BinOp::Mul, left, right) => {
            is_ring_polynomial(left) && is_ring_polynomial(right)
        }
        Expr::Binary(BinOp::Shl, left, right) => {
            matches!(&**right, Expr::Const(_)) && is_ring_polynomial(left)
        }
        Expr::Binary(BinOp::Shr, _, _)
        | Expr::Ite(_, _, _)
        | Expr::Slice(_, _, _)
        | Expr::Compose(_, _, _)
        | Expr::Mem(_, _) => false,
    }
}

fn contains_genuine_product(expr: &Expr) -> bool {
    match expr {
        Expr::Binary(BinOp::Mul, left, right) => {
            (!matches!(&**left, Expr::Const(_)) && !matches!(&**right, Expr::Const(_)))
                || contains_genuine_product(left)
                || contains_genuine_product(right)
        }
        Expr::Unary(_, inner) => contains_genuine_product(inner),
        Expr::Binary(_, left, right) => {
            contains_genuine_product(left) || contains_genuine_product(right)
        }
        Expr::Const(_)
        | Expr::Var(_)
        | Expr::Ite(_, _, _)
        | Expr::Slice(_, _, _)
        | Expr::Compose(_, _, _)
        | Expr::Mem(_, _) => false,
    }
}

fn expand(expr: &Expr, atoms: &mut Vec<Expr>, mask: u128) -> Option<Polynomial> {
    match expr {
        Expr::Const(value) => Some(constant_poly(u128::from(*value) & mask)),
        Expr::Var(_)
        | Expr::Unary(UnOp::Not, _)
        | Expr::Binary(BinOp::And | BinOp::Or | BinOp::Xor, _, _) => {
            let index: usize = intern_atom(atoms, expr.clone())?;
            Some(atom_poly(index))
        }
        Expr::Unary(UnOp::Neg, inner) => {
            let poly: Polynomial = expand(inner, atoms, mask)?;
            Some(negate_poly(&poly, mask))
        }
        Expr::Binary(BinOp::Add, left, right) => {
            let lhs: Polynomial = expand(left, atoms, mask)?;
            let rhs: Polynomial = expand(right, atoms, mask)?;
            Some(add_poly(&lhs, &rhs, mask))
        }
        Expr::Binary(BinOp::Sub, left, right) => {
            let lhs: Polynomial = expand(left, atoms, mask)?;
            let rhs: Polynomial = expand(right, atoms, mask)?;
            let neg_rhs: Polynomial = negate_poly(&rhs, mask);
            Some(add_poly(&lhs, &neg_rhs, mask))
        }
        Expr::Binary(BinOp::Mul, left, right) => {
            let lhs: Polynomial = expand(left, atoms, mask)?;
            let rhs: Polynomial = expand(right, atoms, mask)?;
            multiply_poly(&lhs, &rhs, mask)
        }
        Expr::Binary(BinOp::Shl, left, right) => {
            let Expr::Const(amount): &Expr = right.as_ref() else {
                return None;
            };
            let poly: Polynomial = expand(left, atoms, mask)?;
            let factor: u128 = if *amount >= 128 {
                0
            } else {
                (1u128 << *amount) & mask
            };
            Some(scale_poly(&poly, factor, mask))
        }
        Expr::Binary(BinOp::Shr, _, _)
        | Expr::Ite(_, _, _)
        | Expr::Slice(_, _, _)
        | Expr::Compose(_, _, _)
        | Expr::Mem(_, _) => None,
    }
}

fn intern_atom(atoms: &mut Vec<Expr>, atom: Expr) -> Option<usize> {
    if let Some(index) = atoms.iter().position(|existing: &Expr| *existing == atom) {
        return Some(index);
    }
    if atoms.len() >= MAX_POLY_ATOMS {
        return None;
    }
    atoms.push(atom);
    Some(atoms.len() - 1)
}

fn constant_poly(value: u128) -> Polynomial {
    let mut poly: Polynomial = BTreeMap::new();
    if value != 0 {
        poly.insert(Vec::new(), value);
    }
    poly
}

fn atom_poly(index: usize) -> Polynomial {
    let mut poly: Polynomial = BTreeMap::new();
    poly.insert(vec![(index, 1)], 1);
    poly
}

fn add_poly(lhs: &Polynomial, rhs: &Polynomial, mask: u128) -> Polynomial {
    let mut out: Polynomial = lhs.clone();
    for (monomial, coeff) in rhs {
        insert_coeff(&mut out, monomial.clone(), *coeff, mask);
    }
    out
}

fn negate_poly(poly: &Polynomial, mask: u128) -> Polynomial {
    let mut out: Polynomial = BTreeMap::new();
    for (monomial, coeff) in poly {
        let negated: u128 = ((mask + 1).wrapping_sub(*coeff)) & mask;
        insert_coeff(&mut out, monomial.clone(), negated, mask);
    }
    out
}

fn scale_poly(poly: &Polynomial, factor: u128, mask: u128) -> Polynomial {
    let mut out: Polynomial = BTreeMap::new();
    if factor & mask == 0 {
        return out;
    }
    for (monomial, coeff) in poly {
        let scaled: u128 = coeff.wrapping_mul(factor) & mask;
        insert_coeff(&mut out, monomial.clone(), scaled, mask);
    }
    out
}

fn multiply_poly(lhs: &Polynomial, rhs: &Polynomial, mask: u128) -> Option<Polynomial> {
    let mut out: Polynomial = BTreeMap::new();
    for (left_monomial, left_coeff) in lhs {
        for (right_monomial, right_coeff) in rhs {
            let product: u128 = (left_coeff & mask).wrapping_mul(right_coeff & mask) & mask;
            if product == 0 {
                continue;
            }
            let key: MonomialKey = merge_monomials(left_monomial, right_monomial);
            insert_coeff(&mut out, key, product, mask);
            if out.len() > MAX_POLY_MONOMIALS {
                return None;
            }
        }
    }
    Some(out)
}

fn merge_monomials(lhs: &MonomialKey, rhs: &MonomialKey) -> MonomialKey {
    let mut combined: BTreeMap<usize, u32> = BTreeMap::new();
    for (atom, exponent) in lhs.iter().chain(rhs.iter()) {
        *combined.entry(*atom).or_insert(0) += *exponent;
    }
    combined.into_iter().collect()
}

fn insert_coeff(poly: &mut Polynomial, monomial: MonomialKey, coeff: u128, mask: u128) {
    let masked: u128 = coeff & mask;
    let entry: &mut u128 = poly.entry(monomial).or_insert(0);
    *entry = entry.wrapping_add(masked) & mask;
    let is_zero: bool = *entry == 0;
    if is_zero {
        poly.retain(|_, value: &mut u128| *value != 0);
    }
}

fn polynomials_equal(
    left: &Polynomial,
    left_atoms: &[Expr],
    right: &Polynomial,
    right_atoms: &[Expr],
    mask: u128,
) -> bool {
    let left_canonical: BTreeMap<Vec<(Vec<u64>, u32)>, u128> =
        canonical_poly(left, left_atoms, mask);
    let right_canonical: BTreeMap<Vec<(Vec<u64>, u32)>, u128> =
        canonical_poly(right, right_atoms, mask);
    left_canonical == right_canonical
}

fn canonical_poly(
    poly: &Polynomial,
    atoms: &[Expr],
    mask: u128,
) -> BTreeMap<Vec<(Vec<u64>, u32)>, u128> {
    let mut out: BTreeMap<Vec<(Vec<u64>, u32)>, u128> = BTreeMap::new();
    for (monomial, coeff) in poly {
        let reduced: u128 = coeff & mask;
        if reduced == 0 {
            continue;
        }
        let mut key: Vec<(Vec<u64>, u32)> = Vec::with_capacity(monomial.len());
        for (atom_index, exponent) in monomial {
            let Some(atom): Option<&Expr> = atoms.get(*atom_index) else {
                return BTreeMap::new();
            };
            key.push((atom_fingerprint(atom), *exponent));
        }
        key.sort();
        out.insert(key, reduced);
    }
    out
}

fn atom_fingerprint(atom: &Expr) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    encode(atom, &mut out);
    out
}

fn encode(expr: &Expr, out: &mut Vec<u64>) {
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
            encode(inner, out);
        }
        Expr::Binary(op, left, right) => {
            out.push(3);
            out.push(binop_tag(*op));
            encode(left, out);
            encode(right, out);
        }
        Expr::Ite(cond, then, otherwise) => {
            out.push(4);
            encode(cond, out);
            encode(then, out);
            encode(otherwise, out);
        }
        Expr::Slice(inner, lo, hi) => {
            out.push(5);
            out.push(u64::from(*lo));
            out.push(u64::from(*hi));
            encode(inner, out);
        }
        Expr::Compose(low, high, low_bits) => {
            out.push(6);
            out.push(u64::from(*low_bits));
            encode(low, out);
            encode(high, out);
        }
        Expr::Mem(addr, width) => {
            out.push(7);
            out.push(u64::from(width.bits()));
            encode(addr, out);
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::expr::equivalent_exhaustive;

    fn var(index: u32) -> Expr {
        Expr::var(index)
    }

    #[test]
    fn distributive_cancellation_recovers_variable() {
        let obfuscated: Expr = Expr::sub(
            Expr::mul(var(0), Expr::add(var(1), Expr::konst(1))),
            Expr::mul(var(0), var(1)),
        );
        let solved: Expr = solve_polynomial_mba(&obfuscated, Width::W8, 2).expect("must reduce");
        assert!(equivalent_exhaustive(&obfuscated, &solved, Width::W8, 2));
        assert!(solved.node_count() < obfuscated.node_count());
    }

    #[test]
    fn degree_three_product_cancels_to_variable() {
        let product: Expr = Expr::mul(Expr::mul(var(0), var(1)), var(2));
        let obfuscated: Expr = Expr::sub(Expr::add(var(0), product.clone()), product);
        let solved: Expr = solve_polynomial_mba(&obfuscated, Width::W8, 3).expect("must reduce");
        assert!(equivalent_exhaustive(&obfuscated, &solved, Width::W8, 3));
    }

    #[test]
    fn genuine_product_is_left_untouched() {
        let genuine: Expr = Expr::mul(var(0), var(1));
        assert!(solve_polynomial_mba(&genuine, Width::W8, 2).is_none());
    }

    #[test]
    fn surviving_square_is_left_untouched() {
        let square: Expr = Expr::mul(var(0), var(0));
        assert!(solve_polynomial_mba(&square, Width::W8, 1).is_none());
    }

    #[test]
    fn right_shift_is_rejected() {
        let shifted: Expr = Expr::mul(Expr::shr(var(0), Expr::konst(1)), var(0));
        assert!(solve_polynomial_mba(&shifted, Width::W8, 1).is_none());
    }

    #[test]
    fn width_specific_coefficient_vanishes() {
        let product: Expr = Expr::mul(var(0), var(1));
        let obfuscated: Expr = Expr::add(var(0), Expr::mul(Expr::konst(256), product));
        let solved: Expr =
            solve_polynomial_mba(&obfuscated, Width::W8, 2).expect("256*x*y is 0 mod 2^8");
        assert!(equivalent_exhaustive(&obfuscated, &solved, Width::W8, 2));
        assert!(equivalent_exhaustive(&solved, &var(0), Width::W8, 2));
    }

    #[test]
    fn width_specific_coefficient_survives_at_wider_width() {
        let product: Expr = Expr::mul(var(0), var(1));
        let obfuscated: Expr = Expr::add(var(0), Expr::mul(Expr::konst(256), product));
        assert!(solve_polynomial_mba(&obfuscated, Width::W16, 2).is_none());
    }
}
