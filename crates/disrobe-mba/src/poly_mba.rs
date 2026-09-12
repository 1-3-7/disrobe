use crate::expr::{BinOp, Expr, UnOp, Width};
use crate::linear_solver::{scaled_atom_term, sum_terms};
use std::collections::BTreeMap;

pub const MAX_POLY_MBA_VARS: u32 = 4;

const MAX_POLY_ATOMS: usize = 24;
const MAX_POLY_MONOMIALS: usize = 8192;
const MAX_ATOM_DEGREE: u32 = 32;

type MonomialKey = Vec<(usize, u32)>;
type Polynomial = BTreeMap<MonomialKey, u128>;
type DenseKey = Vec<u32>;
type DensePoly = BTreeMap<DenseKey, u128>;

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
    let bits: u32 = width.bits();
    let mut atoms: Vec<Expr> = Vec::new();
    let sparse: Polynomial = expand(&normalized, &mut atoms, mask)?;
    let atom_count: usize = atoms.len();
    let std_dense: DensePoly = to_dense(&sparse, atom_count);

    let normal_std: DensePoly = falling_factorial_normal_form(&std_dense, atom_count, bits, mask)?;
    let reduced_std: DensePoly = to_power_basis(&normal_std, atom_count, mask)?;
    let candidate: Expr = build_expr(&reduced_std, &atoms, width)?;
    if candidate.node_count() >= expr.node_count() {
        return None;
    }

    let mut candidate_atoms: Vec<Expr> = atoms.clone();
    let candidate_sparse: Polynomial = expand(&candidate, &mut candidate_atoms, mask)?;
    if candidate_atoms.len() != atom_count {
        return None;
    }
    let candidate_dense: DensePoly = to_dense(&candidate_sparse, atom_count);

    let difference: Vec<(DenseKey, u128)> = subtract_dense(&std_dense, &candidate_dense, mask)
        .into_iter()
        .collect();
    let finite_diff_zero: bool =
        crate::finite_diff::multivar_induces_zero(&difference, atom_count, width);

    let normal_candidate: DensePoly =
        falling_factorial_normal_form(&candidate_dense, atom_count, bits, mask)?;
    let canonical_equal: bool = normal_std == normal_candidate;

    if finite_diff_zero != canonical_equal || !finite_diff_zero {
        return None;
    }
    Some(candidate)
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

fn to_dense(sparse: &Polynomial, atom_count: usize) -> DensePoly {
    let mut out: DensePoly = BTreeMap::new();
    for (monomial, coeff) in sparse {
        let mut key: DenseKey = vec![0; atom_count];
        for (atom, exponent) in monomial {
            if let Some(slot) = key.get_mut(*atom) {
                *slot = *exponent;
            }
        }
        out.insert(key, *coeff);
    }
    out
}

fn max_axis_degree(poly: &DensePoly, atom_count: usize) -> u32 {
    let mut max_degree: u32 = 0;
    for key in poly.keys() {
        for exponent in key.iter().take(atom_count) {
            if *exponent > max_degree {
                max_degree = *exponent;
            }
        }
    }
    max_degree
}

fn falling_factorial_normal_form(
    poly: &DensePoly,
    atom_count: usize,
    bits: u32,
    mask: u128,
) -> Option<DensePoly> {
    let falling: DensePoly = to_falling_factorial(poly, atom_count, mask)?;
    Some(reduce_null_ideal(&falling, bits))
}

fn to_falling_factorial(poly: &DensePoly, atom_count: usize, mask: u128) -> Option<DensePoly> {
    let max_degree: u32 = max_axis_degree(poly, atom_count);
    if max_degree > MAX_ATOM_DEGREE {
        return None;
    }
    let expansion: Vec<Vec<(u32, u128)>> = basis_expansion(&stirling_second(max_degree, mask));
    substitute_all_axes(poly, atom_count, &expansion, mask)
}

fn to_power_basis(poly: &DensePoly, atom_count: usize, mask: u128) -> Option<DensePoly> {
    let max_degree: u32 = max_axis_degree(poly, atom_count);
    if max_degree > MAX_ATOM_DEGREE {
        return None;
    }
    let expansion: Vec<Vec<(u32, u128)>> =
        basis_expansion(&stirling_first_signed(max_degree, mask));
    substitute_all_axes(poly, atom_count, &expansion, mask)
}

fn substitute_all_axes(
    poly: &DensePoly,
    atom_count: usize,
    expansion: &[Vec<(u32, u128)>],
    mask: u128,
) -> Option<DensePoly> {
    let mut current: DensePoly = poly.clone();
    for axis in 0..atom_count {
        current = substitute_axis(&current, axis, expansion, mask)?;
    }
    Some(current)
}

fn substitute_axis(
    poly: &DensePoly,
    axis: usize,
    expansion: &[Vec<(u32, u128)>],
    mask: u128,
) -> Option<DensePoly> {
    let mut out: DensePoly = BTreeMap::new();
    for (key, coeff) in poly {
        let current_exponent: usize = *key.get(axis)? as usize;
        let terms: &Vec<(u32, u128)> = expansion.get(current_exponent)?;
        for (new_exponent, factor) in terms {
            let contribution: u128 = (coeff & mask).wrapping_mul(*factor & mask) & mask;
            if contribution == 0 {
                continue;
            }
            let mut new_key: DenseKey = key.clone();
            if let Some(slot) = new_key.get_mut(axis) {
                *slot = *new_exponent;
            }
            let entry: &mut u128 = out.entry(new_key).or_insert(0);
            *entry = entry.wrapping_add(contribution) & mask;
            if out.len() > MAX_POLY_MONOMIALS {
                return None;
            }
        }
    }
    out.retain(|_, value: &mut u128| *value != 0);
    Some(out)
}

fn basis_expansion(table: &[Vec<u128>]) -> Vec<Vec<(u32, u128)>> {
    let mut expansion: Vec<Vec<(u32, u128)>> = Vec::with_capacity(table.len());
    for row in table {
        let mut terms: Vec<(u32, u128)> = Vec::new();
        for (target, coeff) in row.iter().enumerate() {
            if *coeff != 0 {
                terms.push((target as u32, *coeff));
            }
        }
        expansion.push(terms);
    }
    expansion
}

fn stirling_second(max_degree: u32, mask: u128) -> Vec<Vec<u128>> {
    let size: usize = max_degree as usize + 1;
    let mut base: Vec<u128> = vec![0; size];
    base[0] = 1;
    let mut table: Vec<Vec<u128>> = vec![base];
    for power in 1..size {
        let mut row: Vec<u128> = vec![0; size];
        let previous: &[u128] = &table[power - 1];
        for count in 1..=power {
            let scaled: u128 = (count as u128 & mask).wrapping_mul(previous[count]) & mask;
            let promoted: u128 = previous[count - 1];
            row[count] = scaled.wrapping_add(promoted) & mask;
        }
        table.push(row);
    }
    table
}

fn stirling_first_signed(max_degree: u32, mask: u128) -> Vec<Vec<u128>> {
    let size: usize = max_degree as usize + 1;
    let mut base: Vec<u128> = vec![0; size];
    base[0] = 1;
    let mut table: Vec<Vec<u128>> = vec![base];
    for degree in 1..size {
        let mut row: Vec<u128> = vec![0; size];
        let previous: &[u128] = &table[degree - 1];
        for power in 1..=degree {
            let scaled: u128 = ((degree - 1) as u128 & mask).wrapping_mul(previous[power]) & mask;
            let promoted: u128 = previous[power - 1];
            row[power] = promoted.wrapping_sub(scaled) & mask;
        }
        table.push(row);
    }
    table
}

fn reduce_null_ideal(falling: &DensePoly, bits: u32) -> DensePoly {
    let mut out: DensePoly = BTreeMap::new();
    for (key, coeff) in falling {
        let modulus: u128 = null_modulus(key, bits);
        let reduced: u128 = coeff % modulus;
        if reduced != 0 {
            out.insert(key.clone(), reduced);
        }
    }
    out
}

fn null_modulus(key: &DenseKey, bits: u32) -> u128 {
    let mut valuation: u32 = 0;
    for degree in key {
        valuation = valuation.saturating_add(two_adic_factorial(*degree));
    }
    let exponent: u32 = bits.saturating_sub(valuation);
    1u128 << exponent
}

const fn two_adic_factorial(degree: u32) -> u32 {
    degree - degree.count_ones()
}

fn subtract_dense(lhs: &DensePoly, rhs: &DensePoly, mask: u128) -> DensePoly {
    let mut out: DensePoly = lhs.clone();
    for (key, coeff) in rhs {
        let negated: u128 = ((mask + 1).wrapping_sub(*coeff)) & mask;
        let entry: &mut u128 = out.entry(key.clone()).or_insert(0);
        *entry = entry.wrapping_add(negated) & mask;
    }
    out.retain(|_, value: &mut u128| *value != 0);
    out
}

fn build_expr(poly: &DensePoly, atoms: &[Expr], width: Width) -> Option<Expr> {
    let mut terms: Vec<Expr> = Vec::new();
    for (key, coeff) in poly {
        let monomial: Option<Expr> = build_monomial(key, atoms);
        let term: Expr = scaled_atom_term(*coeff as i128, monomial, width)?;
        terms.push(term);
    }
    if terms.is_empty() {
        return Some(Expr::konst(0));
    }
    Some(sum_terms(terms))
}

fn build_monomial(key: &DenseKey, atoms: &[Expr]) -> Option<Expr> {
    let mut factors: Vec<Expr> = Vec::new();
    for (atom_index, exponent) in key.iter().enumerate() {
        for _ in 0..*exponent {
            factors.push(atoms.get(atom_index)?.clone());
        }
    }
    let mut iter: std::vec::IntoIter<Expr> = factors.into_iter();
    let first: Expr = iter.next()?;
    let mut product: Expr = first;
    for factor in iter {
        product = Expr::mul(product, factor);
    }
    Some(product)
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

    #[test]
    fn half_scaled_square_collapses_to_linear_at_w8() {
        let atom: Expr = Expr::and(var(0), var(1));
        let obfuscated: Expr = Expr::mul(Expr::konst(128), Expr::mul(atom.clone(), atom.clone()));
        let solved: Expr =
            solve_polynomial_mba(&obfuscated, Width::W8, 2).expect("128*(x&y)^2 == 128*(x&y)");
        assert!(equivalent_exhaustive(&obfuscated, &solved, Width::W8, 2));
        assert!(solved.node_count() < obfuscated.node_count());
        let linear: Expr = Expr::mul(Expr::konst(128), atom);
        assert!(equivalent_exhaustive(&solved, &linear, Width::W8, 2));
    }

    #[test]
    fn half_scaled_falling_factorial_vanishes_at_w8() {
        let atom: Expr = Expr::or(var(0), var(1));
        let predecessor: Expr = Expr::add(atom.clone(), Expr::konst(255));
        let obfuscated: Expr = Expr::mul(Expr::konst(128), Expr::mul(atom, predecessor));
        let solved: Expr =
            solve_polynomial_mba(&obfuscated, Width::W8, 2).expect("128*u*(u-1) == 0 mod 2^8");
        assert!(equivalent_exhaustive(&obfuscated, &solved, Width::W8, 2));
        assert!(equivalent_exhaustive(
            &solved,
            &Expr::konst(0),
            Width::W8,
            2
        ));
    }

    #[test]
    fn half_scaled_square_survives_at_wider_width() {
        let atom: Expr = Expr::and(var(0), var(1));
        let obfuscated: Expr = Expr::mul(Expr::konst(128), Expr::mul(atom.clone(), atom));
        assert!(solve_polynomial_mba(&obfuscated, Width::W16, 2).is_none());
    }

    #[test]
    fn correlated_product_abstains() {
        let obfuscated: Expr = Expr::mul(Expr::and(var(0), var(1)), Expr::or(var(0), var(1)));
        assert!(solve_polynomial_mba(&obfuscated, Width::W8, 2).is_none());
    }
}
