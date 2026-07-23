use crate::expr::{BinOp, Expr, UnOp, Width};
use std::collections::BTreeMap;

const MAX_MONOMIALS: usize = 4096;
const MAX_MONOMIAL_DEGREE: u32 = 128;

type Monomial = BTreeMap<u32, u32>;
type Poly = BTreeMap<Monomial, u64>;

#[derive(Debug, Default)]
struct AtomTable {
    registry: Vec<Expr>,
}

impl AtomTable {
    fn intern(&mut self, expr: &Expr) -> Option<u32> {
        if let Some(position) = self.registry.iter().position(|entry: &Expr| entry == expr) {
            return u32::try_from(position).ok();
        }
        self.registry.push(expr.clone());
        u32::try_from(self.registry.len() - 1).ok()
    }
}

fn poly_constant(value: u64) -> Poly {
    let mut poly: Poly = Poly::new();
    if value != 0 {
        poly.insert(Monomial::new(), value);
    }
    poly
}

fn poly_atom(id: u32) -> Poly {
    let mut monomial: Monomial = Monomial::new();
    monomial.insert(id, 1);
    let mut poly: Poly = Poly::new();
    poly.insert(monomial, 1);
    poly
}

fn accumulate(poly: &mut Poly, monomial: Monomial, coeff: u64, mask: u64) {
    if coeff == 0 {
        return;
    }
    let updated: u64 = poly
        .get(&monomial)
        .copied()
        .unwrap_or(0)
        .wrapping_add(coeff)
        & mask;
    if updated == 0 {
        poly.remove(&monomial);
    } else {
        poly.insert(monomial, updated);
    }
}

fn negate(poly: &Poly, mask: u64) -> Poly {
    poly.iter()
        .map(|(monomial, coeff): (&Monomial, &u64)| (monomial.clone(), coeff.wrapping_neg() & mask))
        .collect()
}

fn add(left: &Poly, right: &Poly, mask: u64) -> Poly {
    let mut result: Poly = left.clone();
    for (monomial, coeff) in right {
        accumulate(&mut result, monomial.clone(), *coeff, mask);
    }
    result
}

fn scale(poly: &Poly, factor: u64, mask: u64) -> Poly {
    let mut result: Poly = Poly::new();
    for (monomial, coeff) in poly {
        let product: u64 = ((u128::from(*coeff) * u128::from(factor)) & u128::from(mask)) as u64;
        accumulate(&mut result, monomial.clone(), product, mask);
    }
    result
}

fn multiply_monomials(left: &Monomial, right: &Monomial) -> Option<Monomial> {
    let mut result: Monomial = left.clone();
    let mut degree: u32 = result.values().sum();
    for (atom, exponent) in right {
        let entry: &mut u32 = result.entry(*atom).or_insert(0);
        *entry = entry.checked_add(*exponent)?;
        degree = degree.checked_add(*exponent)?;
    }
    if degree > MAX_MONOMIAL_DEGREE {
        return None;
    }
    Some(result)
}

fn multiply(left: &Poly, right: &Poly, mask: u64) -> Option<Poly> {
    let mut result: Poly = Poly::new();
    for (left_monomial, left_coeff) in left {
        for (right_monomial, right_coeff) in right {
            let monomial: Monomial = multiply_monomials(left_monomial, right_monomial)?;
            let coeff: u64 =
                ((u128::from(*left_coeff) * u128::from(*right_coeff)) & u128::from(mask)) as u64;
            accumulate(&mut result, monomial, coeff, mask);
            if result.len() > MAX_MONOMIALS {
                return None;
            }
        }
    }
    Some(result)
}

fn normalize(expr: &Expr, width: Width, atoms: &mut AtomTable) -> Option<Poly> {
    let mask: u64 = width.mask();
    match expr {
        Expr::Const(value) => Some(poly_constant(value & mask)),
        Expr::Unary(UnOp::Neg, inner) => {
            let inner_poly: Poly = normalize(inner, width, atoms)?;
            Some(negate(&inner_poly, mask))
        }
        Expr::Binary(BinOp::Add, left, right) => {
            let left_poly: Poly = normalize(left, width, atoms)?;
            let right_poly: Poly = normalize(right, width, atoms)?;
            Some(add(&left_poly, &right_poly, mask))
        }
        Expr::Binary(BinOp::Sub, left, right) => {
            let left_poly: Poly = normalize(left, width, atoms)?;
            let right_poly: Poly = normalize(right, width, atoms)?;
            Some(add(&left_poly, &negate(&right_poly, mask), mask))
        }
        Expr::Binary(BinOp::Mul, left, right) => {
            let left_poly: Poly = normalize(left, width, atoms)?;
            let right_poly: Poly = normalize(right, width, atoms)?;
            multiply(&left_poly, &right_poly, mask)
        }
        Expr::Binary(BinOp::Shl, left, right) => {
            let Expr::Const(shift) = right.as_ref() else {
                return Some(poly_atom(atoms.intern(expr)?));
            };
            let left_poly: Poly = normalize(left, width, atoms)?;
            let amount: u64 = *shift & mask;
            let factor: u64 = if amount >= u64::from(width.bits()) {
                0
            } else {
                (1u64 << amount) & mask
            };
            Some(scale(&left_poly, factor, mask))
        }
        Expr::Binary(BinOp::Xor, left, right) if left == right => Some(poly_constant(0)),
        Expr::Binary(BinOp::And | BinOp::Or, left, right) if left == right => {
            normalize(left, width, atoms)
        }
        Expr::Binary(BinOp::Xor, left, right) => {
            let left_poly: Poly = normalize(left, width, atoms)?;
            let right_poly: Poly = normalize(right, width, atoms)?;
            let conjunction: u32 = atoms.intern(&Expr::and((**left).clone(), (**right).clone()))?;
            let sum: Poly = add(&left_poly, &right_poly, mask);
            Some(add(
                &sum,
                &negate(&scale(&poly_atom(conjunction), 2, mask), mask),
                mask,
            ))
        }
        Expr::Binary(BinOp::Or, left, right) => {
            let left_poly: Poly = normalize(left, width, atoms)?;
            let right_poly: Poly = normalize(right, width, atoms)?;
            let conjunction: u32 = atoms.intern(&Expr::and((**left).clone(), (**right).clone()))?;
            let sum: Poly = add(&left_poly, &right_poly, mask);
            Some(add(&sum, &negate(&poly_atom(conjunction), mask), mask))
        }
        Expr::Unary(UnOp::Not, inner) => {
            let inner_poly: Poly = normalize(inner, width, atoms)?;
            Some(add(&poly_constant(mask), &negate(&inner_poly, mask), mask))
        }
        _ => Some(poly_atom(atoms.intern(expr)?)),
    }
}

fn var_upper_bound(expr: &Expr, bound: &mut u32) {
    match expr {
        Expr::Const(_) => {}
        Expr::Var(index) => *bound = (*bound).max(index.saturating_add(1)),
        Expr::Unary(_, inner) | Expr::Slice(inner, _, _) | Expr::Mem(inner, _) => {
            var_upper_bound(inner, bound);
        }
        Expr::Binary(_, left, right) | Expr::Compose(left, right, _) => {
            var_upper_bound(left, bound);
            var_upper_bound(right, bound);
        }
        Expr::Ite(cond, then_branch, else_branch) => {
            var_upper_bound(cond, bound);
            var_upper_bound(then_branch, bound);
            var_upper_bound(else_branch, bound);
        }
    }
}

fn concrete_refutes(original: &Expr, candidate: &Expr, width: Width) -> bool {
    let mask: u64 = width.mask();
    let mut var_count: u32 = 0;
    var_upper_bound(original, &mut var_count);
    var_upper_bound(candidate, &mut var_count);
    let corners: [u64; 6] = [
        0,
        1,
        mask,
        mask ^ 1,
        0x5555_5555_5555_5555 & mask,
        0xAAAA_AAAA_AAAA_AAAA & mask,
    ];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for round in 0..64u32 {
        let mut env: Vec<u64> = Vec::with_capacity(var_count as usize);
        for index in 0..var_count {
            let value: u64 = if (round as usize) < corners.len() {
                corners[round as usize]
            } else {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state = state.wrapping_add(u64::from(index).wrapping_mul(0x1000_0001B));
                state & mask
            };
            env.push(value);
        }
        if original.eval(&env, width) & mask != candidate.eval(&env, width) & mask {
            return true;
        }
    }
    false
}

#[must_use]
pub fn polynomial_identity_proves(original: &Expr, candidate: &Expr, width: Width) -> bool {
    if concrete_refutes(original, candidate, width) {
        return false;
    }
    let mut atoms: AtomTable = AtomTable::default();
    let Some(original_poly): Option<Poly> = normalize(original, width, &mut atoms) else {
        return false;
    };
    let Some(candidate_poly): Option<Poly> = normalize(candidate, width, &mut atoms) else {
        return false;
    };
    original_poly == candidate_poly
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::polynomial_identity_proves;
    use crate::expr::{Expr, Width};

    fn var(index: u32) -> Expr {
        Expr::var(index)
    }

    #[test]
    fn commuted_product_difference_is_zero_at_w64() {
        let original: Expr = Expr::sub(Expr::mul(var(0), var(1)), Expr::mul(var(1), var(0)));
        assert!(polynomial_identity_proves(
            &original,
            &Expr::konst(0),
            Width::W64
        ));
    }

    #[test]
    fn xor_self_cancels_under_product_at_w64() {
        let original: Expr = Expr::add(Expr::mul(var(0), var(1)), Expr::xor(var(2), var(2)));
        let candidate: Expr = Expr::mul(var(0), var(1));
        assert!(polynomial_identity_proves(
            &original,
            &candidate,
            Width::W64
        ));
    }

    #[test]
    fn distributes_multiplication_over_addition() {
        let original: Expr = Expr::mul(var(0), Expr::add(var(1), var(2)));
        let candidate: Expr = Expr::add(Expr::mul(var(0), var(1)), Expr::mul(var(0), var(2)));
        assert!(polynomial_identity_proves(
            &original,
            &candidate,
            Width::W32
        ));
    }

    #[test]
    fn shift_left_by_constant_is_multiplication() {
        let original: Expr = Expr::shl(var(0), Expr::konst(3));
        let candidate: Expr = Expr::mul(var(0), Expr::konst(8));
        assert!(polynomial_identity_proves(
            &original,
            &candidate,
            Width::W32
        ));
    }

    #[test]
    fn oversized_constant_shift_uses_the_width_masked_amount() {
        let atom: Expr = Expr::mem(var(0), Width::W8);
        let shifted: Expr = Expr::shl(atom.clone(), Expr::konst(256));
        assert!(!polynomial_identity_proves(
            &shifted,
            &Expr::konst(0),
            Width::W8
        ));
        assert!(polynomial_identity_proves(&shifted, &atom, Width::W8));
    }

    #[test]
    fn rejects_a_non_equivalent_product() {
        let original: Expr = Expr::mul(var(0), var(1));
        let candidate: Expr = Expr::add(var(0), var(1));
        assert!(!polynomial_identity_proves(
            &original,
            &candidate,
            Width::W32
        ));
    }

    #[test]
    fn abstains_on_opaque_shift_mismatch() {
        let original: Expr = Expr::shr(var(0), Expr::konst(1));
        let candidate: Expr = Expr::konst(0);
        assert!(!polynomial_identity_proves(
            &original,
            &candidate,
            Width::W32
        ));
    }

    #[test]
    fn opaque_atoms_cancel_when_structurally_shared() {
        let shifted: Expr = Expr::shr(var(0), Expr::konst(1));
        let original: Expr = Expr::sub(
            Expr::add(Expr::mul(var(1), var(1)), shifted.clone()),
            shifted,
        );
        let candidate: Expr = Expr::mul(var(1), var(1));
        assert!(polynomial_identity_proves(
            &original,
            &candidate,
            Width::W64
        ));
    }

    #[test]
    fn xor_plus_twice_and_recovers_addition_at_w64() {
        let obfuscated: Expr = Expr::add(
            Expr::xor(var(0), var(1)),
            Expr::mul(Expr::konst(2), Expr::and(var(0), var(1))),
        );
        let clean: Expr = Expr::add(var(0), var(1));
        assert!(polynomial_identity_proves(&obfuscated, &clean, Width::W64));
    }

    #[test]
    fn or_plus_and_recovers_addition_at_w64() {
        let obfuscated: Expr = Expr::add(Expr::or(var(0), var(1)), Expr::and(var(0), var(1)));
        let clean: Expr = Expr::add(var(0), var(1));
        assert!(polynomial_identity_proves(&obfuscated, &clean, Width::W64));
    }

    #[test]
    fn or_minus_xor_recovers_and_at_w32() {
        let obfuscated: Expr = Expr::sub(Expr::or(var(0), var(1)), Expr::xor(var(0), var(1)));
        let clean: Expr = Expr::and(var(0), var(1));
        assert!(polynomial_identity_proves(&obfuscated, &clean, Width::W32));
    }

    #[test]
    fn complement_plus_self_is_all_ones_at_w32() {
        let obfuscated: Expr = Expr::add(Expr::not(var(0)), var(0));
        assert!(polynomial_identity_proves(
            &obfuscated,
            &Expr::konst(0xFFFF_FFFF),
            Width::W32
        ));
    }

    #[test]
    fn does_not_falsely_equate_or_with_and_at_w32() {
        let disjunction: Expr = Expr::or(var(0), var(1));
        let conjunction: Expr = Expr::and(var(0), var(1));
        assert!(!polynomial_identity_proves(
            &disjunction,
            &conjunction,
            Width::W32
        ));
    }

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn random_expr(state: &mut u64, depth: u32) -> Expr {
        if depth == 0 || xorshift(state).is_multiple_of(5) {
            return match xorshift(state) % 3 {
                0 => var(0),
                1 => var(1),
                _ => Expr::konst(xorshift(state) & 0xFF),
            };
        }
        let left: Expr = random_expr(state, depth - 1);
        let right: Expr = random_expr(state, depth - 1);
        match xorshift(state) % 10 {
            0 => Expr::add(left, right),
            1 => Expr::sub(left, right),
            2 => Expr::mul(left, right),
            3 => Expr::xor(left, right),
            4 => Expr::and(left, right),
            5 => Expr::or(left, right),
            6 => Expr::neg(left),
            7 => Expr::not(left),
            8 => Expr::shl(left, Expr::konst(xorshift(state) % 300)),
            _ => Expr::shr(left, Expr::konst(xorshift(state) % 300)),
        }
    }

    #[test]
    fn oracle_never_accepts_a_non_equivalent_pair_under_w8_exhaustive() {
        use crate::expr::equivalent_exhaustive;
        let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
        let mut proven: u32 = 0;
        for _ in 0..4000u32 {
            let original: Expr = random_expr(&mut state, 4);
            let candidate: Expr = random_expr(&mut state, 4);
            if polynomial_identity_proves(&original, &candidate, Width::W8) {
                proven += 1;
                assert!(
                    equivalent_exhaustive(&original, &candidate, Width::W8, 2),
                    "oracle accepted a non-equivalent pair at W8: {original:?} vs {candidate:?}",
                );
            }
        }
        assert!(proven > 0, "fuzz never exercised the accept path");
    }
}
