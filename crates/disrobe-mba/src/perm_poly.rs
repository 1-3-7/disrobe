#![doc = "Inversion of univariate permutation polynomials over Z/2^n."]
#![doc = ""]
#![doc = "Obfuscators encode a value x as P(x) where P is a permutation polynomial over"]
#![doc = "Z/2^n (a bijection) and later apply the compositional inverse to recover x."]
#![doc = "[`PermutationPolynomial::inverse`] recovers that inverse so the encoding can be"]
#![doc = "undone."]
#![doc = ""]
#![doc = "Detection follows Rivest (2001): a polynomial with constant term a0, linear term"]
#![doc = "a1, quadratic term a2, and so on is a permutation of Z/2^w for w at least two iff"]
#![doc = "a1 is odd, the sum of the coefficients at even positions two, four, and up is"]
#![doc = "even, and the sum of the coefficients at odd positions three, five, and up is"]
#![doc = "even. Because these conditions constrain only coefficient parities they are width"]
#![doc = "independent, so a polynomial that passes at one width is a bijection at every"]
#![doc = "width."]
#![doc = ""]
#![doc = "The inverse is recovered without stochastic search. Each inverse value at a point"]
#![doc = "t in the range zero up to m is found by a per-point Hensel lift of the equation"]
#![doc = "P(y) equals t, doubling 2-adic precision one bit at a time; the derivative of P"]
#![doc = "is odd because a1 is odd, so the lift is exact and unique. Here m is the least"]
#![doc = "integer whose factorial is divisible by 2^n, the Kempner bound, so the falling"]
#![doc = "factorial of order m vanishes identically over Z/2^n and any polynomial function"]
#![doc = "is determined by its values on the first m points. The Newton forward-difference"]
#![doc = "table of those values gives the falling-factorial coefficients, which the signed"]
#![doc = "Stirling numbers of the first kind carry back to a monomial form equal to the"]
#![doc = "inverse as a function at the full width."]

use crate::expr::{Expr, Width};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermutationPolynomial {
    width: Width,
    coeffs: Vec<u64>,
}

impl PermutationPolynomial {
    #[must_use]
    pub fn new(width: Width, coeffs: &[u64]) -> Self {
        let mask: u64 = width.mask();
        let mut reduced: Vec<u64> = coeffs.iter().map(|c: &u64| *c & mask).collect();
        while reduced.len() > 1 && reduced.last() == Some(&0) {
            reduced.pop();
        }
        if reduced.is_empty() {
            reduced.push(0);
        }
        Self {
            width,
            coeffs: reduced,
        }
    }

    #[must_use]
    pub const fn width(&self) -> Width {
        self.width
    }

    #[must_use]
    pub fn coefficients(&self) -> &[u64] {
        &self.coeffs
    }

    #[must_use]
    pub const fn degree(&self) -> usize {
        self.coeffs.len().saturating_sub(1)
    }

    #[must_use]
    pub fn is_permutation(&self) -> bool {
        let bits: u32 = self.width.bits();
        let odd_index_sum: u64 = self
            .coeffs
            .iter()
            .skip(1)
            .fold(0u64, |acc: u64, c: &u64| acc.wrapping_add(*c));
        if bits == 1 {
            return odd_index_sum & 1 == 1;
        }
        let a1: u64 = self.coeffs.get(1).copied().unwrap_or(0);
        if a1 & 1 == 0 {
            return false;
        }
        let mut even_positions: u64 = 0;
        let mut odd_positions: u64 = 0;
        for (index, coeff) in self.coeffs.iter().enumerate().skip(2) {
            if index % 2 == 0 {
                even_positions = even_positions.wrapping_add(*coeff);
            } else {
                odd_positions = odd_positions.wrapping_add(*coeff);
            }
        }
        even_positions & 1 == 0 && odd_positions & 1 == 0
    }

    #[must_use]
    pub fn inverse(&self) -> Option<Self> {
        if !self.is_permutation() {
            return None;
        }
        let bits: u32 = self.width.bits();
        let mask: u128 = u128::from(self.width.mask());
        let point_count: usize = kempner_bound(bits);
        let coeffs: Vec<u128> = self.coeffs.iter().map(|c: &u64| u128::from(*c)).collect();

        let mut values: Vec<u128> = Vec::with_capacity(point_count);
        for target in 0..point_count as u128 {
            let solved: u128 = solve_point(&coeffs, target, bits, mask)?;
            values.push(solved);
        }

        let differences: Vec<u128> = forward_differences(&values, mask);
        let monomial: Vec<u64> = reconstruct_monomial(&differences, bits, mask)?;
        Some(Self::new(self.width, &monomial))
    }

    #[must_use]
    pub fn to_expr(&self, var: u32) -> Expr {
        polynomial_to_expr(&self.coeffs, var)
    }
}

#[must_use]
pub fn recover_inverse(width: Width, coeffs: &[u64]) -> Option<PermutationPolynomial> {
    PermutationPolynomial::new(width, coeffs).inverse()
}

fn horner(coeffs: &[u128], x: u128, mask: u128) -> u128 {
    let mut acc: u128 = 0;
    for coeff in coeffs.iter().rev() {
        acc = (acc.wrapping_mul(x) & mask).wrapping_add(*coeff) & mask;
    }
    acc
}

fn solve_point(coeffs: &[u128], target: u128, bits: u32, mask: u128) -> Option<u128> {
    let mut y: u128 = 0;
    for bit in 0..bits {
        let value: u128 = horner(coeffs, y, mask);
        let diff: u128 = value.wrapping_sub(target) & mask;
        if (diff >> bit) & 1 == 1 {
            y |= 1u128 << bit;
        }
    }
    if horner(coeffs, y, mask) == target & mask {
        Some(y)
    } else {
        None
    }
}

fn forward_differences(values: &[u128], mask: u128) -> Vec<u128> {
    let mut table: Vec<u128> = values.to_vec();
    let mut out: Vec<u128> = Vec::with_capacity(table.len());
    out.push(table.first().copied().unwrap_or(0));
    while table.len() > 1 {
        for index in 0..table.len() - 1 {
            table[index] = table[index + 1].wrapping_sub(table[index]) & mask;
        }
        table.pop();
        out.push(table[0]);
    }
    out
}

fn reconstruct_monomial(differences: &[u128], bits: u32, mask: u128) -> Option<Vec<u64>> {
    let count: usize = differences.len();
    let stirling: Vec<Vec<u128>> = stirling_first_kind(count, mask);
    let falling: Vec<u128> = falling_factorial_coeffs(differences, bits, mask)?;

    let mut accumulator: Vec<u128> = vec![0u128; count];
    for (coefficient, row) in falling.iter().zip(stirling.iter()) {
        for (slot, stir) in accumulator.iter_mut().zip(row.iter()) {
            *slot = slot.wrapping_add(coefficient.wrapping_mul(*stir) & mask) & mask;
        }
    }
    Some(
        accumulator
            .iter()
            .map(|value: &u128| *value as u64)
            .collect(),
    )
}

fn falling_factorial_coeffs(differences: &[u128], bits: u32, mask: u128) -> Option<Vec<u128>> {
    let mut coeffs: Vec<u128> = Vec::with_capacity(differences.len());
    let mut odd_factorial: u128 = 1;
    let mut two_adic: u32 = 0;
    for (order, difference) in differences.iter().enumerate() {
        if order >= 1 {
            let index: u32 = order as u32;
            let valuation: u32 = index.trailing_zeros();
            let odd_part: u128 = u128::from(index) >> valuation;
            odd_factorial = odd_factorial.wrapping_mul(odd_part) & mask;
            two_adic += valuation;
        }
        if two_adic >= bits {
            coeffs.push(0);
            continue;
        }
        if two_adic > 0 && difference & ((1u128 << two_adic) - 1) != 0 {
            return None;
        }
        let residual_bits: u32 = bits - two_adic;
        let residual_mask: u128 = pow2_mask(residual_bits);
        let scaled: u128 = (difference >> two_adic) & residual_mask;
        let inverse: u128 = inverse_mod_pow2(odd_factorial & residual_mask, residual_bits);
        coeffs.push(scaled.wrapping_mul(inverse) & residual_mask);
    }
    Some(coeffs)
}

fn stirling_first_kind(count: usize, mask: u128) -> Vec<Vec<u128>> {
    let mut table: Vec<Vec<u128>> = vec![vec![0u128; count]; count.max(1)];
    if count == 0 {
        return table;
    }
    table[0][0] = 1;
    for order in 0..count - 1 {
        let scale: u128 = (order as u128) & mask;
        for degree in 0..count {
            let raised: u128 = if degree >= 1 {
                table[order][degree - 1]
            } else {
                0
            };
            let lowered: u128 = scale.wrapping_mul(table[order][degree]) & mask;
            table[order + 1][degree] = raised.wrapping_sub(lowered) & mask;
        }
    }
    table
}

const fn pow2_mask(bits: u32) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

const fn inverse_mod_pow2(value: u128, bits: u32) -> u128 {
    let modulus_mask: u128 = pow2_mask(bits);
    let mut inverse: u128 = 1;
    let mut round: u32 = 0;
    while round < 8 {
        let product: u128 = value.wrapping_mul(inverse) & modulus_mask;
        inverse = inverse.wrapping_mul(2u128.wrapping_sub(product)) & modulus_mask;
        round += 1;
    }
    inverse
}

const fn kempner_bound(bits: u32) -> usize {
    let mut k: u32 = 1;
    loop {
        if k - k.count_ones() >= bits {
            return k as usize;
        }
        k += 1;
    }
}

fn polynomial_to_expr(coeffs: &[u64], var: u32) -> Expr {
    let degree: Option<usize> = coeffs.iter().rposition(|coeff: &u64| *coeff != 0);
    let Some(top): Option<usize> = degree else {
        return Expr::konst(0);
    };
    let x: Expr = Expr::var(var);
    let mut acc: Expr = Expr::konst(coeffs[top]);
    for index in (0..top).rev() {
        acc = Expr::mul(acc, x.clone());
        if coeffs[index] != 0 {
            acc = Expr::add(acc, Expr::konst(coeffs[index]));
        }
    }
    acc
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::expr::equivalent_exhaustive;

    fn composed(outer: &[u64], inner: &Expr, var: u32) -> Expr {
        let inner_expr: Expr = inner.clone();
        let degree: Option<usize> = outer.iter().rposition(|coeff: &u64| *coeff != 0);
        let Some(top): Option<usize> = degree else {
            return Expr::konst(0);
        };
        let mut acc: Expr = Expr::konst(outer[top]);
        for index in (0..top).rev() {
            acc = Expr::mul(acc, inner_expr.clone());
            if outer[index] != 0 {
                acc = Expr::add(acc, Expr::konst(outer[index]));
            }
        }
        let _ = var;
        acc
    }

    fn round_trips(coeffs: &[u64], width: Width) {
        let poly: PermutationPolynomial = PermutationPolynomial::new(width, coeffs);
        assert!(poly.is_permutation(), "{coeffs:?} must be a permutation");
        let inverse: PermutationPolynomial = poly.inverse().expect("inverse must exist");
        let inverse_expr: Expr = inverse.to_expr(0);
        let forward: Expr = composed(coeffs, &inverse_expr, 0);
        assert!(
            equivalent_exhaustive(&forward, &Expr::var(0), width, 1),
            "P(P_inv(x)) must equal x at {width:?} for {coeffs:?}; inverse {:?}",
            inverse.coefficients()
        );
        let inverse_coeffs: Vec<u64> = inverse.coefficients().to_vec();
        let backward: Expr = composed(&inverse_coeffs, &poly.to_expr(0), 0);
        assert!(
            equivalent_exhaustive(&backward, &Expr::var(0), width, 1),
            "P_inv(P(x)) must equal x at {width:?} for {coeffs:?}"
        );
    }

    #[test]
    fn linear_permutation_inverts_at_w8() {
        round_trips(&[5, 3], Width::W8);
    }

    #[test]
    fn quadratic_permutation_inverts_at_w8() {
        round_trips(&[0, 1, 2], Width::W8);
        round_trips(&[7, 3, 4], Width::W8);
    }

    #[test]
    fn cubic_permutation_inverts_at_w8() {
        round_trips(&[1, 3, 4, 6], Width::W8);
    }

    #[test]
    fn permutation_inverts_at_w16() {
        round_trips(&[9, 5, 6], Width::W16);
        round_trips(&[3, 7, 8, 2], Width::W16);
    }

    #[test]
    fn rivest_rejects_even_leading_coefficient() {
        let poly: PermutationPolynomial = PermutationPolynomial::new(Width::W8, &[1, 2, 4]);
        assert!(!poly.is_permutation());
        assert!(poly.inverse().is_none());
    }

    #[test]
    fn rivest_rejects_odd_cubic_parity() {
        let poly: PermutationPolynomial = PermutationPolynomial::new(Width::W8, &[0, 1, 0, 1]);
        assert!(!poly.is_permutation());
        assert!(poly.inverse().is_none());
    }

    #[test]
    fn rivest_rejects_odd_even_index_sum() {
        let poly: PermutationPolynomial = PermutationPolynomial::new(Width::W8, &[0, 1, 1]);
        assert!(!poly.is_permutation());
        assert!(poly.inverse().is_none());
    }

    #[test]
    fn kempner_bounds_match_two_adic_valuation() {
        assert_eq!(kempner_bound(8), 10);
        assert_eq!(kempner_bound(16), 18);
        assert_eq!(kempner_bound(32), 34);
        assert_eq!(kempner_bound(64), 66);
    }

    #[test]
    fn inverse_composition_is_identity_pointwise_w16() {
        let coeffs: [u64; 3] = [12345, 9, 10];
        let poly: PermutationPolynomial = PermutationPolynomial::new(Width::W16, &coeffs);
        let inverse: PermutationPolynomial = poly.inverse().expect("inverse");
        let width: Width = Width::W16;
        let forward: Vec<u128> = poly
            .coefficients()
            .iter()
            .map(|c: &u64| u128::from(*c))
            .collect();
        let backward: Vec<u128> = inverse
            .coefficients()
            .iter()
            .map(|c: &u64| u128::from(*c))
            .collect();
        let mask: u128 = u128::from(width.mask());
        for x in 0..=width.mask() as u128 {
            let composed_value: u128 = horner(&forward, horner(&backward, x, mask), mask);
            assert_eq!(composed_value, x, "P(P_inv({x})) must equal {x}");
        }
    }
}
