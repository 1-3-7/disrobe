use crate::expr::Width;

pub const MAX_CERTIFICATE_DEGREE: usize = 1 << 16;

fn modulus_mask(width: Width) -> u128 {
    u128::from(width.mask())
}

fn eval_poly_mod(coeffs: &[u128], x: u128, mask: u128) -> u128 {
    let mut acc: u128 = 0;
    for coeff in coeffs.iter().rev() {
        acc = (acc.wrapping_mul(x) & mask).wrapping_add(*coeff) & mask;
    }
    acc
}

fn effective_degree(coeffs: &[u128]) -> usize {
    coeffs
        .iter()
        .rposition(|coeff: &u128| *coeff != 0)
        .unwrap_or(0)
}

#[must_use]
pub fn induces_zero_function(point_values: &[u128], width: Width) -> bool {
    if point_values.is_empty() {
        return false;
    }
    let mask: u128 = modulus_mask(width);
    let mut row: Vec<u128> = point_values
        .iter()
        .map(|value: &u128| value & mask)
        .collect();
    loop {
        let Some(&leading): Option<&u128> = row.first() else {
            return false;
        };
        if leading != 0 {
            return false;
        }
        if row.len() == 1 {
            return true;
        }
        for index in 0..row.len() - 1 {
            row[index] = row[index + 1].wrapping_sub(row[index]) & mask;
        }
        row.pop();
    }
}

#[must_use]
pub fn polynomial_is_zero_function(coeffs: &[u64], width: Width) -> bool {
    let mask: u128 = modulus_mask(width);
    let reduced: Vec<u128> = coeffs
        .iter()
        .map(|coeff: &u64| u128::from(*coeff) & mask)
        .collect();
    let degree: usize = effective_degree(&reduced);
    if degree > MAX_CERTIFICATE_DEGREE {
        return false;
    }
    let point_count: usize = degree + 1;
    let mut values: Vec<u128> = Vec::with_capacity(point_count);
    for x in 0..point_count as u128 {
        values.push(eval_poly_mod(&reduced, x & mask, mask));
    }
    induces_zero_function(&values, width)
}

#[must_use]
pub fn composition_is_identity(outer: &[u64], inner: &[u64], width: Width) -> bool {
    let mask: u128 = modulus_mask(width);
    let outer_mod: Vec<u128> = outer
        .iter()
        .map(|coeff: &u64| u128::from(*coeff) & mask)
        .collect();
    let inner_mod: Vec<u128> = inner
        .iter()
        .map(|coeff: &u64| u128::from(*coeff) & mask)
        .collect();
    let degree_outer: usize = effective_degree(&outer_mod);
    let degree_inner: usize = effective_degree(&inner_mod);
    let Some(product): Option<usize> = degree_outer.checked_mul(degree_inner) else {
        return false;
    };
    let degree_r: usize = product.max(1);
    if degree_r > MAX_CERTIFICATE_DEGREE {
        return false;
    }
    let point_count: usize = degree_r + 1;
    let mut values: Vec<u128> = Vec::with_capacity(point_count);
    for point in 0..point_count as u128 {
        let x: u128 = point & mask;
        let inner_value: u128 = eval_poly_mod(&inner_mod, x, mask);
        let composed: u128 = eval_poly_mod(&outer_mod, inner_value, mask);
        values.push(composed.wrapping_sub(x) & mask);
    }
    induces_zero_function(&values, width)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn horner(coeffs: &[u64], x: u128, mask: u128) -> u128 {
        let mut acc: u128 = 0;
        for coeff in coeffs.iter().rev() {
            acc = (acc.wrapping_mul(x) & mask).wrapping_add(u128::from(*coeff)) & mask;
        }
        acc
    }

    #[test]
    fn zero_polynomial_certifies() {
        assert!(polynomial_is_zero_function(&[0], Width::W8));
        assert!(polynomial_is_zero_function(&[0, 0, 0], Width::W64));
    }

    #[test]
    fn nonzero_constant_is_rejected() {
        assert!(!polynomial_is_zero_function(&[1], Width::W8));
        assert!(!polynomial_is_zero_function(&[0, 1], Width::W8));
    }

    #[test]
    fn consecutive_product_is_null_mod_two() {
        assert!(polynomial_is_zero_function(&[0, u64::MAX, 1], Width::W1));
    }

    #[test]
    fn half_scaled_consecutive_product_is_null_mod_pow2() {
        let bits: u32 = Width::W8.bits();
        let half: u64 = 1u64 << (bits - 1);
        let neg_half: u64 = half.wrapping_neg();
        assert!(polynomial_is_zero_function(&[0, neg_half, half], Width::W8));
    }

    #[test]
    fn falling_binomial_is_not_null_mod_pow2() {
        assert!(!polynomial_is_zero_function(&[0, u64::MAX, 1], Width::W8));
    }

    #[test]
    fn affine_round_trip_certifies_identity() {
        let outer: [u64; 2] = [0, 3];
        let inner: [u64; 2] = [0, 171];
        assert!(composition_is_identity(&outer, &inner, Width::W8));
        let shifted_outer: [u64; 2] = [7, 3];
        let shifted_inner: [u64; 2] = [(7u64.wrapping_mul(171)).wrapping_neg() & 0xFF, 171];
        assert!(composition_is_identity(
            &shifted_outer,
            &shifted_inner,
            Width::W8
        ));
    }

    #[test]
    fn wrong_composition_is_rejected() {
        let outer: [u64; 2] = [0, 3];
        let bogus: [u64; 2] = [0, 1];
        assert!(!composition_is_identity(&outer, &bogus, Width::W8));
    }

    #[test]
    fn empty_point_set_abstains() {
        assert!(!induces_zero_function(&[], Width::W8));
    }

    #[test]
    fn difference_table_matches_direct_evaluation() {
        let coeffs: [u64; 3] = [7, 13, 4];
        let mask: u128 = modulus_mask(Width::W16);
        let mut values: Vec<u128> = Vec::new();
        for x in 0u128..3 {
            values.push(horner(&coeffs, x, mask));
        }
        assert!(!induces_zero_function(&values, Width::W16));
        let null: Vec<u128> = vec![0, 0, 0];
        assert!(induces_zero_function(&null, Width::W16));
    }
}
