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

const MULTIVAR_EVAL_BUDGET: u128 = 1 << 22;

pub(crate) fn multivar_induces_zero(
    monomials: &[(Vec<u32>, u128)],
    var_count: usize,
    width: Width,
) -> bool {
    let mask: u128 = modulus_mask(width);
    let mut degree: Vec<u32> = vec![0; var_count];
    for (key, _coeff) in monomials {
        for (axis, exponent) in key.iter().enumerate() {
            if let Some(slot) = degree.get_mut(axis)
                && *exponent > *slot
            {
                *slot = *exponent;
            }
        }
    }
    let dims: Vec<usize> = degree.iter().map(|d: &u32| *d as usize + 1).collect();
    let mut total: u128 = 1;
    for dim in &dims {
        total = total.saturating_mul(*dim as u128);
    }
    if total.saturating_mul(monomials.len().max(1) as u128) > MULTIVAR_EVAL_BUDGET {
        return false;
    }
    let total_points: usize = total as usize;
    let mut values: Vec<u128> = vec![0; total_points];
    for (flat, slot) in values.iter_mut().enumerate() {
        let coords: Vec<u32> = unflatten(flat, &dims);
        let mut acc: u128 = 0;
        for (key, coeff) in monomials {
            acc = acc.wrapping_add(eval_monomial(key, &coords, *coeff & mask, mask)) & mask;
        }
        *slot = acc;
    }
    difference_tensor(&mut values, &dims, mask);
    values.iter().all(|value: &u128| *value == 0)
}

fn eval_monomial(key: &[u32], coords: &[u32], coeff: u128, mask: u128) -> u128 {
    let mut term: u128 = coeff & mask;
    for (axis, exponent) in key.iter().enumerate() {
        if *exponent == 0 {
            continue;
        }
        let Some(base): Option<&u32> = coords.get(axis) else {
            return 0;
        };
        let base128: u128 = u128::from(*base) & mask;
        for _ in 0..*exponent {
            term = term.wrapping_mul(base128) & mask;
        }
    }
    term
}

fn unflatten(flat: usize, dims: &[usize]) -> Vec<u32> {
    let mut remaining: usize = flat;
    let mut coords: Vec<u32> = Vec::with_capacity(dims.len());
    for dim in dims {
        coords.push((remaining % *dim) as u32);
        remaining /= *dim;
    }
    coords
}

fn difference_tensor(values: &mut [u128], dims: &[usize], mask: u128) {
    let mut stride: usize = 1;
    for dim in dims {
        let len: usize = *dim;
        if len > 1 {
            let block: usize = stride * len;
            let total: usize = values.len();
            let mut base: usize = 0;
            while base < total {
                for offset in 0..stride {
                    difference_fiber(values, base + offset, stride, len, mask);
                }
                base += block;
            }
        }
        stride *= len;
    }
}

fn difference_fiber(values: &mut [u128], start: usize, stride: usize, len: usize, mask: u128) {
    let mut table: Vec<u128> = (0..len)
        .map(|position: usize| values[start + position * stride])
        .collect();
    let mut result: Vec<u128> = vec![0; len];
    for (order, cell) in result.iter_mut().enumerate() {
        if order > 0 {
            for index in 0..len - order {
                table[index] = table[index + 1].wrapping_sub(table[index]) & mask;
            }
        }
        *cell = table[0];
    }
    for (position, value) in result.into_iter().enumerate() {
        values[start + position * stride] = value;
    }
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

    #[test]
    fn multivar_certifies_half_scaled_square_difference() {
        let bits: u32 = Width::W8.bits();
        let half: u128 = 1u128 << (bits - 1);
        let difference: Vec<(Vec<u32>, u128)> =
            vec![(vec![2], half), (vec![1], half.wrapping_neg() & 0xFF)];
        assert!(multivar_induces_zero(&difference, 1, Width::W8));
    }

    #[test]
    fn multivar_rejects_non_null_difference() {
        let difference: Vec<(Vec<u32>, u128)> = vec![(vec![1, 0], 1)];
        assert!(!multivar_induces_zero(&difference, 2, Width::W8));
    }

    #[test]
    fn multivar_certifies_bilinear_falling_factorial_null() {
        let bits: u32 = Width::W8.bits();
        let half: u128 = 1u128 << (bits - 1);
        let difference: Vec<(Vec<u32>, u128)> =
            vec![(vec![2, 1], half), (vec![1, 1], half.wrapping_neg() & 0xFF)];
        assert!(multivar_induces_zero(&difference, 2, Width::W8));
    }

    #[test]
    fn multivar_empty_polynomial_is_zero() {
        let difference: Vec<(Vec<u32>, u128)> = Vec::new();
        assert!(multivar_induces_zero(&difference, 3, Width::W16));
    }

    #[test]
    fn multivar_survives_at_wider_width() {
        let bits: u32 = Width::W8.bits();
        let half: u128 = 1u128 << (bits - 1);
        let difference: Vec<(Vec<u32>, u128)> =
            vec![(vec![2], half), (vec![1], half.wrapping_neg() & 0xFF)];
        assert!(!multivar_induces_zero(&difference, 1, Width::W16));
    }
}
