#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_mba::{
    Expr, PermutationPolynomial, Simplification, Width, composition_is_identity,
    equivalent_exhaustive, polynomial_is_zero_function, simplify,
};
use proptest::prelude::*;

fn horner(coeffs: &[u64], x: u128, mask: u128) -> u128 {
    let mut acc: u128 = 0;
    for coeff in coeffs.iter().rev() {
        acc = (acc.wrapping_mul(x) & mask).wrapping_add(u128::from(*coeff)) & mask;
    }
    acc
}

fn make_permutation(mut coeffs: Vec<u64>) -> Vec<u64> {
    if coeffs.len() < 2 {
        coeffs.resize(2, 0);
    }
    coeffs[1] |= 1;
    let even_parity: u64 = (2..coeffs.len())
        .step_by(2)
        .fold(0u64, |acc: u64, index: usize| acc ^ (coeffs[index] & 1));
    if even_parity == 1 {
        let last_even: Option<usize> = (2..coeffs.len()).step_by(2).next_back();
        if let Some(index) = last_even {
            coeffs[index] ^= 1;
        }
    }
    let odd_parity: u64 = (3..coeffs.len())
        .step_by(2)
        .fold(0u64, |acc: u64, index: usize| acc ^ (coeffs[index] & 1));
    if odd_parity == 1 {
        let last_odd: Option<usize> = (3..coeffs.len()).step_by(2).next_back();
        if let Some(index) = last_odd {
            coeffs[index] ^= 1;
        }
    }
    coeffs
}

fn composition_matches_identity_exhaustively(
    outer: &[u64],
    inner: &[u64],
    width: Width,
) -> Result<(), String> {
    let mask: u128 = u128::from(width.mask());
    let modulus: u128 = mask + 1;
    for x in 0..modulus {
        let recovered: u128 = horner(outer, horner(inner, x, mask), mask);
        if recovered != x {
            return Err(format!(
                "P(Q({x})) = {recovered} != {x} at {width:?} for outer {outer:?} inner {inner:?}"
            ));
        }
    }
    Ok(())
}

fn composition_matches_identity_sampled(outer: &[u64], inner: &[u64], width: Width) -> bool {
    let mask: u128 = u128::from(width.mask());
    let mut state: u128 = 0x9E37_79B9_7F4A_7C15;
    for coeff in outer.iter().chain(inner.iter()) {
        state = state
            .wrapping_add(u128::from(*coeff))
            .wrapping_mul(0x2545_F491_4F6C_DD1D)
            & mask;
    }
    for _ in 0..2048 {
        state = state
            .wrapping_mul(0x5851_F42D_4C95_7F2D)
            .wrapping_add(0x1405_7B7E_F767_814F)
            & mask;
        let x: u128 = state & mask;
        if horner(outer, horner(inner, x, mask), mask) != x {
            return false;
        }
    }
    true
}

const fn narrow_widths() -> [Width; 2] {
    [Width::W8, Width::W16]
}

const fn wide_widths() -> [Width; 2] {
    [Width::W32, Width::W64]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 400,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_permutations_invert_and_certify_at_narrow_widths(
        raw in prop::collection::vec(any::<u64>(), 0usize..5),
        width_index in 0usize..2,
    ) {
        let coeffs: Vec<u64> = make_permutation(raw);
        let width: Width = narrow_widths()[width_index];
        let polynomial: PermutationPolynomial = PermutationPolynomial::new(width, &coeffs);
        prop_assert!(
            polynomial.is_permutation(),
            "constructed coefficients {coeffs:?} must be a permutation"
        );
        let Some(inverse): Option<PermutationPolynomial> = polynomial.inverse() else {
            return Err(TestCaseError::fail(format!(
                "gated inverse abstained on a genuine permutation {coeffs:?} at {width:?}"
            )));
        };
        let inverse_coeffs: Vec<u64> = inverse.coefficients().to_vec();
        prop_assert!(
            composition_is_identity(polynomial.coefficients(), &inverse_coeffs, width),
            "certificate rejected a returned inverse"
        );
        if let Err(message) =
            composition_matches_identity_exhaustively(polynomial.coefficients(), &inverse_coeffs, width)
        {
            return Err(TestCaseError::fail(message));
        }
    }

    #[test]
    fn random_permutations_invert_and_certify_at_wide_widths(
        raw in prop::collection::vec(any::<u64>(), 0usize..5),
        width_index in 0usize..2,
    ) {
        let coeffs: Vec<u64> = make_permutation(raw);
        let width: Width = wide_widths()[width_index];
        let polynomial: PermutationPolynomial = PermutationPolynomial::new(width, &coeffs);
        prop_assert!(polynomial.is_permutation());
        let Some(inverse): Option<PermutationPolynomial> = polynomial.inverse() else {
            return Err(TestCaseError::fail(format!(
                "gated inverse abstained on a genuine permutation {coeffs:?} at {width:?}"
            )));
        };
        let inverse_coeffs: Vec<u64> = inverse.coefficients().to_vec();
        prop_assert!(
            composition_is_identity(polynomial.coefficients(), &inverse_coeffs, width),
            "certificate rejected a returned inverse at {:?}",
            width
        );
        prop_assert!(
            composition_matches_identity_sampled(polynomial.coefficients(), &inverse_coeffs, width),
            "sampled evaluation disagrees with the certificate for {coeffs:?} at {width:?}"
        );
    }
}

#[test]
fn certificate_rejects_perturbed_inverse() {
    for width in [Width::W8, Width::W16, Width::W32, Width::W64] {
        let coeffs: [u64; 3] = [7, 3, 4];
        let polynomial: PermutationPolynomial = PermutationPolynomial::new(width, &coeffs);
        let inverse: PermutationPolynomial = polynomial
            .inverse()
            .unwrap_or_else(|| panic!("permutation must invert at {width:?}"));
        let mut broken: Vec<u64> = inverse.coefficients().to_vec();
        broken[0] = broken[0].wrapping_add(1);
        assert!(
            !composition_is_identity(polynomial.coefficients(), &broken, width),
            "a perturbed inverse must fail the finite-difference certificate at {width:?}"
        );
    }
}

#[test]
fn non_permutations_abstain() {
    let cases: [(&[u64], Width); 4] = [
        (&[1, 2, 4], Width::W8),
        (&[0, 1, 1], Width::W8),
        (&[0, 1, 0, 1], Width::W16),
        (&[3, 4, 8], Width::W32),
    ];
    for (coeffs, width) in cases {
        let polynomial: PermutationPolynomial = PermutationPolynomial::new(width, coeffs);
        assert!(
            !polynomial.is_permutation(),
            "{coeffs:?} must be detected as a non-permutation"
        );
        assert!(
            polynomial.inverse().is_none(),
            "{coeffs:?} must abstain rather than emit an inverse"
        );
    }
}

#[test]
fn certificate_agrees_with_null_polynomials() {
    let bits: u32 = Width::W16.bits();
    let half: u64 = 1u64 << (bits - 1);
    assert!(polynomial_is_zero_function(
        &[0, half.wrapping_neg(), half],
        Width::W16
    ));
    assert!(!polynomial_is_zero_function(&[0, 1], Width::W16));
}

fn basis_term(index: usize) -> Expr {
    let x: Expr = Expr::var(0);
    let y: Expr = Expr::var(1);
    match index {
        0 => x,
        1 => y,
        2 => Expr::not(Expr::var(0)),
        3 => Expr::not(Expr::var(1)),
        4 => Expr::and(x, y),
        5 => Expr::or(x, y),
        6 => Expr::xor(x, y),
        7 => Expr::and(x, Expr::not(y)),
        8 => Expr::and(Expr::not(x), y),
        _ => Expr::not(Expr::or(x, y)),
    }
}

fn build_linear_mba(coeffs: &[i32]) -> Expr {
    let mut terms: Vec<Expr> = Vec::new();
    for (index, &coeff) in coeffs.iter().enumerate() {
        if coeff == 0 {
            continue;
        }
        let magnitude: u64 = coeff.unsigned_abs().into();
        let basis: Expr = basis_term(index);
        let scaled: Expr = if magnitude == 1 {
            basis
        } else {
            Expr::mul(Expr::konst(magnitude), basis)
        };
        let signed: Expr = if coeff < 0 { Expr::neg(scaled) } else { scaled };
        terms.push(signed);
    }
    let mut iter: std::vec::IntoIter<Expr> = terms.into_iter();
    let Some(first): Option<Expr> = iter.next() else {
        return Expr::konst(0);
    };
    let mut acc: Expr = first;
    for term in iter {
        acc = match term {
            Expr::Unary(disrobe_mba::UnOp::Neg, inner) => Expr::sub(acc, *inner),
            other => Expr::add(acc, other),
        };
    }
    acc
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1500,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_linear_mba_simplifications_stay_equivalent(
        coeffs in prop::collection::vec(-4i32..5, 10usize..=10),
    ) {
        let original: Expr = build_linear_mba(&coeffs);
        for width in [Width::W4, Width::W8] {
            let result: Simplification = simplify(&original, width);
            prop_assert!(
                equivalent_exhaustive(&original, &result.simplified, width, 2),
                "simplified `{}` is not equivalent to `{}` at {:?}",
                result.simplified,
                original,
                width
            );
            if result.changed() {
                prop_assert!(result.verification.is_proven());
            }
        }
    }
}

#[test]
fn nonlinear_and_over_budget_inputs_are_untouched_or_equivalent() {
    let product: Expr = Expr::mul(Expr::var(0), Expr::var(1));
    let result: Simplification = simplify(&product, Width::W8);
    assert!(!result.changed(), "a genuine product must not be rewritten");

    let mut wide: Expr = Expr::var(0);
    for index in 1..5 {
        wide = Expr::add(wide, Expr::var(index));
    }
    let simplified: Simplification = simplify(&wide, Width::W2);
    assert!(
        equivalent_exhaustive(&wide, &simplified.simplified, Width::W2, 5),
        "a five-variable sum must never be rewritten to a non-equivalent form"
    );
}
