#![cfg(feature = "smt-verify")]

use disrobe_mba::{
    Equivalence, Expr, PermutationPolynomial, Simplification, Width, simplify, verify_equivalent,
};
use proptest::prelude::*;

const fn widths() -> [Width; 4] {
    [Width::W8, Width::W16, Width::W32, Width::W64]
}

fn compose_at(coefficients: &[u64], inner: &Expr) -> Expr {
    let Some(top): Option<usize> = coefficients
        .iter()
        .rposition(|coefficient: &u64| *coefficient != 0)
    else {
        return Expr::konst(0);
    };
    let mut accumulator: Expr = Expr::konst(coefficients[top]);
    for index in (0..top).rev() {
        accumulator = Expr::mul(accumulator, inner.clone());
        if coefficients[index] != 0 {
            accumulator = Expr::add(accumulator, Expr::konst(coefficients[index]));
        }
    }
    accumulator
}

fn xor_carry_add(left: u32, right: u32) -> Expr {
    Expr::add(
        Expr::xor(Expr::var(left), Expr::var(right)),
        Expr::mul(Expr::konst(2), Expr::and(Expr::var(left), Expr::var(right))),
    )
}

fn assert_inverse_proven(coefficients: &[u64], width: Width) -> Result<(), String> {
    let source: Expr = Expr::var(0);
    let polynomial: PermutationPolynomial = PermutationPolynomial::new(width, coefficients);
    assert!(
        polynomial.is_permutation(),
        "expected a permutation at {width:?}"
    );
    let Some(inverse): Option<PermutationPolynomial> = polynomial.inverse() else {
        return Err(format!(
            "expected an inverse for {coefficients:?} at {width:?}"
        ));
    };
    let forward: Expr = compose_at(coefficients, &inverse.to_expr(0));
    let backward: Expr = compose_at(inverse.coefficients(), &polynomial.to_expr(0));
    assert_eq!(
        verify_equivalent(&forward, &source, width),
        Equivalence::Proven,
        "expected a forward verifier proof at {width:?}"
    );
    assert_eq!(
        verify_equivalent(&backward, &source, width),
        Equivalence::Proven,
        "expected a backward verifier proof at {width:?}"
    );
    Ok(())
}

#[test]
fn sparse_linear_mba_reduces_without_phantom_variables() {
    let input: Expr = xor_carry_add(7, 19);
    let expected: Expr = Expr::add(Expr::var(7), Expr::var(19));
    for width in widths() {
        let result: Simplification = simplify(&input, width);
        assert!(result.changed(), "expected a simplification at {width:?}");
        assert_eq!(
            result.simplified, expected,
            "expected affine form at {width:?}"
        );
        assert_eq!(
            verify_equivalent(&input, &result.simplified, width),
            Equivalence::Proven,
            "expected a verifier proof at {width:?}"
        );
    }
}

#[test]
fn affine_and_higher_degree_inverses_are_recovered_and_verifier_proven() -> Result<(), String> {
    for width in widths() {
        assert_inverse_proven(&[5, 3], width)?;
        let exponent: u32 = width.bits() - 1;
        let coefficients: [u64; 3] = [0, 1, 1u64 << exponent];
        assert_inverse_proven(&coefficients, width)?;
    }
    Ok(())
}

#[test]
fn sparse_genuine_product_stays_unchanged() {
    let input: Expr = Expr::mul(Expr::var(7), Expr::var(19));
    for width in widths() {
        let result: Simplification = simplify(&input, width);
        assert!(!result.changed(), "unexpected rewrite at {width:?}");
        assert_eq!(result.simplified, input);
    }
}

#[test]
fn sparse_simplification_is_deterministic() {
    let input: Expr = xor_carry_add(7, 19);
    for width in widths() {
        let first: Simplification = simplify(&input, width);
        for _ in 0..2 {
            assert_eq!(simplify(&input, width), first);
        }
    }
}

#[test]
fn maximum_variable_indices_compact_and_restore_without_overflow() {
    let left: u32 = u32::MAX - 1;
    let right: u32 = u32::MAX;
    let input: Expr = xor_carry_add(left, right);
    let expected: Expr = Expr::add(Expr::var(left), Expr::var(right));
    for width in widths() {
        let result: Simplification = simplify(&input, width);
        assert!(result.changed(), "expected a simplification at {width:?}");
        assert_eq!(result.simplified, expected);
        assert_eq!(
            verify_equivalent(&input, &result.simplified, width),
            Equivalence::Proven,
            "expected a verifier proof at {width:?}"
        );
    }
}

fn sparse_expression(form: u8, left: u32, right: u32) -> Expr {
    match form {
        0 => xor_carry_add(left, right),
        1 => Expr::add(
            Expr::xor(Expr::var(left), Expr::var(right)),
            Expr::and(Expr::var(left), Expr::var(right)),
        ),
        2 => Expr::sub(
            Expr::xor(Expr::var(left), Expr::var(right)),
            Expr::mul(
                Expr::konst(2),
                Expr::and(Expr::not(Expr::var(left)), Expr::var(right)),
            ),
        ),
        _ => Expr::mul(Expr::var(left), Expr::var(right)),
    }
}

#[test]
fn sparse_form_width_matrix_only_emits_proven_rewrites() {
    for form in 0u8..4 {
        for width in widths() {
            let input: Expr = sparse_expression(form, 7, 19);
            let result: Simplification = simplify(&input, width);
            if result.changed() {
                assert_eq!(
                    verify_equivalent(&input, &result.simplified, width),
                    Equivalence::Proven
                );
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn every_emitted_sparse_rewrite_is_verifier_proven(
        form in 0u8..4,
        left in 2u32..48,
        gap in 1u32..16,
        width_index in 0usize..4,
    ) {
        let right: u32 = left + gap;
        let width: Width = widths()[width_index];
        let input: Expr = sparse_expression(form, left, right);
        let result: Simplification = simplify(&input, width);
        if result.changed() {
            prop_assert_eq!(
                verify_equivalent(&input, &result.simplified, width),
                Equivalence::Proven
            );
        }
    }
}
