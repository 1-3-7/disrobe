#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_mba::{Expr, Simplification, Width, equivalent_exhaustive, simplify, simplify_mixed};
use proptest::prelude::*;

const fn var(index: u32) -> Expr {
    Expr::var(index)
}

fn hidden_sum(a: u32, b: u32) -> Expr {
    Expr::add(
        Expr::xor(var(a), var(b)),
        Expr::mul(Expr::konst(2), Expr::and(var(a), var(b))),
    )
}

#[test]
fn xor_of_two_encodings_of_the_same_sum_cancels_to_zero() {
    let obfuscated: Expr = Expr::xor(hidden_sum(0, 1), Expr::add(var(0), var(1)));
    let result: Option<Expr> = simplify_mixed(&obfuscated, Width::W8);
    let simplified: Expr = result.expect("mixed reducer must fire");
    assert_eq!(simplified, Expr::konst(0));
    assert!(equivalent_exhaustive(
        &obfuscated,
        &simplified,
        Width::W8,
        2
    ));
}

#[test]
fn top_level_simplify_reaches_the_mixed_reduction_and_tags_it() {
    let obfuscated: Expr = Expr::xor(hidden_sum(0, 1), Expr::add(var(0), var(1)));
    let result: Simplification = simplify(&obfuscated, Width::W16);
    assert!(result.changed());
    assert_eq!(result.simplified, Expr::konst(0));
    assert!(
        result.verification.is_proven(),
        "the mixed reduction must be a proven verification, got {:?}",
        result.verification
    );
}

#[test]
fn bitwise_carry_identity_nested_inside_an_outer_xor_reduces_first() {
    let inner: Expr = Expr::add(Expr::and(var(0), var(1)), Expr::xor(var(0), var(1)));
    let obfuscated: Expr = Expr::xor(inner, var(2));
    let simplified: Expr = simplify_mixed(&obfuscated, Width::W8).expect("mixed reducer must fire");
    let expected: Expr = Expr::xor(Expr::or(var(0), var(1)), var(2));
    assert!(
        equivalent_exhaustive(&simplified, &expected, Width::W8, 3),
        "expected an (x|y)^z shaped result, got `{simplified}`"
    );
    assert!(simplified.node_count() < obfuscated.node_count());
}

#[test]
fn product_cancellation_nested_inside_a_bitwise_op_collapses() {
    let product: Expr = Expr::mul(var(0), var(1));
    let obfuscated: Expr = Expr::xor(Expr::sub(product.clone(), product), var(2));
    let simplified: Expr = simplify_mixed(&obfuscated, Width::W8).expect("mixed reducer must fire");
    assert_eq!(simplified, var(2));
    assert!(equivalent_exhaustive(
        &obfuscated,
        &simplified,
        Width::W8,
        3
    ));
}

#[test]
fn right_shift_nested_inside_a_bitwise_op_is_recovered_or_rejected() {
    let obfuscated: Expr = Expr::xor(Expr::shr(var(0), Expr::konst(1)), var(1));
    assert!(
        simplify_mixed(&obfuscated, Width::W8).is_none(),
        "a right shift is not a ring operation and must never be wrongly simplified"
    );
    let result: Simplification = simplify(&obfuscated, Width::W8);
    if result.changed() {
        assert!(equivalent_exhaustive(
            &obfuscated,
            &result.simplified,
            Width::W8,
            2
        ));
    }
}

#[test]
fn unsigned_division_shaped_construct_is_recovered_or_rejected() {
    let divided_like: Expr = Expr::mul(Expr::shr(var(0), Expr::konst(2)), var(1));
    let obfuscated: Expr = Expr::and(divided_like, var(2));
    assert!(
        simplify_mixed(&obfuscated, Width::W8).is_none(),
        "an unsigned-shift-shaped divide must never be wrongly simplified"
    );
}

#[test]
fn xor_of_two_unrelated_arithmetic_sides_has_no_sound_reduction() {
    let irreducible: Expr = Expr::xor(Expr::add(var(0), var(1)), Expr::sub(var(0), var(1)));
    assert!(simplify_mixed(&irreducible, Width::W8).is_none());
}

fn mixed_leaf() -> impl Strategy<Value = Expr> {
    prop_oneof![
        (0u32..3).prop_map(Expr::var),
        (0u64..8).prop_map(Expr::konst),
    ]
}

fn mixed_expr_strategy() -> impl Strategy<Value = Expr> {
    mixed_leaf().prop_recursive(5, 48, 2, |inner| {
        prop_oneof![
            inner.clone().prop_map(Expr::not),
            inner.clone().prop_map(Expr::neg),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::add(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::sub(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::mul(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::and(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::or(a, b)),
            (inner.clone(), inner).prop_map(|(a, b): (Expr, Expr)| Expr::xor(a, b)),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn mixed_reducer_never_changes_semantics_at_w4_three_vars(expr in mixed_expr_strategy()) {
        if let Some(result) = simplify_mixed(&expr, Width::W4) {
            prop_assert_ne!(&result, &expr);
            prop_assert!(
                equivalent_exhaustive(&expr, &result, Width::W4, 3),
                "simplify_mixed changed the semantics of `{}` -> `{}`",
                expr,
                result
            );
        }
    }
}

fn mixed_leaf_two_vars() -> impl Strategy<Value = Expr> {
    prop_oneof![
        (0u32..2).prop_map(Expr::var),
        (0u64..8).prop_map(Expr::konst),
    ]
}

fn mixed_expr_strategy_two_vars() -> impl Strategy<Value = Expr> {
    mixed_leaf_two_vars().prop_recursive(5, 48, 2, |inner| {
        prop_oneof![
            inner.clone().prop_map(Expr::not),
            inner.clone().prop_map(Expr::neg),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::add(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::sub(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::mul(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::and(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::or(a, b)),
            (inner.clone(), inner).prop_map(|(a, b): (Expr, Expr)| Expr::xor(a, b)),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    #[test]
    fn mixed_reducer_never_changes_semantics_at_w8_two_vars(expr in mixed_expr_strategy_two_vars()) {
        if let Some(result) = simplify_mixed(&expr, Width::W8) {
            prop_assert_ne!(&result, &expr);
            prop_assert!(
                equivalent_exhaustive(&expr, &result, Width::W8, 2),
                "simplify_mixed changed the semantics of `{}` -> `{}`",
                expr,
                result
            );
        }
        let result: Simplification = simplify(&expr, Width::W8);
        if result.changed() {
            prop_assert!(result.verification.is_proven());
            prop_assert!(
                equivalent_exhaustive(&expr, &result.simplified, Width::W8, 2),
                "simplify changed the semantics of `{}` -> `{}`",
                expr,
                result.simplified
            );
        }
    }
}
