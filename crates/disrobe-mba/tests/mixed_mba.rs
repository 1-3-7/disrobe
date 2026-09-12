#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_mba::poly_oracle::polynomial_identity_proves;
use disrobe_mba::{
    Expr, MAX_MIXED_MBA_NODES, MAX_MIXED_MBA_WORK, MixedRefusal, MixedSimplification,
    Simplification, Verification, Width, equivalent_exhaustive, simplify, simplify_mixed,
    simplify_mixed_detailed,
};
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

fn hidden_sum_of(left: Expr, right: Expr) -> Expr {
    Expr::add(
        Expr::xor(left.clone(), right.clone()),
        Expr::mul(Expr::konst(2), Expr::and(left, right)),
    )
}

#[test]
fn nonlinear_product_subterm_is_recovered_with_a_width_specific_proof() {
    let product: Expr = Expr::mul(var(0), var(1));
    let obfuscated: Expr = hidden_sum_of(product.clone(), var(2));
    for width in [
        Width::W1,
        Width::W2,
        Width::W4,
        Width::W8,
        Width::W16,
        Width::W32,
        Width::W64,
    ] {
        let result: MixedSimplification = simplify_mixed_detailed(&obfuscated, width);
        let MixedSimplification::Simplified {
            expression,
            verification,
        } = result
        else {
            panic!("{width:?}: expected a proven nonlinear-subterm rewrite, got {result:?}");
        };
        let expected: Expr = if width == Width::W1 {
            Expr::xor(var(2), product.clone())
        } else {
            Expr::add(product.clone(), var(2))
        };
        assert!(
            polynomial_identity_proves(&expression, &expected, width),
            "{width:?}: expected `{expected}`, got `{expression}`"
        );
        assert!(
            expression.node_count() < obfuscated.node_count(),
            "{width:?}"
        );
        assert!(verification.is_proven(), "{width:?}: {verification:?}");
        assert_ne!(verification, Verification::Unverified, "{width:?}");
    }
}

#[test]
fn substitution_refuses_when_fresh_atoms_exceed_the_effective_variable_cap() {
    let nonlinear: Expr = Expr::mul(
        Expr::add(Expr::add(var(1), var(2)), Expr::add(var(3), var(4))),
        var(5),
    );
    let obfuscated: Expr = hidden_sum_of(nonlinear, var(0));
    assert_eq!(
        simplify_mixed_detailed(&obfuscated, Width::W8),
        MixedSimplification::Refused(MixedRefusal::VariableLimit {
            required: 7,
            limit: 6,
        })
    );
}

#[test]
fn memory_load_is_never_selected_as_a_substitution_atom() {
    let read: Expr = Expr::mem(var(0), Width::W8);
    let obfuscated: Expr = hidden_sum_of(read, var(1));
    assert_eq!(
        simplify_mixed_detailed(&obfuscated, Width::W8),
        MixedSimplification::Refused(MixedRefusal::Memory)
    );
    assert!(simplify_mixed(&obfuscated, Width::W8).is_none());
}

fn balanced_add_tree(levels: usize) -> Expr {
    let mut expression: Expr = var(0);
    for _ in 0..levels {
        expression = Expr::add(expression.clone(), expression);
    }
    expression
}

#[test]
fn repeated_requests_return_the_same_typed_depth_node_and_work_refusals() {
    let mut too_deep: Expr = var(0);
    for _ in 1..256 {
        too_deep = Expr::not(too_deep);
    }
    let too_many_nodes: Expr = balanced_add_tree(14);
    assert_eq!(too_many_nodes.node_count(), MAX_MIXED_MBA_NODES * 2 - 1);
    let too_much_work: Expr = balanced_add_tree(10);
    assert_eq!(too_much_work.node_count(), MAX_MIXED_MBA_WORK * 2 - 1);
    for _ in 0..3 {
        assert_eq!(
            simplify_mixed_detailed(&too_deep, Width::W8),
            MixedSimplification::Refused(MixedRefusal::DepthLimit {
                depth: 256,
                limit: 256,
            })
        );
        assert_eq!(
            simplify_mixed_detailed(&too_many_nodes, Width::W8),
            MixedSimplification::Refused(MixedRefusal::NodeLimit {
                nodes: MAX_MIXED_MBA_NODES * 2 - 1,
                limit: MAX_MIXED_MBA_NODES,
            })
        );
        assert_eq!(
            simplify_mixed_detailed(&too_much_work, Width::W8),
            MixedSimplification::Refused(MixedRefusal::WorkLimit {
                required: MAX_MIXED_MBA_WORK + 1,
                limit: MAX_MIXED_MBA_WORK,
            })
        );
    }
}

fn assert_proven_rewrite(original: &Expr, expected: &Expr, width: Width) {
    let result: MixedSimplification = simplify_mixed_detailed(original, width);
    let MixedSimplification::Simplified {
        expression,
        verification,
    } = result
    else {
        panic!("expected a proven rewrite for `{original}`, got {result:?}");
    };
    assert!(verification.is_proven(), "{verification:?}");
    assert!(
        polynomial_identity_proves(&expression, expected, width)
            || equivalent_exhaustive(&expression, expected, width, original.vars().len() as u32),
        "expected `{expected}`, got `{expression}`"
    );
}

#[test]
fn recursion_proves_rewrites_inside_ite_slice_and_compose_nodes() {
    let product: Expr = Expr::mul(var(0), var(1));
    let hidden: Expr = hidden_sum_of(product.clone(), var(2));
    let clean: Expr = Expr::add(product, var(2));
    let ite: Expr = Expr::ite(var(3), hidden.clone(), var(4));
    let clean_ite: Expr = Expr::ite(var(3), clean.clone(), var(4));
    assert_proven_rewrite(&ite, &clean_ite, Width::W2);
    let slice: Expr = Expr::slice(hidden.clone(), 0, 2);
    let clean_slice: Expr = Expr::slice(clean.clone(), 0, 2);
    assert_proven_rewrite(&slice, &clean_slice, Width::W2);
    let compose: Expr = Expr::compose(hidden, var(3), 1);
    let clean_compose: Expr = Expr::compose(clean, var(3), 1);
    assert_proven_rewrite(&compose, &clean_compose, Width::W2);
}

#[test]
fn nested_mixed_subterm_and_variable_shift_rewrite_only_after_whole_width_proof() {
    let product: Expr = Expr::mul(var(0), var(1));
    let inner_hidden: Expr = hidden_sum_of(product.clone(), var(2));
    let nested: Expr = Expr::mul(inner_hidden, var(3));
    let obfuscated: Expr = hidden_sum_of(nested, var(4));
    let clean_nested: Expr = Expr::mul(Expr::add(product, var(2)), var(3));
    let clean: Expr = Expr::add(clean_nested, var(4));
    assert_proven_rewrite(&obfuscated, &clean, Width::W2);
    let shifted: Expr = Expr::shl(var(0), var(1));
    let shifted_obfuscated: Expr = hidden_sum_of(shifted.clone(), var(2));
    let shifted_clean: Expr = Expr::add(shifted, var(2));
    assert_proven_rewrite(&shifted_obfuscated, &shifted_clean, Width::W32);
}

#[test]
fn zero_width_slice_has_a_named_refusal() {
    let invalid: Expr = Expr::slice(hidden_sum(0, 1), 4, 4);
    assert_eq!(
        simplify_mixed_detailed(&invalid, Width::W8),
        MixedSimplification::Refused(MixedRefusal::InvalidSlice { lo: 4, hi: 4 })
    );
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
    if !cfg!(feature = "smt-verify") {
        assert!(
            !result.changed(),
            "two W16 variables are beyond the enumerable core, so without the bit-blasting leg this construct must be left alone, got `{}`",
            result.simplified
        );
        return;
    }
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
