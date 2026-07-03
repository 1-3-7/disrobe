use disrobe_mba::{
    Expr, Simplification, Verification, Width, columns_equal_mod_width, equivalent_exhaustive,
    is_column_faithful, simplify, truth_column,
};
use proptest::prelude::*;

fn leaf() -> impl Strategy<Value = Expr> {
    prop_oneof![
        (0u32..2).prop_map(Expr::var),
        (0u64..8).prop_map(Expr::konst),
    ]
}

fn leaf3() -> impl Strategy<Value = Expr> {
    prop_oneof![
        (0u32..3).prop_map(Expr::var),
        (0u64..8).prop_map(Expr::konst),
    ]
}

fn expr3_strategy() -> impl Strategy<Value = Expr> {
    leaf3().prop_recursive(4, 32, 2, |inner| {
        prop_oneof![
            inner.clone().prop_map(Expr::not),
            inner.clone().prop_map(Expr::neg),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::add(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::sub(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::and(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::or(a, b)),
            (inner.clone(), inner).prop_map(|(a, b): (Expr, Expr)| Expr::xor(a, b)),
        ]
    })
}

fn expr_strategy() -> impl Strategy<Value = Expr> {
    leaf().prop_recursive(4, 32, 2, |inner| {
        prop_oneof![
            inner.clone().prop_map(Expr::not),
            inner.clone().prop_map(Expr::neg),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::add(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::sub(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::and(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::or(a, b)),
            (inner.clone(), inner).prop_map(|(a, b): (Expr, Expr)| Expr::xor(a, b)),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn simplifier_preserves_semantics(expr in expr_strategy()) {
        let result: Simplification = simplify(&expr, Width::W8);
        prop_assert!(
            equivalent_exhaustive(&expr, &result.simplified, Width::W8, 2),
            "simplified `{}` is not equivalent to original `{}`",
            result.simplified,
            expr
        );
        if result.changed() {
            prop_assert!(result.verification.is_proven());
            prop_assert!(result.simplified_nodes < result.original_nodes);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn simplifier_preserves_semantics_three_vars(expr in expr3_strategy()) {
        let result: Simplification = simplify(&expr, Width::W4);
        prop_assert!(
            equivalent_exhaustive(&expr, &result.simplified, Width::W4, 3),
            "3-var simplified `{}` is not equivalent to original `{}`",
            result.simplified,
            expr
        );
        if result.changed() {
            prop_assert!(result.verification.is_proven());
            prop_assert!(result.simplified_nodes < result.original_nodes);
        }
    }
}

fn leaf4() -> impl Strategy<Value = Expr> {
    prop_oneof![
        (0u32..4).prop_map(Expr::var),
        (0u64..4).prop_map(|value: u64| Expr::konst(value * 2)),
    ]
}

fn expr4_strategy() -> impl Strategy<Value = Expr> {
    leaf4().prop_recursive(4, 28, 2, |inner| {
        prop_oneof![
            inner.clone().prop_map(Expr::not),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::add(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::sub(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::and(a, b)),
            (inner.clone(), inner.clone()).prop_map(|(a, b): (Expr, Expr)| Expr::or(a, b)),
            (inner.clone(), inner).prop_map(|(a, b): (Expr, Expr)| Expr::xor(a, b)),
        ]
    })
}

fn columns_match(lhs: &Expr, rhs: &Expr, var_count: u32, width: Width) -> bool {
    let rows: usize = 1usize << var_count;
    let left: Vec<i128> = truth_column(lhs, var_count, rows);
    let right: Vec<i128> = truth_column(rhs, var_count, rows);
    columns_equal_mod_width(&left, &right, width)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn solver_at_w32_never_falsely_collapses_four_vars(expr in expr4_strategy()) {
        for width in [Width::W16, Width::W32] {
            let result: Simplification = simplify(&expr, width);
            if !result.changed() {
                continue;
            }
            prop_assert!(
                result.verification.is_proven(),
                "any emitted rewrite of `{}` at {width:?} must be proven",
                expr
            );
            prop_assert!(result.simplified_nodes < result.original_nodes);
            if let Verification::LinearColumnIdentity(proven_width) = result.verification {
                prop_assert_eq!(proven_width, width);
                prop_assert!(is_column_faithful(&expr, width));
                prop_assert!(is_column_faithful(&result.simplified, width));
                prop_assert!(
                    columns_match(&expr, &result.simplified, 4, width),
                    "column-identity proof claimed but columns differ for `{}` vs `{}`",
                    expr,
                    result.simplified
                );
                prop_assert!(
                    equivalent_exhaustive(&expr, &result.simplified, Width::W4, 4),
                    "a column-faithful Z/2^n equivalence must also hold at the runnable W4 check: `{}` vs `{}`",
                    expr,
                    result.simplified
                );
            }
        }
    }
}
