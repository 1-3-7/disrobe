use disrobe_mba::{
    Expr, Simplification, Verification, Width, columns_equal_mod_width, equivalent_exhaustive,
    equivalent_exhaustive_runnable, is_column_faithful, simplify, solve_linear_mba, truth_column,
};

const fn var(index: u32) -> Expr {
    Expr::var(index)
}

fn columns_match(lhs: &Expr, rhs: &Expr, var_count: u32, width: Width) -> bool {
    let rows: usize = 1usize << var_count;
    let left: Vec<i128> = truth_column(lhs, var_count, rows);
    let right: Vec<i128> = truth_column(rhs, var_count, rows);
    columns_equal_mod_width(&left, &right, width)
}

fn assert_equivalent_where_runnable(lhs: &Expr, rhs: &Expr, var_count: u32) {
    let mut checked: bool = false;
    for width in [Width::W4, Width::W8, Width::W16] {
        if equivalent_exhaustive_runnable(width, var_count) {
            assert!(
                equivalent_exhaustive(lhs, rhs, width, var_count),
                "`{lhs}` not equivalent to `{rhs}` at {width:?}"
            );
            checked = true;
        }
    }
    assert!(
        checked,
        "no runnable exhaustive width for {var_count} vars to grade `{lhs}` vs `{rhs}`"
    );
}

fn assert_recovers(
    obfuscated: &Expr,
    clean: &Expr,
    var_count: u32,
    width: Width,
) -> Simplification {
    let result: Simplification = simplify(obfuscated, width);
    assert!(
        result.changed(),
        "expected `{obfuscated}` to simplify, stayed `{}`",
        result.simplified
    );
    assert!(
        result.verification.is_proven(),
        "rewrite of `{obfuscated}` emitted without a soundness proof"
    );
    assert_equivalent_where_runnable(&result.simplified, clean, var_count);
    assert!(
        result.simplified_nodes < result.original_nodes,
        "recovered `{}` ({} nodes) not simpler than `{obfuscated}` ({} nodes)",
        result.simplified,
        result.simplified_nodes,
        result.original_nodes
    );
    result
}

fn assert_self_consistent_or_unchanged(obfuscated: &Expr, var_count: u32, width: Width) {
    let result: Simplification = simplify(obfuscated, width);
    if result.changed() {
        assert!(
            result.verification.is_proven(),
            "any emitted rewrite of `{obfuscated}` must be proven"
        );
        assert_equivalent_where_runnable(obfuscated, &result.simplified, var_count);
    }
}

#[test]
fn ollvm_xor_plus_twice_and_is_addition() {
    let obfuscated: Expr = Expr::add(
        Expr::xor(var(0), var(1)),
        Expr::mul(Expr::konst(2), Expr::and(var(0), var(1))),
    );
    assert_recovers(&obfuscated, &Expr::add(var(0), var(1)), 2, Width::W8);
}

#[test]
fn ollvm_or_plus_and_is_addition() {
    let obfuscated: Expr = Expr::add(Expr::or(var(0), var(1)), Expr::and(var(0), var(1)));
    assert_recovers(&obfuscated, &Expr::add(var(0), var(1)), 2, Width::W8);
}

#[test]
fn ollvm_or_minus_xor_is_and() {
    let obfuscated: Expr = Expr::sub(Expr::or(var(0), var(1)), Expr::xor(var(0), var(1)));
    assert_recovers(&obfuscated, &Expr::and(var(0), var(1)), 2, Width::W8);
}

#[test]
fn ollvm_or_minus_and_is_xor() {
    let obfuscated: Expr = Expr::sub(Expr::or(var(0), var(1)), Expr::and(var(0), var(1)));
    assert_recovers(&obfuscated, &Expr::xor(var(0), var(1)), 2, Width::W8);
}

#[test]
fn ollvm_twice_or_minus_xor_is_addition() {
    let obfuscated: Expr = Expr::sub(
        Expr::mul(Expr::konst(2), Expr::or(var(0), var(1))),
        Expr::xor(var(0), var(1)),
    );
    assert_recovers(&obfuscated, &Expr::add(var(0), var(1)), 2, Width::W8);
}

#[test]
fn ollvm_x_minus_x_and_y_is_x_and_not_y() {
    let obfuscated: Expr = Expr::sub(var(0), Expr::and(var(0), var(1)));
    assert_recovers(
        &obfuscated,
        &Expr::and(var(0), Expr::not(var(1))),
        2,
        Width::W8,
    );
}

#[test]
fn ollvm_xor_via_and_or_minus_twice_and_is_subtraction() {
    let obfuscated: Expr = Expr::sub(
        Expr::xor(var(0), var(1)),
        Expr::mul(Expr::konst(2), Expr::and(Expr::not(var(0)), var(1))),
    );
    assert_recovers(&obfuscated, &Expr::sub(var(0), var(1)), 2, Width::W8);
}

#[test]
fn ollvm_xor_decomposition_is_xor() {
    let obfuscated: Expr = Expr::or(
        Expr::and(var(0), Expr::not(var(1))),
        Expr::and(Expr::not(var(0)), var(1)),
    );
    assert_recovers(&obfuscated, &Expr::xor(var(0), var(1)), 2, Width::W8);
}

#[test]
fn ollvm_sum_of_three_bitwise_basis_is_addition() {
    let obfuscated: Expr = Expr::sub(
        Expr::add(Expr::or(var(0), var(1)), Expr::and(var(0), var(1))),
        Expr::konst(0),
    );
    assert_recovers(&obfuscated, &Expr::add(var(0), var(1)), 2, Width::W8);
}

#[test]
fn ollvm_three_var_xor_plus_carry_stays_consistent() {
    let obfuscated: Expr = Expr::add(
        Expr::xor(Expr::xor(var(0), var(1)), var(2)),
        Expr::mul(Expr::konst(2), Expr::and(var(0), var(1))),
    );
    assert_self_consistent_or_unchanged(&obfuscated, 3, Width::W8);
}

#[test]
fn ollvm_three_var_addition_recovers() {
    let obfuscated: Expr = Expr::add(
        Expr::add(Expr::or(var(0), var(1)), Expr::and(var(0), var(1))),
        var(2),
    );
    assert_recovers(
        &obfuscated,
        &Expr::add(Expr::add(var(0), var(1)), var(2)),
        3,
        Width::W8,
    );
}

#[test]
fn negative_genuine_addition_not_falsely_collapsed() {
    let genuine: Expr = Expr::add(var(0), var(1));
    let result: Simplification = simplify(&genuine, Width::W8);
    assert!(
        !result.changed() || equivalent_exhaustive(&result.simplified, &genuine, Width::W8, 2),
        "genuine x+y must not become a non-equivalent form"
    );
}

#[test]
fn negative_xor_must_not_become_and() {
    let obfuscated: Expr = Expr::sub(Expr::or(var(0), var(1)), Expr::and(var(0), var(1)));
    let result: Simplification = simplify(&obfuscated, Width::W8);
    let wrong: Expr = Expr::and(var(0), var(1));
    assert!(
        !equivalent_exhaustive(&result.simplified, &wrong, Width::W8, 2),
        "x^y form must never collapse to x&y"
    );
}

#[test]
fn negative_real_multiplication_is_left_untouched() {
    let genuine: Expr = Expr::mul(var(0), var(1));
    let result: Simplification = simplify(&genuine, Width::W8);
    assert!(!result.changed());
    assert_eq!(result.verification, Verification::Unverified);
}

#[test]
fn negative_distinct_pair_never_rewritten_to_each_other() {
    let pairs: [(Expr, Expr); 4] = [
        (Expr::add(var(0), var(1)), Expr::sub(var(0), var(1))),
        (Expr::and(var(0), var(1)), Expr::or(var(0), var(1))),
        (Expr::xor(var(0), var(1)), Expr::and(var(0), var(1))),
        (
            Expr::and(var(0), Expr::not(var(1))),
            Expr::and(Expr::not(var(0)), var(1)),
        ),
    ];
    for (left, right) in pairs {
        let result: Simplification = simplify(&left, Width::W8);
        assert!(
            !equivalent_exhaustive(&result.simplified, &right, Width::W8, 2),
            "`{left}` was rewritten into the non-equivalent `{right}` as `{}`",
            result.simplified
        );
    }
}

#[test]
fn affine_like_terms_collapse_over_nonlinear_atom_at_wide_width() {
    let product: Expr = Expr::mul(var(0), var(1));
    let obfuscated: Expr = Expr::add(product.clone(), product.clone());
    let result: Simplification = simplify(&obfuscated, Width::W64);
    assert!(
        result.changed() && result.verification == Verification::PolynomialIdentity(Width::W64),
        "t + t over a nonlinear atom t=x*y must collapse to 2*t by algebraic identity at 64-bit, got {result:?}"
    );
    assert_eq!(
        result.simplified,
        Expr::mul(Expr::konst(2), product),
        "expected 2*(x*y), got `{}`",
        result.simplified
    );
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn affine_like_terms_cancel_nonlinear_atom_to_zero_at_wide_width() {
    let product: Expr = Expr::mul(var(0), var(1));
    let obfuscated: Expr = Expr::sub(product.clone(), product);
    let result: Simplification = simplify(&obfuscated, Width::W64);
    assert_eq!(
        result.verification,
        Verification::PolynomialIdentity(Width::W64)
    );
    assert_eq!(result.simplified, Expr::konst(0));
}

#[test]
fn affine_coefficient_merge_folds_scaled_terms() {
    let atom: Expr = Expr::and(var(0), var(1));
    let obfuscated: Expr = Expr::sub(Expr::mul(Expr::konst(3), atom.clone()), atom.clone());
    let result: Simplification = simplify(&obfuscated, Width::W8);
    assert!(result.changed() && result.verification.is_proven());
    assert!(
        equivalent_exhaustive(
            &result.simplified,
            &Expr::mul(Expr::konst(2), atom),
            Width::W8,
            2
        ),
        "3*(x&y) - (x&y) must fold to 2*(x&y), got `{}`",
        result.simplified
    );
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn wide_width_multivar_lifts_or_stays_proven() {
    let obfuscated: Expr = Expr::sub(var(0), Expr::and(var(0), var(1)));
    for width in [Width::W16, Width::W32, Width::W64] {
        let result: Simplification = simplify(&obfuscated, width);
        if result.changed() {
            assert!(result.verification.is_proven());
            assert_equivalent_where_runnable(&obfuscated, &result.simplified, 2);
        }
    }
}

#[cfg(feature = "smt-verify")]
#[test]
fn smt_proves_wide_multivar_when_exhaustive_cannot() {
    let obfuscated: Expr = Expr::sub(var(0), Expr::and(var(0), var(1)));
    let result: Simplification = simplify(&obfuscated, Width::W64);
    if result.changed() {
        assert!(result.verification.is_proven());
        assert_equivalent_where_runnable(&obfuscated, &result.simplified, 2);
    }
}

#[test]
fn solver_four_var_two_pair_addition_at_w32_column_proven() {
    let obfuscated: Expr = Expr::add(
        Expr::add(
            Expr::xor(var(0), var(1)),
            Expr::mul(Expr::konst(2), Expr::and(var(0), var(1))),
        ),
        Expr::add(
            Expr::xor(var(2), var(3)),
            Expr::mul(Expr::konst(2), Expr::and(var(2), var(3))),
        ),
    );
    let result: Simplification = simplify(&obfuscated, Width::W32);
    assert!(result.changed());
    assert_eq!(
        result.verification,
        Verification::LinearColumnIdentity(Width::W32)
    );
    let clean: Expr = Expr::add(Expr::add(var(0), var(1)), Expr::add(var(2), var(3)));
    assert!(columns_match(&result.simplified, &clean, 4, Width::W32));
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn solver_recovers_x_minus_and_at_w64_for_two_vars() {
    let obfuscated: Expr = Expr::sub(var(0), Expr::and(var(0), var(1)));
    let solved: Option<Expr> = solve_linear_mba(&obfuscated, Width::W64, 2);
    assert!(
        solved.is_some(),
        "x - (x & y) is a faithful linear MBA the solver must recover"
    );
    let clean: Expr = Expr::and(var(0), Expr::not(var(1)));
    if let Some(recovered) = solved {
        assert!(columns_match(&recovered, &clean, 2, Width::W64));
        assert!(recovered.node_count() <= clean.node_count() + 1);
    }
    let result: Simplification = simplify(&obfuscated, Width::W64);
    assert!(result.changed());
    assert_eq!(
        result.verification,
        Verification::LinearColumnIdentity(Width::W64)
    );
}

#[test]
fn solver_refuses_value_position_partial_mask_constant() {
    let obfuscated: Expr = Expr::xor(var(0), Expr::konst(0x0F));
    assert!(
        !is_column_faithful(&obfuscated, Width::W32),
        "a partial-width mask constant is not column-faithful at W32"
    );
    let result: Simplification = simplify(&obfuscated, Width::W32);
    if result.changed() {
        assert_ne!(
            result.verification,
            Verification::LinearColumnIdentity(Width::W32),
            "the column proof must not fire on a partial-mask constant; only an exact oracle may"
        );
    }
}

#[test]
fn solver_negative_distinct_multivar_forms_never_collapse_at_w32() {
    let pairs: [(Expr, Expr); 3] = [
        (
            Expr::add(Expr::add(var(0), var(1)), var(2)),
            Expr::sub(Expr::add(var(0), var(1)), var(2)),
        ),
        (
            Expr::xor(Expr::xor(var(0), var(1)), var(2)),
            Expr::and(Expr::and(var(0), var(1)), var(2)),
        ),
        (
            Expr::add(Expr::or(var(0), var(1)), var(2)),
            Expr::add(Expr::and(var(0), var(1)), var(2)),
        ),
    ];
    for (left, right) in pairs {
        let result: Simplification = simplify(&left, Width::W32);
        assert!(
            !columns_match(&result.simplified, &right, 3, Width::W32),
            "`{left}` must never be rewritten into the non-equivalent `{right}` at W32, got `{}`",
            result.simplified
        );
    }
}

#[test]
fn solver_soundness_no_false_column_proof_against_exhaustive() {
    let forms: [Expr; 8] = [
        Expr::add(var(0), var(1)),
        Expr::sub(var(0), var(1)),
        Expr::and(var(0), var(1)),
        Expr::or(var(0), var(1)),
        Expr::xor(var(0), var(1)),
        Expr::and(var(0), Expr::not(var(1))),
        Expr::add(Expr::xor(var(0), var(1)), Expr::and(var(0), var(1))),
        Expr::sub(var(0), Expr::and(var(0), var(1))),
    ];
    for left in &forms {
        for right in &forms {
            if !is_column_faithful(left, Width::W8) || !is_column_faithful(right, Width::W8) {
                continue;
            }
            let proof: bool = columns_match(left, right, 2, Width::W8);
            let truth: bool = equivalent_exhaustive(left, right, Width::W8, 2);
            assert_eq!(
                proof, truth,
                "column proof for faithful `{left}` vs `{right}` disagreed with exhaustive truth"
            );
        }
    }
}
