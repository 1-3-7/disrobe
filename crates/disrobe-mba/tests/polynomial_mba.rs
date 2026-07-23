use disrobe_mba::{
    Expr, Simplification, Verification, Width, equivalent_exhaustive, simplify,
    solve_polynomial_mba,
};

const fn var(index: u32) -> Expr {
    Expr::var(index)
}

fn eval_points_agree(lhs: &Expr, rhs: &Expr, width: Width, points: &[[u64; 3]]) -> bool {
    points
        .iter()
        .all(|env: &[u64; 3]| lhs.eval(env, width) == rhs.eval(env, width))
}

const WIDE_POINTS: [[u64; 3]; 6] = [
    [0, 0, 0],
    [1, 1, 1],
    [u64::MAX, 1, 2],
    [0x1234_5678_9ABC_DEF0, 0x0FED_CBA9_8765_4321, 7],
    [1u64 << 63, (1u64 << 63) + 1, u64::MAX],
    [u64::MAX - 1, 3, 1u64 << 40],
];

#[test]
fn distributive_cancellation_recovers_x_at_narrow_and_wide() {
    let obfuscated: Expr = Expr::sub(
        Expr::mul(var(0), Expr::add(var(1), Expr::konst(1))),
        Expr::mul(var(0), var(1)),
    );
    let clean: Expr = var(0);

    let narrow: Simplification = simplify(&obfuscated, Width::W8);
    assert!(narrow.changed());
    assert!(narrow.verification.is_proven());
    assert!(equivalent_exhaustive(
        &narrow.simplified,
        &clean,
        Width::W8,
        2
    ));
    assert!(narrow.simplified_nodes < narrow.original_nodes);

    let wide: Simplification = simplify(&obfuscated, Width::W64);
    assert!(wide.changed());
    assert_eq!(
        wide.verification,
        Verification::PolynomialIdentity(Width::W64),
        "wide-width polynomial reduction proves by the mod-2^n normal form, got {:?}",
        wide.verification
    );
    assert!(eval_points_agree(
        &obfuscated,
        &wide.simplified,
        Width::W64,
        &WIDE_POINTS
    ));
    assert!(eval_points_agree(
        &wide.simplified,
        &clean,
        Width::W64,
        &WIDE_POINTS
    ));
}

#[test]
fn scaled_distribution_recovers_two_x() {
    let obfuscated: Expr = Expr::sub(
        Expr::mul(var(0), Expr::add(var(1), Expr::konst(2))),
        Expr::mul(var(0), var(1)),
    );
    let clean: Expr = Expr::mul(Expr::konst(2), var(0));
    let result: Simplification = simplify(&obfuscated, Width::W8);
    assert!(result.changed());
    assert!(result.verification.is_proven());
    assert!(equivalent_exhaustive(
        &result.simplified,
        &clean,
        Width::W8,
        2
    ));
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn full_distribution_cancels_to_zero_three_vars() {
    let obfuscated: Expr = Expr::sub(
        Expr::sub(
            Expr::mul(var(0), Expr::add(var(1), var(2))),
            Expr::mul(var(0), var(1)),
        ),
        Expr::mul(var(0), var(2)),
    );
    let result: Simplification = simplify(&obfuscated, Width::W8);
    assert!(result.changed());
    assert!(result.verification.is_proven());
    assert!(equivalent_exhaustive(
        &result.simplified,
        &Expr::konst(0),
        Width::W4,
        3
    ));
    assert!(equivalent_exhaustive(
        &result.simplified,
        &Expr::konst(0),
        Width::W8,
        3
    ));
}

#[test]
fn degree_three_product_cancels_to_variable_wide() {
    let obfuscated: Expr = Expr::sub(
        Expr::mul(var(0), Expr::add(Expr::mul(var(1), var(2)), Expr::konst(1))),
        Expr::mul(Expr::mul(var(0), var(1)), var(2)),
    );
    let clean: Expr = var(0);

    let narrow: Simplification = simplify(&obfuscated, Width::W8);
    assert!(narrow.changed());
    assert!(narrow.verification.is_proven());
    assert!(equivalent_exhaustive(
        &narrow.simplified,
        &clean,
        Width::W4,
        3
    ));

    let wide: Simplification = simplify(&obfuscated, Width::W64);
    assert!(wide.changed());
    assert_eq!(
        wide.verification,
        Verification::PolynomialIdentity(Width::W64)
    );
    assert!(eval_points_agree(
        &obfuscated,
        &wide.simplified,
        Width::W64,
        &WIDE_POINTS
    ));
    assert!(eval_points_agree(
        &wide.simplified,
        &clean,
        Width::W64,
        &WIDE_POINTS
    ));
}

#[test]
fn mixed_polynomial_and_linear_atoms_reduce() {
    let obfuscated: Expr = Expr::add(
        Expr::sub(
            Expr::mul(var(0), Expr::add(var(1), Expr::konst(1))),
            Expr::mul(var(0), var(1)),
        ),
        Expr::add(
            Expr::xor(var(0), var(1)),
            Expr::mul(Expr::konst(2), Expr::and(var(0), var(1))),
        ),
    );
    let clean: Expr = Expr::add(var(0), Expr::add(var(0), var(1)));
    let result: Simplification = simplify(&obfuscated, Width::W8);
    assert!(result.changed());
    assert!(result.verification.is_proven());
    assert!(
        equivalent_exhaustive(&result.simplified, &clean, Width::W8, 2),
        "expected 2*x + y, got `{}`",
        result.simplified
    );
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn width_specific_vanishing_collapses_at_w8_only() {
    let product: Expr = Expr::mul(var(0), var(1));
    let obfuscated: Expr = Expr::add(var(0), Expr::mul(Expr::konst(256), product));

    let at_w8: Simplification = simplify(&obfuscated, Width::W8);
    assert!(at_w8.changed());
    assert!(at_w8.verification.is_proven());
    assert!(
        equivalent_exhaustive(&at_w8.simplified, &var(0), Width::W8, 2),
        "256*x*y vanishes mod 2^8 so the form is x, got `{}`",
        at_w8.simplified
    );

    let at_w16: Simplification = simplify(&obfuscated, Width::W16);
    let sample: [u64; 3] = [1, 1, 0];
    assert_eq!(
        obfuscated.eval(&sample, Width::W16),
        at_w16.simplified.eval(&sample, Width::W16),
        "any emitted W16 form must preserve semantics"
    );
    assert_ne!(
        at_w16.simplified.eval(&sample, Width::W16),
        var(0).eval(&sample, Width::W16),
        "256*x*y survives mod 2^16, so the form must not collapse to x"
    );
}

#[test]
fn genuine_product_untouched() {
    let genuine: Expr = Expr::mul(var(0), var(1));
    let result: Simplification = simplify(&genuine, Width::W8);
    assert!(!result.changed());
    assert_eq!(result.verification, Verification::Unverified);
}

#[test]
fn surviving_scaled_product_untouched() {
    let obfuscated: Expr = Expr::mul(Expr::konst(2), Expr::mul(var(0), var(1)));
    assert!(solve_polynomial_mba(&obfuscated, Width::W8, 2).is_none());
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
fn square_is_not_linear_and_untouched() {
    let square: Expr = Expr::mul(var(0), var(0));
    assert!(solve_polynomial_mba(&square, Width::W8, 1).is_none());
    let result: Simplification = simplify(&square, Width::W8);
    if result.changed() {
        assert!(equivalent_exhaustive(
            &square,
            &result.simplified,
            Width::W8,
            1
        ));
    }
}
