use disrobe_mba::{
    BranchFold, CmpOp, Expr, OpaqueVerdict, Predicate, Simplification, Verification, Width,
    classify, columns_equal_mod_width, equivalent_exhaustive, equivalent_exhaustive_runnable,
    fold_branch, simplify, truth_column,
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

#[test]
fn mba_full_adder_identity_canonicalizes_to_addition() {
    let obfuscated: Expr = Expr::add(
        Expr::xor(var(0), var(1)),
        Expr::mul(Expr::konst(2), Expr::and(var(0), var(1))),
    );
    let result = simplify(&obfuscated, Width::W32);
    assert!(result.changed());
    assert!(result.verification.is_proven());
    let known_answer: Expr = Expr::add(var(0), var(1));
    assert!(
        equivalent_exhaustive(&result.simplified, &known_answer, Width::W8, 2),
        "expected x + y, got `{}`",
        result.simplified
    );
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn mba_or_identity_recovers_or() {
    let obfuscated: Expr = Expr::add(Expr::xor(var(0), var(1)), Expr::and(var(0), var(1)));
    let result = simplify(&obfuscated, Width::W16);
    assert!(result.changed());
    let known_answer: Expr = Expr::or(var(0), var(1));
    assert!(equivalent_exhaustive(
        &result.simplified,
        &known_answer,
        Width::W8,
        2
    ));
}

#[test]
fn mba_sub_disguise_recovers_subtraction() {
    let obfuscated: Expr = Expr::sub(
        Expr::xor(var(0), var(1)),
        Expr::mul(Expr::konst(2), Expr::and(Expr::not(var(0)), var(1))),
    );
    let result = simplify(&obfuscated, Width::W32);
    let known_answer: Expr = Expr::sub(var(0), var(1));
    assert!(
        equivalent_exhaustive(&result.simplified, &known_answer, Width::W8, 2),
        "expected x - y, got `{}`",
        result.simplified
    );
}

#[test]
fn mba_leaves_real_multiplication_alone() {
    let genuine: Expr = Expr::mul(var(0), var(1));
    let result = simplify(&genuine, Width::W32);
    assert!(!result.changed());
    assert_eq!(result.verification, Verification::Unverified);
}

#[test]
fn opaque_collatz_style_parity_predicate_is_dead() {
    let body: Expr = Expr::add(Expr::mul(var(0), var(0)), var(0));
    let predicate: Predicate = Predicate::eq(Expr::and(body, Expr::konst(1)), Expr::konst(0));
    let verdict: OpaqueVerdict = classify(&predicate, Width::W8);
    assert_eq!(verdict.constant_value(), Some(true));
    assert_eq!(
        fold_branch(&predicate, Width::W8),
        BranchFold::KeepConsequent
    );
}

#[test]
fn opaque_quadratic_non_residue_is_always_true() {
    let lhs: Expr = Expr::sub(
        Expr::mul(Expr::konst(7), Expr::mul(var(1), var(1))),
        Expr::konst(1),
    );
    let rhs: Expr = Expr::mul(var(0), var(0));
    let predicate: Predicate = Predicate::ne(lhs, rhs);
    assert!(classify(&predicate, Width::W8).is_opaque());
}

#[test]
fn opaque_negative_control_real_predicate_survives() {
    let predicate: Predicate = Predicate::Compare {
        op: CmpOp::UnsignedLt,
        left: var(0),
        right: Expr::konst(42),
    };
    let verdict: OpaqueVerdict = classify(&predicate, Width::W8);
    assert_eq!(verdict, OpaqueVerdict::DataDependent);
    assert_eq!(fold_branch(&predicate, Width::W8), BranchFold::Unresolved);
}

#[test]
fn opaque_equality_negative_control_survives() {
    let predicate: Predicate = Predicate::eq(Expr::mul(var(0), var(0)), var(1));
    assert_eq!(
        classify(&predicate, Width::W8),
        OpaqueVerdict::DataDependent
    );
}

#[test]
fn solver_proves_xor_carry_addition_at_w16_by_column_identity() {
    let obfuscated: Expr = Expr::add(
        Expr::xor(var(0), var(1)),
        Expr::mul(Expr::konst(2), Expr::and(var(0), var(1))),
    );
    let result: Simplification = simplify(&obfuscated, Width::W16);
    assert!(result.changed(), "expected a simplification at W16");
    assert_eq!(
        result.verification,
        Verification::LinearColumnIdentity(Width::W16),
        "two-var xor-carry at W16 must be proven exactly by the column-identity solver, got {:?}",
        result.verification
    );
    assert!(columns_match(
        &result.simplified,
        &Expr::add(var(0), var(1)),
        2,
        Width::W16
    ));
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn solver_proves_xor_carry_addition_at_w32_by_column_identity() {
    let obfuscated: Expr = Expr::add(
        Expr::xor(var(0), var(1)),
        Expr::mul(Expr::konst(2), Expr::and(var(0), var(1))),
    );
    let result: Simplification = simplify(&obfuscated, Width::W32);
    assert!(result.changed());
    assert_eq!(
        result.verification,
        Verification::LinearColumnIdentity(Width::W32)
    );
    assert!(columns_match(
        &result.simplified,
        &Expr::add(var(0), var(1)),
        2,
        Width::W32
    ));
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn solver_recovers_four_var_addition_beyond_exhaustive_core_at_w16() {
    let obfuscated: Expr = Expr::add(
        Expr::add(Expr::or(var(0), var(1)), Expr::and(var(0), var(1))),
        Expr::add(Expr::or(var(2), var(3)), Expr::and(var(2), var(3))),
    );
    assert!(
        !equivalent_exhaustive_runnable(Width::W16, 4),
        "four 16-bit vars must be outside the exhaustive core so this exercises the solver"
    );
    let result: Simplification = simplify(&obfuscated, Width::W16);
    assert!(
        result.changed(),
        "four-var W16 MBA must simplify via the solver"
    );
    assert_eq!(
        result.verification,
        Verification::LinearColumnIdentity(Width::W16),
        "got {:?}",
        result.verification
    );
    let clean: Expr = Expr::add(Expr::add(var(0), var(1)), Expr::add(var(2), var(3)));
    assert!(
        columns_match(&result.simplified, &clean, 4, Width::W16),
        "recovered `{}` must equal x+y+z+w over Z/2^16",
        result.simplified
    );
    assert!(result.simplified_nodes < result.original_nodes);
    assert!(
        equivalent_exhaustive(&result.simplified, &clean, Width::W4, 4),
        "must also agree at the runnable W4 cross-check"
    );
}

#[test]
fn solver_recovers_five_var_xor_chain_at_w32() {
    let obfuscated: Expr = Expr::add(
        Expr::add(
            Expr::sub(Expr::or(var(0), var(1)), Expr::and(var(0), var(1))),
            Expr::sub(Expr::or(var(2), var(3)), Expr::and(var(2), var(3))),
        ),
        var(4),
    );
    let result: Simplification = simplify(&obfuscated, Width::W32);
    assert!(result.changed(), "five-var W32 MBA must simplify");
    assert_eq!(
        result.verification,
        Verification::LinearColumnIdentity(Width::W32)
    );
    let clean: Expr = Expr::add(
        Expr::add(Expr::xor(var(0), var(1)), Expr::xor(var(2), var(3))),
        var(4),
    );
    assert!(columns_match(&result.simplified, &clean, 5, Width::W32));
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn solver_negative_genuine_addition_at_w32_not_collapsed_to_difference() {
    let genuine: Expr = Expr::add(var(0), var(1));
    let result: Simplification = simplify(&genuine, Width::W32);
    assert!(
        !columns_match(
            &result.simplified,
            &Expr::sub(var(0), var(1)),
            2,
            Width::W32
        ),
        "x+y must never become x-y at W32"
    );
}

#[test]
fn solver_negative_real_multiplication_untouched_at_w16() {
    let genuine: Expr = Expr::mul(var(0), var(1));
    let result: Simplification = simplify(&genuine, Width::W16);
    assert!(!result.changed());
    assert_eq!(result.verification, Verification::Unverified);
}

#[test]
fn solver_eight_var_additive_form_is_bounded_and_proven() {
    let mut obfuscated: Expr = Expr::add(Expr::or(var(0), var(1)), Expr::and(var(0), var(1)));
    for pair in 1..4u32 {
        let lo: u32 = pair * 2;
        let hi: u32 = lo + 1;
        let piece: Expr = Expr::add(Expr::or(var(lo), var(hi)), Expr::and(var(lo), var(hi)));
        obfuscated = Expr::add(obfuscated, piece);
    }
    let result: Simplification = simplify(&obfuscated, Width::W32);
    assert!(
        result.changed(),
        "eight-var additive MBA must simplify under the bounded solver"
    );
    assert!(result.verification.is_proven());
    let mut clean: Expr = Expr::add(var(0), var(1));
    for index in 2..8u32 {
        clean = Expr::add(clean, var(index));
    }
    assert!(columns_match(&result.simplified, &clean, 8, Width::W32));
    assert!(result.simplified_nodes < result.original_nodes);
}
