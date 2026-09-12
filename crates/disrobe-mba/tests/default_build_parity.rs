use disrobe_mba::{
    BranchFold, Equivalence, Expr, OpaqueVerdict, Predicate, Simplification, Width, classify,
    fold_branch, simplify, verify_equivalent,
};

fn x_squared_plus_x() -> Expr {
    Expr::add(Expr::mul(Expr::var(0), Expr::var(0)), Expr::var(0))
}

#[test]
fn opaque_classification_does_not_depend_on_the_solver_feature() {
    let always_even: Predicate = Predicate::eq(
        Expr::and(x_squared_plus_x(), Expr::konst(1)),
        Expr::konst(0),
    );
    assert_eq!(
        classify(&always_even, Width::W32),
        OpaqueVerdict::AlwaysTrue {
            verified_width: Width::W32,
            lifted: false,
        }
    );

    let never_odd: Predicate = Predicate::eq(
        Expr::and(x_squared_plus_x(), Expr::konst(1)),
        Expr::konst(1),
    );
    assert_eq!(classify(&never_odd, Width::W32), OpaqueVerdict::OutOfBudget);

    let data_dependent: Predicate = Predicate::eq(Expr::var(0), Expr::konst(7));
    assert_eq!(
        classify(&data_dependent, Width::W32),
        OpaqueVerdict::DataDependent
    );

    assert_eq!(
        fold_branch(&always_even, Width::W32),
        BranchFold::KeepConsequent
    );
    assert_eq!(fold_branch(&never_odd, Width::W32), BranchFold::Unresolved);
    assert_eq!(
        fold_branch(&data_dependent, Width::W32),
        BranchFold::Unresolved
    );
}

#[test]
fn equivalence_verdicts_do_not_depend_on_the_solver_feature() {
    let carry_form: Expr = Expr::add(
        Expr::xor(Expr::var(0), Expr::var(1)),
        Expr::mul(Expr::konst(2), Expr::and(Expr::var(0), Expr::var(1))),
    );
    let sum: Expr = Expr::add(Expr::var(0), Expr::var(1));
    assert_eq!(
        verify_equivalent(&carry_form, &sum, Width::W64),
        Equivalence::Proven
    );

    let difference: Expr = Expr::sub(Expr::var(0), Expr::var(1));
    assert!(verify_equivalent(&sum, &difference, Width::W64).is_disproven());
}

#[test]
fn simplification_output_does_not_depend_on_the_solver_feature() {
    let mba: Expr = Expr::add(
        Expr::and(Expr::var(0), Expr::var(1)),
        Expr::xor(Expr::var(0), Expr::var(1)),
    );
    let outcome: Simplification = simplify(&mba, Width::W32);
    assert_eq!(outcome.simplified, Expr::or(Expr::var(0), Expr::var(1)));
    assert!(outcome.verification.is_proven());

    let already_minimal: Expr = Expr::var(0);
    let untouched: Simplification = simplify(&already_minimal, Width::W32);
    assert_eq!(untouched.simplified, already_minimal);
    assert!(!untouched.changed());
}
