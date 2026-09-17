#![cfg(feature = "smt-verify")]

use disrobe_mba::{
    CmpOp, Equivalence, Expr, Predicate, PredicateSimplification, Simplification, Width, simplify,
    simplify_predicate, verify_equivalent, verify_predicate_equivalent_budgeted,
};
use proptest::prelude::*;

const fn variable(index: u32) -> Expr {
    Expr::var(index)
}

const fn widths() -> [Width; 4] {
    [Width::W8, Width::W16, Width::W32, Width::W64]
}

fn boolean_expr_strategy() -> impl Strategy<Value = Expr> {
    let leaf: BoxedStrategy<Expr> = (0u32..3).prop_map(Expr::var).boxed();
    leaf.prop_recursive(4, 48, 2, |inner: BoxedStrategy<Expr>| {
        prop_oneof![
            inner.clone().prop_map(Expr::not),
            (inner.clone(), inner.clone())
                .prop_map(|(left, right): (Expr, Expr)| { Expr::and(left, right) }),
            (inner.clone(), inner.clone())
                .prop_map(|(left, right): (Expr, Expr)| { Expr::or(left, right) }),
            (inner.clone(), inner)
                .prop_map(|(left, right): (Expr, Expr)| { Expr::xor(left, right) }),
        ]
    })
}

fn predicate_strategy() -> impl Strategy<Value = Predicate> {
    let comparison: BoxedStrategy<Predicate> = (
        prop_oneof![
            Just(CmpOp::Eq),
            Just(CmpOp::Ne),
            Just(CmpOp::UnsignedLt),
            Just(CmpOp::UnsignedLe),
            Just(CmpOp::UnsignedGt),
            Just(CmpOp::UnsignedGe),
            Just(CmpOp::SignedLt),
            Just(CmpOp::SignedLe),
            Just(CmpOp::SignedGt),
            Just(CmpOp::SignedGe),
        ],
        0u32..3,
        0u32..3,
    )
        .prop_map(|(op, left, right): (CmpOp, u32, u32)| Predicate::Compare {
            op,
            left: Expr::var(left),
            right: Expr::var(right),
        })
        .boxed();
    let nonzero: BoxedStrategy<Predicate> = (0u32..3)
        .prop_map(|index: u32| Predicate::nonzero(Expr::var(index)))
        .boxed();
    prop_oneof![comparison, nonzero].prop_recursive(3, 32, 2, |inner: BoxedStrategy<Predicate>| {
        prop_oneof![
            (inner.clone(), inner.clone())
                .prop_map(|(left, right): (Predicate, Predicate)| Predicate::or(left, right)),
            (inner.clone(), inner)
                .prop_map(|(left, right): (Predicate, Predicate)| Predicate::and(left, right)),
        ]
    })
}

#[test]
fn boolean_minimization_reduces_identities_at_all_target_widths() {
    let a: Expr = variable(0);
    let b: Expr = variable(1);
    let c: Expr = variable(2);
    let cases: Vec<(Expr, Expr)> = vec![
        (
            Expr::or(
                Expr::and(a.clone(), b.clone()),
                Expr::and(a.clone(), Expr::not(b.clone())),
            ),
            a.clone(),
        ),
        (
            Expr::and(
                Expr::or(a.clone(), b.clone()),
                Expr::or(a.clone(), Expr::not(b.clone())),
            ),
            a.clone(),
        ),
        (
            Expr::or(a.clone(), Expr::and(a.clone(), b.clone())),
            a.clone(),
        ),
        (
            Expr::or(
                Expr::or(
                    Expr::and(a.clone(), b.clone()),
                    Expr::and(Expr::not(a.clone()), c.clone()),
                ),
                Expr::and(b, c),
            ),
            Expr::or(
                Expr::and(a.clone(), variable(1)),
                Expr::and(Expr::not(a), variable(2)),
            ),
        ),
    ];

    for width in widths() {
        for (input, expected) in &cases {
            let result: Simplification = simplify(input, width);
            assert!(
                result.changed(),
                "expected `{input}` to reduce at {width:?}"
            );
            assert_eq!(result.simplified, *expected);
            assert_eq!(
                verify_equivalent(input, &result.simplified, width),
                Equivalence::Proven,
                "expected a verifier proof for `{input}` at {width:?}"
            );
        }
    }
}

#[test]
fn nonreducible_boolean_function_stays_unchanged() {
    let input: Expr = Expr::xor(variable(0), variable(1));
    for width in widths() {
        let result: Simplification = simplify(&input, width);
        assert!(!result.changed(), "`{input}` changed at {width:?}");
        assert_eq!(result.simplified, input);
    }
}

#[test]
fn boolean_minimization_is_deterministic() {
    let input: Expr = Expr::or(
        Expr::or(
            Expr::and(variable(0), variable(1)),
            Expr::and(variable(0), Expr::not(variable(1))),
        ),
        Expr::and(variable(1), variable(2)),
    );
    let expected: Simplification = simplify(&input, Width::W64);
    for _ in 0..32 {
        assert_eq!(simplify(&input, Width::W64), expected);
    }
}

#[test]
fn predicate_canonicalization_normalizes_comparisons_at_all_target_widths() {
    let a: Expr = variable(0);
    let b: Expr = variable(1);
    let cases: Vec<(Predicate, Predicate)> = vec![
        (
            Predicate::Compare {
                op: CmpOp::UnsignedGt,
                left: b.clone(),
                right: a.clone(),
            },
            Predicate::Compare {
                op: CmpOp::UnsignedLt,
                left: a.clone(),
                right: b.clone(),
            },
        ),
        (
            Predicate::Compare {
                op: CmpOp::SignedGt,
                left: b.clone(),
                right: a.clone(),
            },
            Predicate::Compare {
                op: CmpOp::SignedLt,
                left: a.clone(),
                right: b.clone(),
            },
        ),
        (
            Predicate::Compare {
                op: CmpOp::UnsignedLe,
                left: b.clone(),
                right: a.clone(),
            },
            Predicate::Compare {
                op: CmpOp::UnsignedGe,
                left: a.clone(),
                right: b.clone(),
            },
        ),
        (
            Predicate::Compare {
                op: CmpOp::Eq,
                left: b.clone(),
                right: a.clone(),
            },
            Predicate::Compare {
                op: CmpOp::Eq,
                left: a,
                right: b,
            },
        ),
        (
            Predicate::Compare {
                op: CmpOp::Ne,
                left: variable(1),
                right: variable(0),
            },
            Predicate::Compare {
                op: CmpOp::Ne,
                left: variable(0),
                right: variable(1),
            },
        ),
    ];

    for width in widths() {
        for (input, expected) in &cases {
            let result: PredicateSimplification = simplify_predicate(input, width);
            assert!(
                result.changed(),
                "expected `{input:?}` to canonicalize at {width:?}"
            );
            assert_eq!(result.simplified, *expected);
            assert_eq!(
                verify_equivalent(input, &result.simplified, width),
                Equivalence::Proven,
                "expected a verifier proof for `{input:?}` at {width:?}"
            );
        }
    }
}

#[test]
fn predicate_canonicalization_normalizes_nonzero_and_preserves_signedness() {
    let input: Predicate = Predicate::nonzero(variable(0));
    for width in widths() {
        let result: PredicateSimplification = simplify_predicate(&input, width);
        assert!(
            result.changed(),
            "expected nonzero to canonicalize at {width:?}"
        );
        assert!(matches!(
            result.simplified,
            Predicate::Compare { op: CmpOp::Ne, .. }
        ));
        assert_eq!(
            verify_equivalent(&input, &result.simplified, width),
            Equivalence::Proven,
            "expected a verifier proof for nonzero at {width:?}"
        );

        let signed: Predicate = Predicate::Compare {
            op: CmpOp::SignedLt,
            left: Expr::konst(width.mask()),
            right: Expr::konst(1),
        };
        let unsigned: Predicate = Predicate::Compare {
            op: CmpOp::UnsignedLt,
            left: Expr::konst(width.mask()),
            right: Expr::konst(1),
        };
        assert!(
            verify_equivalent(&signed, &unsigned, width).is_disproven(),
            "signed and unsigned comparisons unexpectedly converged at {width:?}"
        );
    }
}

#[test]
fn predicate_canonicalization_is_deterministic_across_boolean_chains() {
    let first: Predicate = Predicate::or(
        Predicate::or(
            Predicate::Compare {
                op: CmpOp::UnsignedGt,
                left: variable(1),
                right: variable(0),
            },
            Predicate::nonzero(variable(2)),
        ),
        Predicate::Compare {
            op: CmpOp::Ne,
            left: variable(1),
            right: variable(0),
        },
    );
    let second: Predicate = Predicate::or(
        Predicate::Compare {
            op: CmpOp::UnsignedGt,
            left: variable(1),
            right: variable(0),
        },
        Predicate::or(
            Predicate::nonzero(variable(2)),
            Predicate::Compare {
                op: CmpOp::Ne,
                left: variable(1),
                right: variable(0),
            },
        ),
    );
    for width in widths() {
        let expected: PredicateSimplification = simplify_predicate(&first, width);
        assert!(
            expected.changed(),
            "expected chain normalization at {width:?}"
        );
        let alternate: PredicateSimplification = simplify_predicate(&second, width);
        assert_eq!(alternate.simplified, expected.simplified);
        assert_eq!(alternate.verification, expected.verification);
        for _ in 0..32 {
            assert_eq!(simplify_predicate(&first, width), expected);
        }
        assert_eq!(
            verify_equivalent(&first, &expected.simplified, width),
            Equivalence::Proven,
            "expected a verifier proof for the chain at {width:?}"
        );
    }
}

#[test]
fn predicate_minimization_folds_complementary_comparisons() {
    let less: Predicate = Predicate::Compare {
        op: CmpOp::UnsignedLt,
        left: variable(0),
        right: variable(1),
    };
    let not_less: Predicate = Predicate::Compare {
        op: CmpOp::UnsignedGe,
        left: variable(0),
        right: variable(1),
    };
    let input: Predicate = Predicate::or(less, not_less);
    let expected: Predicate = Predicate::eq(Expr::konst(0), Expr::konst(0));

    for width in widths() {
        let result: PredicateSimplification = simplify_predicate(&input, width);
        assert!(result.changed(), "expected a fold at {width:?}");
        assert_eq!(result.simplified, expected);
        assert_eq!(
            verify_equivalent(&input, &result.simplified, width),
            Equivalence::Proven,
            "expected a verifier proof at {width:?}"
        );
    }
}

#[test]
fn predicate_minimization_folds_contradictory_comparisons() {
    let less: Predicate = Predicate::Compare {
        op: CmpOp::UnsignedLt,
        left: variable(0),
        right: variable(1),
    };
    let not_less: Predicate = Predicate::Compare {
        op: CmpOp::UnsignedGe,
        left: variable(0),
        right: variable(1),
    };
    let input: Predicate = Predicate::and(less, not_less);
    let expected: Predicate = Predicate::eq(Expr::konst(0), Expr::konst(1));

    for width in widths() {
        let result: PredicateSimplification = simplify_predicate(&input, width);
        assert!(result.changed(), "expected a fold at {width:?}");
        assert_eq!(result.simplified, expected);
        assert_eq!(
            verify_equivalent(&input, &result.simplified, width),
            Equivalence::Proven,
            "expected a verifier proof at {width:?}"
        );
    }
}

#[test]
fn predicate_minimization_stops_at_the_atom_cap() {
    let mut input: Predicate = Predicate::eq(Expr::konst(0), variable(0));
    for index in 1..=8 {
        let atom: Predicate = Predicate::eq(Expr::konst(0), variable(index));
        input = Predicate::and(input, atom);
    }
    let result: PredicateSimplification = simplify_predicate(&input, Width::W8);
    assert!(!result.changed(), "over-cap predicate changed");
    assert_eq!(result.simplified, input);
}

#[test]
fn predicate_verifier_honors_node_budget() {
    let input: Predicate = Predicate::eq(variable(0), Expr::konst(0));
    assert_eq!(
        verify_predicate_equivalent_budgeted(&input, &input, Width::W64, 1),
        Equivalence::Unknown
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn every_emitted_boolean_rewrite_is_verifier_proven(input in boolean_expr_strategy()) {
        let result: Simplification = simplify(&input, Width::W32);
        if result.changed() {
            prop_assert_eq!(
                verify_equivalent(&input, &result.simplified, Width::W32),
                Equivalence::Proven
            );
        }
    }

    #[test]
    fn every_emitted_predicate_rewrite_is_verifier_proven(input in predicate_strategy()) {
        let result: PredicateSimplification = simplify_predicate(&input, Width::W32);
        if result.changed() {
            prop_assert_eq!(
                verify_equivalent(&input, &result.simplified, Width::W32),
                Equivalence::Proven
            );
        }
    }
}
