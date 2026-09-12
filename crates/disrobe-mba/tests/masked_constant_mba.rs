#![allow(clippy::verbose_bit_mask)]

use disrobe_mba::{Expr, Simplification, Verification, Width, equivalent_exhaustive, simplify};

const fn var(index: u32) -> Expr {
    Expr::var(index)
}

fn assert_recovers(obfuscated: &Expr, clean: &Expr, var_count: u32) -> Simplification {
    let result: Simplification = simplify(obfuscated, Width::W8);
    assert!(
        result.changed(),
        "expected `{obfuscated}` to simplify, stayed `{}`",
        result.simplified
    );
    assert!(
        result.verification.is_proven(),
        "rewrite of `{obfuscated}` was emitted without a soundness proof"
    );
    assert_eq!(
        result.verification,
        Verification::ExhaustiveAtWidth(Width::W8),
        "8-bit recovery must be proven by the exhaustive checker, got {:?}",
        result.verification
    );
    assert!(
        equivalent_exhaustive(&result.simplified, clean, Width::W8, var_count),
        "recovered `{}` is not equivalent to clean `{clean}`",
        result.simplified
    );
    assert!(
        equivalent_exhaustive(&result.simplified, clean, Width::W16, var_count),
        "recovered `{}` is not equivalent to clean `{clean}` at 16 bits",
        result.simplified
    );
    assert!(
        result.simplified_nodes < result.original_nodes,
        "recovered `{}` ({} nodes) is not simpler than `{obfuscated}` ({} nodes)",
        result.simplified,
        result.simplified_nodes,
        result.original_nodes
    );
    result
}

fn masked_select(mask: u64) -> Expr {
    Expr::or(
        Expr::and(var(0), Expr::konst(mask)),
        Expr::and(Expr::not(var(0)), Expr::konst(!mask)),
    )
}

#[test]
fn ollvm_masked_select_recovers_xnor_with_constant() {
    for mask in [0x00u64, 0xFF, 0x5A, 0xA5, 0x0F, 0xF0, 0x3C, 0x81, 0x7E] {
        let obfuscated: Expr = masked_select(mask);
        let clean: Expr = if (mask & 0xFF) == 0xFF {
            var(0)
        } else if (mask & 0xFF) == 0 {
            Expr::not(var(0))
        } else {
            Expr::xor(var(0), Expr::konst((!mask) & 0xFF))
        };
        let result: Simplification = assert_recovers(&obfuscated, &clean, 1);
        assert!(
            result.simplified_nodes <= 3,
            "select with mask {mask:#x} should collapse to a 1-3 node form, got `{}`",
            result.simplified
        );
    }
}

#[test]
fn arbitrary_mask_and_select_recovers_masked_identity() {
    let obfuscated: Expr = Expr::or(
        Expr::and(var(0), Expr::konst(0x3C)),
        Expr::and(Expr::konst(0), Expr::konst(0xC3)),
    );
    let clean: Expr = Expr::and(var(0), Expr::konst(0x3C));
    let result: Simplification = simplify(&obfuscated, Width::W8);
    assert!(
        equivalent_exhaustive(&result.simplified, &clean, Width::W8, 1),
        "recovered `{}` not equal to x & 0x3C",
        result.simplified
    );
}

#[test]
fn masked_or_with_constant_recovers() {
    let obfuscated: Expr = Expr::or(
        Expr::and(var(0), Expr::konst(0x3C)),
        Expr::or(Expr::konst(0xC3), Expr::and(var(0), Expr::konst(0xC3))),
    );
    let clean: Expr = Expr::or(var(0), Expr::konst(0xC3));
    let result: Simplification = simplify(&obfuscated, Width::W8);
    assert!(
        result.verification.is_proven() || !result.changed(),
        "any emitted rewrite must be proven"
    );
    if result.changed() {
        assert!(
            equivalent_exhaustive(&result.simplified, &clean, Width::W8, 1),
            "recovered `{}` not equal to x | 0xC3",
            result.simplified
        );
    }
}

#[test]
fn double_complement_xor_constant_is_recovered() {
    let obfuscated: Expr = Expr::not(Expr::xor(var(0), Expr::konst(0x5A)));
    let clean: Expr = Expr::xor(var(0), Expr::konst(0xA5));
    assert_recovers(&obfuscated, &clean, 1);
}

#[test]
fn wide_width_masked_select_left_unchanged_without_smt() {
    let obfuscated: Expr = masked_select(0x5A);
    let result: Simplification = simplify(&obfuscated, Width::W64);
    if cfg!(feature = "smt-verify") {
        assert!(result.verification.is_proven() || !result.changed());
    } else {
        assert!(
            !result.changed(),
            "without an SMT oracle a 64-bit masked select must stay unchanged, got `{}`",
            result.simplified
        );
    }
}

#[test]
fn negative_not_a_uniform_select_is_not_rewritten_wrongly() {
    let genuine: Expr = Expr::and(
        Expr::or(var(0), Expr::konst(0x5A)),
        Expr::xor(var(0), Expr::konst(0x3C)),
    );
    let result: Simplification = simplify(&genuine, Width::W8);
    assert!(
        result.verification.is_proven() || !result.changed(),
        "any change must be proven"
    );
    if result.changed() {
        assert!(
            equivalent_exhaustive(&genuine, &result.simplified, Width::W8, 1),
            "rewrite `{}` diverged from the genuine expression",
            result.simplified
        );
    }
}

#[test]
fn negative_near_miss_constant_must_not_collapse_to_clean() {
    let obfuscated: Expr = masked_select(0x5A);
    let wrong_clean: Expr = Expr::xor(var(0), Expr::konst(0x5A));
    let result: Simplification = simplify(&obfuscated, Width::W8);
    assert!(
        !equivalent_exhaustive(&result.simplified, &wrong_clean, Width::W8, 1),
        "recovered `{}` must not equal the wrong-constant form x ^ 0x5A",
        result.simplified
    );
}

fn mixed_blend(id_and_not_mask: u64, one_mask: u64) -> Expr {
    Expr::or(
        Expr::or(
            Expr::and(var(0), Expr::konst(id_and_not_mask)),
            Expr::and(Expr::not(var(0)), Expr::konst(!id_and_not_mask)),
        ),
        Expr::konst(one_mask),
    )
}

#[test]
fn wide_single_var_bitwise_blend_recovers_and_is_proven() {
    if !cfg!(feature = "smt-verify") {
        return;
    }
    let masks: [u64; 8] = [0x5A, 0xA5, 0x0F, 0xF0, 0x3C, 0x81, 0x7E, 0xC3];
    for &keep in &masks {
        for &set in &masks {
            let one_mask: u64 = set & !keep;
            let obfuscated: Expr = mixed_blend(keep, one_mask);
            let result: Simplification = simplify(&obfuscated, Width::W64);
            assert!(
                result.changed(),
                "wide single-var bitwise blend keep={keep:#x} one={one_mask:#x} must reduce, stayed `{}`",
                result.simplified
            );
            assert!(
                result.verification.is_proven(),
                "emitted rewrite of blend keep={keep:#x} must carry a soundness proof, got {:?}",
                result.verification
            );
            assert!(
                result.simplified_nodes < result.original_nodes,
                "recovered `{}` ({} nodes) not simpler than the {}-node blend",
                result.simplified,
                result.simplified_nodes,
                result.original_nodes
            );
            for width in [Width::W4, Width::W8] {
                assert!(
                    equivalent_exhaustive(&obfuscated, &result.simplified, width, 1),
                    "recovered `{}` diverges from the blend at {width:?}",
                    result.simplified
                );
            }
        }
    }
}

#[test]
fn wide_pure_xor_constant_recovers_full_width_not() {
    if !cfg!(feature = "smt-verify") {
        return;
    }
    let obfuscated: Expr = masked_select(0x5A);
    let result: Simplification = simplify(&obfuscated, Width::W64);
    let clean: Expr = Expr::xor(var(0), Expr::konst((!0x5Au64) & Width::W64.mask()));
    assert!(result.changed() && result.verification.is_proven());
    assert_eq!(
        result.simplified, clean,
        "a full-width uniform select must collapse to the two-node xor-constant form, got `{}`",
        result.simplified
    );
}

#[test]
fn wide_blend_never_falsely_collapses_a_data_dependent_form() {
    if !cfg!(feature = "smt-verify") {
        return;
    }
    let genuine: Expr = Expr::and(
        Expr::or(var(0), Expr::konst(0x5A)),
        Expr::xor(var(0), Expr::konst(0x3C)),
    );
    let result: Simplification = simplify(&genuine, Width::W64);
    if result.changed() {
        assert!(result.verification.is_proven());
        for width in [Width::W4, Width::W8] {
            assert!(
                equivalent_exhaustive(&genuine, &result.simplified, width, 1),
                "rewrite `{}` diverged from the genuine form at {width:?}",
                result.simplified
            );
        }
    }
}
