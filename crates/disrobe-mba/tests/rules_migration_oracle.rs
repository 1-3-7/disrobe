#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_mba::rules::{RuleHit, RuleSet, apply_root, mba_peephole_rules, rewrite_fixpoint};
use disrobe_mba::{
    Expr, Width, canonicalize, equivalent_exhaustive, equivalent_exhaustive_runnable,
};

const FIXPOINT_PASSES: u32 = 64;

fn rules() -> RuleSet {
    mba_peephole_rules().expect("shipped mba peephole rules must load and validate")
}

fn assert_dsl_matches_hardcoded(input: &Expr, width: Width, var_count: u32) {
    let set: RuleSet = rules();
    let dsl: Expr = rewrite_fixpoint(&set, input, width, FIXPOINT_PASSES);
    let hardcoded: Expr = canonicalize(input, width);
    assert_eq!(
        dsl, hardcoded,
        "dsl output `{dsl}` differs from hard-coded canonicalize `{hardcoded}` for input `{input}`"
    );
    assert!(
        equivalent_exhaustive(input, &dsl, width, var_count),
        "dsl rewrite changed semantics for input `{input}` -> `{dsl}`"
    );
}

#[test]
fn add_zero_identity_matches_hardcoded() {
    let input: Expr = Expr::add(Expr::var(0), Expr::konst(0));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn add_zero_identity_commutative_left_const_matches_hardcoded() {
    let input: Expr = Expr::add(Expr::konst(0), Expr::var(0));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn sub_zero_identity_matches_hardcoded() {
    let input: Expr = Expr::sub(Expr::var(0), Expr::konst(0));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn mul_one_identity_matches_hardcoded() {
    let input: Expr = Expr::mul(Expr::var(0), Expr::konst(1));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn double_negation_matches_hardcoded() {
    let input: Expr = Expr::neg(Expr::neg(Expr::var(0)));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn negated_not_matches_hardcoded() {
    let input: Expr = Expr::neg(Expr::not(Expr::var(0)));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn not_negated_matches_hardcoded() {
    let input: Expr = Expr::not(Expr::neg(Expr::var(0)));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn add_negated_operand_matches_hardcoded() {
    let input: Expr = Expr::add(Expr::var(0), Expr::neg(Expr::var(1)));
    assert_dsl_matches_hardcoded(&input, Width::W8, 2);
}

#[test]
fn sub_negated_operand_matches_hardcoded() {
    let input: Expr = Expr::sub(Expr::var(0), Expr::neg(Expr::var(1)));
    assert_dsl_matches_hardcoded(&input, Width::W8, 2);
}

#[test]
fn mul_zero_annihilates_matches_hardcoded() {
    let input: Expr = Expr::mul(Expr::var(0), Expr::konst(0));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn sub_self_is_zero_matches_hardcoded() {
    let input: Expr = Expr::sub(Expr::var(0), Expr::var(0));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn xor_self_is_zero_matches_hardcoded() {
    let input: Expr = Expr::xor(Expr::var(0), Expr::var(0));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn xor_all_ones_is_not_matches_hardcoded() {
    let input: Expr = Expr::xor(Expr::var(0), Expr::konst(0xFF));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn xor_all_ones_is_not_w16_matches_hardcoded() {
    let input: Expr = Expr::xor(Expr::var(0), Expr::konst(0xFFFF));
    assert_dsl_matches_hardcoded(&input, Width::W16, 1);
}

#[test]
fn double_not_cancels_matches_hardcoded() {
    let input: Expr = Expr::not(Expr::not(Expr::var(0)));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn nested_subtree_double_not_matches_hardcoded() {
    let inner: Expr = Expr::xor(Expr::var(0), Expr::var(1));
    let input: Expr = Expr::not(Expr::not(inner));
    assert_dsl_matches_hardcoded(&input, Width::W8, 2);
}

#[test]
fn add_zero_nested_under_mul_zero_matches_hardcoded() {
    let lhs: Expr = Expr::add(Expr::var(0), Expr::konst(0));
    let input: Expr = Expr::mul(lhs, Expr::konst(0));
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn xor_all_ones_then_double_not_chain_matches_hardcoded() {
    let masked: Expr = Expr::xor(Expr::var(0), Expr::konst(0xFF));
    let input: Expr = Expr::not(masked);
    assert_dsl_matches_hardcoded(&input, Width::W8, 1);
}

#[test]
fn unrelated_expression_is_left_untouched() {
    let set: RuleSet = rules();
    let input: Expr = Expr::and(Expr::var(0), Expr::var(1));
    let dsl: Expr = rewrite_fixpoint(&set, &input, Width::W8, FIXPOINT_PASSES);
    assert_eq!(dsl, input);
}

#[test]
fn apply_root_reports_which_rule_fired() {
    let set: RuleSet = rules();
    let input: Expr = Expr::xor(Expr::var(0), Expr::konst(0xFF));
    let hit: RuleHit = apply_root(&set, &input, Width::W8).expect("xor all-ones must hit a rule");
    assert_eq!(hit.rule, "xor_all_ones_is_not");
    assert_eq!(hit.result, Expr::not(Expr::var(0)));
}

#[test]
fn add_zero_no_match_when_const_is_nonzero() {
    let set: RuleSet = rules();
    let input: Expr = Expr::add(Expr::var(0), Expr::konst(3));
    assert!(apply_root(&set, &input, Width::W8).is_none());
}

#[test]
fn add_const_sweep_fires_only_on_zero_and_matches_hardcoded_identity() {
    let set: RuleSet = rules();
    for value in 0u64..=255 {
        let input: Expr = Expr::add(Expr::var(0), Expr::konst(value));
        let hit: Option<RuleHit> = apply_root(&set, &input, Width::W8);
        if value == 0 {
            let hit: RuleHit = hit.expect("add_zero must fire for const 0");
            assert_eq!(hit.rule, "add_zero_identity");
            assert_eq!(hit.result, canonicalize(&input, Width::W8));
            assert_eq!(hit.result, Expr::var(0));
            assert!(equivalent_exhaustive(&input, &hit.result, Width::W8, 1));
        } else {
            assert!(
                hit.is_none(),
                "no migrated rule should fire for add(v0, {value})"
            );
        }
    }
}

#[test]
fn xor_const_sweep_fires_only_on_zero_or_all_ones_and_matches_hardcoded_identity() {
    let set: RuleSet = rules();
    for value in 0u64..=255 {
        let input: Expr = Expr::xor(Expr::var(0), Expr::konst(value));
        let hit: Option<RuleHit> = apply_root(&set, &input, Width::W8);
        if value == 0 {
            let hit: RuleHit = hit.expect("xor_zero must fire for const 0");
            assert_eq!(hit.rule, "xor_zero_identity");
            assert_eq!(hit.result, canonicalize(&input, Width::W8));
            assert_eq!(hit.result, Expr::var(0));
            assert!(equivalent_exhaustive(&input, &hit.result, Width::W8, 1));
        } else if value == 0xFF {
            let hit: RuleHit = hit.expect("xor_all_ones must fire for const 0xFF");
            assert_eq!(hit.rule, "xor_all_ones_is_not");
            assert_eq!(hit.result, canonicalize(&input, Width::W8));
            assert_eq!(hit.result, Expr::not(Expr::var(0)));
            assert!(equivalent_exhaustive(&input, &hit.result, Width::W8, 1));
        } else {
            assert!(
                hit.is_none(),
                "no migrated rule should fire for xor(v0, {value})"
            );
        }
    }
}

#[test]
fn shift_identities_match_hardcoded_at_every_declared_width() {
    let widths: [Width; 7] = [
        Width::W1,
        Width::W2,
        Width::W4,
        Width::W8,
        Width::W16,
        Width::W32,
        Width::W64,
    ];
    let set: RuleSet = rules();
    for width in widths {
        for input in [
            Expr::shl(Expr::var(0), Expr::konst(0)),
            Expr::shr(Expr::var(0), Expr::konst(0)),
            Expr::shl(Expr::konst(0), Expr::var(0)),
            Expr::shr(Expr::konst(0), Expr::var(0)),
        ] {
            let dsl: Expr = rewrite_fixpoint(&set, &input, width, FIXPOINT_PASSES);
            assert_eq!(dsl, canonicalize(&input, width));
            if equivalent_exhaustive_runnable(width, 1) {
                assert!(equivalent_exhaustive(&input, &dsl, width, 1));
            }
        }
    }
}

#[test]
fn left_shift_at_its_width_matches_hardcoded_at_every_supported_width() {
    let widths: [Width; 7] = [
        Width::W1,
        Width::W2,
        Width::W4,
        Width::W8,
        Width::W16,
        Width::W32,
        Width::W64,
    ];
    let set: RuleSet = rules();
    for width in widths {
        let input: Expr = Expr::shl(Expr::var(0), Expr::konst(u64::from(width.bits())));
        let dsl: Expr = rewrite_fixpoint(&set, &input, width, FIXPOINT_PASSES);
        assert_eq!(dsl, canonicalize(&input, width));
        if equivalent_exhaustive_runnable(width, 1) {
            assert!(equivalent_exhaustive(&input, &dsl, width, 1));
        }
    }
}

#[test]
fn constant_ite_matches_hardcoded_at_every_supported_width() {
    let widths: [Width; 7] = [
        Width::W1,
        Width::W2,
        Width::W4,
        Width::W8,
        Width::W16,
        Width::W32,
        Width::W64,
    ];
    let set: RuleSet = rules();
    for width in widths {
        for input in [
            Expr::ite(Expr::konst(0), Expr::var(0), Expr::var(1)),
            Expr::ite(Expr::konst(1), Expr::var(0), Expr::var(1)),
            Expr::ite(Expr::konst(2), Expr::var(0), Expr::var(1)),
        ] {
            let dsl: Expr = rewrite_fixpoint(&set, &input, width, FIXPOINT_PASSES);
            assert_eq!(dsl, canonicalize(&input, width));
            if equivalent_exhaustive_runnable(width, 2) {
                assert!(equivalent_exhaustive(&input, &dsl, width, 2));
            }
        }
    }
}

#[test]
fn constant_slice_bits_match_hardcoded_at_every_supported_width() {
    let widths: [Width; 7] = [
        Width::W1,
        Width::W2,
        Width::W4,
        Width::W8,
        Width::W16,
        Width::W32,
        Width::W64,
    ];
    let set: RuleSet = rules();
    for width in widths {
        let low_bit: Expr = Expr::slice(Expr::konst(0xA5A5_A5A5_A5A5_A5A5), 0, 1);
        let dsl: Expr = rewrite_fixpoint(&set, &low_bit, width, FIXPOINT_PASSES);
        assert_eq!(dsl, canonicalize(&low_bit, width));
        if equivalent_exhaustive_runnable(width, 0) {
            assert!(equivalent_exhaustive(&low_bit, &dsl, width, 0));
        }
        if width != Width::W1 {
            let next_bit: Expr = Expr::slice(Expr::konst(0xA5A5_A5A5_A5A5_A5A5), 1, 2);
            let dsl: Expr = rewrite_fixpoint(&set, &next_bit, width, FIXPOINT_PASSES);
            assert_eq!(dsl, canonicalize(&next_bit, width));
            if equivalent_exhaustive_runnable(width, 0) {
                assert!(equivalent_exhaustive(&next_bit, &dsl, width, 0));
            }
        }
    }
}

#[test]
fn constant_compose_layouts_match_hardcoded_at_every_supported_width() {
    let widths: [Width; 7] = [
        Width::W1,
        Width::W2,
        Width::W4,
        Width::W8,
        Width::W16,
        Width::W32,
        Width::W64,
    ];
    let set: RuleSet = rules();
    for width in widths {
        for input in [
            Expr::compose(
                Expr::konst(0xA5A5_A5A5_A5A5_A5A5),
                Expr::konst(0x5A5A_5A5A_5A5A_5A5A),
                1,
            ),
            Expr::compose(
                Expr::konst(0xA5A5_A5A5_A5A5_A5A5),
                Expr::konst(0x5A5A_5A5A_5A5A_5A5A),
                8,
            ),
        ] {
            let dsl: Expr = rewrite_fixpoint(&set, &input, width, FIXPOINT_PASSES);
            assert_eq!(dsl, canonicalize(&input, width));
            if equivalent_exhaustive_runnable(width, 0) {
                assert!(equivalent_exhaustive(&input, &dsl, width, 0));
            }
        }
    }
}
