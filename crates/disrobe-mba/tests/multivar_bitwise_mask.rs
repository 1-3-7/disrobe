#![allow(clippy::unwrap_used, clippy::expect_used)]

use disrobe_mba::{
    Expr, MAX_BITWISE_SYNTH_VARS, Simplification, Verification, Width, equivalent_exhaustive,
    simplify, synthesize_bitwise_masked,
};

#[cfg(feature = "smt-verify")]
use disrobe_mba::{Equivalence, verify_equivalent};

const fn v(index: u32) -> Expr {
    Expr::var(index)
}

fn masked(body: Expr, mask: u64) -> Expr {
    Expr::and(body, Expr::konst(mask))
}

fn boolean_fns(var_count: u32) -> Vec<Expr> {
    let x: Expr = v(0);
    let y: Expr = v(1);
    if var_count == 2 {
        return vec![
            Expr::and(x.clone(), y.clone()),
            Expr::or(x.clone(), y.clone()),
            Expr::xor(x.clone(), y.clone()),
            Expr::not(Expr::xor(x.clone(), y.clone())),
            Expr::and(x.clone(), Expr::not(y.clone())),
            Expr::and(Expr::not(x.clone()), y.clone()),
            Expr::not(Expr::or(x.clone(), y.clone())),
            Expr::not(Expr::and(x, y)),
        ];
    }
    let z: Expr = v(2);
    vec![
        Expr::and(Expr::and(x.clone(), y.clone()), z.clone()),
        Expr::or(Expr::or(x.clone(), y.clone()), z.clone()),
        Expr::xor(Expr::xor(x.clone(), y.clone()), z.clone()),
        Expr::or(
            Expr::or(
                Expr::and(x.clone(), y.clone()),
                Expr::and(x.clone(), z.clone()),
            ),
            Expr::and(y.clone(), z.clone()),
        ),
        Expr::and(x.clone(), Expr::not(Expr::or(y.clone(), z.clone()))),
        Expr::xor(x.clone(), Expr::and(y.clone(), z.clone())),
        Expr::or(x.clone(), Expr::xor(y.clone(), z.clone())),
        Expr::not(Expr::and(Expr::and(x, y), z)),
    ]
}

fn assert_narrow_differential(obfuscated: &Expr, synth: &Expr, var_count: u32) {
    for width in [Width::W4, Width::W8] {
        assert!(
            equivalent_exhaustive(obfuscated, synth, width, var_count),
            "exhaustive differential at {width:?} rejects synth `{synth}` for `{obfuscated}`"
        );
    }
}

#[cfg(feature = "smt-verify")]
fn assert_bit_blast_proven(obfuscated: &Expr, synth: &Expr, widths: &[Width]) {
    for &width in widths {
        assert_eq!(
            verify_equivalent(obfuscated, synth, width),
            Equivalence::Proven,
            "bit-blast oracle failed to prove synth `{synth}` == `{obfuscated}` at {width:?}"
        );
    }
}

fn assert_both_oracles(obfuscated: &Expr, synth: &Expr, var_count: u32) {
    assert_narrow_differential(obfuscated, synth, var_count);
    #[cfg(feature = "smt-verify")]
    assert_bit_blast_proven(obfuscated, synth, &[Width::W16, Width::W32, Width::W64]);
}

#[test]
fn two_var_sweep_proven_by_both_oracles() {
    let masks: [u64; 6] = [0x0F, 0xF0, 0x33, 0xCC, 0x5A, 0xA5];
    let library: Vec<Expr> = boolean_fns(2);
    for (a_index, first) in library.iter().enumerate() {
        for second in library.iter().skip(a_index + 1) {
            for &mask in &masks {
                let complement: u64 = (!mask) & 0xFF;
                let obfuscated: Expr = Expr::or(
                    masked(first.clone(), mask),
                    masked(second.clone(), complement),
                );
                let synth: Expr = synthesize_bitwise_masked(&obfuscated, Width::W64, 2)
                    .expect("synthesizer must produce a candidate for a pure bitwise form");
                assert_both_oracles(&obfuscated, &synth, 2);
            }
        }
    }
}

#[test]
fn three_var_sweep_narrow_exhaustive_and_wide_bit_blast() {
    let masks: [u64; 2] = [0x0F, 0x5A];
    let library: Vec<Expr> = boolean_fns(3);
    for (a_index, first) in library.iter().enumerate() {
        for second in library.iter().skip(a_index + 1) {
            for &mask in &masks {
                let complement: u64 = (!mask) & 0xFF;
                let obfuscated: Expr = Expr::or(
                    masked(first.clone(), mask),
                    masked(second.clone(), complement),
                );
                let synth: Expr = synthesize_bitwise_masked(&obfuscated, Width::W16, 3)
                    .expect("three-var pure bitwise form must synthesize");
                assert_narrow_differential(&obfuscated, &synth, 3);
                #[cfg(feature = "smt-verify")]
                assert_bit_blast_proven(&obfuscated, &synth, &[Width::W16]);
            }
        }
    }
}

#[cfg(feature = "smt-verify")]
#[test]
fn three_var_partial_mask_proven_at_full_width_by_bit_blast() {
    let majority: Expr = Expr::or(
        Expr::or(Expr::and(v(0), v(1)), Expr::and(v(0), v(2))),
        Expr::and(v(1), v(2)),
    );
    let parity: Expr = Expr::xor(Expr::xor(v(0), v(1)), v(2));
    let obfuscated: Expr = Expr::or(masked(majority, 0x0F), masked(parity, 0xF0));
    let synth: Expr =
        synthesize_bitwise_masked(&obfuscated, Width::W64, 3).expect("full-width synth");
    assert_narrow_differential(&obfuscated, &synth, 3);
    assert_bit_blast_proven(&obfuscated, &synth, &[Width::W64]);
}

#[test]
fn end_to_end_simplify_collapses_two_var_partial_mask() {
    let obfuscated: Expr = Expr::or(
        Expr::or(
            masked(Expr::and(v(0), v(1)), 0xF0),
            masked(Expr::and(v(0), v(1)), 0xF0),
        ),
        masked(Expr::xor(v(0), v(1)), 0x0F),
    );
    let clean: Expr = Expr::or(
        masked(Expr::and(v(0), v(1)), 0xF0),
        masked(Expr::xor(v(0), v(1)), 0x0F),
    );

    let at_w8: Simplification = simplify(&obfuscated, Width::W8);
    assert!(
        at_w8.changed(),
        "W8 blend must collapse, stayed `{}`",
        at_w8.simplified
    );
    assert_eq!(
        at_w8.verification,
        Verification::ExhaustiveAtWidth(Width::W8)
    );
    assert!(equivalent_exhaustive(
        &at_w8.simplified,
        &clean,
        Width::W8,
        2
    ));
    assert!(at_w8.simplified_nodes < at_w8.original_nodes);

    let at_w64: Simplification = simplify(&obfuscated, Width::W64);
    if cfg!(feature = "smt-verify") {
        assert!(
            at_w64.changed(),
            "W64 blend must collapse under the bit-blast oracle"
        );
        assert!(at_w64.verification.is_proven());
        assert!(at_w64.simplified_nodes < at_w64.original_nodes);
        for width in [Width::W4, Width::W8] {
            assert!(equivalent_exhaustive(
                &obfuscated,
                &at_w64.simplified,
                width,
                2
            ));
        }
    } else {
        assert!(
            !at_w64.changed(),
            "without the bit-blast oracle a wide blend must stay put"
        );
    }
}

#[test]
fn negative_control_data_dependent_form_never_falsely_collapses() {
    let genuine: Expr = Expr::and(
        Expr::or(v(0), Expr::konst(0x5A)),
        Expr::xor(v(1), Expr::konst(0x3C)),
    );
    let synth: Expr =
        synthesize_bitwise_masked(&genuine, Width::W64, 2).expect("pure bitwise form synthesizes");
    assert_both_oracles(&genuine, &synth, 2);

    let result: Simplification = simplify(&genuine, Width::W64);
    if result.changed() {
        assert!(result.verification.is_proven());
        for width in [Width::W4, Width::W8] {
            assert!(
                equivalent_exhaustive(&genuine, &result.simplified, width, 2),
                "rewrite `{}` diverged from the genuine form at {width:?}",
                result.simplified
            );
        }
    }
}

#[test]
fn negative_control_near_miss_constant_must_not_collapse_to_wrong_clean() {
    let obfuscated: Expr = Expr::or(
        masked(Expr::and(v(0), v(1)), 0xF0),
        masked(Expr::xor(v(0), v(1)), 0x0F),
    );
    let wrong_clean: Expr = Expr::or(
        masked(Expr::or(v(0), v(1)), 0xF0),
        masked(Expr::xor(v(0), v(1)), 0x0F),
    );
    let synth: Expr = synthesize_bitwise_masked(&obfuscated, Width::W64, 2).unwrap();
    assert!(
        !equivalent_exhaustive(&synth, &wrong_clean, Width::W8, 2),
        "synth `{synth}` must not equal the wrong-mask form `{wrong_clean}`"
    );
    #[cfg(feature = "smt-verify")]
    assert!(
        !verify_equivalent(&synth, &wrong_clean, Width::W64).is_proven(),
        "bit-blast oracle must distinguish the correct synth from the wrong-mask form"
    );
}

#[test]
fn negative_control_synthesizer_output_never_disproven() {
    let masks: [u64; 4] = [0x0F, 0xF0, 0x3C, 0xC3];
    for &high in &masks {
        for &low in &masks {
            if high & low != 0 {
                continue;
            }
            let obfuscated: Expr = Expr::or(
                masked(Expr::and(v(0), Expr::not(v(1))), high),
                masked(Expr::not(Expr::or(v(0), v(1))), low),
            );
            let Some(synth): Option<Expr> = synthesize_bitwise_masked(&obfuscated, Width::W64, 2)
            else {
                continue;
            };
            assert!(
                equivalent_exhaustive(&obfuscated, &synth, Width::W8, 2),
                "synth `{synth}` disagreed with `{obfuscated}` at W8"
            );
            #[cfg(feature = "smt-verify")]
            assert!(
                !verify_equivalent(&obfuscated, &synth, Width::W64).is_disproven(),
                "synthesizer emitted a form the bit-blast oracle disproves for `{obfuscated}`"
            );
        }
    }
}

#[test]
fn rejects_expressions_outside_the_pure_bitwise_grammar() {
    let arithmetic: Expr = Expr::add(Expr::and(v(0), v(1)), Expr::konst(3));
    assert!(synthesize_bitwise_masked(&arithmetic, Width::W64, 2).is_none());

    let shifted: Expr = Expr::or(masked(Expr::shl(v(0), Expr::konst(1)), 0xF0), v(1));
    assert!(synthesize_bitwise_masked(&shifted, Width::W64, 2).is_none());

    let mut too_many: Expr = v(0);
    for index in 1..=MAX_BITWISE_SYNTH_VARS {
        too_many = Expr::and(too_many, v(index));
    }
    assert!(
        synthesize_bitwise_masked(&too_many, Width::W64, MAX_BITWISE_SYNTH_VARS + 1).is_none(),
        "var count above the budget must be refused"
    );
}
