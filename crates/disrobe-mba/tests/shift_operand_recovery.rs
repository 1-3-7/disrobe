use disrobe_mba::{Expr, Simplification, Width, simplify};

const WIDTHS: [Width; 7] = [
    Width::W1,
    Width::W2,
    Width::W4,
    Width::W8,
    Width::W16,
    Width::W32,
    Width::W64,
];

struct Lcg {
    state: u64,
}

impl Lcg {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }
}

fn probe_vectors(width: Width, arity: usize) -> Vec<Vec<u64>> {
    sampled_vectors(width, arity, 2048)
}

fn sampled_vectors(width: Width, arity: usize, samples: u32) -> Vec<Vec<u64>> {
    let mask: u64 = width.mask();
    let bits: u32 = width.bits();
    let corners: [u64; 8] = [
        0,
        1 & mask,
        2 & mask,
        3 & mask,
        mask,
        mask ^ 1,
        1u64.wrapping_shl(bits - 1) & mask,
        u64::from(bits) & mask,
    ];
    let mut vectors: Vec<Vec<u64>> = Vec::new();
    for first in corners {
        for second in corners {
            let mut row: Vec<u64> = Vec::with_capacity(arity);
            for slot in 0..arity {
                row.push(if slot % 2 == 0 { first } else { second });
            }
            vectors.push(row);
        }
    }
    let mut rng: Lcg = Lcg::new(0x00DE_F1CE_2026_0813 ^ u64::from(bits));
    for _ in 0..samples {
        let row: Vec<u64> = (0..arity).map(|_| rng.next() & mask).collect();
        vectors.push(row);
    }
    vectors
}

fn exhaustive_vectors(width: Width, arity: usize) -> Vec<Vec<u64>> {
    let mask: u64 = width.mask();
    let mut vectors: Vec<Vec<u64>> = vec![Vec::new()];
    for _ in 0..arity {
        let mut grown: Vec<Vec<u64>> = Vec::new();
        for prefix in &vectors {
            for value in 0..=mask {
                let mut row: Vec<u64> = prefix.clone();
                row.push(value);
                grown.push(row);
            }
        }
        vectors = grown;
    }
    vectors
}

fn opaque_or_and_sum(left: &Expr, right: &Expr) -> Expr {
    Expr::add(
        Expr::or(left.clone(), right.clone()),
        Expr::and(left.clone(), right.clone()),
    )
}

fn carry_sum(left: &Expr, right: &Expr) -> Expr {
    Expr::add(
        Expr::xor(left.clone(), right.clone()),
        Expr::mul(Expr::konst(2), Expr::and(left.clone(), right.clone())),
    )
}

fn shifted_product_sum_reference(row: &[u64], width: Width, shift: u64) -> u64 {
    let mask: u64 = width.mask();
    let product: u64 = row[0].wrapping_mul(row[1]) & mask;
    let sum: u64 = product.wrapping_add(row[2]) & mask;
    if shift >= u64::from(width.bits()) {
        0
    } else {
        (sum >> shift) & mask
    }
}

fn grade(name: &str, obfuscated: &Expr, recovered: &Expr, width: Width, vectors: &[Vec<u64>]) {
    for row in vectors {
        let from_input: u64 = obfuscated.eval(row, width);
        let from_recovery: u64 = recovered.eval(row, width);
        assert_eq!(
            from_recovery, from_input,
            "{name} at {width:?}: `{recovered}` returns {from_recovery} where the input returns {from_input} on {row:?}"
        );
    }
}

#[test]
fn an_mba_identity_under_a_constant_shift_is_recovered_at_every_width() {
    let product: Expr = Expr::mul(Expr::var(0), Expr::var(1));
    let obfuscated: Expr = Expr::shr(opaque_or_and_sum(&product, &Expr::var(2)), Expr::konst(1));
    assert_eq!(obfuscated.node_count(), 13);

    for width in WIDTHS {
        let result: Simplification = simplify(&obfuscated, width);
        assert!(
            result.verification.is_proven(),
            "{width:?}: `{}` shipped without a proof",
            result.simplified
        );
        assert!(
            result.simplified_nodes < result.original_nodes,
            "{width:?}: recovery left `{}` at {} nodes",
            result.simplified,
            result.simplified_nodes
        );

        let vectors: Vec<Vec<u64>> = if width.bits() <= 4 {
            exhaustive_vectors(width, 3)
        } else {
            probe_vectors(width, 3)
        };
        for row in &vectors {
            let reference: u64 = shifted_product_sum_reference(row, width, 1);
            assert_eq!(
                obfuscated.eval(row, width),
                reference,
                "{width:?}: the fixture disagrees with the reference on {row:?}"
            );
            assert_eq!(
                result.simplified.eval(row, width),
                reference,
                "{width:?}: `{}` disagrees with the reference on {row:?}",
                result.simplified
            );
        }

        let repeated: Simplification = simplify(&obfuscated, width);
        assert_eq!(
            repeated.simplified, result.simplified,
            "{width:?}: two runs on the same input disagreed"
        );
    }
}

#[test]
fn an_mba_identity_under_a_variable_shift_is_recovered_at_every_width() {
    let product: Expr = Expr::mul(Expr::var(0), Expr::var(1));
    let obfuscated: Expr = Expr::shr(
        opaque_or_and_sum(&product, &Expr::var(2)),
        Expr::add(Expr::var(3), Expr::var(4)),
    );
    assert_eq!(obfuscated.node_count(), 15);

    for width in WIDTHS {
        let result: Simplification = simplify(&obfuscated, width);
        assert!(
            result.verification.is_proven(),
            "{width:?}: `{}` shipped without a proof",
            result.simplified
        );
        assert!(
            result.simplified_nodes < result.original_nodes,
            "{width:?}: recovery left `{}` at {} nodes",
            result.simplified,
            result.simplified_nodes
        );

        let mask: u64 = width.mask();
        for row in probe_vectors(width, 5) {
            let shift: u64 = row[3].wrapping_add(row[4]) & mask;
            let reference: u64 = shifted_product_sum_reference(&row, width, shift);
            assert_eq!(
                obfuscated.eval(&row, width),
                reference,
                "{width:?}: the fixture disagrees with the reference on {row:?}"
            );
            assert_eq!(
                result.simplified.eval(&row, width),
                reference,
                "{width:?}: `{}` disagrees with the reference on {row:?}",
                result.simplified
            );
        }
    }
}

#[test]
fn a_carry_encoded_sum_under_a_shift_is_recovered_over_the_whole_byte() {
    let width: Width = Width::W8;
    let mask: u64 = 0xFF;
    let obfuscated: Expr = Expr::shr(carry_sum(&Expr::var(0), &Expr::var(1)), Expr::konst(1));
    let result: Simplification = simplify(&obfuscated, width);
    assert!(result.verification.is_proven());
    assert!(result.simplified_nodes < result.original_nodes);

    let mut checked: u32 = 0;
    for left in 0..=mask {
        for right in 0..=mask {
            let reference: u64 = (left.wrapping_add(right) & mask) >> 1;
            assert_eq!(
                obfuscated.eval(&[left, right], width),
                reference,
                "the fixture disagrees with the reference at ({left}, {right})"
            );
            assert_eq!(
                result.simplified.eval(&[left, right], width),
                reference,
                "`{}` disagrees with the reference at ({left}, {right})",
                result.simplified
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 65_536, "the sweep did not cover the whole width");
}

#[test]
fn two_shifts_equal_only_after_rewriting_cancel() {
    let width: Width = Width::W8;
    let plain: Expr = Expr::shr(Expr::add(Expr::var(0), Expr::var(1)), Expr::konst(2));
    let obfuscated: Expr = Expr::shr(carry_sum(&Expr::var(0), &Expr::var(1)), Expr::konst(2));
    let difference: Expr = Expr::sub(obfuscated, plain);
    let result: Simplification = simplify(&difference, width);
    assert_eq!(
        result.simplified,
        Expr::konst(0),
        "`{difference}` reduced to `{}` instead of zero",
        result.simplified
    );
    assert!(result.verification.is_proven());
}

#[test]
fn a_constant_shift_amount_at_or_above_the_width_folds_to_zero() {
    let cases: [(Width, u64); 3] = [(Width::W4, 4), (Width::W8, 8), (Width::W16, 16)];
    for (width, bits) in cases {
        for amount in [bits, bits + 1, 255] {
            let expr: Expr = Expr::shr(Expr::add(Expr::var(0), Expr::var(1)), Expr::konst(amount));
            let result: Simplification = simplify(&expr, width);
            assert_eq!(
                result.simplified,
                Expr::konst(0),
                "{width:?}: `{expr}` reduced to `{}` instead of zero",
                result.simplified
            );
            assert!(
                result.verification.is_proven(),
                "{width:?}: the zero fold of `{expr}` shipped unproven"
            );
        }
    }
}

#[test]
fn a_shift_rewrite_never_disagrees_with_the_evaluator_on_random_inputs() {
    let mut rng: Lcg = Lcg::new(0x7E51_0BEE_5417_0001);
    let widths: [Width; 3] = [Width::W4, Width::W8, Width::W32];
    let vectors: Vec<(Width, Vec<Vec<u64>>)> = widths
        .into_iter()
        .map(|width: Width| (width, sampled_vectors(width, 3, 96)))
        .collect();
    let mut fired: u32 = 0;
    for _ in 0..60u32 {
        let inner: Expr = match rng.next() % 3 {
            0 => opaque_or_and_sum(&Expr::mul(Expr::var(0), Expr::var(1)), &Expr::var(2)),
            1 => carry_sum(&Expr::var(0), &Expr::var(1)),
            _ => Expr::add(
                Expr::or(Expr::var(0), Expr::var(1)),
                Expr::and(Expr::var(0), Expr::var(1)),
            ),
        };
        let amount: Expr = match rng.next() % 3 {
            0 => Expr::konst(rng.next() % 9),
            1 => Expr::var(2),
            _ => Expr::add(Expr::var(2), Expr::konst(1)),
        };
        let obfuscated: Expr = Expr::shr(inner, amount);
        for (width, rows) in &vectors {
            let result: Simplification = simplify(&obfuscated, *width);
            if !result.changed() {
                continue;
            }
            fired += 1;
            assert!(result.verification.is_proven());
            grade(
                "random shift rewrite",
                &obfuscated,
                &result.simplified,
                *width,
                rows,
            );
        }
    }
    assert!(fired > 0, "no random shift input produced a rewrite");
}

#[test]
fn an_oversized_and_an_overdeep_shift_chain_stay_typed() {
    let width: Width = Width::W8;
    let mut oversized: Expr = Expr::var(0);
    for _ in 0..60u32 {
        oversized = Expr::shr(oversized, Expr::konst(1));
    }
    let bounded: Simplification = simplify(&oversized, width);
    assert!(
        bounded.verification.is_proven() || !bounded.changed(),
        "an oversized shift chain changed without a proof"
    );
    assert_eq!(
        simplify(&oversized, width).simplified,
        bounded.simplified,
        "an oversized shift chain simplified non-deterministically"
    );

    let mut overdeep: Expr = Expr::var(0);
    for _ in 0..260u32 {
        overdeep = Expr::shr(overdeep, Expr::konst(1));
    }
    let refused: Simplification = simplify(&overdeep, width);
    assert!(
        !refused.changed(),
        "an input past the depth cap must leave the pipeline untouched"
    );
}
