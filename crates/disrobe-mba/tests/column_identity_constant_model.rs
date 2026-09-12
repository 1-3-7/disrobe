#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_mba::{
    Expr, Simplification, Verification, Width, is_column_faithful, simplify, truth_column,
};

const fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn reference_environments(width: Width, var_count: u32) -> Vec<Vec<u64>> {
    let mask: u64 = width.mask();
    let high: u64 = 1u64 << (width.bits() - 1);
    let corners: [u64; 7] = [
        0,
        1,
        mask,
        mask ^ 1,
        high,
        high.wrapping_sub(1) & mask,
        0x5555_5555_5555_5555 & mask,
    ];
    let mut environments: Vec<Vec<u64>> = Vec::new();
    for value in corners {
        environments.push(vec![value; var_count as usize]);
    }
    for left in corners {
        for right in corners {
            let mut environment: Vec<u64> = vec![left; var_count as usize];
            if let Some(slot) = environment.last_mut() {
                *slot = right;
            }
            environments.push(environment);
        }
    }
    let mut state: u64 = 0xFEED_FACE_0BAD_0007 ^ u64::from(width.bits());
    for _ in 0..512 {
        environments.push(
            (0..var_count)
                .map(|_| xorshift(&mut state) & mask)
                .collect(),
        );
    }
    environments
}

fn disagreement(
    original: &Expr,
    candidate: &Expr,
    width: Width,
    var_count: u32,
) -> Option<(Vec<u64>, u64, u64)> {
    reference_environments(width, var_count)
        .into_iter()
        .find_map(|environment: Vec<u64>| {
            let left: u64 = original.eval(&environment, width);
            let right: u64 = candidate.eval(&environment, width);
            (left != right).then_some((environment, left, right))
        })
}

#[cfg(feature = "smt-verify")]
fn bdd_counterexample(original: &Expr, candidate: &Expr, width: Width) -> Option<Vec<u64>> {
    use disrobe_mba::{Equivalence, verify_equivalent_budgeted};
    match verify_equivalent_budgeted(original, candidate, width, 1usize << 17) {
        Equivalence::Disproven { counterexample } => Some(counterexample),
        Equivalence::Proven | Equivalence::Unknown => None,
    }
}

#[cfg(not(feature = "smt-verify"))]
const fn bdd_counterexample(
    _original: &Expr,
    _candidate: &Expr,
    _width: Width,
) -> Option<Vec<u64>> {
    None
}

fn assert_rewrite_is_equivalent(original: &Expr, width: Width, var_count: u32) -> Simplification {
    let result: Simplification = simplify(original, width);
    if !result.changed() {
        return result;
    }
    assert!(
        result.verification.is_proven(),
        "`{original}` at {width:?} was rewritten without a proof"
    );
    if let Some((environment, left, right)) =
        disagreement(original, &result.simplified, width, var_count)
    {
        panic!(
            "`{original}` -> `{}` at {width:?} disagrees at env {environment:?}: {left} vs {right}",
            result.simplified
        );
    }
    if let Some(counterexample) = bdd_counterexample(original, &result.simplified, width) {
        panic!(
            "`{original}` -> `{}` at {width:?} was disproved by bit-blasting at {counterexample:?}",
            result.simplified
        );
    }
    result
}

fn all_ones_shapes(width: Width) -> Vec<(&'static str, Expr, u32)> {
    let mask: Expr = Expr::konst(width.mask());
    let x: Expr = Expr::var(0);
    let y: Expr = Expr::var(1);
    let z: Expr = Expr::var(2);
    vec![
        (
            "negated_all_ones_minus_complement",
            Expr::sub(
                Expr::neg(mask.clone()),
                Expr::not(Expr::xor(x.clone(), y.clone())),
            ),
            2,
        ),
        (
            "all_ones_as_a_trailing_term",
            Expr::sub(
                Expr::add(
                    Expr::neg(Expr::not(y.clone())),
                    Expr::mul(Expr::konst(4), Expr::xor(x.clone(), y.clone())),
                ),
                mask.clone(),
            ),
            2,
        ),
        (
            "complemented_all_ones_under_a_shift",
            Expr::add(
                Expr::sub(
                    Expr::neg(Expr::xor(x.clone(), y.clone())),
                    Expr::shl(Expr::not(Expr::konst(0)), Expr::konst(2)),
                ),
                Expr::shl(Expr::not(mask.clone()), Expr::konst(1)),
            ),
            2,
        ),
        (
            "complemented_all_ones_under_a_coefficient",
            Expr::add(
                Expr::sub(
                    Expr::mul(Expr::konst(2), Expr::not(mask.clone())),
                    Expr::shl(y.clone(), Expr::konst(2)),
                ),
                Expr::mul(Expr::konst(27608), x.clone()),
            ),
            2,
        ),
        (
            "unit_scaled_all_ones",
            Expr::add(
                Expr::sub(
                    Expr::mul(Expr::konst(82), z.clone()),
                    Expr::neg(Expr::not(Expr::xor(x.clone(), y.clone()))),
                ),
                Expr::mul(Expr::konst(1), mask.clone()),
            ),
            3,
        ),
        (
            "all_ones_beside_a_masked_complement",
            Expr::add(
                Expr::sub(
                    Expr::sub(Expr::not(Expr::konst(0)), Expr::not(z)),
                    Expr::neg(Expr::and(Expr::not(x.clone()), mask)),
                ),
                Expr::mul(Expr::konst(6), Expr::or(x, y)),
            ),
            3,
        ),
    ]
}

#[test]
fn all_ones_constants_are_outside_the_column_proof() {
    for width in [Width::W8, Width::W16, Width::W32] {
        for (name, expr, var_count) in all_ones_shapes(width) {
            assert!(
                !is_column_faithful(&expr, width),
                "{name} at {width:?} carries a raw all-ones constant, which the truth column does not model, so it must not be column faithful"
            );
            let result: Simplification = assert_rewrite_is_equivalent(&expr, width, var_count);
            assert_ne!(
                result.verification,
                Verification::LinearColumnIdentity(width),
                "{name} at {width:?} must not be proven by the column identity"
            );
            eprintln!(
                "{name} at {width:?}: `{expr}` -> `{}` {:?}",
                result.simplified, result.verification
            );
        }
    }
}

#[test]
fn the_column_proof_still_carries_boolean_atom_rewrites() {
    let x: Expr = Expr::var(0);
    let y: Expr = Expr::var(1);
    let xor_carry: Expr = Expr::add(
        Expr::xor(x.clone(), y.clone()),
        Expr::mul(Expr::konst(2), Expr::and(x.clone(), y.clone())),
    );
    let four_var: Expr = Expr::add(
        Expr::add(Expr::or(x.clone(), y.clone()), Expr::and(x, y)),
        Expr::add(
            Expr::or(Expr::var(2), Expr::var(3)),
            Expr::and(Expr::var(2), Expr::var(3)),
        ),
    );
    let mut proven: u32 = 0;
    for (expr, var_count) in [(xor_carry, 2u32), (four_var, 4)] {
        for width in [Width::W16, Width::W32, Width::W64] {
            assert!(
                is_column_faithful(&expr, width),
                "`{expr}` at {width:?} is a boolean-atom linear MBA and must stay column faithful"
            );
            let result: Simplification = assert_rewrite_is_equivalent(&expr, width, var_count);
            assert!(result.changed(), "`{expr}` at {width:?} must still reduce");
            if result.verification == Verification::LinearColumnIdentity(width) {
                proven += 1;
            }
        }
    }
    assert!(
        proven >= 4,
        "the column identity must still carry these rewrites, otherwise the tightened predicate is vacuous (carried {proven})"
    );
}

fn column_reconstruction(column: &[i128], environment: &[u64], width: Width) -> i128 {
    let modulus: i128 = width.modulus() as i128;
    let mut total: i128 = 0;
    for bit in (0..width.bits()).rev() {
        let mut row: usize = 0;
        for (index, value) in environment.iter().enumerate() {
            row |= (((*value >> bit) & 1) as usize) << index;
        }
        let entry: i128 = column.get(row).copied().unwrap_or_default();
        total = (total * 2 + entry.rem_euclid(modulus)).rem_euclid(modulus);
    }
    total
}

fn column_reconstruction_holds(expr: &Expr, width: Width, var_count: u32) -> bool {
    let rows: usize = 1usize << var_count;
    let column: Vec<i128> = truth_column(expr, var_count, rows);
    let modulus: i128 = width.modulus() as i128;
    reference_environments(width, var_count)
        .into_iter()
        .all(|environment: Vec<u64>| {
            let value: i128 = i128::from(expr.eval(&environment, width));
            column_reconstruction(&column, &environment, width) == value.rem_euclid(modulus)
        })
}

#[test]
fn the_truth_column_reproduces_evaluation_exactly_on_admitted_shapes() {
    let x: Expr = Expr::var(0);
    let y: Expr = Expr::var(1);
    let admitted: [Expr; 6] = [
        Expr::add(x.clone(), y.clone()),
        Expr::sub(
            Expr::or(x.clone(), y.clone()),
            Expr::and(x.clone(), y.clone()),
        ),
        Expr::mul(Expr::konst(3), Expr::not(Expr::xor(x.clone(), y.clone()))),
        Expr::neg(Expr::and(Expr::not(x), y.clone())),
        Expr::shl(Expr::not(Expr::konst(0)), Expr::konst(1)),
        Expr::add(Expr::konst(0), Expr::not(y)),
    ];
    for width in [Width::W8, Width::W16, Width::W32, Width::W64] {
        for expr in &admitted {
            assert!(is_column_faithful(expr, width), "`{expr}` must be admitted");
            assert!(
                column_reconstruction_holds(expr, width, 2),
                "`{expr}` at {width:?} is admitted, so its truth column must reproduce its value at every input"
            );
        }
        let mut broken: u32 = 0;
        for (name, expr, var_count) in all_ones_shapes(width) {
            if !column_reconstruction_holds(&expr, width, var_count) {
                broken += 1;
                eprintln!("{name} at {width:?}: the truth column does not reproduce its value");
            }
        }
        assert!(
            broken > 0,
            "at {width:?} no all-ones shape broke the column model, so the tightened predicate guards nothing"
        );
    }
}
