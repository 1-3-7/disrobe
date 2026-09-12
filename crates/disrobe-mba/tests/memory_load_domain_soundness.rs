#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_mba::{Expr, Simplification, Verification, Width, simplify};

type MemoryModel = (&'static str, fn(u64, Width) -> u64);

const MEMORY_MODELS: [MemoryModel; 6] = [
    ("zero", |_address: u64, _load: Width| 0),
    ("ones", |_address: u64, load: Width| load.mask()),
    ("one", |_address: u64, load: Width| 1 & load.mask()),
    ("identity", |address: u64, load: Width| {
        address & load.mask()
    }),
    ("xor_key", |address: u64, load: Width| {
        (address ^ 0x5A) & load.mask()
    }),
    ("mixed", |address: u64, load: Width| {
        address
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .rotate_left(11)
            .wrapping_add(0x1357)
            & load.mask()
    }),
];

fn disagreement(
    original: &Expr,
    candidate: &Expr,
    width: Width,
    var_count: u32,
) -> Option<(&'static str, Vec<u64>, u64, u64)> {
    let domain: u64 = width.mask().wrapping_add(1);
    for (name, model) in MEMORY_MODELS {
        let load: &dyn Fn(u64, Width) -> u64 = &model;
        for index in 0..domain.checked_pow(var_count).unwrap_or(u64::MAX) {
            let mut environment: Vec<u64> = Vec::with_capacity(var_count as usize);
            let mut remaining: u64 = index;
            for _ in 0..var_count {
                environment.push(remaining % domain);
                remaining /= domain;
            }
            let left: u64 = original.eval_with_mem(&environment, load, width);
            let right: u64 = candidate.eval_with_mem(&environment, load, width);
            if left != right {
                return Some((name, environment, left, right));
            }
        }
    }
    None
}

fn assert_memory_faithful(original: &Expr, width: Width, var_count: u32) -> Simplification {
    let result: Simplification = simplify(original, width);
    if !result.changed() {
        assert_eq!(
            result.verification,
            Verification::Unverified,
            "an unchanged expression must not carry a proof: `{original}` at {width:?}"
        );
        return result;
    }
    assert!(
        result.verification.is_proven(),
        "the simplifier changed `{original}` at {width:?} without a proof"
    );
    if let Some((model, environment, left, right)) =
        disagreement(original, &result.simplified, width, var_count)
    {
        panic!(
            "`{original}` -> `{}` at {width:?} is wrong under memory model {model}: env {environment:?} gives {left} vs {right}",
            result.simplified
        );
    }
    result
}

fn load(address: Expr, load_width: Width) -> Expr {
    Expr::mem(address, load_width)
}

fn family(load_width: Width) -> Vec<(&'static str, Expr)> {
    let cell: Expr = load(Expr::var(0), load_width);
    vec![
        ("bare", cell.clone()),
        ("doubled", Expr::add(cell.clone(), cell.clone())),
        (
            "tripled",
            Expr::add(Expr::add(cell.clone(), cell.clone()), cell.clone()),
        ),
        ("masked", Expr::and(cell.clone(), Expr::konst(0xFF))),
        ("xored", Expr::xor(cell.clone(), Expr::konst(0x5A))),
        (
            "scaled_plus_var",
            Expr::add(Expr::mul(Expr::konst(3), cell.clone()), Expr::var(0)),
        ),
        (
            "sum_identity",
            Expr::add(
                Expr::xor(cell.clone(), Expr::var(0)),
                Expr::mul(Expr::konst(2), Expr::and(cell.clone(), Expr::var(0))),
            ),
        ),
        (
            "self_cancelling",
            Expr::add(Expr::xor(cell.clone(), cell.clone()), Expr::var(0)),
        ),
        (
            "boolean_absorption",
            Expr::or(Expr::and(cell.clone(), Expr::var(0)), cell.clone()),
        ),
        ("negated_pair", Expr::add(cell.clone(), Expr::not(cell))),
    ]
}

#[test]
fn memory_loads_are_never_folded_as_though_memory_were_zero() {
    let mut emitted: u32 = 0;
    let mut withheld: u32 = 0;
    for width in [Width::W4, Width::W8, Width::W16] {
        for (name, expr) in family(Width::W8) {
            let result: Simplification = assert_memory_faithful(&expr, width, 1);
            if result.changed() {
                emitted += 1;
            } else {
                withheld += 1;
            }
            eprintln!(
                "{name} at {width:?}: `{expr}` -> `{}` {:?}",
                result.simplified, result.verification
            );
        }
    }
    assert!(
        withheld > 0,
        "the family must contain shapes the stack cannot prove, or the refusal is untested"
    );
    assert!(
        emitted > 0,
        "the family must contain shapes the stack still proves, or the refusal is vacuous"
    );
}

#[test]
fn a_load_alone_is_never_replaced_by_a_constant() {
    let cell: Expr = load(Expr::var(0), Width::W8);
    for width in [Width::W1, Width::W2, Width::W4, Width::W8, Width::W16] {
        let result: Simplification = simplify(&cell, width);
        assert!(
            !result.changed(),
            "`{cell}` at {width:?} was rewritten to `{}`, but a load of unknown memory has no smaller equal form",
            result.simplified
        );
        assert_eq!(result.verification, Verification::Unverified);
    }
}

#[test]
fn arithmetic_over_one_load_still_reduces_at_narrow_widths() {
    let cell: Expr = load(Expr::var(0), Width::W8);
    let doubled: Expr = Expr::add(cell.clone(), cell.clone());
    let cancelling: Expr = Expr::add(Expr::xor(cell.clone(), cell), Expr::var(0));
    for width in [Width::W4, Width::W8, Width::W16] {
        let reduced: Simplification = assert_memory_faithful(&doubled, width, 1);
        assert!(
            reduced.changed() && reduced.verification.is_proven(),
            "`{doubled}` at {width:?} must still reduce, otherwise the guard cost real capability"
        );
        let cleared: Simplification = assert_memory_faithful(&cancelling, width, 1);
        assert_eq!(
            cleared.simplified,
            Expr::var(0),
            "`{cancelling}` at {width:?} must still collapse to the variable"
        );
    }
}

const fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn random_load_bearing_shapes_are_never_rewritten_wrongly() {
    let mut state: u64 = 0x51DE_0BAD_1234_5678;
    let cell: Expr = load(Expr::var(0), Width::W8);
    let atoms: [Expr; 4] = [
        cell.clone(),
        Expr::var(0),
        Expr::not(cell.clone()),
        Expr::and(cell, Expr::var(0)),
    ];
    let mut changed: u32 = 0;
    for width in [Width::W4, Width::W8] {
        for _ in 0..240u32 {
            let mut expr: Expr = atoms[(xorshift(&mut state) % 4) as usize].clone();
            for _ in 0..2 + xorshift(&mut state) % 3 {
                let other: Expr = atoms[(xorshift(&mut state) % 4) as usize].clone();
                expr = match xorshift(&mut state) % 6 {
                    0 => Expr::add(expr, other),
                    1 => Expr::sub(expr, other),
                    2 => Expr::xor(expr, other),
                    3 => Expr::or(expr, other),
                    4 => Expr::and(expr, other),
                    _ => Expr::mul(Expr::konst(xorshift(&mut state) & width.mask()), expr),
                };
            }
            if assert_memory_faithful(&expr, width, 1).changed() {
                changed += 1;
            }
        }
    }
    eprintln!("random load-bearing shapes rewritten: {changed}");
    assert!(
        changed > 0,
        "the random sweep never produced a rewrite, so it checks nothing"
    );
}
