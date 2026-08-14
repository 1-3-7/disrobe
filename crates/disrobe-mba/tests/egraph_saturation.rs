use disrobe_mba::{
    Expr, Simplification, Width, canonicalize, equivalent_exhaustive, simplify, simplify_mixed,
    solve_linear_mba, solve_polynomial_mba,
};

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
        self.state >> 17
    }

    const fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

fn opaque_leaf(rng: &mut Lcg, vars: u32) -> Expr {
    let base: u32 = rng.below(u64::from(vars)) as u32;
    match rng.below(2) {
        0 => Expr::mul(Expr::var(base), Expr::var((base + 1) % vars)),
        _ => Expr::shr(Expr::var(base), Expr::konst(1 + rng.below(2))),
    }
}

fn random_expr(rng: &mut Lcg, depth: u32, vars: u32) -> Expr {
    if depth == 0 || rng.below(100) < 32 {
        return match rng.below(4) {
            0 => Expr::konst(rng.next()),
            1 => opaque_leaf(rng, vars),
            _ => Expr::var(rng.below(u64::from(vars)) as u32),
        };
    }
    match rng.below(10) {
        0 => Expr::add(
            random_expr(rng, depth - 1, vars),
            random_expr(rng, depth - 1, vars),
        ),
        1 => Expr::sub(
            random_expr(rng, depth - 1, vars),
            random_expr(rng, depth - 1, vars),
        ),
        2 => Expr::and(
            random_expr(rng, depth - 1, vars),
            random_expr(rng, depth - 1, vars),
        ),
        3 => Expr::or(
            random_expr(rng, depth - 1, vars),
            random_expr(rng, depth - 1, vars),
        ),
        4 => Expr::xor(
            random_expr(rng, depth - 1, vars),
            random_expr(rng, depth - 1, vars),
        ),
        5 => Expr::not(random_expr(rng, depth - 1, vars)),
        6 => Expr::neg(random_expr(rng, depth - 1, vars)),
        7 => Expr::shr(
            random_expr(rng, depth - 1, vars),
            Expr::konst(rng.below(10)),
        ),
        8 => Expr::shr(
            random_expr(rng, depth - 1, vars),
            Expr::var(rng.below(u64::from(vars)) as u32),
        ),
        _ => Expr::mul(Expr::konst(rng.next()), random_expr(rng, depth - 1, vars)),
    }
}

#[test]
fn whole_simplifier_never_produces_non_equivalent_output() {
    let mut rng: Lcg = Lcg::new(0x0BAD_F00D_1357_2468);
    let mut changed: u32 = 0;
    for _ in 0..1500 {
        let vars: u32 = 1 + rng.below(3) as u32;
        let depth: u32 = 2 + rng.below(3) as u32;
        let expr: Expr = random_expr(&mut rng, depth, vars);
        for width in [Width::W4, Width::W8] {
            if width == Width::W8 && vars > 2 {
                continue;
            }
            let result: Simplification = simplify(&expr, width);
            if result.changed() {
                changed += 1;
                assert!(
                    result.verification.is_proven(),
                    "changed output at {width:?} for `{expr}` is unproven"
                );
                assert!(
                    equivalent_exhaustive(&expr, &result.simplified, width, vars),
                    "non-equivalent rewrite at {width:?}: `{expr}` -> `{}`",
                    result.simplified
                );
            }
            let again: Simplification = simplify(&expr, width);
            assert_eq!(
                result.simplified, again.simplified,
                "non-deterministic simplification"
            );
        }
    }
    assert!(
        changed > 0,
        "expected the simplifier to fire on some inputs"
    );
}

#[test]
fn l5_collapses_opaque_leaf_identity_that_pre_l5_layers_miss() {
    let width: Width = Width::W8;
    let opaque: Expr = Expr::mul(Expr::var(0), Expr::var(1));
    let other: Expr = Expr::var(2);
    let obfuscated: Expr = Expr::add(
        Expr::or(opaque.clone(), other.clone()),
        Expr::and(opaque.clone(), other.clone()),
    );

    assert_eq!(
        canonicalize(&obfuscated, width).node_count(),
        obfuscated.node_count(),
        "canonicalize alone must not shrink this input"
    );
    assert!(
        solve_linear_mba(&obfuscated, width, 3).is_none(),
        "the linear solver must not fire on an opaque-leaf identity"
    );
    assert!(
        solve_polynomial_mba(&obfuscated, width, 3).is_none(),
        "the polynomial reducer must not fire on an opaque-leaf identity"
    );
    assert!(
        simplify_mixed(&obfuscated, width).is_none(),
        "the mixed reducer must not fire on an opaque-leaf identity"
    );

    let result: Simplification = simplify(&obfuscated, width);
    assert!(
        result.changed(),
        "L5 must reduce (a|b)+(a&b) with an opaque leaf"
    );
    assert!(result.verification.is_proven());
    assert!(result.simplified.node_count() < obfuscated.node_count());
    let expected: Expr = Expr::add(opaque, other);
    assert!(
        equivalent_exhaustive(&result.simplified, &expected, width, 3),
        "expected v0*v1 + v2, got `{}`",
        result.simplified
    );
}

#[test]
fn only_saturation_closes_the_carry_identity_over_a_memory_load() {
    let cell: Expr = Expr::mem(Expr::var(0), Width::W8);
    let obfuscated: Expr = Expr::add(
        Expr::xor(cell.clone(), Expr::var(0)),
        Expr::mul(Expr::konst(2), Expr::and(cell.clone(), Expr::var(0))),
    );
    let recovered: Expr = Expr::add(Expr::var(0), cell);

    for width in [Width::W4, Width::W8, Width::W16] {
        assert_eq!(
            canonicalize(&obfuscated, width).node_count(),
            obfuscated.node_count(),
            "{width:?}: canonicalization alone must not shrink this input"
        );
        assert!(
            solve_linear_mba(&obfuscated, width, 1).is_none(),
            "{width:?}: the linear solver must not fire over a load"
        );
        assert!(
            solve_polynomial_mba(&obfuscated, width, 1).is_none(),
            "{width:?}: the polynomial reducer must not fire over a load"
        );
        assert!(
            simplify_mixed(&obfuscated, width).is_none(),
            "{width:?}: the mixed reducer must not fire over a load"
        );

        let result: Simplification = simplify(&obfuscated, width);
        assert!(
            result.changed(),
            "{width:?}: equality saturation is the only layer left for `{obfuscated}`, and it did not fire"
        );
        assert!(result.verification.is_proven());
        assert_eq!(
            result.simplified, recovered,
            "{width:?}: expected the carry identity to collapse to v0 + the load"
        );
        for probe in 0..=width.mask() {
            let load = |_address: u64, load_width: Width| -> u64 {
                probe.wrapping_mul(0x9E37_79B9).rotate_left(7) & load_width.mask()
            };
            assert_eq!(
                obfuscated.eval_with_mem(&[probe], &load, width),
                result.simplified.eval_with_mem(&[probe], &load, width),
                "{width:?}: the rewrite disagrees with the input at v0 = {probe}"
            );
        }
    }
}
