#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_mba::{Expr, Simplification, Verification, Width, equivalent_exhaustive, simplify};

#[derive(Debug)]
struct Lcg {
    state: u64,
}

impl Lcg {
    const fn new(seed: u64) -> Self {
        Self {
            state: seed
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(0x1234_5678_9ABC_DEF1),
        }
    }

    const fn step(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.state >> 33) ^ (self.state >> 11)
    }

    const fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 { 0 } else { self.step() % bound }
    }
}

fn atom_pool(var_count: u32) -> Vec<Expr> {
    let mut pool: Vec<Expr> = Vec::new();
    for index in 0..var_count {
        pool.push(Expr::var(index));
        pool.push(Expr::not(Expr::var(index)));
    }
    for left in 0..var_count {
        for right in (left + 1)..var_count {
            pool.push(Expr::and(Expr::var(left), Expr::var(right)));
            pool.push(Expr::or(Expr::var(left), Expr::var(right)));
            pool.push(Expr::xor(Expr::var(left), Expr::var(right)));
        }
    }
    pool
}

fn pick<'pool>(rng: &mut Lcg, pool: &'pool [Expr]) -> &'pool Expr {
    let index: usize = rng.below(pool.len() as u64) as usize;
    &pool[index]
}

fn scaled(coeff: u64, base: Expr) -> Expr {
    match coeff {
        0 => Expr::konst(0),
        1 => base,
        other => Expr::mul(Expr::konst(other), base),
    }
}

fn random_monomial(rng: &mut Lcg, pool: &[Expr], modulus: u64) -> Expr {
    let coeff: u64 = rng.below(modulus);
    let degree: u64 = 1 + rng.below(2);
    let mut product: Expr = pick(rng, pool).clone();
    for _ in 1..degree {
        product = Expr::mul(product, pick(rng, pool).clone());
    }
    scaled(coeff, product)
}

fn combine(rng: &mut Lcg, accumulator: Expr, term: Expr) -> Expr {
    if rng.below(2) == 0 {
        Expr::sub(accumulator, term)
    } else {
        Expr::add(accumulator, term)
    }
}

fn null_term(rng: &mut Lcg, pool: &[Expr], width: Width) -> Expr {
    let half: u64 = 1u64 << (width.bits() - 1);
    let atom: Expr = pick(rng, pool).clone();
    let predecessor: Expr = Expr::add(atom.clone(), Expr::konst(width.mask()));
    Expr::mul(Expr::konst(half), Expr::mul(atom, predecessor))
}

fn generate(seed: u64, var_count: u32, width: Width, inject_null: bool) -> Expr {
    let modulus: u64 = width.mask().wrapping_add(1).max(1);
    let pool: Vec<Expr> = atom_pool(var_count);
    let mut rng: Lcg = Lcg::new(seed);
    let count: u64 = 1 + rng.below(3);
    let mut accumulator: Expr = random_monomial(&mut rng, &pool, modulus);
    for _ in 1..count {
        let term: Expr = random_monomial(&mut rng, &pool, modulus);
        accumulator = combine(&mut rng, accumulator, term);
    }
    let genuine: Expr = Expr::mul(pick(&mut rng, &pool).clone(), pick(&mut rng, &pool).clone());
    accumulator = Expr::add(accumulator, genuine);
    if inject_null {
        let null: Expr = null_term(&mut rng, &pool, width);
        accumulator = Expr::add(accumulator, null);
    }
    accumulator
}

fn assert_sound(original: &Expr, result: &Simplification, width: Width, var_count: u32) {
    assert!(
        equivalent_exhaustive(original, &result.simplified, width, var_count),
        "emitted a non-equivalent rewrite of `{original}` -> `{}` at {width:?}",
        result.simplified
    );
    if result.changed() {
        assert!(
            result.verification.is_proven(),
            "changed `{original}` without a proof at {width:?}"
        );
    }
}

#[derive(Debug, Default)]
struct Tally {
    simplified: u32,
    abstained: u32,
}

fn sweep(width: Width, var_count: u32, seeds: u64, inject_null: bool, tally: &mut Tally) {
    for seed in 0..seeds {
        let original: Expr = generate(seed, var_count, width, inject_null && seed % 2 == 0);
        let result: Simplification = simplify(&original, width);
        assert_sound(&original, &result, width, var_count);
        if result.changed() {
            tally.simplified += 1;
        } else {
            tally.abstained += 1;
        }
    }
}

#[test]
fn random_nonlinear_mba_rewrites_stay_equivalent() {
    let mut tally: Tally = Tally::default();
    sweep(Width::W8, 2, 900, true, &mut tally);
    sweep(Width::W4, 3, 600, true, &mut tally);
    assert!(
        tally.simplified > 0,
        "the sweep never exercised a nonlinear simplification"
    );
    assert!(
        tally.abstained > 0,
        "the sweep never exercised the abstain path"
    );
}

#[test]
fn half_scaled_nonlinear_terms_collapse() {
    let atom: Expr = Expr::xor(Expr::var(0), Expr::var(1));
    let obfuscated: Expr = Expr::mul(Expr::konst(128), Expr::mul(atom.clone(), atom.clone()));
    let result: Simplification = simplify(&obfuscated, Width::W8);
    assert!(result.changed());
    assert!(result.verification.is_proven());
    assert!(equivalent_exhaustive(
        &obfuscated,
        &result.simplified,
        Width::W8,
        2
    ));
    let linear: Expr = Expr::mul(Expr::konst(128), atom);
    assert!(equivalent_exhaustive(
        &result.simplified,
        &linear,
        Width::W8,
        2
    ));
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn tigress_style_nonlinear_junk_is_stripped_to_sum() {
    let x: Expr = Expr::var(0);
    let y: Expr = Expr::var(1);
    let sum_identity: Expr = Expr::add(
        Expr::xor(x.clone(), y.clone()),
        Expr::mul(Expr::konst(2), Expr::and(x.clone(), y.clone())),
    );
    let junk_atom: Expr = Expr::or(x.clone(), y.clone());
    let junk: Expr = Expr::mul(
        Expr::konst(128),
        Expr::mul(
            junk_atom.clone(),
            Expr::add(junk_atom, Expr::konst(Width::W8.mask())),
        ),
    );
    let obfuscated: Expr = Expr::add(sum_identity, junk);
    let result: Simplification = simplify(&obfuscated, Width::W8);
    assert!(result.changed());
    assert!(result.verification.is_proven());
    assert!(equivalent_exhaustive(
        &obfuscated,
        &result.simplified,
        Width::W8,
        2
    ));
    let clean_sum: Expr = Expr::add(x, y);
    assert!(
        equivalent_exhaustive(&result.simplified, &clean_sum, Width::W8, 2),
        "nonlinear junk should leave a form equal to x + y, got `{}`",
        result.simplified
    );
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn correlated_nonlinear_equivalence_is_not_fabricated() {
    let x: Expr = Expr::var(0);
    let y: Expr = Expr::var(1);
    let correlated: Expr = Expr::mul(
        Expr::and(x.clone(), y.clone()),
        Expr::or(x.clone(), y.clone()),
    );
    let result: Simplification = simplify(&correlated, Width::W8);
    assert!(
        !result.changed(),
        "the substitution model must not simplify a correlation-only equivalence"
    );
    assert_eq!(result.verification, Verification::Unverified);

    let equivalent_form: Expr = Expr::add(
        Expr::mul(
            Expr::and(x.clone(), y.clone()),
            Expr::and(x.clone(), y.clone()),
        ),
        Expr::mul(Expr::and(x.clone(), y.clone()), Expr::xor(x, y)),
    );
    assert!(
        equivalent_exhaustive(&correlated, &equivalent_form, Width::W8, 2),
        "the abstained equivalence is a genuine function identity the model cannot see"
    );
}

#[test]
fn genuine_bilinear_product_abstains() {
    let product: Expr = Expr::mul(Expr::var(0), Expr::var(1));
    let result: Simplification = simplify(&product, Width::W8);
    assert!(!result.changed());
    assert_eq!(result.verification, Verification::Unverified);
}
