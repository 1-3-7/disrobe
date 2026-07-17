#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_mba::{
    Expr, Simplification, Verification, Width, simplify, simplify_mixed, solve_polynomial_mba,
};

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
        (self.state >> 33) ^ (self.state >> 11) ^ self.state
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
    &pool[rng.below(pool.len() as u64) as usize]
}

fn scaled(coeff: u64, base: Expr) -> Expr {
    match coeff {
        0 => Expr::konst(0),
        1 => base,
        other => Expr::mul(Expr::konst(other), base),
    }
}

fn random_monomial(rng: &mut Lcg, pool: &[Expr], modulus: u64, max_degree: u64) -> Expr {
    let coeff: u64 = rng.below(modulus);
    let degree: u64 = 1 + rng.below(max_degree);
    let mut product: Expr = pick(rng, pool).clone();
    for _ in 1..degree {
        product = Expr::mul(product, pick(rng, pool).clone());
    }
    scaled(coeff, product)
}

fn null_term(rng: &mut Lcg, pool: &[Expr], width: Width) -> Expr {
    let half: u64 = 1u64 << (width.bits() - 1);
    let atom: Expr = pick(rng, pool).clone();
    let predecessor: Expr = Expr::add(atom.clone(), Expr::konst(width.mask()));
    Expr::mul(Expr::konst(half), Expr::mul(atom, predecessor))
}

fn generate(seed: u64, var_count: u32, width: Width, max_degree: u64, inject_null: bool) -> Expr {
    let modulus: u64 = width.mask().wrapping_add(1).max(1);
    let pool: Vec<Expr> = atom_pool(var_count);
    let mut rng: Lcg = Lcg::new(seed);
    let count: u64 = 1 + rng.below(4);
    let mut accumulator: Expr = random_monomial(&mut rng, &pool, modulus, max_degree);
    for _ in 1..count {
        let term: Expr = random_monomial(&mut rng, &pool, modulus, max_degree);
        accumulator = if rng.below(2) == 0 {
            Expr::sub(accumulator, term)
        } else {
            Expr::add(accumulator, term)
        };
    }
    let genuine: Expr = Expr::mul(pick(&mut rng, &pool).clone(), pick(&mut rng, &pool).clone());
    accumulator = Expr::add(accumulator, genuine);
    if inject_null {
        accumulator = Expr::add(accumulator, null_term(&mut rng, &pool, width));
    }
    accumulator
}

fn sampling_environments(
    rng: &mut Lcg,
    var_count: usize,
    width: Width,
    random_samples: usize,
) -> Vec<Vec<u64>> {
    let mask: u64 = width.mask();
    let high_bit: u64 = 1u64 << (width.bits() - 1);
    let mut environments: Vec<Vec<u64>> = vec![
        vec![0u64; var_count],
        vec![mask; var_count],
        vec![1u64; var_count],
        vec![high_bit; var_count],
        vec![high_bit.wrapping_sub(1) & mask; var_count],
    ];
    for _ in 0..random_samples {
        environments.push((0..var_count).map(|_| rng.step() & mask).collect());
    }
    environments
}

fn eval_counterexample(
    original: &Expr,
    candidate: &Expr,
    width: Width,
    var_count: usize,
    seed: u64,
    samples: usize,
) -> Option<Vec<u64>> {
    let mut rng: Lcg = Lcg::new(seed ^ 0x00A5_5A00_F0F0_0F0F ^ u64::from(width.bits()));
    sampling_environments(&mut rng, var_count, width, samples)
        .into_iter()
        .find(|environment: &Vec<u64>| {
            original.eval(environment, width) != candidate.eval(environment, width)
        })
}

#[cfg(feature = "smt-verify")]
fn bdd_disproof(original: &Expr, candidate: &Expr, width: Width) -> Option<Vec<u64>> {
    use disrobe_mba::{Equivalence, verify_equivalent_budgeted};
    match verify_equivalent_budgeted(original, candidate, width, 1usize << 13) {
        Equivalence::Disproven { counterexample } => Some(counterexample),
        Equivalence::Proven | Equivalence::Unknown => None,
    }
}

#[cfg(not(feature = "smt-verify"))]
fn bdd_disproof(_original: &Expr, _candidate: &Expr, _width: Width) -> Option<Vec<u64>> {
    None
}

fn confirm_equivalent(
    original: &Expr,
    candidate: &Expr,
    width: Width,
    var_count: usize,
    seed: u64,
) {
    if let Some(environment) = eval_counterexample(original, candidate, width, var_count, seed, 256)
    {
        panic!(
            "sampling disproved `{original}` -> `{candidate}` at {width:?}: env {environment:?} gives {} vs {}",
            original.eval(&environment, width),
            candidate.eval(&environment, width)
        );
    }
    if let Some(counterexample) = bdd_disproof(original, candidate, width) {
        panic!(
            "bit-blasting disproved `{original}` -> `{candidate}` at {width:?} with {counterexample:?}"
        );
    }
}

#[test]
fn wide_polynomial_certificate_only_accepts_equivalent_reductions() {
    let mut accepted: u32 = 0;
    for width in [Width::W32, Width::W64] {
        for var_count in 1u32..=4 {
            for seed in 0..350u64 {
                let original: Expr = generate(seed, var_count, width, 3, seed % 2 == 0);
                let Some(candidate): Option<Expr> =
                    solve_polynomial_mba(&original, width, var_count)
                else {
                    continue;
                };
                assert!(
                    candidate.node_count() < original.node_count(),
                    "poly candidate for `{original}` at {width:?} did not shrink"
                );
                confirm_equivalent(&original, &candidate, width, var_count as usize, seed);
                accepted += 1;
            }
        }
    }
    eprintln!("wide polynomial certificate accepted={accepted}");
    assert!(
        accepted > 50,
        "the sweep never exercised the wide-width polynomial certificate (accepted={accepted})"
    );
}

fn sum_identity(x: &Expr, y: &Expr) -> Expr {
    Expr::add(
        Expr::xor(x.clone(), y.clone()),
        Expr::mul(Expr::konst(2), Expr::and(x.clone(), y.clone())),
    )
}

fn vanishing_scaled_predecessor(atom: Expr, width: Width) -> Expr {
    let half: u64 = 1u64 << (width.bits() - 1);
    let predecessor: Expr = Expr::add(atom.clone(), Expr::konst(width.mask()));
    Expr::mul(Expr::konst(half), Expr::mul(atom, predecessor))
}

fn assert_end_to_end_sound(original: &Expr, width: Width, var_count: usize) -> Verification {
    let result: Simplification = simplify(original, width);
    assert!(
        result.changed(),
        "expected `{original}` to reduce at {width:?}"
    );
    assert!(
        result.verification.is_proven(),
        "the full simplifier changed `{original}` at {width:?} without a proof"
    );
    assert!(
        result.simplified_nodes < result.original_nodes,
        "the full simplifier changed `{original}` at {width:?} without shrinking"
    );
    confirm_equivalent(
        original,
        &result.simplified,
        width,
        var_count,
        0x00C0_FFEE_1357_2468,
    );
    result.verification
}

#[test]
fn wide_full_simplifier_curated_acceptances_stay_equivalent() {
    let x: Expr = Expr::var(0);
    let y: Expr = Expr::var(1);
    for width in [Width::W32, Width::W64] {
        let hidden_sum_junk: Expr = Expr::add(
            sum_identity(&x, &y),
            vanishing_scaled_predecessor(Expr::or(x.clone(), y.clone()), width),
        );
        let tag_a: Verification = assert_end_to_end_sound(&hidden_sum_junk, width, 2);

        let triple_null: Expr = Expr::add(
            Expr::add(
                Expr::add(
                    x.clone(),
                    vanishing_scaled_predecessor(Expr::and(x.clone(), y.clone()), width),
                ),
                vanishing_scaled_predecessor(Expr::or(x.clone(), y.clone()), width),
            ),
            vanishing_scaled_predecessor(Expr::xor(x.clone(), y.clone()), width),
        );
        let tag_b: Verification = assert_end_to_end_sound(&triple_null, width, 2);

        let distributive: Expr = Expr::sub(
            Expr::mul(x.clone(), Expr::add(y.clone(), Expr::konst(1))),
            Expr::mul(x.clone(), y.clone()),
        );
        let tag_c: Verification = assert_end_to_end_sound(&distributive, width, 2);

        eprintln!(
            "{width:?} curated tags: hidden_sum={tag_a:?} triple_null={tag_b:?} distributive={tag_c:?}"
        );
    }
}

#[test]
fn wide_mixed_path_is_gated_and_equivalent() {
    let x: Expr = Expr::var(0);
    let y: Expr = Expr::var(1);
    let obfuscated: Expr = Expr::xor(sum_identity(&x, &y), Expr::add(x.clone(), y.clone()));
    for width in [Width::W32, Width::W64] {
        let Some(collapsed): Option<Expr> = simplify_mixed(&obfuscated, width) else {
            panic!("the mixed path must collapse `{obfuscated}` at {width:?}");
        };
        assert_eq!(collapsed, Expr::konst(0));
        confirm_equivalent(&obfuscated, &collapsed, width, 2, 0x1BAD_C0DE_0F0F_0F0F);
    }
    let irreducible: Expr = Expr::xor(Expr::add(x.clone(), y.clone()), Expr::sub(x, y));
    for width in [Width::W32, Width::W64] {
        assert!(
            simplify_mixed(&irreducible, width).is_none(),
            "the mixed path must abstain on `{irreducible}` at {width:?} rather than invent a form"
        );
    }
}
