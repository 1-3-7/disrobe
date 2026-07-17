#![doc = "Bounded enumerative synthesis (L6): the final MBA layer, sound-or-abstain."]
#![doc = ""]
#![doc = "When the algebraic layers L0 through L5 leave an expression unsimplified, this"]
#![doc = "layer treats the maximal subterms outside the ring/bitwise grammar (a right shift,"]
#![doc = "a memory read, an unresolved select) as opaque leaves and runs a bounded bottom-up"]
#![doc = "enumerative search over the grammar `+ - * & | ^ ~ <<` applied to those leaves and a"]
#![doc = "small constant set. Candidates are pruned by observational equivalence against a"]
#![doc = "fixed sample-point set: only a candidate whose sample vector matches the target and"]
#![doc = "whose node count is strictly below the input is a hypothesis. Every hypothesis is"]
#![doc = "then proven over the whole word domain by the same gate the earlier heuristic layers"]
#![doc = "use (exhaustive small-domain evaluation cross-checked against the bit-blasting"]
#![doc = "verifier, avoiding the memory-read evaluation hole). A hypothesis that the gate does"]
#![doc = "not prove is discarded and the search continues; on budget exhaustion the input is"]
#![doc = "returned untouched. The search never emits a rewrite it has not proven equivalent."]

use crate::expr::{BinOp, Expr, UnOp, Width};
use crate::rewrite::order_key;
use crate::simplify::{Verification, accept_verified};
use std::collections::BTreeSet;

const MAX_ATOMS: usize = 3;
const MAX_VARS: u32 = 4;
const MAX_CONSTS: usize = 8;
const MIN_INPUT_NODES: usize = 5;
const MAX_CANDIDATE_NODES: usize = 16;
const SAMPLE_RANDOM: usize = 48;
const BANK_CAP: usize = 128;
const MAX_ROUNDS: u32 = 4;
const GEN_BUDGET: u64 = 60_000;
const VERIFY_BUDGET: u32 = 32;

const BIN_OPS: [BinOp; 6] = [
    BinOp::Add,
    BinOp::Sub,
    BinOp::Mul,
    BinOp::And,
    BinOp::Or,
    BinOp::Xor,
];
const SHIFT_AMOUNTS: [u64; 2] = [1, 2];

#[must_use]
pub(crate) fn synthesize(
    original: &Expr,
    width: Width,
    var_count: u32,
) -> Option<(Expr, Verification)> {
    if var_count == 0 || var_count > MAX_VARS {
        return None;
    }
    let original_nodes: usize = original.node_count();
    if original_nodes < MIN_INPUT_NODES {
        return None;
    }
    let (atoms, in_consts): (Vec<Expr>, BTreeSet<u64>) = collect_atoms(original)?;
    if atoms.is_empty() {
        return None;
    }
    let node_cap: usize = original_nodes.saturating_sub(1).min(MAX_CANDIDATE_NODES);
    if node_cap == 0 {
        return None;
    }
    let seed: u64 = structural_seed(original, width);
    let samples: Vec<Vec<u64>> = build_samples(var_count, width, seed);
    let target: Vec<u64> = samples
        .iter()
        .map(|env: &Vec<u64>| original.eval(env, width))
        .collect();
    let consts: Vec<u64> = build_consts(&in_consts, width);

    let mut engine: Enumerator<'_> = Enumerator {
        original,
        width,
        var_count,
        node_cap,
        samples,
        target,
        bank: Vec::new(),
        seen_sigs: BTreeSet::new(),
        tried: BTreeSet::new(),
        gens: 0,
        verify_attempts: 0,
        result: None,
    };
    engine.seed_terminals(&atoms, &consts);
    engine.grow();
    engine.result
}

#[derive(Debug)]
struct Entry {
    expr: Expr,
    cost: usize,
    order: Vec<u64>,
}

#[derive(Debug)]
struct Enumerator<'a> {
    original: &'a Expr,
    width: Width,
    var_count: u32,
    node_cap: usize,
    samples: Vec<Vec<u64>>,
    target: Vec<u64>,
    bank: Vec<Entry>,
    seen_sigs: BTreeSet<Vec<u64>>,
    tried: BTreeSet<Vec<u64>>,
    gens: u64,
    verify_attempts: u32,
    result: Option<(Expr, Verification)>,
}

impl Enumerator<'_> {
    const fn stop(&self) -> bool {
        self.result.is_some() || self.gens >= GEN_BUDGET
    }

    fn signature(&self, expr: &Expr) -> Vec<u64> {
        self.samples
            .iter()
            .map(|env: &Vec<u64>| expr.eval(env, self.width))
            .collect()
    }

    fn offer(&mut self, candidate: Expr) {
        if self.stop() {
            return;
        }
        self.gens += 1;
        let nodes: usize = candidate.node_count();
        if nodes > self.node_cap {
            return;
        }
        let signature: Vec<u64> = self.signature(&candidate);
        if signature == self.target
            && self.verify_attempts < VERIFY_BUDGET
            && self.tried.insert(order_key(&candidate))
        {
            self.verify_attempts += 1;
            if let Some(proof) =
                accept_verified(self.original, &candidate, self.width, self.var_count)
            {
                self.result = Some((candidate, proof));
                return;
            }
        }
        if self.bank.len() < BANK_CAP && self.seen_sigs.insert(signature) {
            let order: Vec<u64> = order_key(&candidate);
            self.bank.push(Entry {
                expr: candidate,
                cost: nodes,
                order,
            });
        }
    }

    fn seed_terminals(&mut self, atoms: &[Expr], consts: &[u64]) {
        for atom in atoms {
            self.offer(atom.clone());
        }
        for value in consts {
            self.offer(Expr::konst(*value));
        }
    }

    fn grow(&mut self) {
        for _ in 0..MAX_ROUNDS {
            if self.stop() {
                return;
            }
            self.bank.sort_by(compare_entry);
            let current: Vec<Expr> = self
                .bank
                .iter()
                .map(|entry: &Entry| entry.expr.clone())
                .collect();
            self.expand_layer(&current);
        }
    }

    fn expand_layer(&mut self, current: &[Expr]) {
        for base in current {
            if self.stop() {
                return;
            }
            self.offer(Expr::not(base.clone()));
            self.offer(Expr::neg(base.clone()));
            for amount in SHIFT_AMOUNTS {
                self.offer(Expr::shl(base.clone(), Expr::konst(amount)));
            }
        }
        for (left_index, left) in current.iter().enumerate() {
            if self.stop() {
                return;
            }
            for (right_index, right) in current.iter().enumerate() {
                if self.stop() {
                    return;
                }
                for op in BIN_OPS {
                    if is_commutative(op) && right_index < left_index {
                        continue;
                    }
                    self.offer(Expr::Binary(
                        op,
                        Box::new(left.clone()),
                        Box::new(right.clone()),
                    ));
                }
            }
        }
    }
}

fn compare_entry(a: &Entry, b: &Entry) -> std::cmp::Ordering {
    a.cost.cmp(&b.cost).then_with(|| a.order.cmp(&b.order))
}

const fn is_commutative(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Add | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
    )
}

fn collect_atoms(expr: &Expr) -> Option<(Vec<Expr>, BTreeSet<u64>)> {
    let mut atoms: Vec<Expr> = Vec::new();
    let mut consts: BTreeSet<u64> = BTreeSet::new();
    gather_atoms(expr, &mut atoms, &mut consts)?;
    Some((atoms, consts))
}

fn gather_atoms(expr: &Expr, atoms: &mut Vec<Expr>, consts: &mut BTreeSet<u64>) -> Option<()> {
    match expr {
        Expr::Const(value) => {
            consts.insert(*value);
            Some(())
        }
        Expr::Unary(UnOp::Neg | UnOp::Not, inner) => gather_atoms(inner, atoms, consts),
        Expr::Binary(
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor,
            left,
            right,
        ) => {
            gather_atoms(left, atoms, consts)?;
            gather_atoms(right, atoms, consts)
        }
        Expr::Binary(BinOp::Shl | BinOp::Shr, _, _)
        | Expr::Var(_)
        | Expr::Ite(_, _, _)
        | Expr::Slice(_, _, _)
        | Expr::Compose(_, _, _)
        | Expr::Mem(_, _) => push_atom(expr, atoms),
    }
}

fn push_atom(atom: &Expr, atoms: &mut Vec<Expr>) -> Option<()> {
    if atoms.iter().any(|known: &Expr| known == atom) {
        return Some(());
    }
    if atoms.len() >= MAX_ATOMS {
        return None;
    }
    atoms.push(atom.clone());
    Some(())
}

fn build_consts(in_consts: &BTreeSet<u64>, width: Width) -> Vec<u64> {
    let mask: u64 = width.mask();
    let sign_bit: u64 = 1u64 << (width.bits() - 1);
    let mut set: BTreeSet<u64> = BTreeSet::new();
    for value in [0u64, 1, 2, mask, sign_bit] {
        set.insert(value & mask);
    }
    for value in in_consts {
        set.insert(*value & mask);
    }
    let mut out: Vec<u64> = set.into_iter().collect();
    out.truncate(MAX_CONSTS);
    out
}

fn build_samples(var_count: u32, width: Width, seed: u64) -> Vec<Vec<u64>> {
    let mask: u64 = width.mask();
    let sign_bit: u64 = 1u64 << (width.bits() - 1);
    let corners: [u64; 6] = [0, 1, 2, mask, mask.wrapping_sub(1) & mask, sign_bit];
    let slots: usize = var_count as usize;
    let mut samples: Vec<Vec<u64>> = Vec::new();
    let mut seen: BTreeSet<Vec<u64>> = BTreeSet::new();
    for corner in corners {
        let tuple: Vec<u64> = vec![corner; slots];
        if seen.insert(tuple.clone()) {
            samples.push(tuple);
        }
    }
    let mut rng: SplitMix64 = SplitMix64::new(seed);
    let mut attempts: usize = 0;
    let cap: usize = SAMPLE_RANDOM.saturating_mul(32).max(1024);
    while samples.len() < corners.len() + SAMPLE_RANDOM && attempts < cap {
        attempts += 1;
        let tuple: Vec<u64> = (0..slots)
            .map(|_| {
                if rng.below(3) == 0 {
                    corners[rng.below(corners.len())]
                } else {
                    rng.next_u64() & mask
                }
            })
            .collect();
        if seen.insert(tuple.clone()) {
            samples.push(tuple);
        }
    }
    samples
}

fn structural_seed(expr: &Expr, width: Width) -> u64 {
    let encoded: String = format!("{expr}|w{}", width.bits());
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for byte in encoded.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

#[derive(Debug)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z: u64 = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    const fn below(&mut self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::expr::equivalent_exhaustive;
    use crate::rewrite::canonicalize;
    use crate::simplify::{Simplification, simplify, simplify_l0_l5};

    fn shr(index: u32, amount: u64) -> Expr {
        Expr::shr(Expr::var(index), Expr::konst(amount))
    }

    fn a() -> Expr {
        shr(0, 1)
    }

    fn b() -> Expr {
        shr(1, 1)
    }

    fn l0_l5_untouched(expr: &Expr, width: Width, var_count: u32) -> bool {
        let (candidate, verification): (Expr, Verification) =
            simplify_l0_l5(expr, width, var_count);
        candidate == *expr && !verification.is_proven()
    }

    fn genuine_win_cases() -> Vec<(Expr, u32)> {
        vec![
            (Expr::sub(Expr::or(a(), b()), b()), 2),
            (Expr::sub(Expr::and(a(), b()), Expr::or(a(), b())), 2),
            (Expr::sub(b(), Expr::and(a(), b())), 2),
            (
                Expr::or(
                    Expr::and(a(), Expr::not(b())),
                    Expr::and(Expr::not(a()), b()),
                ),
                2,
            ),
            (Expr::add(a(), Expr::sub(b(), Expr::and(a(), b()))), 2),
        ]
    }

    #[test]
    fn every_genuine_win_is_untouched_by_l0_l5() {
        for (expr, var_count) in genuine_win_cases() {
            assert!(
                l0_l5_untouched(&expr, Width::W8, var_count),
                "L0-L5 unexpectedly simplified `{expr}`; it is not an L6-only case"
            );
        }
    }

    #[test]
    fn l6_recovers_and_proves_every_genuine_win() {
        for (expr, var_count) in genuine_win_cases() {
            let result: Simplification = simplify(&expr, Width::W8);
            assert!(
                result.changed(),
                "L6 failed to simplify `{expr}` that L0-L5 left untouched"
            );
            assert!(
                result.verification.is_proven(),
                "L6 emitted an unproven rewrite for `{expr}`"
            );
            assert!(
                result.simplified.node_count() < expr.node_count(),
                "L6 rewrite `{}` is not strictly smaller than `{expr}`",
                result.simplified
            );
            assert!(
                equivalent_exhaustive(&expr, &result.simplified, Width::W8, var_count),
                "L6 rewrite `{}` is not equal to `{expr}`",
                result.simplified
            );
        }
    }

    #[test]
    fn or_minus_b_recovers_and_not() {
        let expr: Expr = Expr::sub(Expr::or(a(), b()), b());
        let result: Simplification = simplify(&expr, Width::W8);
        let expected: Expr = Expr::and(a(), Expr::not(b()));
        assert!(equivalent_exhaustive(
            &result.simplified,
            &expected,
            Width::W8,
            2
        ));
        assert!(result.simplified.node_count() <= expected.node_count());
    }

    #[test]
    fn xor_reconstruction_beats_sum_of_products() {
        let expr: Expr = Expr::or(
            Expr::and(a(), Expr::not(b())),
            Expr::and(Expr::not(a()), b()),
        );
        let result: Simplification = simplify(&expr, Width::W8);
        let expected: Expr = Expr::xor(a(), b());
        assert!(result.changed());
        assert!(equivalent_exhaustive(
            &result.simplified,
            &expected,
            Width::W8,
            2
        ));
    }

    #[test]
    fn deterministic_across_repeated_runs() {
        let expr: Expr = Expr::sub(Expr::and(a(), b()), Expr::or(a(), b()));
        let first: Simplification = simplify(&expr, Width::W8);
        let second: Simplification = simplify(&expr, Width::W8);
        assert_eq!(first.simplified, second.simplified);
        assert_eq!(first.verification, second.verification);
        assert!(first.changed());
    }

    #[test]
    fn abstains_on_irreducible_opaque_expression() {
        let expr: Expr = Expr::xor(Expr::add(a(), b()), Expr::sub(a(), b()));
        assert!(
            synthesize(&expr, Width::W8, 2).is_none(),
            "an irreducible mixed opaque expression must abstain"
        );
        let result: Simplification = simplify(&expr, Width::W8);
        assert!(!result.changed());
    }

    #[test]
    fn abstains_beyond_atom_budget() {
        let expr: Expr = Expr::add(
            Expr::add(Expr::add(shr(0, 1), shr(1, 1)), shr(2, 1)),
            shr(3, 1),
        );
        assert!(
            collect_atoms(&expr).is_none(),
            "four distinct opaque leaves exceed the atom budget and must abstain"
        );
        assert!(synthesize(&expr, Width::W8, 4).is_none());
    }

    #[test]
    fn abstains_below_node_floor() {
        let expr: Expr = shr(0, 1);
        assert!(synthesize(&expr, Width::W8, 1).is_none());
    }

    #[test]
    fn only_fires_when_l0_l5_leave_input_unsimplified() {
        let carry: Expr = Expr::add(
            Expr::xor(a(), b()),
            Expr::mul(Expr::konst(2), Expr::and(a(), b())),
        );
        assert!(
            !l0_l5_untouched(&carry, Width::W8, 2),
            "the xor-carry form is an L5 case; L6 must not be the one that fires"
        );
    }

    #[cfg(feature = "smt-verify")]
    #[test]
    fn wide_width_win_is_proven_by_bit_blast() {
        let expr: Expr = Expr::sub(Expr::or(a(), b()), b());
        let result: Simplification = simplify(&expr, Width::W64);
        if result.changed() {
            assert!(result.verification.is_proven());
            let expected: Expr = Expr::and(a(), Expr::not(b()));
            assert_eq!(
                crate::verify::verify_equivalent(&result.simplified, &expected, Width::W64),
                crate::verify::Equivalence::Proven
            );
        }
    }

    #[test]
    fn synthesis_never_emits_a_non_equivalent_rewrite() {
        let width: Width = Width::W8;
        let mut cases: Vec<(Expr, u32)> = genuine_win_cases();
        let mut rng: SplitMix64 = SplitMix64::new(0x9E37_79B9_7F4A_7C15);
        for _ in 0..400 {
            let vars: u32 = 1 + rng.below(2) as u32;
            cases.push((random_opaque_expr(&mut rng, 3, vars), vars));
        }

        let mut newly_simplified: u32 = 0;
        let mut abstained: u32 = 0;
        let mut non_equivalent: u32 = 0;
        let mut examined: u32 = 0;
        for (expr, vars) in &cases {
            if !l0_l5_untouched(expr, width, *vars) {
                continue;
            }
            examined += 1;
            let result: Simplification = simplify(expr, width);
            if result.changed() {
                newly_simplified += 1;
                if !equivalent_exhaustive(expr, &result.simplified, width, *vars) {
                    non_equivalent += 1;
                }
                assert!(result.verification.is_proven());
                assert!(result.simplified.node_count() < expr.node_count());
                let repeat: Simplification = simplify(expr, width);
                assert_eq!(repeat.simplified, result.simplified, "non-deterministic");
            } else {
                abstained += 1;
            }
        }
        assert_eq!(non_equivalent, 0, "L6 emitted a non-equivalent rewrite");
        assert!(examined > 0);
        assert!(
            newly_simplified > 0,
            "expected L6 to newly simplify at least one L0-L5-untouched input"
        );
        assert!(abstained > 0, "expected L6 to abstain on some inputs");
        println!(
            "L6 oracle: examined={examined} newly_simplified={newly_simplified} abstained={abstained} non_equivalent={non_equivalent}"
        );
    }

    #[test]
    fn canonicalize_does_not_shrink_the_win_cases() {
        for (expr, _var_count) in genuine_win_cases() {
            let folded: Expr = canonicalize(&expr, Width::W8);
            assert!(
                folded.node_count() >= expr.node_count(),
                "canonicalize shrank `{expr}` to `{folded}`; not an L6-only case"
            );
        }
    }

    fn random_opaque_expr(rng: &mut SplitMix64, depth: u32, vars: u32) -> Expr {
        if depth == 0 || rng.below(4) == 0 {
            let index: u32 = rng.below(vars as usize) as u32;
            return shr(index, 1);
        }
        match rng.below(8) {
            0 => Expr::not(random_opaque_expr(rng, depth - 1, vars)),
            1 => Expr::neg(random_opaque_expr(rng, depth - 1, vars)),
            2 => Expr::add(
                random_opaque_expr(rng, depth - 1, vars),
                random_opaque_expr(rng, depth - 1, vars),
            ),
            3 => Expr::sub(
                random_opaque_expr(rng, depth - 1, vars),
                random_opaque_expr(rng, depth - 1, vars),
            ),
            4 => Expr::and(
                random_opaque_expr(rng, depth - 1, vars),
                random_opaque_expr(rng, depth - 1, vars),
            ),
            5 => Expr::or(
                random_opaque_expr(rng, depth - 1, vars),
                random_opaque_expr(rng, depth - 1, vars),
            ),
            6 => Expr::xor(
                random_opaque_expr(rng, depth - 1, vars),
                random_opaque_expr(rng, depth - 1, vars),
            ),
            _ => Expr::mul(
                random_opaque_expr(rng, depth - 1, vars),
                random_opaque_expr(rng, depth - 1, vars),
            ),
        }
    }
}
