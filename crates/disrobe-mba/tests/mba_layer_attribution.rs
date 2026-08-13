#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "data/mba_corpus.rs"]
#[allow(clippy::redundant_pub_crate)]
mod mba_corpus;

use disrobe_mba::{
    Expr, Simplification, Width, canonicalize, simplify, simplify_mixed, solve_linear_mba,
    solve_polynomial_mba, synthesize_bitwise_masked,
};
use mba_corpus::{CorpusEntry, corpus};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Layer {
    Canonicalization,
    LinearSolver,
    PolynomialSolver,
    MixedSolver,
    BitwiseSynthesis,
    Residue,
}

impl Layer {
    const fn label(self) -> &'static str {
        match self {
            Self::Canonicalization => "canonicalize",
            Self::LinearSolver => "linear",
            Self::PolynomialSolver => "polynomial",
            Self::MixedSolver => "mixed",
            Self::BitwiseSynthesis => "bitwise",
            Self::Residue => "residue",
        }
    }
}

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
}

fn var_count(entry: &CorpusEntry, simplified: &Expr) -> u32 {
    let mut highest: Option<u32> = entry.e_obf.max_var();
    for candidate in [entry.e_src.max_var(), simplified.max_var()] {
        highest = match (highest, candidate) {
            (Some(current), Some(other)) => Some(current.max(other)),
            (Some(current), None) => Some(current),
            (None, other) => other,
        };
    }
    highest.map_or(0, |index: u32| index + 1)
}

fn input_vectors(count: u32, width: Width) -> Vec<Vec<u64>> {
    let slots: usize = count as usize;
    let mask: u64 = width.mask();
    let mut vectors: Vec<Vec<u64>> = vec![
        vec![0; slots],
        vec![mask; slots],
        vec![1; slots],
        vec![mask >> 1; slots],
        vec![0x5555_5555_5555_5555 & mask; slots],
        vec![0xAAAA_AAAA_AAAA_AAAA & mask; slots],
    ];
    for slot in 0..slots {
        let mut vector: Vec<u64> = vec![0; slots];
        if let Some(cell) = vector.get_mut(slot) {
            *cell = mask;
        }
        vectors.push(vector);
    }
    let mut rng: SplitMix64 = SplitMix64::new(0x9A17_2C0D_5EED_4321);
    for _ in 0..512u32 {
        vectors.push((0..slots).map(|_| rng.next_u64() & mask).collect());
    }
    vectors
}

fn agrees(lhs: &Expr, rhs: &Expr, width: Width, vectors: &[Vec<u64>]) -> bool {
    vectors
        .iter()
        .all(|env: &Vec<u64>| lhs.eval(env, width) == rhs.eval(env, width))
}

fn closing_layer(entry: &CorpusEntry, count: u32) -> Layer {
    let width: Width = entry.width;
    let target: usize = entry.e_src.node_count();
    if canonicalize(&entry.e_obf, width).node_count() <= target {
        return Layer::Canonicalization;
    }
    if solve_linear_mba(&entry.e_obf, width, count)
        .is_some_and(|solved: Expr| solved.node_count() <= target)
    {
        return Layer::LinearSolver;
    }
    if solve_polynomial_mba(&entry.e_obf, width, count)
        .is_some_and(|solved: Expr| solved.node_count() <= target)
    {
        return Layer::PolynomialSolver;
    }
    if simplify_mixed(&entry.e_obf, width).is_some_and(|solved: Expr| solved.node_count() <= target)
    {
        return Layer::MixedSolver;
    }
    if synthesize_bitwise_masked(&entry.e_obf, width, count)
        .is_some_and(|solved: Expr| solved.node_count() <= target)
    {
        return Layer::BitwiseSynthesis;
    }
    Layer::Residue
}

#[derive(Debug, Default, Clone, Copy)]
struct Tally {
    pairs: usize,
    reduced: usize,
    proven: usize,
}

#[test]
fn published_identity_recall_is_measured_by_provenance_and_by_closing_layer() {
    const REDUCE_FLOOR: usize = 28;
    const PROVEN_FLOOR: usize = 28;
    const RESIDUE_CLOSED_FLOOR: usize = 3;

    let entries: Vec<CorpusEntry> = corpus();
    let mut by_provenance: BTreeMap<&'static str, Tally> = BTreeMap::new();
    let mut by_layer: BTreeMap<Layer, usize> = BTreeMap::new();
    let mut residue_closed: usize = 0;
    let mut residue_total: usize = 0;
    let mut reduced: usize = 0;
    let mut proven: usize = 0;

    for entry in &entries {
        let result: Simplification = simplify(&entry.e_obf, entry.width);
        let simplified: &Expr = &result.simplified;
        let count: u32 = var_count(entry, simplified);
        let vectors: Vec<Vec<u64>> = input_vectors(count, entry.width);

        assert!(
            agrees(&entry.e_src, &entry.e_obf, entry.width, &vectors),
            "{}: the corpus pair is not an identity, so it cannot grade anything",
            entry.name
        );
        assert!(
            agrees(&entry.e_src, simplified, entry.width, &vectors),
            "{}: simplify(e_obf) = `{simplified}` disagrees with the published source form",
            entry.name
        );
        assert!(
            result.verification.is_proven() || !result.changed(),
            "{}: a rewrite shipped without an independently established proof",
            entry.name
        );

        let layer: Layer = closing_layer(entry, count);
        *by_layer.entry(layer).or_default() += 1;
        let target: usize = entry.e_src.node_count();
        let closed: bool = simplified.node_count() <= target;
        if layer == Layer::Residue {
            residue_total += 1;
            if closed {
                residue_closed += 1;
            }
        }
        if closed {
            reduced += 1;
        }
        if result.verification.is_proven() {
            proven += 1;
        }
        let tally: &mut Tally = by_provenance.entry(entry.provenance).or_default();
        tally.pairs += 1;
        if closed {
            tally.reduced += 1;
        }
        if result.verification.is_proven() {
            tally.proven += 1;
        }
    }

    eprintln!(
        "recall on published MBA identities, ground truth is the published source form, {} pairs",
        entries.len()
    );
    eprintln!(
        "  {:<72} {:>5} {:>7} {:>6}",
        "provenance", "pairs", "reduced", "proven"
    );
    for (provenance, tally) in &by_provenance {
        eprintln!(
            "  {:<72} {:>5} {:>7} {:>6}",
            provenance, tally.pairs, tally.reduced, tally.proven
        );
    }
    eprintln!("closing layer before equality saturation:");
    for (layer, count) in &by_layer {
        eprintln!("  {:<14} {count}", layer.label());
    }
    eprintln!(
        "residue the earlier layers do not close: {residue_total}, of which the full pipeline closes {residue_closed}"
    );

    assert!(
        reduced >= REDUCE_FLOOR,
        "recall regression: {reduced} of {} pairs reached the published source size, floor is {REDUCE_FLOOR}",
        entries.len()
    );
    assert!(
        proven >= PROVEN_FLOOR,
        "proof regression: {proven} of {} pairs carry a proof, floor is {PROVEN_FLOOR}",
        entries.len()
    );
    assert!(
        residue_total > 0,
        "no corpus pair survives the pre-saturation layers, so the residue measurement is vacuous"
    );
    assert!(
        residue_closed >= RESIDUE_CLOSED_FLOOR,
        "residue regression: the layers after the linear and polynomial solvers closed {residue_closed} of {residue_total} residue pairs, floor is {RESIDUE_CLOSED_FLOOR}"
    );
}
