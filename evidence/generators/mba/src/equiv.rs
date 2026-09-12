use crate::rng::SeededRng;
use crate::term::{Term, Width};

pub const EXHAUSTIVE_BUDGET_LOG2: u32 = 20;
pub const SAMPLED_VECTORS: usize = 4096;
pub const SCREENING_VECTORS: usize = 256;
pub const CHECK_VECTORS: usize = 48;

#[must_use]
pub const fn space_log2(width: Width, var_count: u32) -> u64 {
    width.bits() as u64 * var_count as u64
}

#[must_use]
pub const fn is_exhaustible(width: Width, var_count: u32) -> bool {
    space_log2(width, var_count) <= EXHAUSTIVE_BUDGET_LOG2 as u64
}

#[must_use]
pub fn structured_vectors(width: Width, var_count: u32) -> Vec<Vec<u64>> {
    let mask: u64 = width.mask();
    let slots: usize = var_count.max(1) as usize;
    let fills: [u64; 6] = [
        0,
        mask,
        1,
        mask >> 1,
        0x5555_5555_5555_5555 & mask,
        0xAAAA_AAAA_AAAA_AAAA & mask,
    ];
    let mut vectors: Vec<Vec<u64>> = Vec::with_capacity(fills.len() + slots * 2);
    for fill in fills {
        vectors.push(vec![fill; slots]);
    }
    for slot in 0..slots {
        let mut high: Vec<u64> = vec![0; slots];
        let mut low: Vec<u64> = vec![mask; slots];
        if let (Some(high_slot), Some(low_slot)) = (high.get_mut(slot), low.get_mut(slot)) {
            *high_slot = mask;
            *low_slot = 0;
        }
        vectors.push(high);
        vectors.push(low);
    }
    vectors
}

#[must_use]
pub fn sampled_vectors(seed: u64, width: Width, var_count: u32, count: usize) -> Vec<Vec<u64>> {
    let mask: u64 = width.mask();
    let slots: usize = var_count.max(1) as usize;
    let mut rng: SeededRng = SeededRng::new(seed);
    let mut vectors: Vec<Vec<u64>> = Vec::with_capacity(count);
    for _ in 0..count {
        let vector: Vec<u64> = (0..slots).map(|_| rng.next_u64() & mask).collect();
        vectors.push(vector);
    }
    vectors
}

#[must_use]
pub fn check_vectors(seed: u64, width: Width, var_count: u32) -> Vec<Vec<u64>> {
    let mut vectors: Vec<Vec<u64>> = structured_vectors(width, var_count);
    let wanted: usize = CHECK_VECTORS.saturating_sub(vectors.len());
    vectors.extend(sampled_vectors(
        seed ^ 0xC0FF_EE00_1234_5678,
        width,
        var_count,
        wanted,
    ));
    vectors
}

#[must_use]
pub fn equivalent(left: &Term, right: &Term, width: Width, var_count: u32) -> bool {
    equivalent_within(left, right, width, var_count, SAMPLED_VECTORS)
}

#[must_use]
pub fn screened_equivalent(left: &Term, right: &Term, width: Width, var_count: u32) -> bool {
    equivalent_within(left, right, width, var_count, SCREENING_VECTORS)
}

fn equivalent_within(
    left: &Term,
    right: &Term,
    width: Width,
    var_count: u32,
    samples: usize,
) -> bool {
    if is_exhaustible(width, var_count) {
        return exhaustively_equivalent(left, right, width, var_count);
    }
    let structured: Vec<Vec<u64>> = structured_vectors(width, var_count);
    let sampled: Vec<Vec<u64>> = sampled_vectors(0x51E7_1DEA_5EED_0007, width, var_count, samples);
    structured
        .iter()
        .chain(sampled.iter())
        .all(|env: &Vec<u64>| left.eval(env, width) == right.eval(env, width))
}

fn exhaustively_equivalent(left: &Term, right: &Term, width: Width, var_count: u32) -> bool {
    let slots: usize = var_count.max(1) as usize;
    let bits: u32 = width.bits();
    let total: u64 = 1u64 << space_log2(width, var_count).min(63);
    let mut env: Vec<u64> = vec![0; slots];
    for encoded in 0..total {
        for (slot, cell) in env.iter_mut().enumerate() {
            let shift: u32 = bits * u32::try_from(slot).unwrap_or(0);
            *cell = if shift >= 64 {
                0
            } else {
                (encoded >> shift) & width.mask()
            };
        }
        if left.eval(&env, width) != right.eval(&env, width) {
            return false;
        }
    }
    true
}
