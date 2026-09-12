use rand::SeedableRng;
use rand::rngs::{StdRng, ThreadRng};

pub type SeededRng = StdRng;

#[must_use]
pub fn seeded(seed: u64) -> SeededRng {
    StdRng::seed_from_u64(seed)
}

#[must_use]
pub fn os() -> ThreadRng {
    #[allow(clippy::disallowed_methods)]
    rand::rng()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rand::RngExt;

    #[test]
    fn seeded_is_deterministic() {
        let mut a: SeededRng = seeded(42);
        let mut b: SeededRng = seeded(42);
        let av: [u64; 4] = [a.random(), a.random(), a.random(), a.random()];
        let bv: [u64; 4] = [b.random(), b.random(), b.random(), b.random()];
        assert_eq!(av, bv);
    }

    #[test]
    fn seeded_different_seeds_diverge() {
        let mut a: SeededRng = seeded(1);
        let mut b: SeededRng = seeded(2);
        let av: u64 = a.random();
        let bv: u64 = b.random();
        assert_ne!(av, bv);
    }

    #[test]
    fn os_produces_values() {
        let mut r: ThreadRng = os();
        let _: u64 = r.random();
    }
}
