pub(crate) const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub const ZERO_SEED_REPLACEMENT: u64 = GOLDEN_GAMMA;

    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                Self::ZERO_SEED_REPLACEMENT
            } else {
                seed
            },
        }
    }

    pub const fn next_u64(&mut self) -> u64 {
        let mut value: u64 = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    pub const fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        let remainder: u64 = (u64::MAX % bound).wrapping_add(1) % bound;
        if remainder == 0 {
            return self.next_u64() % bound;
        }
        let accept_below: u64 = (u64::MAX - remainder).wrapping_add(1);
        loop {
            let value: u64 = self.next_u64();
            if value < accept_below {
                return value % bound;
            }
        }
    }

    pub(crate) fn below_usize(&mut self, bound: usize) -> usize {
        let widened: u64 = u64::try_from(bound).unwrap_or(u64::MAX);
        usize::try_from(self.below(widened)).unwrap_or(0)
    }

    pub(crate) const fn next_byte(&mut self) -> u8 {
        self.next_u64().to_le_bytes()[0]
    }
}

pub(crate) const fn splitmix64(seed: u64) -> u64 {
    let mut value: u64 = seed.wrapping_add(GOLDEN_GAMMA);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::{XorShift64, splitmix64};

    #[test]
    fn a_zero_seed_is_remapped_off_the_fixed_point() {
        let mut zero_seeded: XorShift64 = XorShift64::new(0);
        let mut replacement_seeded: XorShift64 = XorShift64::new(XorShift64::ZERO_SEED_REPLACEMENT);
        let first: u64 = zero_seeded.next_u64();
        assert_ne!(first, 0);
        assert_eq!(first, replacement_seeded.next_u64());
    }

    #[test]
    fn a_stream_never_stalls_on_zero() {
        let mut rng: XorShift64 = XorShift64::new(0);
        for _ in 0..4096 {
            assert_ne!(rng.next_u64(), 0);
        }
    }

    #[test]
    fn below_stays_inside_its_bound() {
        let mut rng: XorShift64 = XorShift64::new(0x1234_5678_9ABC_DEF0);
        assert_eq!(rng.below(0), 0);
        assert_eq!(rng.below(1), 0);
        for bound in [2u64, 7, 8, 255, 1000, u64::MAX] {
            for _ in 0..512 {
                assert!(rng.below(bound) < bound);
            }
        }
    }

    #[test]
    fn below_covers_every_residue_of_a_small_bound() {
        let mut rng: XorShift64 = XorShift64::new(0xFEED_FACE_CAFE_BEEF);
        let mut seen: [bool; 7] = [false; 7];
        for _ in 0..4096 {
            let index: usize = usize::try_from(rng.below(7)).unwrap_or(0);
            if let Some(slot) = seen.get_mut(index) {
                *slot = true;
            }
        }
        assert!(seen.iter().all(|hit: &bool| *hit));
    }

    #[test]
    fn identical_seeds_produce_identical_streams() {
        let mut left: XorShift64 = XorShift64::new(0xABCD_0123_4567_89EF);
        let mut right: XorShift64 = XorShift64::new(0xABCD_0123_4567_89EF);
        for _ in 0..1024 {
            assert_eq!(left.next_u64(), right.next_u64());
        }
    }

    #[test]
    fn splitmix_avalanches_adjacent_seeds() {
        let low: u64 = splitmix64(0);
        let high: u64 = splitmix64(1);
        assert_ne!(low, high);
        assert!((low ^ high).count_ones() > 8);
    }
}
