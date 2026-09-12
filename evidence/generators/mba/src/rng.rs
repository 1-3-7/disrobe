#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    pub const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed: u64 = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    pub const fn below(&mut self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }
        let draw: u128 = self.next_u64() as u128;
        ((draw * bound as u128) >> 64) as usize
    }

    pub fn pick<'a, T>(&mut self, choices: &'a [T]) -> Option<&'a T> {
        if choices.is_empty() {
            return None;
        }
        let index: usize = self.below(choices.len());
        choices.get(index)
    }
}
