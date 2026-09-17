const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908_b0df;
const UPPER_MASK: u32 = 0x8000_0000;
const LOWER_MASK: u32 = 0x7fff_ffff;

#[derive(Debug, Clone)]
pub(crate) struct MersenneTwister {
    state: [u32; N],
    index: usize,
}

impl MersenneTwister {
    fn raw_seed(seed: u32) -> Self {
        let mut state: [u32; N] = [0u32; N];
        state[0] = seed;
        for i in 1..N {
            let prev: u32 = state[i - 1] ^ (state[i - 1] >> 30);
            state[i] = 1_812_433_253u32
                .wrapping_mul(prev)
                .wrapping_add(u32::try_from(i).unwrap_or(0));
        }
        Self { state, index: N }
    }

    fn init_by_array(init_key: &[u32]) -> Self {
        let mut mt: Self = Self::raw_seed(19_650_218u32);
        let mut i: usize = 1;
        let mut j: usize = 0;
        let key_len: usize = init_key.len();
        let mut k: usize = N.max(key_len);
        while k > 0 {
            let prev: u32 = mt.state[i - 1] ^ (mt.state[i - 1] >> 30);
            mt.state[i] = (mt.state[i] ^ prev.wrapping_mul(1_664_525u32))
                .wrapping_add(init_key[j])
                .wrapping_add(u32::try_from(j).unwrap_or(0));
            i += 1;
            j += 1;
            if i >= N {
                mt.state[0] = mt.state[N - 1];
                i = 1;
            }
            if j >= key_len {
                j = 0;
            }
            k -= 1;
        }
        let mut k2: usize = N - 1;
        while k2 > 0 {
            let prev: u32 = mt.state[i - 1] ^ (mt.state[i - 1] >> 30);
            mt.state[i] = (mt.state[i] ^ prev.wrapping_mul(1_566_083_941u32))
                .wrapping_sub(u32::try_from(i).unwrap_or(0));
            i += 1;
            if i >= N {
                mt.state[0] = mt.state[N - 1];
                i = 1;
            }
            k2 -= 1;
        }
        mt.state[0] = 0x8000_0000;
        mt.index = N;
        mt
    }

    pub(crate) fn from_u32_words_le(words: &[u32]) -> Self {
        let key: Vec<u32> = if words.is_empty() {
            vec![0u32]
        } else {
            words.to_vec()
        };
        Self::init_by_array(&key)
    }

    fn generate(&mut self) {
        for i in 0..N {
            let y: u32 = (self.state[i] & UPPER_MASK) | (self.state[(i + 1) % N] & LOWER_MASK);
            let mut next: u32 = self.state[(i + M) % N] ^ (y >> 1);
            if y & 1 != 0 {
                next ^= MATRIX_A;
            }
            self.state[i] = next;
        }
        self.index = 0;
    }

    pub(crate) fn next_u32(&mut self) -> u32 {
        if self.index >= N {
            self.generate();
        }
        let mut y: u32 = self.state[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }

    pub(crate) fn getrandbits(&mut self, k: u32) -> u64 {
        if k == 0 {
            return 0;
        }
        if k <= 32 {
            return u64::from(self.next_u32() >> (32 - k));
        }
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        let mut remaining: u32 = k;
        while remaining > 0 {
            let take: u32 = remaining.min(32);
            let word: u32 = self.next_u32() >> (32 - take);
            result |= u64::from(word) << shift;
            shift += 32;
            remaining -= take;
        }
        result
    }

    fn randbelow(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let k: u32 = u64::BITS - n.leading_zeros();
        loop {
            let r: u64 = self.getrandbits(k);
            if r < n {
                return r;
            }
        }
    }

    pub(crate) fn shuffle_range(&mut self, len: usize) -> Vec<u8> {
        let mut perm: Vec<usize> = (0..len).collect();
        if len > 1 {
            let mut i: usize = len - 1;
            while i >= 1 {
                let j: usize = usize::try_from(self.randbelow(i as u64 + 1)).unwrap_or(0);
                perm.swap(i, j);
                i -= 1;
            }
        }
        perm.into_iter()
            .map(|v: usize| u8::try_from(v).unwrap_or(0))
            .collect()
    }
}

pub(crate) fn words_from_be_bytes_le_order(digest: &[u8]) -> Vec<u32> {
    let mut le: Vec<u8> = digest.iter().rev().copied().collect();
    while le.last() == Some(&0u8) && le.len() > 1 {
        le.pop();
    }
    while !le.len().is_multiple_of(4) {
        le.push(0);
    }
    let mut words: Vec<u32> = Vec::with_capacity(le.len() / 4);
    for chunk in le.chunks_exact(4) {
        words.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    if words.is_empty() {
        words.push(0);
    }
    words
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn mt_from_sha256(key: &[u8]) -> MersenneTwister {
        let digest: [u8; 32] = Sha256::digest(key).into();
        let words: Vec<u32> = words_from_be_bytes_le_order(&digest);
        MersenneTwister::from_u32_words_le(&words)
    }

    #[test]
    fn getrandbits32_matches_cpython_seed_12345() {
        let mut mt: MersenneTwister = MersenneTwister::from_u32_words_le(&[12345u32]);
        assert_eq!(mt.getrandbits(32), 1_789_368_711);
        assert_eq!(mt.getrandbits(32), 3_146_859_322);
        assert_eq!(mt.getrandbits(32), 43_676_229);
    }

    #[test]
    fn randbelow_matches_cpython_seed_0() {
        let mut mt: MersenneTwister = MersenneTwister::from_u32_words_le(&[0u32]);
        let got: Vec<u64> = (0..5).map(|_| mt.randbelow(256)).collect();
        assert_eq!(got, vec![197, 215, 20, 132, 248]);
    }

    #[test]
    fn shuffle10_matches_cpython_seed_99() {
        let mut mt: MersenneTwister = MersenneTwister::from_u32_words_le(&[99u32]);
        let shuffled: Vec<u8> = mt.shuffle_range(10);
        assert_eq!(shuffled, vec![7, 2, 0, 8, 5, 1, 4, 3, 9, 6]);
    }

    #[test]
    fn perm_matches_cpython_sha256_key_range20() {
        let key: Vec<u8> = (0u8..20).collect();
        let mut mt: MersenneTwister = mt_from_sha256(&key);
        let perm: Vec<u8> = mt.shuffle_range(256);
        assert_eq!(
            &perm[..16],
            &[
                160, 188, 186, 229, 90, 227, 115, 178, 153, 5, 96, 82, 250, 254, 222, 242
            ]
        );
        assert_eq!(&perm[248..], &[13, 195, 63, 156, 99, 215, 26, 48]);
    }
}
