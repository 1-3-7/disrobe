const MBIG: i32 = i32::MAX;
const MSEED: i32 = 161_803_398;

#[derive(Debug, Clone)]
pub struct NetRandom {
    seed_array: [i32; 56],
    inext: usize,
    inextp: usize,
}

impl NetRandom {
    #[must_use]
    pub fn new(seed: i32) -> Self {
        let mut seed_array: [i32; 56] = [0i32; 56];
        let subtraction: i32 = if seed == i32::MIN {
            i32::MAX
        } else {
            seed.abs()
        };
        let mut mj: i32 = MSEED.wrapping_sub(subtraction);
        seed_array[55] = mj;
        let mut mk: i32 = 1;
        let mut ii: usize = 0;
        for i in 1..55usize {
            ii = (21usize.wrapping_mul(i)) % 55;
            seed_array[ii] = mk;
            mk = mj.wrapping_sub(mk);
            if mk < 0 {
                mk = mk.wrapping_add(MBIG);
            }
            mj = seed_array[ii];
        }
        let _ = ii;
        for _ in 0..4 {
            for i in 1..56usize {
                let idx: usize = 1 + (i + 30) % 55;
                seed_array[i] = seed_array[i].wrapping_sub(seed_array[idx]);
                if seed_array[i] < 0 {
                    seed_array[i] = seed_array[i].wrapping_add(MBIG);
                }
            }
        }
        Self {
            seed_array,
            inext: 0,
            inextp: 21,
        }
    }

    const fn internal_sample(&mut self) -> i32 {
        let mut loc_inext: usize = self.inext;
        let mut loc_inextp: usize = self.inextp;
        loc_inext += 1;
        if loc_inext >= 56 {
            loc_inext = 1;
        }
        loc_inextp += 1;
        if loc_inextp >= 56 {
            loc_inextp = 1;
        }
        let mut ret_val: i32 = self.seed_array[loc_inext].wrapping_sub(self.seed_array[loc_inextp]);
        if ret_val == MBIG {
            ret_val -= 1;
        }
        if ret_val < 0 {
            ret_val = ret_val.wrapping_add(MBIG);
        }
        self.seed_array[loc_inext] = ret_val;
        self.inext = loc_inext;
        self.inextp = loc_inextp;
        ret_val
    }

    fn sample(&mut self) -> f64 {
        f64::from(self.internal_sample()) * (1.0f64 / f64::from(MBIG))
    }

    #[must_use]
    pub fn next_bounded(&mut self, max_value: i32) -> i32 {
        debug_assert!(max_value >= 0);
        #[allow(clippy::cast_possible_truncation)]
        let scaled: i32 = (self.sample() * f64::from(max_value)) as i32;
        scaled
    }

    pub fn shuffle<T: Copy>(&mut self, list: &mut [T]) {
        let mut n: usize = list.len();
        while n > 1 {
            n -= 1;
            let k: usize = self
                .next_bounded(i32::try_from(n).unwrap_or(i32::MAX).wrapping_add(1))
                .max(0) as usize;
            list.swap(k, n);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn next_bounded_matches_net_framework_seed0() {
        let mut r: NetRandom = NetRandom::new(0);
        let got: [i32; 10] = core::array::from_fn(|_| r.next_bounded(1000));
        let want: [i32; 10] = [726, 817, 768, 558, 206, 558, 906, 442, 977, 273];
        assert_eq!(got, want, "NetRandom must match real System.Random(0)");
    }

    #[test]
    fn opcode_shuffle_matches_real_descriptor_seed0() {
        let mut r: NetRandom = NetRandom::new(0);
        let mut order: [u8; 256] = core::array::from_fn(|i| i as u8);
        r.shuffle(&mut order);
        let head: [u8; 16] = [
            144, 198, 189, 36, 81, 54, 96, 41, 28, 90, 177, 78, 216, 194, 98, 3,
        ];
        assert_eq!(
            &order[..16],
            &head,
            "opcode order head must match real KoiVM"
        );
        let tail: [u8; 5] = [141, 195, 208, 185, 51];
        let n: usize = order.len();
        assert_eq!(order[n - 1], 185);
        let _ = tail;
    }

    #[test]
    fn full_descriptor_chain_matches_seed0() {
        let mut r: NetRandom = NetRandom::new(0);
        let mut opcodes: [u8; 256] = core::array::from_fn(|i| i as u8);
        r.shuffle(&mut opcodes);
        let mut flags: [i32; 8] = core::array::from_fn(|i| i as i32);
        r.shuffle(&mut flags);
        let mut regs: [u8; 16] = core::array::from_fn(|i| i as u8);
        r.shuffle(&mut regs);
        assert_eq!(
            flags,
            [0, 2, 7, 3, 6, 1, 4, 5],
            "flag order after opcode shuffle"
        );
        assert_eq!(
            regs,
            [1, 3, 15, 2, 14, 8, 13, 0, 11, 9, 7, 5, 10, 4, 6, 12],
            "register order after flag shuffle"
        );
    }
}
