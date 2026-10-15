use std::cmp::Ordering;
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct U256([u64; 4]);

impl U256 {
    pub const ZERO: Self = Self([0; 4]);
    pub const ONE: Self = Self([1, 0, 0, 0]);
    pub const MAX: Self = Self([u64::MAX; 4]);

    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self([value, 0, 0, 0])
    }

    #[must_use]
    pub fn from_be_slice(bytes: &[u8]) -> Self {
        let mut padded: [u8; 32] = [0; 32];
        let take: usize = bytes.len().min(32);
        padded[32 - take..].copy_from_slice(&bytes[bytes.len() - take..]);
        Self::from_be_bytes(padded)
    }

    #[must_use]
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs: [u64; 4] = [0; 4];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let start: usize = 32 - (index + 1) * 8;
            let mut chunk: [u8; 8] = [0; 8];
            chunk.copy_from_slice(&bytes[start..start + 8]);
            *limb = u64::from_be_bytes(chunk);
        }
        Self(limbs)
    }

    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out: [u8; 32] = [0; 32];
        for (index, limb) in self.0.iter().enumerate() {
            let start: usize = 32 - (index + 1) * 8;
            out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    #[must_use]
    pub const fn to_u64(self) -> Option<u64> {
        if self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0 {
            Some(self.0[0])
        } else {
            None
        }
    }

    #[must_use]
    pub fn to_usize(self) -> Option<usize> {
        self.to_u64()
            .and_then(|value: u64| usize::try_from(value).ok())
    }

    #[must_use]
    pub const fn bit(self, index: u32) -> bool {
        (self.0[(index / 64) as usize] >> (index % 64)) & 1 == 1
    }

    #[must_use]
    pub const fn is_negative(self) -> bool {
        self.bit(255)
    }

    #[must_use]
    pub fn leading_zeros(self) -> u32 {
        let mut zeros: u32 = 0;
        for limb in self.0.iter().rev() {
            if *limb == 0 {
                zeros += 64;
            } else {
                return zeros + limb.leading_zeros();
            }
        }
        zeros
    }

    #[must_use]
    pub fn bits(self) -> u32 {
        256 - self.leading_zeros()
    }

    #[must_use]
    pub fn trailing_zeros(self) -> u32 {
        let mut zeros: u32 = 0;
        for limb in &self.0 {
            if *limb == 0 {
                zeros += 64;
            } else {
                return zeros + limb.trailing_zeros();
            }
        }
        zeros
    }

    #[must_use]
    pub fn low_mask_bits(self) -> Option<u32> {
        let bits: u32 = self.bits();
        if bits > 0 && self.trailing_ones() == bits {
            Some(bits)
        } else {
            None
        }
    }

    #[must_use]
    pub fn high_mask_bits(self) -> Option<u32> {
        if self.is_zero() {
            return None;
        }
        let inverted: Self = !self;
        if inverted.is_zero() {
            return Some(256);
        }
        inverted.low_mask_bits().map(|low: u32| 256 - low)
    }

    fn trailing_ones(self) -> u32 {
        (!self).trailing_zeros()
    }

    #[must_use]
    pub fn overflowing_add(self, other: Self) -> (Self, bool) {
        let mut out: [u64; 4] = [0; 4];
        let mut carry: bool = false;
        for (index, slot) in out.iter_mut().enumerate() {
            let (sum, first) = self.0[index].overflowing_add(other.0[index]);
            let (sum, second) = sum.overflowing_add(u64::from(carry));
            *slot = sum;
            carry = first || second;
        }
        (Self(out), carry)
    }

    #[must_use]
    pub fn wrapping_add(self, other: Self) -> Self {
        self.overflowing_add(other).0
    }

    #[must_use]
    pub fn wrapping_sub(self, other: Self) -> Self {
        self.wrapping_add((!other).wrapping_add(Self::ONE))
    }

    #[must_use]
    pub fn wrapping_neg(self) -> Self {
        Self::ZERO.wrapping_sub(self)
    }

    #[must_use]
    pub fn wrapping_mul(self, other: Self) -> Self {
        let mut out: [u64; 4] = [0; 4];
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..4 - i {
                let current: u128 =
                    u128::from(out[i + j]) + u128::from(self.0[i]) * u128::from(other.0[j]) + carry;
                out[i + j] = current as u64;
                carry = current >> 64;
            }
        }
        Self(out)
    }

    #[must_use]
    pub fn div_rem(self, divisor: Self) -> (Self, Self) {
        if divisor.is_zero() {
            return (Self::ZERO, Self::ZERO);
        }
        if let (Some(a), Some(b)) = (self.to_u64(), divisor.to_u64()) {
            return (Self::from_u64(a / b), Self::from_u64(a % b));
        }
        let mut quotient: Self = Self::ZERO;
        let mut remainder: Self = Self::ZERO;
        for index in (0..self.bits()).rev() {
            remainder = remainder.shift_left(1);
            if self.bit(index) {
                remainder.0[0] |= 1;
            }
            if remainder >= divisor {
                remainder = remainder.wrapping_sub(divisor);
                quotient.0[(index / 64) as usize] |= 1 << (index % 64);
            }
        }
        (quotient, remainder)
    }

    #[must_use]
    pub fn sdiv(self, divisor: Self) -> Self {
        if divisor.is_zero() {
            return Self::ZERO;
        }
        let negative: bool = self.is_negative() != divisor.is_negative();
        let quotient: Self = self.abs().div_rem(divisor.abs()).0;
        if negative {
            quotient.wrapping_neg()
        } else {
            quotient
        }
    }

    #[must_use]
    pub fn smod(self, divisor: Self) -> Self {
        if divisor.is_zero() {
            return Self::ZERO;
        }
        let remainder: Self = self.abs().div_rem(divisor.abs()).1;
        if self.is_negative() {
            remainder.wrapping_neg()
        } else {
            remainder
        }
    }

    fn abs(self) -> Self {
        if self.is_negative() {
            self.wrapping_neg()
        } else {
            self
        }
    }

    #[must_use]
    pub fn wrapping_pow(self, exponent: Self) -> Self {
        let mut result: Self = Self::ONE;
        let mut base: Self = self;
        for index in 0..exponent.bits() {
            if exponent.bit(index) {
                result = result.wrapping_mul(base);
            }
            base = base.wrapping_mul(base);
        }
        result
    }

    #[must_use]
    pub fn shift_left(self, shift: u32) -> Self {
        if shift >= 256 {
            return Self::ZERO;
        }
        let limbs: usize = (shift / 64) as usize;
        let bits: u32 = shift % 64;
        let mut out: [u64; 4] = [0; 4];
        for index in (limbs..4).rev() {
            let source: usize = index - limbs;
            out[index] = self.0[source] << bits;
            if bits > 0 && source > 0 {
                out[index] |= self.0[source - 1] >> (64 - bits);
            }
        }
        Self(out)
    }

    #[must_use]
    pub fn shift_right(self, shift: u32) -> Self {
        if shift >= 256 {
            return Self::ZERO;
        }
        let limbs: usize = (shift / 64) as usize;
        let bits: u32 = shift % 64;
        let mut out: [u64; 4] = [0; 4];
        for (index, slot) in out.iter_mut().enumerate().take(4 - limbs) {
            let source: usize = index + limbs;
            *slot = self.0[source] >> bits;
            if bits > 0 && source + 1 < 4 {
                *slot |= self.0[source + 1] << (64 - bits);
            }
        }
        Self(out)
    }

    #[must_use]
    pub fn sar(self, shift: u32) -> Self {
        if !self.is_negative() {
            return self.shift_right(shift);
        }
        if shift >= 256 {
            return Self::MAX;
        }
        !((!self).shift_right(shift))
    }

    #[must_use]
    pub fn shift_amount(self) -> u32 {
        self.to_u64()
            .and_then(|value: u64| u32::try_from(value).ok())
            .map_or(256, |value: u32| value.min(256))
    }

    #[must_use]
    pub fn signextend(self, byte_index: Self) -> Self {
        let Some(index) = byte_index.to_u64().filter(|index: &u64| *index < 31) else {
            return self;
        };
        let bit: u32 = (index as u32) * 8 + 7;
        let mask: Self = Self::ONE.shift_left(bit + 1).wrapping_sub(Self::ONE);
        if self.bit(bit) {
            self | !mask
        } else {
            self & mask
        }
    }

    #[must_use]
    pub fn byte(self, index: Self) -> Self {
        match index.to_u64() {
            Some(position) if position < 32 => {
                Self::from_u64(u64::from(self.to_be_bytes()[position as usize]))
            }
            _ => Self::ZERO,
        }
    }

    #[must_use]
    pub fn signed_cmp(self, other: Self) -> Ordering {
        match (self.is_negative(), other.is_negative()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => self.cmp(&other),
        }
    }

    #[must_use]
    pub const fn from_bool(value: bool) -> Self {
        if value { Self::ONE } else { Self::ZERO }
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for index in (0..4).rev() {
            match self.0[index].cmp(&other.0[index]) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::ops::Not for U256 {
    type Output = Self;
    fn not(self) -> Self {
        Self([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }
}

impl std::ops::BitAnd for U256 {
    type Output = Self;
    fn bitand(self, other: Self) -> Self {
        Self([
            self.0[0] & other.0[0],
            self.0[1] & other.0[1],
            self.0[2] & other.0[2],
            self.0[3] & other.0[3],
        ])
    }
}

impl std::ops::BitOr for U256 {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self([
            self.0[0] | other.0[0],
            self.0[1] | other.0[1],
            self.0[2] | other.0[2],
            self.0[3] | other.0[3],
        ])
    }
}

impl std::ops::BitXor for U256 {
    type Output = Self;
    fn bitxor(self, other: Self) -> Self {
        Self([
            self.0[0] ^ other.0[0],
            self.0[1] ^ other.0[1],
            self.0[2] ^ other.0[2],
            self.0[3] ^ other.0[3],
        ])
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(small) = self.to_u64().filter(|value: &u64| *value < 0x1_0000) {
            return write!(formatter, "{small:#x}");
        }
        let bytes: [u8; 32] = self.to_be_bytes();
        let first: usize = bytes.iter().position(|byte: &u8| *byte != 0).unwrap_or(31);
        formatter.write_str("0x")?;
        for byte in &bytes[first..] {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::U256;

    fn hex(text: &str) -> U256 {
        let digits: String = format!("{text:0>64}");
        let mut bytes: [u8; 32] = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16).unwrap_or(0);
        }
        U256::from_be_bytes(bytes)
    }

    #[test]
    fn arithmetic_wraps_like_the_evm() {
        assert_eq!(U256::MAX.wrapping_add(U256::ONE), U256::ZERO);
        assert_eq!(U256::ZERO.wrapping_sub(U256::ONE), U256::MAX);
        assert_eq!(
            hex("100000000000000000000000000000000")
                .wrapping_mul(hex("100000000000000000000000000000000")),
            U256::ZERO
        );
        assert_eq!(
            hex("ffffffffffffffffffffffffffffffff").wrapping_mul(hex("2")),
            hex("1fffffffffffffffffffffffffffffffe")
        );
        assert_eq!(
            U256::from_u64(7).div_rem(U256::ZERO),
            (U256::ZERO, U256::ZERO)
        );
        assert_eq!(
            hex("1000000000000000000000000000000000000000000000000").div_rem(hex("100000000")),
            (hex("10000000000000000000000000000000000000000"), U256::ZERO)
        );
        assert_eq!(
            U256::from_u64(2).wrapping_pow(U256::from_u64(255)),
            hex("8").shift_left(252)
        );
    }

    #[test]
    fn signed_operations_follow_twos_complement() {
        let minus_eight: U256 = U256::from_u64(8).wrapping_neg();
        assert_eq!(
            minus_eight.sdiv(U256::from_u64(2)),
            U256::from_u64(4).wrapping_neg()
        );
        assert_eq!(
            minus_eight.smod(U256::from_u64(3)),
            U256::from_u64(2).wrapping_neg()
        );
        assert_eq!(
            minus_eight.sar(U256::from_u64(1).shift_amount()),
            U256::from_u64(4).wrapping_neg()
        );
        assert_eq!(U256::from_u64(0xff).signextend(U256::ZERO), U256::MAX);
        assert_eq!(
            U256::from_u64(0x7f).signextend(U256::ZERO),
            U256::from_u64(0x7f)
        );
        assert_eq!(
            hex("ab").shift_left(248).byte(U256::ZERO),
            U256::from_u64(0xab)
        );
    }

    #[test]
    fn masks_are_recognised() {
        assert_eq!(
            hex("ffffffffffffffffffffffffffffffffffffffff").low_mask_bits(),
            Some(160)
        );
        assert_eq!(hex("ffffffff").shift_left(224).high_mask_bits(), Some(32));
        assert_eq!(hex("ff00").low_mask_bits(), None);
        assert_eq!(U256::MAX.high_mask_bits(), Some(256));
        assert_eq!(hex("ff").high_mask_bits(), None);
    }
}
