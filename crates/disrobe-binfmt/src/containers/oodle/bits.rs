use super::OodleError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    Forward,
    Backward,
}

#[derive(Debug, Clone)]
pub(super) struct MsbReader<'a> {
    data: &'a [u8],
    direction: Direction,
    loaded: usize,
    buf: u64,
    avail: u32,
}

impl<'a> MsbReader<'a> {
    pub(super) fn new(data: &'a [u8], direction: Direction) -> Self {
        let mut reader: Self = Self {
            data,
            direction,
            loaded: 0,
            buf: 0,
            avail: 0,
        };
        reader.refill();
        reader
    }

    pub(super) fn forward(data: &'a [u8]) -> Self {
        Self::new(data, Direction::Forward)
    }

    pub(super) fn backward(data: &'a [u8]) -> Self {
        Self::new(data, Direction::Backward)
    }

    fn byte(&self, index: usize) -> u8 {
        match self.direction {
            Direction::Forward => self.data.get(index).copied().unwrap_or(0),
            Direction::Backward => self
                .data
                .len()
                .checked_sub(index + 1)
                .and_then(|at: usize| self.data.get(at).copied())
                .unwrap_or(0),
        }
    }

    fn refill(&mut self) {
        while self.avail <= 56 {
            let byte: u8 = self.byte(self.loaded);
            self.loaded += 1;
            self.buf |= u64::from(byte) << (56 - self.avail);
            self.avail += 8;
        }
    }

    pub(super) const fn peek(&self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            (self.buf >> (64 - n)) as u32
        }
    }

    pub(super) fn skip(&mut self, n: u32) {
        self.buf <<= n;
        self.avail -= n;
        self.refill();
    }

    pub(super) fn read(&mut self, n: u32) -> u32 {
        let value: u32 = self.peek(n);
        self.skip(n);
        value
    }

    pub(super) fn bit(&mut self) -> bool {
        self.read(1) == 1
    }

    pub(super) const fn leading_zeros(&self) -> u32 {
        self.buf.leading_zeros()
    }

    pub(super) const fn consumed_bits(&self) -> usize {
        self.loaded * 8 - self.avail as usize
    }

    pub(super) const fn consumed_bytes(&self) -> usize {
        self.consumed_bits().div_ceil(8)
    }

    pub(super) const fn within(&self) -> bool {
        self.consumed_bits() <= self.data.len() * 8
    }

    pub(super) fn gamma(&mut self, max_zeros: u32) -> Result<u32, OodleError> {
        let zeros: u32 = self.leading_zeros();
        if zeros > max_zeros {
            return Err(OodleError::Malformed("gamma code run is too long"));
        }
        Ok(self.read(2 * zeros + 2) - 2)
    }

    pub(super) fn gamma_x(&mut self, forced: u32, max_zeros: u32) -> Result<u32, OodleError> {
        let zeros: u32 = self.leading_zeros();
        if zeros > max_zeros {
            return Err(OodleError::Malformed("extended gamma code run is too long"));
        }
        let raw: u32 = self.read(zeros + forced + 1);
        Ok(raw + (zeros << forced) - (1 << forced))
    }

    pub(super) fn unary(&mut self) -> Result<u32, OodleError> {
        let mut count: u32 = 0;
        loop {
            let zeros: u32 = self.leading_zeros().min(32);
            if zeros < 32 {
                self.skip(zeros + 1);
                count += zeros;
                break;
            }
            self.skip(32);
            count += 32;
            if !self.within() || count > MAX_UNARY {
                return Err(OodleError::Malformed("unary code runs past its region"));
            }
        }
        if !self.within() || count > MAX_UNARY {
            return Err(OodleError::Malformed("unary code runs past its region"));
        }
        Ok(count)
    }

    pub(super) fn fluff(&mut self, num_symbols: u32) -> u32 {
        if num_symbols == 256 {
            return 0;
        }
        let x: u32 = 2 * (257 - num_symbols).min(num_symbols);
        let y: u32 = 32 - (x - 1).leading_zeros();
        let v: u32 = self.peek(y);
        let z: u32 = (1 << y) - x;
        if (v >> 1) >= z {
            self.skip(y);
            v - z
        } else {
            self.skip(y - 1);
            v >> 1
        }
    }
}

const MAX_UNARY: u32 = 255;

#[derive(Debug, Clone)]
pub(super) struct LsbReader<'a> {
    data: &'a [u8],
    direction: Direction,
    loaded: usize,
    buf: u64,
    avail: u32,
}

impl<'a> LsbReader<'a> {
    pub(super) fn new(data: &'a [u8], direction: Direction) -> Self {
        let mut reader: Self = Self {
            data,
            direction,
            loaded: 0,
            buf: 0,
            avail: 0,
        };
        reader.refill();
        reader
    }

    pub(super) fn forward(data: &'a [u8]) -> Self {
        Self::new(data, Direction::Forward)
    }

    pub(super) fn backward(data: &'a [u8]) -> Self {
        Self::new(data, Direction::Backward)
    }

    fn byte(&self, index: usize) -> u8 {
        match self.direction {
            Direction::Forward => self.data.get(index).copied().unwrap_or(0),
            Direction::Backward => self
                .data
                .len()
                .checked_sub(index + 1)
                .and_then(|at: usize| self.data.get(at).copied())
                .unwrap_or(0),
        }
    }

    fn refill(&mut self) {
        while self.avail <= 56 {
            let byte: u8 = self.byte(self.loaded);
            self.loaded += 1;
            self.buf |= u64::from(byte) << self.avail;
            self.avail += 8;
        }
    }

    pub(super) const fn peek(&self, n: u32) -> u32 {
        (self.buf & ((1u64 << n) - 1)) as u32
    }

    pub(super) fn skip(&mut self, n: u32) {
        self.buf >>= n;
        self.avail -= n;
        self.refill();
    }

    pub(super) fn read(&mut self, n: u32) -> u32 {
        let value: u32 = self.peek(n);
        self.skip(n);
        value
    }

    pub(super) const fn consumed_bits(&self) -> usize {
        self.loaded * 8 - self.avail as usize
    }

    pub(super) const fn consumed_bytes(&self) -> usize {
        self.consumed_bits().div_ceil(8)
    }
}

pub(super) const fn zigzag(value: u32) -> i32 {
    ((value >> 1) as i32) ^ -((value & 1) as i32)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn msb_readers_take_bits_from_the_top_in_both_directions() {
        let data: [u8; 3] = [0b1010_0000, 0xFF, 0b0000_0001];
        let mut forward: MsbReader<'_> = MsbReader::forward(&data);
        assert_eq!(forward.read(3), 0b101);
        assert_eq!(forward.consumed_bits(), 3);
        assert_eq!(forward.consumed_bytes(), 1);
        let mut backward: MsbReader<'_> = MsbReader::backward(&data);
        assert_eq!(backward.read(8), 1);
        assert_eq!(backward.read(4), 0xF);
        assert_eq!(backward.consumed_bytes(), 2);
    }

    #[test]
    fn lsb_readers_take_bits_from_the_bottom_in_both_directions() {
        let data: [u8; 2] = [0b0000_0110, 0b1000_0000];
        let mut forward: LsbReader<'_> = LsbReader::forward(&data);
        assert_eq!(forward.read(3), 0b110);
        let mut backward: LsbReader<'_> = LsbReader::backward(&data);
        assert_eq!(backward.read(8), 0b1000_0000);
        assert_eq!(backward.read(3), 0b110);
    }

    #[test]
    fn primitive_codes_follow_their_definitions() {
        let mut gamma: MsbReader<'_> = MsbReader::forward(&[0b0010_1000]);
        assert_eq!(gamma.gamma(7).unwrap(), 8);
        let mut unary: MsbReader<'_> = MsbReader::forward(&[0b0001_1000, 0, 0, 0, 0, 0x80]);
        assert_eq!(unary.unary().unwrap(), 3);
        assert_eq!(unary.unary().unwrap(), 0);
        assert_eq!(unary.unary().unwrap(), 35);
        assert!(MsbReader::forward(&[0, 0]).unary().is_err());
        assert_eq!(zigzag(0), 0);
        assert_eq!(zigzag(1), -1);
        assert_eq!(zigzag(2), 1);
        assert_eq!(zigzag(3), -2);
        let mut fluff: MsbReader<'_> = MsbReader::forward(&[0xFF]);
        assert_eq!(fluff.fluff(256), 0);
        assert_eq!(fluff.consumed_bits(), 0);
    }
}
