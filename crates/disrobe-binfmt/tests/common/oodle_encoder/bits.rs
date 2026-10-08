#[derive(Debug, Default, Clone)]
pub struct MsbWriter {
    bytes: Vec<u8>,
    acc: u64,
    pending: u32,
}

impl MsbWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, value: u32, bits: u32) {
        assert!(bits <= 32, "at most 32 bits per write");
        if bits == 0 {
            return;
        }
        assert!(
            bits == 32 || value >> bits == 0,
            "value {value:#x} does not fit in {bits} bits"
        );
        self.acc = (self.acc << bits) | u64::from(value);
        self.pending += bits;
        while self.pending >= 8 {
            self.pending -= 8;
            self.bytes.push((self.acc >> self.pending) as u8);
        }
        self.acc &= (1u64 << self.pending) - 1;
    }

    pub fn bit(&mut self, set: bool) {
        self.put(u32::from(set), 1);
    }

    pub const fn bit_len(&self) -> usize {
        self.bytes.len() * 8 + self.pending as usize
    }

    pub fn finish(mut self) -> Vec<u8> {
        if self.pending > 0 {
            self.bytes.push((self.acc << (8 - self.pending)) as u8);
        }
        self.bytes
    }

    pub fn gamma(&mut self, value: u32) {
        let shifted: u32 = value + 2;
        let width: u32 = 32 - shifted.leading_zeros();
        let zeros: u32 = width - 2;
        self.put(0, zeros);
        self.put(shifted, width);
    }

    pub fn unary(&mut self, value: u32) {
        let mut left: u32 = value;
        while left >= 32 {
            self.put(0, 32);
            left -= 32;
        }
        self.put(1, left + 1);
    }

    pub fn fluff(&mut self, num_symbols: u32, value: u32) {
        if num_symbols == 256 {
            assert_eq!(value, 0, "a full alphabet carries no range values");
            return;
        }
        let x: u32 = 2 * (257 - num_symbols).min(num_symbols);
        assert!(
            value < x,
            "range value count {value} too large for {num_symbols} symbols"
        );
        let y: u32 = 32 - (x - 1).leading_zeros();
        let z: u32 = (1 << y) - x;
        if value < z {
            self.put(value, y - 1);
        } else {
            self.put(value + z, y);
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct LsbWriter {
    bytes: Vec<u8>,
    acc: u64,
    pending: u32,
}

impl LsbWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, value: u32, bits: u32) {
        assert!(bits <= 32, "at most 32 bits per write");
        if bits == 0 {
            return;
        }
        assert!(
            bits == 32 || value >> bits == 0,
            "value {value:#x} does not fit in {bits} bits"
        );
        self.acc |= u64::from(value) << self.pending;
        self.pending += bits;
        while self.pending >= 8 {
            self.bytes.push(self.acc as u8);
            self.acc >>= 8;
            self.pending -= 8;
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        if self.pending > 0 {
            self.bytes.push(self.acc as u8);
        }
        self.bytes
    }
}

pub const fn unzigzag(delta: i32) -> u32 {
    if delta >= 0 {
        (delta as u32) * 2
    } else {
        (-delta as u32) * 2 - 1
    }
}

pub const fn bit_length(value: u32) -> u32 {
    32 - value.leading_zeros()
}

pub const fn reverse_bits(code: u32, len: u32) -> u32 {
    code.reverse_bits() >> (32 - len)
}
