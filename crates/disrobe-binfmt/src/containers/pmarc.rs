use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmMethod {
    Pm1,
    Pm2,
}

impl PmMethod {
    const fn tag(self) -> &'static str {
        match self {
            Self::Pm1 => "-pm1-",
            Self::Pm2 => "-pm2-",
        }
    }
}

const PM1_RING_SIZE: usize = 16_384;
const PM2_RING_SIZE: usize = 8_192;
const PM1_MAX_BYTE_BLOCK: usize = 216;
const PM1_MAX_COPY: usize = 244;
const PM2_MAX_COPY: usize = 256;
const PM1_MAX_COMMAND_OUTPUT: usize = PM1_MAX_BYTE_BLOCK + PM1_MAX_COPY;
const PM1_TREE_WALK_LIMIT: usize = 5;
const PM1_MAX_ZERO_FILL_BITS: u64 = 2_424;
const PM2_CODE_TREE_ELEMENTS: usize = 65;
const PM2_OFFSET_TREE_ELEMENTS: usize = 17;
const PM2_MAX_CODES: usize = 29;
const PM2_MAX_OFFSETS: usize = 8;
const TREE_LEAF: u8 = 0x80;

struct VariableLength {
    offset: u32,
    bits: u32,
}

const PM1_COPY_RANGES: [VariableLength; 15] = [
    VariableLength { offset: 0, bits: 6 },
    VariableLength {
        offset: 64,
        bits: 8,
    },
    VariableLength { offset: 0, bits: 6 },
    VariableLength {
        offset: 64,
        bits: 9,
    },
    VariableLength {
        offset: 576,
        bits: 11,
    },
    VariableLength {
        offset: 2624,
        bits: 13,
    },
    VariableLength {
        offset: 64,
        bits: 8,
    },
    VariableLength {
        offset: 576,
        bits: 8,
    },
    VariableLength {
        offset: 576,
        bits: 9,
    },
    VariableLength {
        offset: 576,
        bits: 10,
    },
    VariableLength {
        offset: 2624,
        bits: 8,
    },
    VariableLength {
        offset: 2624,
        bits: 9,
    },
    VariableLength {
        offset: 2624,
        bits: 10,
    },
    VariableLength {
        offset: 2624,
        bits: 11,
    },
    VariableLength {
        offset: 2624,
        bits: 12,
    },
];

const PM1_BYTE_RANGES: [VariableLength; 6] = [
    VariableLength { offset: 0, bits: 4 },
    VariableLength {
        offset: 16,
        bits: 4,
    },
    VariableLength {
        offset: 32,
        bits: 5,
    },
    VariableLength {
        offset: 64,
        bits: 6,
    },
    VariableLength {
        offset: 128,
        bits: 6,
    },
    VariableLength {
        offset: 192,
        bits: 6,
    },
];

const PM1_BYTE_DECODE_TREES: [[u8; 5]; 32] = [
    [0x12, 0x2d, 0xef, 0x1c, 0xab],
    [0x12, 0x23, 0xde, 0xab, 0xcf],
    [0x12, 0x2c, 0xd2, 0xab, 0xef],
    [0x12, 0xa2, 0xd2, 0xbc, 0xef],
    [0x12, 0xa2, 0xc2, 0xbd, 0xef],
    [0x12, 0xa2, 0xcd, 0xb1, 0xef],
    [0x12, 0xab, 0x12, 0xcd, 0xef],
    [0x12, 0xab, 0x1d, 0xc1, 0xef],
    [0x12, 0xab, 0xc1, 0xd1, 0xef],
    [0xa1, 0x12, 0x2c, 0xde, 0xbf],
    [0xa1, 0x1d, 0x1c, 0xb1, 0xef],
    [0xa1, 0x12, 0x2d, 0xef, 0xbc],
    [0xa1, 0x12, 0xb2, 0xde, 0xcf],
    [0xa1, 0x12, 0xbc, 0xd1, 0xef],
    [0xa1, 0x1c, 0xb1, 0xd1, 0xef],
    [0xa1, 0xb1, 0x12, 0xcd, 0xef],
    [0xa1, 0xb1, 0xc1, 0xd1, 0xef],
    [0x12, 0x1c, 0xde, 0xab, 0x00],
    [0x12, 0xa2, 0xcd, 0xbe, 0x00],
    [0x12, 0xab, 0xc1, 0xde, 0x00],
    [0xa1, 0x1d, 0x1c, 0xbe, 0x00],
    [0xa1, 0x12, 0xbc, 0xde, 0x00],
    [0xa1, 0x1c, 0xb1, 0xde, 0x00],
    [0xa1, 0xb1, 0xc1, 0xde, 0x00],
    [0x1d, 0x1c, 0xab, 0x00, 0x00],
    [0x1c, 0xa1, 0xbd, 0x00, 0x00],
    [0x12, 0xab, 0xcd, 0x00, 0x00],
    [0xa1, 0x1c, 0xbd, 0x00, 0x00],
    [0xa1, 0xb1, 0xcd, 0x00, 0x00],
    [0xa1, 0xbc, 0x00, 0x00, 0x00],
    [0xab, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00],
];

const PM2_HISTORY_DECODE: [VariableLength; 8] = [
    VariableLength { offset: 0, bits: 3 },
    VariableLength { offset: 8, bits: 3 },
    VariableLength {
        offset: 16,
        bits: 4,
    },
    VariableLength {
        offset: 32,
        bits: 5,
    },
    VariableLength {
        offset: 64,
        bits: 5,
    },
    VariableLength {
        offset: 96,
        bits: 5,
    },
    VariableLength {
        offset: 128,
        bits: 6,
    },
    VariableLength {
        offset: 192,
        bits: 6,
    },
];

const PM2_COPY_DECODE: [VariableLength; 6] = [
    VariableLength {
        offset: 17,
        bits: 3,
    },
    VariableLength {
        offset: 25,
        bits: 3,
    },
    VariableLength {
        offset: 33,
        bits: 5,
    },
    VariableLength {
        offset: 65,
        bits: 6,
    },
    VariableLength {
        offset: 129,
        bits: 7,
    },
    VariableLength {
        offset: 256,
        bits: 0,
    },
];

struct BitReader<'a> {
    src: &'a [u8],
    pos: usize,
    accumulator: u64,
    bits: u32,
    consumed_bits: u64,
    pad_bits: u64,
    method: PmMethod,
    allow_zero_fill: bool,
}

impl<'a> BitReader<'a> {
    const fn new(src: &'a [u8], method: PmMethod, allow_zero_fill: bool) -> Self {
        Self {
            src,
            pos: 0,
            accumulator: 0,
            bits: 0,
            consumed_bits: 0,
            pad_bits: 0,
            method,
            allow_zero_fill,
        }
    }

    fn read(&mut self, count: u32) -> Result<u32> {
        if count == 0 {
            return Ok(0);
        }
        if count > 32 {
            return Err(Error::Decompression(
                "pmarc: bit request exceeds the reader width".to_owned(),
            ));
        }
        while self.bits < count {
            let byte: u8 = if let Some(&value) = self.src.get(self.pos) {
                self.pos = self.pos.checked_add(1).ok_or_else(|| {
                    Error::Decompression("pmarc: compressed input position overflow".to_owned())
                })?;
                value
            } else {
                if !self.allow_zero_fill {
                    return Err(Error::Decompression(format!(
                        "pmarc: {} compressed body ended before the decoded stream",
                        self.method.tag()
                    )));
                }
                self.pad_bits = self.pad_bits.checked_add(8).ok_or_else(|| {
                    Error::Decompression("pmarc: zero-fill work counter overflow".to_owned())
                })?;
                if self.pad_bits > PM1_MAX_ZERO_FILL_BITS {
                    return Err(Error::Decompression(format!(
                        "pmarc: -pm1- zero-fill work exceeds the {PM1_MAX_ZERO_FILL_BITS}-bit final-command ceiling"
                    )));
                }
                0
            };
            self.accumulator |= u64::from(byte) << (56 - self.bits);
            self.bits = self.bits.checked_add(8).ok_or_else(|| {
                Error::Decompression("pmarc: buffered bit count overflow".to_owned())
            })?;
        }
        let value: u32 = u32::try_from(self.accumulator >> (64 - u64::from(count))).map_err(
            |_e: std::num::TryFromIntError| {
                Error::Decompression("pmarc: bit window exceeds u32".to_owned())
            },
        )?;
        self.accumulator <<= count;
        self.bits -= count;
        self.consumed_bits = self
            .consumed_bits
            .checked_add(u64::from(count))
            .ok_or_else(|| Error::Decompression("pmarc: consumed bit count overflow".to_owned()))?;
        Ok(value)
    }

    fn read_variable(&mut self, table: &[VariableLength], index: usize) -> Result<u32> {
        let entry: &VariableLength = table.get(index).ok_or_else(|| {
            Error::Decompression(format!(
                "pmarc: variable-length index {index} exceeds table length {}",
                table.len()
            ))
        })?;
        let value: u32 = self.read(entry.bits)?;
        entry
            .offset
            .checked_add(value)
            .ok_or_else(|| Error::Decompression("pmarc: variable-length value overflow".to_owned()))
    }

    fn unread_bits(&self) -> Result<u64> {
        let source_len: u64 =
            u64::try_from(self.src.len()).map_err(|_error: std::num::TryFromIntError| {
                Error::Decompression("pmarc: compressed input length exceeds u64".to_owned())
            })?;
        let available: u64 = source_len.checked_mul(8).ok_or_else(|| {
            Error::Decompression("pmarc: compressed input bit length overflow".to_owned())
        })?;
        match self.consumed_bits.cmp(&available) {
            std::cmp::Ordering::Less => {
                available.checked_sub(self.consumed_bits).ok_or_else(|| {
                    Error::Decompression("pmarc: unread bit count underflow".to_owned())
                })
            }
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => Ok(0),
        }
    }
}

struct HistoryList {
    prev: [u8; 256],
    next: [u8; 256],
    head: u8,
}

impl HistoryList {
    fn new() -> Self {
        let mut prev: [u8; 256] = [0; 256];
        let mut next: [u8; 256] = [0; 256];
        for code in u8::MIN..=u8::MAX {
            let index: usize = usize::from(code);
            prev[index] = code.wrapping_add(1);
            next[index] = code.wrapping_sub(1);
        }
        prev[0x7f] = 0x00;
        next[0x00] = 0x7f;
        prev[0x1f] = 0xa0;
        next[0xa0] = 0x1f;
        prev[0xdf] = 0x80;
        next[0x80] = 0xdf;
        prev[0x9f] = 0xe0;
        next[0xe0] = 0x9f;
        prev[0xff] = 0x20;
        next[0x20] = 0xff;
        Self {
            prev,
            next,
            head: 0x20,
        }
    }

    fn find(&self, count: u8) -> u8 {
        let mut code: u8 = self.head;
        if count < 128 {
            for _ in 0..count {
                code = self.prev[usize::from(code)];
            }
        } else {
            for _ in 0..(256u16 - u16::from(count)) {
                code = self.next[usize::from(code)];
            }
        }
        code
    }

    fn update(&mut self, byte: u8) {
        if self.head == byte {
            return;
        }
        let slot: usize = usize::from(byte);
        let node_prev: u8 = self.prev[slot];
        let node_next: u8 = self.next[slot];
        self.prev[usize::from(node_next)] = node_prev;
        self.next[usize::from(node_prev)] = node_next;
        let head: u8 = self.head;
        let head_next: u8 = self.next[usize::from(head)];
        self.prev[slot] = head;
        self.next[slot] = head_next;
        self.prev[usize::from(head_next)] = byte;
        self.next[usize::from(head)] = byte;
        self.head = byte;
    }
}

fn decoded_count(value: u32, offset: usize, method: PmMethod) -> Result<usize> {
    let value: usize = usize::try_from(value).map_err(|_error: std::num::TryFromIntError| {
        Error::Decompression(format!(
            "pmarc: {} decoded count exceeds usize",
            method.tag()
        ))
    })?;
    value.checked_add(offset).ok_or_else(|| {
        Error::Decompression(format!("pmarc: {} decoded count overflow", method.tag()))
    })
}

fn allocate_ring(size: usize, fill: u8, method: PmMethod) -> Result<Box<[u8]>> {
    let mut ring: Vec<u8> = Vec::new();
    ring.try_reserve_exact(size)
        .map_err(|error: std::collections::TryReserveError| {
            Error::Decompression(format!(
                "pmarc: {} ring allocation failed: {error}",
                method.tag()
            ))
        })?;
    ring.resize(size, fill);
    Ok(ring.into_boxed_slice())
}

fn allocate_output(declared: usize, method: PmMethod) -> Result<Vec<u8>> {
    let declared_u64: u64 =
        u64::try_from(declared).map_err(|_error: std::num::TryFromIntError| {
            Error::Decompression("pmarc: declared output exceeds u64".to_owned())
        })?;
    let capacity: usize = crate::quota::bounded_prealloc(declared_u64);
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve_exact(capacity)
        .map_err(|error: std::collections::TryReserveError| {
            Error::Decompression(format!(
                "pmarc: {} output allocation failed: {error}",
                method.tag()
            ))
        })?;
    Ok(out)
}

fn reserve_output(out: &mut Vec<u8>, additional: usize, method: PmMethod) -> Result<()> {
    let _: usize = out.len().checked_add(additional).ok_or_else(|| {
        Error::Decompression(format!("pmarc: {} output length overflow", method.tag()))
    })?;
    out.try_reserve(additional)
        .map_err(|error: std::collections::TryReserveError| {
            Error::Decompression(format!(
                "pmarc: {} output allocation failed: {error}",
                method.tag()
            ))
        })
}

struct Pm1Decoder {
    ring: Box<[u8]>,
    ring_pos: usize,
    history: HistoryList,
    tree: &'static [u8; 5],
}

impl Pm1Decoder {
    fn new() -> Result<Self> {
        Ok(Self {
            ring: allocate_ring(PM1_RING_SIZE, 0, PmMethod::Pm1)?,
            ring_pos: 0,
            history: HistoryList::new(),
            tree: &PM1_BYTE_DECODE_TREES[31],
        })
    }

    fn output_byte(&mut self, out: &mut Vec<u8>, byte: u8) -> Result<()> {
        self.ring[self.ring_pos] = byte;
        self.ring_pos = self.ring_pos.checked_add(1).ok_or_else(|| {
            Error::Decompression("pmarc: -pm1- ring position overflow".to_owned())
        })? % PM1_RING_SIZE;
        self.history.update(byte);
        out.push(byte);
        Ok(())
    }

    fn read_byte_decode_index(&self, reader: &mut BitReader<'_>) -> Result<usize> {
        if self.tree[0] == 0 {
            return Ok(0);
        }
        let mut node: usize = 0;
        for _ in 0..PM1_TREE_WALK_LIMIT {
            let entry: u8 = *self.tree.get(node).ok_or_else(|| {
                Error::Decompression("pmarc: -pm1- byte tree walks past its node table".to_owned())
            })?;
            let bit: u32 = reader.read(1)?;
            let child: usize = if bit == 0 {
                usize::from(entry >> 4)
            } else {
                usize::from(entry & 0x0f)
            };
            if child >= 10 {
                return Ok(child - 10);
            }
            if child == 0 {
                return Err(Error::Decompression(
                    "pmarc: -pm1- byte tree contains a zero-offset node".to_owned(),
                ));
            }
            node = node.checked_add(child).ok_or_else(|| {
                Error::Decompression("pmarc: -pm1- byte tree position overflow".to_owned())
            })?;
        }
        Err(Error::Decompression(
            "pmarc: -pm1- byte tree exceeds its depth limit".to_owned(),
        ))
    }

    fn read_byte(&self, reader: &mut BitReader<'_>) -> Result<u8> {
        let index: usize = self.read_byte_decode_index(reader)?;
        let count: u32 = reader.read_variable(&PM1_BYTE_RANGES, index)?;
        let count: u8 = u8::try_from(count).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("pmarc: -pm1- history distance exceeds 255".to_owned())
        })?;
        Ok(self.history.find(count))
    }

    fn read_copy_byte_count(reader: &mut BitReader<'_>) -> Result<usize> {
        let first: u32 = reader.read(2)?;
        if first < 3 {
            return decoded_count(first, 3, PmMethod::Pm1);
        }
        let second: u32 = reader.read(3)?;
        match second {
            0..=4 => decoded_count(second, 6, PmMethod::Pm1),
            5 => decoded_count(reader.read(2)?, 11, PmMethod::Pm1),
            6 => decoded_count(reader.read(3)?, 15, PmMethod::Pm1),
            _ => {
                let third: u32 = reader.read(6)?;
                match third {
                    0..=61 => decoded_count(third, 23, PmMethod::Pm1),
                    62 => decoded_count(reader.read(5)?, 85, PmMethod::Pm1),
                    _ => decoded_count(reader.read(7)?, 117, PmMethod::Pm1),
                }
            }
        }
    }

    fn read_byte_block_count(reader: &mut BitReader<'_>) -> Result<usize> {
        let first: u32 = reader.read(2)?;
        if first < 3 {
            return decoded_count(first, 1, PmMethod::Pm1);
        }
        let second: u32 = reader.read(3)?;
        if second < 7 {
            return decoded_count(second, 4, PmMethod::Pm1);
        }
        let third: u32 = reader.read(4)?;
        match third {
            0..=13 => decoded_count(third, 11, PmMethod::Pm1),
            14 => decoded_count(reader.read(6)?, 25, PmMethod::Pm1),
            _ => decoded_count(reader.read(7)?, 89, PmMethod::Pm1),
        }
    }

    fn read_bit_after_threshold(
        reader: &mut BitReader<'_>,
        produced: u64,
        threshold: u64,
        default: u32,
    ) -> Result<u32> {
        if produced >= threshold {
            reader.read(1)
        } else {
            Ok(default)
        }
    }

    fn read_copy_type_range(reader: &mut BitReader<'_>, produced: u64) -> Result<usize> {
        if reader.read(1)? == 0 {
            if Self::read_bit_after_threshold(reader, produced, 576, 0)? != 0 {
                return Ok(4);
            }
            return usize::try_from(Self::read_bit_after_threshold(reader, produced, 64, 0)?)
                .map_err(|_error: std::num::TryFromIntError| {
                    Error::Decompression("pmarc: -pm1- copy range exceeds usize".to_owned())
                });
        }
        if Self::read_bit_after_threshold(reader, produced, 64, 1)? == 0 {
            return Ok(3);
        }
        if Self::read_bit_after_threshold(reader, produced, 2624, 1)? != 0 {
            return Ok(2);
        }
        Ok(5)
    }

    const fn narrow_range(range_index: usize, produced: u64) -> usize {
        match range_index {
            3 if produced < 320 => 6,
            4 if produced < 832 => 7,
            4 if produced < 1088 => 8,
            4 if produced < 1600 => 9,
            5 if produced < 2880 => 10,
            5 if produced < 3136 => 11,
            5 if produced < 3648 => 12,
            5 if produced < 4672 => 13,
            5 if produced < 6720 => 14,
            _ => range_index,
        }
    }

    fn read_copy_command(&mut self, reader: &mut BitReader<'_>, out: &mut Vec<u8>) -> Result<()> {
        let produced: u64 =
            u64::try_from(out.len()).map_err(|_error: std::num::TryFromIntError| {
                Error::Decompression("pmarc: -pm1- output length exceeds u64".to_owned())
            })?;
        let range_index: usize = Self::read_copy_type_range(reader, produced)?;
        let count: usize = if range_index < 2 {
            2
        } else {
            Self::read_copy_byte_count(reader)?
        };
        if count > PM1_MAX_COPY {
            return Err(Error::Decompression(format!(
                "pmarc: -pm1- copy length {count} exceeds the {PM1_MAX_COPY}-byte ceiling"
            )));
        }
        let distance: u64 = u64::from(
            reader.read_variable(&PM1_COPY_RANGES, Self::narrow_range(range_index, produced))?,
        );
        if distance >= produced {
            return Err(Error::Decompression(format!(
                "pmarc: -pm1- copy distance {distance} exceeds the {produced} byte(s) produced"
            )));
        }
        let distance: usize =
            usize::try_from(distance).map_err(|_e: std::num::TryFromIntError| {
                Error::Decompression("pmarc: -pm1- copy distance exceeds usize".to_owned())
            })?;
        reserve_output(out, count, PmMethod::Pm1)?;
        let mut source: usize = self
            .ring_pos
            .checked_add(PM1_RING_SIZE)
            .and_then(|value: usize| value.checked_sub(distance))
            .and_then(|value: usize| value.checked_sub(1))
            .ok_or_else(|| {
                Error::Decompression("pmarc: -pm1- history position overflow".to_owned())
            })?
            % PM1_RING_SIZE;
        for _ in 0..count {
            let byte: u8 = self.ring[source];
            self.output_byte(out, byte)?;
            source = source.checked_add(1).ok_or_else(|| {
                Error::Decompression("pmarc: -pm1- history position overflow".to_owned())
            })? % PM1_RING_SIZE;
        }
        Ok(())
    }

    fn read_byte_block(&mut self, reader: &mut BitReader<'_>, out: &mut Vec<u8>) -> Result<()> {
        let block_len: usize = Self::read_byte_block_count(reader)?;
        if block_len == 0 || block_len > PM1_MAX_BYTE_BLOCK {
            return Err(Error::Decompression(format!(
                "pmarc: -pm1- byte block length {block_len} is outside 1..={PM1_MAX_BYTE_BLOCK}"
            )));
        }
        reserve_output(out, block_len, PmMethod::Pm1)?;
        for _ in 0..block_len {
            let byte: u8 = self.read_byte(reader)?;
            self.output_byte(out, byte)?;
        }
        if block_len == PM1_MAX_BYTE_BLOCK {
            return Ok(());
        }
        self.read_copy_command(reader, out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pm2RebuildState {
    Unbuilt,
    Build1,
    Build2,
    Build3,
    Continuing,
}

impl Pm2RebuildState {
    const fn interval(self) -> u64 {
        match self {
            Self::Unbuilt | Self::Build1 => 1024,
            Self::Build2 => 2048,
            Self::Build3 | Self::Continuing => 4096,
        }
    }
}

struct Pm2Decoder {
    ring: Box<[u8]>,
    ring_pos: usize,
    history: HistoryList,
    code_tree: [u8; PM2_CODE_TREE_ELEMENTS],
    offset_tree: [u8; PM2_OFFSET_TREE_ELEMENTS],
    need_offset_tree: bool,
    state: Pm2RebuildState,
    rebuild_remaining: u64,
    rebuild_pending: bool,
}

impl Pm2Decoder {
    fn new() -> Result<Self> {
        Ok(Self {
            ring: allocate_ring(PM2_RING_SIZE, b' ', PmMethod::Pm2)?,
            ring_pos: 0,
            history: HistoryList::new(),
            code_tree: [TREE_LEAF; PM2_CODE_TREE_ELEMENTS],
            offset_tree: [TREE_LEAF; PM2_OFFSET_TREE_ELEMENTS],
            need_offset_tree: false,
            state: Pm2RebuildState::Unbuilt,
            rebuild_remaining: Pm2RebuildState::Unbuilt.interval(),
            rebuild_pending: true,
        })
    }

    fn output_byte(&mut self, out: &mut Vec<u8>, byte: u8) -> Result<()> {
        self.ring[self.ring_pos] = byte;
        self.ring_pos = self.ring_pos.checked_add(1).ok_or_else(|| {
            Error::Decompression("pmarc: -pm2- ring position overflow".to_owned())
        })? % PM2_RING_SIZE;
        self.history.update(byte);
        out.push(byte);
        self.rebuild_remaining = self.rebuild_remaining.checked_sub(1).ok_or_else(|| {
            Error::Decompression("pmarc: -pm2- rebuild work counter underflow".to_owned())
        })?;
        if self.rebuild_remaining == 0 {
            self.rebuild_pending = true;
            self.rebuild_remaining = self.state.interval();
        }
        Ok(())
    }

    fn read_from_tree(reader: &mut BitReader<'_>, tree: &[u8]) -> Result<u8> {
        let mut code: u8 = *tree
            .first()
            .ok_or_else(|| Error::Decompression("pmarc: -pm2- tree has no root node".to_owned()))?;
        let mut steps: usize = 0;
        while code & TREE_LEAF == 0 {
            steps = steps.checked_add(1).ok_or_else(|| {
                Error::Decompression("pmarc: -pm2- tree walk count overflow".to_owned())
            })?;
            if steps > tree.len() {
                return Err(Error::Decompression(
                    "pmarc: -pm2- tree walk exceeds its node count".to_owned(),
                ));
            }
            let bit: u32 = reader.read(1)?;
            let bit: usize =
                usize::try_from(bit).map_err(|_error: std::num::TryFromIntError| {
                    Error::Decompression("pmarc: -pm2- tree bit exceeds usize".to_owned())
                })?;
            let slot: usize = usize::from(code).checked_add(bit).ok_or_else(|| {
                Error::Decompression("pmarc: -pm2- tree position overflow".to_owned())
            })?;
            code = *tree.get(slot).ok_or_else(|| {
                Error::Decompression("pmarc: -pm2- tree walks past its node table".to_owned())
            })?;
        }
        Ok(code & !TREE_LEAF)
    }

    fn set_tree_single(tree: &mut [u8], code: u8) -> Result<()> {
        let root: &mut u8 = tree
            .first_mut()
            .ok_or_else(|| Error::Decompression("pmarc: -pm2- tree has no root node".to_owned()))?;
        *root = code | TREE_LEAF;
        Ok(())
    }

    fn build_tree(tree: &mut [u8], code_lengths: &[u8]) -> Result<()> {
        tree.fill(TREE_LEAF);
        let mut next_entry: usize = 0;
        let mut allocated: usize = 1;
        let mut code_len: u32 = 0;
        loop {
            let pending: usize = allocated.checked_sub(next_entry).ok_or_else(|| {
                Error::Decompression("pmarc: -pm2- tree queue position overflow".to_owned())
            })?;
            let new_nodes: usize = pending.checked_mul(2).ok_or_else(|| {
                Error::Decompression("pmarc: -pm2- tree node count overflow".to_owned())
            })?;
            let expanded: usize = allocated.checked_add(new_nodes).ok_or_else(|| {
                Error::Decompression("pmarc: -pm2- tree allocation count overflow".to_owned())
            })?;
            if expanded > tree.len() {
                return Err(Error::Decompression(
                    "pmarc: -pm2- tree construction exceeds its node table".to_owned(),
                ));
            }
            let end_offset: usize = allocated;
            while next_entry < end_offset {
                if allocated >= usize::from(TREE_LEAF) {
                    return Err(Error::Decompression(
                        "pmarc: -pm2- tree node index collides with the leaf flag".to_owned(),
                    ));
                }
                let slot: &mut u8 = tree.get_mut(next_entry).ok_or_else(|| {
                    Error::Decompression("pmarc: -pm2- tree build ran past its table".to_owned())
                })?;
                *slot = u8::try_from(allocated).map_err(|_error: std::num::TryFromIntError| {
                    Error::Decompression("pmarc: -pm2- tree node index exceeds u8".to_owned())
                })?;
                allocated = allocated.checked_add(2).ok_or_else(|| {
                    Error::Decompression("pmarc: -pm2- tree allocation overflow".to_owned())
                })?;
                next_entry = next_entry.checked_add(1).ok_or_else(|| {
                    Error::Decompression("pmarc: -pm2- tree queue overflow".to_owned())
                })?;
            }
            code_len = code_len.checked_add(1).ok_or_else(|| {
                Error::Decompression("pmarc: -pm2- tree depth overflow".to_owned())
            })?;
            let mut codes_remaining: bool = false;
            for (index, &length) in code_lengths.iter().enumerate() {
                if u32::from(length) == code_len {
                    if next_entry >= allocated {
                        return Err(Error::Decompression(
                            "pmarc: -pm2- tree declares more codes than available nodes".to_owned(),
                        ));
                    }
                    let node: usize = next_entry;
                    next_entry = next_entry.checked_add(1).ok_or_else(|| {
                        Error::Decompression("pmarc: -pm2- tree queue overflow".to_owned())
                    })?;
                    let code: u8 =
                        u8::try_from(index).map_err(|_e: std::num::TryFromIntError| {
                            Error::Decompression("pmarc: -pm2- tree code exceeds u8".to_owned())
                        })?;
                    let slot: &mut u8 = tree.get_mut(node).ok_or_else(|| {
                        Error::Decompression(
                            "pmarc: -pm2- tree build ran past its table".to_owned(),
                        )
                    })?;
                    *slot = code | TREE_LEAF;
                } else if u32::from(length) > code_len {
                    codes_remaining = true;
                }
            }
            if !codes_remaining {
                if next_entry != allocated {
                    return Err(Error::Decompression(
                        "pmarc: -pm2- tree leaves part of its prefix space unassigned".to_owned(),
                    ));
                }
                return Ok(());
            }
            if code_len >= u32::from(u8::MAX) {
                return Err(Error::Decompression(
                    "pmarc: -pm2- tree code lengths exceed the depth limit".to_owned(),
                ));
            }
        }
    }

    fn read_code_tree(&mut self, reader: &mut BitReader<'_>) -> Result<()> {
        let num_codes: usize =
            usize::try_from(reader.read(5)?).map_err(|_error: std::num::TryFromIntError| {
                Error::Decompression("pmarc: -pm2- code count exceeds usize".to_owned())
            })?;
        let min_code_length: u32 = reader.read(3)?;
        if num_codes > PM2_MAX_CODES {
            return Err(Error::Decompression(format!(
                "pmarc: -pm2- code tree declares {num_codes} codes above the {PM2_MAX_CODES} ceiling"
            )));
        }
        if num_codes == 0 {
            return Err(Error::Decompression(
                "pmarc: -pm2- code tree declares no codes".to_owned(),
            ));
        }
        self.need_offset_tree =
            num_codes >= 10 && !(num_codes == PM2_MAX_CODES && min_code_length == 0);
        if min_code_length == 0 {
            let single: u8 =
                u8::try_from(num_codes - 1).map_err(|_e: std::num::TryFromIntError| {
                    Error::Decompression("pmarc: -pm2- single code exceeds u8".to_owned())
                })?;
            return Self::set_tree_single(&mut self.code_tree, single);
        }
        let length_bits: u32 = reader.read(3)?;
        let mut code_lengths: [u8; PM2_MAX_CODES] = [0; PM2_MAX_CODES];
        for slot in code_lengths.iter_mut().take(num_codes) {
            let value: u32 = reader.read(length_bits)?;
            *slot = if value == 0 {
                0
            } else {
                let length: u32 = min_code_length
                    .checked_add(value)
                    .and_then(|sum: u32| sum.checked_sub(1))
                    .ok_or_else(|| {
                        Error::Decompression("pmarc: -pm2- code length overflow".to_owned())
                    })?;
                u8::try_from(length).map_err(|_e: std::num::TryFromIntError| {
                    Error::Decompression("pmarc: -pm2- code length exceeds u8".to_owned())
                })?
            };
        }
        let lengths: &[u8] = code_lengths.get(..num_codes).ok_or_else(|| {
            Error::Decompression("pmarc: -pm2- code length table underflow".to_owned())
        })?;
        Self::build_tree(&mut self.code_tree, lengths)
    }

    fn read_offset_tree(&mut self, reader: &mut BitReader<'_>, num_offsets: usize) -> Result<()> {
        if !self.need_offset_tree {
            return Ok(());
        }
        if num_offsets > PM2_MAX_OFFSETS {
            return Err(Error::Decompression(format!(
                "pmarc: -pm2- offset tree declares {num_offsets} offsets above the {PM2_MAX_OFFSETS} ceiling"
            )));
        }
        let mut offset_lengths: [u8; PM2_MAX_OFFSETS] = [0; PM2_MAX_OFFSETS];
        let mut num_codes: usize = 0;
        let mut single_offset: u8 = 0;
        for (offset, slot) in offset_lengths.iter_mut().take(num_offsets).enumerate() {
            let length: u32 = reader.read(3)?;
            *slot = u8::try_from(length).map_err(|_e: std::num::TryFromIntError| {
                Error::Decompression("pmarc: -pm2- offset length exceeds u8".to_owned())
            })?;
            if length != 0 {
                single_offset = u8::try_from(offset).map_err(|_e: std::num::TryFromIntError| {
                    Error::Decompression("pmarc: -pm2- offset index exceeds u8".to_owned())
                })?;
                num_codes = num_codes.checked_add(1).ok_or_else(|| {
                    Error::Decompression("pmarc: -pm2- offset code count overflow".to_owned())
                })?;
            }
        }
        if num_codes == 1 {
            return Self::set_tree_single(&mut self.offset_tree, single_offset);
        }
        if num_codes == 0 {
            return Err(Error::Decompression(
                "pmarc: -pm2- offset tree declares no symbols".to_owned(),
            ));
        }
        let lengths: &[u8] = offset_lengths.get(..num_offsets).ok_or_else(|| {
            Error::Decompression("pmarc: -pm2- offset length table underflow".to_owned())
        })?;
        Self::build_tree(&mut self.offset_tree, lengths)
    }

    fn rebuild_tree(&mut self, reader: &mut BitReader<'_>) -> Result<()> {
        match self.state {
            Pm2RebuildState::Unbuilt => {
                self.read_code_tree(reader)?;
                self.read_offset_tree(reader, 5)?;
                self.state = Pm2RebuildState::Build1;
            }
            Pm2RebuildState::Build1 => {
                self.read_offset_tree(reader, 6)?;
                self.state = Pm2RebuildState::Build2;
            }
            Pm2RebuildState::Build2 => {
                self.read_offset_tree(reader, 7)?;
                self.state = Pm2RebuildState::Build3;
            }
            Pm2RebuildState::Build3 => {
                if reader.read(1)? == 1 {
                    self.read_code_tree(reader)?;
                }
                self.read_offset_tree(reader, 8)?;
                self.state = Pm2RebuildState::Continuing;
            }
            Pm2RebuildState::Continuing => {
                if reader.read(1)? == 1 {
                    self.read_code_tree(reader)?;
                    self.read_offset_tree(reader, 8)?;
                }
            }
        }
        Ok(())
    }

    fn history_get_count(reader: &mut BitReader<'_>, code: usize) -> Result<usize> {
        if code < 15 {
            return code.checked_add(2).ok_or_else(|| {
                Error::Decompression("pmarc: -pm2- copy length overflow".to_owned())
            });
        }
        let value: u32 = reader.read_variable(&PM2_COPY_DECODE, code - 15)?;
        usize::try_from(value).map_err(|_error: std::num::TryFromIntError| {
            Error::Decompression("pmarc: -pm2- copy length exceeds usize".to_owned())
        })
    }

    fn history_get_offset(&self, reader: &mut BitReader<'_>, code: usize) -> Result<usize> {
        let mut result: u32 = 0;
        let bits: u32 = if code == 0 {
            6
        } else if code < 20 {
            let selector: u8 = Self::read_from_tree(reader, &self.offset_tree)?;
            if selector == 0 {
                6
            } else {
                let bits: u32 = u32::from(selector).checked_add(5).ok_or_else(|| {
                    Error::Decompression("pmarc: -pm2- offset width overflow".to_owned())
                })?;
                result = 1u32.checked_shl(bits).ok_or_else(|| {
                    Error::Decompression("pmarc: -pm2- offset width overflow".to_owned())
                })?;
                bits
            }
        } else {
            return Ok(0);
        };
        let value: u32 = reader.read(bits)?;
        let offset: u32 = result
            .checked_add(value)
            .ok_or_else(|| Error::Decompression("pmarc: -pm2- offset overflow".to_owned()))?;
        usize::try_from(offset).map_err(|_error: std::num::TryFromIntError| {
            Error::Decompression("pmarc: -pm2- offset exceeds usize".to_owned())
        })
    }

    fn read_single_byte(
        &mut self,
        reader: &mut BitReader<'_>,
        out: &mut Vec<u8>,
        code: usize,
    ) -> Result<()> {
        let offset: u32 = reader.read_variable(&PM2_HISTORY_DECODE, code)?;
        let offset: u8 = u8::try_from(offset).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("pmarc: -pm2- history distance exceeds 255".to_owned())
        })?;
        let byte: u8 = self.history.find(offset);
        reserve_output(out, 1, PmMethod::Pm2)?;
        self.output_byte(out, byte)?;
        Ok(())
    }

    fn copy_from_history(
        &mut self,
        reader: &mut BitReader<'_>,
        out: &mut Vec<u8>,
        code: usize,
        remaining: usize,
    ) -> Result<()> {
        let to_copy: usize = Self::history_get_count(reader, code)?;
        let offset: usize = self.history_get_offset(reader, code)?;
        if to_copy == 0 || to_copy > PM2_MAX_COPY {
            return Err(Error::Decompression(format!(
                "pmarc: -pm2- copy length {to_copy} is outside 1..={PM2_MAX_COPY}"
            )));
        }
        if to_copy > remaining {
            return Err(Error::Decompression(
                "pmarc: -pm2- command output exceeds the remaining declared length".to_owned(),
            ));
        }
        if offset >= PM2_RING_SIZE {
            return Err(Error::Decompression(format!(
                "pmarc: -pm2- copy offset {offset} exceeds the {PM2_RING_SIZE}-byte window"
            )));
        }
        reserve_output(out, to_copy, PmMethod::Pm2)?;
        let start: usize = self
            .ring_pos
            .checked_add(PM2_RING_SIZE)
            .and_then(|value: usize| value.checked_sub(1))
            .and_then(|value: usize| value.checked_sub(offset))
            .ok_or_else(|| {
                Error::Decompression("pmarc: -pm2- history position overflow".to_owned())
            })?;
        for index in 0..to_copy {
            let position: usize = start.checked_add(index).ok_or_else(|| {
                Error::Decompression("pmarc: -pm2- history position overflow".to_owned())
            })? % PM2_RING_SIZE;
            let byte: u8 = self.ring[position];
            self.output_byte(out, byte)?;
        }
        Ok(())
    }
}

fn decode_pm1(src: &[u8], declared: usize) -> Result<PmDecoded> {
    let mut reader: BitReader<'_> = BitReader::new(src, PmMethod::Pm1, true);
    let mut decoder: Pm1Decoder = Pm1Decoder::new()?;
    let mut out: Vec<u8> = allocate_output(declared, PmMethod::Pm1)?;
    let tree_index: usize =
        usize::try_from(reader.read(5)?).map_err(|_error: std::num::TryFromIntError| {
            Error::Decompression("pmarc: -pm1- start tree index exceeds usize".to_owned())
        })?;
    decoder.tree = PM1_BYTE_DECODE_TREES.get(tree_index).ok_or_else(|| {
        Error::Decompression(format!(
            "pmarc: -pm1- start header selects tree {tree_index} outside the 32-entry table"
        ))
    })?;
    let mut commands: usize = 0;
    while out.len() < declared {
        commands = commands.checked_add(1).ok_or_else(|| {
            Error::Decompression("pmarc: -pm1- command work counter overflow".to_owned())
        })?;
        if commands > declared {
            return Err(Error::Decompression(format!(
                "pmarc: -pm1- stream issued more than {declared} command(s)"
            )));
        }
        let produced: usize = out.len();
        if reader.read(1)? == 0 {
            decoder.read_copy_command(&mut reader, &mut out)?;
        } else {
            decoder.read_byte_block(&mut reader, &mut out)?;
        }
        if out.len() <= produced {
            return Err(Error::Decompression(
                "pmarc: -pm1- command produced no output".to_owned(),
            ));
        }
        if reader.pad_bits > 0 && out.len() < declared {
            return Err(Error::Decompression(
                "pmarc: -pm1- zero-fill work limit exhausted before declared output".to_owned(),
            ));
        }
        if let Some(overrun) = out.len().checked_sub(declared)
            && overrun > PM1_MAX_COMMAND_OUTPUT
        {
            return Err(Error::Decompression(
                "pmarc: -pm1- command exceeded its output ceiling".to_owned(),
            ));
        }
    }
    let unread_bits: u64 = reader.unread_bits()?;
    out.truncate(declared);
    Ok(PmDecoded {
        data: out,
        unread_bits,
    })
}

fn decode_pm2(src: &[u8], declared: usize) -> Result<PmDecoded> {
    let mut reader: BitReader<'_> = BitReader::new(src, PmMethod::Pm2, false);
    let mut decoder: Pm2Decoder = Pm2Decoder::new()?;
    let mut out: Vec<u8> = allocate_output(declared, PmMethod::Pm2)?;
    let _discarded: u32 = reader.read(1)?;
    let mut commands: usize = 0;
    while out.len() < declared {
        commands = commands.checked_add(1).ok_or_else(|| {
            Error::Decompression("pmarc: -pm2- command work counter overflow".to_owned())
        })?;
        if commands > declared {
            return Err(Error::Decompression(format!(
                "pmarc: -pm2- stream issued more than {declared} command(s)"
            )));
        }
        if decoder.rebuild_pending {
            decoder.rebuild_pending = false;
            decoder.rebuild_tree(&mut reader)?;
        }
        let produced: usize = out.len();
        let remaining: usize = declared.checked_sub(produced).ok_or_else(|| {
            Error::Decompression("pmarc: -pm2- remaining output underflow".to_owned())
        })?;
        let code: usize = usize::from(Pm2Decoder::read_from_tree(&mut reader, &decoder.code_tree)?);
        if code < 8 {
            decoder.read_single_byte(&mut reader, &mut out, code)?;
        } else {
            decoder.copy_from_history(&mut reader, &mut out, code - 8, remaining)?;
        }
        if out.len() <= produced {
            return Err(Error::Decompression(
                "pmarc: -pm2- command produced no output".to_owned(),
            ));
        }
    }
    let unread_bits: u64 = reader.unread_bits()?;
    Ok(PmDecoded {
        data: out,
        unread_bits,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PmDecoded {
    pub data: Vec<u8>,
    pub unread_bits: u64,
}

pub fn decode_bounded(
    method: PmMethod,
    src: &[u8],
    original_size: u64,
    max_output: u64,
) -> Result<PmDecoded> {
    if original_size > max_output {
        return Err(Error::Decompression(format!(
            "pmarc: declared output exceeds {max_output}-byte limit"
        )));
    }
    let declared: usize =
        usize::try_from(original_size).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("pmarc: declared output exceeds usize".to_owned())
        })?;
    if declared == 0 {
        let source_len: u64 =
            u64::try_from(src.len()).map_err(|_error: std::num::TryFromIntError| {
                Error::Decompression("pmarc: compressed input length exceeds u64".to_owned())
            })?;
        let unread_bits: u64 = source_len.checked_mul(8).ok_or_else(|| {
            Error::Decompression("pmarc: compressed input bit length overflow".to_owned())
        })?;
        return Ok(PmDecoded {
            data: Vec::new(),
            unread_bits,
        });
    }
    let decoded: PmDecoded = match method {
        PmMethod::Pm1 => decode_pm1(src, declared)?,
        PmMethod::Pm2 => decode_pm2(src, declared)?,
    };
    if decoded.data.len() != declared {
        return Err(Error::Decompression(format!(
            "pmarc: decoded {} bytes, expected {declared}",
            decoded.data.len()
        )));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{PmMethod, reserve_output};

    #[test]
    fn output_reservation_grows_amortized_capacity() {
        let mut output: Vec<u8> = Vec::new();
        let initial_reserve: std::result::Result<(), std::collections::TryReserveError> =
            output.try_reserve_exact(64);
        assert!(initial_reserve.is_ok(), "{initial_reserve:?}");
        output.resize(output.capacity(), 0);
        let previous_capacity: usize = output.capacity();
        assert!(previous_capacity <= usize::MAX / 2);
        let doubled_capacity: usize = previous_capacity * 2;
        let growth: crate::Result<()> = reserve_output(&mut output, 1, PmMethod::Pm1);
        assert!(growth.is_ok(), "{growth:?}");
        assert!(output.capacity() >= doubled_capacity);
    }
}
