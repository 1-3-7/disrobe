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
const PM1_MAX_PAD_BITS: u64 = 64;
const PM2_MAX_PAD_BITS: u64 = 0;
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
    max_pad_bits: u64,
}

impl<'a> BitReader<'a> {
    const fn new(src: &'a [u8], method: PmMethod, max_pad_bits: u64) -> Self {
        Self {
            src,
            pos: 0,
            accumulator: 0,
            bits: 0,
            consumed_bits: 0,
            pad_bits: 0,
            method,
            max_pad_bits,
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
                self.pos += 1;
                value
            } else {
                if self.max_pad_bits == 0 {
                    return Err(Error::Decompression(format!(
                        "pmarc: {} compressed body ended before the decoded stream",
                        self.method.tag()
                    )));
                }
                self.pad_bits = self.pad_bits.saturating_add(8);
                if self.pad_bits > self.max_pad_bits {
                    return Err(Error::Decompression(format!(
                        "pmarc: {} stream read {} bit(s) past the compressed body",
                        self.method.tag(),
                        self.pad_bits
                    )));
                }
                0
            };
            self.accumulator |= u64::from(byte) << (56 - self.bits);
            self.bits += 8;
        }
        let value: u32 = u32::try_from(self.accumulator >> (64 - u64::from(count))).map_err(
            |_e: std::num::TryFromIntError| {
                Error::Decompression("pmarc: bit window exceeds u32".to_owned())
            },
        )?;
        self.accumulator <<= count;
        self.bits -= count;
        self.consumed_bits = self.consumed_bits.saturating_add(u64::from(count));
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

    const fn unread_bits(&self) -> u64 {
        let available: u64 = (self.src.len() as u64).saturating_mul(8);
        available.saturating_sub(self.consumed_bits)
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
        for index in 0..256usize {
            let code: u8 = index as u8;
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

struct Pm1Decoder {
    ring: Box<[u8; PM1_RING_SIZE]>,
    ring_pos: usize,
    history: HistoryList,
    tree: &'static [u8; 5],
}

impl Pm1Decoder {
    fn new() -> Self {
        Self {
            ring: Box::new([0; PM1_RING_SIZE]),
            ring_pos: 0,
            history: HistoryList::new(),
            tree: &PM1_BYTE_DECODE_TREES[31],
        }
    }

    fn output_byte(&mut self, out: &mut Vec<u8>, byte: u8) {
        self.ring[self.ring_pos] = byte;
        self.ring_pos = (self.ring_pos + 1) % PM1_RING_SIZE;
        self.history.update(byte);
        out.push(byte);
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
            node += child;
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
            return Ok(first as usize + 3);
        }
        let second: u32 = reader.read(3)?;
        match second {
            0..=4 => Ok(second as usize + 6),
            5 => Ok(reader.read(2)? as usize + 11),
            6 => Ok(reader.read(3)? as usize + 15),
            _ => {
                let third: u32 = reader.read(6)?;
                match third {
                    0..=61 => Ok(third as usize + 23),
                    62 => Ok(reader.read(5)? as usize + 85),
                    _ => Ok(reader.read(7)? as usize + 117),
                }
            }
        }
    }

    fn read_byte_block_count(reader: &mut BitReader<'_>) -> Result<usize> {
        let first: u32 = reader.read(2)?;
        if first < 3 {
            return Ok(first as usize + 1);
        }
        let second: u32 = reader.read(3)?;
        if second < 7 {
            return Ok(second as usize + 4);
        }
        let third: u32 = reader.read(4)?;
        match third {
            0..=13 => Ok(third as usize + 11),
            14 => Ok(reader.read(6)? as usize + 25),
            _ => Ok(reader.read(7)? as usize + 89),
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
            return Ok(Self::read_bit_after_threshold(reader, produced, 64, 0)? as usize);
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
        let produced: u64 = out.len() as u64;
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
        let mut source: usize = (self.ring_pos + PM1_RING_SIZE - distance - 1) % PM1_RING_SIZE;
        for _ in 0..count {
            let byte: u8 = self.ring[source];
            self.output_byte(out, byte);
            source = (source + 1) % PM1_RING_SIZE;
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
        for _ in 0..block_len {
            let byte: u8 = self.read_byte(reader)?;
            self.output_byte(out, byte);
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
    ring: Box<[u8; PM2_RING_SIZE]>,
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
    fn new() -> Self {
        Self {
            ring: Box::new([b' '; PM2_RING_SIZE]),
            ring_pos: 0,
            history: HistoryList::new(),
            code_tree: [TREE_LEAF; PM2_CODE_TREE_ELEMENTS],
            offset_tree: [TREE_LEAF; PM2_OFFSET_TREE_ELEMENTS],
            need_offset_tree: false,
            state: Pm2RebuildState::Unbuilt,
            rebuild_remaining: Pm2RebuildState::Unbuilt.interval(),
            rebuild_pending: true,
        }
    }

    fn output_byte(&mut self, out: &mut Vec<u8>, byte: u8) {
        self.ring[self.ring_pos] = byte;
        self.ring_pos = (self.ring_pos + 1) % PM2_RING_SIZE;
        self.history.update(byte);
        out.push(byte);
        self.rebuild_remaining = self.rebuild_remaining.saturating_sub(1);
        if self.rebuild_remaining == 0 {
            self.rebuild_pending = true;
            self.rebuild_remaining = self.state.interval();
        }
    }

    fn read_from_tree(reader: &mut BitReader<'_>, tree: &[u8]) -> Result<u8> {
        let mut code: u8 = *tree
            .first()
            .ok_or_else(|| Error::Decompression("pmarc: -pm2- tree has no root node".to_owned()))?;
        let mut steps: usize = 0;
        while code & TREE_LEAF == 0 {
            steps += 1;
            if steps > tree.len() {
                return Err(Error::Decompression(
                    "pmarc: -pm2- tree walk exceeds its node count".to_owned(),
                ));
            }
            let bit: u32 = reader.read(1)?;
            let slot: usize = usize::from(code) + bit as usize;
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
        let mut next_entry: usize = 0;
        let mut allocated: usize = 1;
        let mut code_len: u32 = 0;
        loop {
            let new_nodes: usize = allocated.saturating_sub(next_entry).saturating_mul(2);
            if allocated.saturating_add(new_nodes) <= tree.len() {
                let end_offset: usize = allocated;
                while next_entry < end_offset {
                    if allocated >= usize::from(TREE_LEAF) {
                        return Err(Error::Decompression(
                            "pmarc: -pm2- tree node index collides with the leaf flag".to_owned(),
                        ));
                    }
                    let slot: &mut u8 = tree.get_mut(next_entry).ok_or_else(|| {
                        Error::Decompression(
                            "pmarc: -pm2- tree build ran past its table".to_owned(),
                        )
                    })?;
                    *slot = allocated as u8;
                    allocated += 2;
                    next_entry += 1;
                }
            }
            code_len += 1;
            let mut codes_remaining: bool = false;
            for (index, &length) in code_lengths.iter().enumerate() {
                if u32::from(length) == code_len {
                    let node: usize = if next_entry < allocated {
                        let taken: usize = next_entry;
                        next_entry += 1;
                        taken
                    } else {
                        0
                    };
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
                return Ok(());
            }
            if code_len > u32::from(u8::MAX) {
                return Err(Error::Decompression(
                    "pmarc: -pm2- tree code lengths exceed the depth limit".to_owned(),
                ));
            }
        }
    }

    fn read_code_tree(&mut self, reader: &mut BitReader<'_>) -> Result<()> {
        let num_codes: usize = reader.read(5)? as usize;
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
                num_codes += 1;
            }
        }
        if num_codes == 1 {
            return Self::set_tree_single(&mut self.offset_tree, single_offset);
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
            return Ok(code + 2);
        }
        let value: u32 = reader.read_variable(&PM2_COPY_DECODE, code - 15)?;
        Ok(value as usize)
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
                let bits: u32 = u32::from(selector) + 5;
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
        Ok(offset as usize)
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
        self.output_byte(out, byte);
        Ok(())
    }

    fn copy_from_history(
        &mut self,
        reader: &mut BitReader<'_>,
        out: &mut Vec<u8>,
        code: usize,
    ) -> Result<()> {
        let to_copy: usize = Self::history_get_count(reader, code)?;
        let offset: usize = self.history_get_offset(reader, code)?;
        if to_copy == 0 || to_copy > PM2_MAX_COPY {
            return Err(Error::Decompression(format!(
                "pmarc: -pm2- copy length {to_copy} is outside 1..={PM2_MAX_COPY}"
            )));
        }
        if offset >= PM2_RING_SIZE {
            return Err(Error::Decompression(format!(
                "pmarc: -pm2- copy offset {offset} exceeds the {PM2_RING_SIZE}-byte window"
            )));
        }
        let start: usize = self.ring_pos + PM2_RING_SIZE - 1 - offset;
        for index in 0..to_copy {
            let byte: u8 = self.ring[(start + index) % PM2_RING_SIZE];
            self.output_byte(out, byte);
        }
        Ok(())
    }
}

fn decode_pm1(src: &[u8], declared: usize) -> Result<PmDecoded> {
    let mut reader: BitReader<'_> = BitReader::new(src, PmMethod::Pm1, PM1_MAX_PAD_BITS);
    let mut decoder: Pm1Decoder = Pm1Decoder::new();
    let mut out: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(declared as u64));
    let tree_index: usize = reader.read(5)? as usize;
    decoder.tree = PM1_BYTE_DECODE_TREES.get(tree_index).ok_or_else(|| {
        Error::Decompression(format!(
            "pmarc: -pm1- start header selects tree {tree_index} outside the 32-entry table"
        ))
    })?;
    let mut commands: usize = 0;
    while out.len() < declared {
        commands += 1;
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
        if out.len() > declared + PM1_MAX_COMMAND_OUTPUT {
            return Err(Error::Decompression(format!(
                "pmarc: -pm1- decoded {} bytes past the declared {declared}",
                out.len() - declared
            )));
        }
    }
    let unread_bits: u64 = reader.unread_bits();
    out.truncate(declared);
    Ok(PmDecoded {
        data: out,
        unread_bits,
    })
}

fn decode_pm2(src: &[u8], declared: usize) -> Result<PmDecoded> {
    let mut reader: BitReader<'_> = BitReader::new(src, PmMethod::Pm2, PM2_MAX_PAD_BITS);
    let mut decoder: Pm2Decoder = Pm2Decoder::new();
    let mut out: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(declared as u64));
    let _discarded: u32 = reader.read(1)?;
    let mut commands: usize = 0;
    while out.len() < declared {
        commands += 1;
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
        let code: usize = usize::from(Pm2Decoder::read_from_tree(&mut reader, &decoder.code_tree)?);
        if code < 8 {
            decoder.read_single_byte(&mut reader, &mut out, code)?;
        } else {
            decoder.copy_from_history(&mut reader, &mut out, code - 8)?;
        }
        if out.len() <= produced {
            return Err(Error::Decompression(
                "pmarc: -pm2- command produced no output".to_owned(),
            ));
        }
        if out.len() > declared + PM2_MAX_COPY {
            return Err(Error::Decompression(format!(
                "pmarc: -pm2- decoded {} bytes past the declared {declared}",
                out.len() - declared
            )));
        }
    }
    let unread_bits: u64 = reader.unread_bits();
    out.truncate(declared);
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
        return Ok(PmDecoded {
            data: Vec::new(),
            unread_bits: (src.len() as u64).saturating_mul(8),
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
