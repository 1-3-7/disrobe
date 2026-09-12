use crate::error::{Error, Result};

const RLE_MARKER: u8 = 0x90;

pub fn un_rle(input: &[u8], cap: usize) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut last: Option<u8> = None;
    let mut index: usize = 0;
    while index < input.len() {
        let byte: u8 = input[index];
        index += 1;
        if byte == RLE_MARKER {
            let count: u8 = *input
                .get(index)
                .ok_or_else(|| Error::Arc("arc-rle: truncated repeat count".to_owned()))?;
            index += 1;
            if count == 0 {
                out.push(RLE_MARKER);
                last = Some(RLE_MARKER);
            } else {
                let prev: u8 = last
                    .ok_or_else(|| Error::Arc("arc-rle: repeat with no prior byte".to_owned()))?;
                for _ in 1..count {
                    out.push(prev);
                    if out.len() > cap {
                        return Err(Error::Arc("arc-rle: output exceeds cap".to_owned()));
                    }
                }
            }
        } else {
            out.push(byte);
            last = Some(byte);
        }
        if out.len() > cap {
            return Err(Error::Arc("arc-rle: output exceeds cap".to_owned()));
        }
    }
    Ok(out)
}

const FIXED_TABLE_SIZE: usize = 4096;
const FIXED_NO_PREDECESSOR: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct FixedEntry {
    used: bool,
    next: u16,
    predecessor: u16,
    follower: u8,
}

#[derive(Clone, Copy)]
enum FixedHash {
    Old,
    New,
}

struct FixedTable {
    entries: Box<[FixedEntry]>,
    hash: FixedHash,
    remaining: usize,
}

impl FixedTable {
    fn new(hash: FixedHash) -> Result<Self> {
        const EMPTY: FixedEntry = FixedEntry {
            used: false,
            next: 0,
            predecessor: 0,
            follower: 0,
        };
        let mut table: Self = Self {
            entries: vec![EMPTY; FIXED_TABLE_SIZE].into_boxed_slice(),
            hash,
            remaining: FIXED_TABLE_SIZE,
        };
        for literal in 0_u16..=255 {
            let _: usize = table.insert(FIXED_NO_PREDECESSOR, literal as u8)?;
        }
        Ok(table)
    }

    fn slot_for(&mut self, predecessor: u16, follower: u8) -> Result<usize> {
        let mut slot: usize = fixed_hash(predecessor, follower, self.hash);
        if !self.entries[slot].used {
            return Ok(slot);
        }
        for _ in 0..FIXED_TABLE_SIZE {
            let next: usize = usize::from(self.entries[slot].next);
            if next == 0 {
                break;
            }
            slot = next;
        }
        let mut candidate: usize = (slot + 101) & 0x0fff;
        for _ in 0..FIXED_TABLE_SIZE {
            if !self.entries[candidate].used {
                self.entries[slot].next = candidate as u16;
                return Ok(candidate);
            }
            candidate = (candidate + 1) & 0x0fff;
        }
        Err(Error::Arc("arc-fixed-lzw: dictionary is full".to_owned()))
    }

    fn insert(&mut self, predecessor: u16, follower: u8) -> Result<usize> {
        if self.remaining == 0 {
            return Err(Error::Arc("arc-fixed-lzw: dictionary is full".to_owned()));
        }
        let slot: usize = self.slot_for(predecessor, follower)?;
        self.entries[slot] = FixedEntry {
            used: true,
            next: 0,
            predecessor,
            follower,
        };
        self.remaining -= 1;
        Ok(slot)
    }

    fn expand(&self, mut code: usize, stack: &mut Vec<u8>) -> Result<u8> {
        for _ in 0..FIXED_TABLE_SIZE {
            let current: FixedEntry = self.entries[code];
            if !current.used {
                return Err(Error::Arc(format!(
                    "arc-fixed-lzw: code {code} references an uninitialized slot"
                )));
            }
            stack.push(current.follower);
            if current.predecessor == FIXED_NO_PREDECESSOR {
                return Ok(current.follower);
            }
            code = usize::from(current.predecessor);
        }
        Err(Error::Arc(
            "arc-fixed-lzw: predecessor chain is cyclic".to_owned(),
        ))
    }
}

const fn fixed_hash(predecessor: u16, follower: u8, hash: FixedHash) -> usize {
    let sum: u16 = predecessor.wrapping_add(follower as u16);
    match hash {
        FixedHash::Old => {
            let key: u32 = (sum | 0x0800) as u32;
            ((key.wrapping_mul(key) >> 6) & 0x0fff) as usize
        }
        FixedHash::New => (sum.wrapping_mul(15_073) & 0x0fff) as usize,
    }
}

struct FixedCodeReader<'a> {
    input: &'a [u8],
    offset: usize,
    first_in_pair: bool,
}

impl<'a> FixedCodeReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            first_in_pair: true,
        }
    }

    fn read(&mut self) -> Result<Option<usize>> {
        let remaining: usize = self.input.len().saturating_sub(self.offset);
        if remaining == 0 {
            return Ok(None);
        }
        if remaining == 1 {
            if !self.first_in_pair && self.input[self.offset].trailing_zeros() >= 4 {
                self.offset += 1;
                self.first_in_pair = true;
                return Ok(None);
            }
            return Err(Error::Arc(
                "arc-fixed-lzw: truncated 12-bit code".to_owned(),
            ));
        }
        let first: u8 = self.input[self.offset];
        let second: u8 = self.input[self.offset + 1];
        if self.first_in_pair {
            self.offset += 1;
            self.first_in_pair = false;
            return Ok(Some((usize::from(first) << 4) | usize::from(second >> 4)));
        }
        self.offset += 2;
        self.first_in_pair = true;
        Ok(Some((usize::from(first & 0x0f) << 8) | usize::from(second)))
    }
}

pub(crate) fn un_crunch_fixed(input: &[u8], new_hash: bool, cap: usize) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let hash: FixedHash = if new_hash {
        FixedHash::New
    } else {
        FixedHash::Old
    };
    let mut table: FixedTable = FixedTable::new(hash)?;
    let mut reader: FixedCodeReader<'_> = FixedCodeReader::new(input);
    let first_code: usize = reader
        .read()?
        .ok_or_else(|| Error::Arc("arc-fixed-lzw: missing first code".to_owned()))?;
    let first_entry: FixedEntry = table.entries[first_code];
    if !first_entry.used || first_entry.predecessor != FIXED_NO_PREDECESSOR {
        return Err(Error::Arc(format!(
            "arc-fixed-lzw: first code {first_code} is not an initialized literal"
        )));
    }
    let mut output: Vec<u8> = Vec::with_capacity(cap.min(64 * 1024));
    output.push(first_entry.follower);
    if output.len() > cap {
        return Err(Error::Arc("arc-fixed-lzw: output exceeds cap".to_owned()));
    }
    let mut old_code: usize = first_code;
    let mut first_byte: u8 = first_entry.follower;
    let mut stack: Vec<u8> = Vec::with_capacity(FIXED_TABLE_SIZE);
    while let Some(new_code) = reader.read()? {
        let entry: FixedEntry = table.entries[new_code];
        let undefined: bool = !entry.used;
        let code: usize = if undefined {
            stack.push(first_byte);
            old_code
        } else {
            new_code
        };
        first_byte = table.expand(code, &mut stack)?;
        while let Some(byte) = stack.pop() {
            output.push(byte);
            if output.len() > cap {
                return Err(Error::Arc("arc-fixed-lzw: output exceeds cap".to_owned()));
            }
        }
        if table.remaining > 0 {
            let inserted: usize = table.insert(old_code as u16, first_byte)?;
            if undefined && inserted != new_code {
                return Err(Error::Arc(format!(
                    "arc-fixed-lzw: undefined code {new_code} does not match insertion slot {inserted}"
                )));
            }
        } else if undefined {
            return Err(Error::Arc(format!(
                "arc-fixed-lzw: undefined code {new_code} after dictionary saturation"
            )));
        }
        old_code = new_code;
    }
    Ok(output)
}

struct LzwGroupReader<'a> {
    src: &'a [u8],
    cursor: usize,
    group_start: usize,
    group_end: usize,
    group_width: u32,
    code_index: usize,
    code_count: usize,
}

impl<'a> LzwGroupReader<'a> {
    const fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            cursor: 0,
            group_start: 0,
            group_end: 0,
            group_width: 0,
            code_index: 0,
            code_count: 0,
        }
    }

    const fn realign(&mut self) {
        self.code_index = self.code_count;
    }

    fn read_code(&mut self, width: u32) -> Result<Option<u32>> {
        if width == 0 || width > u32::BITS {
            return Err(Error::Arc("arc-lzw: invalid code width".to_owned()));
        }
        if self.group_width != width || self.code_index >= self.code_count {
            if self.cursor >= self.src.len() {
                return Ok(None);
            }
            let width_bytes: usize = usize::try_from(width)
                .map_err(|_| Error::Arc("arc-lzw: invalid code width".to_owned()))?;
            self.group_start = self.cursor;
            let group_limit: usize = self
                .cursor
                .checked_add(width_bytes)
                .ok_or_else(|| Error::Arc("arc-lzw: group range overflow".to_owned()))?;
            self.group_end = group_limit.min(self.src.len());
            self.cursor = self.group_end;
            self.group_width = width;
            self.code_index = 0;
            self.code_count = (self.group_end - self.group_start)
                .checked_mul(8)
                .ok_or_else(|| Error::Arc("arc-lzw: group size overflow".to_owned()))?
                / width_bytes;
            if self.code_count == 0 {
                return Err(Error::Arc("arc-lzw: bit underrun".to_owned()));
            }
        }
        let bit_pos: usize = self
            .group_start
            .checked_mul(8)
            .and_then(|start: usize| {
                self.code_index
                    .checked_mul(width as usize)
                    .and_then(|offset: usize| start.checked_add(offset))
            })
            .ok_or_else(|| Error::Arc("arc-lzw: bit position overflow".to_owned()))?;
        let mut code: u32 = 0;
        for i in 0..width {
            let absolute_bit: usize = bit_pos
                .checked_add(i as usize)
                .ok_or_else(|| Error::Arc("arc-lzw: bit position overflow".to_owned()))?;
            let byte_index: usize = absolute_bit / 8;
            if byte_index >= self.group_end {
                return Err(Error::Arc("arc-lzw: bit underrun".to_owned()));
            }
            let bit_index: u32 = (absolute_bit % 8) as u32;
            let byte: u8 = self.src[byte_index];
            let bit: u32 = u32::from((byte >> bit_index) & 1);
            code |= bit << i;
        }
        self.code_index += 1;
        Ok(Some(code))
    }
}

const LZW_CLEAR: u32 = 256;
const LZW_MIN_BITS: u32 = 9;

fn lzw_decode(input: &[u8], max_bits: u32, cap: usize) -> Result<Vec<u8>> {
    let first_code: u32 = 257;
    let mut reader: LzwGroupReader<'_> = LzwGroupReader::new(input);
    let mut out: Vec<u8> = Vec::new();
    let mut prefix: Vec<u32> = vec![0; 1 << max_bits];
    let mut suffix: Vec<u8> = vec![0; 1 << max_bits];
    let mut stack: Vec<u8> = Vec::with_capacity(1 << max_bits);
    let mut next_code: u32 = first_code;
    let mut width: u32 = LZW_MIN_BITS;
    let mut old_code: Option<u32> = None;
    let mut first_byte: u8 = 0;
    let mut needs_code_after_clear: bool = false;

    loop {
        if next_code > (1 << width) - 1 && width < max_bits {
            width += 1;
        }
        let Some(code) = reader.read_code(width)? else {
            if needs_code_after_clear {
                return Err(Error::Arc(
                    "arc-lzw: clear code has no following code".to_owned(),
                ));
            }
            break;
        };
        if code == LZW_CLEAR {
            next_code = first_code;
            width = LZW_MIN_BITS;
            old_code = None;
            reader.realign();
            needs_code_after_clear = true;
            continue;
        }
        needs_code_after_clear = false;
        let Some(prev) = old_code else {
            if code > 0xFF {
                return Err(Error::Arc(
                    "arc-lzw: first code is not a literal".to_owned(),
                ));
            }
            first_byte = code as u8;
            out.push(first_byte);
            if out.len() > cap {
                return Err(Error::Arc("arc-lzw: output exceeds cap".to_owned()));
            }
            old_code = Some(code);
            continue;
        };
        if code > next_code {
            return Err(Error::Arc(format!(
                "arc-lzw: code {code} ahead of table position {next_code}"
            )));
        }
        let mut current: u32 = if code == next_code {
            stack.push(first_byte);
            prev
        } else {
            code
        };
        while current >= 256 {
            let idx: usize = current as usize;
            stack.push(suffix[idx]);
            current = prefix[idx];
            if stack.len() > (1 << max_bits) {
                return Err(Error::Arc("arc-lzw: prefix chain too long".to_owned()));
            }
        }
        first_byte = current as u8;
        stack.push(first_byte);
        while let Some(byte) = stack.pop() {
            out.push(byte);
            if out.len() > cap {
                return Err(Error::Arc("arc-lzw: output exceeds cap".to_owned()));
            }
        }
        if next_code < (1 << max_bits) {
            prefix[next_code as usize] = prev;
            suffix[next_code as usize] = first_byte;
            next_code += 1;
        }
        old_code = Some(code);
    }
    Ok(out)
}

pub fn un_crunch(input: &[u8], cap: usize) -> Result<Vec<u8>> {
    let (&max_width, body): (&u8, &[u8]) = input
        .split_first()
        .ok_or_else(|| Error::Arc("arc-lzw: missing method 8 width header".to_owned()))?;
    if max_width != 12 {
        return Err(Error::Arc(format!(
            "arc-lzw: method 8 width header is {max_width}, expected 12"
        )));
    }
    let intermediate_cap: usize = cap
        .checked_mul(2)
        .ok_or_else(|| Error::Arc("arc-lzw: intermediate size cap overflow".to_owned()))?;
    let lzw: Vec<u8> = lzw_decode(body, 12, intermediate_cap)?;
    un_rle(&lzw, cap)
}

pub fn un_squash(input: &[u8], cap: usize) -> Result<Vec<u8>> {
    lzw_decode(input, 13, cap)
}

#[derive(Clone, Copy)]
struct SqNode {
    child: [i16; 2],
}

const SQ_NUMVALS: usize = 257;
const SQ_SPEOF: u16 = 256;
const SQ_NUMNODES: usize = SQ_NUMVALS + SQ_NUMVALS - 1;

struct SqBitReader<'a> {
    src: &'a [u8],
    byte_pos: usize,
    bit_buf: u16,
    bits_left: u8,
}

impl<'a> SqBitReader<'a> {
    const fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            byte_pos: 0,
            bit_buf: 0,
            bits_left: 0,
        }
    }

    fn read_bit(&mut self) -> Result<u16> {
        if self.bits_left == 0 {
            let byte: u8 = *self
                .src
                .get(self.byte_pos)
                .ok_or_else(|| Error::Arc("arc-squeeze: bit underrun".to_owned()))?;
            self.byte_pos += 1;
            self.bit_buf = u16::from(byte);
            self.bits_left = 8;
        }
        let bit: u16 = self.bit_buf & 1;
        self.bit_buf >>= 1;
        self.bits_left -= 1;
        Ok(bit)
    }
}

pub fn un_squeeze(input: &[u8], cap: usize) -> Result<Vec<u8>> {
    if input.len() < 2 {
        return Err(Error::Arc("arc-squeeze: missing node count".to_owned()));
    }
    let numnodes: usize = u16::from_le_bytes([input[0], input[1]]) as usize;
    if numnodes == 0 || numnodes > SQ_NUMNODES {
        return Err(Error::Arc(format!(
            "arc-squeeze: invalid node count {numnodes}"
        )));
    }
    let mut nodes: Vec<SqNode> = vec![SqNode { child: [0, 0] }; numnodes];
    let mut cursor: usize = 2;
    for node in &mut nodes {
        let l: i16 = read_i16(input, &mut cursor)?;
        let r: i16 = read_i16(input, &mut cursor)?;
        node.child = [l, r];
    }
    let mut reader: SqBitReader<'_> = SqBitReader::new(&input[cursor..]);
    let mut rle_out: Vec<u8> = Vec::new();
    loop {
        let mut node: i16 = 0;
        while node >= 0 {
            let bit: u16 = match reader.read_bit() {
                Ok(b) => b,
                Err(_) => {
                    return un_rle(&rle_out, cap);
                }
            };
            let idx: usize = node as usize;
            if idx >= nodes.len() {
                return Err(Error::Arc("arc-squeeze: node index oob".to_owned()));
            }
            node = nodes[idx].child[bit as usize];
        }
        let value: u16 = (-(node) - 1) as u16;
        if value == SQ_SPEOF {
            break;
        }
        rle_out.push(value as u8);
        if rle_out.len() > cap {
            return Err(Error::Arc("arc-squeeze: output exceeds cap".to_owned()));
        }
    }
    un_rle(&rle_out, cap)
}

fn read_i16(input: &[u8], cursor: &mut usize) -> Result<i16> {
    let s: &[u8] = input
        .get(*cursor..*cursor + 2)
        .ok_or_else(|| Error::Arc("arc-squeeze: truncated node table".to_owned()))?;
    *cursor += 2;
    Ok(i16::from_le_bytes([s[0], s[1]]))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum TestHash {
        Old,
        New,
    }

    #[derive(Clone)]
    struct TestEntry {
        used: bool,
        next: usize,
        predecessor: u16,
        follower: u8,
    }

    fn test_hash(predecessor: u16, follower: u8, hash: TestHash) -> usize {
        let sum: u16 = predecessor.wrapping_add(u16::from(follower));
        match hash {
            TestHash::Old => {
                let key: u32 = u32::from(sum | 0x0800);
                ((key.wrapping_mul(key) >> 6) & 0x0fff) as usize
            }
            TestHash::New => usize::from(sum.wrapping_mul(15_073) & 0x0fff),
        }
    }

    fn test_slot(table: &mut [TestEntry], predecessor: u16, follower: u8, hash: TestHash) -> usize {
        let mut slot: usize = test_hash(predecessor, follower, hash);
        if !table[slot].used {
            return slot;
        }
        while table[slot].next != 0 {
            slot = table[slot].next;
        }
        let mut free: usize = (slot + 101) & 0x0fff;
        for _ in 0..table.len() {
            if !table[free].used {
                table[slot].next = free;
                return free;
            }
            free = (free + 1) & 0x0fff;
        }
        usize::MAX
    }

    fn test_insert(
        table: &mut [TestEntry],
        predecessor: u16,
        follower: u8,
        hash: TestHash,
    ) -> usize {
        let slot: usize = test_slot(table, predecessor, follower, hash);
        assert_ne!(slot, usize::MAX);
        table[slot] = TestEntry {
            used: true,
            next: 0,
            predecessor,
            follower,
        };
        slot
    }

    fn test_find(
        table: &[TestEntry],
        predecessor: u16,
        follower: u8,
        hash: TestHash,
    ) -> Option<usize> {
        let mut slot: usize = test_hash(predecessor, follower, hash);
        loop {
            let entry: &TestEntry = &table[slot];
            if !entry.used {
                return None;
            }
            if entry.predecessor == predecessor && entry.follower == follower {
                return Some(slot);
            }
            if entry.next == 0 {
                return None;
            }
            slot = entry.next;
        }
    }

    fn pack_fixed_codes(codes: &[usize]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(codes.len().div_ceil(2) * 3);
        for pair in codes.chunks(2) {
            let first: u16 = pair[0] as u16;
            out.push((first >> 4) as u8);
            let second: u16 = pair.get(1).copied().unwrap_or(0) as u16;
            out.push(((first & 0x0f) << 4) as u8 | (second >> 8) as u8);
            if pair.len() == 2 {
                out.push(second as u8);
            }
        }
        out
    }

    fn fixed_lzw_encode(input: &[u8], hash: TestHash) -> Vec<u8> {
        const NO_PREDECESSOR: u16 = u16::MAX;
        let blank: TestEntry = TestEntry {
            used: false,
            next: 0,
            predecessor: 0,
            follower: 0,
        };
        let mut table: Vec<TestEntry> = vec![blank; 4096];
        for literal in 0_u16..=255 {
            test_insert(&mut table, NO_PREDECESSOR, literal as u8, hash);
        }
        let Some((&first, rest)): Option<(&u8, &[u8])> = input.split_first() else {
            return Vec::new();
        };
        let mut current: usize =
            test_find(&table, NO_PREDECESSOR, first, hash).expect("literal must be initialized");
        let mut codes: Vec<usize> = Vec::new();
        let mut remaining: usize = 4096 - 256;
        for &follower in rest {
            if let Some(next) = test_find(&table, current as u16, follower, hash) {
                current = next;
                continue;
            }
            codes.push(current);
            if remaining > 0 {
                test_insert(&mut table, current as u16, follower, hash);
                remaining -= 1;
            }
            current = test_find(&table, NO_PREDECESSOR, follower, hash)
                .expect("literal must be initialized");
        }
        codes.push(current);
        pack_fixed_codes(&codes)
    }

    #[test]
    fn fixed_old_hash_lzw_decodes_method_five_payload() {
        let input: Vec<u8> = b"TOBEORNOTTOBEORTOBEORNOT".repeat(32);
        let encoded: Vec<u8> = fixed_lzw_encode(&input, TestHash::Old);
        let decoded: Vec<u8> = un_crunch_fixed(&encoded, false, input.len()).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn fixed_new_hash_lzw_decodes_method_seven_intermediate_stream() {
        let input: Vec<u8> = rle_encode(&[
            b'A', b'A', b'A', b'A', b'A', 0x90, 0x90, b'B', b'C', b'C', b'C', b'C',
        ]);
        let encoded: Vec<u8> = fixed_lzw_encode(&input, TestHash::New);
        let decoded: Vec<u8> = un_crunch_fixed(&encoded, true, input.len()).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn fixed_lzw_rejects_truncated_and_uninitialized_codes() {
        let truncated: Result<Vec<u8>> = un_crunch_fixed(&[0x12], false, 64);
        assert!(matches!(truncated, Err(Error::Arc(message)) if message.contains("truncated")));

        let uninitialized: Vec<u8> = pack_fixed_codes(&[4095]);
        let invalid: Result<Vec<u8>> = un_crunch_fixed(&uninitialized, false, 64);
        assert!(matches!(invalid, Err(Error::Arc(message)) if message.contains("first code")));
    }

    #[test]
    fn fixed_lzw_accepts_one_terminal_code_in_two_bytes() {
        const NO_PREDECESSOR: u16 = u16::MAX;
        let blank: TestEntry = TestEntry {
            used: false,
            next: 0,
            predecessor: 0,
            follower: 0,
        };
        let mut table: Vec<TestEntry> = vec![blank; 4096];
        let literal: usize = test_insert(&mut table, NO_PREDECESSOR, b'Q', TestHash::Old);
        let encoded: Vec<u8> = pack_fixed_codes(&[literal]);
        let decoded: Vec<u8> = un_crunch_fixed(&encoded, false, 1).expect("terminal code");
        assert_eq!(decoded, b"Q");
    }

    #[test]
    fn fixed_lzw_enforces_the_output_cap_during_expansion() {
        let input: Vec<u8> = b"bounded fixed dictionary output".repeat(16);
        let encoded: Vec<u8> = fixed_lzw_encode(&input, TestHash::Old);
        let decoded: Result<Vec<u8>> = un_crunch_fixed(&encoded, false, input.len() - 1);
        assert!(
            matches!(decoded, Err(Error::Arc(message)) if message.contains("output exceeds cap"))
        );
    }

    #[test]
    fn fixed_lzw_accepts_the_exact_undefined_code_insertion_slot() {
        let input: &[u8] = b"AAA";
        let encoded: Vec<u8> = fixed_lzw_encode(input, TestHash::Old);
        let decoded: Vec<u8> = un_crunch_fixed(&encoded, false, input.len())
            .expect("decode exact undefined insertion slot");
        assert_eq!(decoded, input);
    }

    #[test]
    fn fixed_dictionary_bounds_collisions_saturation_and_cycles() {
        let mut table: FixedTable = FixedTable::new(FixedHash::Old).expect("initialize table");
        let mut collision: Option<((u16, u8), (u16, u8))> = None;
        let mut seen: Vec<Option<(u16, u8)>> = vec![None; FIXED_TABLE_SIZE];
        'outer: for predecessor in 0_u16..512 {
            for follower in 0_u8..=255 {
                let hash: usize = fixed_hash(predecessor, follower, FixedHash::Old);
                if let Some(prior) = seen[hash] {
                    if prior != (predecessor, follower) {
                        collision = Some((prior, (predecessor, follower)));
                        break 'outer;
                    }
                } else {
                    seen[hash] = Some((predecessor, follower));
                }
            }
        }
        let (first, second): ((u16, u8), (u16, u8)) = collision.expect("find hash collision");
        let first_slot: usize = table
            .insert(first.0, first.1)
            .expect("insert first collision");
        let second_slot: usize = table
            .insert(second.0, second.1)
            .expect("insert second collision");
        assert_ne!(first_slot, second_slot);

        while table.remaining > 0 {
            let ordinal: usize = table.remaining;
            let _: usize = table
                .insert(ordinal as u16, ordinal as u8)
                .expect("fill bounded dictionary");
        }
        assert!(matches!(
            table.insert(0, 0),
            Err(Error::Arc(message)) if message.contains("full")
        ));

        let mut corrupt: FixedTable = FixedTable::new(FixedHash::New).expect("initialize table");
        let slot: usize = corrupt.insert(1, 2).expect("insert corruptible entry");
        corrupt.entries[slot].predecessor = slot as u16;
        let mut stack: Vec<u8> = Vec::new();
        assert!(matches!(
            corrupt.expand(slot, &mut stack),
            Err(Error::Arc(message)) if message.contains("cyclic")
        ));
    }

    fn rle_encode(input: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i < input.len() {
            let byte: u8 = input[i];
            let mut run: usize = 1;
            while i + run < input.len() && input[i + run] == byte && run < 255 {
                run += 1;
            }
            if byte == RLE_MARKER {
                for _ in 0..run {
                    out.push(RLE_MARKER);
                    out.push(0);
                }
                i += run;
            } else if run >= 4 {
                out.push(byte);
                out.push(RLE_MARKER);
                out.push(run as u8);
                i += run;
            } else {
                out.push(byte);
                i += 1;
            }
        }
        out
    }

    struct LzwBitWriter {
        out: Vec<u8>,
        group: Vec<u8>,
        bit_pos: usize,
        width: u32,
    }

    impl LzwBitWriter {
        fn new() -> Self {
            Self {
                out: Vec::new(),
                group: Vec::new(),
                bit_pos: 0,
                width: 0,
            }
        }

        fn write_code(&mut self, code: u32, width: u32) {
            if self.width != 0 && self.width != width {
                self.flush_group(true);
            }
            if self.width == 0 {
                self.width = width;
                self.group.resize(width as usize, 0);
            }
            for i in 0..width {
                let bit: u8 = ((code >> i) & 1) as u8;
                let byte_index: usize = self.bit_pos / 8;
                let bit_index: u32 = (self.bit_pos % 8) as u32;
                self.group[byte_index] |= bit << bit_index;
                self.bit_pos += 1;
            }
            if self.bit_pos == width as usize * 8 {
                self.flush_group(true);
            }
        }

        fn flush_group(&mut self, complete: bool) {
            if self.bit_pos == 0 {
                return;
            }
            let bytes: usize = if complete {
                self.width as usize
            } else {
                self.bit_pos.div_ceil(8)
            };
            self.out.extend_from_slice(&self.group[..bytes]);
            self.group.fill(0);
            self.bit_pos = 0;
            self.width = 0;
        }

        fn realign(&mut self) {
            self.flush_group(true);
        }

        fn finish(mut self) -> Vec<u8> {
            self.flush_group(false);
            self.out
        }
    }

    fn lzw_encode(input: &[u8], max_bits: u32) -> Vec<u8> {
        let first_code: u32 = 257;
        let mut writer: LzwBitWriter = LzwBitWriter::new();
        let mut table: std::collections::BTreeMap<Vec<u8>, u32> = std::collections::BTreeMap::new();
        let mut next_code: u32 = first_code;
        let mut width: u32 = LZW_MIN_BITS;
        if input.is_empty() {
            return writer.finish();
        }
        let emit = |code: u32, next_code: u32, width: &mut u32, writer: &mut LzwBitWriter| {
            writer.write_code(code, *width);
            if next_code > (1 << *width) - 1 && *width < max_bits {
                *width += 1;
            }
        };
        let mut current: Vec<u8> = vec![input[0]];
        for &byte in &input[1..] {
            let mut candidate: Vec<u8> = current.clone();
            candidate.push(byte);
            if table.contains_key(&candidate) || candidate.len() == 1 {
                current = candidate;
            } else {
                let code: u32 = emit_string(&current, &table);
                emit(code, next_code, &mut width, &mut writer);
                if next_code < (1 << max_bits) {
                    table.insert(candidate, next_code);
                    next_code += 1;
                }
                current = vec![byte];
            }
        }
        let code: u32 = emit_string(&current, &table);
        emit(code, next_code, &mut width, &mut writer);
        writer.finish()
    }

    fn emit_string(s: &[u8], table: &std::collections::BTreeMap<Vec<u8>, u32>) -> u32 {
        if s.len() == 1 {
            u32::from(s[0])
        } else {
            *table.get(s).expect("string in table")
        }
    }

    #[test]
    fn rle_round_trip() {
        let mut input: Vec<u8> = b"aaaaa bbbb".to_vec();
        input.extend(std::iter::repeat_n(0x90u8, 3));
        input.extend_from_slice(b" zz");
        let encoded: Vec<u8> = rle_encode(&input);
        let decoded: Vec<u8> = un_rle(&encoded, 1 << 20).expect("un_rle");
        assert_eq!(decoded, input);
    }

    #[test]
    fn crunch_lzw_round_trip() {
        let mut input: Vec<u8> = Vec::new();
        for _ in 0..50 {
            input.extend_from_slice(b"the quick brown fox ");
        }
        let lzw: Vec<u8> = lzw_encode(&input, 12);
        let decoded: Vec<u8> = lzw_decode(&lzw, 12, 1 << 20).expect("lzw decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn squash_13bit_round_trip() {
        let input: Vec<u8> = (0u8..=255).cycle().take(5000).collect();
        let lzw: Vec<u8> = lzw_encode(&input, 13);
        let decoded: Vec<u8> = un_squash(&lzw, 1 << 20).expect("squash decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn crunch_with_rle_round_trip() {
        let mut input: Vec<u8> = Vec::new();
        input.extend(std::iter::repeat_n(b'X', 200));
        input.extend_from_slice(b"crunch+rle payload crunch+rle payload");
        let rle: Vec<u8> = rle_encode(&input);
        let mut lzw: Vec<u8> = vec![12];
        lzw.extend(lzw_encode(&rle, 12));
        let decoded: Vec<u8> = un_crunch(&lzw, 1 << 20).expect("un_crunch");
        assert_eq!(decoded, input);
    }

    #[test]
    fn dynamic_lzw_clear_realigns_the_code_group() {
        let mut writer: LzwBitWriter = LzwBitWriter::new();
        for code in [u32::from(b'A'), u32::from(b'B'), LZW_CLEAR] {
            writer.write_code(code, LZW_MIN_BITS);
        }
        writer.realign();
        for code in [u32::from(b'C'), u32::from(b'D')] {
            writer.write_code(code, LZW_MIN_BITS);
        }
        let encoded: Vec<u8> = writer.finish();
        let decoded: Vec<u8> = un_squash(&encoded, 4).expect("decode clear-aligned stream");
        assert_eq!(decoded, b"ABCD");

        let mut truncated_writer: LzwBitWriter = LzwBitWriter::new();
        truncated_writer.write_code(u32::from(b'A'), LZW_MIN_BITS);
        truncated_writer.write_code(LZW_CLEAR, LZW_MIN_BITS);
        let truncated: Vec<u8> = truncated_writer.finish();
        assert!(matches!(
            un_squash(&truncated, 4),
            Err(Error::Arc(message)) if message.contains("no following code")
        ));
    }

    #[test]
    fn dynamic_lzw_rejects_invalid_method8_headers_and_bit_underruns() {
        assert!(matches!(
            un_crunch(&[], 16),
            Err(Error::Arc(message)) if message.contains("missing method 8 width header")
        ));
        assert!(matches!(
            un_crunch(&[13, 0, 0], 16),
            Err(Error::Arc(message)) if message.contains("expected 12")
        ));
        assert!(matches!(
            un_squash(&[0], 16),
            Err(Error::Arc(message)) if message.contains("bit underrun")
        ));
        let mut writer: LzwBitWriter = LzwBitWriter::new();
        writer.write_code(u32::from(b'A'), LZW_MIN_BITS);
        writer.write_code(300, LZW_MIN_BITS);
        assert!(matches!(
            un_squash(&writer.finish(), 16),
            Err(Error::Arc(message)) if message.contains("ahead of table")
        ));
    }

    enum TreeNode {
        Leaf(u16),
        Internal(Box<Self>, Box<Self>),
    }

    fn build_squeeze_tree(freqs: &[u32; SQ_NUMVALS]) -> (Vec<[i16; 2]>, Vec<(u32, u32)>) {
        let mut forest: Vec<(u64, TreeNode)> = Vec::new();
        for (value, &f) in freqs.iter().enumerate() {
            if f > 0 || value == SQ_SPEOF as usize {
                forest.push((u64::from(f) + 1, TreeNode::Leaf(value as u16)));
            }
        }
        if forest.len() == 1 {
            let (_, node): (u64, TreeNode) = forest.pop().expect("single");
            forest.push((
                1,
                TreeNode::Internal(Box::new(node), Box::new(TreeNode::Leaf(0))),
            ));
        }
        while forest.len() > 1 {
            forest.sort_by_key(|(w, _)| std::cmp::Reverse(*w));
            let (wa, a): (u64, TreeNode) = forest.pop().expect("a");
            let (wb, b): (u64, TreeNode) = forest.pop().expect("b");
            forest.push((wa + wb, TreeNode::Internal(Box::new(a), Box::new(b))));
        }
        let (_, root): (u64, TreeNode) = forest.pop().expect("root");
        let mut table: Vec<[i16; 2]> = Vec::new();
        assign_table(&root, &mut table);
        let mut codes: Vec<(u32, u32)> = vec![(0, 0); SQ_NUMVALS];
        walk_codes(&table, 0, 0, 0, &mut codes);
        (table, codes)
    }

    fn assign_table(node: &TreeNode, table: &mut Vec<[i16; 2]>) -> i16 {
        match node {
            TreeNode::Leaf(value) => -(i16::try_from(*value).expect("value")) - 1,
            TreeNode::Internal(left, right) => {
                let slot: usize = table.len();
                table.push([0, 0]);
                let l: i16 = assign_table(left, table);
                let r: i16 = assign_table(right, table);
                table[slot] = [l, r];
                slot as i16
            }
        }
    }

    fn walk_codes(table: &[[i16; 2]], node: i16, code: u32, len: u32, codes: &mut [(u32, u32)]) {
        if node < 0 {
            let value: usize = (-node - 1) as usize;
            codes[value] = (code, len);
            return;
        }
        let idx: usize = node as usize;
        walk_codes(table, table[idx][0], code, len + 1, codes);
        walk_codes(table, table[idx][1], code | (1 << len), len + 1, codes);
    }

    fn squeeze_encode(input: &[u8]) -> Vec<u8> {
        let rle: Vec<u8> = rle_encode(input);
        let mut freqs: [u32; SQ_NUMVALS] = [0; SQ_NUMVALS];
        for &b in &rle {
            freqs[b as usize] += 1;
        }
        freqs[SQ_SPEOF as usize] = 1;
        let (table, codes): (Vec<[i16; 2]>, Vec<(u32, u32)>) = build_squeeze_tree(&freqs);
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&(table.len() as u16).to_le_bytes());
        for entry in &table {
            out.extend_from_slice(&entry[0].to_le_bytes());
            out.extend_from_slice(&entry[1].to_le_bytes());
        }
        let mut bit_buf: u32 = 0;
        let mut bit_count: u32 = 0;
        let mut emit = |code: u32, len: u32, out: &mut Vec<u8>| {
            for i in 0..len {
                let bit: u32 = (code >> i) & 1;
                bit_buf |= bit << bit_count;
                bit_count += 1;
                if bit_count == 8 {
                    out.push(bit_buf as u8);
                    bit_buf = 0;
                    bit_count = 0;
                }
            }
        };
        for &b in &rle {
            let (code, len): (u32, u32) = codes[b as usize];
            emit(code, len, &mut out);
        }
        let (eof_code, eof_len): (u32, u32) = codes[SQ_SPEOF as usize];
        emit(eof_code, eof_len, &mut out);
        if bit_count > 0 {
            out.push(bit_buf as u8);
        }
        out
    }

    #[test]
    fn squeeze_round_trip() {
        let input: &[u8] =
            b"squeeze huffman coded payload with some repetition aaaa bbbb cccc squeeze";
        let encoded: Vec<u8> = squeeze_encode(input);
        let decoded: Vec<u8> = un_squeeze(&encoded, 1 << 20).expect("un_squeeze");
        assert_eq!(decoded, input);
    }
}
