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

struct LzwBitReader<'a> {
    src: &'a [u8],
    bit_pos: usize,
}

impl<'a> LzwBitReader<'a> {
    const fn new(src: &'a [u8]) -> Self {
        Self { src, bit_pos: 0 }
    }

    fn read_code(&mut self, width: u32) -> Option<u32> {
        let mut code: u32 = 0;
        for i in 0..width {
            let byte_index: usize = self.bit_pos / 8;
            let bit_index: u32 = (self.bit_pos % 8) as u32;
            let byte: u8 = *self.src.get(byte_index)?;
            let bit: u32 = u32::from((byte >> bit_index) & 1);
            code |= bit << i;
            self.bit_pos += 1;
        }
        Some(code)
    }
}

const LZW_CLEAR: u32 = 256;
const LZW_MIN_BITS: u32 = 9;

fn lzw_decode(input: &[u8], max_bits: u32, has_clear: bool, cap: usize) -> Result<Vec<u8>> {
    let first_code: u32 = if has_clear { 257 } else { 256 };
    let mut reader: LzwBitReader<'_> = LzwBitReader::new(input);
    let mut out: Vec<u8> = Vec::new();
    let mut prefix: Vec<u32> = vec![0; 1 << max_bits];
    let mut suffix: Vec<u8> = vec![0; 1 << max_bits];
    let mut stack: Vec<u8> = Vec::with_capacity(1 << max_bits);
    let mut next_code: u32 = first_code;
    let mut width: u32 = LZW_MIN_BITS;
    let mut old_code: Option<u32> = None;
    let mut first_byte: u8 = 0;

    loop {
        if next_code + 1 > (1 << width) - 1 && width < max_bits {
            width += 1;
        }
        let Some(code) = reader.read_code(width) else {
            break;
        };
        if has_clear && code == LZW_CLEAR {
            next_code = first_code;
            width = LZW_MIN_BITS;
            old_code = None;
            continue;
        }
        let Some(prev) = old_code else {
            if code > 0xFF {
                return Err(Error::Arc(
                    "arc-lzw: first code is not a literal".to_owned(),
                ));
            }
            first_byte = code as u8;
            out.push(first_byte);
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
    let lzw: Vec<u8> = lzw_decode(input, 12, true, cap)?;
    un_rle(&lzw, cap)
}

pub fn un_squash(input: &[u8], cap: usize) -> Result<Vec<u8>> {
    lzw_decode(input, 13, false, cap)
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
        bit_pos: usize,
    }

    impl LzwBitWriter {
        fn new() -> Self {
            Self {
                out: Vec::new(),
                bit_pos: 0,
            }
        }

        fn write_code(&mut self, code: u32, width: u32) {
            for i in 0..width {
                let bit: u8 = ((code >> i) & 1) as u8;
                let byte_index: usize = self.bit_pos / 8;
                let bit_index: u32 = (self.bit_pos % 8) as u32;
                if byte_index >= self.out.len() {
                    self.out.push(0);
                }
                self.out[byte_index] |= bit << bit_index;
                self.bit_pos += 1;
            }
        }
    }

    fn lzw_encode(input: &[u8], max_bits: u32, has_clear: bool) -> Vec<u8> {
        let first_code: u32 = if has_clear { 257 } else { 256 };
        let mut writer: LzwBitWriter = LzwBitWriter::new();
        let mut table: std::collections::BTreeMap<Vec<u8>, u32> = std::collections::BTreeMap::new();
        let mut next_code: u32 = first_code;
        let mut width: u32 = LZW_MIN_BITS;
        if input.is_empty() {
            return writer.out;
        }
        let emit = |code: u32, next_code: u32, width: &mut u32, writer: &mut LzwBitWriter| {
            if next_code > (1 << *width) - 1 && *width < max_bits {
                *width += 1;
            }
            writer.write_code(code, *width);
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
        writer.out
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
        let lzw: Vec<u8> = lzw_encode(&input, 12, true);
        let decoded: Vec<u8> = lzw_decode(&lzw, 12, true, 1 << 20).expect("lzw decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn squash_13bit_round_trip() {
        let input: Vec<u8> = (0u8..=255).cycle().take(5000).collect();
        let lzw: Vec<u8> = lzw_encode(&input, 13, false);
        let decoded: Vec<u8> = un_squash(&lzw, 1 << 20).expect("squash decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn crunch_with_rle_round_trip() {
        let mut input: Vec<u8> = Vec::new();
        input.extend(std::iter::repeat_n(b'X', 200));
        input.extend_from_slice(b"crunch+rle payload crunch+rle payload");
        let rle: Vec<u8> = rle_encode(&input);
        let lzw: Vec<u8> = lzw_encode(&rle, 12, true);
        let decoded: Vec<u8> = un_crunch(&lzw, 1 << 20).expect("un_crunch");
        assert_eq!(decoded, input);
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
