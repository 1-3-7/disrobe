use crate::error::{Error, Result};

const NUM_COMMANDS: usize = 510;
const NUM_TEMP_CODELEN: usize = 20;
const MIN_MATCH: usize = 3;

#[derive(Debug, Clone, Copy)]
pub struct LhaParams {
    pub history_bits: u32,
    pub offset_bits: u32,
}

pub const LH5: LhaParams = LhaParams {
    history_bits: 14,
    offset_bits: 4,
};
pub const LH6: LhaParams = LhaParams {
    history_bits: 15,
    offset_bits: 5,
};
pub const LH7: LhaParams = LhaParams {
    history_bits: 17,
    offset_bits: 5,
};

struct BitReader<'a> {
    src: &'a [u8],
    byte_pos: usize,
    bit_pos: u32,
}

impl<'a> BitReader<'a> {
    const fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bit(&mut self) -> Result<u32> {
        let byte: u8 = *self
            .src
            .get(self.byte_pos)
            .ok_or_else(|| Error::Decompression("lha: bitstream underrun".to_owned()))?;
        let bit: u32 = u32::from((byte >> (7 - self.bit_pos)) & 1);
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Ok(bit)
    }

    fn read_bits(&mut self, n: u32) -> Result<u32> {
        let mut value: u32 = 0;
        for _ in 0..n {
            value = (value << 1) | self.read_bit()?;
        }
        Ok(value)
    }
}

struct HuffTree {
    tree: Vec<i32>,
    single: Option<u16>,
}

impl HuffTree {
    const fn single(value: u16) -> Self {
        Self {
            tree: Vec::new(),
            single: Some(value),
        }
    }

    fn build(lengths: &[u8]) -> Result<Self> {
        let mut tree: Vec<i32> = Vec::new();
        let mut max_allocated: usize = 1;
        let mut current_len: u8 = 1;
        loop {
            let max_limit: usize = max_allocated;
            while tree.len() < max_limit {
                tree.push(-(max_allocated as i32));
                max_allocated += 2;
            }
            let mut more_leaves: bool = false;
            for (value, &len) in lengths.iter().enumerate() {
                match len.cmp(&current_len) {
                    std::cmp::Ordering::Equal => tree.push(value as i32 + 1),
                    std::cmp::Ordering::Greater => more_leaves = true,
                    std::cmp::Ordering::Less => {}
                }
            }
            if tree.len() > max_allocated {
                return Err(Error::Decompression(
                    "lha: too many huffman leaves".to_owned(),
                ));
            }
            if !more_leaves {
                break;
            }
            current_len = current_len
                .checked_add(1)
                .ok_or_else(|| Error::Decompression("lha: huffman depth overflow".to_owned()))?;
        }
        if tree.len() != max_allocated {
            return Err(Error::Decompression(
                "lha: incomplete huffman tree".to_owned(),
            ));
        }
        Ok(Self { tree, single: None })
    }

    fn read(&self, reader: &mut BitReader<'_>) -> Result<u16> {
        if let Some(value) = self.single {
            return Ok(value);
        }
        let mut node: i32 = self.tree[0];
        loop {
            if node > 0 {
                return Ok((node - 1) as u16);
            }
            let branch: usize = (-node) as usize;
            let index: usize = branch + reader.read_bit()? as usize;
            node = *self
                .tree
                .get(index)
                .ok_or_else(|| Error::Decompression("lha: huffman index oob".to_owned()))?;
        }
    }
}

fn read_code_length(reader: &mut BitReader<'_>) -> Result<u8> {
    let mut len: u8 = reader.read_bits(3)? as u8;
    if len == 7 {
        while reader.read_bit()? == 1 {
            len = len
                .checked_add(1)
                .ok_or_else(|| Error::Decompression("lha: code length overflow".to_owned()))?;
        }
    }
    Ok(len)
}

fn read_code_skip(reader: &mut BitReader<'_>, skip_range: u16) -> Result<usize> {
    let (bits, increment): (u32, usize) = match skip_range {
        0 => return Ok(1),
        1 => (4, 3),
        _ => (9, 20),
    };
    Ok(reader.read_bits(bits)? as usize + increment)
}

fn read_temp_tree(reader: &mut BitReader<'_>) -> Result<HuffTree> {
    let num_codes: usize = reader.read_bits(5)? as usize;
    if num_codes == 0 {
        let code: u16 = reader.read_bits(5)? as u16;
        return Ok(HuffTree::single(code));
    }
    if num_codes > NUM_TEMP_CODELEN {
        return Err(Error::Decompression(
            "lha: temp codelen too large".to_owned(),
        ));
    }
    let mut lengths: [u8; NUM_TEMP_CODELEN] = [0; NUM_TEMP_CODELEN];
    for slot in &mut lengths[0..num_codes.min(3)] {
        *slot = read_code_length(reader)?;
    }
    let skip: usize = reader.read_bits(2)? as usize;
    if 3 + skip > num_codes {
        return Err(Error::Decompression(
            "lha: temp codelen skip invalid".to_owned(),
        ));
    }
    for slot in &mut lengths[3 + skip..num_codes] {
        *slot = read_code_length(reader)?;
    }
    HuffTree::build(&lengths[0..num_codes])
}

fn read_command_tree(reader: &mut BitReader<'_>, temp: &HuffTree) -> Result<HuffTree> {
    let num_codes: usize = reader.read_bits(9)? as usize;
    if num_codes == 0 {
        let code: u16 = reader.read_bits(9)? as u16;
        return Ok(HuffTree::single(code));
    }
    if num_codes > NUM_COMMANDS {
        return Err(Error::Decompression(
            "lha: command codelen too large".to_owned(),
        ));
    }
    let mut lengths: Vec<u8> = vec![0; num_codes];
    let mut index: usize = 0;
    'outer: while index < num_codes {
        let remaining: usize = num_codes - index;
        for n in 0..remaining {
            match temp.read(reader)? {
                skip_range @ 0..=2 => {
                    let skip_count: usize = read_code_skip(reader, skip_range)?;
                    index += n + skip_count;
                    continue 'outer;
                }
                code => {
                    lengths[index + n] = (code - 2) as u8;
                }
            }
        }
        break;
    }
    HuffTree::build(&lengths)
}

fn read_offset_tree(reader: &mut BitReader<'_>, params: LhaParams) -> Result<HuffTree> {
    let num_codes: usize = reader.read_bits(params.offset_bits)? as usize;
    if num_codes == 0 {
        let code: u16 = reader.read_bits(params.offset_bits)? as u16;
        return Ok(HuffTree::single(code));
    }
    if num_codes > params.history_bits as usize {
        return Err(Error::Decompression(
            "lha: offset codelen too large".to_owned(),
        ));
    }
    let mut lengths: Vec<u8> = vec![0; num_codes];
    for slot in &mut lengths {
        *slot = read_code_length(reader)?;
    }
    HuffTree::build(&lengths)
}

fn read_offset(reader: &mut BitReader<'_>, offset_tree: &HuffTree) -> Result<usize> {
    let bits: u32 = u32::from(offset_tree.read(reader)?);
    match bits {
        0 | 1 => Ok(bits as usize),
        _ => {
            let rest: u32 = reader.read_bits(bits - 1)?;
            Ok((rest | (1 << (bits - 1))) as usize)
        }
    }
}

pub fn decode(params: LhaParams, src: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    let mut reader: BitReader<'_> = BitReader::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(expected_len);
    while out.len() < expected_len {
        let mut remaining_commands: u32 = reader.read_bits(16)?;
        if remaining_commands == 0 {
            return Err(Error::Decompression("lha: zero-command block".to_owned()));
        }
        let temp: HuffTree = read_temp_tree(&mut reader)?;
        let command_tree: HuffTree = read_command_tree(&mut reader, &temp)?;
        let offset_tree: HuffTree = read_offset_tree(&mut reader, params)?;
        while remaining_commands > 0 && out.len() < expected_len {
            remaining_commands -= 1;
            let command: u16 = command_tree.read(&mut reader)?;
            if command <= 0xff {
                out.push(command as u8);
            } else {
                let length: usize = command as usize - 0x100 + MIN_MATCH;
                let offset: usize = read_offset(&mut reader, &offset_tree)?;
                let distance: usize = offset + 1;
                if distance > out.len() {
                    return Err(Error::Decompression(format!(
                        "lha: match distance {distance} exceeds output {}",
                        out.len()
                    )));
                }
                let start: usize = out.len() - distance;
                for i in 0..length {
                    let byte: u8 = out[start + i];
                    out.push(byte);
                    if out.len() >= expected_len {
                        break;
                    }
                }
            }
        }
    }
    if out.len() != expected_len {
        return Err(Error::Decompression(format!(
            "lha: decoded {} bytes, expected {expected_len}",
            out.len()
        )));
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const MAX_MATCH: usize = 256;

    #[derive(Debug, Clone, Copy)]
    enum Token {
        Literal(u8),
        Match { length: usize, distance: usize },
    }

    fn greedy_tokens(input: &[u8], params: LhaParams) -> Vec<Token> {
        let window: usize = 1 << params.history_bits;
        let mut tokens: Vec<Token> = Vec::new();
        let mut pos: usize = 0;
        while pos < input.len() {
            let lower: usize = pos.saturating_sub(window);
            let max_len: usize = (input.len() - pos).min(MAX_MATCH);
            let mut best_len: usize = 0;
            let mut best_dist: usize = 0;
            for start in lower..pos {
                let mut len: usize = 0;
                while len < max_len && input[start + len] == input[pos + len] {
                    len += 1;
                }
                if len > best_len {
                    best_len = len;
                    best_dist = pos - start;
                }
            }
            if best_len >= MIN_MATCH {
                tokens.push(Token::Match {
                    length: best_len,
                    distance: best_dist,
                });
                pos += best_len;
            } else {
                tokens.push(Token::Literal(input[pos]));
                pos += 1;
            }
        }
        tokens
    }

    #[derive(Clone)]
    struct Node {
        weight: u64,
        symbol: Option<usize>,
        left: usize,
        right: usize,
    }

    fn canonical_lengths(freqs: &[u32], limit: u8) -> Vec<u8> {
        let symbols: Vec<usize> = (0..freqs.len()).filter(|&i| freqs[i] > 0).collect();
        let mut lengths: Vec<u8> = vec![0; freqs.len()];
        if symbols.is_empty() {
            return lengths;
        }
        if symbols.len() == 1 {
            lengths[symbols[0]] = 1;
            return lengths;
        }
        let mut nodes: Vec<Node> = symbols
            .iter()
            .map(|&s| Node {
                weight: u64::from(freqs[s]),
                symbol: Some(s),
                left: 0,
                right: 0,
            })
            .collect();
        let mut heap: Vec<usize> = (0..nodes.len()).collect();
        while heap.len() > 1 {
            heap.sort_by_key(|&i| std::cmp::Reverse(nodes[i].weight));
            let a: usize = heap.pop().expect("a");
            let b: usize = heap.pop().expect("b");
            nodes.push(Node {
                weight: nodes[a].weight + nodes[b].weight,
                symbol: None,
                left: a,
                right: b,
            });
            heap.push(nodes.len() - 1);
        }
        let root: usize = heap[0];
        assign_depths(&nodes, root, 0, &mut lengths);
        for len in &mut lengths {
            if *len > limit {
                *len = limit;
            }
        }
        lengths
    }

    fn assign_depths(nodes: &[Node], index: usize, depth: u8, lengths: &mut [u8]) {
        if let Some(symbol) = nodes[index].symbol {
            lengths[symbol] = depth.max(1);
        } else {
            assign_depths(nodes, nodes[index].left, depth + 1, lengths);
            assign_depths(nodes, nodes[index].right, depth + 1, lengths);
        }
    }

    fn canonical_codes(lengths: &[u8]) -> Vec<(u32, u8)> {
        let max_len: u8 = lengths.iter().copied().max().map_or(0, |value: u8| value);
        let mut bl_count: Vec<u32> = vec![0; (max_len + 1) as usize];
        for &len in lengths {
            if len > 0 {
                bl_count[len as usize] += 1;
            }
        }
        let mut next_code: Vec<u32> = vec![0; (max_len + 1) as usize];
        let mut code: u32 = 0;
        for bits in 1..=max_len as usize {
            code = (code + bl_count[bits - 1]) << 1;
            next_code[bits] = code;
        }
        let mut codes: Vec<(u32, u8)> = vec![(0, 0); lengths.len()];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len > 0 {
                codes[symbol] = (next_code[len as usize], len);
                next_code[len as usize] += 1;
            }
        }
        codes
    }

    struct BitWriter {
        out: Vec<u8>,
        cur: u8,
        nbits: u32,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                out: Vec::new(),
                cur: 0,
                nbits: 0,
            }
        }

        fn put_bit(&mut self, bit: u32) {
            self.cur = (self.cur << 1) | (bit as u8 & 1);
            self.nbits += 1;
            if self.nbits == 8 {
                self.out.push(self.cur);
                self.cur = 0;
                self.nbits = 0;
            }
        }

        fn put_bits(&mut self, value: u32, n: u32) {
            for i in (0..n).rev() {
                self.put_bit((value >> i) & 1);
            }
        }

        fn finish(mut self) -> Vec<u8> {
            if self.nbits > 0 {
                self.cur <<= 8 - self.nbits;
                self.out.push(self.cur);
            }
            self.out
        }
    }

    fn write_code_length(w: &mut BitWriter, len: u8) {
        if len < 7 {
            w.put_bits(u32::from(len), 3);
        } else {
            w.put_bits(7, 3);
            for _ in 0..(len - 7) {
                w.put_bit(1);
            }
            w.put_bit(0);
        }
    }

    fn offset_to_bits_code(distance: usize) -> (u16, u32, u32) {
        let offset: u32 = (distance - 1) as u32;
        if offset == 0 {
            return (0, 0, 0);
        }
        if offset == 1 {
            return (1, 0, 0);
        }
        let bits: u32 = 32 - offset.leading_zeros();
        let extra: u32 = offset & ((1 << (bits - 1)) - 1);
        (bits as u16, extra, bits - 1)
    }

    #[derive(Debug, Clone, Copy)]
    enum TempSym {
        Skip(u16, u32, u32),
        Length(u16),
    }

    fn command_temp_stream(cmd_lengths: &[u8]) -> Vec<TempSym> {
        let mut stream: Vec<TempSym> = Vec::new();
        let mut index: usize = 0;
        while index < cmd_lengths.len() {
            if cmd_lengths[index] == 0 {
                let mut run: usize = 0;
                while index + run < cmd_lengths.len() && cmd_lengths[index + run] == 0 {
                    run += 1;
                }
                let mut remaining: usize = run;
                while remaining > 0 {
                    if remaining < 3 {
                        stream.push(TempSym::Skip(0, 0, 0));
                        remaining -= 1;
                    } else if remaining <= 18 {
                        stream.push(TempSym::Skip(1, (remaining - 3) as u32, 4));
                        remaining = 0;
                    } else {
                        let take: usize = remaining.min(531);
                        stream.push(TempSym::Skip(2, (take - 20) as u32, 9));
                        remaining -= take;
                    }
                }
                index += run;
            } else {
                stream.push(TempSym::Length(u16::from(cmd_lengths[index]) + 2));
                index += 1;
            }
        }
        stream
    }

    fn encode_block(input: &[u8], params: LhaParams) -> Vec<u8> {
        let tokens: Vec<Token> = greedy_tokens(input, params);
        let mut cmd_freq: Vec<u32> = vec![0; NUM_COMMANDS];
        let mut off_freq: Vec<u32> = vec![0; (params.history_bits + 1) as usize];
        for token in &tokens {
            match *token {
                Token::Literal(b) => cmd_freq[b as usize] += 1,
                Token::Match { length, distance } => {
                    cmd_freq[0x100 + length - MIN_MATCH] += 1;
                    let (bits, _, _): (u16, u32, u32) = offset_to_bits_code(distance);
                    off_freq[bits as usize] += 1;
                }
            }
        }
        let cmd_lengths: Vec<u8> = canonical_lengths(&cmd_freq, 16);
        let off_lengths: Vec<u8> = canonical_lengths(&off_freq, 16);
        let cmd_codes: Vec<(u32, u8)> = canonical_codes(&cmd_lengths);
        let off_codes: Vec<(u32, u8)> = canonical_codes(&off_lengths);

        let cmd_used: usize = highest_used(&cmd_lengths);
        let temp_stream: Vec<TempSym> = command_temp_stream(&cmd_lengths[..cmd_used]);
        let mut temp_freqs: Vec<u32> = vec![0; NUM_TEMP_CODELEN];
        for sym in &temp_stream {
            let s: usize = match *sym {
                TempSym::Skip(code, _, _) => code as usize,
                TempSym::Length(value) => value as usize,
            };
            temp_freqs[s] += 1;
        }
        let temp_lengths: Vec<u8> = canonical_lengths(&temp_freqs, 16);
        let temp_codes: Vec<(u32, u8)> = canonical_codes(&temp_lengths);

        let mut w: BitWriter = BitWriter::new();
        w.put_bits(tokens.len() as u32, 16);
        write_temp_tree(&mut w, &temp_lengths);
        write_command_tree(&mut w, &cmd_lengths, &temp_stream, &temp_codes);
        write_offset_tree(&mut w, &off_lengths, params);
        for token in &tokens {
            match *token {
                Token::Literal(b) => {
                    let (code, len): (u32, u8) = cmd_codes[b as usize];
                    w.put_bits(code, u32::from(len));
                }
                Token::Match { length, distance } => {
                    let (code, len): (u32, u8) = cmd_codes[0x100 + length - MIN_MATCH];
                    w.put_bits(code, u32::from(len));
                    let (bits, extra, extra_bits): (u16, u32, u32) = offset_to_bits_code(distance);
                    let (ocode, olen): (u32, u8) = off_codes[bits as usize];
                    w.put_bits(ocode, u32::from(olen));
                    if extra_bits > 0 {
                        w.put_bits(extra, extra_bits);
                    }
                }
            }
        }
        w.finish()
    }

    fn highest_used(lengths: &[u8]) -> usize {
        lengths.iter().rposition(|&l| l > 0).map_or(0, |i| i + 1)
    }

    fn single_symbol(lengths: &[u8]) -> Option<u16> {
        let used: Vec<usize> = (0..lengths.len()).filter(|&i| lengths[i] > 0).collect();
        match used.len() {
            0 => Some(0),
            1 => Some(used[0] as u16),
            _ => None,
        }
    }

    fn write_temp_tree(w: &mut BitWriter, temp_lengths: &[u8]) {
        if let Some(symbol) = single_symbol(temp_lengths) {
            w.put_bits(0, 5);
            w.put_bits(u32::from(symbol), 5);
            return;
        }
        let num_codes: usize = highest_used(temp_lengths);
        w.put_bits(num_codes as u32, 5);
        for &len in temp_lengths.iter().take(num_codes.min(3)) {
            write_code_length(w, len);
        }
        w.put_bits(0, 2);
        for &len in temp_lengths.iter().take(num_codes).skip(3) {
            write_code_length(w, len);
        }
    }

    fn write_command_tree(
        w: &mut BitWriter,
        cmd_lengths: &[u8],
        temp_stream: &[TempSym],
        temp_codes: &[(u32, u8)],
    ) {
        if let Some(symbol) = single_symbol(cmd_lengths) {
            w.put_bits(0, 9);
            w.put_bits(u32::from(symbol), 9);
            return;
        }
        let num_codes: usize = highest_used(cmd_lengths);
        w.put_bits(num_codes as u32, 9);
        for sym in temp_stream {
            match *sym {
                TempSym::Skip(code, extra, extra_bits) => {
                    let (c, clen): (u32, u8) = temp_codes[code as usize];
                    w.put_bits(c, u32::from(clen));
                    if extra_bits > 0 {
                        w.put_bits(extra, extra_bits);
                    }
                }
                TempSym::Length(value) => {
                    let (c, clen): (u32, u8) = temp_codes[value as usize];
                    w.put_bits(c, u32::from(clen));
                }
            }
        }
    }

    fn write_offset_tree(w: &mut BitWriter, off_lengths: &[u8], params: LhaParams) {
        if let Some(symbol) = single_symbol(off_lengths) {
            w.put_bits(0, params.offset_bits);
            w.put_bits(u32::from(symbol), params.offset_bits);
            return;
        }
        let num_codes: usize = highest_used(off_lengths);
        w.put_bits(num_codes as u32, params.offset_bits);
        for &len in off_lengths.iter().take(num_codes) {
            write_code_length(w, len);
        }
    }

    fn lha_lh_archive(method: [u8; 5], body: &[u8], original: &[u8]) -> Vec<u8> {
        let crc: u16 = lha_crc16(original);
        let name: &[u8] = b"x";
        let mut hdr: Vec<u8> = Vec::new();
        hdr.extend_from_slice(&method);
        hdr.extend_from_slice(&(body.len() as u32).to_le_bytes());
        hdr.extend_from_slice(&(original.len() as u32).to_le_bytes());
        hdr.extend_from_slice(&[0u8; 4]);
        hdr.push(0x20);
        hdr.push(0x00);
        hdr.push(name.len() as u8);
        hdr.extend_from_slice(name);
        hdr.extend_from_slice(&crc.to_le_bytes());
        let header_size: u8 = hdr.len() as u8;
        let checksum: u8 = hdr.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        let mut out: Vec<u8> = Vec::new();
        out.push(header_size);
        out.push(checksum);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(body);
        out.push(0);
        out
    }

    fn lha_crc16(data: &[u8]) -> u16 {
        let mut crc: u16 = 0;
        for &byte in data {
            crc ^= u16::from(byte);
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xA001;
                } else {
                    crc >>= 1;
                }
            }
        }
        crc
    }

    fn decode_with_delharc(archive: &[u8]) -> Vec<u8> {
        use std::io::Read as _;
        let mut reader: delharc::LhaDecodeReader<&[u8]> =
            delharc::LhaDecodeReader::new(archive).expect("delharc header");
        let mut out: Vec<u8> = Vec::new();
        reader.read_to_end(&mut out).expect("delharc decode");
        out
    }

    #[test]
    fn lh6_literal_only_round_trip() {
        let input: &[u8] = b"the static huffman lzss literal-only block exercises tree machinery";
        let encoded: Vec<u8> = encode_block(input, LH6);
        let decoded: Vec<u8> = decode(LH6, &encoded, input.len()).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn lh6_round_trip_with_matches() {
        let mut input: Vec<u8> = Vec::new();
        for _ in 0..40 {
            input.extend_from_slice(b"ARJ method 1-3 static huffman lzss. ");
        }
        let encoded: Vec<u8> = encode_block(&input, LH6);
        let decoded: Vec<u8> = decode(LH6, &encoded, input.len()).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn lh6_round_trip_binary() {
        let input: Vec<u8> = (0u8..=255).cycle().take(3000).collect();
        let encoded: Vec<u8> = encode_block(&input, LH6);
        let decoded: Vec<u8> = decode(LH6, &encoded, input.len()).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn lh5_round_trip() {
        let mut input: Vec<u8> = Vec::new();
        for _ in 0..20 {
            input.extend_from_slice(b"lh5 same block format, smaller history window. ");
        }
        let encoded: Vec<u8> = encode_block(&input, LH5);
        let decoded: Vec<u8> = decode(LH5, &encoded, input.len()).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn lh5_bitstream_cross_validates_against_independent_decoder() {
        let mut input: Vec<u8> = Vec::new();
        for _ in 0..30 {
            input.extend_from_slice(b"cross-check lh5 body against an independent lha decoder. ");
        }
        let body: Vec<u8> = encode_block(&input, LH5);
        let archive: Vec<u8> = lha_lh_archive(*b"-lh5-", &body, &input);
        let independent: Vec<u8> = decode_with_delharc(&archive);
        assert_eq!(independent, input, "independent lha decoder must agree");
        let ours: Vec<u8> = decode(LH5, &body, input.len()).expect("our decode");
        assert_eq!(ours, input);
    }

    #[test]
    fn truncated_errors() {
        assert!(decode(LH6, &[0x00, 0x01], 50).is_err());
    }

    #[test]
    fn huffman_lengths_form_valid_prefix_code() {
        let freqs: Vec<u32> = vec![10, 5, 1, 1, 1, 1, 1, 8, 3, 2, 30, 4];
        let lengths: Vec<u8> = canonical_lengths(&freqs, 16);
        let max_len: u32 = u32::from(lengths.iter().copied().max().unwrap());
        let kraft: u64 = lengths
            .iter()
            .filter(|&&l| l > 0)
            .map(|&l| 1u64 << (max_len - u32::from(l)))
            .sum();
        assert_eq!(kraft, 1u64 << max_len, "Kraft equality for complete code");
        HuffTree::build(&lengths).expect("decoder builds the encoder's lengths");
    }
}
