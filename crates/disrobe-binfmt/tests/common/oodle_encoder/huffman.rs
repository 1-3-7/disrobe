use super::bits::{LsbWriter, MsbWriter, bit_length, reverse_bits, unzigzag};

pub const MAX_CODE_LEN: u32 = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuffHeader {
    OldSparse,
    OldDense { forced: u32 },
    New { forced: u32 },
}

pub fn histogram(data: &[u8]) -> [u64; 256] {
    let mut counts: [u64; 256] = [0; 256];
    for &byte in data {
        counts[usize::from(byte)] += 1;
    }
    counts
}

fn huffman_lengths(counts: &[u64; 256]) -> [u8; 256] {
    let mut weights: Vec<(u64, Vec<usize>)> = counts
        .iter()
        .enumerate()
        .filter(|entry: &(usize, &u64)| *entry.1 > 0)
        .map(|(symbol, &count): (usize, &u64)| (count, vec![symbol]))
        .collect();
    let mut lengths: [u8; 256] = [0; 256];
    assert!(
        weights.len() >= 2,
        "a Huffman code needs at least two symbols"
    );
    while weights.len() > 1 {
        weights.sort_by(|a: &(u64, Vec<usize>), b: &(u64, Vec<usize>)| {
            b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1))
        });
        let (count_a, symbols_a): (u64, Vec<usize>) = weights.pop().expect("two nodes");
        let (count_b, symbols_b): (u64, Vec<usize>) = weights.pop().expect("two nodes");
        let mut merged: Vec<usize> = symbols_a;
        merged.extend(symbols_b);
        for &symbol in &merged {
            lengths[symbol] += 1;
        }
        weights.push((count_a + count_b, merged));
    }
    lengths
}

pub fn limited_lengths(data: &[u8]) -> [u8; 256] {
    let mut counts: [u64; 256] = histogram(data);
    loop {
        let lengths: [u8; 256] = huffman_lengths(&counts);
        if lengths
            .iter()
            .all(|&len: &u8| u32::from(len) <= MAX_CODE_LEN)
        {
            return lengths;
        }
        for count in &mut counts {
            if *count > 0 {
                *count = *count / 2 + 1;
            }
        }
    }
}

fn canonical_codes(order: &[(u8, u8)]) -> [(u32, u32); 256] {
    let mut codes: [(u32, u32); 256] = [(0, 0); 256];
    let mut code: u32 = 0;
    for len in 1..=MAX_CODE_LEN {
        for &(symbol, symbol_len) in order {
            if u32::from(symbol_len) == len {
                codes[usize::from(symbol)] = (code, len);
                code += 1;
            }
        }
        code <<= 1;
    }
    codes
}

fn write_sparse(writer: &mut MsbWriter, coded: &[(u8, u8)]) {
    writer.bit(false);
    writer.bit(false);
    assert!(
        coded.len() < 256,
        "the sparse form lists at most 255 symbols"
    );
    writer.put(coded.len() as u32, 8);
    let max_len: u32 = coded
        .iter()
        .map(|&(_, len): &(u8, u8)| u32::from(len))
        .max()
        .unwrap_or(1);
    let codelen_bits: u32 = bit_length(max_len - 1);
    writer.put(codelen_bits, 3);
    for &(symbol, len) in coded {
        writer.put(u32::from(symbol), 8);
        writer.put(u32::from(len) - 1, codelen_bits);
    }
}

fn gamma_x(writer: &mut MsbWriter, value: u32, forced: u32) {
    let zeros: u32 = value >> forced;
    assert!(
        zeros <= 20 >> forced,
        "value {value} needs a zero run longer than {forced} forced bits allow"
    );
    writer.put(0, zeros);
    writer.put((1 << forced) | (value & ((1 << forced) - 1)), forced + 1);
}

fn write_dense(writer: &mut MsbWriter, lengths: &[u8; 256], forced: u32) {
    writer.bit(false);
    writer.bit(true);
    writer.put(forced, 2);
    let skip_first: bool = lengths[0] > 0;
    writer.bit(skip_first);
    let mut symbol: usize = 0;
    let mut avg_x4: u32 = 32;
    let mut first: bool = true;
    while symbol < 256 {
        if !(first && skip_first) {
            let start: usize = symbol;
            while symbol < 256 && lengths[symbol] == 0 {
                symbol += 1;
            }
            writer.gamma((symbol - start - 1) as u32);
            if symbol >= 256 {
                break;
            }
        }
        first = false;
        let start: usize = symbol;
        while symbol < 256 && lengths[symbol] > 0 {
            symbol += 1;
        }
        writer.gamma((symbol - start - 1) as u32);
        for &len in &lengths[start..symbol] {
            let predicted: i32 = ((avg_x4 + 2) >> 2) as i32;
            gamma_x(writer, unzigzag(i32::from(len) - predicted), forced);
            avg_x4 = u32::from(len) + ((3 * avg_x4 + 2) >> 2);
        }
    }
}

pub fn range_codes(symbols: &[usize]) -> (Vec<u32>, Vec<(u32, u32)>) {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for &symbol in symbols {
        match runs.last_mut() {
            Some((start, len)) if *start + *len == symbol => *len += 1,
            _ => runs.push((symbol, 1)),
        }
    }
    let mut extra: Vec<u32> = Vec::new();
    let mut bits: Vec<(u32, u32)> = Vec::new();
    if runs[0].0 > 0 {
        let gap: u32 = runs[0].0 as u32;
        let v: u32 = bit_length(gap + 1) - 2;
        extra.push(v);
        bits.push((gap + 1 - (1 << (v + 1)), v + 1));
    }
    for pair in runs.windows(2) {
        let (start, num): (usize, usize) = pair[0];
        let space: u32 = (pair[1].0 - start - num) as u32;
        let v1: u32 = bit_length(num as u32) - 1;
        extra.push(v1);
        bits.push((num as u32 - (1 << v1), v1));
        let v2: u32 = bit_length(space + 1) - 2;
        extra.push(v2);
        bits.push((space + 1 - (1 << (v2 + 1)), v2 + 1));
    }
    (extra, bits)
}

fn write_new(writer: &mut MsbWriter, lengths: &[u8; 256], forced: u32) {
    writer.bit(true);
    writer.bit(false);
    writer.put(forced, 2);
    let symbols: Vec<usize> = (0..256).filter(|&s: &usize| lengths[s] > 0).collect();
    writer.put(symbols.len() as u32 - 1, 8);
    let (extra, range_bits): (Vec<u32>, Vec<(u32, u32)>) = range_codes(&symbols);
    writer.fluff(symbols.len() as u32, extra.len() as u32);
    let mut running: i32 = 0x1E;
    let mut values: Vec<u32> = Vec::with_capacity(symbols.len());
    for &symbol in &symbols {
        let delta: i32 = i32::from(lengths[symbol]) - 1 - (running >> 2);
        values.push(unzigzag(delta));
        running += delta;
    }
    for &value in &values {
        writer.unary(value >> forced);
    }
    for &value in &extra {
        writer.unary(value);
    }
    for &value in &values {
        writer.put(value & ((1 << forced) - 1), forced);
    }
    for (value, width) in range_bits {
        writer.put(value, width);
    }
}

fn three_streams(codes: &[(u32, u32); 256], data: &[u8]) -> Vec<u8> {
    let mut a: LsbWriter = LsbWriter::new();
    let mut b: LsbWriter = LsbWriter::new();
    let mut c: LsbWriter = LsbWriter::new();
    for (i, &byte) in data.iter().enumerate() {
        let (code, len): (u32, u32) = codes[usize::from(byte)];
        let writer: &mut LsbWriter = match i % 3 {
            0 => &mut a,
            1 => &mut c,
            _ => &mut b,
        };
        writer.put(reverse_bits(code, len), len);
    }
    let a: Vec<u8> = a.finish();
    let b: Vec<u8> = b.finish();
    let mut c: Vec<u8> = c.finish();
    c.reverse();
    let mut out: Vec<u8> = (a.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(&a);
    out.extend_from_slice(&b);
    out.extend_from_slice(&c);
    out
}

pub fn encode_payload(data: &[u8], header: HuffHeader, two_halves: bool) -> Vec<u8> {
    let distinct: usize = histogram(data).iter().filter(|&&c: &&u64| c > 0).count();
    let mut writer: MsbWriter = MsbWriter::new();
    if distinct == 1 {
        writer.bit(false);
        writer.bit(false);
        writer.put(1, 8);
        writer.put(u32::from(data[0]), 8);
        return writer.finish();
    }
    let lengths: [u8; 256] = limited_lengths(data);
    let order: Vec<(u8, u8)> = (0..256)
        .filter(|&s: &usize| lengths[s] > 0)
        .map(|s: usize| (s as u8, lengths[s]))
        .collect();
    match header {
        HuffHeader::OldSparse => write_sparse(&mut writer, &order),
        HuffHeader::OldDense { forced } => write_dense(&mut writer, &lengths, forced),
        HuffHeader::New { forced } => write_new(&mut writer, &lengths, forced),
    }
    let codes: [(u32, u32); 256] = canonical_codes(&order);
    let mut out: Vec<u8> = writer.finish();
    if two_halves {
        let half: usize = data.len().div_ceil(2);
        let first: Vec<u8> = three_streams(&codes, &data[..half]);
        let second: Vec<u8> = three_streams(&codes, &data[half..]);
        out.extend_from_slice(&(first.len() as u32).to_le_bytes()[..3]);
        out.extend_from_slice(&first);
        out.extend_from_slice(&second);
    } else {
        out.extend_from_slice(&three_streams(&codes, data));
    }
    out
}
