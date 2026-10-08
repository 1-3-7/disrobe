use super::bits::{LsbWriter, MsbWriter, bit_length, unzigzag};
use super::huffman::{histogram, range_codes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TansTable {
    Explicit,
    Rice { q: u32 },
}

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    symbol: u8,
    bits_x: u32,
    w: u32,
}

fn normalize(data: &[u8], table_size: u32) -> Vec<(u8, u32)> {
    let counts: [u64; 256] = histogram(data);
    let total: u64 = data.len() as u64;
    let mut weights: Vec<(u8, u32)> = counts
        .iter()
        .enumerate()
        .filter(|entry: &(usize, &u64)| *entry.1 > 0)
        .map(|(s, &c): (usize, &u64)| {
            (s as u8, ((c * u64::from(table_size)) / total).max(1) as u32)
        })
        .collect();
    loop {
        let sum: u32 = weights.iter().map(|&(_, w): &(u8, u32)| w).sum();
        if sum == table_size {
            break;
        }
        let largest: usize = (0..weights.len())
            .max_by_key(|&i: &usize| (weights[i].1, usize::from(weights[i].0)))
            .expect("at least one symbol");
        if sum < table_size {
            weights[largest].1 += table_size - sum;
        } else {
            let excess: u32 = sum - table_size;
            let take: u32 = excess.min(weights[largest].1 - 1);
            assert!(take > 0, "cannot normalise TANS weights");
            weights[largest].1 -= take;
        }
    }
    weights
}

fn build(weights: &[(u8, u32)], l_bits: u32) -> Vec<Slot> {
    let table_size: usize = 1 << l_bits;
    let mut singles: Vec<u8> = weights
        .iter()
        .filter(|&&(_, w): &&(u8, u32)| w == 1)
        .map(|&(s, _): &(u8, u32)| s)
        .collect();
    singles.sort_unstable();
    let mut multiples: Vec<(u8, u32)> = weights
        .iter()
        .filter(|&&(_, w): &&(u8, u32)| w > 1)
        .copied()
        .collect();
    multiples.sort_unstable();
    let mut table: Vec<Slot> = vec![Slot::default(); table_size];
    let spread: usize = table_size - singles.len();
    let mut cursors: [usize; 4] = [0; 4];
    for (j, cursor) in cursors.iter_mut().enumerate() {
        *cursor = j * (spread >> 2) + j.min(spread & 3);
    }
    for (i, &symbol) in singles.iter().enumerate() {
        table[spread + i] = Slot {
            symbol,
            bits_x: l_bits,
            w: 0,
        };
    }
    let mask: u32 = (1 << l_bits) - 1;
    let mut sum: u32 = 0;
    for &(symbol, weight) in &multiples {
        if weight > 4 {
            let sym_bits: u32 = weight.ilog2();
            let mut z: u32 = l_bits - sym_bits;
            let mut slot: Slot = Slot {
                symbol,
                bits_x: z,
                w: (weight << z) & mask,
            };
            let mut step: u32 = 1 << z;
            let mut x: u32 = (1 << (sym_bits + 1)) - weight;
            for (j, cursor) in cursors.iter_mut().enumerate() {
                let y: u32 = (weight + (sum.wrapping_sub(j as u32 + 1) & 3)) >> 2;
                let first: u32 = if x >= y { y } else { x };
                for _ in 0..first {
                    table[*cursor] = slot;
                    *cursor += 1;
                    slot.w += step;
                }
                if x >= y {
                    x -= y;
                } else {
                    z -= 1;
                    step >>= 1;
                    slot.bits_x = z;
                    slot.w = 0;
                    for _ in 0..y - x {
                        table[*cursor] = slot;
                        *cursor += 1;
                        slot.w += step;
                    }
                    x = weight;
                }
            }
        } else {
            let mut bits: u32 = ((1 << weight) - 1) << (sum & 3);
            bits |= bits >> 4;
            for ww in weight..2 * weight {
                let index: usize = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let bits_x: u32 = l_bits - ww.ilog2();
                table[cursors[index]] = Slot {
                    symbol,
                    bits_x,
                    w: (ww << bits_x) & mask,
                };
                cursors[index] += 1;
            }
        }
        sum += weight;
    }
    table
}

fn write_explicit(writer: &mut MsbWriter, weights: &[(u8, u32)], l_bits: u32) {
    writer.bit(false);
    let mut ordered: Vec<(u8, u32)> = weights.to_vec();
    ordered.sort_by_key(|&(s, w): &(u8, u32)| (w, s));
    let last: (u8, u32) = ordered.pop().expect("two symbols");
    assert!(
        (1..=8).contains(&ordered.len()),
        "explicit TANS tables list 2..=9 symbols"
    );
    writer.put(ordered.len() as u32 - 1, 3);
    let mut previous: u32 = 0;
    let mut deltas: Vec<u32> = Vec::with_capacity(ordered.len());
    for &(_, w) in &ordered {
        deltas.push(w - previous);
        previous = w;
    }
    let max_delta_bits: u32 = deltas
        .iter()
        .map(|&d: &u32| bit_length(d))
        .max()
        .unwrap_or(1)
        .max(1);
    writer.put(max_delta_bits, bit_length(l_bits));
    for (&(symbol, _), &delta) in ordered.iter().zip(&deltas) {
        writer.put(u32::from(symbol), 8);
        writer.put(delta, max_delta_bits);
    }
    writer.put(u32::from(last.0), 8);
}

fn write_rice(writer: &mut MsbWriter, weights: &[(u8, u32)], q: u32) {
    writer.bit(true);
    writer.put(q, 3);
    writer.put(weights.len() as u32 - 1, 8);
    let symbols: Vec<usize> = weights
        .iter()
        .map(|&(s, _): &(u8, u32)| usize::from(s))
        .collect();
    let (extra, range_bits): (Vec<u32>, Vec<(u32, u32)>) = range_codes(&symbols);
    writer.fluff(weights.len() as u32, extra.len() as u32);
    let mut average: i32 = 6;
    let mut raw_values: Vec<(u32, u32)> = Vec::with_capacity(weights.len());
    for &(_, weight) in weights {
        let target: i32 = weight as i32 - 1;
        let average_div4: i32 = average >> 2;
        let mut limit: i32 = 2 * average_div4;
        let raw: u32 = if target <= limit {
            unzigzag(target - average_div4)
        } else {
            target as u32
        };
        if limit > target {
            limit = target;
        }
        average += limit - average_div4;
        let nextra: u32 = bit_length(raw + (1 << q)) - 1;
        assert!(nextra <= 15, "TANS weight too wide");
        raw_values.push((raw + (1 << q) - (1 << nextra), nextra));
    }
    for &(_, nextra) in &raw_values {
        writer.unary(nextra - q);
    }
    for &value in &extra {
        writer.unary(value);
    }
    for (value, width) in range_bits {
        writer.put(value, width);
    }
    for (value, nextra) in raw_values {
        writer.put(value, nextra);
    }
}

pub fn encode_payload(data: &[u8], table: TansTable, l_bits: u32) -> Vec<u8> {
    assert!(data.len() >= 5, "TANS arrays carry at least five bytes");
    let table_size: u32 = 1 << l_bits;
    let mut weights: Vec<(u8, u32)> = normalize(data, table_size);
    weights.sort_unstable();
    assert!(weights.len() >= 2, "TANS needs at least two symbols");
    let mut writer: MsbWriter = MsbWriter::new();
    writer.bit(false);
    writer.put(l_bits - 8, 2);
    match table {
        TansTable::Explicit => write_explicit(&mut writer, &weights, l_bits),
        TansTable::Rice { q } => write_rice(&mut writer, &weights, q),
    }
    let mut out: Vec<u8> = writer.finish();
    let slots: Vec<Slot> = build(&weights, l_bits);
    let mut by_symbol: Vec<Vec<(usize, Slot)>> = vec![Vec::new(); 256];
    for (index, slot) in slots.iter().enumerate() {
        by_symbol[usize::from(slot.symbol)].push((index, *slot));
    }
    let body: usize = data.len() - 5;
    let mut states: [u32; 5] = [0; 5];
    for (lane, state) in states.iter_mut().enumerate() {
        *state = u32::from(data[body + lane]);
    }
    let mut steps: Vec<(u32, u32)> = vec![(0, 0); body];
    for t in (0..body).rev() {
        let lane: usize = t % 5;
        let x: u32 = states[lane];
        let (index, slot): (usize, Slot) = *by_symbol[usize::from(data[t])]
            .iter()
            .find(|(_, slot): &&(usize, Slot)| x >= slot.w && x < slot.w + (1 << slot.bits_x))
            .expect("every state lies in one slot interval of its symbol");
        steps[t] = (x - slot.w, slot.bits_x);
        states[lane] = index as u32;
    }
    let mut forward: LsbWriter = LsbWriter::new();
    let mut backward: LsbWriter = LsbWriter::new();
    forward.put(states[0], l_bits);
    backward.put(states[1], l_bits);
    forward.put(states[2], l_bits);
    backward.put(states[3], l_bits);
    forward.put(states[4], l_bits);
    for (t, &(value, bits)) in steps.iter().enumerate() {
        if (t / 5) % 2 == 0 {
            forward.put(value, bits);
        } else {
            backward.put(value, bits);
        }
    }
    let mut back: Vec<u8> = backward.finish();
    back.reverse();
    out.extend(forward.finish());
    out.extend(back);
    out
}
