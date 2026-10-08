use super::bits::{LsbReader, MsbReader, zigzag};
use super::huffman::{read_ranges, read_rice_values};
use super::{Ctx, OodleError};

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    symbol: u8,
    bits_x: u32,
    w: u32,
}

struct Weights {
    singles: Vec<u8>,
    multiples: Vec<(u8, u32)>,
}

fn read_weights(
    reader: &mut MsbReader<'_>,
    l_bits: u32,
    ctx: &mut Ctx<'_>,
) -> Result<Weights, OodleError> {
    let table_size: u32 = 1 << l_bits;
    let mut singles: Vec<u8> = Vec::new();
    let mut multiples: Vec<(u8, u32)> = Vec::new();
    if reader.bit() {
        ctx.bump("tans:rice-weights");
        let q: u32 = reader.read(3);
        let num_symbols: usize = reader.read(8) as usize + 1;
        if num_symbols < 2 {
            return Err(OodleError::Malformed(
                "TANS table declares fewer than two symbols",
            ));
        }
        let fluff: usize = reader.fluff(num_symbols as u32) as usize;
        let rice: Vec<u32> = read_rice_values(reader, num_symbols + fluff)?;
        let ranges: Vec<(usize, usize)> = read_ranges(reader, num_symbols, &rice[num_symbols..])?;
        let mut average: i32 = 6;
        let mut total: u32 = 0;
        let mut next_rice: std::slice::Iter<'_, u32> = rice.iter();
        for (start, count) in ranges {
            for symbol in start..start + count {
                let extra: u32 = *next_rice
                    .next()
                    .ok_or(OodleError::Malformed("TANS ranges outnumber their weights"))?;
                let nextra: u32 = q + extra;
                if nextra > 15 {
                    return Err(OodleError::Malformed("TANS weight width above 15 bits"));
                }
                let mut v: i32 = (reader.read(nextra) + (1 << nextra) - (1 << q)) as i32;
                let average_div4: i32 = average >> 2;
                let mut limit: i32 = 2 * average_div4;
                if v <= limit {
                    v = average_div4 + zigzag(v as u32);
                }
                if limit > v {
                    limit = v;
                }
                let weight: u32 = (v + 1) as u32;
                average += limit - average_div4;
                if weight == 1 {
                    singles.push(symbol as u8);
                } else {
                    multiples.push((symbol as u8, weight));
                }
                total += weight;
                if total > table_size {
                    return Err(OodleError::Malformed("TANS weights exceed the table size"));
                }
            }
        }
        if total != table_size || !reader.within() {
            return Err(OodleError::Malformed(
                "TANS weights do not sum to the table size",
            ));
        }
    } else {
        ctx.bump("tans:explicit-weights");
        let mut seen: [bool; 256] = [false; 256];
        let count: u32 = reader.read(3) + 1;
        let bits_per_symbol: u32 = 32 - l_bits.leading_zeros();
        let max_delta_bits: u32 = reader.read(bits_per_symbol);
        if max_delta_bits == 0 || max_delta_bits > l_bits {
            return Err(OodleError::Malformed(
                "TANS weight delta width outside 1..=L",
            ));
        }
        let mut weight: u32 = 0;
        let mut total: u32 = 0;
        for _ in 0..count {
            let symbol: usize = reader.read(8) as usize;
            if seen[symbol] {
                return Err(OodleError::Malformed("TANS table repeats a symbol"));
            }
            weight += reader.read(max_delta_bits);
            if weight == 0 {
                return Err(OodleError::Malformed("TANS table carries a zero weight"));
            }
            seen[symbol] = true;
            if weight == 1 {
                singles.push(symbol as u8);
            } else {
                multiples.push((symbol as u8, weight));
            }
            total += weight;
        }
        let symbol: usize = reader.read(8) as usize;
        if seen[symbol] {
            return Err(OodleError::Malformed("TANS table repeats a symbol"));
        }
        let last: u32 = table_size
            .checked_sub(total)
            .ok_or(OodleError::Malformed("TANS weights exceed the table size"))?;
        if last < weight || last <= 1 || !reader.within() {
            return Err(OodleError::Malformed("TANS final weight is too small"));
        }
        multiples.push((symbol as u8, last));
        singles.sort_unstable();
        multiples.sort_unstable();
    }
    Ok(Weights { singles, multiples })
}

fn place(table: &mut [Slot], cursor: &mut usize, slot: Slot) -> Result<(), OodleError> {
    let entry: &mut Slot = table.get_mut(*cursor).ok_or(OodleError::Malformed(
        "TANS weights overrun the state table",
    ))?;
    *entry = slot;
    *cursor += 1;
    Ok(())
}

fn build_table(weights: &Weights, l_bits: u32) -> Result<Vec<Slot>, OodleError> {
    let table_size: usize = 1 << l_bits;
    let mut table: Vec<Slot> = vec![Slot::default(); table_size];
    let spread: usize = table_size - weights.singles.len();
    let quarter: usize = spread >> 2;
    let rem: usize = spread & 3;
    let mut cursors: [usize; 4] = [0; 4];
    for (j, cursor) in cursors.iter_mut().enumerate() {
        *cursor = j * quarter + j.min(rem);
    }
    for (i, &symbol) in weights.singles.iter().enumerate() {
        table[spread + i] = Slot {
            symbol,
            bits_x: l_bits,
            w: 0,
        };
    }
    let mask: u32 = (1 << l_bits) - 1;
    let mut sum: u32 = 0;
    for &(symbol, weight) in &weights.multiples {
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
                if x >= y {
                    for _ in 0..y {
                        place(&mut table, cursor, slot)?;
                        slot.w += step;
                    }
                    x -= y;
                } else {
                    for _ in 0..x {
                        place(&mut table, cursor, slot)?;
                        slot.w += step;
                    }
                    z -= 1;
                    step >>= 1;
                    slot.bits_x = z;
                    slot.w = 0;
                    for _ in 0..y - x {
                        place(&mut table, cursor, slot)?;
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
                let weight_bits: u32 = ww.ilog2();
                let bits_x: u32 = l_bits - weight_bits;
                place(
                    &mut table,
                    &mut cursors[index],
                    Slot {
                        symbol,
                        bits_x,
                        w: (ww << bits_x) & mask,
                    },
                )?;
            }
        }
        sum += weight;
    }
    Ok(table)
}

pub(super) fn decode(
    ctx: &mut Ctx<'_>,
    payload: &[u8],
    dst_size: usize,
    out: &mut Vec<u8>,
) -> Result<(), OodleError> {
    if payload.len() < 8 || dst_size < 5 {
        return Err(OodleError::Malformed(
            "TANS array is shorter than its fixed states",
        ));
    }
    let mut reader: MsbReader<'_> = MsbReader::forward(payload);
    if reader.bit() {
        return Err(OodleError::Malformed("TANS reserved bit is set"));
    }
    let l_bits: u32 = reader.read(2) + 8;
    let weights: Weights = read_weights(&mut reader, l_bits, ctx)?;
    let header_len: usize = reader.consumed_bytes();
    if header_len >= payload.len() {
        return Err(OodleError::Malformed(
            "TANS table runs to the end of the array",
        ));
    }
    let table: Vec<Slot> = build_table(&weights, l_bits)?;
    let data: &[u8] = &payload[header_len..];
    let mut f: LsbReader<'_> = LsbReader::forward(data);
    let mut b: LsbReader<'_> = LsbReader::backward(data);
    let mut states: [u32; 5] = [0; 5];
    states[0] = f.read(l_bits);
    states[1] = b.read(l_bits);
    states[2] = f.read(l_bits);
    states[3] = b.read(l_bits);
    states[4] = f.read(l_bits);
    let body: usize = dst_size - 5;
    let start: usize = out.len();
    let mut produced: usize = 0;
    let round = |state: &mut u32,
                 reader: &mut LsbReader<'_>,
                 out: &mut Vec<u8>|
     -> Result<(), OodleError> {
        let slot: Slot = *table
            .get(*state as usize)
            .ok_or(OodleError::Malformed("TANS state leaves the table"))?;
        out.push(slot.symbol);
        *state = reader.read(slot.bits_x) + slot.w;
        Ok(())
    };
    'decode: while produced < body {
        for state in &mut states {
            round(state, &mut f, out)?;
            produced += 1;
            if produced == body {
                break 'decode;
            }
        }
        for state in &mut states {
            round(state, &mut b, out)?;
            produced += 1;
            if produced == body {
                break 'decode;
            }
        }
    }
    if f.consumed_bytes() + b.consumed_bytes() != data.len() {
        return Err(OodleError::Malformed("TANS streams do not meet exactly"));
    }
    if states.iter().any(|&state: &u32| state > 0xFF) {
        return Err(OodleError::Malformed("TANS final state is not a byte"));
    }
    out.extend(states.iter().map(|&state: &u32| state as u8));
    debug_assert_eq!(out.len() - start, dst_size);
    Ok(())
}
