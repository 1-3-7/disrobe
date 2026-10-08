use super::bits::{LsbReader, MsbReader, zigzag};
use super::{Ctx, OodleError};

pub(super) const MAX_CODE_LEN: u32 = 11;
const LUT_BITS: u32 = 11;
const LUT_SIZE: usize = 1 << LUT_BITS;

pub(super) enum CodeTable {
    Single(u8),
    Lengths(Vec<(u8, u8)>),
}

pub(super) fn read_ranges(
    reader: &mut MsbReader<'_>,
    num_symbols: usize,
    extra: &[u32],
) -> Result<Vec<(usize, usize)>, OodleError> {
    let mut values: std::slice::Iter<'_, u32> = extra.iter();
    let mut next = || -> Result<u32, OodleError> {
        values
            .next()
            .copied()
            .ok_or(OodleError::Malformed("symbol range values exhausted"))
    };
    let mut symbol: usize = if extra.len() & 1 == 1 {
        let v: u32 = next()?;
        if v >= 8 {
            return Err(OodleError::Malformed("initial symbol gap is too wide"));
        }
        reader.read(v + 1) as usize + (1 << (v + 1)) - 1
    } else {
        0
    };
    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(extra.len() / 2 + 1);
    let mut used: usize = 0;
    for _ in 0..extra.len() / 2 {
        let v1: u32 = next()?;
        if v1 >= 9 {
            return Err(OodleError::Malformed("symbol range length is too wide"));
        }
        let num: usize = reader.read(v1) as usize + (1 << v1);
        let v2: u32 = next()?;
        if v2 >= 8 {
            return Err(OodleError::Malformed("symbol range gap is too wide"));
        }
        let space: usize = reader.read(v2 + 1) as usize + (1 << (v2 + 1)) - 1;
        ranges.push((symbol, num));
        used += num;
        symbol += num + space;
    }
    if symbol >= 256 || used >= num_symbols || symbol + num_symbols - used > 256 {
        return Err(OodleError::Malformed(
            "symbol ranges overrun the byte alphabet",
        ));
    }
    ranges.push((symbol, num_symbols - used));
    Ok(ranges)
}

pub(super) fn read_rice_values(
    reader: &mut MsbReader<'_>,
    count: usize,
) -> Result<Vec<u32>, OodleError> {
    let mut values: Vec<u32> = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.unary()?);
    }
    Ok(values)
}

fn read_old(reader: &mut MsbReader<'_>, ctx: &mut Ctx<'_>) -> Result<CodeTable, OodleError> {
    if reader.bit() {
        ctx.bump("huffman:old-dense");
        let forced: u32 = reader.read(2);
        let max_gamma_x_zeros: u32 = 20 >> forced;
        let skip_first_run: bool = reader.bit();
        let mut symbol: u32 = 0;
        let mut coded: u32 = 0;
        let mut avg_x4: u32 = 32;
        let mut lengths: Vec<(u8, u8)> = Vec::new();
        let mut first: bool = true;
        loop {
            if !(first && skip_first_run) {
                symbol += reader.gamma(7)? + 1;
                if symbol >= 256 {
                    break;
                }
            }
            first = false;
            let run: u32 = reader.gamma(7)? + 1;
            if symbol + run > 256 {
                return Err(OodleError::Malformed(
                    "Huffman symbol run overruns the alphabet",
                ));
            }
            coded += run;
            for _ in 0..run {
                let v: u32 = reader.gamma_x(forced, max_gamma_x_zeros)?;
                let len: i32 = zigzag(v) + ((avg_x4 + 2) >> 2) as i32;
                if !(1..=MAX_CODE_LEN as i32).contains(&len) {
                    return Err(OodleError::Malformed("Huffman code length outside 1..=11"));
                }
                avg_x4 = len as u32 + ((3 * avg_x4 + 2) >> 2);
                lengths.push((symbol as u8, len as u8));
                symbol += 1;
            }
            if symbol == 256 {
                break;
            }
        }
        if symbol != 256 || coded < 2 || !reader.within() {
            return Err(OodleError::Malformed(
                "Huffman dense header does not cover the alphabet",
            ));
        }
        Ok(CodeTable::Lengths(lengths))
    } else {
        let num_symbols: u32 = reader.read(8);
        if num_symbols == 0 {
            return Err(OodleError::Malformed(
                "Huffman sparse header declares no symbols",
            ));
        }
        if num_symbols == 1 {
            ctx.bump("huffman:memset");
            return Ok(CodeTable::Single(reader.read(8) as u8));
        }
        ctx.bump("huffman:old-sparse");
        let codelen_bits: u32 = reader.read(3);
        if codelen_bits > 4 {
            return Err(OodleError::Malformed(
                "Huffman sparse code-length width above 4",
            ));
        }
        let mut lengths: Vec<(u8, u8)> = Vec::with_capacity(num_symbols as usize);
        for _ in 0..num_symbols {
            let symbol: u8 = reader.read(8) as u8;
            let len: u32 = reader.read(codelen_bits) + 1;
            if len > MAX_CODE_LEN {
                return Err(OodleError::Malformed("Huffman code length outside 1..=11"));
            }
            lengths.push((symbol, len as u8));
        }
        Ok(CodeTable::Lengths(lengths))
    }
}

fn read_new(reader: &mut MsbReader<'_>, ctx: &mut Ctx<'_>) -> Result<CodeTable, OodleError> {
    let forced: u32 = reader.read(2);
    let num_symbols: usize = reader.read(8) as usize + 1;
    let fluff: usize = reader.fluff(num_symbols as u32) as usize;
    let mut values: Vec<u32> = read_rice_values(reader, num_symbols + fluff)?;
    if forced > 0 {
        for value in values.iter_mut().take(num_symbols) {
            *value = (*value << forced) | reader.read(forced);
        }
        if !reader.within() {
            return Err(OodleError::Malformed(
                "Huffman Rice extra bits run past the array",
            ));
        }
    }
    let mut running: i32 = 0x1E;
    let mut code_lengths: Vec<u8> = Vec::with_capacity(num_symbols);
    for &value in values.iter().take(num_symbols) {
        let delta: i32 = zigzag(value);
        let len: i32 = delta + (running >> 2) + 1;
        if !(1..=MAX_CODE_LEN as i32).contains(&len) {
            return Err(OodleError::Malformed("Huffman code length outside 1..=11"));
        }
        code_lengths.push(len as u8);
        running += delta;
    }
    let ranges: Vec<(usize, usize)> = read_ranges(reader, num_symbols, &values[num_symbols..])?;
    if !reader.within() {
        return Err(OodleError::Malformed("Huffman header runs past the array"));
    }
    if num_symbols == 1 {
        ctx.bump("huffman:memset");
        let symbol: usize = ranges.first().map_or(0, |range: &(usize, usize)| range.0);
        return Ok(CodeTable::Single(symbol as u8));
    }
    ctx.bump("huffman:new");
    let mut lengths: Vec<(u8, u8)> = Vec::with_capacity(num_symbols);
    let mut next_len: std::slice::Iter<'_, u8> = code_lengths.iter();
    for (start, count) in ranges {
        for symbol in start..start + count {
            let len: u8 = *next_len.next().ok_or(OodleError::Malformed(
                "Huffman ranges outnumber code lengths",
            ))?;
            lengths.push((symbol as u8, len));
        }
    }
    Ok(CodeTable::Lengths(lengths))
}

pub(super) fn read_table(
    reader: &mut MsbReader<'_>,
    ctx: &mut Ctx<'_>,
) -> Result<CodeTable, OodleError> {
    let new_form: bool = reader.bit();
    if !new_form {
        return read_old(reader, ctx);
    }
    let reserved: bool = reader.bit();
    if reserved {
        return Err(OodleError::Malformed(
            "Huffman header selects a reserved encoding",
        ));
    }
    read_new(reader, ctx)
}

pub(super) struct Lut {
    entries: Box<[u16; LUT_SIZE]>,
}

impl Lut {
    pub(super) fn build(lengths: &[(u8, u8)]) -> Result<Self, OodleError> {
        let mut by_len: [Vec<u8>; MAX_CODE_LEN as usize + 1] = Default::default();
        for &(symbol, len) in lengths {
            by_len[usize::from(len)].push(symbol);
        }
        let mut entries: Box<[u16; LUT_SIZE]> = Box::new([0u16; LUT_SIZE]);
        let mut slot: usize = 0;
        for (len, symbols) in by_len.iter().enumerate().skip(1) {
            let width: usize = 1 << (LUT_BITS as usize - len);
            for &symbol in symbols {
                if slot + width > LUT_SIZE {
                    return Err(OodleError::Malformed(
                        "Huffman code lengths oversubscribe the code space",
                    ));
                }
                let code: usize = slot >> (LUT_BITS as usize - len);
                let reversed: usize = code.reverse_bits() >> (usize::BITS as usize - len);
                let entry: u16 = u16::from(symbol) | ((len as u16) << 8);
                let mut index: usize = reversed;
                while index < LUT_SIZE {
                    entries[index] = entry;
                    index += 1 << len;
                }
                slot += width;
            }
        }
        if slot != LUT_SIZE {
            return Err(OodleError::Malformed(
                "Huffman code lengths leave the code space incomplete",
            ));
        }
        Ok(Self { entries })
    }

    fn decode(&self, reader: &mut LsbReader<'_>) -> u8 {
        let entry: u16 = self.entries[reader.peek(LUT_BITS) as usize];
        reader.skip(u32::from(entry >> 8));
        entry as u8
    }
}

fn decode_three_streams(
    lut: &Lut,
    data: &[u8],
    split: usize,
    count: usize,
    out: &mut Vec<u8>,
) -> Result<(), OodleError> {
    if split > data.len() {
        return Err(OodleError::Malformed(
            "Huffman stream split lies past the array",
        ));
    }
    let (first, rest): (&[u8], &[u8]) = data.split_at(split);
    let mut a: LsbReader<'_> = LsbReader::forward(first);
    let mut b: LsbReader<'_> = LsbReader::forward(rest);
    let mut c: LsbReader<'_> = LsbReader::backward(rest);
    let mut produced: usize = 0;
    while produced < count {
        out.push(lut.decode(&mut a));
        produced += 1;
        if produced == count {
            break;
        }
        out.push(lut.decode(&mut c));
        produced += 1;
        if produced == count {
            break;
        }
        out.push(lut.decode(&mut b));
        produced += 1;
    }
    if a.consumed_bytes() != split || b.consumed_bytes() + c.consumed_bytes() != rest.len() {
        return Err(OodleError::Malformed(
            "Huffman streams do not tile their array",
        ));
    }
    Ok(())
}

fn u16_le(bytes: &[u8], at: usize) -> Option<usize> {
    let slice: &[u8] = bytes.get(at..at + 2)?;
    Some(usize::from(slice[0]) | (usize::from(slice[1]) << 8))
}

pub(super) fn decode(
    ctx: &mut Ctx<'_>,
    payload: &[u8],
    dst_size: usize,
    two_halves: bool,
    out: &mut Vec<u8>,
) -> Result<(), OodleError> {
    let mut reader: MsbReader<'_> = MsbReader::forward(payload);
    let table: CodeTable = read_table(&mut reader, ctx)?;
    let header_len: usize = reader.consumed_bytes();
    if header_len > payload.len() {
        return Err(OodleError::Malformed("Huffman header runs past the array"));
    }
    let lengths: Vec<(u8, u8)> = match table {
        CodeTable::Single(symbol) => {
            if header_len != payload.len() {
                return Err(OodleError::Malformed(
                    "single-symbol Huffman array carries payload bytes",
                ));
            }
            out.resize(out.len() + dst_size, symbol);
            return Ok(());
        }
        CodeTable::Lengths(lengths) => lengths,
    };
    let lut: Lut = Lut::build(&lengths)?;
    let body: &[u8] = &payload[header_len..];
    if two_halves {
        ctx.bump("huffman:two-halves");
        if body.len() < 6 {
            return Err(OodleError::Malformed("two-half Huffman array truncated"));
        }
        let split_mid: usize =
            usize::from(body[0]) | (usize::from(body[1]) << 8) | (usize::from(body[2]) << 16);
        let rest: &[u8] = &body[3..];
        if split_mid > rest.len() {
            return Err(OodleError::Malformed(
                "two-half Huffman split lies past the array",
            ));
        }
        let (first, second): (&[u8], &[u8]) = rest.split_at(split_mid);
        let split_left: usize = u16_le(first, 0).ok_or(OodleError::Malformed(
            "two-half Huffman first half truncated",
        ))?;
        if first.len() - 2 < split_left + 2 || second.len() < 3 {
            return Err(OodleError::Malformed(
                "two-half Huffman halves are too short",
            ));
        }
        let split_right: usize = u16_le(second, 0).ok_or(OodleError::Malformed(
            "two-half Huffman second half truncated",
        ))?;
        if second.len() - 2 < split_right + 2 {
            return Err(OodleError::Malformed(
                "two-half Huffman second half is too short",
            ));
        }
        let half: usize = dst_size.div_ceil(2);
        decode_three_streams(&lut, &first[2..], split_left, half, out)?;
        decode_three_streams(&lut, &second[2..], split_right, dst_size - half, out)?;
    } else {
        if body.len() < 3 {
            return Err(OodleError::Malformed(
                "Huffman array truncated before its streams",
            ));
        }
        let split: usize =
            u16_le(body, 0).ok_or(OodleError::Malformed("Huffman split truncated"))?;
        decode_three_streams(&lut, &body[2..], split, dst_size, out)?;
    }
    Ok(())
}
