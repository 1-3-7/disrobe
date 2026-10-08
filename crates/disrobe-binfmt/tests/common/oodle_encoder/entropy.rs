use super::bits::{MsbWriter, bit_length};
use super::huffman::{self, HuffHeader, histogram};
use super::tans::{self, TansTable};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Form {
    Stored,
    Huffman(HuffHeader),
    HuffmanHalves(HuffHeader),
    Tans { table: TansTable, l_bits: u32 },
    Rle,
    RleCodedCommands,
    Recursive(usize),
    RecursiveMulti(usize),
}

fn frame(kind: u8, payload: &[u8], dst_size: usize, long: bool) -> Vec<u8> {
    let src_size: usize = payload.len();
    let mut out: Vec<u8> = Vec::with_capacity(src_size + 5);
    if kind == 0 {
        if !long && src_size <= 0xFFF {
            out.push(0x80 | (src_size >> 8) as u8);
            out.push(src_size as u8);
        } else {
            assert!(src_size <= 0x3_FFFF, "stored array too long");
            out.extend_from_slice(&(src_size as u32).to_be_bytes()[1..]);
        }
    } else if !long && src_size <= 0x3FF && dst_size > src_size && dst_size - src_size - 1 <= 0x3FF
    {
        let bits: usize = src_size | ((dst_size - src_size - 1) << 10);
        out.push(0x80 | (kind << 4) | (bits >> 16) as u8);
        out.push((bits >> 8) as u8);
        out.push(bits as u8);
    } else {
        assert!(
            src_size < dst_size,
            "an entropy array must be smaller than its output"
        );
        assert!(dst_size <= 0x4_0000, "entropy array output too long");
        let bits: u32 = ((((dst_size - 1) & 0x3FFF) as u32) << 18) | src_size as u32;
        out.push((kind << 4) | ((dst_size - 1) >> 14) as u8);
        out.extend_from_slice(&bits.to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

pub fn stored(data: &[u8], long: bool) -> Vec<u8> {
    frame(0, data, data.len(), long)
}

fn rle_commands(data: &[u8]) -> Vec<u8> {
    let mut literals: Vec<u8> = Vec::new();
    let mut commands: Vec<Vec<u8>> = Vec::new();
    let mut rle_byte: u8 = 0;
    let mut pending: usize = 0;
    let mut pos: usize = 0;
    let flush_copy = |literals: &mut Vec<u8>,
                      commands: &mut Vec<Vec<u8>>,
                      from: usize,
                      count: usize,
                      repeat: usize| {
        let mut copy: usize = count;
        let mut at: usize = from;
        while copy >= 64 {
            let chunk: usize = (copy / 64).min(0x700);
            let value: usize = 511 + chunk;
            commands.push(vec![value as u8, (value >> 8) as u8]);
            literals.extend_from_slice(&data[at..at + chunk * 64]);
            at += chunk * 64;
            copy -= chunk * 64;
        }
        let mut repeat: usize = repeat;
        let mut long_repeat: usize = repeat / 128;
        if copy == 0 && long_repeat > 0 {
            long_repeat = long_repeat.min(0x700);
            let value: usize = 0x8FF + long_repeat;
            commands.push(vec![value as u8, (value >> 8) as u8]);
            repeat -= long_repeat * 128;
        }
        while copy > 0 || repeat > 0 {
            let take_copy: usize = copy.min(63);
            let take_repeat: usize = repeat.min(127);
            if take_copy <= 15 && (3..=15).contains(&take_repeat) {
                commands.push(vec![((take_repeat << 4) | (15 - take_copy)) as u8]);
            } else {
                let value: usize = 4096 + ((take_repeat << 6) | take_copy);
                commands.push(vec![value as u8, (value >> 8) as u8]);
            }
            literals.extend_from_slice(&data[at..at + take_copy]);
            at += take_copy;
            copy -= take_copy;
            repeat -= take_repeat;
        }
    };
    while pos < data.len() {
        let byte: u8 = data[pos];
        let mut run: usize = 1;
        while pos + run < data.len() && data[pos + run] == byte {
            run += 1;
        }
        if run >= 4 {
            if byte != rle_byte {
                flush_copy(&mut literals, &mut commands, pos - pending, pending, 0);
                pending = 0;
                commands.push(vec![1]);
                literals.push(byte);
                rle_byte = byte;
            }
            flush_copy(&mut literals, &mut commands, pos - pending, pending, run);
            pending = 0;
        } else {
            pending += run;
        }
        pos += run;
    }
    flush_copy(&mut literals, &mut commands, pos - pending, pending, 0);
    let mut buffer: Vec<u8> = literals;
    for command in commands.iter().rev() {
        buffer.extend_from_slice(command);
    }
    buffer
}

fn rle_payload(data: &[u8], coded: bool) -> Vec<u8> {
    let distinct: usize = histogram(data).iter().filter(|&&c: &&u64| c > 0).count();
    if distinct == 1 && !coded {
        return vec![data[0]];
    }
    let buffer: Vec<u8> = rle_commands(data);
    if coded {
        let split: usize = buffer.len() / 2;
        let mut out: Vec<u8> = encode(
            &buffer[..split],
            &Form::Huffman(HuffHeader::New { forced: 1 }),
            false,
        )
        .unwrap_or_else(|| stored(&buffer[..split], false));
        assert_ne!(
            out[0], 0,
            "a coded command prefix cannot start with a zero byte"
        );
        out.extend_from_slice(&buffer[split..]);
        out
    } else {
        let mut out: Vec<u8> = vec![0];
        out.extend_from_slice(&buffer);
        out
    }
}

pub fn encode(data: &[u8], form: &Form, long: bool) -> Option<Vec<u8>> {
    if data.is_empty() {
        return Some(stored(data, long));
    }
    let (kind, payload): (u8, Vec<u8>) = match form {
        Form::Stored => return Some(stored(data, long)),
        Form::Huffman(header) | Form::HuffmanHalves(header) => {
            let halves: bool = matches!(form, Form::HuffmanHalves(_));
            if halves && data.len() < 12 {
                return None;
            }
            let distinct: usize = histogram(data).iter().filter(|&&c: &&u64| c > 0).count();
            if distinct > 255 && *header == HuffHeader::OldSparse {
                return None;
            }
            let payload: Vec<u8> = huffman::encode_payload(data, *header, halves);
            (if halves { 4 } else { 2 }, payload)
        }
        Form::Tans { table, l_bits } => {
            let distinct: usize = histogram(data).iter().filter(|&&c: &&u64| c > 0).count();
            if data.len() < 5 || distinct < 2 || (*table == TansTable::Explicit && distinct > 9) {
                return None;
            }
            (1, tans::encode_payload(data, *table, *l_bits))
        }
        Form::Rle => (3, rle_payload(data, false)),
        Form::RleCodedCommands => (3, rle_payload(data, true)),
        Form::Recursive(parts) => {
            let parts: usize = (*parts).clamp(2, 127);
            if data.len() < parts {
                return None;
            }
            let chunk: usize = data.len().div_ceil(parts);
            let mut payload: Vec<u8> = vec![parts as u8];
            let pieces: Vec<&[u8]> = data.chunks(chunk).collect();
            if pieces.len() != parts {
                return None;
            }
            for (i, piece) in pieces.iter().enumerate() {
                let inner: Form = if i % 2 == 0 {
                    Form::Huffman(HuffHeader::OldDense { forced: 1 })
                } else {
                    Form::Stored
                };
                payload
                    .extend(encode(piece, &inner, false).unwrap_or_else(|| stored(piece, false)));
            }
            (5, payload)
        }
        Form::RecursiveMulti(sources) => {
            let payload: Vec<u8> = encode_multi(
                &[data.to_vec()],
                &MultiStyle::Intervals {
                    sources: (*sources).clamp(2, 15),
                    packed: true,
                },
            )?;
            (5, payload)
        }
    };
    if payload.len() < 6 && kind == 5 {
        return None;
    }
    if payload.len() >= data.len() || data.len() > 0x4_0000 {
        return None;
    }
    if long && payload.len() > 0x3_FFFF {
        return None;
    }
    Some(frame(kind, &payload, data.len(), long))
}

pub fn encode_or_store(data: &[u8], form: &Form, long: bool) -> Vec<u8> {
    encode(data, form, long).unwrap_or_else(|| stored(data, long))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiStyle {
    Plain(Form),
    Intervals { sources: usize, packed: bool },
}

pub fn encode_multi(arrays: &[Vec<u8>], style: &MultiStyle) -> Option<Vec<u8>> {
    match style {
        MultiStyle::Plain(form) => {
            let mut out: Vec<u8> = vec![0x80];
            for array in arrays {
                out.extend(encode_or_store(array, form, false));
            }
            if out.len() < 4 {
                return None;
            }
            Some(out)
        }
        MultiStyle::Intervals { sources, packed } => encode_intervals(arrays, *sources, *packed),
    }
}

fn encode_intervals(arrays: &[Vec<u8>], sources: usize, packed: bool) -> Option<Vec<u8>> {
    let concat: Vec<u8> = arrays.concat();
    if concat.len() < sources || sources == 0 || sources > 63 || (packed && sources > 15) {
        return None;
    }
    let chunk: usize = concat.len().div_ceil(sources);
    let bounds: Vec<(usize, usize)> = (0..sources)
        .map(|i: usize| (i * chunk, ((i + 1) * chunk).min(concat.len())))
        .collect();
    if bounds
        .iter()
        .any(|&(start, end): &(usize, usize)| start >= end)
    {
        return None;
    }
    let max_len: usize = if packed { (1 << 15) - 1 } else { (1 << 16) - 1 };
    let mut indexes: Vec<u8> = Vec::new();
    let mut lens: Vec<usize> = Vec::new();
    let mut offset: usize = 0;
    for array in arrays {
        let mut left: usize = array.len();
        while left > 0 {
            let source: usize = offset / chunk;
            let room: usize = bounds[source].1 - offset;
            let take: usize = left.min(room).min(max_len);
            indexes.push(source as u8 + 1);
            lens.push(take);
            offset += take;
            left -= take;
        }
        indexes.push(0);
        if packed {
            lens.push(0);
        }
    }
    if indexes.len() <= arrays.len() || indexes.len() > concat.len() {
        return None;
    }
    let mut out: Vec<u8> = vec![0x80 | sources as u8];
    for (i, &(start, end)) in bounds.iter().enumerate() {
        let form: Form = if i % 2 == 0 {
            Form::Huffman(HuffHeader::New { forced: 0 })
        } else {
            Form::Stored
        };
        out.extend(encode_or_store(&concat[start..end], &form, false));
    }
    let mut forward: MsbWriter = MsbWriter::new();
    let mut backward: MsbWriter = MsbWriter::new();
    let mut lenlog2: Vec<u8> = Vec::with_capacity(lens.len());
    for (i, &len) in lens.iter().enumerate() {
        let bits: u32 = bit_length(len.max(1) as u32) - 1;
        lenlog2.push(bits as u8);
        let rest: u32 = len.max(1) as u32 - (1 << bits);
        if i % 2 == 0 {
            forward.put(rest, bits);
        } else {
            backward.put(rest, bits);
        }
    }
    let mut region: Vec<u8> = forward.finish();
    let mut back: Vec<u8> = backward.finish();
    back.reverse();
    region.extend(back);
    if region.len() > 0x3FFF {
        return None;
    }
    let q: u16 = region.len() as u16 | if packed { 0x8000 } else { 0 };
    out.extend_from_slice(&q.to_le_bytes());
    if packed {
        let combined: Vec<u8> = indexes
            .iter()
            .zip(&lenlog2)
            .map(|(&index, &bits): (&u8, &u8)| (bits << 4) | index)
            .collect();
        out.extend(encode_or_store(&combined, &Form::Stored, false));
    } else {
        out.extend(encode_or_store(&indexes, &Form::Rle, false));
        out.extend(encode_or_store(&lenlog2, &Form::Stored, false));
    }
    out.extend(region);
    Some(out)
}
