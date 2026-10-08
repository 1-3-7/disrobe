use super::bits::MsbReader;
use super::{Ctx, OodleError, huffman, tans};

pub(super) const MAX_ARRAY_LEN: usize = 0x4_0000;

struct ArrayHeader {
    kind: u8,
    header_len: usize,
    src_size: usize,
    dst_size: usize,
}

fn parse_header(src: &[u8]) -> Result<ArrayHeader, OodleError> {
    let (b0, b1): (u8, u8) = match src {
        [b0, b1, ..] => (*b0, *b1),
        _ => return Err(OodleError::Malformed("entropy array header truncated")),
    };
    let kind: u8 = (b0 >> 4) & 7;
    if kind == 0 {
        if b0 >= 0x80 {
            let len: usize = ((usize::from(b0) << 8) | usize::from(b1)) & 0xFFF;
            return Ok(ArrayHeader {
                kind,
                header_len: 2,
                src_size: len,
                dst_size: len,
            });
        }
        let b2: u8 = *src
            .get(2)
            .ok_or(OodleError::Malformed("entropy array header truncated"))?;
        let len: usize = (usize::from(b0) << 16) | (usize::from(b1) << 8) | usize::from(b2);
        if len & !0x3_FFFF != 0 {
            return Err(OodleError::Malformed(
                "stored entropy array sets reserved length bits",
            ));
        }
        return Ok(ArrayHeader {
            kind,
            header_len: 3,
            src_size: len,
            dst_size: len,
        });
    }
    if kind >= 6 {
        return Err(OodleError::Malformed(
            "entropy array type 6 or 7 is reserved",
        ));
    }
    if b0 >= 0x80 {
        let bytes: &[u8] = src
            .get(..3)
            .ok_or(OodleError::Malformed("entropy array header truncated"))?;
        let bits: usize =
            (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]);
        let src_size: usize = bits & 0x3FF;
        let dst_size: usize = src_size + ((bits >> 10) & 0x3FF) + 1;
        return Ok(ArrayHeader {
            kind,
            header_len: 3,
            src_size,
            dst_size,
        });
    }
    let bytes: &[u8] = src
        .get(..5)
        .ok_or(OodleError::Malformed("entropy array header truncated"))?;
    let bits: usize = (usize::from(bytes[1]) << 24)
        | (usize::from(bytes[2]) << 16)
        | (usize::from(bytes[3]) << 8)
        | usize::from(bytes[4]);
    let src_size: usize = bits & 0x3_FFFF;
    let dst_size: usize = (((bits >> 18) | (usize::from(bytes[0]) << 14)) & 0x3_FFFF) + 1;
    if src_size >= dst_size {
        return Err(OodleError::Malformed(
            "entropy array declares no fewer input than output bytes",
        ));
    }
    Ok(ArrayHeader {
        kind,
        header_len: 5,
        src_size,
        dst_size,
    })
}

pub(super) fn peek_len(src: &[u8], capacity: usize) -> Result<usize, OodleError> {
    let header: ArrayHeader = parse_header(src)?;
    if header.dst_size > capacity || src.len() - header.header_len < header.src_size {
        return Err(OodleError::Malformed("entropy array exceeds its bound"));
    }
    Ok(header.dst_size)
}

pub(super) fn decode_bytes(
    ctx: &mut Ctx<'_>,
    src: &[u8],
    capacity: usize,
    out: &mut Vec<u8>,
) -> Result<usize, OodleError> {
    let header: ArrayHeader = parse_header(src)?;
    if header.dst_size > capacity.min(MAX_ARRAY_LEN)
        || src.len() - header.header_len < header.src_size
    {
        return Err(OodleError::Malformed("entropy array exceeds its bound"));
    }
    let payload: &[u8] = &src[header.header_len..header.header_len + header.src_size];
    let start: usize = out.len();
    if header.kind == 0 {
        ctx.bump("entropy:stored");
        out.extend_from_slice(payload);
        return Ok(header.header_len + header.src_size);
    }
    ctx.enter()?;
    let result: Result<(), OodleError> = match header.kind {
        1 => {
            ctx.bump("entropy:tans");
            tans::decode(ctx, payload, header.dst_size, out)
        }
        2 => {
            ctx.bump("entropy:huffman");
            huffman::decode(ctx, payload, header.dst_size, false, out)
        }
        3 => {
            ctx.bump("entropy:rle");
            decode_rle(ctx, payload, header.dst_size, out)
        }
        4 => {
            ctx.bump("entropy:huffman-two-halves");
            huffman::decode(ctx, payload, header.dst_size, true, out)
        }
        _ => {
            ctx.bump("entropy:recursive");
            decode_recursive(ctx, payload, header.dst_size, out)
        }
    };
    ctx.leave();
    result?;
    if out.len() - start != header.dst_size {
        return Err(OodleError::Malformed(
            "entropy array decodes to the wrong length",
        ));
    }
    Ok(header.header_len + header.src_size)
}

fn u16_at(bytes: &[u8], end: usize) -> u32 {
    u32::from(bytes[end - 2]) | (u32::from(bytes[end - 1]) << 8)
}

fn decode_rle(
    ctx: &mut Ctx<'_>,
    payload: &[u8],
    dst_size: usize,
    out: &mut Vec<u8>,
) -> Result<(), OodleError> {
    if payload.len() <= 1 {
        let fill: u8 = *payload
            .first()
            .ok_or(OodleError::Malformed("RLE array is empty"))?;
        out.resize(out.len() + dst_size, fill);
        return Ok(());
    }
    let commands: Vec<u8> = if payload[0] == 0 {
        payload[1..].to_vec()
    } else {
        ctx.bump("rle:entropy-coded-commands");
        let mut buffer: Vec<u8> = Vec::new();
        let used: usize = decode_bytes(ctx, payload, MAX_ARRAY_LEN, &mut buffer)?;
        buffer.extend_from_slice(&payload[used..]);
        buffer
    };
    let target: usize = out.len() + dst_size;
    let mut front: usize = 0;
    let mut back: usize = commands.len();
    let mut rle_byte: u8 = 0;
    let room = |out: &Vec<u8>| target - out.len();
    while front < back {
        let command: u8 = commands[back - 1];
        let (copy, repeat): (usize, usize) = if command == 0 || command >= 0x30 {
            back -= 1;
            (usize::from(!command & 0xF), usize::from(command >> 4))
        } else if command >= 0x10 {
            if back - front < 2 {
                return Err(OodleError::Malformed("RLE command truncated"));
            }
            let data: u32 = u16_at(&commands, back) - 4096;
            back -= 2;
            ((data & 0x3F) as usize, (data >> 6) as usize)
        } else if command == 1 {
            if back - front < 2 {
                return Err(OodleError::Malformed("RLE byte switch lacks its literal"));
            }
            rle_byte = commands[front];
            front += 1;
            back -= 1;
            continue;
        } else if command >= 9 {
            if back - front < 2 {
                return Err(OodleError::Malformed("RLE command truncated"));
            }
            let repeat: usize = (u16_at(&commands, back) - 0x8FF) as usize * 128;
            back -= 2;
            (0, repeat)
        } else {
            if back - front < 2 {
                return Err(OodleError::Malformed("RLE command truncated"));
            }
            let copy: usize = (u16_at(&commands, back) - 511) as usize * 64;
            back -= 2;
            (copy, 0)
        };
        if copy + repeat > room(out) || back - front < copy {
            return Err(OodleError::Malformed("RLE command overruns its buffers"));
        }
        out.extend_from_slice(&commands[front..front + copy]);
        front += copy;
        out.resize(out.len() + repeat, rle_byte);
    }
    if front != back || out.len() != target {
        return Err(OodleError::Malformed(
            "RLE commands do not fill the array exactly",
        ));
    }
    Ok(())
}

fn decode_recursive(
    ctx: &mut Ctx<'_>,
    payload: &[u8],
    dst_size: usize,
    out: &mut Vec<u8>,
) -> Result<(), OodleError> {
    if payload.len() < 6 {
        return Err(OodleError::Malformed("recursive entropy array truncated"));
    }
    let count: usize = usize::from(payload[0] & 0x7F);
    if count < 2 {
        return Err(OodleError::Malformed(
            "recursive entropy array holds fewer than two parts",
        ));
    }
    let start: usize = out.len();
    let used: usize = if payload[0] & 0x80 == 0 {
        let mut at: usize = 1;
        for _ in 0..count {
            let room: usize = dst_size - (out.len() - start);
            at += decode_bytes(ctx, &payload[at..], room, out)?;
        }
        at
    } else {
        let (used, arrays): (usize, Vec<Vec<u8>>) = decode_multi_array(ctx, payload, 1, dst_size)?;
        for array in arrays {
            out.extend_from_slice(&array);
        }
        used
    };
    if out.len() - start != dst_size || used != payload.len() {
        return Err(OodleError::Malformed(
            "recursive entropy array does not fill its output",
        ));
    }
    Ok(())
}

pub(super) fn decode_multi_array(
    ctx: &mut Ctx<'_>,
    src: &[u8],
    array_count: usize,
    capacity: usize,
) -> Result<(usize, Vec<Vec<u8>>), OodleError> {
    if src.len() < 4 {
        return Err(OodleError::Malformed("multi-array header truncated"));
    }
    if src[0] & 0x80 == 0 {
        return Err(OodleError::Malformed(
            "multi-array header lacks its flag bit",
        ));
    }
    ctx.bump("entropy:multi-array");
    let sources: usize = usize::from(src[0] & 0x3F);
    let mut at: usize = 1;
    let mut arrays: Vec<Vec<u8>> = Vec::with_capacity(array_count);
    if sources == 0 {
        ctx.bump("multi-array:plain");
        let mut total: usize = 0;
        for _ in 0..array_count {
            let mut array: Vec<u8> = Vec::new();
            at += decode_bytes(
                ctx,
                src.get(at..).unwrap_or(&[]),
                capacity - total,
                &mut array,
            )?;
            total += array.len();
            arrays.push(array);
        }
        return Ok((at, arrays));
    }
    let mut entropy: Vec<Vec<u8>> = Vec::with_capacity(sources);
    let mut total: usize = 0;
    for _ in 0..sources {
        let mut array: Vec<u8> = Vec::new();
        at += decode_bytes(
            ctx,
            src.get(at..).unwrap_or(&[]),
            capacity - total,
            &mut array,
        )?;
        total += array.len();
        entropy.push(array);
    }
    if src.len() - at < 3 {
        return Err(OodleError::Malformed(
            "multi-array interval header truncated",
        ));
    }
    let q: usize = usize::from(src[at]) | (usize::from(src[at + 1]) << 8);
    at += 2;
    let num_indexes: usize = peek_len(&src[at..], total)?;
    if num_indexes <= array_count {
        return Err(OodleError::Malformed(
            "multi-array declares too few intervals",
        ));
    }
    let mut indexes: Vec<u8> = Vec::with_capacity(num_indexes);
    let mut lenlog2: Vec<u8> = Vec::with_capacity(num_indexes);
    let num_lens: usize = if q & 0x8000 != 0 {
        ctx.bump("multi-array:packed-intervals");
        let mut packed: Vec<u8> = Vec::with_capacity(num_indexes);
        at += decode_bytes(ctx, &src[at..], num_indexes, &mut packed)?;
        if packed.len() != num_indexes {
            return Err(OodleError::Malformed(
                "multi-array packed intervals have the wrong length",
            ));
        }
        for byte in packed {
            lenlog2.push(byte >> 4);
            indexes.push(byte & 0xF);
        }
        num_indexes
    } else {
        ctx.bump("multi-array:split-intervals");
        let num_lens: usize = num_indexes - array_count;
        at += decode_bytes(ctx, &src[at..], num_indexes, &mut indexes)?;
        if indexes.len() != num_indexes {
            return Err(OodleError::Malformed(
                "multi-array interval indexes have the wrong length",
            ));
        }
        at += decode_bytes(ctx, src.get(at..).unwrap_or(&[]), num_lens, &mut lenlog2)?;
        if lenlog2.len() != num_lens || lenlog2.iter().any(|&bits: &u8| bits > 16) {
            return Err(OodleError::Malformed(
                "multi-array interval widths are malformed",
            ));
        }
        num_lens
    };
    let varbits: usize = q & 0x3FFF;
    let region: &[u8] = src.get(at..at + varbits).ok_or(OodleError::Malformed(
        "multi-array interval lengths truncated",
    ))?;
    let mut forward: MsbReader<'_> = MsbReader::forward(region);
    let mut backward: MsbReader<'_> = MsbReader::backward(region);
    let mut lens: Vec<usize> = Vec::with_capacity(num_lens);
    for (i, &bits) in lenlog2.iter().take(num_lens).enumerate() {
        let reader: &mut MsbReader<'_> = if i & 1 == 0 {
            &mut forward
        } else {
            &mut backward
        };
        lens.push((1usize << bits) | reader.read(u32::from(bits)) as usize);
    }
    if forward.consumed_bytes() + backward.consumed_bytes() > region.len() {
        return Err(OodleError::Malformed(
            "multi-array interval lengths overrun their region",
        ));
    }
    at += varbits;
    if indexes.last() != Some(&0) {
        return Err(OodleError::Malformed(
            "multi-array interval list does not end with a terminator",
        ));
    }
    let mut cursors: Vec<usize> = vec![0; sources];
    let mut index_at: usize = 0;
    let mut len_at: usize = 0;
    let mut produced: usize = 0;
    for _ in 0..array_count {
        let mut array: Vec<u8> = Vec::new();
        loop {
            let source: usize = usize::from(
                *indexes
                    .get(index_at)
                    .ok_or(OodleError::Malformed("multi-array intervals run out"))?,
            );
            index_at += 1;
            if source == 0 {
                break;
            }
            if source > sources {
                return Err(OodleError::Malformed(
                    "multi-array interval names a missing source",
                ));
            }
            let len: usize = *lens.get(len_at).ok_or(OodleError::Malformed(
                "multi-array interval lengths run out",
            ))?;
            len_at += 1;
            let from: &[u8] = &entropy[source - 1];
            let cursor: usize = cursors[source - 1];
            if len > from.len() - cursor || len > capacity - produced {
                return Err(OodleError::Malformed(
                    "multi-array interval overruns its source",
                ));
            }
            array.extend_from_slice(&from[cursor..cursor + len]);
            cursors[source - 1] += len;
            produced += len;
        }
        if q & 0x8000 != 0 {
            len_at += 1;
        }
        arrays.push(array);
    }
    if index_at != num_indexes || len_at != num_lens {
        return Err(OodleError::Malformed(
            "multi-array intervals are not consumed exactly",
        ));
    }
    ctx.bump("multi-array:intervals-read");
    if cursors
        .iter()
        .zip(&entropy)
        .any(|(&cursor, array): (&usize, &Vec<u8>)| cursor != array.len())
    {
        return Err(OodleError::Malformed(
            "multi-array sources are not consumed exactly",
        ));
    }
    Ok((at, arrays))
}
