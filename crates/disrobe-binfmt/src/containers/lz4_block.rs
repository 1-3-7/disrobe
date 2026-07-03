use crate::error::{Error, Result};

const MIN_MATCH: usize = 4;

pub fn decompress(src: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    let out: Vec<u8> = decode_block(src, expected_len)?;
    if out.len() != expected_len {
        return Err(Error::Decompression(format!(
            "lz4: decoded {} bytes, expected {expected_len}",
            out.len()
        )));
    }
    Ok(out)
}

pub fn decompress_bounded(src: &[u8], max_len: usize) -> Result<Vec<u8>> {
    decode_block(src, max_len)
}

pub fn decompress_stop_at(src: &[u8], target_len: usize) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(target_len);
    let mut ip: usize = 0;
    while ip < src.len() && out.len() < target_len {
        let token: u8 = src[ip];
        ip += 1;

        let mut literal_len: usize = (token >> 4) as usize;
        if literal_len == 0x0F {
            literal_len += read_length_extension(src, &mut ip)?;
        }

        let literal_end: usize = ip.checked_add(literal_len).ok_or_else(length_overflow)?;
        let literals: &[u8] = src
            .get(ip..literal_end)
            .ok_or_else(|| Error::Decompression("lz4: literal run past end of input".to_owned()))?;
        out.extend_from_slice(literals);
        ip = literal_end;

        if out.len() >= target_len || ip >= src.len() {
            break;
        }

        let offset: usize = read_offset(src, &mut ip)?;
        if offset == 0 || offset > out.len() {
            return Err(Error::Decompression(format!(
                "lz4: match offset {offset} out of range (output len {})",
                out.len()
            )));
        }

        let mut match_len: usize = (token & 0x0F) as usize;
        if match_len == 0x0F {
            match_len += read_length_extension(src, &mut ip)?;
        }
        match_len += MIN_MATCH;

        copy_match(&mut out, offset, match_len);
    }
    out.truncate(target_len);
    Ok(out)
}

fn decode_block(src: &[u8], cap_hint: usize) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(cap_hint);
    let mut ip: usize = 0;
    while ip < src.len() {
        let token: u8 = src[ip];
        ip += 1;

        let mut literal_len: usize = (token >> 4) as usize;
        if literal_len == 0x0F {
            literal_len += read_length_extension(src, &mut ip)?;
        }

        let literal_end: usize = ip.checked_add(literal_len).ok_or_else(length_overflow)?;
        let literals: &[u8] = src
            .get(ip..literal_end)
            .ok_or_else(|| Error::Decompression("lz4: literal run past end of input".to_owned()))?;
        out.extend_from_slice(literals);
        ip = literal_end;

        if ip >= src.len() {
            break;
        }

        let offset: usize = read_offset(src, &mut ip)?;
        if offset == 0 || offset > out.len() {
            return Err(Error::Decompression(format!(
                "lz4: match offset {offset} out of range (output len {})",
                out.len()
            )));
        }

        let mut match_len: usize = (token & 0x0F) as usize;
        if match_len == 0x0F {
            match_len += read_length_extension(src, &mut ip)?;
        }
        match_len += MIN_MATCH;

        copy_match(&mut out, offset, match_len);
    }
    Ok(out)
}

fn read_length_extension(src: &[u8], ip: &mut usize) -> Result<usize> {
    let mut total: usize = 0;
    loop {
        let byte: u8 = *src
            .get(*ip)
            .ok_or_else(|| Error::Decompression("lz4: truncated length extension".to_owned()))?;
        *ip += 1;
        total = total
            .checked_add(byte as usize)
            .ok_or_else(length_overflow)?;
        if byte != 0xFF {
            return Ok(total);
        }
    }
}

fn read_offset(src: &[u8], ip: &mut usize) -> Result<usize> {
    let slice: &[u8] = src
        .get(*ip..*ip + 2)
        .ok_or_else(|| Error::Decompression("lz4: truncated match offset".to_owned()))?;
    *ip += 2;
    Ok(usize::from(u16::from_le_bytes([slice[0], slice[1]])))
}

fn copy_match(out: &mut Vec<u8>, offset: usize, match_len: usize) {
    let start: usize = out.len() - offset;
    for index in start..start + match_len {
        let byte: u8 = out[index];
        out.push(byte);
    }
}

fn length_overflow() -> Error {
    Error::Decompression("lz4: length arithmetic overflow".to_owned())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn compress_block(input: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        emit_literals_only(&mut out, input);
        out
    }

    fn emit_literals_only(out: &mut Vec<u8>, input: &[u8]) {
        let len: usize = input.len();
        let token: u8 = if len >= 0x0F { 0xF0 } else { (len as u8) << 4 };
        out.push(token);
        if len >= 0x0F {
            let mut remaining: usize = len - 0x0F;
            while remaining >= 0xFF {
                out.push(0xFF);
                remaining -= 0xFF;
            }
            out.push(remaining as u8);
        }
        out.extend_from_slice(input);
    }

    #[test]
    fn round_trip_literals_only_short() {
        let input: &[u8] = b"hello world";
        let compressed: Vec<u8> = compress_block(input);
        let decoded: Vec<u8> = decompress(&compressed, input.len()).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn round_trip_literals_only_long() {
        let input: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let compressed: Vec<u8> = compress_block(&input);
        let decoded: Vec<u8> = decompress(&compressed, input.len()).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn decodes_a_match_sequence() {
        let mut block: Vec<u8> = Vec::new();
        block.push(0x11);
        block.push(b'a');
        block.extend_from_slice(&1u16.to_le_bytes());
        let decoded: Vec<u8> = decompress(&block, 6).expect("decode");
        assert_eq!(decoded, b"aaaaaa");
    }

    #[test]
    fn overlapping_match_with_offset_two() {
        let mut block: Vec<u8> = Vec::new();
        block.push(0x23);
        block.extend_from_slice(b"ab");
        block.extend_from_slice(&2u16.to_le_bytes());
        let decoded: Vec<u8> = decompress(&block, 9).expect("decode");
        assert_eq!(decoded, b"ababababa");
    }

    #[test]
    fn rejects_offset_past_output() {
        let mut block: Vec<u8> = Vec::new();
        block.push(0x01);
        block.push(b'x');
        block.extend_from_slice(&5u16.to_le_bytes());
        let err: Error = decompress(&block, 5).expect_err("must reject");
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn rejects_wrong_expected_len() {
        let input: &[u8] = b"abc";
        let compressed: Vec<u8> = compress_block(input);
        let err: Error = decompress(&compressed, 99).expect_err("must reject");
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn bounded_accepts_short_decode_under_cap() {
        let input: &[u8] = b"squashfs tail block shorter than block size";
        let compressed: Vec<u8> = compress_block(input);
        let decoded: Vec<u8> = decompress_bounded(&compressed, 131_072).expect("bounded decode");
        assert_eq!(decoded, input);
    }
}
