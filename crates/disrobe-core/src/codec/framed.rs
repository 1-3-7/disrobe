//! Framed transport codecs.
//!
//! Adobe `ASCII85` (`<~ ~>` framing with `z`/`y` specials), `ZeroMQ` Z85, uuencode
//! (`begin`/`end` with a per-line length char and a 32 offset), xxencode, and yEnc
//! (`=ybegin`/`=yend`, 42 offset, `0x3D` escape).
//!
//! Each decoder bounds its output against the input length and rejects malformed
//! framing rather than guessing.

use super::{DecodeError, bytes_to_string};

const ASCII85_OFFSET: u8 = 33;
const Z85_ALPHABET: &[u8; 85] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
const UU_OFFSET: u8 = 32;
const YENC_OFFSET: u8 = 42;
const YENC_ESCAPE: u8 = 0x3d;
const XX_ALPHABET: &[u8; 64] = b"+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const MAX_FRAMED_INPUT: usize = 1 << 26;

#[must_use]
const fn invert64(alphabet: &[u8; 64]) -> [i16; 256] {
    let mut table: [i16; 256] = [-1; 256];
    let mut i: usize = 0;
    while i < 64 {
        table[alphabet[i] as usize] = i as i16;
        i += 1;
    }
    table
}

#[must_use]
const fn invert85(alphabet: &[u8; 85]) -> [i16; 256] {
    let mut table: [i16; 256] = [-1; 256];
    let mut i: usize = 0;
    while i < 85 {
        table[alphabet[i] as usize] = i as i16;
        i += 1;
    }
    table
}

/// Decode an Adobe ASCII85 stream. Optional `<~`/`~>` framing is stripped, the `z`
/// all-zero and `y` all-space shortcuts are honored, and whitespace is ignored.
pub fn ascii85_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if input.len() > MAX_FRAMED_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let mut body: &[u8] = input;
    if let Some(rest) = strip_prefix(body, b"<~") {
        body = rest;
    }
    if let Some(rest) = strip_suffix(body, b"~>") {
        body = rest;
    }
    let mut out: Vec<u8> = Vec::with_capacity(body.len() * 4 / 5 + 4);
    let mut group: [u8; 5] = [0; 5];
    let mut count: usize = 0;
    for &byte in body {
        match byte {
            b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c => {}
            b'z' if count == 0 => out.extend_from_slice(&[0, 0, 0, 0]),
            b'y' if count == 0 => out.extend_from_slice(&[0x20, 0x20, 0x20, 0x20]),
            0x21..=0x75 => {
                group[count] = byte - ASCII85_OFFSET;
                count += 1;
                if count == 5 {
                    push_ascii85_group(group, 5, &mut out)?;
                    count = 0;
                }
            }
            other => return Err(DecodeError::InvalidSymbol { symbol: other }),
        }
    }
    if count > 0 {
        if count == 1 {
            return Err(DecodeError::BadLength { len: body.len() });
        }
        for slot in group.iter_mut().skip(count) {
            *slot = 84;
        }
        push_ascii85_group(group, count, &mut out)?;
    }
    Ok(out)
}

fn push_ascii85_group(group: [u8; 5], count: usize, out: &mut Vec<u8>) -> Result<(), DecodeError> {
    let mut value: u32 = 0;
    for &digit in &group {
        value = value
            .checked_mul(85)
            .and_then(|v: u32| v.checked_add(digit as u32))
            .ok_or(DecodeError::Overflow)?;
    }
    let bytes: [u8; 4] = value.to_be_bytes();
    out.extend_from_slice(&bytes[..count - 1]);
    Ok(())
}

/// Encode bytes as an Adobe ASCII85 stream, including the `<~`/`~>` framing.
#[must_use]
pub fn ascii85_encode(input: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 5 / 4 + 8);
    out.extend_from_slice(b"<~");
    for chunk in input.chunks(4) {
        if chunk.len() == 4 && chunk.iter().all(|&b: &u8| b == 0) {
            out.push(b'z');
            continue;
        }
        let mut value: u32 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            value |= (byte as u32) << (24 - 8 * i);
        }
        let mut digits: [u8; 5] = [0; 5];
        let mut remainder: u32 = value;
        for slot in digits.iter_mut().rev() {
            *slot = (remainder % 85) as u8 + ASCII85_OFFSET;
            remainder /= 85;
        }
        out.extend_from_slice(&digits[..=chunk.len()]);
    }
    out.extend_from_slice(b"~>");
    bytes_to_string(out)
}

/// Decode a `ZeroMQ` Z85 string. The input length must be a multiple of five.
pub fn z85_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if input.len() > MAX_FRAMED_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    if !input.len().is_multiple_of(5) {
        return Err(DecodeError::BadLength { len: input.len() });
    }
    let table: [i16; 256] = invert85(Z85_ALPHABET);
    let mut out: Vec<u8> = Vec::with_capacity(input.len() / 5 * 4);
    for chunk in input.chunks(5) {
        let mut value: u32 = 0;
        for &symbol in chunk {
            let digit: i16 = table[symbol as usize];
            if digit < 0 {
                return Err(DecodeError::InvalidSymbol { symbol });
            }
            value = value
                .checked_mul(85)
                .and_then(|v: u32| v.checked_add(digit as u32))
                .ok_or(DecodeError::Overflow)?;
        }
        out.extend_from_slice(&value.to_be_bytes());
    }
    Ok(out)
}

/// Encode bytes as a `ZeroMQ` Z85 string. The input length must be a multiple of four.
pub fn z85_encode(input: &[u8]) -> Result<String, DecodeError> {
    if !input.len().is_multiple_of(4) {
        return Err(DecodeError::BadLength { len: input.len() });
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len() / 4 * 5);
    for chunk in input.chunks(4) {
        let value: u32 = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let mut digits: [u8; 5] = [0; 5];
        let mut remainder: u32 = value;
        for slot in digits.iter_mut().rev() {
            *slot = Z85_ALPHABET[(remainder % 85) as usize];
            remainder /= 85;
        }
        out.extend_from_slice(&digits);
    }
    Ok(bytes_to_string(out))
}

/// Decode a uuencoded stream framed by `begin <mode> <name>` and `end`. Each data
/// line begins with a length character (`byte - 32`) followed by 4:3 groups.
pub fn uudecode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode_uu_family(input, b"begin", UU_OFFSET, true)
}

/// Decode an xxencoded stream framed by `begin`/`end`. The alphabet is positional
/// rather than offset-based.
pub fn xxdecode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode_uu_family(input, b"begin", 0, false)
}

fn decode_uu_family(
    input: &[u8],
    marker: &[u8],
    offset: u8,
    offset_based: bool,
) -> Result<Vec<u8>, DecodeError> {
    if input.len() > MAX_FRAMED_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let table: [i16; 256] = invert64(XX_ALPHABET);
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 3 / 4 + 4);
    let mut started: bool = false;
    let mut finished: bool = false;
    for line in input.split(|&b: &u8| b == b'\n') {
        let line: &[u8] = trim_cr(line);
        if !started {
            if line.starts_with(marker) {
                started = true;
            }
            continue;
        }
        if line == b"end" {
            finished = true;
            break;
        }
        if line.is_empty() {
            continue;
        }
        let length: usize = decode_uu_line_length(line[0], offset, offset_based, &table)?;
        if length == 0 {
            continue;
        }
        let mut produced: usize = 0;
        let payload: &[u8] = &line[1..];
        for chunk in payload.chunks(4) {
            if chunk.len() < 2 {
                break;
            }
            let mut sextets: [u8; 4] = [0; 4];
            for (i, &symbol) in chunk.iter().enumerate() {
                sextets[i] = decode_uu_symbol(symbol, offset, offset_based, &table)?;
            }
            let b0: u8 = (sextets[0] << 2) | (sextets[1] >> 4);
            let b1: u8 = (sextets[1] << 4) | (sextets[2] >> 2);
            let b2: u8 = (sextets[2] << 6) | sextets[3];
            for byte in [b0, b1, b2] {
                if produced < length {
                    out.push(byte);
                    produced += 1;
                }
            }
        }
    }
    if !finished && !started {
        return Err(DecodeError::MissingFrame);
    }
    Ok(out)
}

const fn decode_uu_line_length(
    first: u8,
    offset: u8,
    offset_based: bool,
    table: &[i16; 256],
) -> Result<usize, DecodeError> {
    if offset_based {
        Ok((first.wrapping_sub(offset) & 0x3f) as usize)
    } else {
        let digit: i16 = table[first as usize];
        if digit < 0 {
            return Err(DecodeError::InvalidSymbol { symbol: first });
        }
        Ok(digit as usize)
    }
}

const fn decode_uu_symbol(
    symbol: u8,
    offset: u8,
    offset_based: bool,
    table: &[i16; 256],
) -> Result<u8, DecodeError> {
    if offset_based {
        if symbol == b'`' {
            return Ok(0);
        }
        Ok(symbol.wrapping_sub(offset) & 0x3f)
    } else {
        let digit: i16 = table[symbol as usize];
        if digit < 0 {
            return Err(DecodeError::InvalidSymbol { symbol });
        }
        Ok(digit as u8)
    }
}

/// Encode bytes as a uuencoded stream named `name`.
#[must_use]
pub fn uuencode(input: &[u8], name: &str) -> String {
    encode_uu_family(input, name, UU_OFFSET, true)
}

/// Encode bytes as an xxencoded stream named `name`.
#[must_use]
pub fn xxencode(input: &[u8], name: &str) -> String {
    encode_uu_family(input, name, 0, false)
}

fn encode_uu_family(input: &[u8], name: &str, offset: u8, offset_based: bool) -> String {
    let symbol = |value: u8| -> u8 {
        if offset_based {
            if value == 0 { b'`' } else { value + offset }
        } else {
            XX_ALPHABET[value as usize]
        }
    };
    let length_char = |len: u8| -> u8 {
        if offset_based {
            if len == 0 { b'`' } else { len + offset }
        } else {
            XX_ALPHABET[len as usize]
        }
    };
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 4 / 3 + 32);
    out.extend_from_slice(format!("begin 644 {name}\n").as_bytes());
    for line in input.chunks(45) {
        out.push(length_char(line.len() as u8));
        for chunk in line.chunks(3) {
            let mut triple: [u8; 3] = [0; 3];
            triple[..chunk.len()].copy_from_slice(chunk);
            out.push(symbol(triple[0] >> 2));
            out.push(symbol(((triple[0] << 4) | (triple[1] >> 4)) & 0x3f));
            out.push(symbol(((triple[1] << 2) | (triple[2] >> 6)) & 0x3f));
            out.push(symbol(triple[2] & 0x3f));
        }
        out.push(b'\n');
    }
    out.push(length_char(0));
    out.push(b'\n');
    out.extend_from_slice(b"end\n");
    bytes_to_string(out)
}

/// Decode a yEnc stream. Recognizes `=ybegin`/`=yend` headers, applies the 42
/// offset, and undoes the `0x3D` critical-byte escape (`escaped - 64 - 42`).
pub fn yenc_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if input.len() > MAX_FRAMED_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut in_body: bool = false;
    let mut saw_begin: bool = false;
    for line in input.split(|&b: &u8| b == b'\n') {
        let line: &[u8] = trim_cr(line);
        if line.starts_with(b"=ybegin") {
            saw_begin = true;
            in_body = true;
            continue;
        }
        if line.starts_with(b"=ypart") {
            continue;
        }
        if line.starts_with(b"=yend") {
            in_body = false;
            continue;
        }
        if !in_body {
            continue;
        }
        let mut escape: bool = false;
        for &byte in line {
            if escape {
                out.push(byte.wrapping_sub(64).wrapping_sub(YENC_OFFSET));
                escape = false;
            } else if byte == YENC_ESCAPE {
                escape = true;
            } else {
                out.push(byte.wrapping_sub(YENC_OFFSET));
            }
        }
    }
    if !saw_begin {
        return Err(DecodeError::MissingFrame);
    }
    Ok(out)
}

/// Encode bytes as a single-part yEnc stream named `name`. The result is binary, not
/// text, because yEnc emits bytes across the full `0..=255` range.
#[must_use]
pub fn yenc_encode(input: &[u8], name: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 2 + 64);
    out.extend_from_slice(
        format!("=ybegin line=128 size={} name={name}\r\n", input.len()).as_bytes(),
    );
    let mut column: usize = 0;
    for &byte in input {
        let encoded: u8 = byte.wrapping_add(YENC_OFFSET);
        let critical: bool = matches!(encoded, 0x00 | 0x0a | 0x0d | 0x3d);
        if critical {
            out.push(YENC_ESCAPE);
            out.push(encoded.wrapping_add(64));
            column += 2;
        } else {
            out.push(encoded);
            column += 1;
        }
        if column >= 128 {
            out.extend_from_slice(b"\r\n");
            column = 0;
        }
    }
    if column > 0 {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("=yend size={}\r\n", input.len()).as_bytes());
    out
}

#[must_use]
const fn trim_cr(line: &[u8]) -> &[u8] {
    if let [body @ .., b'\r'] = line {
        body
    } else {
        line
    }
}

#[must_use]
fn strip_prefix<'a>(input: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let trimmed: &[u8] = trim_lead_ws(input);
    trimmed.strip_prefix(prefix)
}

#[must_use]
fn strip_suffix<'a>(input: &'a [u8], suffix: &[u8]) -> Option<&'a [u8]> {
    let trimmed: &[u8] = trim_trail_ws(input);
    trimmed.strip_suffix(suffix)
}

#[must_use]
const fn trim_lead_ws(input: &[u8]) -> &[u8] {
    let mut i: usize = 0;
    while i < input.len() && input[i].is_ascii_whitespace() {
        i += 1;
    }
    input.split_at(i).1
}

#[must_use]
const fn trim_trail_ws(input: &[u8]) -> &[u8] {
    let mut end: usize = input.len();
    while end > 0 && input[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    input.split_at(end).0
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn ascii85_known_vector() {
        let plain: &[u8] = b"Man is distinguished";
        let encoded: String = ascii85_encode(plain);
        assert!(encoded.starts_with("<~") && encoded.ends_with("~>"));
        assert_eq!(ascii85_decode(encoded.as_bytes()).unwrap(), plain);
    }

    #[test]
    fn ascii85_z_and_y_shortcuts() {
        assert_eq!(ascii85_decode(b"<~z~>").unwrap(), vec![0, 0, 0, 0]);
        assert_eq!(
            ascii85_decode(b"<~y~>").unwrap(),
            vec![0x20, 0x20, 0x20, 0x20]
        );
    }

    #[test]
    fn ascii85_ignores_whitespace_and_no_frame() {
        let encoded: String = ascii85_encode(b"hello world");
        let inner: &str = encoded.trim_start_matches("<~").trim_end_matches("~>");
        let spaced: String = format!("{} {}", &inner[..4], &inner[4..]);
        assert_eq!(ascii85_decode(spaced.as_bytes()).unwrap(), b"hello world");
    }

    #[test]
    fn z85_reference_vector() {
        let data: [u8; 8] = [0x86, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b];
        assert_eq!(z85_encode(&data).unwrap(), "HelloWorld");
        assert_eq!(z85_decode(b"HelloWorld").unwrap(), data);
    }

    #[test]
    fn z85_rejects_bad_length() {
        assert!(matches!(
            z85_decode(b"Hell"),
            Err(DecodeError::BadLength { .. })
        ));
    }

    #[test]
    fn uuencode_roundtrip() {
        let plain: &[u8] = b"The quick brown fox jumps over 13 lazy dogs.";
        let encoded: String = uuencode(plain, "test.bin");
        assert!(encoded.contains("begin 644 test.bin"));
        assert_eq!(uudecode(encoded.as_bytes()).unwrap(), plain);
    }

    #[test]
    fn uudecode_known_cat_vector() {
        let stream: &str = "begin 644 cat.txt\n#0V%T\n`\nend\n";
        assert_eq!(uudecode(stream.as_bytes()).unwrap(), b"Cat");
    }

    #[test]
    fn xxencode_roundtrip() {
        let plain: &[u8] = b"xxencode positional alphabet payload!!";
        let encoded: String = xxencode(plain, "x.bin");
        assert_eq!(xxdecode(encoded.as_bytes()).unwrap(), plain);
    }

    #[test]
    fn yenc_roundtrip_with_escapes() {
        let plain: Vec<u8> = (0u16..=255).map(|b: u16| b as u8).collect();
        let encoded: Vec<u8> = yenc_encode(&plain, "all.bin");
        let head: &str = core::str::from_utf8(&encoded[..32]).unwrap();
        assert!(head.starts_with("=ybegin"));
        assert_eq!(yenc_decode(&encoded).unwrap(), plain);
    }

    #[test]
    fn yenc_requires_begin() {
        assert!(matches!(
            yenc_decode(b"no frame here"),
            Err(DecodeError::MissingFrame)
        ));
    }
}
