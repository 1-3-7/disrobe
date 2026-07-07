use super::{DecodeError, bytes_to_string};

const PUNY_BASE: u32 = 36;
const PUNY_TMIN: u32 = 1;
const PUNY_TMAX: u32 = 26;
const PUNY_SKEW: u32 = 38;
const PUNY_DAMP: u32 = 700;
const PUNY_INITIAL_BIAS: u32 = 72;
const PUNY_INITIAL_N: u32 = 128;
const MAX_WEB_INPUT: usize = 1 << 24;

pub fn percent_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if input.len() > MAX_WEB_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i: usize = 0;
    while i < input.len() {
        let byte: u8 = input[i];
        if byte == b'%' {
            let hi: u8 = *input
                .get(i + 1)
                .ok_or(DecodeError::BadLength { len: input.len() })?;
            let lo: u8 = *input
                .get(i + 2)
                .ok_or(DecodeError::BadLength { len: input.len() })?;
            let hi_v: u8 = hex_value(hi).ok_or(DecodeError::InvalidSymbol { symbol: hi })?;
            let lo_v: u8 = hex_value(lo).ok_or(DecodeError::InvalidSymbol { symbol: lo })?;
            out.push((hi_v << 4) | lo_v);
            i += 3;
        } else if byte == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(byte);
            i += 1;
        }
    }
    Ok(out)
}

#[must_use]
pub fn percent_encode(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 3);
    for &byte in input {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte);
        } else {
            out.push(b'%');
            out.push(HEX[(byte >> 4) as usize]);
            out.push(HEX[(byte & 0x0f) as usize]);
        }
    }
    bytes_to_string(out)
}

pub fn html_entity_decode(input: &str) -> Result<String, DecodeError> {
    if input.len() > MAX_WEB_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let bytes: &[u8] = input.as_bytes();
    let mut out: String = String::with_capacity(input.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            let ch: char = input[i..]
                .chars()
                .next()
                .ok_or(DecodeError::BadLength { len: input.len() })?;
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let Some(semicolon) = bytes[i + 1..].iter().position(|&b: &u8| b == b';') else {
            out.push('&');
            i += 1;
            continue;
        };
        let entity: &str = &input[i + 1..i + 1 + semicolon];
        if let Some(decoded) = decode_one_entity(entity) {
            out.push(decoded);
            i += 1 + semicolon + 1;
        } else {
            out.push('&');
            i += 1;
        }
    }
    Ok(out)
}

fn decode_one_entity(entity: &str) -> Option<char> {
    if let Some(rest) = entity.strip_prefix('#') {
        let code: u32 = if let Some(hex) = rest.strip_prefix(['x', 'X']) {
            u32::from_str_radix(hex, 16).ok()?
        } else {
            rest.parse::<u32>().ok()?
        };
        return char::from_u32(code);
    }
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{a0}'),
        "copy" => Some('\u{a9}'),
        "reg" => Some('\u{ae}'),
        "trade" => Some('\u{2122}'),
        "euro" => Some('\u{20ac}'),
        "mdash" => Some('\u{2014}'),
        "ndash" => Some('\u{2013}'),
        "hellip" => Some('\u{2026}'),
        _ => None,
    }
}

pub fn punycode_decode_label(input: &str) -> Result<String, DecodeError> {
    if input.len() > MAX_WEB_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let bytes: &[u8] = input.as_bytes();
    let mut output: Vec<char> = Vec::new();
    let mut n: u32 = PUNY_INITIAL_N;
    let mut i: u32 = 0;
    let mut bias: u32 = PUNY_INITIAL_BIAS;
    let basic_end: usize = input.rfind('-').unwrap_or(0);
    if basic_end > 0 {
        for &byte in &bytes[..basic_end] {
            if byte >= 0x80 {
                return Err(DecodeError::InvalidSymbol { symbol: byte });
            }
            output.push(byte as char);
        }
    }
    let mut pos: usize = if basic_end > 0 { basic_end + 1 } else { 0 };
    while pos < bytes.len() {
        let old_i: u32 = i;
        let mut weight: u32 = 1;
        let mut k: u32 = PUNY_BASE;
        loop {
            let symbol: u8 = *bytes
                .get(pos)
                .ok_or(DecodeError::BadLength { len: input.len() })?;
            pos += 1;
            let digit: u32 =
                puny_decode_digit(symbol).ok_or(DecodeError::InvalidSymbol { symbol })?;
            i = digit
                .checked_mul(weight)
                .and_then(|v: u32| v.checked_add(i))
                .ok_or(DecodeError::Overflow)?;
            let t: u32 = puny_threshold(k, bias);
            if digit < t {
                break;
            }
            weight = weight
                .checked_mul(PUNY_BASE - t)
                .ok_or(DecodeError::Overflow)?;
            k += PUNY_BASE;
        }
        let out_len: u32 = output.len() as u32 + 1;
        bias = puny_adapt(i - old_i, out_len, old_i == 0);
        n = n.checked_add(i / out_len).ok_or(DecodeError::Overflow)?;
        i %= out_len;
        let scalar: char = char::from_u32(n).ok_or(DecodeError::Overflow)?;
        output.insert(i as usize, scalar);
        i += 1;
    }
    Ok(output.into_iter().collect())
}

pub fn punycode_decode(input: &str) -> Result<String, DecodeError> {
    input
        .strip_prefix("xn--")
        .or_else(|| input.strip_prefix("XN--"))
        .map_or_else(|| Ok(input.to_owned()), punycode_decode_label)
}

const fn puny_threshold(k: u32, bias: u32) -> u32 {
    if k <= bias + PUNY_TMIN {
        PUNY_TMIN
    } else if k >= bias + PUNY_TMAX {
        PUNY_TMAX
    } else {
        k - bias
    }
}

const fn puny_adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
    delta = if first_time {
        delta / PUNY_DAMP
    } else {
        delta / 2
    };
    delta += delta / num_points;
    let mut k: u32 = 0;
    while delta > (PUNY_BASE - PUNY_TMIN) * PUNY_TMAX / 2 {
        delta /= PUNY_BASE - PUNY_TMIN;
        k += PUNY_BASE;
    }
    k + (PUNY_BASE - PUNY_TMIN + 1) * delta / (delta + PUNY_SKEW)
}

const fn puny_decode_digit(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as u32 + 26),
        b'A'..=b'Z' => Some((byte - b'A') as u32),
        b'a'..=b'z' => Some((byte - b'a') as u32),
        _ => None,
    }
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn percent_roundtrip() {
        let plain: &[u8] = b"a b/c?d=e&f%g+h";
        let encoded: String = percent_encode(plain);
        assert_eq!(percent_decode(encoded.as_bytes()).unwrap(), plain);
    }

    #[test]
    fn percent_known_vector_and_plus() {
        assert_eq!(percent_decode(b"%2Fpath%20here").unwrap(), b"/path here");
        assert_eq!(percent_decode(b"a+b").unwrap(), b"a b");
    }

    #[test]
    fn percent_rejects_truncated_escape() {
        assert!(matches!(
            percent_decode(b"%4"),
            Err(DecodeError::BadLength { .. })
        ));
        assert!(matches!(
            percent_decode(b"%zz"),
            Err(DecodeError::InvalidSymbol { .. })
        ));
    }

    #[test]
    fn html_numeric_and_named() {
        assert_eq!(html_entity_decode("&#65;&#x42;C").unwrap(), "ABC");
        assert_eq!(
            html_entity_decode("Tom &amp; Jerry &lt;3 &#x2764;").unwrap(),
            "Tom & Jerry <3 \u{2764}"
        );
        assert_eq!(
            html_entity_decode("&unknown; stays").unwrap(),
            "&unknown; stays"
        );
    }

    #[test]
    fn html_entity_decode_preserves_utf8_text() {
        assert_eq!(
            html_entity_decode("\u{e9} &amp; \u{96ea}").unwrap(),
            "\u{e9} & \u{96ea}"
        );
    }

    #[test]
    fn punycode_rfc3492_vectors() {
        assert_eq!(
            punycode_decode("xn--nxasmq6b").unwrap(),
            "\u{3b2}\u{3cc}\u{3bb}\u{3bf}\u{3c3}"
        );
        assert_eq!(punycode_decode("xn--bcher-kva").unwrap(), "b\u{fc}cher");
        assert_eq!(punycode_decode("xn--mnchen-3ya").unwrap(), "m\u{fc}nchen");
    }

    #[test]
    fn punycode_passthrough_without_prefix() {
        assert_eq!(punycode_decode("example").unwrap(), "example");
    }
}
