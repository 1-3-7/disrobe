//! Radix-alphabet decoders: base58 (bitcoin + ripple), base62, base45 (RFC 9285), base91 (basE91), and base92.

use super::{DecodeError, bytes_to_string};

const BASE58_BITCOIN: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_RIPPLE: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
const BASE62_STANDARD: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE45_ALPHABET: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
const BASE91_ALPHABET: &[u8; 91] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";
const BASE92_ALPHABET: &[u8; 91] =
    b"!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}";

const MAX_RADIX_INPUT: usize = 1 << 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base58Variant {
    Bitcoin,
    Ripple,
}

#[must_use]
const fn invert(alphabet: &[u8], len: usize) -> [i16; 256] {
    let mut table: [i16; 256] = [-1; 256];
    let mut i: usize = 0;
    while i < len {
        table[alphabet[i] as usize] = i as i16;
        i += 1;
    }
    table
}

fn decode_baseradix(input: &[u8], alphabet: &[u8], radix: u16) -> Result<Vec<u8>, DecodeError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() > MAX_RADIX_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let table: [i16; 256] = invert(alphabet, alphabet.len());
    let leading_zero_byte: u8 = alphabet[0];
    let mut leading_zeros: usize = 0;
    for &b in input {
        if b == leading_zero_byte {
            leading_zeros += 1;
        } else {
            break;
        }
    }
    let cap: usize = input
        .len()
        .saturating_mul(733)
        .checked_div(1000)
        .unwrap_or(input.len())
        .saturating_add(1);
    let mut buffer: Vec<u8> = Vec::with_capacity(cap.min(MAX_RADIX_INPUT));
    for &symbol in &input[leading_zeros..] {
        let digit: i16 = table[symbol as usize];
        if digit < 0 {
            return Err(DecodeError::InvalidSymbol { symbol });
        }
        let mut carry: u32 = digit as u32;
        for byte in &mut buffer {
            let value: u32 = (*byte as u32) * (radix as u32) + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            buffer.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(leading_zeros + buffer.len());
    out.resize(leading_zeros, 0);
    out.extend(buffer.iter().rev().copied());
    Ok(out)
}

fn encode_baseradix(input: &[u8], alphabet: &[u8], radix: u16) -> String {
    if input.is_empty() {
        return String::new();
    }
    let leading_zeros: usize = input.iter().take_while(|&&b: &&u8| b == 0).count();
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 2);
    for &byte in &input[leading_zeros..] {
        let mut carry: u32 = byte as u32;
        for digit in &mut digits {
            let value: u32 = (*digit as u32) * 256 + carry;
            *digit = (value % radix as u32) as u8;
            carry = value / radix as u32;
        }
        while carry > 0 {
            digits.push((carry % radix as u32) as u8);
            carry /= radix as u32;
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        out.push(alphabet[0]);
    }
    for &digit in digits.iter().rev() {
        out.push(alphabet[digit as usize]);
    }
    bytes_to_string(out)
}

/// Decode a base58 string in the given variant.
pub fn base58_decode(input: &[u8], variant: Base58Variant) -> Result<Vec<u8>, DecodeError> {
    let alphabet: &[u8; 58] = match variant {
        Base58Variant::Bitcoin => BASE58_BITCOIN,
        Base58Variant::Ripple => BASE58_RIPPLE,
    };
    decode_baseradix(input, alphabet, 58)
}

/// Encode bytes to a base58 string in the given variant.
#[must_use]
pub fn base58_encode(input: &[u8], variant: Base58Variant) -> String {
    let alphabet: &[u8; 58] = match variant {
        Base58Variant::Bitcoin => BASE58_BITCOIN,
        Base58Variant::Ripple => BASE58_RIPPLE,
    };
    encode_baseradix(input, alphabet, 58)
}

/// Decode a base62 string.
pub fn base62_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode_baseradix(input, BASE62_STANDARD, 62)
}

/// Encode bytes to a base62 string.
#[must_use]
pub fn base62_encode(input: &[u8]) -> String {
    encode_baseradix(input, BASE62_STANDARD, 62)
}

/// Decode a base45 string per RFC 9285.
pub fn base45_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() > MAX_RADIX_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    if input.len() % 3 == 1 {
        return Err(DecodeError::BadLength { len: input.len() });
    }
    let table: [i16; 256] = invert(BASE45_ALPHABET, BASE45_ALPHABET.len());
    let mut out: Vec<u8> = Vec::with_capacity(input.len() / 3 * 2 + 1);
    for chunk in input.chunks(3) {
        let mut value: u32 = 0;
        let mut weight: u32 = 1;
        for &symbol in chunk {
            let digit: i16 = table[symbol as usize];
            if digit < 0 {
                return Err(DecodeError::InvalidSymbol { symbol });
            }
            value += digit as u32 * weight;
            weight *= 45;
        }
        if chunk.len() == 3 {
            if value > 0xffff {
                return Err(DecodeError::Overflow);
            }
            out.push((value >> 8) as u8);
        } else if value > 0xff {
            return Err(DecodeError::Overflow);
        }
        out.push((value & 0xff) as u8);
    }
    Ok(out)
}

/// Encode bytes to a base45 string per RFC 9285.
#[must_use]
pub fn base45_encode(input: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() / 2 * 3 + 2);
    for chunk in input.chunks(2) {
        if chunk.len() == 2 {
            let value: u32 = (chunk[0] as u32) << 8 | chunk[1] as u32;
            out.push(BASE45_ALPHABET[(value % 45) as usize]);
            out.push(BASE45_ALPHABET[(value / 45 % 45) as usize]);
            out.push(BASE45_ALPHABET[(value / 2025) as usize]);
        } else {
            let value: u32 = chunk[0] as u32;
            out.push(BASE45_ALPHABET[(value % 45) as usize]);
            out.push(BASE45_ALPHABET[(value / 45) as usize]);
        }
    }
    bytes_to_string(out)
}

/// Decode a basE91 string.
pub fn base91_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() > MAX_RADIX_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let table: [i16; 256] = invert(BASE91_ALPHABET, BASE91_ALPHABET.len());
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 7 / 8 + 1);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut value: i32 = -1;
    for &symbol in input {
        let digit: i16 = table[symbol as usize];
        if digit < 0 {
            return Err(DecodeError::InvalidSymbol { symbol });
        }
        if value < 0 {
            value = digit as i32;
        } else {
            let combined: u32 = value as u32 + (digit as u32) * 91;
            accumulator |= combined << bits;
            bits += if combined & 8191 > 88 { 13 } else { 14 };
            while bits >= 8 {
                out.push((accumulator & 0xff) as u8);
                accumulator >>= 8;
                bits -= 8;
            }
            value = -1;
        }
    }
    if value >= 0 {
        accumulator |= (value as u32) << bits;
        out.push((accumulator & 0xff) as u8);
    }
    Ok(out)
}

/// Encode bytes to a basE91 string.
#[must_use]
pub fn base91_encode(input: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 8 / 6 + 2);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in input {
        accumulator |= (byte as u32) << bits;
        bits += 8;
        if bits > 13 {
            let mut value: u32 = accumulator & 8191;
            if value > 88 {
                accumulator >>= 13;
                bits -= 13;
            } else {
                value = accumulator & 16383;
                accumulator >>= 14;
                bits -= 14;
            }
            out.push(BASE91_ALPHABET[(value % 91) as usize]);
            out.push(BASE91_ALPHABET[(value / 91) as usize]);
        }
    }
    if bits > 0 {
        out.push(BASE91_ALPHABET[(accumulator % 91) as usize]);
        if bits > 7 || accumulator > 90 {
            out.push(BASE91_ALPHABET[(accumulator / 91) as usize]);
        }
    }
    bytes_to_string(out)
}

/// Decode a base92 string.
pub fn base92_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input == b"~" {
        return Ok(Vec::new());
    }
    if input.len() > MAX_RADIX_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let table: [i16; 256] = invert(BASE92_ALPHABET, BASE92_ALPHABET.len());
    let mut bitstream: Vec<u8> = Vec::with_capacity(input.len() * 13 / 8 + 1);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut pending: Option<u16> = None;
    for &symbol in input {
        let digit: i16 = table[symbol as usize];
        if digit < 0 {
            return Err(DecodeError::InvalidSymbol { symbol });
        }
        match pending.take() {
            None => pending = Some(digit as u16),
            Some(high) => {
                let combined: u32 = high as u32 * 91 + digit as u32;
                accumulator = (accumulator << 13) | combined;
                bits += 13;
                while bits >= 8 {
                    bits -= 8;
                    bitstream.push(((accumulator >> bits) & 0xff) as u8);
                }
            }
        }
    }
    if let Some(last) = pending {
        let value: u32 = last as u32;
        let width: u32 = if value == 0 {
            6
        } else {
            (32 - value.leading_zeros()).max(6)
        };
        accumulator = (accumulator << width) | value;
        bits += width;
        while bits >= 8 {
            bits -= 8;
            bitstream.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    Ok(bitstream)
}

/// Encode bytes to a base92 string.
#[must_use]
pub fn base92_encode(input: &[u8]) -> String {
    if input.is_empty() {
        return "~".to_owned();
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 8 / 13 * 2 + 2);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in input {
        accumulator = (accumulator << 8) | byte as u32;
        bits += 8;
        while bits >= 13 {
            bits -= 13;
            let value: u32 = (accumulator >> bits) & 0x1fff;
            out.push(BASE92_ALPHABET[(value / 91) as usize]);
            out.push(BASE92_ALPHABET[(value % 91) as usize]);
        }
    }
    if bits > 0 {
        let value: u32 = (accumulator << (13 - bits)) & 0x1fff;
        out.push(BASE92_ALPHABET[(value / 91) as usize]);
        if bits > 6 {
            out.push(BASE92_ALPHABET[(value % 91) as usize]);
        }
    }
    bytes_to_string(out)
}

const BASE122_ILLEGALS: [u8; 6] = [0, 10, 13, 34, 38, 92];

fn base122_push7(seven: u8, out: &mut Vec<u8>, cur: &mut u32, bit: &mut u32) {
    let shifted: u32 = (seven as u32) << 1;
    *cur |= shifted >> *bit;
    *bit += 7;
    if *bit >= 8 {
        out.push((*cur & 0xFF) as u8);
        *bit -= 8;
        *cur = (shifted << (7 - *bit)) & 0xFF;
    }
}

pub fn base122_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() > MAX_RADIX_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut cur: u32 = 0;
    let mut bit: u32 = 0;
    let mut i: usize = 0;
    while i < input.len() {
        let lead: u8 = input[i];
        if lead < 0x80 {
            base122_push7(lead, &mut out, &mut cur, &mut bit);
            i += 1;
        } else if lead & 0xE0 == 0xC0 {
            let Some(&cont) = input.get(i + 1) else {
                return Err(DecodeError::BadLength { len: input.len() });
            };
            if cont & 0xC0 != 0x80 {
                return Err(DecodeError::InvalidSymbol { symbol: cont });
            }
            let cp: u32 = (((lead & 0x1F) as u32) << 6) | ((cont & 0x3F) as u32);
            let illegal_index: usize = ((cp >> 8) & 7) as usize;
            if illegal_index != 7 {
                let Some(&illegal) = BASE122_ILLEGALS.get(illegal_index) else {
                    return Err(DecodeError::InvalidSymbol { symbol: lead });
                };
                base122_push7(illegal, &mut out, &mut cur, &mut bit);
            }
            base122_push7((cp & 0x7F) as u8, &mut out, &mut cur, &mut bit);
            i += 2;
        } else {
            return Err(DecodeError::InvalidSymbol { symbol: lead });
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn base58_bitcoin_known_vectors() {
        assert_eq!(
            base58_encode(b"Hello World!", Base58Variant::Bitcoin),
            "2NEpo7TZRRrLZSi2U"
        );
        assert_eq!(
            base58_decode(b"2NEpo7TZRRrLZSi2U", Base58Variant::Bitcoin).unwrap(),
            b"Hello World!"
        );
        assert_eq!(
            base58_encode(&[0x00, 0x00, 0x01], Base58Variant::Bitcoin),
            "112"
        );
        assert_eq!(
            base58_decode(b"112", Base58Variant::Bitcoin).unwrap(),
            vec![0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn base58_ripple_roundtrip() {
        let data: &[u8] = b"ripple address payload";
        let encoded: String = base58_encode(data, Base58Variant::Ripple);
        assert_eq!(
            base58_decode(encoded.as_bytes(), Base58Variant::Ripple).unwrap(),
            data
        );
    }

    #[test]
    fn base58_rejects_out_of_alphabet() {
        assert!(matches!(
            base58_decode(b"0OIl", Base58Variant::Bitcoin),
            Err(DecodeError::InvalidSymbol { .. })
        ));
    }

    #[test]
    fn base62_roundtrip_and_leading_zeros() {
        let data: &[u8] = &[0x00, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let encoded: String = base62_encode(data);
        assert_eq!(base62_decode(encoded.as_bytes()).unwrap(), data);
    }

    #[test]
    fn base45_rfc9285_known_vectors() {
        assert_eq!(base45_encode(b"AB"), "BB8");
        assert_eq!(base45_encode(b"Hello!!"), "%69 VD92EX0");
        assert_eq!(base45_encode(b"base-45"), "UJCLQE7W581");
        assert_eq!(base45_decode(b"BB8").unwrap(), b"AB");
        assert_eq!(base45_decode(b"%69 VD92EX0").unwrap(), b"Hello!!");
        assert_eq!(base45_decode(b"UJCLQE7W581").unwrap(), b"base-45");
    }

    #[test]
    fn base45_rejects_single_trailing_char() {
        assert!(matches!(
            base45_decode(b"BB8B"),
            Err(DecodeError::BadLength { .. })
        ));
    }

    #[test]
    fn base91_known_vector() {
        assert_eq!(base91_encode(b"test"), "fPNKd");
        assert_eq!(base91_decode(b"fPNKd").unwrap(), b"test");
    }

    #[test]
    fn base91_roundtrip_binary() {
        let data: Vec<u8> = (0u16..=255).map(|b: u16| b as u8).collect();
        let encoded: String = base91_encode(&data);
        assert_eq!(base91_decode(encoded.as_bytes()).unwrap(), data);
    }

    #[test]
    fn base92_known_vectors() {
        assert_eq!(base92_encode(b""), "~");
        assert_eq!(base92_encode(b"a"), "D,");
        assert_eq!(base92_encode(b"AB"), "8y8");
        assert_eq!(base92_encode(b"abc"), "D8<q");
        assert_eq!(base92_encode(b"hello"), "Fc_$aOO");
        assert_eq!(
            base92_encode(b"hello, base92 world"),
            "Fc_$aOVi$0gRoGis-Gv^iw3W"
        );
        assert_eq!(base92_decode(b"~").unwrap(), b"");
        assert_eq!(base92_decode(b"D,").unwrap(), b"a");
        assert_eq!(base92_decode(b"Fc_$aOO").unwrap(), b"hello");
    }

    #[test]
    fn base92_roundtrip() {
        let full: Vec<u8> = (0u16..=255).map(|b: u16| b as u8).collect();
        let samples: [&[u8]; 6] = [b"", b"a", b"ab", b"abc", b"hello, base92 world", &full];
        for sample in samples {
            let encoded: String = base92_encode(sample);
            assert_eq!(
                base92_decode(encoded.as_bytes()).unwrap(),
                sample,
                "{sample:?}"
            );
        }
    }

    #[test]
    fn radix_decoders_bound_input() {
        let huge: Vec<u8> = vec![b'1'; MAX_RADIX_INPUT + 1];
        assert!(matches!(
            base58_decode(&huge, Base58Variant::Bitcoin),
            Err(DecodeError::TooLarge { .. })
        ));
    }

    #[test]
    fn base122_decodes_independent_reference_vectors() {
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i: usize| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let all_bytes: Vec<u8> = (0u16..256).map(|b: u16| b as u8).collect();
        let big: &str = "c28020201810c68603420110502c18ca870362010848d294c78542714064341b0e07236179c382ce91490452311c502915c7a54269385e30184c463321546c371c0e272359707a3e1f50081412ca8845231169044a29164cd3934975024524532a152a653a61325a2d570b55727d406131186c462b194e68345a4d366335d7af381c2e271b516a763b5e0f17536d787d3f1f70080cc687044261507844d2950b462331687c42231249651259345e31194dd3b3496c7a3f205068543a25164d27542a352a5d325b2e576c161b154e69355b2d770b4d6a773c5e6f577c060705436231386c3e23134a657319d7b63f215169347a4d2e5b2f586c765b3d66773d5f70383c2e1f134b66737a1d1e572f596d773b7e0f0f4b67747a7d5e7f4767757b7e3f3f6f78";
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (Vec::new(), ""),
            (b"A".to_vec(), "2040"),
            (b"hi".to_vec(), "341a20"),
            (
                b"hello, base122 world".to_vec(),
                "34192d46633c582031182e3629446432101d6d77133148",
            ),
            (vec![0, 10, 13, 34, 38, 92], "c2824152111938"),
            (all_bytes, big),
        ];
        for (plain, enc_hex) in &cases {
            assert_eq!(
                &base122_decode(&unhex(enc_hex)).expect("decode"),
                plain,
                "vector {enc_hex}"
            );
        }
    }

    #[test]
    fn base122_decoder_bounds_input() {
        let huge: Vec<u8> = vec![b'a'; MAX_RADIX_INPUT + 1];
        assert!(matches!(
            base122_decode(&huge),
            Err(DecodeError::TooLarge { .. })
        ));
    }
}
