use super::DecodeError;

pub const LOWER: &[u8; 16] = b"0123456789abcdef";

const INVALID_NIBBLE: u8 = 0xff;

const NIBBLES: [u8; 256] = nibble_table();

const fn nibble_table() -> [u8; 256] {
    let mut table: [u8; 256] = [INVALID_NIBBLE; 256];
    let mut index: usize = 0;
    while index < table.len() {
        let symbol: u8 = index as u8;
        table[index] = match symbol {
            b'0'..=b'9' => symbol - b'0',
            b'a'..=b'f' => symbol - b'a' + 10,
            b'A'..=b'F' => symbol - b'A' + 10,
            _ => INVALID_NIBBLE,
        };
        index += 1;
    }
    table
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OddTail {
    Reject,
    Truncate,
    PadHigh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HexDecodeOptions {
    pub skip_whitespace: bool,
    pub odd_tail: OddTail,
    pub allow_empty: bool,
    pub max_input_bytes: Option<usize>,
}

impl HexDecodeOptions {
    #[inline]
    #[must_use]
    pub const fn with_max_input_bytes(self, max_input_bytes: usize) -> Self {
        Self {
            max_input_bytes: Some(max_input_bytes),
            ..self
        }
    }

    #[inline]
    #[must_use]
    pub const fn with_odd_tail(self, odd_tail: OddTail) -> Self {
        Self { odd_tail, ..self }
    }
}

impl Default for HexDecodeOptions {
    #[inline]
    fn default() -> Self {
        STRICT
    }
}

pub const STRICT: HexDecodeOptions = HexDecodeOptions {
    skip_whitespace: false,
    odd_tail: OddTail::Reject,
    allow_empty: true,
    max_input_bytes: None,
};

pub const TOKEN: HexDecodeOptions = HexDecodeOptions {
    skip_whitespace: false,
    odd_tail: OddTail::Reject,
    allow_empty: false,
    max_input_bytes: None,
};

pub const TRUNCATING: HexDecodeOptions = HexDecodeOptions {
    skip_whitespace: false,
    odd_tail: OddTail::Truncate,
    allow_empty: true,
    max_input_bytes: None,
};

pub const WRAPPED_STREAM: HexDecodeOptions = HexDecodeOptions {
    skip_whitespace: true,
    odd_tail: OddTail::Reject,
    allow_empty: true,
    max_input_bytes: None,
};

pub const WRAPPED_STREAM_NONEMPTY: HexDecodeOptions = HexDecodeOptions {
    skip_whitespace: true,
    odd_tail: OddTail::Reject,
    allow_empty: false,
    max_input_bytes: None,
};

#[inline]
#[must_use]
pub const fn nibble(symbol: u8) -> Option<u8> {
    let value: u8 = NIBBLES[symbol as usize];
    if value == INVALID_NIBBLE {
        None
    } else {
        Some(value)
    }
}

#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        push_byte(&mut out, byte);
    }
    out
}

pub fn push_byte(out: &mut String, byte: u8) {
    out.push(LOWER[usize::from(byte >> 4)] as char);
    out.push(LOWER[usize::from(byte & 0x0f)] as char);
}

pub fn push_fixed(out: &mut String, value: u32, digits: usize) {
    for nibble_index in (0..digits).rev() {
        let shift: u32 = (nibble_index as u32).saturating_mul(4);
        let index: usize = ((value >> shift) & 0x0f) as usize;
        out.push(LOWER[index] as char);
    }
}

pub fn decode(input: &str) -> Result<Vec<u8>, DecodeError> {
    decode_with(input.as_bytes(), STRICT)
}

pub fn decode_bytes(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode_with(input, STRICT)
}

pub fn decode_str_with(input: &str, options: HexDecodeOptions) -> Result<Vec<u8>, DecodeError> {
    decode_with(input.as_bytes(), options)
}

pub fn decode_with(input: &[u8], options: HexDecodeOptions) -> Result<Vec<u8>, DecodeError> {
    if let Some(cap) = options.max_input_bytes
        && input.len() > cap
    {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let digits: usize = if options.skip_whitespace {
        input
            .iter()
            .filter(|byte: &&u8| !byte.is_ascii_whitespace())
            .count()
    } else {
        input.len()
    };
    if digits == 0 {
        return if options.allow_empty {
            Ok(Vec::new())
        } else {
            Err(DecodeError::BadLength { len: digits })
        };
    }
    let odd: bool = !digits.is_multiple_of(2);
    if odd && matches!(options.odd_tail, OddTail::Reject) {
        return Err(DecodeError::BadLength { len: digits });
    }
    let pairs: usize = digits / 2;
    let capacity: usize = if odd && matches!(options.odd_tail, OddTail::PadHigh) {
        pairs + 1
    } else {
        pairs
    };
    let drop_tail_at: Option<usize> = if odd && matches!(options.odd_tail, OddTail::Truncate) {
        Some(digits - 1)
    } else {
        None
    };
    let mut out: Vec<u8> = Vec::with_capacity(capacity);
    let mut pending: Option<u8> = None;
    let mut seen: usize = 0;
    for &symbol in input {
        if options.skip_whitespace && symbol.is_ascii_whitespace() {
            continue;
        }
        if drop_tail_at == Some(seen) {
            break;
        }
        seen += 1;
        let value: u8 = NIBBLES[usize::from(symbol)];
        if value == INVALID_NIBBLE {
            return Err(DecodeError::InvalidSymbol { symbol });
        }
        match pending.take() {
            Some(high) => out.push((high << 4) | value),
            None => pending = Some(value),
        }
    }
    if let Some(high) = pending {
        out.push(high << 4);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        HexDecodeOptions, OddTail, STRICT, TOKEN, TRUNCATING, WRAPPED_STREAM,
        WRAPPED_STREAM_NONEMPTY, decode, decode_str_with, decode_with, encode, push_fixed,
    };
    use crate::codec::DecodeError;

    #[test]
    fn encode_is_lowercase_and_round_trips() {
        let raw: [u8; 5] = [0x00, 0x0f, 0xa5, 0xff, 0x10];
        let text: String = encode(&raw);
        assert_eq!(text, "000fa5ff10");
        assert_eq!(decode(&text).unwrap(), raw);
    }

    #[test]
    fn decode_rejects_odd_length_and_bad_symbol() {
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
        assert_eq!(decode("DEADbeef").unwrap(), [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn nibble_decodes_every_case_and_rejects_non_hex_bytes() {
        assert_eq!(super::nibble(b'0'), Some(0));
        assert_eq!(super::nibble(b'9'), Some(9));
        assert_eq!(super::nibble(b'a'), Some(10));
        assert_eq!(super::nibble(b'f'), Some(15));
        assert_eq!(super::nibble(b'A'), Some(10));
        assert_eq!(super::nibble(b'F'), Some(15));
        assert_eq!(super::nibble(b'g'), None);
        assert_eq!(super::nibble(b'G'), None);
        assert_eq!(super::nibble(b' '), None);
        assert_eq!(super::nibble(0x00), None);
        assert_eq!(super::nibble(0xff), None);
    }

    #[test]
    fn push_fixed_emits_requested_width() {
        let mut out: String = String::new();
        push_fixed(&mut out, 0x1a2b, 4);
        assert_eq!(out, "1a2b");
    }

    #[test]
    fn strict_profile_keeps_the_shipped_policy() {
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(
            decode("abc").unwrap_err(),
            DecodeError::BadLength { len: 3 }
        );
        assert_eq!(
            decode("a b").unwrap_err(),
            DecodeError::BadLength { len: 3 }
        );
        assert_eq!(
            decode(" ab ").unwrap_err(),
            DecodeError::InvalidSymbol { symbol: b' ' }
        );
        assert_eq!(
            decode("g0").unwrap_err(),
            DecodeError::InvalidSymbol { symbol: b'g' }
        );
        assert_eq!(
            decode("\u{ff10}0").unwrap_err(),
            DecodeError::InvalidSymbol { symbol: 0xef }
        );
        assert_eq!(decode("aA").unwrap(), [0xaa]);
    }

    #[test]
    fn token_profile_refuses_empty_and_single_digit_input() {
        assert_eq!(
            decode_str_with("", TOKEN).unwrap_err(),
            DecodeError::BadLength { len: 0 }
        );
        assert_eq!(
            decode_str_with("a", TOKEN).unwrap_err(),
            DecodeError::BadLength { len: 1 }
        );
        assert_eq!(decode_str_with("ab", TOKEN).unwrap(), [0xab]);
        assert_eq!(
            decode_str_with("a b", TOKEN).unwrap_err(),
            DecodeError::BadLength { len: 3 }
        );
    }

    #[test]
    fn truncating_profile_drops_the_odd_tail_without_inspecting_it() {
        assert_eq!(decode_str_with("abc", TRUNCATING).unwrap(), [0xab]);
        assert_eq!(decode_str_with("abz", TRUNCATING).unwrap(), [0xab]);
        assert_eq!(decode_str_with("a", TRUNCATING).unwrap(), Vec::<u8>::new());
        assert_eq!(decode_str_with("", TRUNCATING).unwrap(), Vec::<u8>::new());
        assert_eq!(
            decode_str_with("azc", TRUNCATING).unwrap_err(),
            DecodeError::InvalidSymbol { symbol: b'z' }
        );
    }

    #[test]
    fn pad_high_profile_promotes_the_lone_digit_to_the_high_nibble() {
        let options: HexDecodeOptions = STRICT.with_odd_tail(OddTail::PadHigh);
        assert_eq!(decode_str_with("abc", options).unwrap(), [0xab, 0xc0]);
        assert_eq!(decode_str_with("d", options).unwrap(), [0xd0]);
        assert_eq!(
            decode_str_with("abz", options).unwrap_err(),
            DecodeError::InvalidSymbol { symbol: b'z' }
        );
    }

    #[test]
    fn wrapped_stream_profile_skips_every_ascii_whitespace_form() {
        assert_eq!(
            decode_str_with("de ad\tbe\r\nef", WRAPPED_STREAM).unwrap(),
            [0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(decode_str_with("a b", WRAPPED_STREAM).unwrap(), [0xab]);
        assert_eq!(
            decode_str_with("   ", WRAPPED_STREAM).unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(
            decode_str_with("abc", WRAPPED_STREAM).unwrap_err(),
            DecodeError::BadLength { len: 3 }
        );
    }

    #[test]
    fn wrapped_stream_nonempty_profile_refuses_an_all_whitespace_input() {
        assert_eq!(
            decode_str_with(" \t\r\n", WRAPPED_STREAM_NONEMPTY).unwrap_err(),
            DecodeError::BadLength { len: 0 }
        );
        assert_eq!(
            decode_str_with("", WRAPPED_STREAM_NONEMPTY).unwrap_err(),
            DecodeError::BadLength { len: 0 }
        );
        assert_eq!(
            decode_str_with("ab cd", WRAPPED_STREAM_NONEMPTY).unwrap(),
            [0xab, 0xcd]
        );
    }

    #[test]
    fn a_size_cap_refuses_before_allocating() {
        let options: HexDecodeOptions = STRICT.with_max_input_bytes(8);
        assert_eq!(
            decode_str_with("aabbccdd", options).unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd]
        );
        assert_eq!(
            decode_str_with("aabbccddee", options).unwrap_err(),
            DecodeError::TooLarge { len: 10 }
        );
        let capped: HexDecodeOptions = WRAPPED_STREAM.with_max_input_bytes(4);
        assert_eq!(
            decode_str_with("ab cd", capped).unwrap_err(),
            DecodeError::TooLarge { len: 5 }
        );
    }

    #[test]
    fn a_megabyte_blob_decodes_without_an_overflow_or_a_reallocation_storm() {
        let text: String = "a0".repeat(1 << 19);
        let decoded: Vec<u8> = decode(&text).unwrap();
        assert_eq!(decoded.len(), 1 << 19);
        assert!(decoded.iter().all(|byte: &u8| *byte == 0xa0));
    }

    #[test]
    fn a_high_byte_and_a_nul_are_rejected_as_symbols() {
        assert_eq!(
            decode_with(&[0x00, b'0'], STRICT).unwrap_err(),
            DecodeError::InvalidSymbol { symbol: 0x00 }
        );
        assert_eq!(
            decode_with(&[0x80, b'0'], STRICT).unwrap_err(),
            DecodeError::InvalidSymbol { symbol: 0x80 }
        );
        assert_eq!(
            decode_with(&[0xff, b'0'], STRICT).unwrap_err(),
            DecodeError::InvalidSymbol { symbol: 0xff }
        );
    }

    fn reference(input: &[u8], options: HexDecodeOptions) -> Result<Vec<u8>, DecodeError> {
        if let Some(cap) = options.max_input_bytes
            && input.len() > cap
        {
            return Err(DecodeError::TooLarge { len: input.len() });
        }
        let kept: Vec<u8> = input
            .iter()
            .copied()
            .filter(|byte: &u8| !options.skip_whitespace || !byte.is_ascii_whitespace())
            .collect();
        if kept.is_empty() {
            return if options.allow_empty {
                Ok(Vec::new())
            } else {
                Err(DecodeError::BadLength { len: 0 })
            };
        }
        let odd: bool = !kept.len().is_multiple_of(2);
        let usable: &[u8] = match options.odd_tail {
            OddTail::Reject if odd => {
                return Err(DecodeError::BadLength { len: kept.len() });
            }
            OddTail::Truncate if odd => &kept[..kept.len() - 1],
            _ => kept.as_slice(),
        };
        let mut out: Vec<u8> = Vec::new();
        let mut pending: Option<u8> = None;
        for &symbol in usable {
            let value: u8 = match symbol {
                b'0'..=b'9' => symbol - b'0',
                b'a'..=b'f' => symbol - b'a' + 10,
                b'A'..=b'F' => symbol - b'A' + 10,
                other => return Err(DecodeError::InvalidSymbol { symbol: other }),
            };
            match pending.take() {
                Some(high) => out.push((high << 4) | value),
                None => pending = Some(value),
            }
        }
        if let Some(high) = pending {
            out.push(high << 4);
        }
        Ok(out)
    }

    fn nibble(symbol: u8) -> Option<u8> {
        match symbol {
            b'0'..=b'9' => Some(symbol - b'0'),
            b'a'..=b'f' => Some(symbol - b'a' + 10),
            b'A'..=b'F' => Some(symbol - b'A' + 10),
            _ => None,
        }
    }

    fn shipped_token_policy(input: &[u8]) -> Option<Vec<u8>> {
        if input.len() < 2
            || !input.len().is_multiple_of(2)
            || !input.iter().all(|byte: &u8| byte.is_ascii_hexdigit())
        {
            return None;
        }
        let mut out: Vec<u8> = Vec::with_capacity(input.len() / 2);
        let mut at: usize = 0;
        while at < input.len() {
            out.push((nibble(input[at])? << 4) | nibble(input[at + 1])?);
            at += 2;
        }
        Some(out)
    }

    fn shipped_truncating_policy(input: &[u8]) -> Option<Vec<u8>> {
        let mut out: Vec<u8> = Vec::with_capacity(input.len() / 2);
        let mut at: usize = 0;
        while at + 1 < input.len() {
            out.push((nibble(input[at])? << 4) | nibble(input[at + 1])?);
            at += 2;
        }
        Some(out)
    }

    fn shipped_wrapped_stream_policy(input: &[u8], allow_empty: bool) -> Option<Vec<u8>> {
        let clean: Vec<u8> = input
            .iter()
            .copied()
            .filter(|byte: &u8| !byte.is_ascii_whitespace())
            .collect();
        if !allow_empty && clean.is_empty() {
            return None;
        }
        if !clean.len().is_multiple_of(2) {
            return None;
        }
        let mut out: Vec<u8> = Vec::with_capacity(clean.len() / 2);
        for pair in clean.chunks_exact(2) {
            out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
        }
        Some(out)
    }

    #[test]
    fn each_profile_reproduces_the_policy_it_replaces() {
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"abc",
            b"abz",
            b"zz",
            b" ",
            b"   ",
            b"\t\r\n",
            b"a b",
            b"ab cd",
            b"de ad\tbe\r\nef",
            b" ab ",
            b"AbCdEf",
            b"\x00\x30",
            b"\xff0",
            b"0123456789abcdefABCDEF",
        ];
        for &case in cases {
            assert_eq!(
                decode_with(case, TOKEN).ok(),
                shipped_token_policy(case),
                "token profile diverged on {case:?}"
            );
            assert_eq!(
                decode_with(case, TRUNCATING).ok(),
                shipped_truncating_policy(case),
                "truncating profile diverged on {case:?}"
            );
            assert_eq!(
                decode_with(case, WRAPPED_STREAM).ok(),
                shipped_wrapped_stream_policy(case, true),
                "wrapped-stream profile diverged on {case:?}"
            );
            assert_eq!(
                decode_with(case, WRAPPED_STREAM_NONEMPTY).ok(),
                shipped_wrapped_stream_policy(case, false),
                "non-empty wrapped-stream profile diverged on {case:?}"
            );
        }
    }

    #[test]
    fn every_profile_matches_a_reference_decoder_over_random_bytes() {
        const PROFILES: &[HexDecodeOptions] = &[
            STRICT,
            TOKEN,
            TRUNCATING,
            WRAPPED_STREAM,
            WRAPPED_STREAM_NONEMPTY,
        ];
        let pad_high: HexDecodeOptions = STRICT.with_odd_tail(OddTail::PadHigh);
        let skip_pad_high: HexDecodeOptions = WRAPPED_STREAM.with_odd_tail(OddTail::PadHigh);
        let alphabet: &[u8] = b"0123456789abcdefABCDEF \t\r\n:-xX\0\x7f\x80\xffg";
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        for case in 0..4_000u32 {
            let len: usize = (case as usize) % 17;
            let mut input: Vec<u8> = Vec::with_capacity(len);
            for _ in 0..len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let pick: usize = ((state >> 33) as usize) % (alphabet.len() + 1);
                input.push(alphabet.get(pick).copied().unwrap_or((state >> 17) as u8));
            }
            for options in PROFILES.iter().copied().chain([
                pad_high,
                skip_pad_high,
                STRICT.with_max_input_bytes(8),
            ]) {
                assert_eq!(
                    decode_with(&input, options),
                    reference(&input, options),
                    "profile {options:?} disagreed on {input:?}"
                );
            }
        }
    }
}
