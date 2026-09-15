use super::DecodeError;
use super::hex::nibble as hex_value;

const PUNY_BASE: u32 = 36;
const PUNY_TMIN: u32 = 1;
const PUNY_TMAX: u32 = 26;
const PUNY_SKEW: u32 = 38;
const PUNY_DAMP: u32 = 700;
const PUNY_INITIAL_BIAS: u32 = 72;
const PUNY_INITIAL_N: u32 = 128;
const MAX_WEB_INPUT: usize = 1 << 24;
const MAX_PUNYCODE_LABEL_OUTPUT: usize = 1024;
const MAX_ENTITY_NAME: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlusPolicy {
    Literal,
    Space,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PercentEncodeSet {
    additional_ascii: [u64; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PercentEncodeSetError {
    #[error("the additional unreserved set cannot contain percent")]
    Percent,
    #[error("the additional unreserved byte {byte:#04x} is not ASCII")]
    NonAscii { byte: u8 },
}

impl PercentEncodeSet {
    pub const RFC3986: Self = Self::from_additional_unchecked(b"");
    pub const SARIF_ARTIFACT_URI: Self = Self::from_additional_unchecked(b"/:");
    pub const URI: Self = Self::from_additional_unchecked(b":/?#[]@!$&'()*+,;=");
    pub const PATH_SEGMENT: Self = Self::from_additional_unchecked(b"!$&'()*+,;=:@");
    pub const QUERY_VALUE: Self = Self::from_additional_unchecked(b"!$'()*+,;:@/?");
    pub const FRAGMENT: Self = Self::from_additional_unchecked(b"!$&'()*+,;=:@/?");

    pub const fn with_additional(additional: &[u8]) -> Result<Self, PercentEncodeSetError> {
        let mut set: Self = Self::RFC3986;
        let mut index: usize = 0;
        while index < additional.len() {
            let byte: u8 = additional[index];
            if byte == b'%' {
                return Err(PercentEncodeSetError::Percent);
            }
            if byte > 0x7f {
                return Err(PercentEncodeSetError::NonAscii { byte });
            }
            set.additional_ascii[(byte >> 6) as usize] |= 1u64 << (byte & 0x3f);
            index += 1;
        }
        Ok(set)
    }

    const fn from_additional_unchecked(additional: &[u8]) -> Self {
        let mut set: Self = Self {
            additional_ascii: [0; 2],
        };
        let mut index: usize = 0;
        while index < additional.len() {
            let byte: u8 = additional[index];
            set.additional_ascii[(byte >> 6) as usize] |= 1u64 << (byte & 0x3f);
            index += 1;
        }
        set
    }

    const fn permits(self, byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (byte <= 0x7f
                && self.additional_ascii[(byte >> 6) as usize] & (1u64 << (byte & 0x3f)) != 0)
    }
}

impl Default for PercentEncodeSet {
    fn default() -> Self {
        Self::RFC3986
    }
}

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
pub fn percent_decode_lenient(input: &[u8], plus_policy: PlusPolicy) -> Vec<u8> {
    let bounded: &[u8] = &input[..input.len().min(MAX_WEB_INPUT)];
    let mut out: Vec<u8> = Vec::with_capacity(bounded.len());
    let mut i: usize = 0;
    while i < bounded.len() {
        let byte: u8 = bounded[i];
        if byte == b'%'
            && i + 2 < bounded.len()
            && let (Some(hi), Some(lo)) = (hex_value(bounded[i + 1]), hex_value(bounded[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        if matches!(plus_policy, PlusPolicy::Space) && byte == b'+' {
            out.push(b' ');
        } else {
            out.push(byte);
        }
        i += 1;
    }
    out
}

#[must_use]
pub fn percent_encode(input: &[u8], set: PercentEncodeSet) -> String {
    let mut out: String = String::with_capacity(percent_encode_capacity(input.len()));
    for byte in input {
        if set.permits(*byte) {
            out.push(char::from(*byte));
        } else {
            out.push('%');
            super::hex::push_byte_upper(&mut out, *byte);
        }
    }
    out
}

#[must_use]
pub fn percent_encode_str(input: &str, set: PercentEncodeSet) -> String {
    percent_encode(input.as_bytes(), set)
}

const fn percent_encode_capacity(input_len: usize) -> usize {
    input_len.saturating_mul(3)
}

pub fn html_entity_decode(input: &str) -> Result<String, DecodeError> {
    if input.len() > MAX_WEB_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let bytes: &[u8] = input.as_bytes();
    let mut out: String = String::with_capacity(input.len());
    let mut i: usize = 0;
    let mut next_terminator: Option<usize> = memchr::memchr(b';', bytes);
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
        while let Some(at) = next_terminator
            && at <= i
        {
            next_terminator = memchr::memchr(b';', &bytes[at + 1..]).map(|rel: usize| at + 1 + rel);
        }
        let Some(terminator) = next_terminator else {
            out.push_str(&input[i..]);
            break;
        };
        let entity: &str = &input[i + 1..terminator];
        if entity.len() <= MAX_ENTITY_NAME
            && let Some(decoded) = decode_one_entity(entity)
        {
            out.push(decoded);
            i = terminator + 1;
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
    if basic_end > MAX_PUNYCODE_LABEL_OUTPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
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
        if output.len() >= MAX_PUNYCODE_LABEL_OUTPUT {
            return Err(DecodeError::TooLarge { len: input.len() });
        }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn percent_encode_reference(input: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut output: String = String::new();
        for byte in input {
            if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
                output.push(char::from(*byte));
            } else {
                write!(&mut output, "%{byte:02X}").expect("write to String");
            }
        }
        output
    }

    #[test]
    fn percent_roundtrip() {
        let plain: &[u8] = b"a b/c?d=e&f%g+h";
        let encoded: String = percent_encode(plain, PercentEncodeSet::RFC3986);
        assert_eq!(percent_decode(encoded.as_bytes()).unwrap(), plain);
    }

    #[test]
    fn percent_encode_supports_named_and_custom_unreserved_sets() {
        let input: &[u8] = b"file:///C:/Program Files/a#b?c=%\xff";
        assert_eq!(
            percent_encode(input, PercentEncodeSet::RFC3986),
            "file%3A%2F%2F%2FC%3A%2FProgram%20Files%2Fa%23b%3Fc%3D%25%FF"
        );
        assert_eq!(
            percent_encode(input, PercentEncodeSet::SARIF_ARTIFACT_URI),
            "file:///C:/Program%20Files/a%23b%3Fc%3D%25%FF"
        );
        let custom: PercentEncodeSet = PercentEncodeSet::with_additional(b"@").unwrap();
        assert_eq!(percent_encode_str("a@b c", custom), "a@b%20c");
    }

    #[test]
    fn percent_encode_component_sets_preserve_only_their_delimiters() {
        assert_eq!(
            percent_encode_str("https://a/b?c=d#e%", PercentEncodeSet::URI),
            "https://a/b?c=d#e%25"
        );
        assert_eq!(
            percent_encode_str("a/b:c@d?e#f", PercentEncodeSet::PATH_SEGMENT),
            "a%2Fb:c@d%3Fe%23f"
        );
        assert_eq!(
            percent_encode_str("a/b?c&d=e#f", PercentEncodeSet::QUERY_VALUE),
            "a/b?c%26d%3De%23f"
        );
        assert_eq!(
            percent_encode_str("a/b?c#d", PercentEncodeSet::FRAGMENT),
            "a/b?c%23d"
        );
    }

    #[test]
    fn percent_encode_rejects_unsafe_custom_unreserved_bytes() {
        assert_eq!(
            PercentEncodeSet::with_additional(b"%"),
            Err(PercentEncodeSetError::Percent)
        );
        assert_eq!(
            PercentEncodeSet::with_additional(b"\x80"),
            Err(PercentEncodeSetError::NonAscii { byte: 0x80 })
        );
    }

    #[test]
    fn percent_encode_capacity_saturates() {
        assert_eq!(percent_encode_capacity(usize::MAX), usize::MAX);
    }

    #[test]
    fn percent_encode_matches_reference_over_deterministic_random_bytes() {
        let mut input: Vec<u8> = Vec::with_capacity(4_096);
        let mut state: u32 = 0xa341_316c;
        for length in 0usize..=4_096 {
            assert_eq!(
                percent_encode(&input, PercentEncodeSet::RFC3986),
                percent_encode_reference(&input),
                "length {length}"
            );
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            input.push((state >> 24) as u8);
        }
    }

    #[test]
    fn percent_known_vector_and_plus() {
        assert_eq!(percent_decode(b"%2Fpath%20here").unwrap(), b"/path here");
        assert_eq!(percent_decode(b"a+b").unwrap(), b"a b");
    }

    #[test]
    fn percent_lenient_toggle_and_passthrough() {
        assert_eq!(
            percent_decode_lenient(b"%2Fa+b", PlusPolicy::Space),
            b"/a b"
        );
        assert_eq!(
            percent_decode_lenient(b"%2Fa+b", PlusPolicy::Literal),
            b"/a+b"
        );
        assert_eq!(
            percent_decode_lenient(b"1e+5", PlusPolicy::Literal),
            b"1e+5"
        );
        assert_eq!(
            percent_decode_lenient(b"%zz%2", PlusPolicy::Literal),
            b"%zz%2"
        );
        assert_eq!(
            percent_decode_lenient(b"tail%2", PlusPolicy::Literal),
            b"tail%2"
        );
    }

    #[test]
    fn percent_lenient_caps_oversized_input() {
        let oversized: Vec<u8> = vec![b'+'; MAX_WEB_INPUT + 1];
        let decoded: Vec<u8> = percent_decode_lenient(&oversized, PlusPolicy::Literal);
        assert_eq!(decoded.len(), MAX_WEB_INPUT);
        assert!(decoded.iter().all(|byte: &u8| *byte == b'+'));
    }

    #[test]
    fn percent_lenient_pins_malformed_unicode_and_binary_escapes() {
        let cases: [(&[u8], &[u8]); 6] = [
            (b"%", b"%"),
            (b"%X", b"%X"),
            (b"%ZZ", b"%ZZ"),
            (b"%2X", b"%2X"),
            (b"%u0041%u{0042}", b"%u0041%u{0042}"),
            (b"%00%ff", b"\0\xff"),
        ];
        for (encoded, expected) in cases {
            assert_eq!(
                percent_decode_lenient(encoded, PlusPolicy::Literal),
                expected
            );
        }
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
    fn html_entity_scan_bounds_names_and_stops_at_an_unterminated_tail() {
        assert_eq!(html_entity_decode("&amp; &&& tail").unwrap(), "& &&& tail");
        assert_eq!(html_entity_decode("&amp;&lt;&x").unwrap(), "&<&x");
        assert_eq!(html_entity_decode("a&b;c&#65;").unwrap(), "a&b;cA");
        let long_name: String = format!("&{};", "a".repeat(MAX_ENTITY_NAME + 1));
        assert_eq!(html_entity_decode(&long_name).unwrap(), long_name);
        let padded_numeric: String = format!("&#{}65;", "0".repeat(MAX_ENTITY_NAME));
        assert_eq!(html_entity_decode(&padded_numeric).unwrap(), padded_numeric);
        let longest_named: String = format!("&{};", "a".repeat(MAX_ENTITY_NAME - 1));
        assert_eq!(html_entity_decode(&longest_named).unwrap(), longest_named);
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

    fn craft_front_insert_label(count: usize) -> String {
        fn encode_digit(value: u32) -> char {
            if value < 26 {
                (b'a' + value as u8) as char
            } else {
                (b'0' + (value - 26) as u8) as char
            }
        }
        let mut label: String = String::new();
        let mut bias: u32 = PUNY_INITIAL_BIAS;
        for step in 0..count {
            let out_len: u32 = step as u32 + 1;
            let delta: u32 = step as u32;
            let mut q: u32 = delta;
            let mut k: u32 = PUNY_BASE;
            loop {
                let t: u32 = puny_threshold(k, bias);
                if q < t {
                    label.push(encode_digit(q));
                    break;
                }
                let digit: u32 = t + (q - t) % (PUNY_BASE - t);
                label.push(encode_digit(digit));
                q = (q - t) / (PUNY_BASE - t);
                k += PUNY_BASE;
            }
            bias = puny_adapt(delta, out_len, step == 0);
        }
        label
    }

    #[test]
    fn punycode_front_insert_flood_fails_closed_and_fast() {
        let payload: String = craft_front_insert_label(40_000);
        let label: String = format!("xn--{payload}");
        let start: std::time::Instant = std::time::Instant::now();
        let result: Result<String, DecodeError> = punycode_decode(&label);
        let elapsed: std::time::Duration = start.elapsed();
        assert!(
            matches!(result, Err(DecodeError::TooLarge { .. })),
            "over-long punycode must fail closed, got {result:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "capped decode must return quickly, took {elapsed:?}"
        );
    }

    #[test]
    fn punycode_cap_preserves_valid_labels() {
        assert_eq!(punycode_decode("xn--mnchen-3ya").unwrap(), "m\u{fc}nchen");
        let under_cap: String = format!("xn--{}", craft_front_insert_label(1000));
        let decoded: String = punycode_decode(&under_cap).unwrap();
        assert_eq!(decoded.chars().count(), 1000);
    }
}
