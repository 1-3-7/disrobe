use ruff_python_ast::Mod;
use ruff_python_parser::{Mode, ParseOptions, Parsed, parse};

const RING: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const ZETA: u32 = 0x03B6;
const MAX_CODEPOINT: u32 = 0x0010_FFFF;
const PRINTABLE_RATIO_FLOOR: f32 = 0.95;
const SOURCE_PUNCT: &str = "()[]{}:.,;'\"=+-*/%<>!&|^~@#_\\ \t\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    Decimal,
    Hex,
}

#[derive(Debug, Clone)]
pub(crate) struct FamilyDecode {
    pub(crate) recovered: String,
    pub(crate) shift: u32,
    pub(crate) delimiter: char,
    pub(crate) token_count: usize,
    pub(crate) printable_ratio: f32,
}

#[inline]
fn ring_rotate_forward(c: char) -> char {
    RING.iter()
        .position(|&r: &u8| char::from(r) == c)
        .map_or(c, |idx: usize| char::from(RING[(idx + 1) % RING.len()]))
}

fn printable_ratio(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let printable: usize = s
        .chars()
        .filter(|&c: &char| c == '\n' || c == '\t' || ('\u{20}'..'\u{7f}').contains(&c))
        .count();
    printable as f32 / s.chars().count() as f32
}

fn has_disqualifying_control(s: &str) -> bool {
    s.chars()
        .any(|c: char| c.is_control() && c != '\n' && c != '\t' && c != '\r')
}

fn source_score(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let liked: usize = s
        .chars()
        .filter(|&c: &char| c.is_ascii_alphanumeric() || SOURCE_PUNCT.contains(c))
        .count();
    liked as f32 / s.chars().count() as f32
}

fn stage1_codepoints(blob: &str, delimiter: char, kind: TokenKind) -> Option<Vec<u32>> {
    let tokens: Vec<&str> = blob
        .split(delimiter)
        .filter(|t: &&str| !t.is_empty())
        .collect();
    let count: i64 = i64::try_from(tokens.len()).ok()?;
    let mut out: Vec<u32> = Vec::with_capacity(tokens.len());
    for tok in tokens {
        match kind {
            TokenKind::Decimal => {
                if let Ok(n) = tok.parse::<i64>() {
                    let v: i64 = n - count;
                    if !(0..=i64::from(MAX_CODEPOINT)).contains(&v) {
                        return None;
                    }
                    out.push(u32::try_from(v).ok()?);
                } else {
                    out.push(ZETA);
                }
            }
            TokenKind::Hex => {
                if tok.bytes().all(|b: u8| b.is_ascii_hexdigit()) && tok.len().is_multiple_of(2) {
                    let bytes: Vec<u8> = decode_hex(tok)?;
                    let ch: char = std::str::from_utf8(&bytes).ok()?.chars().next()?;
                    out.push(ch as u32);
                } else {
                    out.push(ZETA);
                }
            }
        }
    }
    Some(out)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() / 2);
    let mut i: usize = 0;
    while i + 1 < bytes.len() {
        let hi: u8 = nibble(bytes[i])?;
        let lo: u8 = nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

#[inline]
const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn apply_shift(codepoints: &[u32], shift: u32) -> Option<String> {
    let mut out: String = String::with_capacity(codepoints.len());
    for &cp in codepoints {
        if cp == ZETA {
            out.push('\n');
            continue;
        }
        let shifted: u32 = cp.checked_sub(shift)?;
        if shifted > MAX_CODEPOINT {
            return None;
        }
        let ch: char = char::from_u32(shifted)?;
        out.push(ring_rotate_forward(ch));
    }
    Some(out)
}

fn candidate_shifts(codepoints: &[u32]) -> Vec<u32> {
    let mut seen: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let mut out: Vec<u32> = Vec::new();
    for &cp in codepoints.iter().filter(|&&c: &&u32| c != ZETA) {
        for ascii in 0x20u32..0x7f {
            if let Some(shift) = cp.checked_sub(ascii)
                && seen.insert(shift)
            {
                out.push(shift);
            }
        }
    }
    out
}

fn parses_as_python(source: &str) -> bool {
    parse(source, ParseOptions::from(Mode::Module))
        .is_ok_and(|p: Parsed<Mod>| p.errors().is_empty())
}

#[derive(Debug, Clone)]
struct Candidate {
    decode: FamilyDecode,
    parses: bool,
    score: f32,
}

fn best_decode(codepoints: &[u32], delimiter: char, token_count: usize) -> Option<FamilyDecode> {
    let mut best: Option<Candidate> = None;
    for shift in candidate_shifts(codepoints) {
        let Some(recovered): Option<String> = apply_shift(codepoints, shift) else {
            continue;
        };
        if has_disqualifying_control(&recovered) {
            continue;
        }
        let ratio: f32 = printable_ratio(&recovered);
        if ratio < PRINTABLE_RATIO_FLOOR {
            continue;
        }
        let parses: bool = parses_as_python(&recovered);
        let score: f32 = source_score(&recovered);
        let cand: Candidate = Candidate {
            decode: FamilyDecode {
                recovered,
                shift,
                delimiter,
                token_count,
                printable_ratio: ratio,
            },
            parses,
            score,
        };
        let better: bool = match best.as_ref() {
            None => true,
            Some(b) => (cand.parses, cand.score) > (b.parses, b.score),
        };
        if better {
            best = Some(cand);
        }
    }
    best.map(|c: Candidate| c.decode)
}

fn infer_delimiter(blob: &str) -> Option<char> {
    let mut counts: std::collections::BTreeMap<char, usize> = std::collections::BTreeMap::new();
    for c in blob.chars().filter(|c: &char| !c.is_ascii_alphanumeric()) {
        *counts.entry(c).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by_key(|&(_, n): &(char, usize)| n)
        .map(|(c, _): (char, usize)| c)
}

pub(crate) fn decode_decimal_sparkle(blob: &str) -> Option<FamilyDecode> {
    let delimiter: char = infer_delimiter(blob)?;
    let codepoints: Vec<u32> = stage1_codepoints(blob, delimiter, TokenKind::Decimal)?;
    let count: usize = codepoints.len();
    best_decode(&codepoints, delimiter, count)
}

pub(crate) fn decode_hex_sparkle(blob: &str) -> Option<FamilyDecode> {
    let delimiter: char = '/';
    let codepoints: Vec<u32> = stage1_codepoints(blob, delimiter, TokenKind::Hex)?;
    let count: usize = codepoints.len();
    best_decode(&codepoints, delimiter, count)
}

pub(crate) fn decode_sparkle_any(blob: &str) -> Option<FamilyDecode> {
    if let Some(hex) = decode_hex_sparkle(blob) {
        return Some(hex);
    }
    decode_decimal_sparkle(blob)
}

pub(crate) fn extract_sparkle(text: &str) -> Option<&str> {
    let key: usize = text.find("_sparkle=")?;
    let after: &str = &text[key + "_sparkle=".len()..];
    let body: &str = after
        .strip_prefix("'''")
        .or_else(|| after.strip_prefix("\"\"\""))?;
    let end: usize = body.find("'''").or_else(|| body.find("\"\"\""))?;
    Some(&body[..end])
}

pub(crate) fn extract_hex_blob_from_pyc(source: &[u8]) -> Option<&[u8]> {
    let mut best: (usize, usize) = (0, 0);
    let mut start: Option<usize> = None;
    let is_tok: fn(u8) -> bool = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'/');
    for (i, &b) in source.iter().enumerate() {
        if is_tok(b) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take()
            && i - s > best.1 - best.0
            && source[s..i].contains(&b'/')
        {
            best = (s, i);
        }
    }
    if let Some(s) = start
        && source.len() - s > best.1 - best.0
        && source[s..].contains(&b'/')
    {
        best = (s, source.len());
    }
    if best.0 == best.1 {
        return None;
    }
    Some(&source[best.0..best.1])
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decimal_sparkle_decodes_hello_dash_delim() {
        let blob: &str =
            "174-176-167-172-178-103-102-166-163-170-170-173-95-181-173-176-170-162-102-104-§";
        let d: FamilyDecode = decode_decimal_sparkle(blob).expect("decode");
        assert_eq!(d.recovered, "print('hello world')\n");
        assert_eq!(d.delimiter, '-');
    }

    #[test]
    fn hex_sparkle_decodes_hello_with_zeta_newline() {
        let blob: &str = "c299/c29b/c292/c297/c29d/52/51/c291/c28e/c295/c295/c298/4a/c2a0/c298/c29b/c295/c28d/51/53/ceb6";
        let d: FamilyDecode = decode_hex_sparkle(blob).expect("decode");
        assert_eq!(d.recovered, "print('hello world')\n");
        assert_eq!(d.shift, 42);
    }

    #[test]
    fn ring_rotation_maps_python_scramble() {
        let scrambled: &str = "Pxsgnm";
        let rotated: String = scrambled.chars().map(ring_rotate_forward).collect();
        assert_eq!(rotated, "Python");
    }

    #[test]
    fn extract_sparkle_triple_quoted() {
        let src: &str = "Berserker(_exec=False,_sparkle='''1-2-3''')";
        assert_eq!(extract_sparkle(src), Some("1-2-3"));
    }

    #[test]
    fn rejects_non_decodable_garbage() {
        assert!(decode_decimal_sparkle("zzzz").is_none());
    }

    #[test]
    fn sparkle_any_routes_hex_and_decimal_variants() {
        let hex_blob: &str = "c299/c29b/c292/c297/c29d/52/51/c291/c28e/c295/c295/c298/4a/c2a0/c298/c29b/c295/c28d/51/53/ceb6";
        let decimal_blob: &str =
            "174-176-167-172-178-103-102-166-163-170-170-173-95-181-173-176-170-162-102-104-§";
        let hex: FamilyDecode = decode_sparkle_any(hex_blob).expect("hex via any");
        let dec: FamilyDecode = decode_sparkle_any(decimal_blob).expect("decimal via any");
        assert_eq!(hex.recovered, "print('hello world')\n");
        assert_eq!(dec.recovered, "print('hello world')\n");
    }

    fn ring_rotate_backward(c: char) -> char {
        RING.iter()
            .position(|&r: &u8| char::from(r) == c)
            .map_or(c, |idx: usize| {
                char::from(RING[(idx + RING.len() - 1) % RING.len()])
            })
    }

    fn encode_hex_sparkle(payload: &str, shift: u32) -> String {
        let mut tokens: Vec<String> = Vec::new();
        for ch in payload.chars() {
            if ch == '\n' {
                tokens.push(format!("{ZETA:x}"));
                continue;
            }
            let pre_rotate: char = ring_rotate_backward(ch);
            let codepoint: u32 = pre_rotate as u32 + shift;
            let encoded: char = char::from_u32(codepoint).expect("valid codepoint");
            let token: String = encoded.to_string().into_bytes().iter().fold(
                String::new(),
                |mut acc: String, b: &u8| {
                    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
                    let byte: u8 = *b;
                    acc.push(LOWER_HEX[(byte >> 4) as usize] as char);
                    acc.push(LOWER_HEX[(byte & 0x0f) as usize] as char);
                    acc
                },
            );
            tokens.push(token);
        }
        tokens.join("/")
    }

    #[test]
    fn brute_recovers_shift_when_leading_codepoints_are_newlines() {
        let payload: &str = "\n\nx = 1\n";
        let blob: String = encode_hex_sparkle(payload, 0x40);
        let decoded: FamilyDecode = decode_hex_sparkle(&blob).expect("brute over full keyspace");
        assert_eq!(
            decoded.recovered, payload,
            "exhaustive shift brute must recover the payload despite leading zeta newlines"
        );
    }
}
