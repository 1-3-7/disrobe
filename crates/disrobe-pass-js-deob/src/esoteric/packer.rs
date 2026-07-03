use regex::Regex;
use serde::Serialize;

const PACKER_SIGNATURE: &str = "function(p,a,c,k,e,";
const MAX_PEEL_LAYERS: usize = 32;

#[derive(Debug, Clone, Default, Serialize)]
pub struct PackerDetection {
    pub matched: bool,
    pub base: u32,
    pub word_count: usize,
    pub layers: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackerDecode {
    pub detection: PackerDetection,
    pub recovered: Option<String>,
}

impl PackerDetection {
    const fn into_decode(self, recovered: Option<String>) -> PackerDecode {
        PackerDecode {
            detection: self,
            recovered,
        }
    }
}

#[must_use]
pub fn detect_packer(source: &str) -> PackerDetection {
    if !source.contains(PACKER_SIGNATURE) {
        return PackerDetection::default();
    }
    match extract_args(source) {
        Some(args) => PackerDetection {
            matched: true,
            base: args.base,
            word_count: args.words.len(),
            layers: 1,
        },
        None => PackerDetection::default(),
    }
}

#[must_use]
pub fn unpack(source: &str) -> PackerDecode {
    if !source.contains(PACKER_SIGNATURE) {
        return PackerDecode {
            detection: PackerDetection::default(),
            recovered: None,
        };
    }
    let Some(first): Option<PackerArgs> = extract_args(source) else {
        return PackerDetection::default().into_decode(None);
    };
    let outer_base: u32 = first.base;
    let outer_words: usize = first.words.len();
    let Some(mut current): Option<String> = unpack_with(&first.payload, first.base, &first.words)
    else {
        return PackerDetection {
            matched: true,
            base: outer_base,
            word_count: outer_words,
            layers: 1,
        }
        .into_decode(None);
    };
    let mut layers: usize = 1;
    while layers < MAX_PEEL_LAYERS {
        if !current.contains(PACKER_SIGNATURE) {
            break;
        }
        let Some(inner): Option<PackerArgs> = extract_args(&current) else {
            break;
        };
        let Some(next): Option<String> = unpack_with(&inner.payload, inner.base, &inner.words)
        else {
            break;
        };
        if next == current {
            break;
        }
        current = next;
        layers += 1;
    }
    PackerDetection {
        matched: true,
        base: outer_base,
        word_count: outer_words,
        layers,
    }
    .into_decode(Some(current))
}

#[derive(Debug)]
struct PackerArgs {
    payload: String,
    base: u32,
    words: Vec<String>,
}

fn extract_args(source: &str) -> Option<PackerArgs> {
    let anchor: usize = source.find("}(")?;
    let after: &str = source.get(anchor + 2..)?;
    let payload_start: usize = after.find(['\'', '"'])?;
    let payload_quote: char = after
        .as_bytes()
        .get(payload_start)
        .copied()
        .map(char::from)?;
    let (payload_raw, after_payload): (String, &str) =
        consume_string_literal(&after[payload_start..], payload_quote)?;
    let after_comma1: &str = skip_to_comma(after_payload)?;
    let (base_str, after_base): (&str, &str) = take_number(after_comma1)?;
    let base: u32 = base_str.parse::<u32>().ok()?;
    if !(2..=62).contains(&base) {
        return None;
    }
    let after_comma2: &str = skip_to_comma(after_base)?;
    let (_count_str, after_count): (&str, &str) = take_number(after_comma2)?;
    let after_comma3: &str = skip_to_comma(after_count)?;
    let words_quote_off: usize = after_comma3.bytes().position(|b| b == b'\'' || b == b'"')?;
    let words_quote: char = after_comma3
        .as_bytes()
        .get(words_quote_off)
        .copied()
        .map(char::from)?;
    let (words_raw, after_words): (String, &str) =
        consume_string_literal(&after_comma3[words_quote_off..], words_quote)?;
    let split_pos: usize = after_words.find(".split")?;
    let after_split: &str = &after_words[split_pos + ".split".len()..];
    let split_paren: usize = after_split.bytes().position(|b| b == b'(')?;
    let after_paren: &str = &after_split[split_paren + 1..];
    let sep_quote_off: usize = after_paren.bytes().position(|b| b == b'\'' || b == b'"')?;
    let sep_quote: char = after_paren
        .as_bytes()
        .get(sep_quote_off)
        .copied()
        .map(char::from)?;
    let (sep_raw, _rest): (String, &str) =
        consume_string_literal(&after_paren[sep_quote_off..], sep_quote)?;
    let payload: String = unescape_js(&payload_raw);
    let sep: String = unescape_js(&sep_raw);
    let words_decoded: String = unescape_js(&words_raw);
    let words: Vec<String> = if sep.is_empty() {
        vec![words_decoded]
    } else {
        words_decoded.split(&sep).map(str::to_owned).collect()
    };
    Some(PackerArgs {
        payload,
        base,
        words,
    })
}

fn consume_string_literal(input: &str, quote: char) -> Option<(String, &str)> {
    let bytes: &[u8] = input.as_bytes();
    let quote_byte: u8 = u8::try_from(quote as u32).ok()?;
    if bytes.first().copied() != Some(quote_byte) {
        return None;
    }
    let mut out: String = String::new();
    let mut i: usize = 1;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            out.push(char::from(b));
            out.push(char::from(bytes[i + 1]));
            i += 2;
            continue;
        }
        if b == quote_byte {
            return Some((out, &input[i + 1..]));
        }
        out.push(char::from(b));
        i += 1;
    }
    None
}

fn skip_to_comma(input: &str) -> Option<&str> {
    let pos: usize = input.bytes().position(|b| b == b',')?;
    Some(&input[pos + 1..])
}

fn take_number(input: &str) -> Option<(&str, &str)> {
    let trimmed: &str = input.trim_start();
    let end: usize = trimmed
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(trimmed.len());
    if end == 0 {
        return None;
    }
    Some((&trimmed[..end], &trimmed[end..]))
}

fn unpack_with(payload: &str, base: u32, words: &[String]) -> Option<String> {
    let re: Regex = Regex::new(r"\b\w+\b").ok()?;
    let out: std::borrow::Cow<'_, str> = re.replace_all(payload, |caps: &regex::Captures<'_>| {
        let token: &str = &caps[0];
        let Some(idx): Option<usize> = decode_base(token, base) else {
            return token.to_owned();
        };
        if idx < words.len() && !words[idx].is_empty() {
            words[idx].clone()
        } else {
            token.to_owned()
        }
    });
    Some(out.into_owned())
}

fn decode_base(token: &str, base: u32) -> Option<usize> {
    if token.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for ch in token.chars() {
        let digit: u32 = digit_value(ch, base)?;
        value = value
            .checked_mul(u64::from(base))?
            .checked_add(u64::from(digit))?;
    }
    usize::try_from(value).ok()
}

fn digit_value(ch: char, base: u32) -> Option<u32> {
    let value: u32 = match ch {
        '0'..='9' => u32::from(ch as u8 - b'0'),
        'a'..='z' => u32::from(ch as u8 - b'a') + 10,
        'A'..='Z' => u32::from(ch as u8 - b'A') + 36,
        _ => return None,
    };
    if value < base { Some(value) } else { None }
}

fn unescape_js(input: &str) -> String {
    let mut out: String = String::with_capacity(input.len());
    let mut iter: std::str::Chars<'_> = input.chars();
    while let Some(ch) = iter.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match iter.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\'') => out.push('\''),
            Some('"') => out.push('"'),
            Some('0') => out.push('\0'),
            Some('/') => out.push('/'),
            Some('b') => out.push('\u{0008}'),
            Some('f') => out.push('\u{000C}'),
            Some('\\') | None => out.push('\\'),
            Some('x') => {
                let hi: Option<char> = iter.next();
                let lo: Option<char> = iter.next();
                if let (Some(h), Some(l)) = (hi, lo)
                    && let (Some(a), Some(b)) = (h.to_digit(16), l.to_digit(16))
                    && let Some(byte) = char::from_u32((a << 4) | b)
                {
                    out.push(byte);
                }
            }
            Some('u') => {
                let mut code: u32 = 0;
                for _ in 0..4 {
                    let Some(c): Option<char> = iter.next() else {
                        break;
                    };
                    let Some(d): Option<u32> = c.to_digit(16) else {
                        break;
                    };
                    code = (code << 4) | d;
                }
                if let Some(ch) = char::from_u32(code) {
                    out.push(ch);
                }
            }
            Some(other) => out.push(other),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    const SAMPLE: &str = "eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('0 1 2',3,3,'console|log|hello'.split('|'),0,{}))";

    #[test]
    fn detects_packer_signature() {
        let det: PackerDetection = detect_packer(SAMPLE);
        assert!(det.matched, "should detect: {det:?}");
        assert_eq!(det.base, 3);
        assert_eq!(det.word_count, 3);
    }

    #[test]
    fn unpacks_simple_payload() {
        let res: PackerDecode = unpack(SAMPLE);
        let Some(out): Option<String> = res.recovered else {
            panic!("must unpack");
        };
        assert_eq!(out, "console log hello");
        assert_eq!(res.detection.layers, 1);
    }

    #[test]
    fn single_payload_without_nesting_stops_after_one_layer() {
        let res: PackerDecode = unpack(SAMPLE);
        let out: String = res.recovered.expect("must unpack");
        assert!(!out.contains(PACKER_SIGNATURE));
        assert_eq!(res.detection.layers, 1);
    }

    #[test]
    fn decode_base_handles_36() {
        let val: usize = decode_base("z", 36).expect("z");
        assert_eq!(val, 35);
        let val2: usize = decode_base("10", 36).expect("10");
        assert_eq!(val2, 36);
    }

    #[test]
    fn decode_base_handles_62() {
        let val: usize = decode_base("Z", 62).expect("Z");
        assert_eq!(val, 61);
    }
}
