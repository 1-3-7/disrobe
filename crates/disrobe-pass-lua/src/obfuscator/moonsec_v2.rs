use crate::error::{Error, Result};
use crate::obfuscator::string_decode::{extract_string_char_arrays, xor_decode_fixed};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[
    b"-- MoonSec v2",
    b"moonsec_v2",
    b"--[[ MoonSec V2 ]]",
    b"MS_V2_KEY",
];

pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut found: Vec<String> = Vec::new();
    for m in MARKERS {
        if windowed_contains(src, m) {
            found.push(String::from_utf8_lossy(m).into_owned());
        }
    }
    if found.is_empty() {
        return None;
    }
    Some(ObfuscatorDetection {
        kind: LuaObfuscatorKind::MoonSecV2,
        variant: Some("xor-string-pool+nested-cff".to_owned()),
        confidence: 90,
        markers: found,
    })
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("MoonSec V2"));
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(src);
    let arrays: Vec<Vec<u8>> = extract_string_char_arrays(&text);
    let key: Option<u8> = find_xor_key(&text);
    let Some((pool, variant)): Option<(Vec<String>, &'static str)> = recover_xor_pool(&arrays, key)
    else {
        return Ok(PeelResult::passthrough(
            src,
            vec![
                "moonsec v2 xor key/string pool not statically recoverable; vm layer remains"
                    .to_owned(),
            ],
        ));
    };
    let mut out: String = String::from("local MOONSEC_V2_STRINGS = {\n");
    for s in &pool {
        out.push_str("  ");
        out.push_str(&quote_lua(s));
        out.push_str(",\n");
    }
    out.push_str("}\n");
    Ok(PeelResult {
        deobfuscated: out.into_bytes(),
        passes_run: vec![
            "moonsec-v2-string-char-pool-extract".to_owned(),
            format!("moonsec-v2-xor-recover-{variant}"),
        ],
        residual_markers: vec![format!(
            "moonsec v2 vm: {variant} xor string pool recovered; bytecode/CFF dispatch layer remains"
        )],
        recovered_strings: pool,
        fully_recovered: false,
    })
}

/// Parses a `MoonSec` V2 numeric XOR key from an `MS_V2_KEY = N` / `key = N`
/// assignment (decimal or `0x` hex), constrained to a single byte.
#[must_use]
fn find_xor_key(text: &str) -> Option<u8> {
    for marker in ["MS_V2_KEY", "xor_key", "XOR_KEY"] {
        if let Some(pos) = text.find(marker) {
            let rest: &str = &text[pos + marker.len()..];
            let Some(after_eq): Option<&str> =
                rest.trim_start().strip_prefix('=').map(str::trim_start)
            else {
                continue;
            };
            if let Some(byte) = parse_byte_literal(after_eq) {
                return Some(byte);
            }
        }
    }
    None
}

#[must_use]
fn parse_byte_literal(s: &str) -> Option<u8> {
    let token: String = s
        .chars()
        .take_while(|c: &char| c.is_ascii_hexdigit() || *c == 'x' || *c == 'X')
        .collect();
    let value: i64 = if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        token.parse::<i64>().ok()?
    };
    u8::try_from(value).ok()
}

/// Applies the recovered key to every extracted byte array with fixed-key XOR.
///
/// Fixed-key XOR is the dominant documented `MoonSec` V2 string layer. Only the
/// fixed variant is auto-selected: fixed and index-rolling XOR of ASCII payloads
/// both stay in the printable range, so a printability score cannot reliably
/// disambiguate them statically, and guessing would risk a fabricated decode.
/// The rolling primitive stays available for callers that know the variant.
#[must_use]
fn recover_xor_pool(arrays: &[Vec<u8>], key: Option<u8>) -> Option<(Vec<String>, &'static str)> {
    if arrays.is_empty() {
        return None;
    }
    let key: u8 = key?;
    let fixed: Vec<String> = decode_pool(arrays, |a: &[u8]| xor_decode_fixed(a, key));
    if printable_score(&fixed) == 0 {
        return None;
    }
    Some((fixed, "fixed"))
}

#[must_use]
fn decode_pool<F: Fn(&[u8]) -> Vec<u8>>(arrays: &[Vec<u8>], decode: F) -> Vec<String> {
    arrays
        .iter()
        .map(|a: &Vec<u8>| String::from_utf8_lossy(&decode(a)).into_owned())
        .collect()
}

#[must_use]
fn printable_score(pool: &[String]) -> usize {
    pool.iter()
        .filter(|s: &&String| {
            !s.is_empty()
                && s.chars()
                    .all(|c: char| !c.is_control() || c == '\n' || c == '\t' || c == '\r')
                && s.chars().any(|c: char| c.is_ascii_alphanumeric())
        })
        .count()
}

#[must_use]
fn quote_lua(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\{}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn windowed_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}
