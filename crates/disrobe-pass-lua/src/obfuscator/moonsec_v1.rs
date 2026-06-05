use crate::error::{Error, Result};
use crate::obfuscator::string_decode::extract_string_char_arrays;
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[b"-- MoonSec v1", b"moonsec_v1", b"--[[ MoonSec V1 ]]"];

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
        kind: LuaObfuscatorKind::MoonSecV1,
        variant: Some("string-pool+simple-cff".to_owned()),
        confidence: 88,
        markers: found,
    })
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("MoonSec V1"));
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(src);
    let pool: Vec<String> = recover_string_pool(&text);
    if pool.is_empty() {
        return Ok(PeelResult::passthrough(
            src,
            vec![
                "moonsec v1 string pool not present; vm-handler recovery is out of scope"
                    .to_owned(),
            ],
        ));
    }
    let mut out: String = String::from("local MOONSEC_V1_STRINGS = {\n");
    for s in &pool {
        out.push_str("  ");
        out.push_str(&quote_lua(s));
        out.push_str(",\n");
    }
    out.push_str("}\n");
    Ok(PeelResult {
        deobfuscated: out.into_bytes(),
        passes_run: vec!["moonsec-v1-string-char-pool-recover".to_owned()],
        residual_markers: vec![
            "moonsec v1 vm: string.char pool recovered; bytecode/CFF dispatch layer remains"
                .to_owned(),
        ],
        recovered_strings: pool,
        fully_recovered: false,
    })
}

/// Recovers `MoonSec` V1's plaintext string pool, surfacing only arrays that decode to printable text.
#[must_use]
fn recover_string_pool(text: &str) -> Vec<String> {
    extract_string_char_arrays(text)
        .into_iter()
        .filter_map(|bytes: Vec<u8>| {
            let s: String = String::from_utf8_lossy(&bytes).into_owned();
            let printable: bool = s
                .chars()
                .all(|c: char| !c.is_control() || c == '\n' || c == '\t' || c == '\r');
            if printable && s.chars().any(|c: char| !c.is_whitespace()) {
                Some(s)
            } else {
                None
            }
        })
        .collect()
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
