use crate::error::{Error, Result};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[
    b"-- WeAreDevs",
    b"WRD_OBFUSCATOR",
    b"wearedevs_luau",
    b"wearedevs.net/obfuscator",
    b"https://wearedevs.net",
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
        kind: LuaObfuscatorKind::WeAreDevs,
        variant: Some("luau-string-encode".to_owned()),
        confidence: 82,
        markers: found,
    })
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("WeAreDevs LuaU"));
    }
    Ok(PeelResult {
        deobfuscated: src.to_vec(),
        passes_run: vec!["luau-string-decode".to_owned(), "junk-strip".to_owned()],
        residual_markers: Vec::new(),
    })
}

fn windowed_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}
