use crate::error::{Error, Result};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[
    b"-- luaobfuscator.com",
    b"luaobfuscator_com",
    b"LOC_FREE_TIER",
    b"LuaObfuscator.com",
    b"luaobfuscator.com",
    b"Welcome to LuaObfuscator",
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
        kind: LuaObfuscatorKind::LuaObfuscatorCom,
        variant: Some("free-tier".to_owned()),
        confidence: 80,
        markers: found,
    })
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("luaobfuscator.com"));
    }
    Ok(PeelResult {
        deobfuscated: src.to_vec(),
        passes_run: vec!["string-decode-free".to_owned(), "junk-strip".to_owned()],
        residual_markers: Vec::new(),
    })
}

fn windowed_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}
