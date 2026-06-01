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

const DISPATCH_FINGERPRINTS: &[&[u8]] = &[
    b"local v0=tonumber;local v1=string.byte;local v2=string.char;local v3=string.sub",
    b"local v4=string.gsub;local v5=string.rep;local v6=table.concat;local v7=table.insert",
    b"local v8=math.ldexp",
    b"local v9=getfenv or function()",
];

const RLE_DISPATCH_HINT: &[u8] = b"if (v1(v30,2)==81) then";

pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut found: Vec<String> = Vec::new();
    for m in MARKERS {
        if windowed_contains(src, m) {
            found.push(String::from_utf8_lossy(m).into_owned());
        }
    }
    if !found.is_empty() {
        return Some(ObfuscatorDetection {
            kind: LuaObfuscatorKind::LuaObfuscatorCom,
            variant: Some("free-tier".to_owned()),
            confidence: 80,
            markers: found,
        });
    }
    fingerprint_detect(src)
}

fn fingerprint_detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let head: &[u8] = &src[..src.len().min(4096)];
    let mut hits: u32 = 0;
    let mut evidence: Vec<String> = Vec::new();
    for fp in DISPATCH_FINGERPRINTS {
        if windowed_contains(head, fp) {
            hits += 1;
        }
    }
    if hits < 3 {
        return None;
    }
    let rle_present: bool = windowed_contains(src, RLE_DISPATCH_HINT);
    if !rle_present {
        return None;
    }
    evidence.push("LuaObfuscator dispatch table fingerprint".to_owned());
    evidence.push("RLE marker v1(v30,2)==81 (Q-prefix)".to_owned());
    Some(ObfuscatorDetection {
        kind: LuaObfuscatorKind::LuaObfuscatorCom,
        variant: Some("free-tier-vm".to_owned()),
        confidence: 72,
        markers: evidence,
    })
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("luaobfuscator.com"));
    }
    Ok(PeelResult::passthrough(
        src,
        vec![
            "luaobfuscator.com free-tier vm: bytecode is RLE-packed in an encoded string fed through a dispatch loop; string-layer decode requires VM key recovery, not yet implemented".to_owned(),
        ],
    ))
}

fn windowed_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}
