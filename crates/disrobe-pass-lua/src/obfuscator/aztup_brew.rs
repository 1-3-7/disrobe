use crate::error::{Error, Result};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[b"AztupBrew", b"-- aztup_brew", b"AZB_VM"];

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
        kind: LuaObfuscatorKind::AztupBrew,
        variant: Some("ironbrew2-fork".to_owned()),
        confidence: 90,
        markers: found,
    })
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("AztupBrew"));
    }
    Ok(PeelResult::passthrough(
        src,
        vec!["aztupbrew (ironbrew2 fork) vm recovery not yet implemented".to_owned()],
    ))
}

fn windowed_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}
