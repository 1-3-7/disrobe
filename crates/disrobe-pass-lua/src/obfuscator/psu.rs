use crate::error::{Error, Result};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[b"-- PSU 4.0", b"-- PSU 4.5", b"PSU_VM_KEY", b"PSU4"];

pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut found: Vec<String> = Vec::new();
    let mut variant: Option<String> = None;
    for m in MARKERS {
        if windowed_contains(src, m) {
            found.push(String::from_utf8_lossy(m).into_owned());
        }
    }
    for v in [b"4.0.A".as_slice(), b"4.5.A"] {
        if windowed_contains(src, v) {
            variant = Some(String::from_utf8_lossy(v).into_owned());
            break;
        }
    }
    if found.is_empty() {
        return None;
    }
    Some(ObfuscatorDetection {
        kind: LuaObfuscatorKind::Psu,
        variant,
        confidence: 88,
        markers: found,
    })
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("PSU"));
    }
    Ok(PeelResult::passthrough(
        src,
        vec!["psu vm + string-table recovery not yet implemented".to_owned()],
    ))
}

fn windowed_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}
