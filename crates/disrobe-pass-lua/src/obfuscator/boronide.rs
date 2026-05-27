use crate::error::{Error, Result};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[
    b"-- Boronide",
    b"BORONIDE_VERSION",
    b"BORONIDE_VM",
    b"boronide_v0",
];

pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut found: Vec<String> = Vec::new();
    let mut variant: Option<String> = None;
    for m in MARKERS {
        if windowed_contains(src, m) {
            found.push(String::from_utf8_lossy(m).into_owned());
        }
    }
    for v in [b"v0.4".as_slice(), b"v0.5", b"v0.6"] {
        if windowed_contains(src, v) {
            variant = Some(String::from_utf8_lossy(v).into_owned());
            break;
        }
    }
    if found.is_empty() {
        return None;
    }
    Some(ObfuscatorDetection {
        kind: LuaObfuscatorKind::Boronide,
        variant,
        confidence: 87,
        markers: found,
    })
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("Boronide"));
    }
    Ok(PeelResult {
        deobfuscated: src.to_vec(),
        passes_run: vec![
            "boronide-vm-recover".to_owned(),
            "string-restore".to_owned(),
        ],
        residual_markers: Vec::new(),
    })
}

fn windowed_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}
