use crate::error::{Error, Result};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[
    b"-- MoonSec v3",
    b"moonsec_v3",
    b"MS_VM_ENTRY",
    b"MS_VM_TAMPER",
    b"--[[ MoonSec V3 ]]",
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
        kind: LuaObfuscatorKind::MoonSecV3,
        variant: Some("custom-vm+advanced-cff+anti-tamper".to_owned()),
        confidence: 95,
        markers: found,
    })
}

pub fn peel(src: &[u8], opts: &DeobfOptions) -> Result<PeelResult> {
    let _det: ObfuscatorDetection =
        detect(src).ok_or(Error::NoObfuscatorSignature("MoonSec V3"))?;
    if !opts.i_have_authorization {
        return Err(Error::AuthorizationRequired("MoonSec V3"));
    }
    Ok(PeelResult::passthrough(
        src,
        vec![
            "moonsec v3 encrypted-constant pool + anti-tamper vm requires runtime keys; static peel not implemented".to_owned(),
        ],
    ))
}

fn windowed_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}
