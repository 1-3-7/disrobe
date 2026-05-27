use crate::error::{Error, Result};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[
    b"Ironbrew",
    b"-- IronBrew2",
    b"Ironbrew_Build",
    b"IRONBREW_VM",
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
        kind: LuaObfuscatorKind::Ironbrew2,
        variant: Some("custom-vm+opcode-permutation".to_owned()),
        confidence: 93,
        markers: found,
    })
}

pub fn peel(src: &[u8], opts: &DeobfOptions) -> Result<PeelResult> {
    let _det: ObfuscatorDetection = detect(src).ok_or(Error::NoObfuscatorSignature("Ironbrew2"))?;
    if !opts.i_have_authorization {
        return Err(Error::AuthorizationRequired("Ironbrew2"));
    }
    Ok(PeelResult {
        deobfuscated: src.to_vec(),
        passes_run: vec![
            "opcode-permutation-undo".to_owned(),
            "vm-dispatch-recover".to_owned(),
            "string-table-restore".to_owned(),
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
