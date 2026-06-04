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

/// Width of the Ironbrew2 little-endian string-length prefix that precedes each
/// string constant body in the serialized chunk (documented format reference).
const IB2_STRING_LEN_PREFIX_BYTES: usize = 4;

pub fn peel(src: &[u8], opts: &DeobfOptions) -> Result<PeelResult> {
    let _det: ObfuscatorDetection = detect(src).ok_or(Error::NoObfuscatorSignature("Ironbrew2"))?;
    if !opts.i_have_authorization {
        return Err(Error::AuthorizationRequired("Ironbrew2"));
    }
    let _ = IB2_STRING_LEN_PREFIX_BYTES;
    Ok(PeelResult::passthrough(
        src,
        vec![
            "ironbrew2 const block not statically recoverable: every chunk byte (type tag, 4-byte le string length, string body) is masked with a per-build primary-xor key and the constant-type tag is a randomized per-build permutation, both embedded inside the obfuscated vm bootstrap; opcode-permutation + dispatch recovery is out of scope"
                .to_owned(),
        ],
    ))
}

fn windowed_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}
