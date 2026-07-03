use crate::error::{Error, Result};
use crate::obfuscator::vm_devirt::{devirt_to_peel, extract_embedded_payload};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[
    b"-- Boronide",
    b"BORONIDE_VERSION",
    b"BORONIDE_VM",
    b"boronide_v0",
];

#[must_use]
pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut found: Vec<String> = Vec::new();
    let mut variant: Option<String> = None;
    for m in MARKERS {
        if disrobe_core::byte_search::contains(src, m) {
            found.push(String::from_utf8_lossy(m).into_owned());
        }
    }
    for v in [b"v0.4".as_slice(), b"v0.5", b"v0.6"] {
        if disrobe_core::byte_search::contains(src, v) {
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
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(src);
    let Some(payload): Option<Vec<u8>> = extract_embedded_payload(&text) else {
        return Ok(PeelResult::passthrough(
            src,
            vec![
                "boronide vm bootstrap detected but no static VMPAYLOAD blob is embedded; the v0.4/0.5/0.6 interpreter and its opcode table are present but the serialized bytecode for this artifact could not be located".to_owned(),
            ],
        ));
    };
    devirt_to_peel(src, &text, &payload, "boronide")
}
