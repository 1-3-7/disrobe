use crate::error::{Error, Result};
use crate::obfuscator::vm_devirt::{devirt_to_peel, extract_embedded_payload};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[b"-- PSU 4.0", b"-- PSU 4.5", b"PSU_VM_KEY", b"PSU4"];

#[must_use]
pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut found: Vec<String> = Vec::new();
    let mut variant: Option<String> = None;
    for m in MARKERS {
        if disrobe_core::byte_search::contains(src, m) {
            found.push(String::from_utf8_lossy(m).into_owned());
        }
    }
    for v in [b"4.0.A".as_slice(), b"4.5.A"] {
        if disrobe_core::byte_search::contains(src, v) {
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
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(src);
    let Some(payload): Option<Vec<u8>> = extract_embedded_payload(&text) else {
        return Ok(PeelResult::passthrough(
            src,
            vec![
                "psu vm bootstrap detected but no static VMPAYLOAD blob is embedded; the 4.0/4.5 interpreter, string table and opcode permutation are present but the serialized bytecode for this artifact could not be located".to_owned(),
            ],
        ));
    };
    devirt_to_peel(src, &text, &payload, "psu")
}
