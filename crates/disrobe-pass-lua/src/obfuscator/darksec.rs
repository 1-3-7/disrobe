use crate::error::{Error, Result};
use crate::obfuscator::vm_devirt::{devirt_to_peel, extract_embedded_payload};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[b"-- DarkSec", b"DarkSec_Obf", b"DS_VM_BOOT"];

#[must_use]
pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut found: Vec<String> = Vec::new();
    for m in MARKERS {
        if disrobe_core::byte_search::contains(src, m) {
            found.push(String::from_utf8_lossy(m).into_owned());
        }
    }
    if found.is_empty() {
        return None;
    }
    Some(ObfuscatorDetection {
        kind: LuaObfuscatorKind::DarkSec,
        variant: Some("string-encode+cff".to_owned()),
        confidence: 85,
        markers: found,
    })
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("DarkSec"));
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(src);
    let Some(payload): Option<Vec<u8>> = extract_embedded_payload(&text) else {
        return Ok(PeelResult::passthrough(
            src,
            vec![
                "darksec vm bootstrap detected but no static VMPAYLOAD blob is embedded; the string-decode and control-flow-flattening dispatch is present but the serialized bytecode for this artifact could not be located".to_owned(),
            ],
        ));
    };
    devirt_to_peel(src, &text, &payload, "darksec")
}
