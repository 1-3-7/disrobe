use crate::error::{Error, Result};
use crate::obfuscator::vm_devirt::{devirt_to_peel, extract_embedded_payload};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[
    b"-- MoonSec v3",
    b"moonsec_v3",
    b"MS_VM_ENTRY",
    b"MS_VM_TAMPER",
    b"--[[ MoonSec V3 ]]",
];

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
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(src);
    let Some(payload): Option<Vec<u8>> = extract_embedded_payload(&text) else {
        return Ok(PeelResult::passthrough(
            src,
            vec![
                "moonsec v3 vm bootstrap detected but no static VMPAYLOAD blob embedded; when the encrypted-constant pool depends on runtime keys (anti-tamper handshake) rather than a key baked into the bootstrap, the instruction stream cannot be devirtualized statically".to_owned(),
            ],
        ));
    };
    devirt_to_peel(src, &text, &payload, "moonsec-v3")
}
