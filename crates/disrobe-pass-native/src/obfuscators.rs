use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObfuscatorFamily {
    Alcatraz,
    OllvmFlattening,
    OllvmBogusControlFlow,
    OllvmSubstitution,
    TigressCff,
    EmotetCff,
    Mirai,
    Dridex,
    Trickbot,
}

impl ObfuscatorFamily {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Alcatraz => "alcatraz",
            Self::OllvmFlattening => "ollvm-cff",
            Self::OllvmBogusControlFlow => "ollvm-bcf",
            Self::OllvmSubstitution => "ollvm-sub",
            Self::TigressCff => "tigress-cff",
            Self::EmotetCff => "emotet-cff",
            Self::Mirai => "mirai",
            Self::Dridex => "dridex",
            Self::Trickbot => "trickbot",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObfuscatorHit {
    pub family: ObfuscatorFamily,
    pub matched_offset: u64,
    pub indicator: String,
}

#[derive(Debug, Clone, Copy)]
struct FamilySignature {
    family: ObfuscatorFamily,
    pattern: &'static [u8],
    indicator: &'static str,
}

const FAMILY_SIGNATURES: &[FamilySignature] = &[
    FamilySignature {
        family: ObfuscatorFamily::Alcatraz,
        pattern: b"AlcatrazRT",
        indicator: "ALCATRAZ runtime tag (Elastic 2024)",
    },
    FamilySignature {
        family: ObfuscatorFamily::Alcatraz,
        pattern: b"alcatraz.cipher",
        indicator: "ALCATRAZ cipher import",
    },
    FamilySignature {
        family: ObfuscatorFamily::OllvmFlattening,
        pattern: b"switch_var",
        indicator: "OLLVM CFF state-variable name",
    },
    FamilySignature {
        family: ObfuscatorFamily::OllvmFlattening,
        pattern: b"ollvm.fla",
        indicator: "OLLVM flatten pass metadata",
    },
    FamilySignature {
        family: ObfuscatorFamily::OllvmBogusControlFlow,
        pattern: b"ollvm.bcf",
        indicator: "OLLVM bogus-control-flow metadata",
    },
    FamilySignature {
        family: ObfuscatorFamily::OllvmSubstitution,
        pattern: b"ollvm.sub",
        indicator: "OLLVM instruction-substitution metadata",
    },
    FamilySignature {
        family: ObfuscatorFamily::TigressCff,
        pattern: b"_TIGRESS_flatten",
        indicator: "Tigress CFF runtime symbol",
    },
    FamilySignature {
        family: ObfuscatorFamily::EmotetCff,
        pattern: b"EmoCFF",
        indicator: "Emotet CFF marker",
    },
    FamilySignature {
        family: ObfuscatorFamily::Mirai,
        pattern: b"/dev/watchdog",
        indicator: "Mirai watchdog string",
    },
    FamilySignature {
        family: ObfuscatorFamily::Dridex,
        pattern: b"DriDex",
        indicator: "Dridex tag",
    },
    FamilySignature {
        family: ObfuscatorFamily::Trickbot,
        pattern: b"ModuleConfig",
        indicator: "Trickbot module config marker",
    },
];

#[must_use]
pub fn detect(bytes: &[u8]) -> Vec<ObfuscatorHit> {
    let mut out: Vec<ObfuscatorHit> = Vec::new();
    for sig in FAMILY_SIGNATURES {
        if let Some(offset) = memmem(bytes, sig.pattern) {
            out.push(ObfuscatorHit {
                family: sig.family,
                matched_offset: offset as u64,
                indicator: sig.indicator.to_owned(),
            });
        }
    }
    out
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CffUnflattenReport {
    pub original_blocks: u32,
    pub recovered_blocks: u32,
    pub dispatcher_address: Option<u64>,
    pub state_variable_register: Option<String>,
    pub notes: Vec<String>,
}

pub fn unflatten_ollvm_stub() -> Result<CffUnflattenReport> {
    Ok(CffUnflattenReport {
        original_blocks: 0,
        recovered_blocks: 0,
        dispatcher_address: None,
        state_variable_register: None,
        notes: vec![
            "unflattener requires fixture-driven dispatcher inference (FIXTURE PENDING)".to_owned(),
        ],
    })
}

pub fn strip_ollvm_bcf_stub() -> Result<u32> {
    Ok(0)
}

pub fn undo_ollvm_substitution_stub() -> Result<u32> {
    Ok(0)
}

pub fn unflatten_tigress_stub() -> Result<CffUnflattenReport> {
    Ok(CffUnflattenReport {
        original_blocks: 0,
        recovered_blocks: 0,
        dispatcher_address: None,
        state_variable_register: None,
        notes: vec![
            "tigress unflattener requires fixture-driven dispatcher inference (FIXTURE PENDING)"
                .to_owned(),
        ],
    })
}

pub fn undo_emotet_cff_stub() -> Result<u32> {
    Ok(0)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringDecryptHit {
    pub family: ObfuscatorFamily,
    pub address: u64,
    pub recovered: String,
}

pub fn decrypt_strings_for_family(
    family: ObfuscatorFamily,
    encoded: &BTreeMap<u64, Vec<u8>>,
) -> Vec<StringDecryptHit> {
    let mut out: Vec<StringDecryptHit> = Vec::new();
    for (addr, bytes) in encoded {
        let plain: String = match family {
            ObfuscatorFamily::Mirai => xor_decrypt(bytes, &[0x22, 0x54, 0x76, 0xC8]),
            ObfuscatorFamily::Dridex => xor_decrypt(bytes, &[0xDE, 0xAD, 0xBE, 0xEF]),
            ObfuscatorFamily::Trickbot => xor_decrypt(bytes, &[0x4B, 0x53, 0x4E, 0x59]),
            _ => continue,
        };
        out.push(StringDecryptHit {
            family,
            address: *addr,
            recovered: plain,
        });
    }
    out
}

fn xor_decrypt(bytes: &[u8], key: &[u8]) -> String {
    if key.is_empty() {
        return String::new();
    }
    let decoded: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
        .collect();
    String::from_utf8_lossy(&decoded).into_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn alcatraz_runtime_tag_detected() {
        let mut buf: Vec<u8> = vec![0u8; 1024];
        buf[200..210].copy_from_slice(b"AlcatrazRT");
        let hits: Vec<ObfuscatorHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Alcatraz)
        );
    }

    #[test]
    fn ollvm_cff_detected() {
        let mut buf: Vec<u8> = vec![0u8; 256];
        buf[10..20].copy_from_slice(b"switch_var");
        let hits: Vec<ObfuscatorHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::OllvmFlattening)
        );
    }

    #[test]
    fn ollvm_stubs_return_zero() {
        assert_eq!(strip_ollvm_bcf_stub().expect("bcf"), 0);
        assert_eq!(undo_ollvm_substitution_stub().expect("sub"), 0);
        assert_eq!(undo_emotet_cff_stub().expect("emotet"), 0);
        assert_eq!(unflatten_ollvm_stub().expect("cff").recovered_blocks, 0);
    }

    #[test]
    fn mirai_string_xor_round_trip() {
        let plain: &[u8] = b"hello-watchdog";
        let key: [u8; 4] = [0x22, 0x54, 0x76, 0xC8];
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        let mut map: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        map.insert(0x1000, cipher);
        let out: Vec<StringDecryptHit> = decrypt_strings_for_family(ObfuscatorFamily::Mirai, &map);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].recovered, "hello-watchdog");
    }
}
