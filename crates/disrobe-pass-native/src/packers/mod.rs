use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub mod pe_sections;

pub use pe_sections::{DataDirectory, PeImage, PeSection, parse_pe_image};

pub mod upx_cleanroom;

pub use upx_cleanroom::{UpxMethod, UpxPackHeader, UpxUnpackOutput, unpack_upx};

pub mod petite_unpack;

pub use petite_unpack::{
    RecoveredImport, RecoveredImportFn, UnpackReport as PetiteUnpackReport,
    UnpackResult as PetiteUnpackResult, unpack_petite, unpack_petite_with_report,
};

pub mod petite_phase2;

pub use petite_phase2::{
    PhaseTwoEmulatedOutput as PetitePhase2EmulatedOutput, unpack_petite_phase2_emulated,
};

pub mod fsg_unpack;

pub use fsg_unpack::{FsgImport, FsgUnpackOutput, unpack_fsg};

pub mod mpress_lzma;

pub use mpress_lzma::{MpressLzmaProps, decode_mpress_lzma};

pub mod mpress_unpack;

pub use mpress_unpack::{
    MpressImport, MpressInfo, MpressRecoveryStatus, MpressUnpackOutput, unpack_mpress,
};

pub mod nspack_unpack;

pub use nspack_unpack::{
    NspackEmulatedReport, NspackLayout, NspackSection, NspackUnpackReport, RecoveredResource,
    RecoveredSectionName, RecoveryStatus as NspackRecoveryStatus, parse_nspack_layout,
    unpack_nspack, unpack_nspack_emulated, unpack_nspack_emulated_with_baseline,
    unpack_nspack_emulated_with_baseline_raw,
};

pub mod kkrunchy_unpack;

pub use kkrunchy_unpack::{
    DisFilterStreamSizes, KkrunchyByteRecoveryReport, KkrunchyEmulatedUnpackOutput,
    KkrunchyEmulationSnapshot, KkrunchyEmulator, KkrunchyHeaderInfo, KkrunchyUnpackOutput,
    KkrunchyVariant, compute_byte_recovery, dis_filter, dis_unfilter, parse_kkrunchy_header,
    unpack_kkrunchy, unpack_kkrunchy_emulated,
};

pub mod kkrunchy_cca;

pub use kkrunchy_cca::{KkrunchyClassicStream, decompress_kkrunchy_classic, locate_classic_stream};

pub mod kkrunchy_phase2;

pub use kkrunchy_phase2::{KkrunchyPhaseTwoOutput, unpack_kkrunchy_phase2_emulated};

pub mod mew_unpack;

pub use mew_unpack::{
    AplibInitialState, AplibTrace, MewImport, MewRecovery, MewUnpackOutput,
    aplib_decode_bytetagged, aplib_decode_bytetagged_lossy, aplib_decode_bytetagged_lossy_with,
    aplib_decode_bytetagged_partial, decode_compressed_payload, unpack_mew,
};

pub use mew_unpack::{MewEmulatedOutput, MewLeadingChunk, MewLzmaProps, unpack_mew_emulated};

pub mod yodas_crypter;

pub use yodas_crypter::{
    RecoveredSection, SectionRecovery, YodasCrypterCarve, YodasCrypterReport,
    recover_yodas_crypter_carve, unpack_yodas_crypter,
};

pub mod yodas_protector;

pub use yodas_protector::{CarvedSection, YodasProtectorReport, carve_yodas_protector};

pub mod aspack_unpack;

pub use aspack_unpack::{
    AspackRecovery, AspackReport, CarvedBlock, RecoveredObject, unpack_aspack,
};

pub mod aspack_phase2;

pub use aspack_phase2::{AspackPhaseTwoOutput, unpack_aspack_phase2_emulated};

pub mod pecompact_unpack;

pub use pecompact_unpack::{CarvedCode, PecompactRecovery, PecompactReport, unpack_pecompact};

pub mod pecompact_phase2;

pub use pecompact_phase2::{PecompactPhaseTwoOutput, unpack_pecompact_phase2_emulated};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Packer {
    Upx,
    AsPack,
    AsProtect,
    Petite,
    Mpress,
    Fsg,
    Morphine,
    PeCompact,
    YodasCrypter,
    YodasProtector,
    NPack,
    Nspack,
    NeoLite,
    Mew,
    Kkrunchy,
    PolyCryptor,
    PeProtector,
    PeLock,
    VmProtect,
    Themida,
    EnigmaProtector,
    Armadillo,
    Obsidium,
    WinLicense,
    WarzoneCrypter,
    DotNetPatcher,
    NetCryptor,
}

impl Packer {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Upx => "upx",
            Self::AsPack => "aspack",
            Self::AsProtect => "asprotect",
            Self::Petite => "petite",
            Self::Mpress => "mpress",
            Self::Fsg => "fsg",
            Self::Morphine => "morphine",
            Self::PeCompact => "pecompact",
            Self::YodasCrypter => "yodas-crypter",
            Self::YodasProtector => "yodas-protector",
            Self::NPack => "npack",
            Self::Nspack => "nspack",
            Self::NeoLite => "neolite",
            Self::Mew => "mew",
            Self::Kkrunchy => "kkrunchy",
            Self::PolyCryptor => "polycryptor",
            Self::PeProtector => "pe-protector",
            Self::PeLock => "pelock",
            Self::VmProtect => "vmprotect",
            Self::Themida => "themida",
            Self::EnigmaProtector => "enigma-protector",
            Self::Armadillo => "armadillo",
            Self::Obsidium => "obsidium",
            Self::WinLicense => "winlicense",
            Self::WarzoneCrypter => "warzone-crypter",
            Self::DotNetPatcher => "dotnet-patcher",
            Self::NetCryptor => "netcryptor",
        }
    }

    #[must_use]
    pub const fn is_grey_zone(self) -> bool {
        matches!(
            self,
            Self::PeProtector
                | Self::PeLock
                | Self::VmProtect
                | Self::Themida
                | Self::EnigmaProtector
                | Self::Armadillo
                | Self::Obsidium
                | Self::WinLicense
        )
    }

    #[must_use]
    pub const fn unpacker_status(self) -> UnpackerStatus {
        match self {
            Self::Upx
            | Self::Fsg
            | Self::Petite
            | Self::Mpress
            | Self::Nspack
            | Self::Mew
            | Self::AsPack
            | Self::PeCompact
            | Self::YodasCrypter
            | Self::Kkrunchy => UnpackerStatus::Implemented,
            Self::AsProtect
            | Self::Morphine
            | Self::YodasProtector
            | Self::NPack
            | Self::NeoLite => UnpackerStatus::StubEvalPending,
            Self::PolyCryptor | Self::WarzoneCrypter | Self::DotNetPatcher | Self::NetCryptor => {
                UnpackerStatus::DetectOnly
            }
            Self::PeProtector
            | Self::PeLock
            | Self::EnigmaProtector
            | Self::Armadillo
            | Self::Obsidium
            | Self::WinLicense => UnpackerStatus::GreyZoneDetectOnly,
            Self::VmProtect | Self::Themida => UnpackerStatus::GreyZoneDetectAndCarve,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnpackerStatus {
    Implemented,
    StubEvalPending,
    DetectOnly,
    GreyZoneDetectOnly,
    GreyZoneDetectAndCarve,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    pub packer: Packer,
    pub confidence: Confidence,
    pub matched_offset: Option<u64>,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy)]
pub struct Signature {
    pub packer: Packer,
    pub pattern: &'static [u8],
    pub note: &'static str,
    pub confidence: Confidence,
}

const SIGNATURES: &[Signature] = &[
    Signature {
        packer: Packer::Upx,
        pattern: b"UPX!",
        note: "UPX section/magic marker",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Upx,
        pattern: b"UPX0",
        note: "UPX0 section name",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Upx,
        pattern: b"UPX1",
        note: "UPX1 section name",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::AsPack,
        pattern: b".aspack",
        note: "ASPack section name",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::AsPack,
        pattern: b".adata",
        note: "ASPack data section",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::AsPack,
        pattern: &[
            0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB, 0x04, 0x5D, 0x45, 0x55, 0xC3,
        ],
        note: "ASPack 2.x EP stub (pushad; call $+8; jmp; pop ebp; inc ebp; push ebp; ret)",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::AsProtect,
        pattern: b".asprotect",
        note: "ASProtect section name",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Petite,
        pattern: b".petite",
        note: "Petite section name (dot-prefixed variant)",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Petite,
        pattern: b"petite\x00\x00",
        note: "Petite section name (bare, NUL-padded - 2.x default)",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Mpress,
        pattern: b".MPRESS1",
        note: "MPRESS section name",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Mpress,
        pattern: b".MPRESS2",
        note: "MPRESS section name (variant)",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Fsg,
        pattern: b"FSG!",
        note: "FSG entry-point magic (1.x)",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Fsg,
        pattern: &[
            0xE8, 0x0A, 0x00, 0x00, 0x00, 0x02, 0xD2, 0x75, 0x05, 0x8A, 0x16, 0x46, 0x12, 0xD2,
            0xC3,
        ],
        note: "FSG 2.0 getbit-helper stub prologue (CALL +0x0A; add dl,dl; jnz; mov dl,[esi]; inc esi; adc dl,dl; ret)",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Morphine,
        pattern: b"morphine",
        note: "Morphine signature",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::PeCompact,
        pattern: b"PEC2",
        note: "PECompact v2 stub",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::PeCompact,
        pattern: b"PECompact2",
        note: "PECompact 2 marker",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::PeCompact,
        pattern: &[
            0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0x64,
            0x89, 0x25, 0x00, 0x00, 0x00, 0x00,
        ],
        note: "PECompact2 SEH-install prologue (mov eax,imm; push eax; push fs:[0]; mov fs:[0],esp)",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::YodasCrypter,
        pattern: b"yC2.0",
        note: "Yoda's Crypter 2.0 marker",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::YodasCrypter,
        pattern: &[
            0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x00, 0x00, 0x00, 0x00, 0x8D,
            0xB5,
        ],
        note: "Yoda's Crypter 1.2 EP delta prologue + LEA ESI decrypt-loop setup (corroboration only)",
        confidence: Confidence::Low,
    },
    Signature {
        packer: Packer::YodasProtector,
        pattern: b"yP1.0",
        note: "Yoda's Protector 1.0 marker",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::NPack,
        pattern: b".nPack",
        note: "nPack section name",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Nspack,
        pattern: b"nsp0",
        note: "NSPack section name nsp0 (decompressor stub host)",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Nspack,
        pattern: b"nsp1",
        note: "NSPack section name nsp1 (compressed payload + rebuilt IAT)",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Nspack,
        pattern: b"nsp2",
        note: "NSPack section name nsp2 (3-section layout variant)",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::NeoLite,
        pattern: b"neolite",
        note: "NeoLite signature",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::Mew,
        pattern: b"MEW",
        note: "MEW magic",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::PolyCryptor,
        pattern: b"PolyCryptor",
        note: "PolyCryptor identifier",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::PeProtector,
        pattern: b".pec1",
        note: "PE Protector",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::PeLock,
        pattern: b"PELock",
        note: "PELock identifier",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::VmProtect,
        pattern: b".vmp0",
        note: "VMProtect section .vmp0",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::VmProtect,
        pattern: b".vmp1",
        note: "VMProtect section .vmp1",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Themida,
        pattern: b".themida",
        note: "Themida section name",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Themida,
        pattern: b".winlice",
        note: "WinLicense/Themida shared section",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::EnigmaProtector,
        pattern: b".enigma",
        note: "Enigma Protector section",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::EnigmaProtector,
        pattern: b"Enigma protector",
        note: "Enigma Protector overlay version-blob literal",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::Armadillo,
        pattern: b"ARMADILLO",
        note: "Armadillo marker",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::Obsidium,
        pattern: b"Obsidium",
        note: "Obsidium identifier",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::Obsidium,
        pattern: &[0xEB, 0x02, 0x00, 0x00, 0xE8, 0x24, 0x00, 0x00, 0x00],
        note: "Obsidium 1.3/1.4 EP stub (jmp $+4 over junk; call $+0x29)",
        confidence: Confidence::Low,
    },
    Signature {
        packer: Packer::WinLicense,
        pattern: b".winlice",
        note: "WinLicense section",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::WinLicense,
        pattern: b"WinLicense",
        note: "WinLicense embedded product literal",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::WarzoneCrypter,
        pattern: b"WarzoneRAT",
        note: "Warzone family marker",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::DotNetPatcher,
        pattern: b"DNPatcher",
        note: "DotNetPatcher marker",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::NetCryptor,
        pattern: b"NETCryptor",
        note: "NetCryptor marker",
        confidence: Confidence::Medium,
    },
    Signature {
        packer: Packer::Kkrunchy,
        pattern: b"MZfarbrausch",
        note: "kkrunchy MZ-header farbrausch tag (k7 + classic 0.23a/a2)",
        confidence: Confidence::High,
    },
    Signature {
        packer: Packer::Kkrunchy,
        pattern: b"kkrunchy",
        note: "kkrunchy section name (single packed section)",
        confidence: Confidence::High,
    },
];

#[must_use]
pub fn detect(bytes: &[u8]) -> Vec<Detection> {
    let mut found: BTreeMap<Packer, Detection> = BTreeMap::new();
    for sig in SIGNATURES {
        if let Some(offset) = memmem_find(bytes, sig.pattern) {
            let existing: Option<&Detection> = found.get(&sig.packer);
            if existing.map_or(true, |prev: &Detection| {
                confidence_rank(prev.confidence) < confidence_rank(sig.confidence)
            }) {
                found.insert(
                    sig.packer,
                    Detection {
                        packer: sig.packer,
                        confidence: sig.confidence,
                        matched_offset: Some(offset as u64),
                        note: sig.note.to_owned(),
                    },
                );
            }
        }
    }
    found.into_values().collect()
}

#[must_use]
pub fn fingerprint_chain(bytes: &[u8]) -> Vec<Detection> {
    detect(bytes)
}

const fn confidence_rank(c: Confidence) -> u8 {
    match c {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

fn memmem_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn upx_signature_detected() {
        let mut buf: Vec<u8> = vec![0u8; 256];
        buf[100..104].copy_from_slice(b"UPX!");
        let hits: Vec<Detection> = detect(&buf);
        assert!(hits.iter().any(|h: &Detection| h.packer == Packer::Upx));
    }

    #[test]
    fn aspack_signature_detected() {
        let mut buf: Vec<u8> = vec![0u8; 256];
        buf[50..57].copy_from_slice(b".aspack");
        let hits: Vec<Detection> = detect(&buf);
        assert!(hits.iter().any(|h: &Detection| h.packer == Packer::AsPack));
    }

    #[test]
    fn fsg2_getbit_helper_stub_detected() {
        let helper: [u8; 15] = [
            0xE8, 0x0A, 0x00, 0x00, 0x00, 0x02, 0xD2, 0x75, 0x05, 0x8A, 0x16, 0x46, 0x12, 0xD2,
            0xC3,
        ];
        let mut buf: Vec<u8> = vec![0u8; 1024];
        buf[528..528 + helper.len()].copy_from_slice(&helper);
        let hits: Vec<Detection> = detect(&buf);
        assert!(
            hits.iter().any(|h: &Detection| h.packer == Packer::Fsg),
            "FSG 2.0 fixtures carry no FSG! literal; the getbit-helper stub prologue must trigger detection",
        );
    }

    #[test]
    fn no_signatures_in_random_returns_empty() {
        let buf: Vec<u8> = vec![0x55u8; 1024];
        let hits: Vec<Detection> = detect(&buf);
        assert!(hits.is_empty());
    }

    #[test]
    fn vmprotect_grey_zone_is_carve_and_detect() {
        let mut buf: Vec<u8> = vec![0u8; 64];
        buf[10..15].copy_from_slice(b".vmp0");
        let hits: Vec<Detection> = detect(&buf);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].packer, Packer::VmProtect);
        assert_eq!(
            Packer::VmProtect.unpacker_status(),
            UnpackerStatus::GreyZoneDetectAndCarve
        );
        assert!(Packer::VmProtect.is_grey_zone());
    }

    #[test]
    fn themida_grey_zone_is_carve_and_detect() {
        let mut buf: Vec<u8> = vec![0u8; 64];
        buf[5..13].copy_from_slice(b".themida");
        let hits: Vec<Detection> = detect(&buf);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].packer, Packer::Themida);
    }

    #[test]
    fn confidence_dedup_promotes_high_over_medium() {
        let mut buf: Vec<u8> = vec![0u8; 1024];
        buf[10..18].copy_from_slice(b".MPRESS1");
        let hits: Vec<Detection> = detect(&buf);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].confidence, Confidence::High);
    }

    #[test]
    fn fingerprint_chain_returns_all_matches() {
        let mut buf: Vec<u8> = vec![0u8; 1024];
        buf[10..14].copy_from_slice(b"UPX!");
        buf[40..47].copy_from_slice(b".aspack");
        let hits: Vec<Detection> = fingerprint_chain(&buf);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn aspack_ep_stub_detected() {
        let stub: [u8; 13] = [
            0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB, 0x04, 0x5D, 0x45, 0x55, 0xC3,
        ];
        let mut buf: Vec<u8> = vec![0u8; 512];
        buf[64..64 + stub.len()].copy_from_slice(&stub);
        let hits: Vec<Detection> = detect(&buf);
        assert!(hits.iter().any(|h: &Detection| h.packer == Packer::AsPack));
    }

    #[test]
    fn pecompact_seh_prologue_detected() {
        let stub: [u8; 20] = [
            0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0x64,
            0x89, 0x25, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut buf: Vec<u8> = vec![0u8; 512];
        buf[64..64 + stub.len()].copy_from_slice(&stub);
        let hits: Vec<Detection> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &Detection| h.packer == Packer::PeCompact)
        );
    }

    #[test]
    fn obsidium_ep_stub_detected() {
        let stub: [u8; 9] = [0xEB, 0x02, 0x00, 0x00, 0xE8, 0x24, 0x00, 0x00, 0x00];
        let mut buf: Vec<u8> = vec![0u8; 512];
        buf[64..64 + stub.len()].copy_from_slice(&stub);
        let hits: Vec<Detection> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &Detection| h.packer == Packer::Obsidium)
        );
    }

    #[test]
    fn enigma_overlay_literal_detected() {
        let mut buf: Vec<u8> = vec![0u8; 512];
        buf[64..64 + b"Enigma protector".len()].copy_from_slice(b"Enigma protector");
        let hits: Vec<Detection> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &Detection| h.packer == Packer::EnigmaProtector)
        );
    }

    #[test]
    fn winlicense_literal_detected() {
        let mut buf: Vec<u8> = vec![0u8; 512];
        buf[64..64 + b"WinLicense".len()].copy_from_slice(b"WinLicense");
        let hits: Vec<Detection> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &Detection| h.packer == Packer::WinLicense)
        );
    }

    #[test]
    fn yodas_crypter_ep_stub_detected() {
        let stub: [u8; 15] = [
            0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x00, 0x00, 0x00, 0x00, 0x8D,
            0xB5,
        ];
        let mut buf: Vec<u8> = vec![0u8; 512];
        buf[64..64 + stub.len()].copy_from_slice(&stub);
        let hits: Vec<Detection> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &Detection| h.packer == Packer::YodasCrypter)
        );
    }

    #[test]
    fn shared_delta_prologue_does_not_false_positive_high() {
        let bare: [u8; 9] = [0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED];
        let mut buf: Vec<u8> = vec![0u8; 512];
        buf[32..32 + bare.len()].copy_from_slice(&bare);
        let hits: Vec<Detection> = detect(&buf);
        assert!(
            !hits
                .iter()
                .any(|h: &Detection| h.confidence == Confidence::High),
            "bare shared delta prologue must never yield a High-confidence family detection",
        );
    }
}
