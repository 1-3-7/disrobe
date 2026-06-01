use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use wait_timeout::ChildExt as _;

use crate::error::{Error, Result};

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

pub mod kkrunchy_reconstruct;

pub use kkrunchy_reconstruct::{
    KkrunchyHeaderReconstructionEmulator, KkrunchyReconstructionConfidence,
    KkrunchyReconstructionPlan,
};

pub mod kkrunchy_cca;

pub use kkrunchy_cca::{KkrunchyClassicStream, decompress_kkrunchy_classic, locate_classic_stream};

pub mod mew_unpack;

pub use mew_unpack::{
    AplibInitialState, AplibTrace, MewImport, MewRecovery, MewUnpackOutput,
    aplib_decode_bytetagged, aplib_decode_bytetagged_lossy, aplib_decode_bytetagged_lossy_with,
    aplib_decode_bytetagged_partial, decode_compressed_payload, unpack_mew,
};

pub use mew_unpack::{MewEmulatedOutput, MewLeadingChunk, MewLzmaProps, unpack_mew_emulated};

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
            Self::Upx => UnpackerStatus::ExternalCliWrap,
            Self::Fsg | Self::Petite | Self::Mpress | Self::Nspack | Self::Mew => {
                UnpackerStatus::Implemented
            }
            Self::Kkrunchy => UnpackerStatus::StubEvalPending,
            Self::AsPack
            | Self::AsProtect
            | Self::Morphine
            | Self::PeCompact
            | Self::YodasCrypter
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
    ExternalCliWrap,
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
        packer: Packer::YodasCrypter,
        pattern: b"yC2.0",
        note: "Yoda's Crypter 2.0 marker",
        confidence: Confidence::High,
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
        packer: Packer::WinLicense,
        pattern: b".winlice",
        note: "WinLicense section",
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpackOutput {
    pub packer: Packer,
    pub status: UnpackerStatus,
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub output_path: Option<String>,
}

#[expect(
    clippy::duration_suboptimal_units,
    reason = "from_mins is unstable (duration_constructors, rust#120301); from_secs is the stable form"
)]
pub fn unpack_with_upx_cli(input: &Path, output: &Path) -> Result<UnpackOutput> {
    let tool: &str = "upx";
    let mut child: std::process::Child = Command::new(tool)
        .arg("-d")
        .arg("-o")
        .arg(output)
        .arg(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e: std::io::Error| match e.kind() {
            std::io::ErrorKind::NotFound => Error::MissingTool(tool.to_owned()),
            _ => Error::Io(e),
        })?;
    let timeout: Duration = Duration::from_secs(60);
    let status: std::process::ExitStatus = match child.wait_timeout(timeout).map_err(Error::Io)? {
        Some(s) => s,
        None => {
            child.kill().ok();
            return Err(Error::BackendTimeout(
                tool.to_owned(),
                timeout.as_millis() as u64,
            ));
        }
    };
    let mut stdout_bytes: Vec<u8> = Vec::new();
    let mut stderr_text: String = String::new();
    if let Some(mut s) = child.stdout.take() {
        std::io::Read::read_to_end(&mut s, &mut stdout_bytes).map_err(Error::Io)?;
    }
    if let Some(mut s) = child.stderr.take() {
        std::io::Read::read_to_string(&mut s, &mut stderr_text).map_err(Error::Io)?;
    }
    if !status.success() {
        return Err(Error::BackendFailed {
            tool: tool.to_owned(),
            status: status.code().unwrap_or(-1),
            stderr: stderr_text,
        });
    }
    Ok(UnpackOutput {
        packer: Packer::Upx,
        status: UnpackerStatus::ExternalCliWrap,
        stdout: stdout_bytes,
        stderr: stderr_text,
        output_path: Some(output.to_string_lossy().into_owned()),
    })
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
    fn upx_cli_missing_path_or_input_yields_actionable_error() {
        let out: Result<UnpackOutput> = unpack_with_upx_cli(
            Path::new("disrobe-native-this-file-does-not-exist.bin"),
            Path::new("out.exe"),
        );
        match out {
            Err(Error::MissingTool(tool)) => assert_eq!(tool, "upx"),
            Err(Error::BackendFailed { tool, .. }) => assert_eq!(tool, "upx"),
            Err(Error::Io(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("must not succeed on missing input"),
        }
    }
}
