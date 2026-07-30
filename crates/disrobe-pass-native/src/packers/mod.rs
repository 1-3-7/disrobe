use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub mod pe_sections;

pub use pe_sections::{DataDirectory, PeImage, PeSection, parse_pe_image};

pub mod pe_resource;

pub use pe_resource::{
    ForcedPlacement, ResourceDirectoryNode, ResourceKey, ResourceLeaf, ResourceTree,
    canonical_structure_bytes, forced_leaf_placements, parse_resource_tree,
};

pub mod section_recovery;

pub use section_recovery::{
    GranuleRecovery, IatReconstructionReport, SectionRecoveryReport, SectionRole,
    build_loaded_image, file_image_section_report, reconstruct_import_address_table,
    section_recovery_report,
};

pub mod pe_unbind;

pub use pe_unbind::{UnbindReport, unbind_pe};

pub mod emulated_unpack;

pub use emulated_unpack::{EmulatedUnpack, EmulationConfig, emulate_unpack_stub};

pub mod stub_pack_oracle;

pub mod overlay;

pub use overlay::{
    ArchiveKind, CertType, OverlayClass, OverlaySegment, PeOverlayReport, analyze_pe_overlay,
    carve_overlay, compute_image_end, normalize_pe, route_overlay_archive,
};

pub mod overlay_extent;

pub use overlay_extent::archive_true_extent;

pub mod upx_decoder;

pub use upx_decoder::{UpxMethod, UpxPackHeader, UpxUnpackOutput, unpack_upx};

pub mod upx_go_chain;

pub use upx_go_chain::{
    GoRuntimeEvidence, UpxGoChainOutput, detect_upx_packed_go, scan_go_runtime, unpack_upx_go_chain,
};

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

pub use fsg_unpack::{FsgBlock, FsgImport, FsgUnpackOutput, unpack_fsg};

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

pub mod kkrunchy_k7_cm;

pub use kkrunchy_k7_cm::rangecoder_depack;

pub mod kkrunchy_phase2;

pub use kkrunchy_phase2::{KkrunchyPhaseTwoOutput, unpack_kkrunchy_phase2_emulated};

pub mod kkrunchy_k7_phase2;

pub use kkrunchy_k7_phase2::{KkrunchyK7Output, unpack_kkrunchy_k7_emulated};

pub mod mew_unpack;

pub use mew_unpack::{
    AplibInitialState, AplibTrace, MewImport, MewRecovery, MewUnpackOutput,
    aplib_decode_bytetagged, aplib_decode_bytetagged_lossy, aplib_decode_bytetagged_lossy_with,
    aplib_decode_bytetagged_partial, decode_compressed_payload, unpack_mew,
};

pub use mew_unpack::{
    MewEmulatedOutput, MewLeadingChunk, MewLzmaProps, MewRebuiltImage, unpack_mew_emulated,
    unpack_mew_rebuilt,
};

pub mod yodas_crypter;

pub use yodas_crypter::{
    RecoveredSection, SectionRecovery, YodasCrypterCarve, YodasCrypterReport,
    recover_yodas_crypter_carve, unpack_yodas_crypter,
};

pub mod yodas_protector;

pub use yodas_protector::{CarvedSection, YodasProtectorReport, carve_yodas_protector};

pub mod yodas_protector_phase2;

pub use yodas_protector_phase2::{
    StubProgress, YodasProtectorPhase2, unpack_yodas_protector_phase2,
};

pub mod yodas_emulated_unpack;

pub use yodas_emulated_unpack::{
    DESCRIPTOR_TABLE_TAG, YODAS_DELTA_PROLOGUE, YODAS_STUB_SECTION, YodasEmulatedUnpack,
    YodasSectionDescriptor, YodasStubProgress, unpack_yodas_emulated,
};

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

pub mod chain_sigs;

pub use chain_sigs::{
    CHAIN_SIGNATURES, ChainConfidenceScore, ChainDetection, ChainSignature, StageConfidence,
    detect_packer_chain,
};

pub mod vmprotect_carve;

pub use vmprotect_carve::{
    CarvedVmpSection, SectionPerms, SyntheticImport, VmProtectCarve, carve_vmprotect,
};

pub mod themida_carve;

pub use themida_carve::{OreansProduct, ThemidaCarve, carve_themida};

pub mod asprotect_unpack;

pub use asprotect_unpack::{
    AsProtectLayout, AsProtectRecovery, asprotect_layout, unpack_asprotect,
    unpack_asprotect_emulated,
};

pub mod morphine_unpack;

pub use morphine_unpack::{
    MorphineLayout, MorphineRecovery, morphine_layout, unpack_morphine, unpack_morphine_emulated,
};

pub mod npack_unpack;

pub use npack_unpack::{
    NPackLayout, NPackRecovery, npack_layout, unpack_npack, unpack_npack_emulated,
};

pub mod neolite_unpack;

pub use neolite_unpack::{
    NeoLiteLayout, NeoLiteRecovery, neolite_layout, unpack_neolite, unpack_neolite_emulated,
};

pub mod polycryptor_unpack;

pub use polycryptor_unpack::{
    PolyCryptorLayout, PolyCryptorRecovery, polycryptor_layout, unpack_polycryptor,
    unpack_polycryptor_emulated,
};

pub mod warzone_crypter_unpack;

pub use warzone_crypter_unpack::{
    WarzoneCrypterLayout, WarzoneCrypterRecovery, unpack_warzone_crypter,
    unpack_warzone_crypter_emulated, warzone_crypter_layout,
};

pub mod recovered_image;

pub use recovered_image::{
    CarvedSectionArtifact, RecoveredImage, RecoveryOracle, recover_detected,
};

pub mod loader_generators;

pub use loader_generators::{
    ByteRegion, DonutCompression, DonutConfig, DonutEntropy, DonutModuleType, LoaderArchitecture,
    LoaderConfig, LoaderFamily, LoaderFingerprint, LoaderInspection, LoaderRecovery, LoaderVariant,
    RecoveryField, SrdiConfig, WrappedModuleFormat, WrappedModuleMetadata, fingerprint_loader,
    recover_loader,
};

macro_rules! packer_families {
    ($($variant:ident => $label:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "kebab-case")]
        pub enum Packer {
            $($variant,)+
        }

        impl Packer {
            pub const ALL: &[Self] = &[$(Self::$variant,)+];

            #[must_use]
            pub const fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }
        }
    };
}

packer_families! {
    Donut => "donut",
    Srdi => "srdi",
    Upx => "upx",
    AsPack => "aspack",
    AsProtect => "asprotect",
    Petite => "petite",
    Mpress => "mpress",
    Fsg => "fsg",
    Morphine => "morphine",
    PeCompact => "pecompact",
    YodasCrypter => "yodas-crypter",
    YodasProtector => "yodas-protector",
    NPack => "npack",
    Nspack => "nspack",
    NeoLite => "neolite",
    Mew => "mew",
    Kkrunchy => "kkrunchy",
    PolyCryptor => "polycryptor",
    PeProtector => "pe-protector",
    PeLock => "pelock",
    VmProtect => "vmprotect",
    Themida => "themida",
    EnigmaProtector => "enigma-protector",
    Armadillo => "armadillo",
    Obsidium => "obsidium",
    WinLicense => "winlicense",
    WarzoneCrypter => "warzone-crypter",
    DotNetPatcher => "dotnet-patcher",
    NetCryptor => "netcryptor",
}

impl Packer {
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
                | Self::YodasProtector
        )
    }

    #[must_use]
    pub const fn unpacker_status(self) -> UnpackerStatus {
        match self {
            Self::Donut
            | Self::Srdi
            | Self::Upx
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
            | Self::NPack
            | Self::PolyCryptor
            | Self::WarzoneCrypter
            | Self::NeoLite => UnpackerStatus::StubEvalPending,
            Self::DotNetPatcher | Self::NetCryptor => UnpackerStatus::DelegatedToDotnet,
            Self::PeProtector
            | Self::PeLock
            | Self::EnigmaProtector
            | Self::Armadillo
            | Self::Obsidium
            | Self::WinLicense => UnpackerStatus::GreyZoneDetectOnly,
            Self::VmProtect | Self::Themida | Self::YodasProtector => {
                UnpackerStatus::GreyZoneDetectAndCarve
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnpackerStatus {
    Implemented,
    StubEvalPending,
    DelegatedToDotnet,
    DetectOnly,
    GreyZoneDetectOnly,
    GreyZoneDetectAndCarve,
}

impl UnpackerStatus {
    #[must_use]
    pub const fn wall_reason(self) -> &'static str {
        match self {
            Self::Implemented => "recovery attempted",
            Self::StubEvalPending => {
                "stub emulator validated byte-exact on spec-constructed and polymorphic stubs, but \
                 real-sample recovery is unproven (no vendor-packed sample in corpus); a captured \
                 sample layers native-VM stub virtualization plus a runtime-rebuilt import table \
                 over the core decrypt-to-oep shape"
            }
            Self::DelegatedToDotnet => {
                "managed CLR wrapper: native.packer-unpack does not own this recovery; route the \
                 same image through dotnet.classify for managed metadata, constants, strings, and \
                 IL body recovery"
            }
            Self::DetectOnly => {
                "method bodies are decrypted by a key derived inside the managed runtime at jit \
                 time; that key is absent from the on-disk image (runtime-key wall)"
            }
            Self::GreyZoneDetectOnly => {
                "commercial protector with a runtime-only key and native-virtualized stub; no \
                 static body recovery exists (detect-only runtime-key/native-VM wall)"
            }
            Self::GreyZoneDetectAndCarve => {
                "native-VM virtualized protector; static recovery is bounded to detect-and-carve \
                 (devirtualization is a vmprotect/themida-tier wall)"
            }
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchScope {
    Anywhere,
    SectionName,
}

#[derive(Debug, Clone, Copy)]
pub struct Signature {
    pub packer: Packer,
    pub pattern: &'static [u8],
    pub note: &'static str,
    pub confidence: Confidence,
    pub scope: MatchScope,
}

const SIGNATURES: &[Signature] = &[
    Signature {
        packer: Packer::Upx,
        pattern: b"UPX!",
        note: "UPX section/magic marker",
        confidence: Confidence::High,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::Upx,
        pattern: b"UPX0",
        note: "UPX0 section name",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::Upx,
        pattern: b"UPX1",
        note: "UPX1 section name",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::AsPack,
        pattern: b".aspack",
        note: "ASPack section name",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::AsPack,
        pattern: b".adata",
        note: "ASPack data section",
        confidence: Confidence::Medium,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::AsPack,
        pattern: &[
            0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB, 0x04, 0x5D, 0x45, 0x55, 0xC3,
        ],
        note: "ASPack 2.x EP stub (pushad; call $+8; jmp; pop ebp; inc ebp; push ebp; ret)",
        confidence: Confidence::High,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::AsProtect,
        pattern: b".asprotect",
        note: "ASProtect embedded literal (exceeds 8-byte PE section-name field)",
        confidence: Confidence::High,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::Petite,
        pattern: b".petite",
        note: "Petite section name (dot-prefixed variant)",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::Petite,
        pattern: b"petite\x00\x00",
        note: "Petite section name (bare, NUL-padded - 2.x default)",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::Mpress,
        pattern: b".MPRESS1",
        note: "MPRESS section name",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::Mpress,
        pattern: b".MPRESS2",
        note: "MPRESS section name (variant)",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::Fsg,
        pattern: b"FSG!",
        note: "FSG entry-point magic (1.x)",
        confidence: Confidence::High,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::Fsg,
        pattern: &[
            0xE8, 0x0A, 0x00, 0x00, 0x00, 0x02, 0xD2, 0x75, 0x05, 0x8A, 0x16, 0x46, 0x12, 0xD2,
            0xC3,
        ],
        note: "FSG 2.0 getbit-helper stub prologue (CALL +0x0A; add dl,dl; jnz; mov dl,[esi]; inc esi; adc dl,dl; ret)",
        confidence: Confidence::High,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::Morphine,
        pattern: b"morphine",
        note: "Morphine signature",
        confidence: Confidence::Medium,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::PeCompact,
        pattern: b"PEC2",
        note: "PECompact v2 stub",
        confidence: Confidence::High,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::PeCompact,
        pattern: b"PECompact2",
        note: "PECompact 2 marker",
        confidence: Confidence::High,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::PeCompact,
        pattern: &[
            0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0x64,
            0x89, 0x25, 0x00, 0x00, 0x00, 0x00,
        ],
        note: "PECompact2 SEH-install prologue (mov eax,imm; push eax; push fs:[0]; mov fs:[0],esp)",
        confidence: Confidence::Medium,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::YodasCrypter,
        pattern: b"yC2.0",
        note: "Yoda's Crypter 2.0 marker",
        confidence: Confidence::High,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::YodasCrypter,
        pattern: &[
            0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x00, 0x00, 0x00, 0x00, 0x8D,
            0xB5,
        ],
        note: "Yoda's Crypter 1.2 EP delta prologue + LEA ESI decrypt-loop setup (corroboration only)",
        confidence: Confidence::Low,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::YodasProtector,
        pattern: b"yP1.0",
        note: "Yoda's Protector 1.0 marker",
        confidence: Confidence::High,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::NPack,
        pattern: b".nPack",
        note: "nPack section name",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::Nspack,
        pattern: b"nsp0",
        note: "NSPack section name nsp0 (decompressor stub host)",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::Nspack,
        pattern: b"nsp1",
        note: "NSPack section name nsp1 (compressed payload + rebuilt IAT)",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::Nspack,
        pattern: b"nsp2",
        note: "NSPack section name nsp2 (3-section layout variant)",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::NeoLite,
        pattern: b"neolite",
        note: "NeoLite signature",
        confidence: Confidence::Medium,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::Mew,
        pattern: b"MEW",
        note: "MEW section-0 name prefix (MEW 11 SE first section is named MEW)",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::PolyCryptor,
        pattern: b"PolyCryptor",
        note: "PolyCryptor identifier",
        confidence: Confidence::Medium,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::PeProtector,
        pattern: b".pec1",
        note: "PE Protector",
        confidence: Confidence::Medium,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::PeLock,
        pattern: b"PELock",
        note: "PELock identifier",
        confidence: Confidence::Medium,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::VmProtect,
        pattern: b".vmp0",
        note: "VMProtect section .vmp0",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::VmProtect,
        pattern: b".vmp1",
        note: "VMProtect section .vmp1",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::Themida,
        pattern: b".themida",
        note: "Themida section name",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::Themida,
        pattern: b".winlice",
        note: "WinLicense/Themida shared section",
        confidence: Confidence::Medium,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::EnigmaProtector,
        pattern: b".enigma",
        note: "Enigma Protector section",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::EnigmaProtector,
        pattern: b"Enigma protector",
        note: "Enigma Protector overlay version-blob literal",
        confidence: Confidence::Medium,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::Armadillo,
        pattern: b"ARMADILLO",
        note: "Armadillo marker",
        confidence: Confidence::Medium,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::Obsidium,
        pattern: b"Obsidium",
        note: "Obsidium identifier",
        confidence: Confidence::Medium,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::Obsidium,
        pattern: &[0xEB, 0x02, 0x00, 0x00, 0xE8, 0x24, 0x00, 0x00, 0x00],
        note: "Obsidium 1.3/1.4 EP stub (jmp $+4 over junk; call $+0x29)",
        confidence: Confidence::Low,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::WinLicense,
        pattern: b".winlice",
        note: "WinLicense section",
        confidence: Confidence::Medium,
        scope: MatchScope::SectionName,
    },
    Signature {
        packer: Packer::WinLicense,
        pattern: b"WinLicense",
        note: "WinLicense embedded product literal",
        confidence: Confidence::Medium,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::WarzoneCrypter,
        pattern: b"WarzoneRAT",
        note: "Warzone family marker",
        confidence: Confidence::Medium,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::DotNetPatcher,
        pattern: b"DNPatcher",
        note: "DotNetPatcher marker",
        confidence: Confidence::Medium,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::NetCryptor,
        pattern: b"NETCryptor",
        note: "NetCryptor marker",
        confidence: Confidence::Medium,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::Kkrunchy,
        pattern: b"MZfarbrausch",
        note: "kkrunchy MZ-header farbrausch tag (k7 + classic 0.23a/a2)",
        confidence: Confidence::High,
        scope: MatchScope::Anywhere,
    },
    Signature {
        packer: Packer::Kkrunchy,
        pattern: b"kkrunchy",
        note: "kkrunchy section name (single packed section)",
        confidence: Confidence::High,
        scope: MatchScope::SectionName,
    },
];

#[must_use]
pub fn detect(bytes: &[u8]) -> Vec<Detection> {
    let mut found: BTreeMap<Packer, Detection> = BTreeMap::new();
    if let Some(loader) = fingerprint_loader(bytes) {
        let packer: Packer = match loader.family {
            LoaderFamily::Donut => Packer::Donut,
            LoaderFamily::Srdi => Packer::Srdi,
        };
        found.insert(
            packer,
            Detection {
                packer,
                confidence: Confidence::High,
                matched_offset: Some(loader.matched_offset),
                note: format!(
                    "{} loader config offset={} length={} and wrapped module offset={} length={} validated",
                    packer.label(),
                    loader.config_region.offset,
                    loader.config_region.length,
                    loader.wrapped_module_region.offset,
                    loader.wrapped_module_region.length,
                ),
            },
        );
    }
    if crate::format::detect(bytes).is_err() {
        return found.into_values().collect();
    }
    let pe: Option<PeImage> = parse_pe_image(bytes).ok();
    for sig in SIGNATURES {
        let Some(offset): Option<u64> = match_offset(bytes, pe.as_ref(), sig) else {
            continue;
        };
        let existing: Option<&Detection> = found.get(&sig.packer);
        if existing.map_or(true, |prev: &Detection| {
            confidence_rank(prev.confidence) < confidence_rank(sig.confidence)
        }) {
            found.insert(
                sig.packer,
                Detection {
                    packer: sig.packer,
                    confidence: sig.confidence,
                    matched_offset: Some(offset),
                    note: sig.note.to_owned(),
                },
            );
        }
    }
    if found.is_empty()
        && let Some(detection) = detect_upx_structural(bytes)
    {
        found.insert(Packer::Upx, detection);
    }
    found.into_values().collect()
}

fn detect_upx_structural(bytes: &[u8]) -> Option<Detection> {
    let header: UpxPackHeader = UpxPackHeader::locate_and_parse(bytes).ok()?;
    Some(Detection {
        packer: Packer::Upx,
        confidence: Confidence::Medium,
        matched_offset: Some(header.header_offset as u64),
        note: "UPX PackHeader recovered structurally (marker/section names scrambled)".to_owned(),
    })
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

fn match_offset(bytes: &[u8], pe: Option<&PeImage>, sig: &Signature) -> Option<u64> {
    match sig.scope {
        MatchScope::Anywhere => memmem_find(bytes, sig.pattern).map(|o: usize| o as u64),
        MatchScope::SectionName => section_name_match(pe?, sig.pattern),
    }
}

fn section_name_match(pe: &PeImage, pattern: &[u8]) -> Option<u64> {
    let trimmed_pattern: &[u8] = trim_trailing_nul(pattern);
    pe.sections
        .iter()
        .find(|s: &&PeSection| s.name_trimmed() == trimmed_pattern)
        .map(|s: &PeSection| u64::from(s.raw_pointer))
}

#[inline]
fn trim_trailing_nul(bytes: &[u8]) -> &[u8] {
    let end: usize = bytes
        .iter()
        .rposition(|b: &u8| *b != 0)
        .map_or(0, |i: usize| i + 1);
    &bytes[..end]
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const EVERY_PACKER: [Packer; 29] = [
        Packer::Donut,
        Packer::Srdi,
        Packer::Upx,
        Packer::AsPack,
        Packer::AsProtect,
        Packer::Petite,
        Packer::Mpress,
        Packer::Fsg,
        Packer::Morphine,
        Packer::PeCompact,
        Packer::YodasCrypter,
        Packer::YodasProtector,
        Packer::NPack,
        Packer::Nspack,
        Packer::NeoLite,
        Packer::Mew,
        Packer::Kkrunchy,
        Packer::PolyCryptor,
        Packer::PeProtector,
        Packer::PeLock,
        Packer::VmProtect,
        Packer::Themida,
        Packer::EnigmaProtector,
        Packer::Armadillo,
        Packer::Obsidium,
        Packer::WinLicense,
        Packer::WarzoneCrypter,
        Packer::DotNetPatcher,
        Packer::NetCryptor,
    ];

    fn or_none(labels: &[&'static str]) -> String {
        if labels.is_empty() {
            "none".to_owned()
        } else {
            labels.join(", ")
        }
    }

    fn roster_drift(roster: &[Packer]) -> Option<String> {
        let published: usize = roster.len();
        let carried: usize = Packer::ALL.len();
        let mut listed: BTreeSet<&'static str> = BTreeSet::new();
        let mut repeated: Vec<&'static str> = Vec::new();
        for packer in roster {
            if !listed.insert(packer.label()) {
                repeated.push(packer.label());
            }
        }
        let carried_labels: BTreeSet<&'static str> = Packer::ALL
            .iter()
            .map(|packer: &Packer| packer.label())
            .collect();
        let absent: Vec<&'static str> = carried_labels.difference(&listed).copied().collect();
        let unknown: Vec<&'static str> = listed.difference(&carried_labels).copied().collect();
        if published == carried && absent.is_empty() && unknown.is_empty() && repeated.is_empty() {
            return None;
        }
        Some(format!(
            "the roster in this file lists {published} packer families and every published packer \
             total is derived from its length, but the `Packer` enum carries {carried}: README.md \
             publishes `Packers ({published} families)` and docs/src/catalog.md publishes a \
             five-tier split summing to {published}, so both pages are stale. Carried by the enum \
             and absent from the roster: {}. Named by the roster and absent from the enum: {}. \
             Listed twice: {}. Put every new variant in EVERY_PACKER and in one tier list below \
             it, then move the two published totals with it.",
            or_none(&absent),
            or_none(&unknown),
            or_none(&repeated),
        ))
    }

    #[test]
    fn the_roster_lists_every_packer_the_enum_carries() {
        if let Some(report) = roster_drift(&EVERY_PACKER) {
            panic!("{report}");
        }
    }

    #[test]
    fn a_roster_lagging_the_enum_reports_the_published_total_as_stale() {
        let lagging: Vec<Packer> = EVERY_PACKER
            .into_iter()
            .filter(|packer: &Packer| *packer != Packer::NetCryptor)
            .collect();
        let report: String = roster_drift(&lagging)
            .expect("a roster one variant short of the enum must be reported, not passed over");
        for expected in [
            "the roster in this file lists 28 packer families",
            "the `Packer` enum carries 29",
            "README.md publishes `Packers (28 families)`",
            "docs/src/catalog.md publishes a five-tier split summing to 28",
            "absent from the roster: netcryptor",
        ] {
            assert!(
                report.contains(expected),
                "the drift report must state `{expected}`, got: {report}"
            );
        }
    }

    #[test]
    fn published_tier_counts_match_this_enum() {
        const IMPLEMENTED: [&str; 12] = [
            "aspack",
            "donut",
            "fsg",
            "kkrunchy",
            "mew",
            "mpress",
            "nspack",
            "pecompact",
            "petite",
            "srdi",
            "upx",
            "yodas-crypter",
        ];
        const STUB_EVAL_PENDING: [&str; 6] = [
            "asprotect",
            "morphine",
            "neolite",
            "npack",
            "polycryptor",
            "warzone-crypter",
        ];
        const GREY_CARVE: [&str; 3] = ["themida", "vmprotect", "yodas-protector"];
        const GREY_DETECT_ONLY: [&str; 6] = [
            "armadillo",
            "enigma-protector",
            "obsidium",
            "pelock",
            "pe-protector",
            "winlicense",
        ];
        const DELEGATED: [&str; 2] = ["dotnet-patcher", "netcryptor"];

        let gather = |wanted: UnpackerStatus| -> Vec<&'static str> {
            let mut names: Vec<&'static str> = EVERY_PACKER
                .into_iter()
                .filter(|p: &Packer| p.unpacker_status() == wanted)
                .map(|p: Packer| p.label())
                .collect();
            names.sort_unstable();
            names
        };

        let normalise = |mut expected: Vec<&'static str>| -> Vec<&'static str> {
            expected.sort_unstable();
            expected
        };

        assert_eq!(
            gather(UnpackerStatus::Implemented),
            normalise(IMPLEMENTED.to_vec()),
            "docs/src/catalog.md publishes the Implemented tier by name and count; a variant moved \
             into or out of that tier without the page moving with it"
        );
        assert_eq!(
            gather(UnpackerStatus::StubEvalPending),
            normalise(STUB_EVAL_PENDING.to_vec())
        );
        assert_eq!(
            gather(UnpackerStatus::GreyZoneDetectAndCarve),
            normalise(GREY_CARVE.to_vec())
        );
        assert_eq!(
            gather(UnpackerStatus::GreyZoneDetectOnly),
            normalise(GREY_DETECT_ONLY.to_vec())
        );
        assert_eq!(
            gather(UnpackerStatus::DelegatedToDotnet),
            normalise(DELEGATED.to_vec())
        );

        assert_eq!(
            IMPLEMENTED.len()
                + STUB_EVAL_PENDING.len()
                + GREY_CARVE.len()
                + GREY_DETECT_ONLY.len()
                + DELEGATED.len(),
            EVERY_PACKER.len(),
            "the published tiers must partition the enum with nothing left over"
        );
    }

    fn mz_buf(len: usize) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; len];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf
    }

    fn pe_with_sections(names: &[&[u8]]) -> Vec<u8> {
        let opt_size: usize = 0xE0;
        let sec_table: usize = 0x80 + 4 + 20 + opt_size;
        let total: usize = sec_table + names.len() * 40 + 0x200;
        let mut buf: Vec<u8> = vec![0u8; total];
        buf[0] = b'M';
        buf[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off: usize = e_lfanew as usize;
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
        let coff: usize = pe_off + 4;
        buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&(names.len() as u16).to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt: usize = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        for (i, name) in names.iter().enumerate() {
            let entry: usize = sec_table + i * 40;
            let len: usize = name.len().min(8);
            buf[entry..entry + len].copy_from_slice(&name[..len]);
        }
        buf
    }

    #[test]
    fn upx_signature_detected() {
        let mut buf: Vec<u8> = mz_buf(256);
        buf[100..104].copy_from_slice(b"UPX!");
        let hits: Vec<Detection> = detect(&buf);
        assert!(hits.iter().any(|h: &Detection| h.packer == Packer::Upx));
    }

    #[test]
    fn aspack_signature_detected() {
        let buf: Vec<u8> = pe_with_sections(&[b".aspack"]);
        let hits: Vec<Detection> = detect(&buf);
        assert!(hits.iter().any(|h: &Detection| h.packer == Packer::AsPack));
    }

    #[test]
    fn section_name_in_payload_is_not_a_false_positive() {
        let mut buf: Vec<u8> = pe_with_sections(&[b".text"]);
        let tail: usize = buf.len();
        buf.resize(tail + 4, 0);
        buf[tail..tail + 4].copy_from_slice(b"UPX0");
        let hits: Vec<Detection> = detect(&buf);
        assert!(
            !hits.iter().any(|h: &Detection| h.packer == Packer::Upx),
            "a bare UPX0 byte run in payload data must not be misread as a UPX section name",
        );
    }

    #[test]
    fn fsg2_getbit_helper_stub_detected() {
        let helper: [u8; 15] = [
            0xE8, 0x0A, 0x00, 0x00, 0x00, 0x02, 0xD2, 0x75, 0x05, 0x8A, 0x16, 0x46, 0x12, 0xD2,
            0xC3,
        ];
        let mut buf: Vec<u8> = mz_buf(1024);
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
    fn apk_zip_container_yields_no_packer_detection() {
        let mut buf: Vec<u8> = vec![0u8; 4096];
        buf[0..4].copy_from_slice(b"PK\x03\x04");
        buf[1024..1024 + b"PECompact2".len()].copy_from_slice(b"PECompact2");
        buf[2048..2048 + b"UPX!".len()].copy_from_slice(b"UPX!");
        let hits: Vec<Detection> = detect(&buf);
        assert!(
            hits.is_empty(),
            "a PK zip/apk container with incidental packer-signature bytes must not match any native PE packer; got {hits:?}",
        );
    }

    #[test]
    fn vmprotect_grey_zone_is_carve_and_detect() {
        let buf: Vec<u8> = pe_with_sections(&[b".vmp0"]);
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
        let buf: Vec<u8> = pe_with_sections(&[b".themida"]);
        let hits: Vec<Detection> = detect(&buf);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].packer, Packer::Themida);
    }

    #[test]
    fn confidence_dedup_promotes_high_over_medium() {
        let buf: Vec<u8> = pe_with_sections(&[b".MPRESS1"]);
        let hits: Vec<Detection> = detect(&buf);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].confidence, Confidence::High);
    }

    #[test]
    fn fingerprint_chain_returns_all_matches() {
        let mut buf: Vec<u8> = pe_with_sections(&[b".aspack"]);
        let tail: usize = buf.len();
        buf.resize(tail + 4, 0);
        buf[tail..tail + 4].copy_from_slice(b"UPX!");
        let hits: Vec<Detection> = fingerprint_chain(&buf);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn aspack_ep_stub_detected() {
        let stub: [u8; 13] = [
            0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB, 0x04, 0x5D, 0x45, 0x55, 0xC3,
        ];
        let mut buf: Vec<u8> = mz_buf(512);
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
        let mut buf: Vec<u8> = mz_buf(512);
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
        let mut buf: Vec<u8> = mz_buf(512);
        buf[64..64 + stub.len()].copy_from_slice(&stub);
        let hits: Vec<Detection> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &Detection| h.packer == Packer::Obsidium)
        );
    }

    #[test]
    fn enigma_overlay_literal_detected() {
        let mut buf: Vec<u8> = mz_buf(512);
        buf[64..64 + b"Enigma protector".len()].copy_from_slice(b"Enigma protector");
        let hits: Vec<Detection> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &Detection| h.packer == Packer::EnigmaProtector)
        );
    }

    #[test]
    fn winlicense_literal_detected() {
        let mut buf: Vec<u8> = mz_buf(512);
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
        let mut buf: Vec<u8> = mz_buf(512);
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
        let mut buf: Vec<u8> = mz_buf(512);
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
