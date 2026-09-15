use std::ops::Range;

use disrobe_bytes::{FileOffset, Size};
use serde::{Deserialize, Serialize};

use crate::entropy::shannon_entropy_bits;

use crate::anti_analysis_sigs::{
    ANALYSIS_USERNAME_SIGS, STRING_SIGS, SigClass, SignalCorroboration, StringSig, UsernameSig,
};
#[cfg(target_arch = "wasm32")]
use crate::anti_analysis_sigs::{NUMBER_SIGS, NumberSig};
use crate::byte_search;
use crate::strings::{self, ExtractedString, Options};

pub use crate::anti_analysis_sigs::Confidence;

pub const ANTI_ANALYSIS_SCHEMA: &str = "disrobe.anti-analysis/v4";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Technique {
    AntiDebug,
    AntiVm,
    AntiSandbox,
    AntiTool,
    AntiAttach,
    AntiDump,
    TimingEvasion,
    AntiDisassembly,
    OpaquePredicate,
    ControlFlowFlattening,
    StringEncryption,
    Packing,
    Rasp,
    VmVirtualization,
}

impl Technique {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AntiDebug => "anti-debug",
            Self::AntiVm => "anti-vm",
            Self::AntiSandbox => "anti-sandbox",
            Self::AntiTool => "anti-tool",
            Self::AntiAttach => "anti-attach",
            Self::AntiDump => "anti-dump",
            Self::TimingEvasion => "timing-evasion",
            Self::AntiDisassembly => "anti-disassembly",
            Self::OpaquePredicate => "opaque-predicate",
            Self::ControlFlowFlattening => "control-flow-flattening",
            Self::StringEncryption => "string-encryption",
            Self::Packing => "packing",
            Self::Rasp => "rasp",
            Self::VmVirtualization => "vm-virtualization",
        }
    }

    #[inline]
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::AntiDebug => "debugger-presence checks",
            Self::AntiVm => "virtual-machine / hypervisor detection",
            Self::AntiSandbox => "automated-sandbox environment detection",
            Self::AntiTool => "analysis-tool presence detection",
            Self::AntiAttach => "debugger-attach denial primitives",
            Self::AntiDump => "in-memory image dump frustration",
            Self::TimingEvasion => "timing / sleep-based analysis evasion",
            Self::AntiDisassembly => "jump-into-instruction byte desync",
            Self::OpaquePredicate => "always-true/false opaque branch guards",
            Self::ControlFlowFlattening => "dispatcher-driven flattened control flow",
            Self::StringEncryption => "encrypted / encoded string literals",
            Self::Packing => "compressed or encrypted code section",
            Self::Rasp => "runtime application self-protection",
            Self::VmVirtualization => "native bytecode virtualization",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mechanism {
    Desync,
    DecoderEmulation,
    CffUnflatten,
    BcfStrip,
    StubEmu,
    MbaSimplify,
    PackerUnpack,
    StringDecrypt,
    RaspNeutralize,
    VmDevirt,
}

impl Mechanism {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Desync => "desync",
            Self::DecoderEmulation => "decoder-emulation",
            Self::CffUnflatten => "cff-unflatten",
            Self::BcfStrip => "bcf-strip",
            Self::StubEmu => "stub-emu",
            Self::MbaSimplify => "mba-simplify",
            Self::PackerUnpack => "packer-unpack",
            Self::StringDecrypt => "string-decrypt",
            Self::RaspNeutralize => "rasp-neutralize",
            Self::VmDevirt => "vm-devirt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum DefeatStatus {
    OvercomeBy { mechanism: Mechanism },
    DetectedNotDefeated { reason: String },
}

impl DefeatStatus {
    #[inline]
    #[must_use]
    pub const fn is_overcome(&self) -> bool {
        matches!(self, Self::OvercomeBy { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingSeverity {
    Informational,
    Detected,
}

impl FindingSeverity {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Detected => "detected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiAnalysisFinding {
    pub technique: Technique,
    pub detected: bool,
    pub severity: FindingSeverity,
    pub confidence: Confidence,
    pub defeated_by: DefeatStatus,
    pub evidence: Vec<String>,
}

impl AntiAnalysisFinding {
    #[inline]
    #[must_use]
    pub fn one_line(&self) -> String {
        match &self.defeated_by {
            DefeatStatus::OvercomeBy { mechanism } => format!(
                "{} -> overcome via {}",
                self.technique.label(),
                mechanism.label()
            ),
            DefeatStatus::DetectedNotDefeated { reason } => {
                format!(
                    "{} -> detected, not defeated: {}",
                    self.technique.label(),
                    reason
                )
            }
        }
    }

    #[inline]
    #[must_use]
    pub fn one_line_graded(&self) -> String {
        format!("[{}] {}", self.confidence.label(), self.one_line())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetFamily {
    Pe,
    Elf,
    MachO,
    JavaClass,
    Dalvik,
    Wasm,
    LuaBytecode,
    Text,
    Unknown,
}

impl TargetFamily {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pe => "pe",
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::JavaClass => "java-class",
            Self::Dalvik => "dalvik",
            Self::Wasm => "wasm",
            Self::LuaBytecode => "lua-bytecode",
            Self::Text => "text",
            Self::Unknown => "unknown",
        }
    }
}

#[must_use]
pub fn classify_family(bytes: &[u8]) -> TargetFamily {
    if bytes.len() >= 4 {
        if &bytes[..2] == b"MZ" {
            return TargetFamily::Pe;
        }
        if &bytes[..4] == b"\x7fELF" {
            return TargetFamily::Elf;
        }
        if &bytes[..4] == b"dex\n" {
            return TargetFamily::Dalvik;
        }
        if &bytes[..4] == b"\x00asm" {
            return TargetFamily::Wasm;
        }
        if bytes[0] == 0x1b && &bytes[1..4] == b"Lua" {
            return TargetFamily::LuaBytecode;
        }
        if &bytes[..4] == b"\xca\xfe\xba\xbe" {
            return TargetFamily::JavaClass;
        }
        if is_macho_magic([bytes[0], bytes[1], bytes[2], bytes[3]]) {
            return TargetFamily::MachO;
        }
    }
    if looks_like_text(bytes) {
        return TargetFamily::Text;
    }
    TargetFamily::Unknown
}

const MACHO_MAGICS: [[u8; 4]; 5] = [
    [0xfe, 0xed, 0xfa, 0xce],
    [0xce, 0xfa, 0xed, 0xfe],
    [0xfe, 0xed, 0xfa, 0xcf],
    [0xcf, 0xfa, 0xed, 0xfe],
    [0xca, 0xfe, 0xba, 0xbf],
];

fn is_macho_magic(head: [u8; 4]) -> bool {
    MACHO_MAGICS.contains(&head)
}

fn looks_like_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let sample: &[u8] = &bytes[..bytes.len().min(4096)];
    let printable: usize = sample
        .iter()
        .filter(|b: &&u8| {
            **b == b'\t' || **b == b'\n' || **b == b'\r' || (0x20..=0x7e).contains(*b)
        })
        .count();
    printable.saturating_mul(100) / sample.len() >= 92
}

#[derive(Debug, Clone, Default)]
pub struct ChainEvidence {
    pub executed_pass_ids: Vec<String>,
    pub recovered_format_tags: Vec<String>,
    pub recovered_techniques: Vec<Technique>,
}

impl ChainEvidence {
    fn has_pass_prefix(&self, prefix: &str) -> bool {
        self.executed_pass_ids
            .iter()
            .any(|p: &String| p.starts_with(prefix))
    }

    fn unpacked_to_native(&self) -> bool {
        self.has_pass_prefix("native.packer-unpack")
            && self
                .recovered_format_tags
                .iter()
                .any(|t: &String| t == "pe" || t == "elf" || t == "macho")
    }

    fn recovered(&self, technique: Technique) -> bool {
        self.recovered_techniques.contains(&technique)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiAnalysisReport {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub byte_len: usize,
    pub target_family: TargetFamily,
    pub findings: Vec<AntiAnalysisFinding>,
}

impl AntiAnalysisReport {
    #[inline]
    #[must_use]
    pub fn any_detected(&self) -> bool {
        self.findings
            .iter()
            .any(|f: &AntiAnalysisFinding| f.detected)
    }

    #[inline]
    #[must_use]
    pub fn overcome_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f: &&AntiAnalysisFinding| f.defeated_by.is_overcome())
            .count()
    }
}

const fn sig_class_technique(class: SigClass) -> Technique {
    match class {
        SigClass::AntiDebug => Technique::AntiDebug,
        SigClass::AntiVm | SigClass::Hypervisor | SigClass::VmMacOui => Technique::AntiVm,
        SigClass::Sandbox | SigClass::ResourceFloor | SigClass::Interaction => {
            Technique::AntiSandbox
        }
        SigClass::AntiTool => Technique::AntiTool,
        SigClass::AntiDump => Technique::AntiDump,
        SigClass::AntiAttach => Technique::AntiAttach,
        SigClass::Timing => Technique::TimingEvasion,
    }
}

#[derive(Debug, Clone, Copy)]
struct ProtectorMarker {
    needle: &'static [u8],
    technique: Technique,
    detail: &'static str,
    confidence: Confidence,
    grey_zone_vm: bool,
}

static PROTECTOR_MARKERS: &[ProtectorMarker] = &[
    ProtectorMarker {
        needle: b"UPX!",
        technique: Technique::Packing,
        detail: "upx section magic",
        confidence: Confidence::High,
        grey_zone_vm: false,
    },
    ProtectorMarker {
        needle: b".MPRESS1",
        technique: Technique::Packing,
        detail: "mpress section",
        confidence: Confidence::High,
        grey_zone_vm: false,
    },
    ProtectorMarker {
        needle: b".aspack",
        technique: Technique::Packing,
        detail: "aspack section",
        confidence: Confidence::High,
        grey_zone_vm: false,
    },
    ProtectorMarker {
        needle: b"FSG!",
        technique: Technique::Packing,
        detail: "fsg magic",
        confidence: Confidence::High,
        grey_zone_vm: false,
    },
    ProtectorMarker {
        needle: b".vmp0",
        technique: Technique::VmVirtualization,
        detail: "vmprotect section",
        confidence: Confidence::High,
        grey_zone_vm: true,
    },
    ProtectorMarker {
        needle: b".themida",
        technique: Technique::VmVirtualization,
        detail: "themida section",
        confidence: Confidence::High,
        grey_zone_vm: true,
    },
    ProtectorMarker {
        needle: b"WinLicense",
        technique: Technique::VmVirtualization,
        detail: "winlicense tag",
        confidence: Confidence::High,
        grey_zone_vm: true,
    },
    ProtectorMarker {
        needle: b".enigma1",
        technique: Technique::VmVirtualization,
        detail: "enigma protector section",
        confidence: Confidence::High,
        grey_zone_vm: true,
    },
];

#[derive(Debug, Clone, Copy)]
struct CodeMarker {
    needle: &'static [u8],
    technique: Technique,
    detail: &'static str,
    confidence: Confidence,
}

static CODE_MARKERS: &[CodeMarker] = &[
    CodeMarker {
        needle: b"ollvm.fla",
        technique: Technique::ControlFlowFlattening,
        detail: "ollvm flatten metadata",
        confidence: Confidence::High,
    },
    CodeMarker {
        needle: b"switch_var",
        technique: Technique::ControlFlowFlattening,
        detail: "ollvm cff state variable",
        confidence: Confidence::Low,
    },
    CodeMarker {
        needle: b"_TIGRESS_flatten",
        technique: Technique::ControlFlowFlattening,
        detail: "tigress flatten symbol",
        confidence: Confidence::High,
    },
    CodeMarker {
        needle: b"ollvm.bcf",
        technique: Technique::OpaquePredicate,
        detail: "ollvm bogus-control-flow metadata",
        confidence: Confidence::High,
    },
    CodeMarker {
        needle: b"ollvm.sub",
        technique: Technique::OpaquePredicate,
        detail: "ollvm instruction-substitution metadata",
        confidence: Confidence::High,
    },
];

#[derive(Debug, Clone, Copy)]
struct RaspMarker {
    needle: &'static [u8],
    detail: &'static str,
    confidence: Confidence,
}

static RASP_MARKERS: &[RaspMarker] = &[
    RaspMarker {
        needle: b"libshield.so",
        detail: "shielding runtime library",
        confidence: Confidence::High,
    },
    RaspMarker {
        needle: b"libdexguard",
        detail: "dexguard runtime library",
        confidence: Confidence::High,
    },
    RaspMarker {
        needle: b"libdexprotector",
        detail: "dexprotector runtime library",
        confidence: Confidence::High,
    },
    RaspMarker {
        needle: b"libappdome",
        detail: "appdome runtime library",
        confidence: Confidence::High,
    },
    RaspMarker {
        needle: b"com.guardsquare",
        detail: "guardsquare runtime package",
        confidence: Confidence::High,
    },
    RaspMarker {
        needle: b"Promon",
        detail: "promon shield runtime tag",
        confidence: Confidence::Medium,
    },
    RaspMarker {
        needle: b"DexProtector",
        detail: "dexprotector runtime tag",
        confidence: Confidence::High,
    },
    RaspMarker {
        needle: b"Zimperium",
        detail: "zimperium runtime tag",
        confidence: Confidence::High,
    },
    RaspMarker {
        needle: b"jscrambler",
        detail: "jscrambler runtime tag",
        confidence: Confidence::High,
    },
];

#[must_use]
pub fn scan(bytes: &[u8], uri: Option<&str>) -> AntiAnalysisReport {
    scan_with_chain(bytes, uri, &ChainEvidence::default())
}

const ANTI_ANALYSIS_SCAN_CAP: usize = 96 * 1024 * 1024;

#[must_use]
pub fn scan_with_chain(
    bytes: &[u8],
    uri: Option<&str>,
    chain: &ChainEvidence,
) -> AntiAnalysisReport {
    let family: TargetFamily = classify_family(bytes);
    let mut acc: TechniqueAccumulator = TechniqueAccumulator::default();

    let scan: &[u8] = &bytes[..bytes.len().min(ANTI_ANALYSIS_SCAN_CAP)];
    collect_protector_markers(scan, &mut acc);
    collect_code_markers(scan, &mut acc);
    collect_rasp_markers(scan, &mut acc);
    collect_string_rules(scan, &mut acc);
    collect_string_encryption(scan, family, &mut acc);
    scan_executable_code(bytes, family, &mut acc);

    let findings: Vec<AntiAnalysisFinding> = acc.finalize(family, chain);
    AntiAnalysisReport {
        schema: ANTI_ANALYSIS_SCHEMA.to_string(),
        uri: uri.map(str::to_owned),
        byte_len: bytes.len(),
        target_family: family,
        findings,
    }
}

#[derive(Default)]
struct TechniqueAccumulator {
    entries: std::collections::BTreeMap<Technique, TechniqueAccum>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    A,
    B,
    C,
}

const fn tier_of(confidence: Confidence) -> Tier {
    match confidence {
        Confidence::High => Tier::A,
        Confidence::Medium => Tier::B,
        Confidence::Low | Confidence::Info => Tier::C,
    }
}

#[derive(Debug, Clone)]
struct EvidenceItem {
    tier: Tier,
    confidence: Confidence,
    kind: &'static str,
    window: Option<usize>,
    detail: String,
    corroboration: SignalCorroboration,
}

struct VerdictEvaluation {
    detected: bool,
    eligible_item_indices: Vec<usize>,
}

#[derive(Default)]
struct TechniqueAccum {
    items: Vec<EvidenceItem>,
    grey_zone_vm: bool,
}

const LOCALITY_WINDOW: usize = 4096;
const MAX_EXEMPLARS_PER_KIND: usize = 5;

impl TechniqueAccumulator {
    fn add(
        &mut self,
        technique: Technique,
        confidence: Confidence,
        kind: &'static str,
        window: Option<usize>,
        detail: String,
        corroboration: SignalCorroboration,
    ) {
        let entry: &mut TechniqueAccum = self.entries.entry(technique).or_default();
        entry.items.push(EvidenceItem {
            tier: tier_of(confidence),
            confidence,
            kind,
            window,
            detail,
            corroboration,
        });
    }

    fn mark_grey_zone_vm(&mut self, technique: Technique) {
        self.entries.entry(technique).or_default().grey_zone_vm = true;
    }

    fn finalize(self, family: TargetFamily, chain: &ChainEvidence) -> Vec<AntiAnalysisFinding> {
        let mut findings: Vec<AntiAnalysisFinding> = Vec::with_capacity(self.entries.len());
        for (technique, accum) in self.entries {
            if accum.items.is_empty() {
                continue;
            }
            let evaluation: VerdictEvaluation = evaluate_verdict(technique, &accum.items);
            let confidence_items: Vec<&EvidenceItem> = if evaluation.detected {
                evaluation
                    .eligible_item_indices
                    .iter()
                    .filter_map(|index: &usize| accum.items.get(*index))
                    .collect()
            } else {
                accum.items.iter().collect()
            };
            let Some(confidence): Option<Confidence> = confidence_items
                .into_iter()
                .map(|i: &EvidenceItem| i.confidence)
                .max()
            else {
                continue;
            };
            let severity: FindingSeverity = if evaluation.detected {
                FindingSeverity::Detected
            } else {
                FindingSeverity::Informational
            };
            let defeated_by: DefeatStatus =
                resolve_defeat(technique, family, accum.grey_zone_vm, chain);
            findings.push(AntiAnalysisFinding {
                technique,
                detected: evaluation.detected,
                severity,
                confidence,
                defeated_by,
                evidence: cap_evidence(&accum.items),
            });
        }
        findings
    }
}

const fn technique_is_structural(technique: Technique) -> bool {
    matches!(
        technique,
        Technique::Packing
            | Technique::VmVirtualization
            | Technique::ControlFlowFlattening
            | Technique::OpaquePredicate
            | Technique::StringEncryption
            | Technique::Rasp
    )
}

fn evaluate_verdict(technique: Technique, items: &[EvidenceItem]) -> VerdictEvaluation {
    let non_context_indices: Vec<usize> = items
        .iter()
        .enumerate()
        .filter_map(|(index, item): (usize, &EvidenceItem)| {
            (item.corroboration != SignalCorroboration::ContextOnly).then_some(index)
        })
        .collect();
    if technique_is_structural(technique) {
        return VerdictEvaluation {
            detected: !non_context_indices.is_empty(),
            eligible_item_indices: non_context_indices,
        };
    }
    let strong_kinds: std::collections::BTreeSet<&'static str> = non_context_indices
        .iter()
        .filter_map(|index: &usize| items.get(*index))
        .filter(|item: &&EvidenceItem| matches!(item.tier, Tier::A | Tier::B))
        .map(|item: &EvidenceItem| item.kind)
        .collect();
    let eligible_item_indices: Vec<usize> = non_context_indices
        .into_iter()
        .filter(|index: &usize| {
            let Some(item): Option<&EvidenceItem> = items.get(*index) else {
                return false;
            };
            match item.corroboration {
                SignalCorroboration::Standalone => true,
                SignalCorroboration::Corroborated => strong_kinds
                    .iter()
                    .any(|kind: &&'static str| *kind != item.kind),
                SignalCorroboration::ContextOnly => false,
            }
        })
        .collect();
    let eligible_items: Vec<&EvidenceItem> = eligible_item_indices
        .iter()
        .filter_map(|index: &usize| items.get(*index))
        .collect();
    let tier_a_detected: bool = eligible_items
        .iter()
        .copied()
        .any(|item: &EvidenceItem| item.tier == Tier::A);
    let b_windows: std::collections::BTreeSet<usize> = eligible_items
        .iter()
        .copied()
        .filter(|item: &&EvidenceItem| item.tier == Tier::B)
        .filter_map(|item: &EvidenceItem| item.window)
        .map(|window: usize| window / LOCALITY_WINDOW)
        .collect();
    let has_tier_b: bool = eligible_items
        .iter()
        .copied()
        .any(|item: &EvidenceItem| item.tier == Tier::B);
    let c_kinds: std::collections::BTreeSet<&'static str> = eligible_items
        .iter()
        .copied()
        .filter(|item: &&EvidenceItem| item.tier == Tier::C)
        .map(|item: &EvidenceItem| item.kind)
        .collect();
    VerdictEvaluation {
        detected: tier_a_detected || b_windows.len() >= 2 || (has_tier_b && c_kinds.len() >= 3),
        eligible_item_indices,
    }
}

fn cap_evidence(items: &[EvidenceItem]) -> Vec<String> {
    let mut by_kind: std::collections::BTreeMap<&'static str, Vec<&EvidenceItem>> =
        std::collections::BTreeMap::new();
    for item in items {
        by_kind.entry(item.kind).or_default().push(item);
    }
    let mut out: Vec<String> = Vec::new();
    for (kind, group) in by_kind {
        for item in group.iter().take(MAX_EXEMPLARS_PER_KIND) {
            if !out.contains(&item.detail) {
                out.push(item.detail.clone());
            }
        }
        if group.len() > MAX_EXEMPLARS_PER_KIND {
            out.push(format!(
                "+{} more '{kind}' matches ({} total)",
                group.len() - MAX_EXEMPLARS_PER_KIND,
                group.len()
            ));
        }
    }
    out
}

fn resolve_defeat(
    technique: Technique,
    family: TargetFamily,
    grey_zone_vm: bool,
    chain: &ChainEvidence,
) -> DefeatStatus {
    match technique {
        Technique::AntiDisassembly => desync_defeat(chain),
        Technique::ControlFlowFlattening => cff_defeat(family, chain),
        Technique::OpaquePredicate => opaque_predicate_defeat(chain),
        Technique::StringEncryption => string_encryption_defeat(chain),
        Technique::Packing => packing_defeat(chain),
        Technique::VmVirtualization => vm_defeat(grey_zone_vm),
        Technique::AntiDebug
        | Technique::AntiVm
        | Technique::AntiSandbox
        | Technique::AntiTool
        | Technique::TimingEvasion => DefeatStatus::DetectedNotDefeated {
            reason: "runtime guard is surfaced for triage; disrobe is static and does not \
                     execute the sample"
                .to_string(),
        },
        Technique::AntiAttach => DefeatStatus::DetectedNotDefeated {
            reason: "attach-denial primitive only fires when a debugger attaches at runtime; \
                     disrobe attributes it but does not execute the sample"
                .to_string(),
        },
        Technique::AntiDump => DefeatStatus::DetectedNotDefeated {
            reason: "in-memory dump frustration acts on the live process image; disrobe reports \
                     the primitive from the on-disk artifact and does not execute the sample"
                .to_string(),
        },
        Technique::Rasp => DefeatStatus::DetectedNotDefeated {
            reason: "runtime self-protection is enterprise-gated and active only at execution; \
                     disrobe reports the vendor but does not neutralize live RASP"
                .to_string(),
        },
    }
}

fn cff_defeat(family: TargetFamily, chain: &ChainEvidence) -> DefeatStatus {
    if chain.recovered(Technique::ControlFlowFlattening) {
        return DefeatStatus::OvercomeBy {
            mechanism: Mechanism::CffUnflatten,
        };
    }
    match family {
        TargetFamily::Pe
        | TargetFamily::Elf
        | TargetFamily::MachO
        | TargetFamily::JavaClass
        | TargetFamily::Dalvik
        | TargetFamily::Wasm => DefeatStatus::DetectedNotDefeated {
            reason: "flattening marker present but no dispatcher-recovered control flow was \
                     produced in this run; run the recovery chain to unflatten"
                .to_string(),
        },
        TargetFamily::LuaBytecode | TargetFamily::Text | TargetFamily::Unknown => {
            DefeatStatus::DetectedNotDefeated {
                reason:
                    "flattening marker present but disrobe has no dispatcher-recovery unflattener \
                         wired for this target family"
                        .to_string(),
            }
        }
    }
}

fn opaque_predicate_defeat(chain: &ChainEvidence) -> DefeatStatus {
    if chain.recovered(Technique::OpaquePredicate) {
        DefeatStatus::OvercomeBy {
            mechanism: Mechanism::BcfStrip,
        }
    } else {
        DefeatStatus::DetectedNotDefeated {
            reason: "bogus-control-flow marker present but no predicate was statically resolved \
                     and stripped in this run"
                .to_string(),
        }
    }
}

fn string_encryption_defeat(chain: &ChainEvidence) -> DefeatStatus {
    if chain.recovered(Technique::StringEncryption) {
        DefeatStatus::OvercomeBy {
            mechanism: Mechanism::DecoderEmulation,
        }
    } else {
        DefeatStatus::DetectedNotDefeated {
            reason: "encoded string block present but no decrypted plaintext was recovered in \
                     this run"
                .to_string(),
        }
    }
}

fn desync_defeat(chain: &ChainEvidence) -> DefeatStatus {
    if chain.recovered(Technique::AntiDisassembly) {
        DefeatStatus::OvercomeBy {
            mechanism: Mechanism::Desync,
        }
    } else {
        DefeatStatus::DetectedNotDefeated {
            reason: "jump-into-instruction desync detected but no realigned instruction stream \
                     was recovered in this run"
                .to_string(),
        }
    }
}

fn packing_defeat(chain: &ChainEvidence) -> DefeatStatus {
    if chain.unpacked_to_native() {
        DefeatStatus::OvercomeBy {
            mechanism: Mechanism::PackerUnpack,
        }
    } else if chain.has_pass_prefix("native.packer-unpack") {
        DefeatStatus::DetectedNotDefeated {
            reason: "packer recognized and routed to the unpacker, but no clean native image was \
                     recovered in this run"
                .to_string(),
        }
    } else {
        DefeatStatus::OvercomeBy {
            mechanism: Mechanism::StubEmu,
        }
    }
}

fn vm_defeat(grey_zone_vm: bool) -> DefeatStatus {
    if grey_zone_vm {
        DefeatStatus::DetectedNotDefeated {
            reason: "original code is lifted into a custom native VM; static unpacking cannot \
                     recover the pre-virtualization instructions"
                .to_string(),
        }
    } else {
        DefeatStatus::OvercomeBy {
            mechanism: Mechanism::VmDevirt,
        }
    }
}

fn collect_protector_markers(bytes: &[u8], acc: &mut TechniqueAccumulator) {
    for marker in PROTECTOR_MARKERS {
        if let Some(off) = byte_search::find(bytes, marker.needle) {
            acc.add(
                marker.technique,
                marker.confidence,
                marker.detail,
                Some(off),
                format!("{} at offset 0x{off:x}", marker.detail),
                SignalCorroboration::Standalone,
            );
            if marker.grey_zone_vm {
                acc.mark_grey_zone_vm(marker.technique);
            }
        }
    }
}

fn collect_code_markers(bytes: &[u8], acc: &mut TechniqueAccumulator) {
    for marker in CODE_MARKERS {
        if let Some(off) = byte_search::find(bytes, marker.needle) {
            acc.add(
                marker.technique,
                marker.confidence,
                marker.detail,
                Some(off),
                format!("{} at offset 0x{off:x}", marker.detail),
                SignalCorroboration::Standalone,
            );
        }
    }
}

fn collect_rasp_markers(bytes: &[u8], acc: &mut TechniqueAccumulator) {
    for marker in RASP_MARKERS {
        if let Some(off) = byte_search::find(bytes, marker.needle) {
            acc.add(
                Technique::Rasp,
                marker.confidence,
                marker.detail,
                Some(off),
                format!(
                    "rasp marker '{}' ({}) at offset 0x{off:x}",
                    String::from_utf8_lossy(marker.needle),
                    marker.detail
                ),
                SignalCorroboration::Standalone,
            );
        }
    }
}

fn collect_string_rules(bytes: &[u8], acc: &mut TechniqueAccumulator) {
    let extracted: Vec<ExtractedString> = strings::extract(
        bytes,
        Options {
            min_len: 4,
            decode: true,
        },
    );
    let mut timing_hits: Vec<(StringSig, usize)> = Vec::new();
    let mut resource_hits: Vec<(StringSig, usize)> = Vec::new();
    let mut interaction_hits: Vec<(StringSig, usize)> = Vec::new();
    let mut tool_hits: Vec<(StringSig, usize)> = Vec::new();
    for s in &extracted {
        let lower: String = s.value.to_ascii_lowercase();
        for sig in STRING_SIGS {
            let hit: bool = if sig.word_bounded {
                is_word_bounded(&lower, sig.needle)
            } else {
                lower.contains(sig.needle)
            };
            if !hit {
                continue;
            }
            match sig.class {
                SigClass::Timing if sig.corroboration == SignalCorroboration::ContextOnly => {
                    acc.add(
                        Technique::TimingEvasion,
                        sig.confidence,
                        sig.needle,
                        Some(s.offset),
                        format!(
                            "timing primitive '{}' ({}) at offset 0x{:x}",
                            sig.needle, sig.note, s.offset
                        ),
                        sig.corroboration,
                    );
                }
                SigClass::ResourceFloor
                    if sig.corroboration == SignalCorroboration::ContextOnly =>
                {
                    acc.add(
                        Technique::AntiSandbox,
                        sig.confidence,
                        sig.needle,
                        Some(s.offset),
                        format!(
                            "resource-floor probe '{}' ({}) at offset 0x{:x}",
                            sig.needle, sig.note, s.offset
                        ),
                        sig.corroboration,
                    );
                }
                SigClass::Interaction if sig.corroboration == SignalCorroboration::ContextOnly => {
                    acc.add(
                        Technique::AntiSandbox,
                        sig.confidence,
                        sig.needle,
                        Some(s.offset),
                        format!(
                            "human-interaction probe '{}' ({}) at offset 0x{:x}",
                            sig.needle, sig.note, s.offset
                        ),
                        sig.corroboration,
                    );
                }
                SigClass::Timing => timing_hits.push((*sig, s.offset)),
                SigClass::ResourceFloor => resource_hits.push((*sig, s.offset)),
                SigClass::Interaction => interaction_hits.push((*sig, s.offset)),
                SigClass::AntiTool => tool_hits.push((*sig, s.offset)),
                _ => acc.add(
                    sig_class_technique(sig.class),
                    sig.confidence,
                    sig.needle,
                    Some(s.offset),
                    format!(
                        "string '{}' ({}) at offset 0x{:x}",
                        sig.needle, sig.note, s.offset
                    ),
                    sig.corroboration,
                ),
            }
        }
        collect_username_sigs(&lower, s.offset, acc);
    }
    finalize_corroborated(
        &timing_hits,
        Technique::TimingEvasion,
        "timing primitive",
        2,
        Confidence::Medium,
        acc,
    );
    finalize_corroborated(
        &resource_hits,
        Technique::AntiSandbox,
        "resource-floor probe",
        2,
        Confidence::Medium,
        acc,
    );
    finalize_corroborated(
        &interaction_hits,
        Technique::AntiSandbox,
        "human-interaction probe",
        2,
        Confidence::Medium,
        acc,
    );
    finalize_tool_hits(&tool_hits, acc);
}

fn distinct_needles(hits: &[(StringSig, usize)]) -> usize {
    let mut needles: Vec<&'static str> = hits
        .iter()
        .map(|(sig, _): &(StringSig, usize)| sig.needle)
        .collect();
    needles.sort_unstable();
    needles.dedup();
    needles.len()
}

fn finalize_corroborated(
    hits: &[(StringSig, usize)],
    technique: Technique,
    label: &str,
    floor: usize,
    raised: Confidence,
    acc: &mut TechniqueAccumulator,
) {
    if distinct_needles(hits) < floor {
        return;
    }
    for (sig, offset) in hits {
        let confidence: Confidence = sig.confidence.max(raised);
        acc.add(
            technique,
            confidence,
            sig.needle,
            Some(*offset),
            format!(
                "{label} '{}' ({}) at offset 0x{offset:x}",
                sig.needle, sig.note
            ),
            sig.corroboration,
        );
    }
}

fn finalize_tool_hits(hits: &[(StringSig, usize)], acc: &mut TechniqueAccumulator) {
    if hits.is_empty() {
        return;
    }
    let raise_high: bool = distinct_needles(hits) >= 3;
    for (sig, offset) in hits {
        let confidence: Confidence = if raise_high {
            sig.confidence.max(Confidence::High)
        } else {
            sig.confidence
        };
        acc.add(
            Technique::AntiTool,
            confidence,
            sig.needle,
            Some(*offset),
            format!(
                "analysis-tool probe '{}' ({}) at offset 0x{offset:x}",
                sig.needle, sig.note
            ),
            sig.corroboration,
        );
    }
}

#[cfg(target_arch = "wasm32")]
const NUMBER_CORROBORATION_WINDOW: usize = 32;

const fn qualified_number_role(
    role: SignalCorroboration,
    corroborated: bool,
) -> Option<SignalCorroboration> {
    match role {
        SignalCorroboration::Standalone => Some(SignalCorroboration::Standalone),
        SignalCorroboration::Corroborated if corroborated => Some(SignalCorroboration::Standalone),
        SignalCorroboration::Corroborated => None,
        SignalCorroboration::ContextOnly => Some(SignalCorroboration::ContextOnly),
    }
}

#[cfg(target_arch = "wasm32")]
fn collect_number_sigs(slice: &[u8], base: usize, whole: &[u8], acc: &mut TechniqueAccumulator) {
    if slice.len() < 4 {
        return;
    }
    let mut i: usize = 0;
    while i + 4 <= slice.len() {
        let window: [u8; 4] = [slice[i], slice[i + 1], slice[i + 2], slice[i + 3]];
        let dword: u32 = u32::from_le_bytes(window);
        for sig in NUMBER_SIGS {
            if sig.value != dword {
                continue;
            }
            let corroborated: bool = match sig.corroboration {
                SignalCorroboration::Corroborated => number_sig_corroborated(whole, base + i, sig),
                SignalCorroboration::Standalone | SignalCorroboration::ContextOnly => false,
            };
            let Some(role): Option<SignalCorroboration> =
                qualified_number_role(sig.corroboration, corroborated)
            else {
                continue;
            };
            acc.add(
                sig_class_technique(sig.class),
                sig.confidence,
                sig.note,
                Some(base + i),
                format!(
                    "magic constant 0x{:x} ({}) at offset 0x{:x}",
                    sig.value,
                    sig.note,
                    base + i
                ),
                role,
            );
        }
        i += 1;
    }
}

#[cfg(target_arch = "wasm32")]
fn number_sig_corroborated(bytes: &[u8], at: usize, sig: &NumberSig) -> bool {
    let lo: usize = at.saturating_sub(NUMBER_CORROBORATION_WINDOW);
    let hi: usize = (at + 4 + NUMBER_CORROBORATION_WINDOW).min(bytes.len());
    let window: &[u8] = &bytes[lo..hi];
    match sig.value {
        0x4000_0000 => window_has_cpuid(window),
        0x0000_5658 => {
            window_has_io_port_opcode(window)
                || byte_search::contains(bytes, &0x564d_5868u32.to_le_bytes())
        }
        _ => {
            byte_search::contains(bytes, b"NtClose")
                || byte_search::contains(bytes, b"CloseHandle")
                || byte_search::contains(bytes, b"UnhandledExceptionFilter")
                || byte_search::contains(bytes, b"VirtualProtect")
                || byte_search::contains(bytes, b"AddVectoredExceptionHandler")
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn window_has_cpuid(window: &[u8]) -> bool {
    window.windows(2).any(|w: &[u8]| w == [0x0f, 0xa2])
}

#[cfg(target_arch = "wasm32")]
const fn is_io_port_opcode(b: u8) -> bool {
    matches!(b, 0xe4 | 0xe5 | 0xe6 | 0xe7 | 0xec | 0xed | 0xee | 0xef)
}

#[cfg(target_arch = "wasm32")]
fn window_has_io_port_opcode(window: &[u8]) -> bool {
    window.iter().any(|b: &u8| is_io_port_opcode(*b))
}

fn collect_username_sigs(lower: &str, offset: usize, acc: &mut TechniqueAccumulator) {
    for sig in ANALYSIS_USERNAME_SIGS {
        if username_signal(lower, sig) {
            acc.add(
                Technique::AntiVm,
                Confidence::Low,
                sig.needle,
                Some(offset),
                format!(
                    "analysis username '{}' ({}) at offset 0x{offset:x}",
                    sig.needle, sig.note
                ),
                SignalCorroboration::Standalone,
            );
        }
    }
}

fn username_signal(lower: &str, sig: &UsernameSig) -> bool {
    if !lower.contains(sig.needle) {
        return false;
    }
    lower.contains("username")
        || lower.contains("computername")
        || lower.contains("user=")
        || lower.contains("\\users\\")
        || lower.contains("/home/")
}

#[derive(Debug, Clone, Copy)]
struct CodeRegion {
    file_offset: usize,
    len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeBitness {
    Bits32,
    Bits64,
}

#[derive(Debug, Clone, Default)]
struct CodeLayout {
    regions: Vec<CodeRegion>,
    bitness: Option<CodeBitness>,
}

const MAX_PARSED_SECTIONS: usize = 96;
const MAX_MACHO_LOAD_CMDS: usize = 4096;
const CODE_SCAN_BUDGET: usize = 16 * 1024 * 1024;
const CODE_REGION_MAX_ENTROPY_BITS: f64 = 7.2;

fn read_u16(bytes: &[u8], off: FileOffset, le: bool) -> Option<u16> {
    let a: [u8; 2] = read_field::<2>(bytes, off)?;
    Some(if le {
        u16::from_le_bytes(a)
    } else {
        u16::from_be_bytes(a)
    })
}

fn read_u32(bytes: &[u8], off: FileOffset, le: bool) -> Option<u32> {
    let a: [u8; 4] = read_field::<4>(bytes, off)?;
    Some(if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    })
}

fn read_u64(bytes: &[u8], off: FileOffset, le: bool) -> Option<u64> {
    let a: [u8; 8] = read_field::<8>(bytes, off)?;
    Some(if le {
        u64::from_le_bytes(a)
    } else {
        u64::from_be_bytes(a)
    })
}

fn read_field<const N: usize>(bytes: &[u8], off: FileOffset) -> Option<[u8; N]> {
    let width: Size = Size::new(N as u64);
    let file_len: Size = Size::try_from(bytes.len()).ok()?;
    let span: Range<usize> = off.checked_range(width, file_len).ok()?;
    let mut field: [u8; N] = [0u8; N];
    field.copy_from_slice(bytes.get(span)?);
    Some(field)
}

const fn field_at(base: FileOffset, delta: u64) -> Option<FileOffset> {
    base.checked_add(Size::new(delta))
}

fn element_at(base: FileOffset, index: usize, stride: u64) -> Option<FileOffset> {
    let step: Size = Size::new(u64::try_from(index).ok()?).checked_mul(stride)?;
    base.checked_add(step)
}

fn push_region(regions: &mut Vec<CodeRegion>, image_len: usize, off: FileOffset, len: Size) {
    let Ok(start): Result<usize, _> = off.to_usize() else {
        return;
    };
    if len.is_zero() || start >= image_len {
        return;
    }
    let end: usize = usize::try_from(len.get())
        .map_or(image_len, |bytes: usize| start.saturating_add(bytes))
        .min(image_len);
    if end <= start {
        return;
    }
    regions.push(CodeRegion {
        file_offset: start,
        len: end - start,
    });
}

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

const PE_SECTION_HEADER_BYTES: u64 = 40;

fn pe_code_layout(bytes: &[u8]) -> CodeLayout {
    let mut layout: CodeLayout = CodeLayout::default();
    let Some(lfanew): Option<u32> = read_u32(bytes, FileOffset::new(0x3C), true) else {
        return layout;
    };
    let lfanew: FileOffset = FileOffset::new(u64::from(lfanew));
    if read_field::<4>(bytes, lfanew).as_ref() != Some(b"PE\0\0") {
        return layout;
    }
    let Some(coff): Option<FileOffset> = field_at(lfanew, 4) else {
        return layout;
    };
    let Some(num_sections): Option<u16> =
        field_at(coff, 2).and_then(|at: FileOffset| read_u16(bytes, at, true))
    else {
        return layout;
    };
    let Some(opt_size): Option<u16> =
        field_at(coff, 16).and_then(|at: FileOffset| read_u16(bytes, at, true))
    else {
        return layout;
    };
    let Some(opt_start): Option<FileOffset> = field_at(coff, 20) else {
        return layout;
    };
    layout.bitness = match read_u16(bytes, opt_start, true) {
        Some(0x010B) => Some(CodeBitness::Bits32),
        Some(0x020B) => Some(CodeBitness::Bits64),
        _ => None,
    };
    let Some(sect_start): Option<FileOffset> = field_at(opt_start, u64::from(opt_size)) else {
        return layout;
    };
    let count: usize = Size::new(u64::from(num_sections))
        .bounded_element_capacity(PE_SECTION_HEADER_BYTES as usize, bytes.len())
        .min(MAX_PARSED_SECTIONS);
    for i in 0..count {
        let Some(base): Option<FileOffset> = element_at(sect_start, i, PE_SECTION_HEADER_BYTES)
        else {
            break;
        };
        let Some(chars): Option<u32> =
            field_at(base, 36).and_then(|at: FileOffset| read_u32(bytes, at, true))
        else {
            break;
        };
        if chars & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let Some(raw_size): Option<u32> =
            field_at(base, 16).and_then(|at: FileOffset| read_u32(bytes, at, true))
        else {
            continue;
        };
        let Some(raw_ptr): Option<u32> =
            field_at(base, 20).and_then(|at: FileOffset| read_u32(bytes, at, true))
        else {
            continue;
        };
        push_region(
            &mut layout.regions,
            bytes.len(),
            FileOffset::new(u64::from(raw_ptr)),
            Size::new(u64::from(raw_size)),
        );
    }
    layout
}

const SHF_EXECINSTR: u64 = 0x4;
const SHT_NOBITS: u32 = 8;

fn elf_code_layout(bytes: &[u8]) -> CodeLayout {
    let mut layout: CodeLayout = CodeLayout::default();
    let is64: bool = match bytes.get(4) {
        Some(2) => true,
        Some(1) => false,
        _ => return layout,
    };
    let le: bool = !matches!(bytes.get(5), Some(2));
    layout.bitness = Some(if is64 {
        CodeBitness::Bits64
    } else {
        CodeBitness::Bits32
    });
    let (shoff, shentsize, shnum): (FileOffset, u64, u64) = if is64 {
        let Some(o): Option<u64> = read_u64(bytes, FileOffset::new(0x28), le) else {
            return layout;
        };
        let Some(es): Option<u16> = read_u16(bytes, FileOffset::new(0x3A), le) else {
            return layout;
        };
        let Some(n): Option<u16> = read_u16(bytes, FileOffset::new(0x3C), le) else {
            return layout;
        };
        (FileOffset::new(o), u64::from(es), u64::from(n))
    } else {
        let Some(o): Option<u32> = read_u32(bytes, FileOffset::new(0x20), le) else {
            return layout;
        };
        let Some(es): Option<u16> = read_u16(bytes, FileOffset::new(0x2E), le) else {
            return layout;
        };
        let Some(n): Option<u16> = read_u16(bytes, FileOffset::new(0x30), le) else {
            return layout;
        };
        (FileOffset::new(u64::from(o)), u64::from(es), u64::from(n))
    };
    if shoff.is_zero() || shentsize == 0 {
        return layout;
    }
    let count: usize = Size::new(shnum)
        .bounded_element_capacity(
            usize::try_from(shentsize).unwrap_or(usize::MAX),
            bytes.len(),
        )
        .min(MAX_PARSED_SECTIONS);
    for i in 0..count {
        let Some(base): Option<FileOffset> = element_at(shoff, i, shentsize) else {
            break;
        };
        let Some(sh_type): Option<u32> =
            field_at(base, 4).and_then(|at: FileOffset| read_u32(bytes, at, le))
        else {
            break;
        };
        let (sh_flags, sh_offset, sh_size): (u64, FileOffset, Size) = if is64 {
            let Some(f): Option<u64> =
                field_at(base, 8).and_then(|at: FileOffset| read_u64(bytes, at, le))
            else {
                break;
            };
            let Some(o): Option<u64> =
                field_at(base, 24).and_then(|at: FileOffset| read_u64(bytes, at, le))
            else {
                break;
            };
            let Some(s): Option<u64> =
                field_at(base, 32).and_then(|at: FileOffset| read_u64(bytes, at, le))
            else {
                break;
            };
            (f, FileOffset::new(o), Size::new(s))
        } else {
            let Some(f): Option<u32> =
                field_at(base, 8).and_then(|at: FileOffset| read_u32(bytes, at, le))
            else {
                break;
            };
            let Some(o): Option<u32> =
                field_at(base, 16).and_then(|at: FileOffset| read_u32(bytes, at, le))
            else {
                break;
            };
            let Some(s): Option<u32> =
                field_at(base, 20).and_then(|at: FileOffset| read_u32(bytes, at, le))
            else {
                break;
            };
            (
                u64::from(f),
                FileOffset::new(u64::from(o)),
                Size::new(u64::from(s)),
            )
        };
        if sh_type != SHT_NOBITS && sh_flags & SHF_EXECINSTR != 0 {
            push_region(&mut layout.regions, bytes.len(), sh_offset, sh_size);
        }
    }
    layout
}

const LC_SEGMENT: u32 = 0x1;
const LC_SEGMENT_64: u32 = 0x19;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

fn macho_code_layout(bytes: &[u8]) -> CodeLayout {
    let mut layout: CodeLayout = CodeLayout::default();
    let Some(magic): Option<u32> = read_u32(bytes, FileOffset::ZERO, true) else {
        return layout;
    };
    let (le, is64): (bool, bool) = match magic {
        0xFEED_FACE => (true, false),
        0xFEED_FACF => (true, true),
        0xCEFA_EDFE => (false, false),
        0xCFFA_EDFE => (false, true),
        _ => return layout,
    };
    layout.bitness = Some(if is64 {
        CodeBitness::Bits64
    } else {
        CodeBitness::Bits32
    });
    let Some(ncmds): Option<u32> = read_u32(bytes, FileOffset::new(16), le) else {
        return layout;
    };
    let mut cmd_off: FileOffset = FileOffset::new(if is64 { 32 } else { 28 });
    let cmds: usize = Size::new(u64::from(ncmds))
        .bounded_element_capacity(MACHO_LOAD_COMMAND_MIN_BYTES, bytes.len())
        .min(MAX_MACHO_LOAD_CMDS);
    for _ in 0..cmds {
        let Some(cmd): Option<u32> = read_u32(bytes, cmd_off, le) else {
            break;
        };
        let Some(cmdsize): Option<u32> =
            field_at(cmd_off, 4).and_then(|at: FileOffset| read_u32(bytes, at, le))
        else {
            break;
        };
        if (cmdsize as usize) < MACHO_LOAD_COMMAND_MIN_BYTES {
            break;
        }
        if cmd == LC_SEGMENT_64 && is64 {
            macho_segment_sections(bytes, cmd_off, le, true, &mut layout.regions);
        } else if cmd == LC_SEGMENT && !is64 {
            macho_segment_sections(bytes, cmd_off, le, false, &mut layout.regions);
        }
        let Some(next): Option<FileOffset> = field_at(cmd_off, u64::from(cmdsize)) else {
            break;
        };
        cmd_off = next;
        let Some(tail): Option<FileOffset> = field_at(cmd_off, 8) else {
            break;
        };
        let Ok(file_len): Result<Size, _> = Size::try_from(bytes.len()) else {
            break;
        };
        if !tail.is_within(file_len) {
            break;
        }
    }
    layout
}

const MACHO_LOAD_COMMAND_MIN_BYTES: usize = 8;

fn macho_segment_sections(
    bytes: &[u8],
    cmd_off: FileOffset,
    le: bool,
    is64: bool,
    regions: &mut Vec<CodeRegion>,
) {
    let (nsects_off, sect_start, sect_size): (u64, u64, u64) =
        if is64 { (64, 72, 80) } else { (48, 56, 68) };
    let Some(nsects): Option<u32> =
        field_at(cmd_off, nsects_off).and_then(|at: FileOffset| read_u32(bytes, at, le))
    else {
        return;
    };
    let Some(table): Option<FileOffset> = field_at(cmd_off, sect_start) else {
        return;
    };
    let n: usize = Size::new(u64::from(nsects))
        .bounded_element_capacity(sect_size as usize, bytes.len())
        .min(MAX_PARSED_SECTIONS);
    for i in 0..n {
        let Some(sbase): Option<FileOffset> = element_at(table, i, sect_size) else {
            break;
        };
        let (size, offset, flags): (Size, FileOffset, u32) = if is64 {
            let Some(sz): Option<u64> =
                field_at(sbase, 40).and_then(|at: FileOffset| read_u64(bytes, at, le))
            else {
                break;
            };
            let Some(o): Option<u32> =
                field_at(sbase, 48).and_then(|at: FileOffset| read_u32(bytes, at, le))
            else {
                break;
            };
            let Some(f): Option<u32> =
                field_at(sbase, 64).and_then(|at: FileOffset| read_u32(bytes, at, le))
            else {
                break;
            };
            (Size::new(sz), FileOffset::new(u64::from(o)), f)
        } else {
            let Some(sz): Option<u32> =
                field_at(sbase, 36).and_then(|at: FileOffset| read_u32(bytes, at, le))
            else {
                break;
            };
            let Some(o): Option<u32> =
                field_at(sbase, 40).and_then(|at: FileOffset| read_u32(bytes, at, le))
            else {
                break;
            };
            let Some(f): Option<u32> =
                field_at(sbase, 56).and_then(|at: FileOffset| read_u32(bytes, at, le))
            else {
                break;
            };
            (Size::new(u64::from(sz)), FileOffset::new(u64::from(o)), f)
        };
        if flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0 {
            push_region(regions, bytes.len(), offset, size);
        }
    }
}

fn code_layout(bytes: &[u8], family: TargetFamily) -> CodeLayout {
    match family {
        TargetFamily::Pe => pe_code_layout(bytes),
        TargetFamily::Elf => elf_code_layout(bytes),
        TargetFamily::MachO => macho_code_layout(bytes),
        _ => CodeLayout::default(),
    }
}

fn scan_executable_code(bytes: &[u8], family: TargetFamily, acc: &mut TechniqueAccumulator) {
    let layout: CodeLayout = code_layout(bytes, family);
    if layout.regions.is_empty() {
        return;
    }
    let mut budget: usize = CODE_SCAN_BUDGET;
    for region in &layout.regions {
        if budget == 0 {
            break;
        }
        let start: usize = region.file_offset.min(bytes.len());
        let avail: usize = region
            .len
            .min(bytes.len().saturating_sub(start))
            .min(budget);
        if avail == 0 {
            continue;
        }
        let slice: &[u8] = &bytes[start..start + avail];
        budget -= avail;
        if shannon_entropy_bits(slice) > CODE_REGION_MAX_ENTROPY_BITS {
            continue;
        }
        collect_anti_disasm(slice, start, acc);
        scan_region_opcodes(slice, start, layout.bitness, bytes, acc);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn scan_region_opcodes(
    slice: &[u8],
    base: usize,
    bitness: Option<CodeBitness>,
    _whole: &[u8],
    acc: &mut TechniqueAccumulator,
) {
    decode::scan_exec_region(slice, base, bitness, acc);
}

#[cfg(target_arch = "wasm32")]
fn scan_region_opcodes(
    slice: &[u8],
    base: usize,
    bitness: Option<CodeBitness>,
    whole: &[u8],
    acc: &mut TechniqueAccumulator,
) {
    collect_red_pill_opcodes(slice, base, acc);
    collect_rdtsc_cpuid_sandwich(slice, base, acc);
    collect_peb_anti_debug(slice, base, bitness, acc);
    collect_hardware_breakpoint(slice, base, acc);
    collect_int_opcodes(slice, base, acc);
    collect_number_sigs(slice, base, whole, acc);
}

#[cfg(not(target_arch = "wasm32"))]
mod decode {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

    use super::{
        CodeBitness, Confidence, Technique, TechniqueAccumulator, qualified_number_role,
        sig_class_technique,
    };
    use crate::anti_analysis_sigs::{NUMBER_SIGS, SignalCorroboration};

    const DECODE_CAP_BYTES: usize = 16 * 1024 * 1024;
    const RDTSC_SANDWICH_SPAN: u64 = 64;
    const PEB_FIELD_WINDOW: u64 = 24;
    const ICEBP_CLUSTER_WINDOW: u64 = 64;
    const CONTEXT_DR7_DISPLACEMENT: u64 = 0x328;
    const CONTEXT_DEBUG_REGISTERS_FLAG: u64 = 0x0001_0010;
    const INT_2D: u8 = 0x2D;
    const VMWARE_VMXH_MAGIC: u64 = 0x564d_5868;
    const CPUID_HYPERVISOR_LEAF: u32 = 0x4000_0000;
    const VMWARE_IO_PORT: u32 = 0x0000_5658;

    struct PebPending {
        label: &'static str,
        base_ip: u64,
        window_end: u64,
    }

    pub(super) fn scan_exec_region(
        slice: &[u8],
        base: usize,
        bitness: Option<CodeBitness>,
        acc: &mut TechniqueAccumulator,
    ) {
        let Some(bitness): Option<CodeBitness> = bitness else {
            return;
        };
        let bits: u32 = match bitness {
            CodeBitness::Bits32 => 32,
            CodeBitness::Bits64 => 64,
        };
        let decode_len: usize = slice.len().min(DECODE_CAP_BYTES);
        if decode_len < slice.len() {
            tracing::debug!(
                target: "disrobe::anti_analysis",
                region_len = slice.len(),
                decoded = decode_len,
                "anti-analysis instruction decode capped"
            );
        }
        let window: &[u8] = &slice[..decode_len];
        let mut decoder: Decoder<'_> =
            Decoder::with_ip(bits, window, base as u64, DecoderOptions::NONE);
        let mut insn: Instruction = Instruction::default();

        let mut rdtsc_ips: Vec<u64> = Vec::new();
        let mut cpuid_ips: Vec<u64> = Vec::new();
        let mut icebp_ips: Vec<u64> = Vec::new();
        let mut hard_trap_ips: Vec<u64> = Vec::new();
        let mut imm_hits: Vec<(u64, u64)> = Vec::new();
        let mut dr7_ips: Vec<u64> = Vec::new();
        let mut io_port_present: bool = false;
        let mut vmxh_present: bool = false;
        let mut peb_pending: Option<PebPending> = None;

        while decoder.can_decode() {
            decoder.decode_out(&mut insn);
            if insn.is_invalid() {
                continue;
            }
            let ip: u64 = insn.ip();
            match insn.mnemonic() {
                Mnemonic::Rdtsc | Mnemonic::Rdtscp => rdtsc_ips.push(ip),
                Mnemonic::Cpuid => cpuid_ips.push(ip),
                Mnemonic::In | Mnemonic::Out => io_port_present = true,
                m @ (Mnemonic::Sgdt
                | Mnemonic::Sidt
                | Mnemonic::Sldt
                | Mnemonic::Smsw
                | Mnemonic::Str) => {
                    if let Some(name) = red_pill_name(m) {
                        acc.add(
                            Technique::AntiVm,
                            Confidence::Low,
                            name,
                            Some(ip as usize),
                            format!("red-pill {name} descriptor-table store at offset 0x{ip:x}"),
                            SignalCorroboration::Standalone,
                        );
                    }
                }
                Mnemonic::Int if int_imm8(&insn) == Some(INT_2D) => {
                    acc.add(
                        Technique::AntiDebug,
                        Confidence::High,
                        "int 2d",
                        Some(ip as usize),
                        format!("int 2d kernel-debugger detection at offset 0x{ip:x}"),
                        SignalCorroboration::Standalone,
                    );
                    hard_trap_ips.push(ip);
                }
                Mnemonic::Int1 => {
                    icebp_ips.push(ip);
                    hard_trap_ips.push(ip);
                }
                _ => {}
            }

            for op in 0..insn.op_count() {
                if let Some(value) = immediate_value(&insn, op) {
                    if value == VMWARE_VMXH_MAGIC {
                        vmxh_present = true;
                    }
                    if is_interesting_immediate(value) {
                        imm_hits.push((value, ip));
                    }
                }
            }

            if has_memory_operand(&insn) && insn.memory_displacement64() == CONTEXT_DR7_DISPLACEMENT
            {
                dr7_ips.push(ip);
            }

            update_peb(&insn, bits, &mut peb_pending, acc);
        }

        let context_flag_present: bool = imm_hits
            .iter()
            .any(|&(value, _): &(u64, u64)| value == CONTEXT_DEBUG_REGISTERS_FLAG);

        emit_sandwich(&rdtsc_ips, &cpuid_ips, acc);
        emit_icebp_clusters(&icebp_ips, &hard_trap_ips, acc);
        emit_constants(
            &imm_hits,
            !cpuid_ips.is_empty(),
            io_port_present,
            vmxh_present,
            acc,
        );
        if context_flag_present {
            emit_dr7_reads(&dr7_ips, acc);
        }
    }

    fn emit_dr7_reads(dr7_ips: &[u64], acc: &mut TechniqueAccumulator) {
        for &ip in dr7_ips {
            acc.add(
                Technique::AntiDebug,
                Confidence::Low,
                "context dr7 read",
                Some(ip as usize),
                format!("x64 context dr7 offset 0x328 read at offset 0x{ip:x}"),
                SignalCorroboration::Standalone,
            );
        }
    }

    const fn red_pill_name(m: Mnemonic) -> Option<&'static str> {
        match m {
            Mnemonic::Sgdt => Some("sgdt"),
            Mnemonic::Sidt => Some("sidt"),
            Mnemonic::Sldt => Some("sldt"),
            Mnemonic::Smsw => Some("smsw"),
            Mnemonic::Str => Some("str"),
            _ => None,
        }
    }

    fn int_imm8(insn: &Instruction) -> Option<u8> {
        (insn.op0_kind() == OpKind::Immediate8).then(|| insn.immediate8())
    }

    fn immediate_value(insn: &Instruction, op: u32) -> Option<u64> {
        match insn.op_kind(op) {
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => Some(insn.immediate(op)),
            _ => None,
        }
    }

    fn has_memory_operand(insn: &Instruction) -> bool {
        (0..insn.op_count()).any(|op: u32| insn.op_kind(op) == OpKind::Memory)
    }

    fn is_interesting_immediate(value: u64) -> bool {
        value == CONTEXT_DEBUG_REGISTERS_FLAG
            || NUMBER_SIGS.iter().any(|sig| u64::from(sig.value) == value)
    }

    fn update_peb(
        insn: &Instruction,
        bits: u32,
        pending: &mut Option<PebPending>,
        acc: &mut TechniqueAccumulator,
    ) {
        if let Some(label) = peb_base_load_label(insn, bits) {
            *pending = Some(PebPending {
                label,
                base_ip: insn.ip(),
                window_end: insn.next_ip().saturating_add(PEB_FIELD_WINDOW),
            });
            return;
        }
        let Some(state): Option<&PebPending> = pending.as_ref() else {
            return;
        };
        if insn.ip() >= state.window_end {
            *pending = None;
            return;
        }
        if let Some(field) = peb_field_label(insn) {
            let base_ip: u64 = state.base_ip;
            let load: &'static str = state.label;
            acc.add(
                Technique::AntiDebug,
                Confidence::High,
                "peb anti-debug field read",
                Some(base_ip as usize),
                format!("{load} peb-base load then {field} read at offset 0x{base_ip:x}"),
                SignalCorroboration::Standalone,
            );
            *pending = None;
        }
    }

    fn peb_base_load_label(insn: &Instruction, bits: u32) -> Option<&'static str> {
        if !has_memory_operand(insn) {
            return None;
        }
        let segment: Register = insn.memory_segment();
        let displacement: u64 = insn.memory_displacement64();
        match bits {
            32 if segment == Register::FS && displacement == 0x30 => Some("fs:[0x30] 32-bit"),
            64 if segment == Register::GS && displacement == 0x60 => Some("gs:[0x60] 64-bit"),
            _ => None,
        }
    }

    fn peb_field_label(insn: &Instruction) -> Option<&'static str> {
        if !has_memory_operand(insn) {
            return None;
        }
        match insn.memory_displacement64() {
            0x02 => Some("beingdebugged (+0x02)"),
            0x68 => Some("ntglobalflag (+0x68 wow64)"),
            0xBC => Some("ntglobalflag (+0xbc native)"),
            _ => None,
        }
    }

    fn emit_sandwich(rdtsc_ips: &[u64], cpuid_ips: &[u64], acc: &mut TechniqueAccumulator) {
        for &start in rdtsc_ips {
            let end: u64 = start.saturating_add(RDTSC_SANDWICH_SPAN);
            let has_cpuid: bool = cpuid_ips.iter().any(|&c: &u64| c > start && c <= end);
            let has_second: bool = rdtsc_ips.iter().any(|&r: &u64| r > start && r <= end);
            if has_cpuid && has_second {
                acc.add(
                    Technique::TimingEvasion,
                    Confidence::High,
                    "rdtsc-cpuid-rdtsc sandwich",
                    Some(start as usize),
                    format!("rdtsc-cpuid-rdtsc vm-exit timing sandwich at offset 0x{start:x}"),
                    SignalCorroboration::Standalone,
                );
            }
        }
    }

    fn emit_icebp_clusters(
        icebp_ips: &[u64],
        hard_trap_ips: &[u64],
        acc: &mut TechniqueAccumulator,
    ) {
        for &p in icebp_ips {
            let clustered: bool = hard_trap_ips
                .iter()
                .any(|&q: &u64| q != p && p.abs_diff(q) <= ICEBP_CLUSTER_WINDOW);
            if clustered {
                acc.add(
                    Technique::AntiDebug,
                    Confidence::Low,
                    "icebp deliberate-fault cluster",
                    Some(p as usize),
                    format!(
                        "icebp (int1) single-step trap (deliberate-fault cluster) at offset 0x{p:x}"
                    ),
                    SignalCorroboration::Standalone,
                );
            }
        }
    }

    fn emit_constants(
        imm_hits: &[(u64, u64)],
        cpuid_present: bool,
        io_port_present: bool,
        vmxh_present: bool,
        acc: &mut TechniqueAccumulator,
    ) {
        for &(value, ip) in imm_hits {
            if value == CONTEXT_DEBUG_REGISTERS_FLAG {
                acc.add(
                    Technique::AntiDebug,
                    Confidence::Low,
                    "context-debug-registers flag",
                    Some(ip as usize),
                    format!(
                        "context-debug-registers flag 0x10010 (hardware-breakpoint inspection) at offset 0x{ip:x}"
                    ),
                    SignalCorroboration::Standalone,
                );
            }
            for sig in NUMBER_SIGS {
                if u64::from(sig.value) != value {
                    continue;
                }
                let corroborated: bool = match sig.corroboration {
                    SignalCorroboration::Corroborated => immediate_corroborated(
                        sig.value,
                        cpuid_present,
                        io_port_present,
                        vmxh_present,
                    ),
                    SignalCorroboration::Standalone | SignalCorroboration::ContextOnly => false,
                };
                let Some(role): Option<SignalCorroboration> =
                    qualified_number_role(sig.corroboration, corroborated)
                else {
                    continue;
                };
                acc.add(
                    sig_class_technique(sig.class),
                    sig.confidence,
                    sig.note,
                    Some(ip as usize),
                    format!(
                        "magic constant 0x{:x} ({}) at offset 0x{:x}",
                        sig.value, sig.note, ip
                    ),
                    role,
                );
            }
        }
    }

    const fn immediate_corroborated(
        value: u32,
        cpuid_present: bool,
        io_port_present: bool,
        vmxh_present: bool,
    ) -> bool {
        match value {
            CPUID_HYPERVISOR_LEAF => cpuid_present,
            VMWARE_IO_PORT => io_port_present || vmxh_present,
            _ => false,
        }
    }
}

fn collect_anti_disasm(bytes: &[u8], base: usize, acc: &mut TechniqueAccumulator) {
    let limit: usize = bytes.len();
    let mut shapes: Vec<(usize, &'static str)> = Vec::new();
    let mut i: usize = 0;
    while i + 3 < limit {
        if let Some(detail) = anti_disasm_shape_at(bytes, i, limit) {
            shapes.push((i, detail));
        }
        i += 1;
    }
    if shapes.is_empty() {
        return;
    }
    let clustered: bool = has_shape_cluster(&shapes, 3, 256);
    for (off, detail) in &shapes {
        let confidence: Confidence = if clustered {
            Confidence::High
        } else {
            Confidence::Low
        };
        acc.add(
            Technique::AntiDisassembly,
            confidence,
            detail,
            Some(base + off),
            format!("{detail} at offset 0x{:x}", base + off),
            SignalCorroboration::Standalone,
        );
    }
}

fn anti_disasm_shape_at(bytes: &[u8], i: usize, limit: usize) -> Option<&'static str> {
    if bytes[i] == 0xEB && bytes[i + 1] == 0x01 {
        let overlapped: u8 = bytes[i + 2];
        if is_multibyte_opcode_lead(overlapped) {
            return Some("short jump into mid-instruction byte");
        }
    }
    if let Some(detail) = double_jcc_same_target(bytes, i, limit) {
        return Some(detail);
    }
    None
}

fn double_jcc_same_target(bytes: &[u8], i: usize, limit: usize) -> Option<&'static str> {
    if i + 3 >= limit {
        return None;
    }
    let first_op: u8 = bytes[i];
    let second_op: u8 = bytes[i + 2];
    if !is_short_jcc(first_op) || !is_short_jcc(second_op) {
        return None;
    }
    if !is_complementary_jcc(first_op, second_op) {
        return None;
    }
    let first_target: i64 = i as i64 + 2 + i8::from_le_bytes([bytes[i + 1]]) as i64;
    let second_target: i64 = i as i64 + 4 + i8::from_le_bytes([bytes[i + 3]]) as i64;
    if first_target == second_target {
        Some("complementary jcc pair to one target (always-jump)")
    } else {
        None
    }
}

const fn is_short_jcc(b: u8) -> bool {
    matches!(b, 0x70..=0x7F)
}

const fn is_complementary_jcc(a: u8, b: u8) -> bool {
    a ^ 0x01 == b
}

fn has_shape_cluster(shapes: &[(usize, &'static str)], min_count: usize, span: usize) -> bool {
    if shapes.len() < min_count {
        return false;
    }
    let mut start: usize = 0;
    for end in 0..shapes.len() {
        while shapes[end].0.saturating_sub(shapes[start].0) > span {
            start += 1;
        }
        if end - start + 1 >= min_count {
            return true;
        }
    }
    false
}

#[cfg(target_arch = "wasm32")]
fn collect_red_pill_opcodes(bytes: &[u8], base: usize, acc: &mut TechniqueAccumulator) {
    let limit: usize = bytes.len();
    let mut i: usize = 0;
    while i + 2 < limit {
        if let Some(mnemonic) = red_pill_mnemonic(bytes[i], bytes[i + 1], bytes[i + 2]) {
            acc.add(
                Technique::AntiVm,
                Confidence::Low,
                mnemonic,
                Some(base + i),
                format!(
                    "red-pill {mnemonic} descriptor-table store at offset 0x{:x}",
                    base + i
                ),
                SignalCorroboration::Standalone,
            );
        }
        i += 1;
    }
}

#[cfg(target_arch = "wasm32")]
const fn red_pill_mnemonic(b0: u8, b1: u8, modrm: u8) -> Option<&'static str> {
    let reg: u8 = (modrm >> 3) & 0x07;
    let is_mem: bool = (modrm >> 6) != 0x03;
    match (b0, b1) {
        (0x0F, 0x01) if is_mem => match reg {
            0 => Some("sgdt"),
            1 => Some("sidt"),
            4 => Some("smsw"),
            _ => None,
        },
        (0x0F, 0x00) => match reg {
            0 => Some("sldt"),
            1 => Some("str"),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(target_arch = "wasm32")]
const RDTSC_SANDWICH_SPAN: usize = 64;

#[cfg(target_arch = "wasm32")]
fn collect_rdtsc_cpuid_sandwich(bytes: &[u8], base: usize, acc: &mut TechniqueAccumulator) {
    let limit: usize = bytes.len();
    let rdtsc: [u8; 2] = [0x0F, 0x31];
    let cpuid: [u8; 2] = [0x0F, 0xA2];
    let mut i: usize = 0;
    while i + 1 < limit {
        if bytes[i] == rdtsc[0] && bytes[i + 1] == rdtsc[1] {
            let hi: usize = (i + RDTSC_SANDWICH_SPAN).min(limit);
            let rest: &[u8] = &bytes[i + 2..hi];
            let has_cpuid: bool = rest.windows(2).any(|w: &[u8]| w == cpuid);
            let has_second_rdtsc: bool = rest.windows(2).any(|w: &[u8]| w == rdtsc);
            if has_cpuid && has_second_rdtsc {
                acc.add(
                    Technique::TimingEvasion,
                    Confidence::High,
                    "rdtsc-cpuid-rdtsc sandwich",
                    Some(base + i),
                    format!(
                        "rdtsc-cpuid-rdtsc vm-exit timing sandwich at offset 0x{:x}",
                        base + i
                    ),
                    SignalCorroboration::Standalone,
                );
            }
        }
        i += 1;
    }
}

#[cfg(target_arch = "wasm32")]
const PEB_DEREF_WINDOW: usize = 24;

#[cfg(target_arch = "wasm32")]
fn collect_peb_anti_debug(
    bytes: &[u8],
    base: usize,
    bitness: Option<CodeBitness>,
    acc: &mut TechniqueAccumulator,
) {
    let limit: usize = bytes.len();
    let mut i: usize = 0;
    while i < limit {
        if let Some((len, label)) = peb_base_load_at(bytes, i, limit, bitness) {
            let lo: usize = i + len;
            let hi: usize = (lo + PEB_DEREF_WINDOW).min(limit);
            if let Some(field) = peb_field_in_window(&bytes[lo..hi]) {
                acc.add(
                    Technique::AntiDebug,
                    Confidence::High,
                    "peb anti-debug field read",
                    Some(base + i),
                    format!(
                        "{label} peb-base load then {field} read at offset 0x{:x}",
                        base + i
                    ),
                    SignalCorroboration::Standalone,
                );
            }
            i += len;
            continue;
        }
        i += 1;
    }
}

#[cfg(target_arch = "wasm32")]
fn peb_base_load_at(
    bytes: &[u8],
    i: usize,
    limit: usize,
    bitness: Option<CodeBitness>,
) -> Option<(usize, &'static str)> {
    match bitness {
        Some(CodeBitness::Bits32)
            if i + 6 <= limit && bytes[i..i + 6] == [0x64, 0xA1, 0x30, 0x00, 0x00, 0x00] =>
        {
            Some((6, "fs:[0x30] 32-bit"))
        }
        Some(CodeBitness::Bits64)
            if i + 9 <= limit
                && bytes[i..i + 9] == [0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00] =>
        {
            Some((9, "gs:[0x60] 64-bit"))
        }
        _ => None,
    }
}

#[cfg(target_arch = "wasm32")]
fn peb_field_in_window(window: &[u8]) -> Option<&'static str> {
    if window.contains(&0x02) && window_has_byte_deref(window) {
        return Some("beingdebugged (+0x02)");
    }
    if window.contains(&0x68) {
        return Some("ntglobalflag (+0x68 wow64)");
    }
    if window.contains(&0xBC) {
        return Some("ntglobalflag (+0xbc native)");
    }
    None
}

#[cfg(target_arch = "wasm32")]
fn window_has_byte_deref(window: &[u8]) -> bool {
    window
        .windows(2)
        .any(|w: &[u8]| matches!(w[0], 0x8A | 0x0F | 0x80 | 0x38 | 0x3A | 0xF6))
}

#[cfg(target_arch = "wasm32")]
fn collect_hardware_breakpoint(bytes: &[u8], base: usize, acc: &mut TechniqueAccumulator) {
    let limit: usize = bytes.len();
    if limit < 4 {
        return;
    }
    let context_flag: [u8; 4] = 0x0001_0010u32.to_le_bytes();
    let dr7_offset: [u8; 4] = 0x0000_0328u32.to_le_bytes();
    let mut i: usize = 0;
    while i + 4 <= limit {
        let window: [u8; 4] = [bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]];
        if window == context_flag {
            acc.add(
                Technique::AntiDebug,
                Confidence::Low,
                "context-debug-registers flag",
                Some(base + i),
                format!(
                    "context-debug-registers flag 0x10010 (hardware-breakpoint inspection) at offset 0x{:x}",
                    base + i
                ),
                SignalCorroboration::Standalone,
            );
        } else if window == dr7_offset && window_references_dr7(bytes, i) {
            acc.add(
                Technique::AntiDebug,
                Confidence::Low,
                "context dr7 read",
                Some(base + i),
                format!(
                    "x64 context dr7 offset 0x328 read at offset 0x{:x}",
                    base + i
                ),
                SignalCorroboration::Standalone,
            );
        }
        i += 1;
    }
}

#[cfg(target_arch = "wasm32")]
fn window_references_dr7(bytes: &[u8], at: usize) -> bool {
    let lo: usize = at.saturating_sub(3);
    let prefix: &[u8] = &bytes[lo..at];
    prefix
        .iter()
        .any(|b: &u8| matches!(b, 0x8B | 0x48 | 0x4C | 0x39 | 0x3B))
}

#[cfg(target_arch = "wasm32")]
const ICEBP_CLUSTER_WINDOW: usize = 64;

#[cfg(target_arch = "wasm32")]
fn collect_int_opcodes(bytes: &[u8], base: usize, acc: &mut TechniqueAccumulator) {
    let limit: usize = bytes.len();
    let mut icebp: Vec<usize> = Vec::new();
    let mut hard_traps: Vec<usize> = Vec::new();
    let mut i: usize = 0;
    while i + 1 < limit {
        if bytes[i] == 0xCD && bytes[i + 1] == 0x2D {
            acc.add(
                Technique::AntiDebug,
                Confidence::High,
                "int 2d",
                Some(base + i),
                format!(
                    "int 2d kernel-debugger detection at offset 0x{:x}",
                    base + i
                ),
                SignalCorroboration::Standalone,
            );
            hard_traps.push(i);
        }
        if bytes[i] == 0xF1 && is_icebp_in_code(bytes, i, limit) {
            icebp.push(i);
            hard_traps.push(i);
        }
        i += 1;
    }
    for &p in &icebp {
        let clustered: bool = hard_traps
            .iter()
            .any(|&q: &usize| q != p && p.abs_diff(q) <= ICEBP_CLUSTER_WINDOW);
        if clustered {
            acc.add(
                Technique::AntiDebug,
                Confidence::Low,
                "icebp deliberate-fault cluster",
                Some(base + p),
                format!(
                    "icebp (int1) single-step trap (deliberate-fault cluster) at offset 0x{:x}",
                    base + p
                ),
                SignalCorroboration::Standalone,
            );
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn is_icebp_in_code(bytes: &[u8], at: usize, limit: usize) -> bool {
    let before_ok: bool = at >= 1 && is_plausible_code_byte(bytes[at - 1]);
    let after_ok: bool = at + 1 < limit && is_plausible_code_byte(bytes[at + 1]);
    before_ok && after_ok
}

#[cfg(target_arch = "wasm32")]
const fn is_plausible_code_byte(b: u8) -> bool {
    matches!(
        b,
        0x90 | 0xCC | 0xC3 | 0xEB | 0xE8 | 0xE9 | 0x0F | 0xFF | 0x50..=0x5F | 0x89 | 0x8B | 0x48
    )
}

fn collect_string_encryption(bytes: &[u8], family: TargetFamily, acc: &mut TechniqueAccumulator) {
    if matches!(family, TargetFamily::Text) {
        return;
    }
    if has_single_byte_xor_string_block(bytes) {
        acc.add(
            Technique::StringEncryption,
            Confidence::Medium,
            "xor string block",
            None,
            "single-byte xor encoded ascii string block".to_string(),
            SignalCorroboration::Standalone,
        );
    }
}

const fn is_multibyte_opcode_lead(b: u8) -> bool {
    matches!(
        b,
        0xE8 | 0xE9 | 0x0F | 0xFF | 0x68 | 0x05 | 0x3D | 0x25 | 0x2D
    )
}

const XOR_RUN_MIN: usize = 8;
const XOR_BLOCK_MIN_RUNS: usize = 4;
const XOR_OUTLIER_MARGIN: usize = 4;
const XOR_MIN_WORD_LEN: usize = 3;
const XOR_PLAINTEXT_WORD_FLOOR: usize = 4;
const XOR_MAX_ENTROPY_BITS: f64 = 7.2;
const XOR_MAX_DOMINANT_FRACTION: f64 = 0.6;

fn dominant_byte_fraction(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts: [u32; 256] = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let top: u32 = counts.iter().copied().max().unwrap_or(0);
    f64::from(top) / bytes.len() as f64
}

fn has_single_byte_xor_string_block(bytes: &[u8]) -> bool {
    let sample: &[u8] = &bytes[..bytes.len().min(1 << 18)];
    if shannon_entropy_bits(sample) >= XOR_MAX_ENTROPY_BITS {
        return false;
    }
    if dominant_byte_fraction(sample) > XOR_MAX_DOMINANT_FRACTION {
        return false;
    }
    if word_like_token_count(sample, 0) >= XOR_PLAINTEXT_WORD_FLOOR {
        return false;
    }
    let plaintext_runs: usize = count_decoded_ascii_runs(sample, 0);
    let mut best_key_runs: usize = 0;
    for key in 1u16..=255u16 {
        let runs: usize = count_decoded_ascii_runs(sample, key as u8);
        if runs > best_key_runs {
            best_key_runs = runs;
        }
    }
    best_key_runs >= XOR_BLOCK_MIN_RUNS
        && best_key_runs
            >= plaintext_runs
                .saturating_mul(XOR_OUTLIER_MARGIN)
                .max(XOR_BLOCK_MIN_RUNS)
}

fn word_like_token_count(bytes: &[u8], key: u8) -> usize {
    let mut tokens: usize = 0;
    let mut letters: usize = 0;
    for &b in bytes {
        let decoded: u8 = b ^ key;
        if decoded.is_ascii_alphabetic() {
            letters += 1;
            continue;
        }
        if letters >= XOR_MIN_WORD_LEN {
            tokens += 1;
        }
        letters = 0;
    }
    if letters >= XOR_MIN_WORD_LEN {
        tokens += 1;
    }
    tokens
}

fn count_decoded_ascii_runs(bytes: &[u8], key: u8) -> usize {
    let mut runs: usize = 0;
    let mut run: usize = 0;
    for &b in bytes {
        let decoded: u8 = b ^ key;
        if is_inner_ascii(decoded) {
            run += 1;
            continue;
        }
        if run >= XOR_RUN_MIN {
            runs += 1;
        }
        run = 0;
    }
    if run >= XOR_RUN_MIN {
        runs += 1;
    }
    runs
}

const fn is_inner_ascii(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b' ' | b'/' | b'.' | b'_' | b'-' | b':')
}

fn is_word_bounded(haystack: &str, needle: &str) -> bool {
    let bytes: &[u8] = haystack.as_bytes();
    let nlen: usize = needle.len();
    let mut from: usize = 0;
    while let Some(rel) = haystack[from..].find(needle) {
        let at: usize = from + rel;
        let before_ok: bool = at == 0 || !is_ident_byte(bytes[at - 1]);
        let after_idx: usize = at + nlen;
        let after_ok: bool = after_idx >= bytes.len() || !is_ident_byte(bytes[after_idx]);
        if before_ok && after_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

#[inline]
const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn qualified_number_roles_preserve_the_closed_role_semantics() {
        assert_eq!(
            qualified_number_role(SignalCorroboration::Standalone, false),
            Some(SignalCorroboration::Standalone)
        );
        assert_eq!(
            qualified_number_role(SignalCorroboration::Standalone, true),
            Some(SignalCorroboration::Standalone)
        );
        assert_eq!(
            qualified_number_role(SignalCorroboration::Corroborated, false),
            None
        );
        assert_eq!(
            qualified_number_role(SignalCorroboration::Corroborated, true),
            Some(SignalCorroboration::Standalone)
        );
        assert_eq!(
            qualified_number_role(SignalCorroboration::ContextOnly, false),
            Some(SignalCorroboration::ContextOnly)
        );
        assert_eq!(
            qualified_number_role(SignalCorroboration::ContextOnly, true),
            Some(SignalCorroboration::ContextOnly)
        );
    }

    fn assert_regions_inside(layout: &CodeLayout, image_len: usize, label: &str) {
        for region in &layout.regions {
            let end: usize = region
                .file_offset
                .checked_add(region.len)
                .unwrap_or_else(|| panic!("{label} produced a region whose end overflows"));
            assert!(
                end <= image_len,
                "{label} produced a region {}..{end} outside a {image_len}-byte image",
                region.file_offset
            );
        }
    }

    fn elf64_header(shoff: u64, shentsize: u16, shnum: u16) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; 4096];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 2;
        out[5] = 1;
        out[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        out[0x3A..0x3C].copy_from_slice(&shentsize.to_le_bytes());
        out[0x3C..0x3E].copy_from_slice(&shnum.to_le_bytes());
        out
    }

    fn pe_header(lfanew: u32, opt_size: u16, num_sections: u16) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; 4096];
        out[..2].copy_from_slice(b"MZ");
        out[0x3C..0x40].copy_from_slice(&lfanew.to_le_bytes());
        let at: usize = lfanew as usize;
        if let Some(slot) = out.get_mut(at..at + 4) {
            slot.copy_from_slice(b"PE\0\0");
        }
        if let Some(slot) = out.get_mut(at + 6..at + 8) {
            slot.copy_from_slice(&num_sections.to_le_bytes());
        }
        if let Some(slot) = out.get_mut(at + 20..at + 22) {
            slot.copy_from_slice(&opt_size.to_le_bytes());
        }
        if let Some(slot) = out.get_mut(at + 24..at + 26) {
            slot.copy_from_slice(&0x020Bu16.to_le_bytes());
        }
        out
    }

    fn macho64_header(ncmds: u32, cmdsize: u32, nsects: u32) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; 4096];
        out[..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
        out[16..20].copy_from_slice(&ncmds.to_le_bytes());
        out[32..36].copy_from_slice(&0x19u32.to_le_bytes());
        out[36..40].copy_from_slice(&cmdsize.to_le_bytes());
        out[96..100].copy_from_slice(&nsects.to_le_bytes());
        out
    }

    #[test]
    fn an_elf_section_table_at_the_width_ceiling_yields_no_region() {
        for shoff in [u64::MAX, u64::MAX - 1, u64::MAX / 2, u64::from(u32::MAX)] {
            let sample: Vec<u8> = elf64_header(shoff, u16::MAX, u16::MAX);
            let layout: CodeLayout = elf_code_layout(&sample);
            assert_regions_inside(&layout, sample.len(), &format!("elf shoff {shoff:#x}"));
            assert!(
                layout.regions.is_empty(),
                "an elf section table at {shoff:#x} reaches no file bytes"
            );
        }
    }

    #[test]
    fn a_pe_section_table_at_the_width_ceiling_yields_no_region() {
        for (lfanew, opt_size) in [
            (u32::MAX, u16::MAX),
            (u32::MAX - 8, u16::MAX),
            (0x0100, u16::MAX),
        ] {
            let sample: Vec<u8> = pe_header(lfanew, opt_size, u16::MAX);
            let layout: CodeLayout = pe_code_layout(&sample);
            assert_regions_inside(&layout, sample.len(), &format!("pe lfanew {lfanew:#x}"));
        }
    }

    #[test]
    fn a_macho_load_command_chain_at_the_width_ceiling_yields_no_region() {
        for cmdsize in [u32::MAX, u32::MAX - 8, 8] {
            let sample: Vec<u8> = macho64_header(u32::MAX, cmdsize, u32::MAX);
            let layout: CodeLayout = macho_code_layout(&sample);
            assert_regions_inside(
                &layout,
                sample.len(),
                &format!("macho cmdsize {cmdsize:#x}"),
            );
        }
    }

    #[test]
    fn a_section_count_past_the_file_cannot_drive_the_element_loop() {
        let sample: Vec<u8> = elf64_header(0x40, 64, u16::MAX);
        let layout: CodeLayout = elf_code_layout(&sample);
        assert_regions_inside(&layout, sample.len(), "elf oversized shnum");
        let dense: Vec<u8> = elf64_header(0x40, 1, u16::MAX);
        let dense_layout: CodeLayout = elf_code_layout(&dense);
        assert_regions_inside(&dense_layout, dense.len(), "elf single-byte shentsize");
    }

    #[test]
    fn a_truncated_but_legitimate_elf_still_reads_what_exists() {
        let mut sample: Vec<u8> = elf64_header(0x40, 64, 4);
        sample[0x40 + 4..0x40 + 8].copy_from_slice(&1u32.to_le_bytes());
        sample[0x40 + 8..0x40 + 16].copy_from_slice(&SHF_EXECINSTR.to_le_bytes());
        sample[0x40 + 24..0x40 + 32].copy_from_slice(&512u64.to_le_bytes());
        sample[0x40 + 32..0x40 + 40].copy_from_slice(&256u64.to_le_bytes());
        let full: CodeLayout = elf_code_layout(&sample);
        assert_eq!(full.regions.len(), 1, "the planted section must be read");
        assert_eq!(full.regions[0].file_offset, 512);
        assert_eq!(full.regions[0].len, 256);

        sample.truncate(600);
        let clipped: CodeLayout = elf_code_layout(&sample);
        assert_regions_inside(&clipped, sample.len(), "truncated elf");
        assert_eq!(
            clipped.regions.len(),
            1,
            "a truncated file must still yield the part that exists"
        );
        assert_eq!(clipped.regions[0].len, 600 - 512);
    }

    const PE_REFERENCE_ARTIFACTS: [&str; 2] = [
        "native/formats/hello.pe64.exe",
        "native/anti-analysis/large-benign-x86_64-pc-windows-msvc.exe",
    ];
    const ELF_REFERENCE_ARTIFACTS: [&str; 2] =
        ["native/formats/hello.elf64", "native/nim/hello.nim.elf"];
    const MACHO_REFERENCE_ARTIFACTS: [&str; 2] = [
        "mobile/macho-mac/SwiftHello.original",
        "native/formats/hello.macho64.o",
    ];
    const REFERENCE_EXECUTABLE_REGIONS: usize = 11;

    type CodeLayoutWalk = fn(&[u8]) -> CodeLayout;
    type ReferenceWalk = fn(&[u8]) -> ReferenceLayout;
    type TruncationCase = (&'static str, CodeLayoutWalk, usize);

    #[derive(Debug)]
    struct ReferenceLayout {
        regions: Vec<(usize, usize)>,
        bitness: CodeBitness,
    }

    fn reference_artifact(relative: &str) -> Vec<u8> {
        let path: std::path::PathBuf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(relative);
        std::fs::read(&path).unwrap_or_else(|err: std::io::Error| {
            panic!(
                "the reference artifact {} must be readable to grade the code-layout walks: {err}",
                path.display()
            )
        })
    }

    fn clamped_region(image_len: usize, offset: u64, len: u64) -> Option<(usize, usize)> {
        let start: usize = usize::try_from(offset).ok()?;
        if len == 0 || start >= image_len {
            return None;
        }
        let end: usize = usize::try_from(len)
            .map_or(image_len, |bytes: usize| start.saturating_add(bytes))
            .min(image_len);
        if end <= start {
            return None;
        }
        Some((start, end - start))
    }

    fn observed_regions(layout: &CodeLayout) -> Vec<(usize, usize)> {
        let mut out: Vec<(usize, usize)> = layout
            .regions
            .iter()
            .map(|region: &CodeRegion| (region.file_offset, region.len))
            .collect();
        out.sort_unstable();
        out
    }

    fn bitness_of(is_64: bool) -> CodeBitness {
        if is_64 {
            CodeBitness::Bits64
        } else {
            CodeBitness::Bits32
        }
    }

    fn reference_pe_layout(bytes: &[u8]) -> ReferenceLayout {
        let pe: goblin::pe::PE<'_> =
            goblin::pe::PE::parse(bytes).unwrap_or_else(|err: goblin::error::Error| {
                panic!("the reference parser must read this pe: {err}")
            });
        let mut regions: Vec<(usize, usize)> = pe
            .sections
            .iter()
            .filter(|section: &&goblin::pe::section_table::SectionTable| {
                section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0
            })
            .filter_map(|section: &goblin::pe::section_table::SectionTable| {
                clamped_region(
                    bytes.len(),
                    u64::from(section.pointer_to_raw_data),
                    u64::from(section.size_of_raw_data),
                )
            })
            .collect();
        regions.sort_unstable();
        ReferenceLayout {
            regions,
            bitness: bitness_of(pe.is_64),
        }
    }

    fn reference_elf_layout(bytes: &[u8]) -> ReferenceLayout {
        let elf: goblin::elf::Elf<'_> =
            goblin::elf::Elf::parse(bytes).unwrap_or_else(|err: goblin::error::Error| {
                panic!("the reference parser must read this elf: {err}")
            });
        let mut regions: Vec<(usize, usize)> = elf
            .section_headers
            .iter()
            .filter(|header: &&goblin::elf::SectionHeader| {
                header.sh_type != goblin::elf::section_header::SHT_NOBITS
                    && header.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0
            })
            .filter_map(|header: &goblin::elf::SectionHeader| {
                clamped_region(bytes.len(), header.sh_offset, header.sh_size)
            })
            .collect();
        regions.sort_unstable();
        ReferenceLayout {
            regions,
            bitness: bitness_of(elf.is_64),
        }
    }

    fn reference_macho_layout(bytes: &[u8]) -> ReferenceLayout {
        let mach: goblin::mach::MachO<'_> =
            goblin::mach::MachO::parse(bytes, 0).unwrap_or_else(|err: goblin::error::Error| {
                panic!("the reference parser must read this mach-o: {err}")
            });
        let mut regions: Vec<(usize, usize)> = Vec::new();
        for segment in &mach.segments {
            let sections: Vec<(
                goblin::mach::segment::Section,
                goblin::mach::segment::SectionData<'_>,
            )> = segment
                .sections()
                .unwrap_or_else(|err: goblin::error::Error| {
                    panic!("the reference parser must read this mach-o segment: {err}")
                });
            for (section, _data) in &sections {
                if section.flags
                    & (goblin::mach::constants::S_ATTR_PURE_INSTRUCTIONS
                        | goblin::mach::constants::S_ATTR_SOME_INSTRUCTIONS)
                    == 0
                {
                    continue;
                }
                if let Some(region) =
                    clamped_region(bytes.len(), u64::from(section.offset), section.size)
                {
                    regions.push(region);
                }
            }
        }
        regions.sort_unstable();
        ReferenceLayout {
            regions,
            bitness: bitness_of(mach.is_64),
        }
    }

    fn grade_family(
        artifacts: &[&str],
        walk: CodeLayoutWalk,
        reference: ReferenceWalk,
        totals: &mut (usize, usize),
    ) {
        for relative in artifacts {
            let bytes: Vec<u8> = reference_artifact(relative);
            let expected: ReferenceLayout = reference(&bytes);
            assert!(
                !expected.regions.is_empty(),
                "{relative} must contribute at least one reference executable region"
            );
            let layout: CodeLayout = walk(&bytes);
            let observed: Vec<(usize, usize)> = observed_regions(&layout);
            assert_eq!(
                observed, expected.regions,
                "{relative}: the executable file regions must match the reference parser"
            );
            assert_eq!(
                layout.bitness,
                Some(expected.bitness),
                "{relative}: the bitness must match the reference parser"
            );
            totals.0 += expected
                .regions
                .iter()
                .filter(|region: &&(usize, usize)| observed.contains(region))
                .count();
            totals.1 += expected.regions.len();
        }
    }

    #[test]
    fn committed_binaries_grade_the_code_layout_walks_against_the_reference_parser() {
        let mut totals: (usize, usize) = (0, 0);
        grade_family(
            &PE_REFERENCE_ARTIFACTS,
            pe_code_layout,
            reference_pe_layout,
            &mut totals,
        );
        grade_family(
            &ELF_REFERENCE_ARTIFACTS,
            elf_code_layout,
            reference_elf_layout,
            &mut totals,
        );
        grade_family(
            &MACHO_REFERENCE_ARTIFACTS,
            macho_code_layout,
            reference_macho_layout,
            &mut totals,
        );
        let (matched, expected): (usize, usize) = totals;
        assert_eq!(
            matched, expected,
            "the code-layout walks recovered {matched}/{expected} reference executable regions"
        );
        assert_eq!(
            expected, REFERENCE_EXECUTABLE_REGIONS,
            "the six committed artifacts no longer hold the recorded number of reference executable regions; re-derive this count from the reference parser after a fixture change, never raise it to match a walk"
        );
    }

    fn pe_section_count_offset(bytes: &[u8]) -> usize {
        let raw: [u8; 4] = bytes[0x3C..0x40].try_into().unwrap();
        usize::try_from(u32::from_le_bytes(raw)).unwrap() + 6
    }

    #[test]
    fn a_crafted_pe_section_count_stays_bounded_and_keeps_the_reference_regions() {
        let original: Vec<u8> = reference_artifact(PE_REFERENCE_ARTIFACTS[0]);
        let genuine: Vec<(usize, usize)> = reference_pe_layout(&original).regions;
        assert!(
            !genuine.is_empty(),
            "the unmodified reference pe must yield regions"
        );
        let mut crafted: Vec<u8> = original;
        let count_at: usize = pe_section_count_offset(&crafted);
        crafted[count_at..count_at + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        let layout: CodeLayout = pe_code_layout(&crafted);
        assert_regions_inside(&layout, crafted.len(), "pe with a crafted section count");
        assert!(
            layout.regions.len() <= MAX_PARSED_SECTIONS,
            "a crafted section count admitted {} regions past the {MAX_PARSED_SECTIONS} ceiling",
            layout.regions.len()
        );
        let crafted_regions: Vec<(usize, usize)> = observed_regions(&layout);
        for region in &genuine {
            assert!(
                crafted_regions.contains(region),
                "a crafted section count must not lose the reference region {region:?}"
            );
        }
    }

    #[test]
    fn a_crafted_elf_section_count_stays_bounded_and_keeps_the_reference_regions() {
        let original: Vec<u8> = reference_artifact(ELF_REFERENCE_ARTIFACTS[1]);
        let genuine: Vec<(usize, usize)> = reference_elf_layout(&original).regions;
        assert!(
            !genuine.is_empty(),
            "the unmodified reference elf must yield regions"
        );

        let mut crafted: Vec<u8> = original.clone();
        crafted[0x3C..0x3E].copy_from_slice(&u16::MAX.to_le_bytes());
        let layout: CodeLayout = elf_code_layout(&crafted);
        assert_regions_inside(&layout, crafted.len(), "elf with a crafted section count");
        assert!(
            layout.regions.len() <= MAX_PARSED_SECTIONS,
            "a crafted section count admitted {} regions past the {MAX_PARSED_SECTIONS} ceiling",
            layout.regions.len()
        );
        let crafted_regions: Vec<(usize, usize)> = observed_regions(&layout);
        for region in &genuine {
            assert!(
                crafted_regions.contains(region),
                "a crafted section count must not lose the reference region {region:?}"
            );
        }

        let mut dense: Vec<u8> = original;
        dense[0x3A..0x3C].copy_from_slice(&1u16.to_le_bytes());
        dense[0x3C..0x3E].copy_from_slice(&u16::MAX.to_le_bytes());
        let dense_layout: CodeLayout = elf_code_layout(&dense);
        assert_regions_inside(
            &dense_layout,
            dense.len(),
            "elf with a one-byte section stride",
        );
        assert!(
            dense_layout.regions.len() <= MAX_PARSED_SECTIONS,
            "a one-byte section stride admitted {} regions past the {MAX_PARSED_SECTIONS} ceiling",
            dense_layout.regions.len()
        );
    }

    #[test]
    fn a_crafted_macho_command_count_stays_bounded_and_keeps_the_reference_regions() {
        let original: Vec<u8> = reference_artifact(MACHO_REFERENCE_ARTIFACTS[0]);
        let genuine: Vec<(usize, usize)> = reference_macho_layout(&original).regions;
        assert!(
            !genuine.is_empty(),
            "the unmodified reference mach-o must yield regions"
        );
        let mut crafted: Vec<u8> = original;
        crafted[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        let layout: CodeLayout = macho_code_layout(&crafted);
        assert_regions_inside(
            &layout,
            crafted.len(),
            "mach-o with a crafted command count",
        );
        assert!(
            layout.regions.len() <= MAX_MACHO_LOAD_CMDS.saturating_mul(MAX_PARSED_SECTIONS),
            "a crafted command count admitted {} regions past the walk ceiling",
            layout.regions.len()
        );
        let crafted_regions: Vec<(usize, usize)> = observed_regions(&layout);
        for region in &genuine {
            assert!(
                crafted_regions.contains(region),
                "a crafted command count must not lose the reference region {region:?}"
            );
        }
    }

    #[test]
    fn a_truncated_real_binary_still_yields_the_regions_that_survive() {
        let cases: [TruncationCase; 2] = [
            (PE_REFERENCE_ARTIFACTS[0], pe_code_layout, 4096),
            (MACHO_REFERENCE_ARTIFACTS[0], macho_code_layout, 32768),
        ];
        for (relative, walk, keep) in cases {
            let original: Vec<u8> = reference_artifact(relative);
            let full: Vec<(usize, usize)> = observed_regions(&walk(&original));
            assert!(
                !full.is_empty(),
                "{relative} must yield regions before truncation"
            );
            let mut clipped: Vec<u8> = original;
            clipped.truncate(keep);
            let layout: CodeLayout = walk(&clipped);
            assert_regions_inside(&layout, clipped.len(), relative);
            assert!(
                !layout.regions.is_empty(),
                "{relative} truncated to {keep} bytes must still yield partial recovery"
            );
            for region in &layout.regions {
                let survives: bool = full.iter().any(|(start, len): &(usize, usize)| {
                    *start == region.file_offset && region.len <= *len
                });
                assert!(
                    survives,
                    "{relative} truncated produced a region at {} of {} byte(s) absent from the full parse",
                    region.file_offset, region.len
                );
            }
        }
    }

    fn finding(report: &AntiAnalysisReport, technique: Technique) -> Option<&AntiAnalysisFinding> {
        report
            .findings
            .iter()
            .find(|f: &&AntiAnalysisFinding| f.technique == technique)
    }

    #[derive(Clone, Copy)]
    struct ContextRow {
        needle: &'static str,
        class: SigClass,
        confidence: Confidence,
        word_bounded: bool,
    }

    const CONTEXT_ROWS: [ContextRow; 23] = [
        ContextRow {
            needle: "queryperformancecounter",
            class: SigClass::Timing,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "gettickcount",
            class: SigClass::Timing,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "rdtsc",
            class: SigClass::Timing,
            confidence: Confidence::Low,
            word_bounded: true,
        },
        ContextRow {
            needle: "globalmemorystatusex",
            class: SigClass::ResourceFloor,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "getdiskfreespaceex",
            class: SigClass::ResourceFloor,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "getsystempowerstatus",
            class: SigClass::ResourceFloor,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "ioctl_disk_get_length_info",
            class: SigClass::ResourceFloor,
            confidence: Confidence::Medium,
            word_bounded: false,
        },
        ContextRow {
            needle: "getcursorpos",
            class: SigClass::Interaction,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "getlastinputinfo",
            class: SigClass::Interaction,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "getforegroundwindow",
            class: SigClass::Interaction,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "getasynckeystate",
            class: SigClass::Interaction,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "outputdebugstring",
            class: SigClass::AntiDebug,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "dbghelp.dll",
            class: SigClass::AntiDebug,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "dbghelp",
            class: SigClass::Sandbox,
            confidence: Confidence::Info,
            word_bounded: true,
        },
        ContextRow {
            needle: "ntqueryinformationprocess",
            class: SigClass::AntiDebug,
            confidence: Confidence::Medium,
            word_bounded: false,
        },
        ContextRow {
            needle: "ntsetinformationthread",
            class: SigClass::AntiDebug,
            confidence: Confidence::Medium,
            word_bounded: false,
        },
        ContextRow {
            needle: "ntqueryobject",
            class: SigClass::AntiDebug,
            confidence: Confidence::Medium,
            word_bounded: false,
        },
        ContextRow {
            needle: "blockinput",
            class: SigClass::AntiDebug,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "getthreadcontext",
            class: SigClass::AntiDebug,
            confidence: Confidence::Low,
            word_bounded: false,
        },
        ContextRow {
            needle: "ntgetcontextthread",
            class: SigClass::AntiDebug,
            confidence: Confidence::Medium,
            word_bounded: false,
        },
        ContextRow {
            needle: "ptrace",
            class: SigClass::AntiDebug,
            confidence: Confidence::Medium,
            word_bounded: true,
        },
        ContextRow {
            needle: "dbgbreakpoint",
            class: SigClass::AntiAttach,
            confidence: Confidence::Medium,
            word_bounded: false,
        },
        ContextRow {
            needle: "dbguiremotebreakin",
            class: SigClass::AntiAttach,
            confidence: Confidence::High,
            word_bounded: false,
        },
    ];

    fn context_technique(class: SigClass) -> Technique {
        match class {
            SigClass::Timing => Technique::TimingEvasion,
            SigClass::ResourceFloor | SigClass::Interaction | SigClass::Sandbox => {
                Technique::AntiSandbox
            }
            SigClass::AntiDebug => Technique::AntiDebug,
            SigClass::AntiAttach => Technique::AntiAttach,
            _ => panic!("non-context class {class:?}"),
        }
    }

    fn evidence_key(detail: &str) -> (String, usize) {
        let first_quote: usize = detail.find('\'').expect("evidence opening quote");
        let relative_end: usize = detail[first_quote + 1..]
            .find('\'')
            .expect("evidence closing quote");
        let end_quote: usize = first_quote + 1 + relative_end;
        let offset_text: &str = detail
            .get(end_quote + 1..)
            .and_then(|tail: &str| tail.rsplit_once(" at offset 0x"))
            .map(|(_, offset): (&str, &str)| offset)
            .expect("evidence offset");
        let offset: usize = usize::from_str_radix(offset_text, 16).expect("hex evidence offset");
        (detail[first_quote + 1..end_quote].to_string(), offset)
    }

    fn context_fixture(
        rows: &[ContextRow],
        split_after: Option<usize>,
    ) -> (Vec<u8>, Vec<(ContextRow, usize)>) {
        let mut bytes: Vec<u8> = vec![0u8; 64];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        let mut expected: Vec<(ContextRow, usize)> = Vec::new();
        for (index, row) in rows.iter().copied().enumerate() {
            if split_after == Some(index) && bytes.len() < 8192 {
                bytes.resize(8192, 0);
            }
            let offset: usize = bytes.len();
            bytes.extend_from_slice(row.needle.as_bytes());
            bytes.push(0);
            expected.push((row, offset));
        }
        (bytes, expected)
    }

    fn expected_context_findings(
        occurrences: &[(ContextRow, usize)],
    ) -> std::collections::BTreeMap<Technique, (Confidence, Vec<(String, usize)>)> {
        let mut expected: std::collections::BTreeMap<
            Technique,
            (Confidence, Vec<(String, usize)>),
        > = std::collections::BTreeMap::new();
        for (row, offset) in occurrences {
            let technique: Technique = context_technique(row.class);
            let entry: &mut (Confidence, Vec<(String, usize)>) = expected
                .entry(technique)
                .or_insert((row.confidence, Vec::new()));
            entry.0 = entry.0.max(row.confidence);
            entry.1.push((row.needle.to_string(), *offset));
            if row.needle == "dbghelp.dll" {
                let sandbox: &mut (Confidence, Vec<(String, usize)>) = expected
                    .entry(Technique::AntiSandbox)
                    .or_insert((Confidence::Info, Vec::new()));
                sandbox.0 = sandbox.0.max(Confidence::Info);
                sandbox.1.push(("dbghelp".to_string(), *offset));
            }
        }
        for (_, evidence) in expected.values_mut() {
            evidence.sort();
        }
        expected
    }

    fn assert_context_fixture(rows: &[ContextRow], split_after: Option<usize>) {
        let (bytes, occurrences): (Vec<u8>, Vec<(ContextRow, usize)>) =
            context_fixture(rows, split_after);
        let report: AntiAnalysisReport = scan(&bytes, None);
        let expected: std::collections::BTreeMap<Technique, (Confidence, Vec<(String, usize)>)> =
            expected_context_findings(&occurrences);
        assert_eq!(
            report.findings.len(),
            expected.len(),
            "{:?}",
            report.findings
        );
        for (technique, (confidence, expected_evidence)) in expected {
            let finding: &AntiAnalysisFinding =
                finding(&report, technique).expect("expected context finding");
            assert!(!finding.detected, "{finding:?}");
            assert_eq!(finding.severity, FindingSeverity::Informational);
            assert_eq!(finding.confidence, confidence);
            let mut actual_evidence: Vec<(String, usize)> = finding
                .evidence
                .iter()
                .map(|detail: &String| evidence_key(detail))
                .collect();
            actual_evidence.sort();
            assert_eq!(actual_evidence, expected_evidence, "{finding:?}");
        }
    }

    fn assert_all_context_techniques_on_both_sides(rows: &[ContextRow], split_after: usize) {
        let expected_techniques: std::collections::BTreeSet<Technique> = [
            Technique::TimingEvasion,
            Technique::AntiSandbox,
            Technique::AntiDebug,
            Technique::AntiAttach,
        ]
        .into_iter()
        .collect();
        let techniques: fn(&[ContextRow]) -> std::collections::BTreeSet<Technique> = |side| {
            side.iter()
                .flat_map(|row: &ContextRow| {
                    let overlap: Option<Technique> =
                        (row.needle == "dbghelp.dll").then_some(Technique::AntiSandbox);
                    std::iter::once(context_technique(row.class)).chain(overlap)
                })
                .collect()
        };
        let first: std::collections::BTreeSet<Technique> = techniques(&rows[..split_after]);
        let second: std::collections::BTreeSet<Technique> = techniques(&rows[split_after..]);
        assert_eq!(first, expected_techniques);
        assert_eq!(second, expected_techniques);
        assert_context_fixture(rows, Some(split_after));
    }

    #[test]
    fn schema_is_v4() {
        assert_eq!(ANTI_ANALYSIS_SCHEMA, "disrobe.anti-analysis/v4");
    }

    #[test]
    fn classify_pe_elf_wasm_dex() {
        assert_eq!(classify_family(b"MZ\x90\x00rest"), TargetFamily::Pe);
        assert_eq!(classify_family(b"\x7fELFmore"), TargetFamily::Elf);
        assert_eq!(
            classify_family(b"\x00asm\x01\x00\x00\x00"),
            TargetFamily::Wasm
        );
        assert_eq!(classify_family(b"dex\n035\x00"), TargetFamily::Dalvik);
    }

    #[test]
    fn classify_text_when_printable() {
        assert_eq!(
            classify_family(b"function f(){ return 1; }\nconst x = 2;\n"),
            TargetFamily::Text
        );
    }

    #[test]
    fn lone_isdebuggerpresent_string_is_informational_not_verdict() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(b"\x00IsDebuggerPresent\x00padding here for strings\x00");
        let report: AntiAnalysisReport = scan(&buf, None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDebug).expect("anti-debug surfaced for triage");
        assert!(
            !f.detected,
            "a single import-table-only isdebuggerpresent reference is also how a benign \
             runtime's own crash/backtrace machinery references the api; it must stay \
             informational, not a high-confidence verdict: {f:?}"
        );
        assert_eq!(f.severity, FindingSeverity::Informational);
    }

    #[test]
    fn two_distinct_high_confidence_anti_debug_strings_reach_verdict() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(b"\x00IsDebuggerPresent\x00CheckRemoteDebuggerPresent\x00");
        let report: AntiAnalysisReport = scan(&buf, None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDebug).expect("anti-debug present");
        assert!(
            f.detected,
            "two distinct high-confidence anti-debug api references corroborate each other \
             and reach a verdict: {f:?}"
        );
        assert!(
            matches!(f.defeated_by, DefeatStatus::DetectedNotDefeated { .. }),
            "anti-debug is a runtime guard, must stay detected-not-defeated: {:?}",
            f.defeated_by
        );
    }

    #[test]
    fn unambiguous_vendor_markers_still_verdict_standalone() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(b"\x00vboxguest\x00padding here for strings\x00");
        let report: AntiAnalysisReport = scan(&buf, None);
        let f: &AntiAnalysisFinding = finding(&report, Technique::AntiVm).expect("anti-vm present");
        assert!(
            f.detected,
            "a virtualbox guest driver name has no benign explanation and must keep \
             verdicting alone; only the two generic win32 debugger-presence apis need a \
             second corroborating signal: {f:?}"
        );
    }

    #[test]
    fn anti_vm_string_detected() {
        let mut buf: Vec<u8> = b"\x7fELF".to_vec();
        buf.extend_from_slice(b"\x00detect VMware and VirtualBox sandbox\x00");
        let report: AntiAnalysisReport = scan(&buf, None);
        assert!(finding(&report, Technique::AntiVm).is_some());
    }

    #[test]
    fn vmprotect_section_is_detected_not_defeated() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(b"\x00\x00.vmp0\x00\x00 packed body");
        let report: AntiAnalysisReport = scan(&buf, None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::VmVirtualization).expect("vmp detected");
        assert!(
            matches!(f.defeated_by, DefeatStatus::DetectedNotDefeated { .. }),
            "native VM virtualization must wall honestly: {:?}",
            f.defeated_by
        );
    }

    #[test]
    fn upx_packing_overcome_only_when_chain_unpacked() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(b"......UPX!......compressed");
        let no_chain: AntiAnalysisReport = scan(&buf, None);
        let f: &AntiAnalysisFinding =
            finding(&no_chain, Technique::Packing).expect("packing detected");
        assert!(
            f.defeated_by.is_overcome(),
            "upx without recorded chain still maps to the stub-emu defeat path"
        );

        let chain: ChainEvidence = ChainEvidence {
            executed_pass_ids: vec!["native.packer-unpack".to_string()],
            recovered_format_tags: vec!["pe".to_string()],
            recovered_techniques: vec![],
        };
        let with_chain: AntiAnalysisReport = scan_with_chain(&buf, None, &chain);
        let f2: &AntiAnalysisFinding =
            finding(&with_chain, Technique::Packing).expect("packing detected");
        match &f2.defeated_by {
            DefeatStatus::OvercomeBy { mechanism } => {
                assert_eq!(*mechanism, Mechanism::PackerUnpack);
            }
            walled @ DefeatStatus::DetectedNotDefeated { .. } => {
                panic!("expected packer-unpack mechanism, got {walled:?}")
            }
        }
    }

    #[test]
    fn packing_routed_but_unrecovered_is_honest() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(b"......UPX!......compressed");
        let chain: ChainEvidence = ChainEvidence {
            executed_pass_ids: vec!["native.packer-unpack".to_string()],
            recovered_format_tags: vec![],
            recovered_techniques: vec![],
        };
        let report: AntiAnalysisReport = scan_with_chain(&buf, None, &chain);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::Packing).expect("packing detected");
        assert!(matches!(
            f.defeated_by,
            DefeatStatus::DetectedNotDefeated { .. }
        ));
    }

    #[test]
    fn cff_marker_without_recovery_is_detected_not_defeated() {
        let mut buf: Vec<u8> = b"\x7fELF".to_vec();
        buf.extend_from_slice(b"\x00.text ollvm.fla switch_var dispatcher\x00");
        let report: AntiAnalysisReport = scan(&buf, None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::ControlFlowFlattening).expect("cff detected");
        assert!(
            matches!(f.defeated_by, DefeatStatus::DetectedNotDefeated { .. }),
            "a flatten marker alone is not recovery; must wall: {:?}",
            f.defeated_by
        );
    }

    #[test]
    fn cff_overcome_only_when_chain_recovered_control_flow() {
        let mut buf: Vec<u8> = b"\x7fELF".to_vec();
        buf.extend_from_slice(b"\x00.text ollvm.fla switch_var dispatcher\x00");
        let chain: ChainEvidence = ChainEvidence {
            executed_pass_ids: vec!["wasm.deob".to_string()],
            recovered_format_tags: vec![],
            recovered_techniques: vec![Technique::ControlFlowFlattening],
        };
        let report: AntiAnalysisReport = scan_with_chain(&buf, None, &chain);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::ControlFlowFlattening).expect("cff detected");
        match &f.defeated_by {
            DefeatStatus::OvercomeBy { mechanism } => {
                assert_eq!(*mechanism, Mechanism::CffUnflatten);
            }
            walled @ DefeatStatus::DetectedNotDefeated { .. } => {
                panic!("expected cff-unflatten once recovery is recorded, got {walled:?}")
            }
        }
    }

    #[test]
    fn opaque_predicate_marker_without_recovery_is_detected_not_defeated() {
        let mut buf: Vec<u8> = b"\x7fELF".to_vec();
        buf.extend_from_slice(b"\x00ollvm.bcf opaque\x00");
        let report: AntiAnalysisReport = scan(&buf, None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::OpaquePredicate).expect("opaque detected");
        assert!(
            matches!(f.defeated_by, DefeatStatus::DetectedNotDefeated { .. }),
            "a bcf marker alone is not a stripped predicate; must wall: {:?}",
            f.defeated_by
        );
    }

    #[test]
    fn opaque_predicate_overcome_only_when_chain_stripped() {
        let mut buf: Vec<u8> = b"\x7fELF".to_vec();
        buf.extend_from_slice(b"\x00ollvm.bcf opaque\x00");
        let chain: ChainEvidence = ChainEvidence {
            executed_pass_ids: vec!["native.deobf".to_string()],
            recovered_format_tags: vec![],
            recovered_techniques: vec![Technique::OpaquePredicate],
        };
        let report: AntiAnalysisReport = scan_with_chain(&buf, None, &chain);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::OpaquePredicate).expect("opaque detected");
        assert!(matches!(
            f.defeated_by,
            DefeatStatus::OvercomeBy {
                mechanism: Mechanism::BcfStrip
            }
        ));
    }

    #[test]
    fn jump_into_instruction_flags_anti_disassembly_walled_without_recovery() {
        let payload: Vec<u8> = vec![0xEB, 0x01, 0xE8, 0x11];
        let buf: Vec<u8> = pe_with_code(&payload, false);
        let report: AntiAnalysisReport = scan(&buf, None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDisassembly).expect("anti-disasm detected");
        assert!(
            matches!(f.defeated_by, DefeatStatus::DetectedNotDefeated { .. }),
            "a desync byte alone is not a realigned stream; must wall: {:?}",
            f.defeated_by
        );

        let chain: ChainEvidence = ChainEvidence {
            executed_pass_ids: vec!["native.deobf".to_string()],
            recovered_format_tags: vec![],
            recovered_techniques: vec![Technique::AntiDisassembly],
        };
        let recovered: AntiAnalysisReport = scan_with_chain(&buf, None, &chain);
        let f2: &AntiAnalysisFinding =
            finding(&recovered, Technique::AntiDisassembly).expect("anti-disasm detected");
        assert!(matches!(
            f2.defeated_by,
            DefeatStatus::OvercomeBy {
                mechanism: Mechanism::Desync
            }
        ));
    }

    #[test]
    fn rasp_marker_detected_not_defeated() {
        let mut buf: Vec<u8> = b"dex\n035\x00".to_vec();
        buf.extend_from_slice(b"\x00libdexguard.so com.guardsquare\x00");
        let report: AntiAnalysisReport = scan(&buf, None);
        let f: &AntiAnalysisFinding = finding(&report, Technique::Rasp).expect("rasp detected");
        assert!(matches!(
            f.defeated_by,
            DefeatStatus::DetectedNotDefeated { .. }
        ));
    }

    #[test]
    fn clean_text_has_no_findings() {
        let report: AntiAnalysisReport = scan(b"the quick brown fox jumps over the lazy dog", None);
        assert!(!report.any_detected(), "{:?}", report.findings);
        assert_eq!(report.target_family, TargetFamily::Text);
    }

    #[test]
    fn one_line_render_shapes() {
        let overcome: AntiAnalysisFinding = AntiAnalysisFinding {
            technique: Technique::ControlFlowFlattening,
            detected: true,
            severity: FindingSeverity::Detected,
            confidence: Confidence::High,
            defeated_by: DefeatStatus::OvercomeBy {
                mechanism: Mechanism::CffUnflatten,
            },
            evidence: vec![],
        };
        assert_eq!(
            overcome.one_line(),
            "control-flow-flattening -> overcome via cff-unflatten"
        );
        assert_eq!(
            overcome.one_line_graded(),
            "[high] control-flow-flattening -> overcome via cff-unflatten"
        );
        let walled: AntiAnalysisFinding = AntiAnalysisFinding {
            technique: Technique::VmVirtualization,
            detected: true,
            severity: FindingSeverity::Detected,
            confidence: Confidence::High,
            defeated_by: DefeatStatus::DetectedNotDefeated {
                reason: "native VM".to_string(),
            },
            evidence: vec![],
        };
        assert_eq!(
            walled.one_line(),
            "vm-virtualization -> detected, not defeated: native VM"
        );
    }

    #[test]
    fn report_serializes_with_schema() {
        let report: AntiAnalysisReport =
            scan(b"MZ\x90\x00\x00IsDebuggerPresent\x00", Some("a.exe"));
        let value: serde_json::Value = serde_json::to_value(&report).expect("serialize");
        assert_eq!(
            value["schema"],
            serde_json::json!("disrobe.anti-analysis/v4")
        );
        assert_eq!(value["uri"], serde_json::json!("a.exe"));
        assert_eq!(value["target_family"], serde_json::json!("pe"));
        let confidence: &serde_json::Value = &value["findings"][0]["confidence"];
        assert_eq!(confidence, &serde_json::json!("high"));
    }

    #[test]
    fn string_encryption_block_detected_in_binary() {
        let key: u8 = 0x5a;
        let secrets: [&str; 4] = [
            "http://malicious.example/c2/gate",
            "CreateRemoteThread inject path",
            "powershell -enc second stage",
            "select from credentials table",
        ];
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        let encrypted_nul: u8 = key;
        for s in secrets {
            for &b in s.as_bytes() {
                buf.push(b ^ key);
            }
            buf.push(encrypted_nul);
        }
        let report: AntiAnalysisReport = scan(&buf, None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::StringEncryption).expect("string encryption detected");
        assert!(
            matches!(f.defeated_by, DefeatStatus::DetectedNotDefeated { .. }),
            "an xor string block alone is not recovered plaintext; must wall: {:?}",
            f.defeated_by
        );

        let chain: ChainEvidence = ChainEvidence {
            executed_pass_ids: vec!["native.deobf".to_string()],
            recovered_format_tags: vec![],
            recovered_techniques: vec![Technique::StringEncryption],
        };
        let recovered: AntiAnalysisReport = scan_with_chain(&buf, None, &chain);
        let f2: &AntiAnalysisFinding =
            finding(&recovered, Technique::StringEncryption).expect("string encryption detected");
        assert!(matches!(
            f2.defeated_by,
            DefeatStatus::OvercomeBy {
                mechanism: Mechanism::DecoderEmulation
            }
        ));
    }

    #[test]
    fn marker_present_but_no_recovery_does_not_count_as_overcome() {
        let mut buf: Vec<u8> = b"\x7fELF".to_vec();
        buf.extend_from_slice(b"\x00.text ollvm.fla ollvm.bcf switch_var dispatcher\x00");
        let report: AntiAnalysisReport = scan(&buf, None);
        assert!(
            report.any_detected(),
            "ollvm markers must still be detected"
        );
        assert_eq!(
            report.overcome_count(),
            0,
            "no recovery ran, so nothing is overcome: {:?}",
            report.findings
        );
        for f in &report.findings {
            assert!(
                matches!(f.defeated_by, DefeatStatus::DetectedNotDefeated { .. }),
                "marker-without-recovery must not report overcome: {f:?}"
            );
        }
    }

    #[test]
    fn benign_pe_yields_no_flags() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(
            b"\x00This program prints hello world. \
              kernel32.dll GetStdHandle WriteConsoleW ExitProcess \
              normal application strings with no evasion intent\x00",
        );
        let report: AntiAnalysisReport = scan(&buf, None);
        assert!(
            !report.any_detected(),
            "benign pe must produce zero anti-analysis flags: {:?}",
            report.findings
        );
    }

    #[test]
    fn every_finding_cites_evidence() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(
            b"\x00IsDebuggerPresent\x00.vmp0\x00ollvm.bcf\x00libdexguard\x00\
              GetTickCount\x00QueryPerformanceCounter\x00",
        );
        let report: AntiAnalysisReport = scan(&buf, None);
        assert!(report.any_detected(), "planted markers must be detected");
        for f in &report.findings {
            assert!(
                !f.evidence.is_empty(),
                "every finding must cite at least one evidence item: {f:?}"
            );
        }
    }

    #[test]
    fn planted_debugger_rdtsc_vmware_mac_are_attributed_with_confidence() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(
            b"\x00IsDebuggerPresent\x00\
              MAC 00:0c:29:ab:cd:ef belongs to this host\x00\
              rdtsc primitive\x00GetTickCount\x00",
        );
        let report: AntiAnalysisReport = scan(&buf, None);

        let debug: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDebug).expect("anti-debug attributed");
        assert_eq!(debug.confidence, Confidence::High);
        assert!(
            debug
                .evidence
                .iter()
                .any(|e: &String| e.contains("isdebuggerpresent")),
            "anti-debug must cite the isdebuggerpresent string: {debug:?}"
        );

        let vm: &AntiAnalysisFinding =
            finding(&report, Technique::AntiVm).expect("anti-vm attributed from mac oui");
        assert_eq!(vm.confidence, Confidence::High);
        assert!(
            vm.evidence.iter().any(|e: &String| e.contains("00:0c:29")),
            "anti-vm must cite the vmware mac oui: {vm:?}"
        );

        let timing: &AntiAnalysisFinding =
            finding(&report, Technique::TimingEvasion).expect("timing attributed");
        assert_eq!(timing.confidence, Confidence::Low);
        assert!(!timing.detected);
        assert_eq!(timing.severity, FindingSeverity::Informational);
        assert!(timing.evidence.iter().any(|e: &String| e.contains("rdtsc")));
        assert!(
            timing
                .evidence
                .iter()
                .any(|e: &String| e.contains("gettickcount"))
        );
    }

    #[test]
    fn lone_timing_primitive_is_visible_and_informational() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(b"\x00GetTickCount only one timing primitive here\x00");
        let report: AntiAnalysisReport = scan(&buf, None);
        let timing: &AntiAnalysisFinding =
            finding(&report, Technique::TimingEvasion).expect("timing context surfaced");
        assert_eq!(timing.confidence, Confidence::Low);
        assert!(!timing.detected);
        assert_eq!(timing.severity, FindingSeverity::Informational);
        assert_eq!(timing.evidence.len(), 1);
        assert!(timing.evidence[0].contains("gettickcount"));
    }

    #[test]
    fn bare_vm_word_without_username_context_is_not_a_username_flag() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(b"\x00the malware sample description text\x00");
        let report: AntiAnalysisReport = scan(&buf, None);
        if let Some(vm) = finding(&report, Technique::AntiVm) {
            assert!(
                !vm.evidence
                    .iter()
                    .any(|e: &String| e.contains("analysis username")),
                "username heuristic must require username context: {vm:?}"
            );
        }
    }

    fn pe(payload: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 64];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf.extend_from_slice(payload);
        buf
    }

    fn pe_with_code(payload: &[u8], bits64: bool) -> Vec<u8> {
        let pe_off: usize = 0x80;
        let opt_size: usize = if bits64 { 0xF0 } else { 0xE0 };
        let sect_start: usize = pe_off + 24 + opt_size;
        let raw_ptr: usize = 0x200;
        let total: usize = (raw_ptr + payload.len().max(1)).max(sect_start + 40);
        let mut img: Vec<u8> = vec![0u8; total];
        img[0] = b'M';
        img[1] = b'Z';
        img[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        img[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        let machine: u16 = if bits64 { 0x8664 } else { 0x014C };
        img[pe_off + 4..pe_off + 6].copy_from_slice(&machine.to_le_bytes());
        img[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes());
        img[pe_off + 20..pe_off + 22]
            .copy_from_slice(&u16::try_from(opt_size).unwrap().to_le_bytes());
        let opt_start: usize = pe_off + 24;
        let magic: u16 = if bits64 { 0x020B } else { 0x010B };
        img[opt_start..opt_start + 2].copy_from_slice(&magic.to_le_bytes());
        let base: usize = sect_start;
        img[base..base + 8].copy_from_slice(b".text\0\0\0");
        let plen: u32 = u32::try_from(payload.len()).unwrap();
        img[base + 8..base + 12].copy_from_slice(&plen.to_le_bytes());
        img[base + 12..base + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        img[base + 16..base + 20].copy_from_slice(&plen.to_le_bytes());
        img[base + 20..base + 24].copy_from_slice(&u32::try_from(raw_ptr).unwrap().to_le_bytes());
        img[base + 36..base + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        img[raw_ptr..raw_ptr + payload.len()].copy_from_slice(payload);
        img
    }

    #[test]
    fn peb_being_debugged_read_is_attributed_high() {
        let mut payload: Vec<u8> = vec![0x64, 0xA1, 0x30, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02, 0x84, 0xC0]);
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDebug).expect("peb anti-debug present");
        assert_eq!(f.confidence, Confidence::High);
        assert!(
            f.evidence.iter().any(|e: &String| e.contains("peb-base")),
            "must cite the peb-base load: {f:?}"
        );
        assert!(matches!(
            f.defeated_by,
            DefeatStatus::DetectedNotDefeated { .. }
        ));
    }

    #[test]
    fn peb_ntglobalflag_x64_read_is_attributed() {
        let mut payload: Vec<u8> = vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&[0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00]);
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, true), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDebug).expect("peb ntglobalflag present");
        assert!(
            f.evidence
                .iter()
                .any(|e: &String| e.contains("ntglobalflag")),
            "must cite ntglobalflag: {f:?}"
        );
    }

    #[test]
    fn nt_query_information_process_class_immediates_are_attributed() {
        let mut payload: Vec<u8> =
            b"\x00NtQueryInformationProcess\x00ProcessDebugPort\x00".to_vec();
        payload.extend_from_slice(b"ProcessDebugObject\x00ProcessDebugFlags\x00");
        let report: AntiAnalysisReport = scan(&pe(&payload), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDebug).expect("nt query class present");
        assert!(
            f.evidence
                .iter()
                .any(|e: &String| e.contains("processdebugport")),
            "must cite the debug-port class string: {f:?}"
        );
    }

    #[test]
    fn thread_hide_from_debugger_string_is_attributed() {
        let payload: Vec<u8> = b"\x00NtSetInformationThread\x00ThreadHideFromDebugger\x00".to_vec();
        let report: AntiAnalysisReport = scan(&pe(&payload), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDebug).expect("hide from debugger present");
        assert!(
            f.evidence
                .iter()
                .any(|e: &String| e.contains("threadhidefromdebugger"))
        );
    }

    #[test]
    fn int_2d_and_icebp_are_attributed() {
        let mut payload: Vec<u8> = vec![0x90, 0xCD, 0x2D, 0x90];
        payload.extend_from_slice(&[0x48, 0xF1, 0x90]);
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDebug).expect("int opcodes present");
        assert!(f.evidence.iter().any(|e: &String| e.contains("int 2d")));
        assert!(f.evidence.iter().any(|e: &String| e.contains("icebp")));
    }

    #[test]
    fn lone_icebp_in_code_is_not_flagged() {
        let payload: Vec<u8> = vec![0x90, 0x90, 0xF1, 0x90, 0x90, 0xC3];
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), None);
        assert!(
            finding(&report, Technique::AntiDebug).is_none(),
            "a single icebp byte with no deliberate-fault corroboration must not flag \
             anti-debug (the 582MB-bundle false-positive class): {:?}",
            report.findings
        );
    }

    #[test]
    fn opcode_heuristics_ignore_non_executable_data() {
        let mut img: Vec<u8> = pe_with_code(&[0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3], false);
        let mut payload: Vec<u8> = Vec::new();
        for _ in 0..4096 {
            payload.push(0xF1);
            payload.extend_from_slice(&0x4001_0006u32.to_le_bytes());
            payload.extend_from_slice(&0x564d_5868u32.to_le_bytes());
        }
        img.extend_from_slice(&payload);
        let report: AntiAnalysisReport = scan(&img, None);
        assert!(
            !report.any_detected(),
            "0xF1 bytes and magic dwords living in appended non-executable data must never \
             produce anti-analysis findings; only executable sections are scanned: {:?}",
            report.findings
        );
    }

    #[test]
    fn high_entropy_executable_section_is_skipped() {
        let mut payload: Vec<u8> = Vec::with_capacity(8192);
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..8192 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            payload.push((state >> 33) as u8);
        }
        payload[100] = 0xCD;
        payload[101] = 0x2D;
        payload[200] = 0x0F;
        payload[201] = 0x31;
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, true), None);
        assert!(
            !report.any_detected(),
            "a high-entropy (packed/compressed) executable section must be skipped, not scanned \
             as native code: {:?}",
            report.findings
        );
    }

    #[test]
    fn lone_red_pill_is_informational_not_verdict() {
        let payload: Vec<u8> = vec![0x0F, 0x01, 0x4C, 0x24, 0xFE];
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiVm).expect("sidt surfaced for triage");
        assert_eq!(
            f.severity,
            FindingSeverity::Informational,
            "a byte-level red-pill store is coincidence-prone and stays informational: {f:?}"
        );
        assert!(
            !f.detected,
            "informational findings must not read as a detection: {f:?}"
        );
        assert!(!report.any_detected(), "{:?}", report.findings);
    }

    #[test]
    fn tier_c_volume_never_reaches_verdict() {
        let mut acc: TechniqueAccumulator = TechniqueAccumulator::default();
        for i in 0..500usize {
            acc.add(
                Technique::AntiVm,
                Confidence::Low,
                "same-kind-weak-signal",
                Some(i * 8192),
                format!("weak signal {i}"),
                SignalCorroboration::Standalone,
            );
        }
        let findings: Vec<AntiAnalysisFinding> =
            acc.finalize(TargetFamily::Pe, &ChainEvidence::default());
        let f: &AntiAnalysisFinding = findings
            .iter()
            .find(|f: &&AntiAnalysisFinding| f.technique == Technique::AntiVm)
            .expect("weak signals still surfaced");
        assert!(
            !f.detected && f.severity == FindingSeverity::Informational,
            "no volume of one tier-C kind may sum to a verdict: {f:?}"
        );
    }

    fn verdict_item(
        confidence: Confidence,
        kind: &'static str,
        window: Option<usize>,
        corroboration: SignalCorroboration,
    ) -> EvidenceItem {
        EvidenceItem {
            tier: tier_of(confidence),
            confidence,
            kind,
            window,
            detail: kind.to_string(),
            corroboration,
        }
    }

    #[test]
    fn context_only_is_excluded_before_structural_evaluation() {
        let context: EvidenceItem = verdict_item(
            Confidence::High,
            "context",
            Some(0),
            SignalCorroboration::ContextOnly,
        );
        let standalone: EvidenceItem = verdict_item(
            Confidence::Low,
            "structural",
            Some(1),
            SignalCorroboration::Standalone,
        );
        let context_evaluation: VerdictEvaluation =
            evaluate_verdict(Technique::Packing, std::slice::from_ref(&context));
        assert!(!context_evaluation.detected);
        assert!(context_evaluation.eligible_item_indices.is_empty());

        let evaluation: VerdictEvaluation =
            evaluate_verdict(Technique::Packing, &[context.clone(), standalone.clone()]);
        assert!(evaluation.detected);
        assert_eq!(evaluation.eligible_item_indices, vec![1]);

        let mut context_acc: TechniqueAccumulator = TechniqueAccumulator::default();
        context_acc.add(
            Technique::Packing,
            context.confidence,
            context.kind,
            context.window,
            context.detail,
            context.corroboration,
        );
        let informational: Vec<AntiAnalysisFinding> =
            context_acc.finalize(TargetFamily::Pe, &ChainEvidence::default());
        assert_eq!(informational.len(), 1);
        assert!(!informational[0].detected);
        assert_eq!(informational[0].severity, FindingSeverity::Informational);

        let mut mixed_acc: TechniqueAccumulator = TechniqueAccumulator::default();
        mixed_acc.add(
            Technique::Packing,
            Confidence::High,
            "context",
            Some(0),
            "context".to_string(),
            SignalCorroboration::ContextOnly,
        );
        mixed_acc.add(
            Technique::Packing,
            Confidence::Low,
            standalone.kind,
            standalone.window,
            standalone.detail,
            standalone.corroboration,
        );
        let detected: Vec<AntiAnalysisFinding> =
            mixed_acc.finalize(TargetFamily::Pe, &ChainEvidence::default());
        assert_eq!(detected.len(), 1);
        assert!(detected[0].detected);
        assert_eq!(detected[0].confidence, Confidence::Low);
    }

    #[test]
    fn corroborated_tier_b_duplicates_cannot_self_corroborate() {
        let duplicate_items: Vec<EvidenceItem> = [0usize, 8192, 16_384]
            .into_iter()
            .map(|window: usize| {
                verdict_item(
                    Confidence::Medium,
                    "/proc/self/status",
                    Some(window),
                    SignalCorroboration::Corroborated,
                )
            })
            .collect();
        let duplicates: VerdictEvaluation =
            evaluate_verdict(Technique::AntiDebug, &duplicate_items);
        assert!(!duplicates.detected);
        assert!(duplicates.eligible_item_indices.is_empty());

        let mut partnered_items: Vec<EvidenceItem> = duplicate_items;
        partnered_items.push(verdict_item(
            Confidence::High,
            "tracerpid",
            Some(24_576),
            SignalCorroboration::Corroborated,
        ));
        let partnered: VerdictEvaluation = evaluate_verdict(Technique::AntiDebug, &partnered_items);
        assert!(partnered.detected);
        assert_eq!(partnered.eligible_item_indices, vec![0, 1, 2, 3]);
    }

    #[test]
    fn verdict_evaluation_owns_membership_detection_and_confidence() {
        let cases: Vec<(Vec<EvidenceItem>, Vec<usize>, bool)> = vec![
            (
                vec![verdict_item(
                    Confidence::High,
                    "context",
                    Some(0),
                    SignalCorroboration::ContextOnly,
                )],
                vec![],
                false,
            ),
            (
                vec![verdict_item(
                    Confidence::High,
                    "standalone-a",
                    Some(0),
                    SignalCorroboration::Standalone,
                )],
                vec![0],
                true,
            ),
            (
                vec![verdict_item(
                    Confidence::High,
                    "corroborated-a",
                    Some(0),
                    SignalCorroboration::Corroborated,
                )],
                vec![],
                false,
            ),
            (
                vec![
                    verdict_item(
                        Confidence::High,
                        "corroborated-a",
                        Some(0),
                        SignalCorroboration::Corroborated,
                    ),
                    verdict_item(
                        Confidence::Medium,
                        "corroborated-b",
                        Some(1),
                        SignalCorroboration::Corroborated,
                    ),
                ],
                vec![0, 1],
                true,
            ),
            (
                vec![
                    verdict_item(
                        Confidence::Medium,
                        "tier-b",
                        Some(0),
                        SignalCorroboration::Standalone,
                    ),
                    verdict_item(
                        Confidence::Medium,
                        "tier-b",
                        Some(4096),
                        SignalCorroboration::Standalone,
                    ),
                ],
                vec![0, 1],
                true,
            ),
            (
                vec![
                    verdict_item(
                        Confidence::Medium,
                        "tier-b",
                        Some(0),
                        SignalCorroboration::Standalone,
                    ),
                    verdict_item(
                        Confidence::Low,
                        "tier-c-1",
                        Some(0),
                        SignalCorroboration::Standalone,
                    ),
                    verdict_item(
                        Confidence::Low,
                        "tier-c-2",
                        Some(0),
                        SignalCorroboration::Standalone,
                    ),
                    verdict_item(
                        Confidence::Low,
                        "tier-c-3",
                        Some(0),
                        SignalCorroboration::Standalone,
                    ),
                ],
                vec![0, 1, 2, 3],
                true,
            ),
        ];
        for (items, expected_indices, expected_detected) in cases {
            let evaluation: VerdictEvaluation = evaluate_verdict(Technique::AntiDebug, &items);
            assert_eq!(evaluation.eligible_item_indices, expected_indices);
            assert_eq!(evaluation.detected, expected_detected);
        }

        let mut acc: TechniqueAccumulator = TechniqueAccumulator::default();
        acc.add(
            Technique::AntiDebug,
            Confidence::High,
            "excluded-context",
            Some(0),
            "excluded-context".to_string(),
            SignalCorroboration::ContextOnly,
        );
        for window in [0usize, 4096] {
            acc.add(
                Technique::AntiDebug,
                Confidence::Medium,
                "eligible-tier-b",
                Some(window),
                format!("eligible-tier-b-{window}"),
                SignalCorroboration::Standalone,
            );
        }
        let findings: Vec<AntiAnalysisFinding> =
            acc.finalize(TargetFamily::Pe, &ChainEvidence::default());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detected);
        assert_eq!(findings[0].confidence, Confidence::Medium);
    }

    #[test]
    fn evidence_is_capped_per_kind_with_a_total_count() {
        let mut payload: Vec<u8> = Vec::new();
        for _ in 0..10 {
            payload.extend_from_slice(&[0xCD, 0x2D, 0x90]);
        }
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDebug).expect("int 2d verdict");
        assert!(
            f.detected,
            "int 2d is a tier-A opcode and reaches a verdict"
        );
        assert!(
            f.evidence.len() <= MAX_EXEMPLARS_PER_KIND + 1,
            "evidence must be capped to <=5 exemplars plus a summary line: {:?}",
            f.evidence
        );
        assert!(
            f.evidence
                .iter()
                .any(|e: &String| e.contains("more 'int 2d' matches") && e.contains("total")),
            "the cap must record a total count: {:?}",
            f.evidence
        );
    }

    #[test]
    fn hardware_breakpoint_context_flag_is_attributed() {
        let mut payload: Vec<u8> = vec![0xB8, 0x10, 0x00, 0x01, 0x00];
        payload.extend_from_slice(b"GetThreadContext\x00");
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDebug).expect("hardware bp present");
        assert!(
            f.evidence
                .iter()
                .any(|e: &String| e.contains("0x10010") || e.contains("dr7"))
        );
    }

    #[test]
    fn cpuid_hypervisor_brand_is_attributed_anti_vm() {
        let payload: Vec<u8> = b"\x00VMwareVMware probe leaf\x00".to_vec();
        let report: AntiAnalysisReport = scan(&pe(&payload), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiVm).expect("cpuid brand present");
        assert_eq!(f.confidence, Confidence::High);
    }

    #[test]
    fn cpuid_hv_leaf_constant_needs_cpuid_opcode_corroboration() {
        let lone: Vec<u8> = {
            let mut p: Vec<u8> = vec![0u8; 16];
            p.extend_from_slice(&0x4000_0000u32.to_le_bytes());
            pe_with_code(&p, false)
        };
        let report: AntiAnalysisReport = scan(&lone, None);
        assert!(
            finding(&report, Technique::AntiVm).is_none()
                && finding(&report, Technique::TimingEvasion).is_none(),
            "ubiquitous 0x40000000 alone must not flag: {:?}",
            report.findings
        );

        let mut corroborated: Vec<u8> = vec![0xB8];
        corroborated.extend_from_slice(&0x4000_0000u32.to_le_bytes());
        corroborated.extend_from_slice(&[0x0F, 0xA2]);
        let report2: AntiAnalysisReport = scan(&pe_with_code(&corroborated, false), None);
        assert!(
            finding(&report2, Technique::AntiVm).is_some(),
            "0x40000000 next to a cpuid opcode must flag: {:?}",
            report2.findings
        );
    }

    #[test]
    fn vmware_vmxh_magic_is_attributed_standalone() {
        let mut payload: Vec<u8> = vec![0xB8];
        payload.extend_from_slice(&0x564d_5868u32.to_le_bytes());
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiVm).expect("vmxh magic present");
        assert_eq!(f.confidence, Confidence::High);
    }

    #[test]
    fn red_pill_sidt_is_attributed_anti_vm() {
        let payload: Vec<u8> = vec![0x0F, 0x01, 0x4C, 0x24, 0xFE];
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), None);
        let f: &AntiAnalysisFinding = finding(&report, Technique::AntiVm).expect("sidt present");
        assert!(f.evidence.iter().any(|e: &String| e.contains("sidt")));
    }

    #[test]
    fn privileged_lgdt_lidt_is_not_a_red_pill() {
        let payload: Vec<u8> = vec![0x0F, 0x01, 0x54, 0x24, 0x00, 0x0F, 0x01, 0x5C, 0x24, 0x00];
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), None);
        if let Some(vm) = finding(&report, Technique::AntiVm) {
            assert!(
                !vm.evidence.iter().any(|e: &String| e.contains("red-pill")),
                "lgdt(/2)/lidt(/3) are privileged loads, not red-pill stores: {vm:?}"
            );
        }
    }

    #[test]
    fn rdtsc_cpuid_sandwich_is_high_timing() {
        let payload: Vec<u8> = vec![0x0F, 0x31, 0x50, 0x0F, 0xA2, 0x58, 0x0F, 0x31, 0x2B, 0xC1];
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::TimingEvasion).expect("sandwich present");
        assert_eq!(f.confidence, Confidence::High);
        assert!(f.evidence.iter().any(|e: &String| e.contains("sandwich")));
    }

    #[test]
    fn anti_disasm_cluster_raises_to_high() {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&[0xEB, 0x01, 0xE8]);
        payload.extend_from_slice(&[0xEB, 0x01, 0xE9]);
        payload.extend_from_slice(&[0xEB, 0x01, 0x0F]);
        payload.extend_from_slice(&[0x90, 0x90, 0x90, 0x90]);
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDisassembly).expect("anti-disasm present");
        assert_eq!(
            f.confidence,
            Confidence::High,
            "three co-occurring jump-into-instruction desyncs in one window must raise to high: {f:?}"
        );
        assert!(f.detected, "a dense desync cluster is verdict-grade: {f:?}");
    }

    #[test]
    fn lone_desync_shape_is_informational() {
        let payload: Vec<u8> = vec![0x90, 0x90, 0xEB, 0x01, 0xE8, 0x90, 0x90, 0xC3];
        let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDisassembly).expect("lone desync surfaced");
        assert!(
            !f.detected && f.severity == FindingSeverity::Informational,
            "a single desync byte is coincidence-prone and must stay informational: {f:?}"
        );
    }

    #[test]
    fn resource_floor_context_is_visible_but_never_votes() {
        let lone: Vec<u8> = pe(b"\x00GlobalMemoryStatusEx only one floor query\x00");
        let report: AntiAnalysisReport = scan(&lone, None);
        let lone_finding: &AntiAnalysisFinding =
            finding(&report, Technique::AntiSandbox).expect("resource context surfaced");
        assert_eq!(lone_finding.confidence, Confidence::Low);
        assert!(!lone_finding.detected);
        assert_eq!(lone_finding.severity, FindingSeverity::Informational);
        assert_eq!(lone_finding.evidence.len(), 1);
        assert!(lone_finding.evidence[0].contains("globalmemorystatusex"));

        let three: Vec<u8> =
            pe(b"\x00GlobalMemoryStatusEx\x00GetDiskFreeSpaceEx\x00GetSystemPowerStatus\x00");
        let report2: AntiAnalysisReport = scan(&three, None);
        let f: &AntiAnalysisFinding =
            finding(&report2, Technique::AntiSandbox).expect("resource context surfaced");
        assert_eq!(f.confidence, Confidence::Low);
        assert!(!f.detected);
        assert_eq!(f.severity, FindingSeverity::Informational);
        assert_eq!(f.evidence.len(), 3);
        for needle in [
            "globalmemorystatusex",
            "getdiskfreespaceex",
            "getsystempowerstatus",
        ] {
            assert!(f.evidence.iter().any(|e: &String| e.contains(needle)));
        }
    }

    #[test]
    fn lone_wine_loader_probe_is_informational() {
        let payload: Vec<u8> =
            pe(b"\x00wine_get_version\x00ntdll.dll\x00GetModuleHandleW\x00GetProcAddress\x00");
        let report: AntiAnalysisReport = scan(&payload, None);
        let finding: &AntiAnalysisFinding =
            finding(&report, Technique::AntiSandbox).expect("wine context surfaced");
        assert!(!finding.detected);
        assert_eq!(finding.severity, FindingSeverity::Informational);
        assert_eq!(finding.confidence, Confidence::High);
        assert!(
            finding
                .evidence
                .iter()
                .any(|e: &String| e.contains("wine_get_version"))
        );
    }

    #[test]
    fn cargo_like_context_surface_cannot_cross_corroborate() {
        let mut payload: Vec<u8> = pe(
            b"\x00wine_get_version\x00dbghelp.dll\x00QueryPerformanceCounter\x00GetTickCount\x00",
        );
        payload.resize(8192, 0);
        payload.extend_from_slice(
            b"\x00GetTickCount64\x00GetTickCount\x00QueryPerformanceCounter\x00dbghelp.dll\x00wine_get_version\x00",
        );
        let report: AntiAnalysisReport = scan(&payload, None);
        for technique in [Technique::AntiSandbox, Technique::TimingEvasion] {
            let finding: &AntiAnalysisFinding =
                finding(&report, technique).expect("context surfaced");
            assert!(!finding.detected, "{technique:?}: {finding:?}");
            assert_eq!(finding.severity, FindingSeverity::Informational);
        }
    }

    #[test]
    fn context_only_timer_names_never_vote() {
        for needles in [
            vec!["QueryPerformanceCounter", "GetTickCount", "rdtsc"],
            vec!["rdtsc", "GetTickCount64", "QueryPerformanceCounter"],
        ] {
            let mut payload: Vec<u8> = pe(needles[0].as_bytes());
            payload.resize(8192, 0);
            for needle in &needles {
                payload.extend_from_slice(needle.as_bytes());
                payload.push(0);
            }
            let report: AntiAnalysisReport = scan(&payload, None);
            let finding: &AntiAnalysisFinding =
                finding(&report, Technique::TimingEvasion).expect("timing context surfaced");
            assert!(!finding.detected, "{finding:?}");
            assert_eq!(finding.severity, FindingSeverity::Informational);
            assert_eq!(finding.confidence, Confidence::Low);
        }
    }

    #[test]
    fn context_only_resource_and_interaction_apis_never_vote() {
        let needles: [&str; 8] = [
            "GlobalMemoryStatusEx",
            "GetDiskFreeSpaceEx",
            "GetSystemPowerStatus",
            "IOCTL_DISK_GET_LENGTH_INFO",
            "GetCursorPos",
            "GetLastInputInfo",
            "GetForegroundWindow",
            "GetAsyncKeyState",
        ];
        for needle in needles {
            let report: AntiAnalysisReport = scan(&pe(needle.as_bytes()), None);
            let finding: &AntiAnalysisFinding =
                finding(&report, Technique::AntiSandbox).expect("sandbox context surfaced");
            assert!(!finding.detected, "{needle}: {finding:?}");
        }
        let mut combined: Vec<u8> = pe(b"GetAsyncKeyState\x00GlobalMemoryStatusEx\x00");
        combined.resize(8192, 0);
        for needle in needles.into_iter().rev() {
            combined.extend_from_slice(needle.as_bytes());
            combined.push(0);
        }
        let report: AntiAnalysisReport = scan(&combined, None);
        let finding: &AntiAnalysisFinding =
            finding(&report, Technique::AntiSandbox).expect("sandbox context surfaced");
        assert!(!finding.detected, "{finding:?}");
        assert_eq!(finding.severity, FindingSeverity::Informational);
    }

    #[test]
    fn context_only_tuple_golden_and_exhaustive_matrix() {
        let declared: std::collections::BTreeSet<(&str, SigClass, Confidence, bool)> = STRING_SIGS
            .iter()
            .filter(|sig: &&StringSig| sig.corroboration == SignalCorroboration::ContextOnly)
            .map(|sig: &StringSig| (sig.needle, sig.class, sig.confidence, sig.word_bounded))
            .collect();
        let golden: std::collections::BTreeSet<(&str, SigClass, Confidence, bool)> = CONTEXT_ROWS
            .iter()
            .map(|row: &ContextRow| (row.needle, row.class, row.confidence, row.word_bounded))
            .collect();
        assert_eq!(declared.len(), 23);
        assert_eq!(declared, golden);

        for row in CONTEXT_ROWS {
            assert_context_fixture(std::slice::from_ref(&row), None);
        }
        for (left, left_row) in CONTEXT_ROWS.iter().copied().enumerate() {
            for right_row in CONTEXT_ROWS.iter().copied().skip(left + 1) {
                if left_row.class == right_row.class {
                    continue;
                }
                let forward: [ContextRow; 2] = [left_row, right_row];
                let reverse: [ContextRow; 2] = [right_row, left_row];
                assert_context_fixture(&forward, None);
                assert_context_fixture(&forward, Some(1));
                assert_context_fixture(&reverse, None);
                assert_context_fixture(&reverse, Some(1));
            }
        }

        assert_context_fixture(&CONTEXT_ROWS, None);
        let first_permutation: [ContextRow; 23] = [
            CONTEXT_ROWS[0],
            CONTEXT_ROWS[3],
            CONTEXT_ROWS[7],
            CONTEXT_ROWS[11],
            CONTEXT_ROWS[13],
            CONTEXT_ROWS[21],
            CONTEXT_ROWS[1],
            CONTEXT_ROWS[4],
            CONTEXT_ROWS[8],
            CONTEXT_ROWS[14],
            CONTEXT_ROWS[15],
            CONTEXT_ROWS[2],
            CONTEXT_ROWS[5],
            CONTEXT_ROWS[6],
            CONTEXT_ROWS[9],
            CONTEXT_ROWS[10],
            CONTEXT_ROWS[12],
            CONTEXT_ROWS[16],
            CONTEXT_ROWS[17],
            CONTEXT_ROWS[18],
            CONTEXT_ROWS[19],
            CONTEXT_ROWS[20],
            CONTEXT_ROWS[22],
        ];
        let second_permutation: [ContextRow; 23] = [
            CONTEXT_ROWS[2],
            CONTEXT_ROWS[6],
            CONTEXT_ROWS[10],
            CONTEXT_ROWS[12],
            CONTEXT_ROWS[22],
            CONTEXT_ROWS[3],
            CONTEXT_ROWS[7],
            CONTEXT_ROWS[16],
            CONTEXT_ROWS[17],
            CONTEXT_ROWS[18],
            CONTEXT_ROWS[19],
            CONTEXT_ROWS[0],
            CONTEXT_ROWS[1],
            CONTEXT_ROWS[4],
            CONTEXT_ROWS[5],
            CONTEXT_ROWS[8],
            CONTEXT_ROWS[9],
            CONTEXT_ROWS[11],
            CONTEXT_ROWS[13],
            CONTEXT_ROWS[14],
            CONTEXT_ROWS[15],
            CONTEXT_ROWS[20],
            CONTEXT_ROWS[21],
        ];
        assert_all_context_techniques_on_both_sides(&first_permutation, 11);
        assert_all_context_techniques_on_both_sides(&second_permutation, 11);

        let tick64: ContextRow = ContextRow {
            needle: "gettickcount64",
            class: SigClass::Timing,
            confidence: Confidence::Low,
            word_bounded: false,
        };
        let (bytes, occurrences): (Vec<u8>, Vec<(ContextRow, usize)>) =
            context_fixture(std::slice::from_ref(&tick64), None);
        let report: AntiAnalysisReport = scan(&bytes, None);
        let timing: &AntiAnalysisFinding =
            finding(&report, Technique::TimingEvasion).expect("tick64 context surfaced");
        assert!(!timing.detected);
        assert_eq!(timing.confidence, Confidence::Low);
        assert_eq!(timing.evidence.len(), 1);
        assert_eq!(
            evidence_key(&timing.evidence[0]),
            ("gettickcount".to_string(), occurrences[0].1)
        );
    }

    #[test]
    fn anti_tool_cluster_raises_to_high() {
        let payload: Vec<u8> = pe(b"\x00x64dbg\x00ollydbg\x00ImmunityDebugger\x00ScyllaHide\x00");
        let report: AntiAnalysisReport = scan(&payload, None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiTool).expect("anti-tool present");
        assert_eq!(f.confidence, Confidence::High);
        assert!(matches!(
            f.defeated_by,
            DefeatStatus::DetectedNotDefeated { .. }
        ));
    }

    #[test]
    fn anti_attach_string_is_attributed() {
        let payload: Vec<u8> = pe(b"\x00DbgUiRemoteBreakin\x00VirtualProtect\x00");
        let report: AntiAnalysisReport = scan(&payload, None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiAttach).expect("anti-attach present");
        assert!(matches!(
            f.defeated_by,
            DefeatStatus::DetectedNotDefeated { .. }
        ));
    }

    #[test]
    fn benign_pe_with_normal_apis_yields_no_new_flags() {
        let payload: Vec<u8> = {
            let mut p: Vec<u8> = b"\x00This program cannot be run in DOS mode.\x00".to_vec();
            p.extend_from_slice(
                b"kernel32.dll GetStdHandle WriteConsoleW ExitProcess CreateFileW \
                  ReadFile WriteFile GetModuleHandleW LoadLibraryW GetProcAddress \
                  HeapAlloc HeapFree GetCommandLineW normal application no evasion\x00",
            );
            p.extend_from_slice(&[
                0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x10, 0x00, 0x00, 0x00, 0x90,
                0xC9, 0xC3,
            ]);
            pe(&p)
        };
        let report: AntiAnalysisReport = scan(&payload, None);
        assert!(
            !report.any_detected(),
            "benign pe must produce zero anti-analysis flags: {:?}",
            report.findings
        );
    }

    #[test]
    fn benign_elf_text_section_yields_no_opcode_flags() {
        let payload: Vec<u8> = {
            let mut p: Vec<u8> = b"\x7fELF".to_vec();
            p.extend_from_slice(&[0u8; 60]);
            p.extend_from_slice(&[
                0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10, 0x89, 0x7D, 0xFC, 0x8B, 0x45, 0xFC,
                0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3,
            ]);
            p
        };
        let report: AntiAnalysisReport = scan(&payload, None);
        assert!(
            !report.any_detected(),
            "benign elf code must produce zero anti-analysis flags: {:?}",
            report.findings
        );
    }
}
