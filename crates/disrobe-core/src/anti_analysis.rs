use serde::{Deserialize, Serialize};

use crate::anti_analysis_sigs::{
    ANALYSIS_USERNAME_SIGS, NUMBER_SIGS, NumberCorroboration, NumberSig, STRING_SIGS, SigClass,
    StringSig, UsernameSig,
};
use crate::byte_search;
use crate::strings::{self, ExtractedString, Options};

pub use crate::anti_analysis_sigs::Confidence;

pub const ANTI_ANALYSIS_SCHEMA: &str = "disrobe.anti-analysis/v3";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiAnalysisFinding {
    pub technique: Technique,
    pub detected: bool,
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
    collect_number_sigs(scan, &mut acc);
    collect_anti_disasm(scan, family, &mut acc);
    collect_red_pill_opcodes(scan, family, &mut acc);
    collect_rdtsc_cpuid_sandwich(scan, family, &mut acc);
    collect_peb_anti_debug(scan, family, &mut acc);
    collect_hardware_breakpoint(scan, family, &mut acc);
    collect_int_opcodes(scan, family, &mut acc);
    collect_string_encryption(scan, family, &mut acc);

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

#[derive(Default)]
struct TechniqueAccum {
    evidence: Vec<String>,
    confidence: Option<Confidence>,
    grey_zone_vm: bool,
}

impl TechniqueAccumulator {
    fn add(&mut self, technique: Technique, confidence: Confidence, evidence: String) {
        let entry: &mut TechniqueAccum = self.entries.entry(technique).or_default();
        if !entry.evidence.contains(&evidence) {
            entry.evidence.push(evidence);
        }
        entry.confidence = Some(
            entry
                .confidence
                .map_or(confidence, |existing: Confidence| existing.max(confidence)),
        );
    }

    fn mark_grey_zone_vm(&mut self, technique: Technique) {
        self.entries.entry(technique).or_default().grey_zone_vm = true;
    }

    fn finalize(self, family: TargetFamily, chain: &ChainEvidence) -> Vec<AntiAnalysisFinding> {
        let mut findings: Vec<AntiAnalysisFinding> = Vec::with_capacity(self.entries.len());
        for (technique, accum) in self.entries {
            if accum.evidence.is_empty() {
                continue;
            }
            let Some(confidence): Option<Confidence> = accum.confidence else {
                continue;
            };
            let defeated_by: DefeatStatus =
                resolve_defeat(technique, family, accum.grey_zone_vm, chain);
            findings.push(AntiAnalysisFinding {
                technique,
                detected: true,
                confidence,
                defeated_by,
                evidence: accum.evidence,
            });
        }
        findings
    }
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
                format!("{} at offset 0x{off:x}", marker.detail),
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
                format!("{} at offset 0x{off:x}", marker.detail),
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
                format!(
                    "rasp marker '{}' ({}) at offset 0x{off:x}",
                    String::from_utf8_lossy(marker.needle),
                    marker.detail
                ),
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
                SigClass::Timing => timing_hits.push((*sig, s.offset)),
                SigClass::ResourceFloor => resource_hits.push((*sig, s.offset)),
                SigClass::Interaction => interaction_hits.push((*sig, s.offset)),
                SigClass::AntiTool => tool_hits.push((*sig, s.offset)),
                _ => acc.add(
                    sig_class_technique(sig.class),
                    sig.confidence,
                    format!(
                        "string '{}' ({}) at offset 0x{:x}",
                        sig.needle, sig.note, s.offset
                    ),
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
            format!(
                "{label} '{}' ({}) at offset 0x{offset:x}",
                sig.needle, sig.note
            ),
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
            format!(
                "analysis-tool probe '{}' ({}) at offset 0x{offset:x}",
                sig.needle, sig.note
            ),
        );
    }
}

const NUMBER_SCAN_LIMIT: usize = 8 * 1024 * 1024;
const NUMBER_CORROBORATION_WINDOW: usize = 32;

fn collect_number_sigs(bytes: &[u8], acc: &mut TechniqueAccumulator) {
    let limit: usize = bytes.len().min(NUMBER_SCAN_LIMIT);
    if limit < 4 {
        return;
    }
    let mut i: usize = 0;
    while i + 4 <= limit {
        let window: [u8; 4] = [bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]];
        let dword: u32 = u32::from_le_bytes(window);
        for sig in NUMBER_SIGS {
            if sig.value != dword {
                continue;
            }
            if matches!(sig.corroboration, NumberCorroboration::Corroborated)
                && !number_sig_corroborated(bytes, i, sig)
            {
                continue;
            }
            acc.add(
                sig_class_technique(sig.class),
                sig.confidence,
                format!(
                    "magic constant 0x{:x} ({}) at offset 0x{i:x}",
                    sig.value, sig.note
                ),
            );
        }
        i += 1;
    }
}

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

fn window_has_cpuid(window: &[u8]) -> bool {
    window.windows(2).any(|w: &[u8]| w == [0x0f, 0xa2])
}

const fn is_io_port_opcode(b: u8) -> bool {
    matches!(b, 0xe4 | 0xe5 | 0xe6 | 0xe7 | 0xec | 0xed | 0xee | 0xef)
}

fn window_has_io_port_opcode(window: &[u8]) -> bool {
    window.iter().any(|b: &u8| is_io_port_opcode(*b))
}

fn collect_username_sigs(lower: &str, offset: usize, acc: &mut TechniqueAccumulator) {
    for sig in ANALYSIS_USERNAME_SIGS {
        if username_signal(lower, sig) {
            acc.add(
                Technique::AntiVm,
                Confidence::Low,
                format!(
                    "analysis username '{}' ({}) at offset 0x{offset:x}",
                    sig.needle, sig.note
                ),
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

const fn is_native_code_family(family: TargetFamily) -> bool {
    matches!(
        family,
        TargetFamily::Pe | TargetFamily::Elf | TargetFamily::MachO
    )
}

fn collect_anti_disasm(bytes: &[u8], family: TargetFamily, acc: &mut TechniqueAccumulator) {
    if !is_native_code_family(family) {
        return;
    }
    let limit: usize = bytes.len().min(JUMP_SCAN_LIMIT);
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
            Confidence::Medium
        };
        acc.add(
            Technique::AntiDisassembly,
            confidence,
            format!("{detail} at offset 0x{off:x}"),
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
    if bytes[i] == 0xEB && bytes[i + 1] == 0xFF {
        return Some("jump-to-self-plus-one desync");
    }
    if is_zeroing_xor(bytes[i], bytes[i + 1]) && bytes[i + 2] == 0x74 {
        return Some("xor-zero then jz opaque always-taken branch");
    }
    if bytes[i] == 0x68 && i + 5 < limit && bytes[i + 5] == 0xC3 {
        return Some("push-imm32 then ret return-pointer abuse");
    }
    if let Some(detail) = double_jcc_same_target(bytes, i, limit) {
        return Some(detail);
    }
    None
}

const fn is_zeroing_xor(a: u8, b: u8) -> bool {
    matches!((a, b), (0x31 | 0x33, 0xC0))
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

const RED_PILL_SCAN_LIMIT: usize = 1 << 20;
const RED_PILL_COMPARE_WINDOW: usize = 16;

fn collect_red_pill_opcodes(bytes: &[u8], family: TargetFamily, acc: &mut TechniqueAccumulator) {
    if !is_native_code_family(family) {
        return;
    }
    let limit: usize = bytes.len().min(RED_PILL_SCAN_LIMIT);
    let mut i: usize = 0;
    while i + 2 < limit {
        if let Some(mnemonic) = red_pill_mnemonic(bytes[i], bytes[i + 1], bytes[i + 2]) {
            let hi: usize = (i + 3 + RED_PILL_COMPARE_WINDOW).min(limit);
            let followed_by_compare: bool = window_has_high_byte_compare(&bytes[i + 3..hi]);
            let confidence: Confidence = if followed_by_compare {
                Confidence::High
            } else {
                Confidence::Medium
            };
            acc.add(
                Technique::AntiVm,
                confidence,
                format!("red-pill {mnemonic} descriptor-table store at offset 0x{i:x}"),
            );
        }
        i += 1;
    }
}

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

fn window_has_high_byte_compare(window: &[u8]) -> bool {
    window.windows(2).any(|w: &[u8]| {
        matches!(w[0], 0x3C | 0x80 | 0x81 | 0x83) || (w[0] == 0x66 && matches!(w[1], 0x81 | 0x83))
    })
}

const RDTSC_SANDWICH_SPAN: usize = 64;

fn collect_rdtsc_cpuid_sandwich(
    bytes: &[u8],
    family: TargetFamily,
    acc: &mut TechniqueAccumulator,
) {
    if !is_native_code_family(family) {
        return;
    }
    let limit: usize = bytes.len().min(RED_PILL_SCAN_LIMIT);
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
                    format!("rdtsc-cpuid-rdtsc vm-exit timing sandwich at offset 0x{i:x}"),
                );
            }
        }
        i += 1;
    }
}

const PEB_SCAN_LIMIT: usize = 1 << 20;
const PEB_DEREF_WINDOW: usize = 24;

fn collect_peb_anti_debug(bytes: &[u8], family: TargetFamily, acc: &mut TechniqueAccumulator) {
    if !is_native_code_family(family) {
        return;
    }
    let limit: usize = bytes.len().min(PEB_SCAN_LIMIT);
    let mut i: usize = 0;
    while i < limit {
        if let Some((len, bitness)) = peb_base_load_at(bytes, i, limit) {
            let lo: usize = i + len;
            let hi: usize = (lo + PEB_DEREF_WINDOW).min(limit);
            if let Some(field) = peb_field_in_window(&bytes[lo..hi]) {
                acc.add(
                    Technique::AntiDebug,
                    Confidence::High,
                    format!("{bitness} peb-base load then {field} read at offset 0x{i:x}"),
                );
            }
            i += len;
            continue;
        }
        i += 1;
    }
}

fn peb_base_load_at(bytes: &[u8], i: usize, limit: usize) -> Option<(usize, &'static str)> {
    if i + 6 <= limit && bytes[i..i + 6] == [0x64, 0xA1, 0x30, 0x00, 0x00, 0x00] {
        return Some((6, "fs:[0x30] 32-bit"));
    }
    if i + 9 <= limit && bytes[i..i + 9] == [0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00] {
        return Some((9, "gs:[0x60] 64-bit"));
    }
    None
}

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

fn window_has_byte_deref(window: &[u8]) -> bool {
    window
        .windows(2)
        .any(|w: &[u8]| matches!(w[0], 0x8A | 0x0F | 0x80 | 0x38 | 0x3A | 0xF6))
}

const HW_BP_SCAN_LIMIT: usize = 1 << 20;

fn collect_hardware_breakpoint(bytes: &[u8], family: TargetFamily, acc: &mut TechniqueAccumulator) {
    if !is_native_code_family(family) {
        return;
    }
    let limit: usize = bytes.len().min(HW_BP_SCAN_LIMIT);
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
                Confidence::Medium,
                format!(
                    "context-debug-registers flag 0x10010 (hardware-breakpoint inspection) at offset 0x{i:x}"
                ),
            );
        } else if window == dr7_offset && window_references_dr7(bytes, i) {
            acc.add(
                Technique::AntiDebug,
                Confidence::Medium,
                format!("x64 context dr7 offset 0x328 read at offset 0x{i:x}"),
            );
        }
        i += 1;
    }
}

fn window_references_dr7(bytes: &[u8], at: usize) -> bool {
    let lo: usize = at.saturating_sub(3);
    let prefix: &[u8] = &bytes[lo..at];
    prefix
        .iter()
        .any(|b: &u8| matches!(b, 0x8B | 0x48 | 0x4C | 0x39 | 0x3B))
}

const INT_SCAN_LIMIT: usize = 1 << 20;

fn collect_int_opcodes(bytes: &[u8], family: TargetFamily, acc: &mut TechniqueAccumulator) {
    if !is_native_code_family(family) {
        return;
    }
    let limit: usize = bytes.len().min(INT_SCAN_LIMIT);
    let mut i: usize = 0;
    while i + 1 < limit {
        if bytes[i] == 0xCD && bytes[i + 1] == 0x2D {
            acc.add(
                Technique::AntiDebug,
                Confidence::High,
                format!("int 2d kernel-debugger detection at offset 0x{i:x}"),
            );
        }
        if bytes[i] == 0xF1 && is_icebp_in_code(bytes, i, limit) {
            acc.add(
                Technique::AntiDebug,
                Confidence::Medium,
                format!("icebp (int1) single-step trap at offset 0x{i:x}"),
            );
        }
        i += 1;
    }
}

fn is_icebp_in_code(bytes: &[u8], at: usize, limit: usize) -> bool {
    let before_ok: bool = at >= 1 && is_plausible_code_byte(bytes[at - 1]);
    let after_ok: bool = at + 1 < limit && is_plausible_code_byte(bytes[at + 1]);
    before_ok && after_ok
}

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
            "single-byte xor encoded ascii string block".to_string(),
        );
    }
}

const JUMP_SCAN_LIMIT: usize = 1 << 20;

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

fn has_single_byte_xor_string_block(bytes: &[u8]) -> bool {
    let sample: &[u8] = &bytes[..bytes.len().min(1 << 18)];
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

    fn finding(report: &AntiAnalysisReport, technique: Technique) -> Option<&AntiAnalysisFinding> {
        report
            .findings
            .iter()
            .find(|f: &&AntiAnalysisFinding| f.technique == technique)
    }

    #[test]
    fn schema_is_v3() {
        assert_eq!(ANTI_ANALYSIS_SCHEMA, "disrobe.anti-analysis/v3");
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
    fn anti_debug_string_detected_not_defeated() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(b"\x00IsDebuggerPresent\x00padding here for strings\x00");
        let report: AntiAnalysisReport = scan(&buf, None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDebug).expect("anti-debug present");
        assert!(f.detected);
        assert!(
            matches!(f.defeated_by, DefeatStatus::DetectedNotDefeated { .. }),
            "anti-debug is a runtime guard, must stay detected-not-defeated: {:?}",
            f.defeated_by
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
        let mut buf: Vec<u8> = vec![0u8; 64];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[16] = 0xEB;
        buf[17] = 0x01;
        buf[18] = 0xE8;
        buf[19] = 0x11;
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
            serde_json::json!("disrobe.anti-analysis/v3")
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
        assert_eq!(
            timing.confidence,
            Confidence::Medium,
            "two corroborating timing primitives raise confidence to medium: {timing:?}"
        );
    }

    #[test]
    fn lone_timing_primitive_is_not_flagged() {
        let mut buf: Vec<u8> = b"MZ\x90\x00".to_vec();
        buf.extend_from_slice(b"\x00GetTickCount only one timing primitive here\x00");
        let report: AntiAnalysisReport = scan(&buf, None);
        assert!(
            finding(&report, Technique::TimingEvasion).is_none(),
            "a single timing primitive is not corroborated evasion: {:?}",
            report.findings
        );
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

    #[test]
    fn peb_being_debugged_read_is_attributed_high() {
        let mut payload: Vec<u8> = vec![0x64, 0xA1, 0x30, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02, 0x84, 0xC0]);
        let report: AntiAnalysisReport = scan(&pe(&payload), None);
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
        let report: AntiAnalysisReport = scan(&pe(&payload), None);
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
        let report: AntiAnalysisReport = scan(&pe(&payload), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDebug).expect("int opcodes present");
        assert!(f.evidence.iter().any(|e: &String| e.contains("int 2d")));
        assert!(f.evidence.iter().any(|e: &String| e.contains("icebp")));
    }

    #[test]
    fn hardware_breakpoint_context_flag_is_attributed() {
        let mut payload: Vec<u8> = b"\x00GetThreadContext\x00".to_vec();
        payload.extend_from_slice(&0x0001_0010u32.to_le_bytes());
        let report: AntiAnalysisReport = scan(&pe(&payload), None);
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
            pe(&p)
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
        let report2: AntiAnalysisReport = scan(&pe(&corroborated), None);
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
        let report: AntiAnalysisReport = scan(&pe(&payload), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiVm).expect("vmxh magic present");
        assert_eq!(f.confidence, Confidence::High);
    }

    #[test]
    fn red_pill_sidt_is_attributed_anti_vm() {
        let payload: Vec<u8> = vec![0x0F, 0x01, 0x4C, 0x24, 0xFE];
        let report: AntiAnalysisReport = scan(&pe(&payload), None);
        let f: &AntiAnalysisFinding = finding(&report, Technique::AntiVm).expect("sidt present");
        assert!(f.evidence.iter().any(|e: &String| e.contains("sidt")));
    }

    #[test]
    fn privileged_lgdt_lidt_is_not_a_red_pill() {
        let payload: Vec<u8> = vec![0x0F, 0x01, 0x54, 0x24, 0x00, 0x0F, 0x01, 0x5C, 0x24, 0x00];
        let report: AntiAnalysisReport = scan(&pe(&payload), None);
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
        let report: AntiAnalysisReport = scan(&pe(&payload), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::TimingEvasion).expect("sandwich present");
        assert_eq!(f.confidence, Confidence::High);
        assert!(f.evidence.iter().any(|e: &String| e.contains("sandwich")));
    }

    #[test]
    fn anti_disasm_cluster_raises_to_high() {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&[0xEB, 0x01, 0xE8]);
        payload.extend_from_slice(&[0xEB, 0xFF]);
        payload.extend_from_slice(&[0x31, 0xC0, 0x74, 0x05]);
        let report: AntiAnalysisReport = scan(&pe(&payload), None);
        let f: &AntiAnalysisFinding =
            finding(&report, Technique::AntiDisassembly).expect("anti-disasm present");
        assert_eq!(
            f.confidence,
            Confidence::High,
            "three co-occurring shapes in one window must raise to high: {f:?}"
        );
    }

    #[test]
    fn resource_floor_requires_corroboration() {
        let lone: Vec<u8> = pe(b"\x00GlobalMemoryStatusEx only one floor query\x00");
        let report: AntiAnalysisReport = scan(&lone, None);
        assert!(
            finding(&report, Technique::AntiSandbox).is_none_or(|f: &AntiAnalysisFinding| !f
                .evidence
                .iter()
                .any(|e: &String| e.contains("resource-floor"))),
            "a single resource query is not corroborated evasion: {:?}",
            report.findings
        );

        let two: Vec<u8> =
            pe(b"\x00GlobalMemoryStatusEx\x00GetDiskFreeSpaceEx\x00GetSystemPowerStatus\x00");
        let report2: AntiAnalysisReport = scan(&two, None);
        let f: &AntiAnalysisFinding = finding(&report2, Technique::AntiSandbox)
            .expect("two resource-floor probes corroborate");
        assert!(
            f.evidence
                .iter()
                .any(|e: &String| e.contains("resource-floor"))
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
