use std::collections::BTreeSet;

use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use disrobe_ir::payload::{DisasmPayload, encode_disasm};
use disrobe_ir::{Envelope, decode_raw};
use serde::{Deserialize, Serialize};

use crate::api_hash::{ApiHashHit, resolve_imports_by_hash};
use crate::crypto_consts::{CryptoConstHit, detect_crypto_constants};
use crate::cxx_recovery::{CxxHierarchy, recover_cxx_hierarchy};
use crate::decompile::{DecompilerBackend, Probe, probe_all};
use crate::deobf::{
    AbiInference, Bits as DeobfBits, BlockCopyProp, BlockDeadFlags, BogusBranch, BranchFoldFinding,
    BranchFoldOutcome, CffOutcome, CffRecovery, CopyPropOutcome, DeadFlagOutcome, DeobfReport,
    FunctionEffect, FunctionSummary, JumpTableResolution, OpaquePredicateSimplification,
    OpaqueResult, PathSenseReport, SubstitutionResult, clean_register_copies,
    defeat_bogus_control_flow, defeat_cff, fold_constant_branch, infer_function_abi,
    prove_dead_paths, resolve_jump_table, summarize_function, undo_substitution,
};
use crate::desync::{
    Bitness as DesyncBitness, VmwareBackdoorHit, cleaned_listing as desync_cleaned_listing,
    scan_vmware_backdoor,
};
use crate::disasm_ir::build_disasm_payload;
use crate::elf::{ElfDynamicReport, analyze as analyze_elf_dynamic};
use crate::emu_strings::EmulatedString;
use crate::format::{DetectedFormat, detect as detect_format};
use crate::identify::IdentityReport;
use crate::lang::{LanguageHit, detect as detect_languages};
use crate::obfuscators::{
    ObfuscatorHit, StringDecryptHit, XorStringHit, detect as detect_obfuscators,
    recover_obfuscxx_strings,
};
use crate::stack_string::{ReassembledStackString, reassemble_stack_strings};

const XOR_SCAN_CAP: usize = 4 * 1024 * 1024;
use crate::format::NativeFormat;
use crate::packers::overlay::{PeOverlayReport, analyze_pe_overlay};
use crate::packers::recovered_image::{RecoveredImage, recover_detected};
use crate::packers::{Detection as PackerDetection, detect as detect_packers};
use crate::vm_devirt::detect::Bitness as VmBitness;
use crate::vm_devirt::{DevirtReport, devirtualize as devirtualize_vm};

pub const PASS_INPUT_PATH_CAP: &str = "raw.native";

#[derive(Debug, Default, Clone, Copy)]
pub struct NativePass;

impl LegacyPass for NativePass {
    const CONSUMES: &'static [Rung] = &[Rung::Raw];
    const EMITS: &'static [Rung] = &[Rung::Disasm];
    const REQUIRES: &'static [fn() -> Capability] =
        &[|| Capability::requires(PASS_INPUT_PATH_CAP, 1)];
    const PRODUCES: &'static [fn() -> Capability] = &[
        || Capability::produces("native.format-detected", 1),
        || Capability::produces("native.packer-fingerprinted", 1),
        || Capability::produces("native.packer-unpacked", 1),
        || Capability::produces("native.anti-analysis-fingerprinted", 1),
        || Capability::produces("native.obfuscator-fingerprinted", 1),
        || Capability::produces("native.obfuscator-defeated", 1),
        || Capability::produces("native.crypto-constant-fingerprinted", 1),
        || Capability::produces("native.language-detected", 1),
        || Capability::produces("disasm.native", 1),
    ];

    fn id(&self) -> PassId {
        "disrobe-pass-native"
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let input: PassInput = decode_pass_input(&artifact.envelope);
        crate::debug::dbg_section("native pass");
        crate::debug::dbg_kv("input", || {
            format!("path={} bytes={}", input.source_path, input.bytes.len())
        });
        let format: DetectedFormat = detect_format(&input.bytes).map_err(|e| {
            crate::debug::dbg_kv("wall", || format!("format-detect failed: {e}"));
            CoreError::PassFailure(format!("DR-NATIVE-PASS: {e}"))
        })?;
        crate::debug::dbg_kv("format", || {
            format!(
                "{} bits={} subsystem={} notes={:?}",
                format.kind.label(),
                format.bits,
                format.subsystem.as_deref().unwrap_or("-"),
                format.notes
            )
        });
        let packers: Vec<PackerDetection> = detect_packers(&input.bytes);
        log_packer_detections(&packers);
        let recovered_images: Vec<RecoveredImage> = recover_detected(&input.bytes, &packers);
        log_recovered_images(&packers, &recovered_images);
        let obfuscators: Vec<ObfuscatorHit> = detect_obfuscators(&input.bytes);
        for hit in &obfuscators {
            crate::debug::dbg_kv("obfuscator", || {
                format!("{:?} :: {}", hit.family, hit.indicator)
            });
        }
        let deobf: Option<DeobfReport> = analyze_deobf(&input.bytes, &format, &obfuscators);
        let crypto_constants: Vec<CryptoConstHit> = detect_crypto_constants(&input.bytes);
        let languages: Vec<LanguageHit> = detect_languages(&input.bytes);
        for hit in &languages {
            crate::debug::dbg_kv("language", || format!("{:?} :: {}", hit.lang, hit.evidence));
        }
        let xor_scan_window: &[u8] = &input.bytes[..input.bytes.len().min(XOR_SCAN_CAP)];
        let recovered_xor_strings: Vec<XorStringHit> =
            crate::obfuscators::recover_single_byte_xor_strings(xor_scan_window);
        for hit in &recovered_xor_strings {
            crate::debug::dbg_kv_guarded(&format!("xor-string key={:#04x}", hit.key), || {
                hit.recovered.clone()
            });
        }
        let recovered_obfuscator_strings: Vec<StringDecryptHit> =
            recover_obfuscxx_strings(&input.bytes);
        for hit in &recovered_obfuscator_strings {
            crate::debug::dbg_kv_guarded(
                &format!("{:?}-string @{:#x}", hit.family, hit.address),
                || hit.recovered.clone(),
            );
        }
        let emulated_strings: Vec<EmulatedString> =
            crate::emu_strings::emulate_string_decoders(&input.bytes);
        for s in &emulated_strings {
            crate::debug::dbg_kv_guarded(&format!("emu-string @{:#x}", s.decoder_address), || {
                s.value.clone()
            });
        }
        let identity: IdentityReport = crate::identify::detect(&input.bytes);
        let elf_dynamic: Option<ElfDynamicReport> = analyze_elf_dynamic(&input.bytes);
        if let Some(elf) = &elf_dynamic {
            crate::debug::dbg_kv("elf-dynamic", || {
                format!(
                    "needed={:?} soname={:?} symbols={} relocs={} source={:?}",
                    elf.needed,
                    elf.soname,
                    elf.symbols.len(),
                    elf.relocations.len(),
                    elf.symbol_count_source
                )
            });
        }
        let pe_overlay: Option<PeOverlayReport> = analyze_pe_overlay(&input.bytes).ok();
        let cxx_hierarchy: Option<CxxHierarchy> = recover_cxx_hierarchy(&input.bytes);
        let vm_devirt: Option<VmDevirtSummary> = analyze_vm_devirt(&input.bytes, &format);
        if let Some(vm) = &vm_devirt {
            crate::debug::dbg_kv("vm-devirt", || {
                format!(
                    "dispatch={} handlers={} fingerprinted={} bytecode_insns={} blocks={}",
                    vm.dispatch_kind,
                    vm.handler_count,
                    vm.fingerprinted_count,
                    vm.bytecode_insn_count,
                    vm.block_count
                )
            });
        }
        let vmware_backdoor: Vec<VmwareBackdoorHit> =
            scan_vmware_backdoor_sections(&input.bytes, &format);
        let backend_probe: NativePassReport = NativePassReport {
            source_path: input.source_path.clone(),
            format,
            packers,
            recovered_images,
            vmware_backdoor,
            obfuscators,
            deobf,
            crypto_constants,
            languages,
            recovered_xor_strings,
            recovered_obfuscator_strings,
            emulated_strings,
            identity,
            elf_dynamic,
            pe_overlay,
            cxx_hierarchy,
            vm_devirt,
            decompiler_probe: probe_all_serializable(),
            byte_count: input.bytes.len() as u64,
        };
        let report_json: Vec<u8> = serde_json::to_vec(&backend_probe)
            .map_err(|e| CoreError::PassFailure(format!("DR-NATIVE-PASS encode: {e}")))?;
        let disasm: DisasmPayload =
            build_disasm_payload(&input.bytes).unwrap_or_else(|_| empty_disasm(&input.bytes));
        let hot: Vec<u8> = encode_disasm(&disasm)
            .map_err(|e| CoreError::PassFailure(format!("DR-NATIVE-PASS disasm encode: {e}")))?;
        let envelope: Vec<u8> = Envelope::new(Rung::Disasm, hot, report_json)
            .encode()
            .map_err(|e| CoreError::PassFailure(format!("DR-NATIVE-PASS envelope encode: {e}")))?;
        let mut next: Artifact = Artifact::new(Rung::Disasm, envelope, artifact.root_hash);
        for producer in <Self as LegacyPass>::PRODUCES {
            next.add_capability(producer());
        }
        Ok(next)
    }
}

fn log_packer_detections(packers: &[PackerDetection]) {
    if packers.is_empty() {
        crate::debug::dbg_kv("packers", || "none detected".to_owned());
        return;
    }
    for detection in packers {
        crate::debug::dbg_kv("packer", || {
            format!(
                "{} confidence={:?} status={:?} evidence_offset={} :: {}",
                detection.packer.label(),
                detection.confidence,
                detection.packer.unpacker_status(),
                detection
                    .matched_offset
                    .map_or_else(|| "-".to_owned(), |o: u64| format!("{o:#x}")),
                detection.note
            )
        });
    }
}

fn log_recovered_images(packers: &[PackerDetection], recovered: &[RecoveredImage]) {
    use crate::packers::UnpackerStatus;
    let recovered_labels: BTreeSet<&str> = recovered
        .iter()
        .map(|r: &RecoveredImage| r.packer.as_str())
        .collect();
    for detection in packers {
        let status: UnpackerStatus = detection.packer.unpacker_status();
        let emits_recovered_image: bool = matches!(
            status,
            UnpackerStatus::Implemented | UnpackerStatus::GreyZoneDetectAndCarve
        );
        if !emits_recovered_image {
            crate::debug::dbg_kv("recovery-skip", || {
                format!(
                    "{} status={:?}: {}",
                    detection.packer.label(),
                    status,
                    status.wall_reason()
                )
            });
            continue;
        }
        if !recovered_labels.contains(detection.packer.label()) {
            let note: &str = if status == UnpackerStatus::GreyZoneDetectAndCarve {
                "detected but carve yielded no validated protected-section artifact"
            } else {
                "detected but unpack yielded no validated image (decoder diverged, stub eval incomplete, or oracle unmet)"
            };
            crate::debug::dbg_kv("recovery-wall", || {
                format!("{} {note}", detection.packer.label())
            });
        }
    }
    for image in recovered {
        crate::debug::dbg_kv("recovered", || {
            format!(
                "{} oracle={:?} recovered_bytes={} :: {}",
                image.packer, image.oracle, image.recovered_len, image.note
            )
        });
    }
}

fn empty_disasm(bytes: &[u8]) -> DisasmPayload {
    DisasmPayload {
        source_hash: *blake3::hash(bytes).as_bytes(),
        instructions: Vec::new(),
        symbol_table: Vec::new(),
    }
}

#[must_use]
pub fn decode_pass_report(envelope_bytes: &[u8]) -> Option<NativePassReport> {
    let envelope: Envelope = Envelope::decode(envelope_bytes).ok()?;
    serde_json::from_slice(&envelope.cold).ok()
}

#[derive(Debug, Clone)]
pub struct PassInput {
    pub source_path: String,
    pub bytes: Vec<u8>,
}

#[must_use]
pub fn decode_pass_input(envelope_bytes: &[u8]) -> PassInput {
    if let Ok(envelope) = Envelope::decode(envelope_bytes)
        && let Ok(raw) = decode_raw(&envelope.hot)
    {
        return PassInput {
            source_path: raw.source_path,
            bytes: raw.source_bytes,
        };
    }
    if let Ok(raw) = decode_raw(envelope_bytes) {
        return PassInput {
            source_path: raw.source_path,
            bytes: raw.source_bytes,
        };
    }
    PassInput {
        source_path: "<artifact>".to_owned(),
        bytes: envelope_bytes.to_vec(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativePassReport {
    pub source_path: String,
    pub format: DetectedFormat,
    pub packers: Vec<PackerDetection>,
    pub recovered_images: Vec<RecoveredImage>,
    pub vmware_backdoor: Vec<VmwareBackdoorHit>,
    pub obfuscators: Vec<ObfuscatorHit>,
    pub deobf: Option<DeobfReport>,
    pub crypto_constants: Vec<CryptoConstHit>,
    pub languages: Vec<LanguageHit>,
    pub recovered_xor_strings: Vec<XorStringHit>,
    pub recovered_obfuscator_strings: Vec<StringDecryptHit>,
    pub emulated_strings: Vec<EmulatedString>,
    pub identity: IdentityReport,
    pub elf_dynamic: Option<ElfDynamicReport>,
    pub pe_overlay: Option<PeOverlayReport>,
    pub cxx_hierarchy: Option<CxxHierarchy>,
    pub vm_devirt: Option<VmDevirtSummary>,
    pub decompiler_probe: Vec<DecompilerProbeSummary>,
    pub byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmDevirtSummary {
    pub dispatch_kind: String,
    pub handler_count: usize,
    pub fingerprinted_count: usize,
    pub bytecode_insn_count: usize,
    pub block_count: usize,
    pub pseudocode: String,
    pub recovered_listing: String,
    pub residual: String,
}

impl From<DevirtReport> for VmDevirtSummary {
    fn from(r: DevirtReport) -> Self {
        Self {
            dispatch_kind: format!("{:?}", r.detection.dispatch_kind),
            handler_count: r.handler_count,
            fingerprinted_count: r.fingerprinted_count,
            bytecode_insn_count: r.bytecode_insn_count,
            block_count: r.block_count,
            pseudocode: r.pseudocode,
            recovered_listing: r.recovered_listing,
            residual: r.residual,
        }
    }
}

fn analyze_vm_devirt(bytes: &[u8], format: &DetectedFormat) -> Option<VmDevirtSummary> {
    let bitness: VmBitness = match (format.kind, format.bits) {
        (NativeFormat::Pe64 | NativeFormat::Elf64 | NativeFormat::MachO64, _) | (_, 64) => {
            VmBitness::Bits64
        }
        (NativeFormat::Pe32 | NativeFormat::Elf32 | NativeFormat::MachO32, _) | (_, 32) => {
            VmBitness::Bits32
        }
        _ => return None,
    };
    let (report, _lifted, _cfg, _semantics) = devirtualize_vm(bytes, bitness).ok()?;
    if !is_credible_vm(&report) {
        return None;
    }
    Some(VmDevirtSummary::from(report))
}

const VMWARE_MAX_HITS: usize = 64;

fn scan_vmware_backdoor_sections(bytes: &[u8], format: &DetectedFormat) -> Vec<VmwareBackdoorHit> {
    let Some(bits): Option<DeobfBits> = deobf_bits(format) else {
        return Vec::new();
    };
    let bitness: DesyncBitness = match bits {
        DeobfBits::Bits32 => DesyncBitness::Bits32,
        DeobfBits::Bits64 => DesyncBitness::Bits64,
    };
    let (sections, _entry): (Vec<CodeSection>, Option<u64>) = executable_sections(bytes);
    let mut hits: Vec<VmwareBackdoorHit> = Vec::new();
    for section in &sections {
        for hit in scan_vmware_backdoor(bitness, section.va, &section.bytes) {
            if hits.len() >= VMWARE_MAX_HITS {
                return hits;
            }
            hits.push(hit);
        }
    }
    hits
}

fn is_credible_vm(report: &DevirtReport) -> bool {
    if report.handler_count < 4 || report.bytecode_insn_count < 4 {
        return false;
    }
    let majority: usize = report.handler_count.div_ceil(2);
    report.fingerprinted_count >= majority
}

const DEOBF_SECTION_CAP: usize = 4 * 1024 * 1024;
const DEOBF_MAX_FINDINGS: usize = 256;
const SUMMARY_MAX_FUNCTIONS: usize = 64;
const SUMMARY_MAX_SPAN: usize = 2048;
const SUMMARY_MAX_CANDIDATES: usize = 4096;

struct CodeSection {
    va: u64,
    bytes: Vec<u8>,
}

fn deobf_bits(format: &DetectedFormat) -> Option<DeobfBits> {
    match (format.kind, format.bits) {
        (NativeFormat::Pe64 | NativeFormat::Elf64 | NativeFormat::MachO64, _) | (_, 64) => {
            Some(DeobfBits::Bits64)
        }
        (NativeFormat::Pe32 | NativeFormat::Elf32 | NativeFormat::MachO32, _) | (_, 32) => {
            Some(DeobfBits::Bits32)
        }
        _ => None,
    }
}

fn executable_sections(bytes: &[u8]) -> (Vec<CodeSection>, Option<u64>) {
    use object::{Object as _, ObjectSection as _};
    let Ok(obj): Result<object::File<'_>, _> = object::File::parse(bytes) else {
        return (Vec::new(), None);
    };
    let entry: u64 = obj.entry();
    let mut sections: Vec<CodeSection> = Vec::new();
    for section in obj.sections() {
        let is_text: bool = matches!(section.kind(), object::SectionKind::Text)
            || section
                .name()
                .is_ok_and(|n: &str| n == ".text" || n == "__text" || n.starts_with(".text"));
        if !is_text {
            continue;
        }
        let Ok(data): Result<&[u8], _> = section.data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        let capped: usize = data.len().min(DEOBF_SECTION_CAP);
        sections.push(CodeSection {
            va: section.address(),
            bytes: data[..capped].to_vec(),
        });
    }
    let entry: Option<u64> = (entry != 0).then_some(entry);
    (sections, entry)
}

const ADDRESS_SPACE_CAP: u64 = 256 * 1024 * 1024;

struct AddressSpace {
    image_base: u64,
    image: Vec<u8>,
}

fn flatten_address_space(bytes: &[u8]) -> Option<AddressSpace> {
    use object::{Object as _, ObjectSection as _};
    let obj: object::File<'_> = object::File::parse(bytes).ok()?;
    let mut spans: Vec<(u64, &[u8])> = Vec::new();
    let mut min_va: u64 = u64::MAX;
    let mut max_va: u64 = 0;
    for section in obj.sections() {
        let va: u64 = section.address();
        if va == 0 {
            continue;
        }
        let Ok(data): Result<&[u8], _> = section.data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        let end: u64 = va.saturating_add(data.len() as u64);
        min_va = min_va.min(va);
        max_va = max_va.max(end);
        spans.push((va, data));
    }
    if spans.is_empty() || max_va <= min_va {
        return None;
    }
    let span_len: u64 = max_va - min_va;
    if span_len > ADDRESS_SPACE_CAP {
        return None;
    }
    let mut image: Vec<u8> = vec![0u8; usize::try_from(span_len).ok()?];
    for (va, data) in spans {
        let offset: usize = usize::try_from(va - min_va).ok()?;
        let end: usize = offset.saturating_add(data.len()).min(image.len());
        if end > offset {
            image[offset..end].copy_from_slice(&data[..end - offset]);
        }
    }
    Some(AddressSpace {
        image_base: min_va,
        image,
    })
}

#[must_use]
pub fn analyze_deobf_report(bytes: &[u8]) -> Option<DeobfReport> {
    let format: DetectedFormat = detect_format(bytes).ok()?;
    let obfuscators: Vec<ObfuscatorHit> = detect_obfuscators(bytes);
    analyze_deobf(bytes, &format, &obfuscators)
}

fn analyze_deobf(
    bytes: &[u8],
    format: &DetectedFormat,
    obfuscators: &[ObfuscatorHit],
) -> Option<DeobfReport> {
    let bits: DeobfBits = deobf_bits(format)?;
    let (sections, entry): (Vec<CodeSection>, Option<u64>) = executable_sections(bytes);
    if sections.is_empty() {
        return None;
    }

    let cff: Option<CffRecovery> = recover_first_cff(bits, &sections, entry);
    let bogus_branches: Vec<BogusBranch> = scan_bogus_branches(bits, &sections);
    let substitutions: Vec<SubstitutionResult> = scan_substitutions(bits, &sections);
    let copyprop_report: Vec<BlockCopyProp> = scan_copyprop(bits, &sections);
    let dead_flag_report: Vec<BlockDeadFlags> = scan_dead_flags(bits, &sections);
    let pathsense_report: Option<PathSenseReport> = scan_pathsense(bits, &sections, entry);
    let mba_simplifications: Vec<OpaquePredicateSimplification> =
        scan_opaque_predicate_mba(bits, &sections, &bogus_branches);
    let branch_folds: Vec<BranchFoldFinding> = scan_branch_folds(bits, &sections);
    let jump_tables: Vec<JumpTableResolution> = scan_jump_tables(bits, &sections, bytes);
    let function_effects: Vec<FunctionEffect> = scan_function_effects(bits, &sections, entry);
    let abi_inferences: Vec<AbiInference> = scan_abi_inferences(bits, &sections, entry);
    let api_hashes: Vec<ApiHashHit> = scan_api_hashes(bits, &sections);
    let stack_strings: Vec<ReassembledStackString> = scan_stack_strings(bits, &sections);
    let cleaned_listing: Option<String> =
        section_cleaned_listing(bits, &sections, entry).map(|listing: String| {
            append_recovery_annotations(
                listing,
                &RecoveryAnnotations {
                    api_hashes: &api_hashes,
                    stack_strings: &stack_strings,
                    copyprop_report: &copyprop_report,
                    dead_flag_report: &dead_flag_report,
                    pathsense_report: pathsense_report.as_ref(),
                    mba_simplifications: &mba_simplifications,
                    branch_folds: &branch_folds,
                    jump_tables: &jump_tables,
                },
            )
        });

    let nothing_found: bool = cff.is_none()
        && bogus_branches.is_empty()
        && substitutions.is_empty()
        && copyprop_report.is_empty()
        && dead_flag_report.is_empty()
        && pathsense_report
            .as_ref()
            .is_none_or(|r: &PathSenseReport| r.dead_edges.is_empty() && r.walls.is_empty())
        && mba_simplifications.is_empty()
        && branch_folds.is_empty()
        && jump_tables.is_empty()
        && function_effects.is_empty()
        && abi_inferences.is_empty()
        && api_hashes.is_empty()
        && stack_strings.is_empty()
        && cleaned_listing.is_none();
    if nothing_found && obfuscators.is_empty() {
        return None;
    }

    let mut notes: Vec<String> = Vec::new();
    if cff.is_none()
        && jump_tables.is_empty()
        && obfuscators
            .iter()
            .any(|h: &ObfuscatorHit| h.indicator.contains("CFF") || h.indicator.contains("flatten"))
    {
        notes.push(
            "CFF signature present but no cmp-chain dispatcher recovered in .text \
             (jump-table dispatch form is detected but not yet linearized)"
                .to_owned(),
        );
    }
    if !jump_tables.is_empty() {
        let total_targets: usize = jump_tables
            .iter()
            .map(|t: &JumpTableResolution| t.cases.len())
            .sum();
        notes.push(format!(
            "resolved {} indirect jump table(s) to {total_targets} concrete target(s)",
            jump_tables.len()
        ));
    }
    Some(DeobfReport {
        cff,
        bogus_branches,
        substitutions,
        copyprop_report,
        dead_flag_report,
        pathsense_report,
        mba_simplifications,
        branch_folds,
        jump_tables,
        function_effects,
        abi_inferences,
        api_hashes,
        stack_strings,
        cleaned_listing,
        notes,
    })
}

fn scan_api_hashes(bits: DeobfBits, sections: &[CodeSection]) -> Vec<ApiHashHit> {
    let mut out: Vec<ApiHashHit> = Vec::new();
    for section in sections {
        if out.len() >= DEOBF_MAX_FINDINGS {
            break;
        }
        out.extend(resolve_imports_by_hash(
            bits.value(),
            section.va,
            &section.bytes,
        ));
    }
    out.truncate(DEOBF_MAX_FINDINGS);
    out
}

fn scan_stack_strings(bits: DeobfBits, sections: &[CodeSection]) -> Vec<ReassembledStackString> {
    let mut out: Vec<ReassembledStackString> = Vec::new();
    for section in sections {
        if out.len() >= DEOBF_MAX_FINDINGS {
            break;
        }
        out.extend(reassemble_stack_strings(
            bits.value(),
            section.va,
            &section.bytes,
        ));
    }
    out.truncate(DEOBF_MAX_FINDINGS);
    out
}

fn function_entry_candidates(
    bits: DeobfBits,
    section: &CodeSection,
    entry: Option<u64>,
) -> Vec<u64> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
    let section_end: u64 = section.va.saturating_add(section.bytes.len() as u64);
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut candidates: Vec<u64> = Vec::new();
    let push = |va: u64, seen: &mut BTreeSet<u64>, out: &mut Vec<u64>| {
        if va >= section.va && va < section_end && seen.insert(va) {
            out.push(va);
        }
    };
    if let Some(e) = entry {
        push(e, &mut seen, &mut candidates);
    }
    push(section.va, &mut seen, &mut candidates);

    let mut decoder: Decoder<'_> = Decoder::with_ip(
        bits.value(),
        &section.bytes,
        section.va,
        DecoderOptions::NONE,
    );
    let mut insn: Instruction = Instruction::default();
    let mut scanned: usize = 0;
    while decoder.can_decode() && scanned < SUMMARY_MAX_CANDIDATES {
        decoder.decode_out(&mut insn);
        scanned += 1;
        if insn.is_invalid() {
            continue;
        }
        if matches!(insn.flow_control(), FlowControl::Call) {
            push(insn.near_branch_target(), &mut seen, &mut candidates);
        }
        if candidates.len() >= SUMMARY_MAX_FUNCTIONS * 4 {
            break;
        }
    }
    candidates
}

fn scan_function_effects(
    bits: DeobfBits,
    sections: &[CodeSection],
    entry: Option<u64>,
) -> Vec<FunctionEffect> {
    let mut effects: Vec<FunctionEffect> = Vec::new();
    for section in sections {
        for candidate in function_entry_candidates(bits, section, entry) {
            if effects.len() >= SUMMARY_MAX_FUNCTIONS {
                effects.sort_by_key(|e: &FunctionEffect| e.address);
                return effects;
            }
            let offset: usize = match usize::try_from(candidate - section.va) {
                Ok(o) => o,
                Err(_) => continue,
            };
            let window_end: usize = offset
                .saturating_add(SUMMARY_MAX_SPAN)
                .min(section.bytes.len());
            let window: &[u8] = &section.bytes[offset..window_end];
            let Some(summary): Option<FunctionSummary> =
                summarize_function(bits.value(), candidate, window, candidate)
            else {
                continue;
            };
            effects.push(FunctionEffect::from_summary(candidate, &summary));
        }
    }
    effects.sort_by_key(|e: &FunctionEffect| e.address);
    effects
}

fn scan_abi_inferences(
    bits: DeobfBits,
    sections: &[CodeSection],
    entry: Option<u64>,
) -> Vec<AbiInference> {
    use crate::deobf::{ArgCount, CallingConvention, ReturnKind};
    let mut inferences: Vec<AbiInference> = Vec::new();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for section in sections {
        for candidate in function_entry_candidates(bits, section, entry) {
            if inferences.len() >= SUMMARY_MAX_FUNCTIONS {
                inferences.sort_by_key(|a: &AbiInference| a.address);
                return inferences;
            }
            if !seen.insert(candidate) {
                continue;
            }
            let offset: usize = match usize::try_from(candidate - section.va) {
                Ok(o) => o,
                Err(_) => continue,
            };
            let window_end: usize = offset
                .saturating_add(SUMMARY_MAX_SPAN)
                .min(section.bytes.len());
            let window: &[u8] = &section.bytes[offset..window_end];
            let Some(inference): Option<AbiInference> =
                infer_function_abi(bits.value(), candidate, window, candidate)
            else {
                continue;
            };
            let informative: bool = inference.abi != CallingConvention::Unknown
                || inference.arg_count != ArgCount::Unknown
                || inference.returns_value != ReturnKind::Unknown;
            if informative {
                inferences.push(inference);
            }
        }
    }
    inferences.sort_by_key(|a: &AbiInference| a.address);
    inferences
}

struct RecoveryAnnotations<'a> {
    api_hashes: &'a [ApiHashHit],
    stack_strings: &'a [ReassembledStackString],
    copyprop_report: &'a [BlockCopyProp],
    dead_flag_report: &'a [BlockDeadFlags],
    pathsense_report: Option<&'a PathSenseReport>,
    mba_simplifications: &'a [OpaquePredicateSimplification],
    branch_folds: &'a [BranchFoldFinding],
    jump_tables: &'a [JumpTableResolution],
}

fn append_recovery_annotations(mut listing: String, findings: &RecoveryAnnotations<'_>) -> String {
    use std::fmt::Write as _;
    let RecoveryAnnotations {
        api_hashes,
        stack_strings,
        copyprop_report,
        dead_flag_report,
        pathsense_report,
        mba_simplifications,
        branch_folds,
        jump_tables,
    } = *findings;
    if !api_hashes.is_empty() {
        let _ = writeln!(listing, "; resolved API-hash imports:");
        for hit in api_hashes {
            let _ = writeln!(listing, ";   @0x{:x} {}", hit.call_site, hit.annotation());
        }
    }
    if !stack_strings.is_empty() {
        let _ = writeln!(listing, "; reassembled stack strings:");
        for string in stack_strings {
            let _ = writeln!(
                listing,
                ";   @0x{:x} [{}{:+}] {:?}",
                string.first_store,
                string.base.name(),
                string.base_displacement,
                string.value
            );
        }
    }
    if !copyprop_report.is_empty() {
        let _ = writeln!(listing, "; copy-propagation + dead-store elimination:");
        for block in copyprop_report {
            let _ = writeln!(
                listing,
                ";   @0x{:x} {} -> {} insns ({} reads forwarded, {} copies, {} dead stores removed)",
                block.block_address,
                block.report.original_insns,
                block.report.cleaned_insns,
                block.report.propagated_reads,
                block.report.eliminated_copies,
                block.report.eliminated_dead_stores
            );
        }
    }
    if !dead_flag_report.is_empty() {
        let _ = writeln!(listing, "; dead-flag (EFLAGS) elimination:");
        for block in dead_flag_report {
            let _ = writeln!(
                listing,
                ";   @0x{:x} {} -> {} insns ({} dead flag-writes removed at {:x?})",
                block.block_address,
                block.report.original_insns,
                block.report.cleaned_insns,
                block.report.eliminated_flag_writes,
                block.report.eliminated_addresses
            );
        }
    }
    if !mba_simplifications.is_empty() {
        let _ = writeln!(listing, "; MBA-simplified opaque-predicate expressions:");
        for entry in mba_simplifications {
            let _ = writeln!(
                listing,
                ";   @0x{:x} {:?} {} = {} -> {}",
                entry.branch_address,
                entry.result,
                entry.simplification.dest,
                entry.simplification.original_expr,
                entry.simplification.simplified_expr
            );
        }
    }
    if !branch_folds.is_empty() {
        let _ = writeln!(listing, "; folded constant / opaque-predicate branches:");
        for fold in branch_folds {
            let _ = writeln!(
                listing,
                ";   @0x{:x} {:?} {:?} live -> 0x{:x}, dead -> 0x{:x} ({} free vars, {} dead stores removed)",
                fold.branch_address,
                fold.kind,
                fold.verdict,
                fold.live_target,
                fold.dead_target,
                fold.free_variables,
                fold.eliminated_dead_stores
            );
        }
    }
    if !jump_tables.is_empty() {
        let _ = writeln!(listing, "; resolved indirect jump tables:");
        for table in jump_tables {
            let _ = writeln!(
                listing,
                ";   @0x{:x} {:?} [{}*{}] base 0x{:x} -> {} targets",
                table.branch_address,
                table.base_form,
                table.index_register,
                table.entry_scale,
                table.table_base,
                table.cases.len()
            );
            for case in &table.cases {
                let _ = writeln!(listing, ";     case {} -> 0x{:x}", case.index, case.target);
            }
        }
    }
    if let Some(pathsense) = pathsense_report {
        if !pathsense.dead_edges.is_empty() {
            let _ = writeln!(listing, "; correlated-branch dead paths:");
            for edge in &pathsense.dead_edges {
                let _ = writeln!(
                    listing,
                    ";   @0x{:x} dead {}-edge -> 0x{:x}: {}",
                    edge.branch_address,
                    if edge.edge_taken {
                        "taken"
                    } else {
                        "fallthrough"
                    },
                    edge.dead_target,
                    edge.reason
                );
            }
        }
        for wall in &pathsense.walls {
            let _ = writeln!(listing, "; path-sense wall: {wall}");
        }
    }
    listing
}

fn recover_first_cff(
    bits: DeobfBits,
    sections: &[CodeSection],
    entry: Option<u64>,
) -> Option<CffRecovery> {
    for section in sections {
        let section_end: u64 = section.va.saturating_add(section.bytes.len() as u64);
        let start: u64 = match entry {
            Some(e) if e >= section.va && e < section_end => e,
            _ => section.va,
        };
        if let CffOutcome::Recovered(rec) = defeat_cff(bits, section.va, &section.bytes, start) {
            return Some(rec);
        }
    }
    None
}

fn scan_bogus_branches(bits: DeobfBits, sections: &[CodeSection]) -> Vec<BogusBranch> {
    let mut out: Vec<BogusBranch> = Vec::new();
    for section in sections {
        for block in basic_blocks(bits, section) {
            if out.len() >= DEOBF_MAX_FINDINGS {
                return out;
            }
            let Some(found): Option<BogusBranch> =
                defeat_bogus_control_flow(bits, block.va, block.bytes)
            else {
                continue;
            };
            if matches!(
                found.result,
                OpaqueResult::AlwaysTaken | OpaqueResult::AlwaysNotTaken
            ) {
                out.push(found);
            }
        }
    }
    out
}

fn scan_substitutions(bits: DeobfBits, sections: &[CodeSection]) -> Vec<SubstitutionResult> {
    let mut out: Vec<SubstitutionResult> = Vec::new();
    for section in sections {
        for block in basic_blocks(bits, section) {
            if out.len() >= DEOBF_MAX_FINDINGS {
                return out;
            }
            let body: &[u8] = strip_trailing_branch(bits, block.va, block.bytes);
            let Some(found): Option<SubstitutionResult> = undo_substitution(bits, block.va, body)
            else {
                continue;
            };
            if found.changed && found.proven && found.simplified_nodes < found.original_nodes {
                out.push(found);
            }
        }
    }
    out
}

fn scan_copyprop(bits: DeobfBits, sections: &[CodeSection]) -> Vec<BlockCopyProp> {
    let mut out: Vec<BlockCopyProp> = Vec::new();
    for section in sections {
        for block in basic_blocks(bits, section) {
            if out.len() >= DEOBF_MAX_FINDINGS {
                return out;
            }
            let body: &[u8] = strip_trailing_branch(bits, block.va, block.bytes);
            if body.is_empty() {
                continue;
            }
            let Some(outcome): Option<CopyPropOutcome> =
                clean_register_copies(bits, block.va, body)
            else {
                continue;
            };
            if !outcome.report.changed {
                continue;
            }
            out.push(BlockCopyProp {
                block_address: block.va,
                report: outcome.report,
            });
        }
    }
    out
}

fn scan_dead_flags(bits: DeobfBits, sections: &[CodeSection]) -> Vec<BlockDeadFlags> {
    let mut out: Vec<BlockDeadFlags> = Vec::new();
    for section in sections {
        for block in basic_blocks(bits, section) {
            if out.len() >= DEOBF_MAX_FINDINGS {
                return out;
            }
            let Some(outcome): Option<DeadFlagOutcome> =
                crate::deobf::clean_dead_flags(bits, block.va, block.bytes)
            else {
                continue;
            };
            out.push(BlockDeadFlags {
                block_address: block.va,
                report: outcome.report,
            });
        }
    }
    out
}

fn scan_pathsense(
    bits: DeobfBits,
    sections: &[CodeSection],
    entry: Option<u64>,
) -> Option<PathSenseReport> {
    let mut merged: PathSenseReport = PathSenseReport {
        dead_edges: Vec::new(),
        walls: Vec::new(),
    };
    let mut any: bool = false;
    for section in sections {
        let section_end: u64 = section.va.saturating_add(section.bytes.len() as u64);
        let start: u64 = match entry {
            Some(e) if e >= section.va && e < section_end => e,
            _ => section.va,
        };
        let report: PathSenseReport = prove_dead_paths(bits, section.va, &section.bytes, start);
        if report.dead_edges.is_empty() && report.walls.is_empty() {
            continue;
        }
        any = true;
        merged.dead_edges.extend(report.dead_edges);
        for wall in report.walls {
            if !merged.walls.contains(&wall) {
                merged.walls.push(wall);
            }
        }
        if merged.dead_edges.len() >= DEOBF_MAX_FINDINGS {
            merged.dead_edges.truncate(DEOBF_MAX_FINDINGS);
            break;
        }
    }
    any.then_some(merged)
}

fn scan_opaque_predicate_mba(
    bits: DeobfBits,
    sections: &[CodeSection],
    bogus_branches: &[BogusBranch],
) -> Vec<OpaquePredicateSimplification> {
    if bogus_branches.is_empty() {
        return Vec::new();
    }
    let branch_results: Vec<(u64, OpaqueResult)> = bogus_branches
        .iter()
        .map(|b: &BogusBranch| (b.branch_address, b.result.clone()))
        .collect();
    let mut out: Vec<OpaquePredicateSimplification> = Vec::new();
    for section in sections {
        for block in basic_blocks(bits, section) {
            if out.len() >= DEOBF_MAX_FINDINGS {
                return out;
            }
            let Some(branch_address): Option<u64> = block_branch_address(bits, &block) else {
                continue;
            };
            let Some(result): Option<OpaqueResult> = branch_results
                .iter()
                .find(|(addr, _): &&(u64, OpaqueResult)| *addr == branch_address)
                .map(|(_, r): &(u64, OpaqueResult)| r.clone())
            else {
                continue;
            };
            let body: &[u8] = strip_trailing_branch(bits, block.va, block.bytes);
            if body.is_empty() {
                continue;
            }
            let Some(simplification): Option<SubstitutionResult> =
                undo_substitution(bits, block.va, body)
            else {
                continue;
            };
            if !(simplification.changed && simplification.proven) {
                continue;
            }
            out.push(OpaquePredicateSimplification {
                branch_address,
                result,
                simplification,
            });
        }
    }
    out
}

fn scan_branch_folds(bits: DeobfBits, sections: &[CodeSection]) -> Vec<BranchFoldFinding> {
    let mut out: Vec<BranchFoldFinding> = Vec::new();
    for section in sections {
        for block in basic_blocks(bits, section) {
            if out.len() >= DEOBF_MAX_FINDINGS {
                return out;
            }
            let Some(outcome): Option<BranchFoldOutcome> =
                fold_constant_branch(bits, block.va, block.bytes)
            else {
                continue;
            };
            out.push(outcome.finding);
        }
    }
    out
}

fn scan_jump_tables(
    bits: DeobfBits,
    sections: &[CodeSection],
    bytes: &[u8],
) -> Vec<JumpTableResolution> {
    let Some(space): Option<AddressSpace> = flatten_address_space(bytes) else {
        return Vec::new();
    };
    let mut out: Vec<JumpTableResolution> = Vec::new();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for section in sections {
        for block in basic_blocks(bits, section) {
            if out.len() >= DEOBF_MAX_FINDINGS {
                return out;
            }
            let Some(resolution): Option<JumpTableResolution> =
                resolve_jump_table(bits, block.va, block.bytes, space.image_base, &space.image)
            else {
                continue;
            };
            if seen.insert(resolution.branch_address) {
                out.push(resolution);
            }
        }
    }
    out
}

fn block_branch_address(bits: DeobfBits, block: &CodeBlock<'_>) -> Option<u64> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bits.value(), block.bytes, block.va, DecoderOptions::NONE);
    let mut last_branch: Option<u64> = None;
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        if insn.flow_control() == FlowControl::ConditionalBranch {
            last_branch = Some(insn.ip());
        }
    }
    last_branch
}

fn section_cleaned_listing(
    bits: DeobfBits,
    sections: &[CodeSection],
    entry: Option<u64>,
) -> Option<String> {
    let bitness: DesyncBitness = match bits {
        DeobfBits::Bits32 => DesyncBitness::Bits32,
        DeobfBits::Bits64 => DesyncBitness::Bits64,
    };
    for section in sections {
        let section_end: u64 = section.va.saturating_add(section.bytes.len() as u64);
        let start: u64 = match entry {
            Some(e) if e >= section.va && e < section_end => e,
            _ => section.va,
        };
        if let Some(listing) = desync_cleaned_listing(bitness, section.va, &section.bytes, &[start])
        {
            return Some(listing);
        }
    }
    None
}

struct CodeBlock<'a> {
    va: u64,
    bytes: &'a [u8],
}

fn basic_blocks<'a>(bits: DeobfBits, section: &'a CodeSection) -> Vec<CodeBlock<'a>> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
    let mut blocks: Vec<CodeBlock<'a>> = Vec::new();
    let mut decoder: Decoder<'_> = Decoder::with_ip(
        bits.value(),
        &section.bytes,
        section.va,
        DecoderOptions::NONE,
    );
    let mut block_start_off: usize = 0;
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        let off_before: usize = decoder.position();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            block_start_off = decoder.position();
            continue;
        }
        let ends: bool = matches!(
            insn.flow_control(),
            FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
                | FlowControl::Return
                | FlowControl::IndirectBranch
                | FlowControl::IndirectCall
        );
        if ends {
            let end_off: usize = decoder.position();
            if end_off > block_start_off {
                blocks.push(CodeBlock {
                    va: section.va + block_start_off as u64,
                    bytes: &section.bytes[block_start_off..end_off],
                });
            }
            block_start_off = end_off;
        }
        let _ = off_before;
        if blocks.len() >= DEOBF_MAX_FINDINGS * 4 {
            break;
        }
    }
    blocks
}

fn strip_trailing_branch(bits: DeobfBits, va: u64, block: &[u8]) -> &[u8] {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
    let mut decoder: Decoder<'_> = Decoder::with_ip(bits.value(), block, va, DecoderOptions::NONE);
    let mut last_branch_off: Option<usize> = None;
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        let off: usize = decoder.position();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        if !matches!(insn.flow_control(), FlowControl::Next) {
            last_branch_off = Some(off);
        }
    }
    last_branch_off.map_or(block, |off: usize| &block[..off])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompilerProbeSummary {
    pub backend: DecompilerBackend,
    pub found: bool,
    pub note: Option<String>,
}

fn probe_all_serializable() -> Vec<DecompilerProbeSummary> {
    probe_all()
        .into_values()
        .map(|p: Probe| DecompilerProbeSummary {
            backend: p.backend,
            found: p.found,
            note: p.note,
        })
        .collect()
}

#[must_use]
pub fn distinct_packer_labels(report: &NativePassReport) -> BTreeSet<&'static str> {
    report
        .packers
        .iter()
        .map(|p: &PackerDetection| p.packer.label())
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_core::PassMetadata;
    use disrobe_ir::{Envelope, RawPayload, encode_raw};

    use super::*;
    use crate::format::NativeFormat;

    fn synth_envelope(source_path: &str, body: &[u8]) -> Vec<u8> {
        let raw: RawPayload = RawPayload {
            source_path: source_path.to_owned(),
            source_bytes: body.to_vec(),
            source_hash: blake3::hash(body).into(),
            detected_format: Some("native".to_owned()),
        };
        let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
        let envelope: Envelope = Envelope::new(Rung::Raw, hot, vec![]);
        envelope.encode().expect("encode envelope")
    }

    #[test]
    fn native_pass_metadata_advertises_capabilities() {
        let p: NativePass = NativePass;
        assert_eq!(PassMetadata::id(&p), "disrobe-pass-native");
        assert_eq!(p.consumes(), &[Rung::Raw]);
        assert_eq!(p.emits(), &[Rung::Disasm]);
        assert_eq!(p.required_capabilities().len(), 1);
        assert_eq!(p.produced_capabilities().len(), 9);
    }

    #[test]
    fn native_pass_on_elf64_envelope_reports_format_and_emits_disasm() {
        let mut body: Vec<u8> = b"\x7FELF\x02\x01\x01\x00".to_vec();
        body.resize(0x80, 0);
        body[16] = 2;
        body[17] = 0;
        let bytes: Vec<u8> = synth_envelope("hello.elf", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [0u8; 32],
        );
        let out: Artifact = NativePass.run(&input).expect("run");
        assert_eq!(out.rung, Rung::Disasm);
        let report: NativePassReport = decode_pass_report(&out.envelope).expect("decode report");
        assert_eq!(report.format.kind, NativeFormat::Elf64);
        assert_eq!(report.source_path, "hello.elf");
    }

    #[test]
    fn native_pass_on_unrecognized_input_returns_pass_failure() {
        let body: Vec<u8> = b"random non-binary text".to_vec();
        let bytes: Vec<u8> = synth_envelope("notes.txt", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [0u8; 32],
        );
        let err: CoreError = NativePass.run(&input).expect_err("non-native");
        assert!(format!("{err}").contains("DR-NATIVE"));
    }

    #[test]
    fn native_pass_finds_upx_signature_in_envelope() {
        let mut body: Vec<u8> = b"\x7FELF\x02\x01\x01\x00".to_vec();
        body.resize(0x200, 0);
        body[16] = 2;
        body[17] = 0;
        body[0x100..0x104].copy_from_slice(b"UPX!");
        let bytes: Vec<u8> = synth_envelope("packed.elf", &body);
        let input: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            bytes,
            [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
            [0u8; 32],
        );
        let out: Artifact = NativePass.run(&input).expect("run");
        let report: NativePassReport = decode_pass_report(&out.envelope).expect("decode");
        let labels: BTreeSet<&'static str> = distinct_packer_labels(&report);
        assert!(labels.contains("upx"));
    }

    #[test]
    fn deobf_section_scan_surfaces_api_hash_and_stack_string() {
        use iced_x86::code_asm::{CodeAssembler, dword_ptr, eax, rsp};

        let va: u64 = 0x1000;
        let target_hash: u32 = crate::api_hash::HashFamily::Ror13Add.hash(b"LoadLibraryA", false);
        let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
        asm.cmp(eax, i32::from_le_bytes(target_hash.to_le_bytes()))
            .unwrap();
        asm.mov(dword_ptr(rsp + 0x30), i32::from_le_bytes(*b"http"))
            .unwrap();
        asm.mov(dword_ptr(rsp + 0x34), i32::from_le_bytes(*b"://x"))
            .unwrap();
        asm.ret().unwrap();
        let code: Vec<u8> = asm.assemble(va).expect("assemble");
        let sections: Vec<CodeSection> = vec![CodeSection { va, bytes: code }];

        let api_hashes: Vec<ApiHashHit> = scan_api_hashes(DeobfBits::Bits64, &sections);
        assert!(
            api_hashes
                .iter()
                .any(|h: &ApiHashHit| h.resolved_name.as_deref() == Some("LoadLibraryA")),
            "the section scan must surface the resolved LoadLibraryA hash: {api_hashes:?}"
        );

        let stack_strings: Vec<ReassembledStackString> =
            scan_stack_strings(DeobfBits::Bits64, &sections);
        assert!(
            stack_strings
                .iter()
                .any(|s: &ReassembledStackString| s.value.contains("http://x")),
            "the section scan must reassemble the inlined stack string: {stack_strings:?}"
        );

        let listing: String = append_recovery_annotations(
            String::from("; base\n"),
            &RecoveryAnnotations {
                api_hashes: &api_hashes,
                stack_strings: &stack_strings,
                copyprop_report: &[],
                dead_flag_report: &[],
                pathsense_report: None,
                mba_simplifications: &[],
                branch_folds: &[],
                jump_tables: &[],
            },
        );
        assert!(
            listing.contains("kernel32.dll!LoadLibraryA") && listing.contains("http://x"),
            "both recoveries must be annotated into the readable listing:\n{listing}"
        );
    }

    fn diamond_section_bytes(va: u64) -> Vec<u8> {
        use iced_x86::code_asm::{CodeAssembler, CodeLabel, eax, edi, esi};
        let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
        let mut else_arm: CodeLabel = asm.create_label();
        let mut join: CodeLabel = asm.create_label();
        asm.cmp(edi, esi).unwrap();
        asm.jg(else_arm).unwrap();
        asm.mov(eax, edi).unwrap();
        asm.add(eax, esi).unwrap();
        asm.jmp(join).unwrap();
        asm.set_label(&mut else_arm).unwrap();
        asm.mov(eax, edi).unwrap();
        asm.sub(eax, esi).unwrap();
        asm.set_label(&mut join).unwrap();
        asm.add(eax, 1u32).unwrap();
        asm.ret().unwrap();
        asm.assemble(va).expect("assemble diamond")
    }

    #[test]
    fn bounded_function_effects_populated_on_synthetic_diamond() {
        let va: u64 = 0x2000;
        let code: Vec<u8> = diamond_section_bytes(va);
        let sections: Vec<CodeSection> = vec![CodeSection { va, bytes: code }];
        let effects: Vec<FunctionEffect> =
            scan_function_effects(DeobfBits::Bits64, &sections, Some(va));
        assert!(
            !effects.is_empty(),
            "the diamond function entry must be summarized into a function effect"
        );
        let diamond: &FunctionEffect = effects
            .iter()
            .find(|e: &&FunctionEffect| e.address == va)
            .expect("entry address must be summarized");
        let eax: &String = diamond.outputs.get("rax").expect("rax effect surfaced");
        assert!(
            eax.contains("ite("),
            "the path-dependent eax effect must surface an ite: {eax}"
        );
        assert!(
            effects.len() <= SUMMARY_MAX_FUNCTIONS,
            "function-effect count must stay within the invocation cap"
        );
    }

    #[test]
    fn bounded_function_effects_empty_on_degenerate_section() {
        let va: u64 = 0x3000;
        let sections: Vec<CodeSection> = vec![CodeSection {
            va,
            bytes: vec![0x90, 0x90, 0x90, 0xC3],
        }];
        let effects: Vec<FunctionEffect> =
            scan_function_effects(DeobfBits::Bits64, &sections, Some(va));
        assert!(
            effects.is_empty(),
            "a straight-line nop;ret stub has no diamond and must yield no effects: {effects:?}"
        );
    }
}
