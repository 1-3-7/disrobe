use std::collections::BTreeSet;

use crate::api_hash::{ApiHashHit, resolve_imports_by_hash};
use crate::deobf::{
    AbiInference, Bits as DeobfBits, BlockCopyProp, BlockDeadFlags, BogusBranch, BranchFoldFinding,
    BranchFoldOutcome, CffOutcome, CffRecovery, CopyPropOutcome, DeadFlagOutcome, DeobfReport,
    FunctionEffect, FunctionSummary, JumpTableResolution, OpaquePredicateSimplification,
    OpaqueResult, PathSenseReport, SubstitutionResult, clean_register_copies,
    defeat_bogus_control_flow, defeat_cff, fold_constant_branch, infer_function_abi,
    prove_dead_paths, resolve_jump_table, summarize_function, undo_substitution,
};
use crate::desync::{Bitness as DesyncBitness, cleaned_listing as desync_cleaned_listing};
use crate::format::{DetectedFormat, NativeFormat, detect as detect_format};
use crate::obfuscators::{ObfuscatorHit, detect as detect_obfuscators};
use crate::stack_string::{ReassembledStackString, reassemble_stack_strings};

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
            let fast: Option<BogusBranch> = defeat_bogus_control_flow(bits, block.va, block.bytes);
            let resolved: Option<BogusBranch> = fast
                .filter(|found: &BogusBranch| {
                    matches!(
                        found.result,
                        OpaqueResult::AlwaysTaken | OpaqueResult::AlwaysNotTaken
                    )
                })
                .or_else(|| escalate_bogus_branch(bits, section, block.va, block.bytes));
            if let Some(found) = resolved {
                out.push(found);
            }
        }
    }
    out
}

#[cfg(feature = "smt-solver")]
fn escalate_bogus_branch(
    bits: DeobfBits,
    section: &CodeSection,
    block_va: u64,
    block_bytes: &[u8],
) -> Option<BogusBranch> {
    let branch_address: u64 = last_conditional_branch_ip(bits, block_va, block_bytes)?;
    let found: BogusBranch = crate::deobf::defeat_bogus_control_flow_deep(
        bits,
        section.va,
        &section.bytes,
        branch_address,
    )?;
    matches!(
        found.result,
        OpaqueResult::AlwaysTaken | OpaqueResult::AlwaysNotTaken
    )
    .then_some(found)
}

#[cfg(not(feature = "smt-solver"))]
const fn escalate_bogus_branch(
    _bits: DeobfBits,
    _section: &CodeSection,
    _block_va: u64,
    _block_bytes: &[u8],
) -> Option<BogusBranch> {
    None
}

#[cfg(feature = "smt-solver")]
fn last_conditional_branch_ip(bits: DeobfBits, va: u64, bytes: &[u8]) -> Option<u64> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
    let mut decoder: Decoder<'_> = Decoder::with_ip(bits.value(), bytes, va, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut last_conditional: Option<u64> = None;
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        if insn.flow_control() == FlowControl::ConditionalBranch {
            last_conditional = Some(insn.ip());
        }
    }
    last_conditional
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

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
