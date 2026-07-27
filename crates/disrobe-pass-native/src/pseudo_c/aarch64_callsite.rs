use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use object::{
    Object as _, ObjectSection as _, ObjectSymbol as _, RelocationFlags, RelocationTarget,
    SectionIndex,
};

use super::{
    CallSiteIdentitySignature, CallSiteReturnProof, CallSiteScalar, CallSiteSignatureProof, Error,
    FpWidth, LeafRecovery, RecoveredFunction, RecoveredProgram, UnrecoveredFunction, Width,
    aarch64_call_site_body_is_bounded, recover_aarch64_function, recover_call_site_identity,
    rename_recovered_c_symbol, rename_recovered_rust_symbol,
};
use crate::arch::{Arch, DisasmInsn, disassemble};

const AARCH64_CALL26: u32 = object::elf::R_AARCH64_CALL26;
const AARCH64_JUMP26: u32 = object::elf::R_AARCH64_JUMP26;
const BL_OPCODE: u32 = 0x9400_0000;
const B_OPCODE: u32 = 0x1400_0000;
const BRANCH_OPCODE_MASK: u32 = 0xfc00_0000;
const REGISTER_ARGUMENT_LIMIT: usize = 8;

#[derive(Debug, Clone)]
struct FunctionSymbol {
    index: usize,
    name: String,
    address: u64,
    section: SectionIndex,
    section_offset: u64,
    code: Option<Arc<[u8]>>,
}

#[derive(Debug, Clone)]
struct FunctionMetadata {
    index: usize,
    name: String,
    address: u64,
    section: SectionIndex,
    section_offset: u64,
    size: u64,
}

#[derive(Debug, Clone)]
struct AttributedSite {
    instructions: Arc<[DisasmInsn]>,
    relocated_branches: Arc<BTreeSet<usize>>,
    call_index: usize,
    tail: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EvidenceWidth {
    Integer32,
    Integer64,
    FloatingPoint32,
    FloatingPoint64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RegisterFile {
    Integer,
    FloatingPoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrackedRegister {
    file: RegisterFile,
    index: u8,
}

#[derive(Debug, Clone, Default)]
struct RegisterAccess {
    reads: BTreeSet<EvidenceWidth>,
    writes: BTreeSet<EvidenceWidth>,
    unknown: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReachingDefinition {
    index: usize,
    width: EvidenceWidth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArgumentSignature {
    fp: Vec<EvidenceWidth>,
    int: Vec<EvidenceWidth>,
}

#[derive(Debug, Clone)]
struct SiteEvidence {
    arguments: Option<ArgumentSignature>,
    return_read: Option<EvidenceWidth>,
    indirect_composite: bool,
    issue: Option<SiteIssue>,
}

#[derive(Debug, Clone)]
enum SiteIssue {
    Discarded(String),
    Fatal(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BufferLocation {
    base: String,
    displacement: i64,
}

pub(super) fn recover(object_bytes: &[u8]) -> RecoveredProgram {
    let file: object::File<'_> = match object::File::parse(object_bytes) {
        Ok(file) => file,
        Err(error) => return object_refusal(format!("cannot parse object: {error}")),
    };
    if file.architecture() != object::Architecture::Aarch64 {
        return object_refusal("object is not aarch64".to_owned());
    }
    if file.format() != object::BinaryFormat::Elf {
        return object_refusal("aarch64 call-site recovery requires an elf object".to_owned());
    }
    if !file.is_little_endian() {
        return object_refusal(
            "aarch64 call-site recovery requires little-endian instruction encoding".to_owned(),
        );
    }
    let functions: Vec<FunctionSymbol> = collect_functions(&file);
    let attributed: BTreeMap<usize, Vec<AttributedSite>> = attribute_call_sites(&file, &functions);
    let mut recovered: Vec<RecoveredFunction> = Vec::with_capacity(functions.len());
    let mut unrecovered: Vec<UnrecoveredFunction> = Vec::new();
    for function in &functions {
        let Some(code): Option<&Arc<[u8]>> = function.code.as_ref() else {
            unrecovered.push(UnrecoveredFunction {
                name: function.name.clone(),
                address: function.address,
                reason: "function symbol has no bounded body".to_owned(),
            });
            continue;
        };
        let isolated: core::result::Result<LeafRecovery, Error> =
            recover_aarch64_function(code.as_ref(), function.address);
        let recovery: core::result::Result<LeafRecovery, String> = match isolated {
            Ok(recovery) => Ok(recovery),
            Err(error) => {
                let reason: String = error.to_string();
                if is_result_free_return_body(code.as_ref(), function.address) {
                    recover_ambiguous_identity(function, attributed.get(&function.index), &reason)
                } else {
                    Err(reason)
                }
            }
        };
        match recovery {
            Ok(function_recovery) => {
                recovered.push(recovered_function(function, function_recovery));
            }
            Err(reason) => {
                unrecovered.push(UnrecoveredFunction {
                    name: function.name.clone(),
                    address: function.address,
                    reason,
                });
            }
        }
    }
    RecoveredProgram {
        recovered,
        unrecovered,
    }
}

fn object_refusal(reason: String) -> RecoveredProgram {
    RecoveredProgram {
        recovered: Vec::new(),
        unrecovered: vec![UnrecoveredFunction {
            name: "<object>".to_owned(),
            address: 0,
            reason,
        }],
    }
}

fn collect_functions(file: &object::File<'_>) -> Vec<FunctionSymbol> {
    let mut metadata: Vec<FunctionMetadata> = Vec::new();
    for symbol in file.symbols() {
        if symbol.kind() != object::SymbolKind::Text || !symbol.is_definition() {
            continue;
        }
        let name: &str = match symbol.name() {
            Ok(name) if !name.is_empty() => name,
            Ok(_) | Err(_) => continue,
        };
        let object::SymbolSection::Section(section_index) = symbol.section() else {
            continue;
        };
        let section: object::Section<'_, '_> = match file.section_by_index(section_index) {
            Ok(section) => section,
            Err(_) => continue,
        };
        let data: &[u8] = match section.data() {
            Ok(data) => data,
            Err(_) => continue,
        };
        let section_offset_u64: u64 = match symbol.address().checked_sub(section.address()) {
            Some(offset) => offset,
            None => continue,
        };
        let start: usize = match usize::try_from(section_offset_u64) {
            Ok(start) => start,
            Err(_) => continue,
        };
        if start > data.len() {
            continue;
        }
        metadata.push(FunctionMetadata {
            index: symbol.index().0,
            name: name.to_owned(),
            address: symbol.address(),
            section: section_index,
            section_offset: section_offset_u64,
            size: symbol.size(),
        });
    }
    let mut peer_sizes: BTreeMap<(usize, u64), BTreeSet<u64>> = BTreeMap::new();
    for entry in &metadata {
        if entry.size > 0 {
            peer_sizes
                .entry((entry.section.0, entry.section_offset))
                .or_default()
                .insert(entry.size);
        }
    }
    let mut bodies: BTreeMap<(usize, u64, u64), Arc<[u8]>> = BTreeMap::new();
    let mut functions: Vec<FunctionSymbol> = Vec::with_capacity(metadata.len());
    for entry in &metadata {
        let bounded_size: Option<u64> = if entry.size == 0 {
            peer_sizes
                .get(&(entry.section.0, entry.section_offset))
                .filter(|sizes: &&BTreeSet<u64>| sizes.len() == 1)
                .and_then(|sizes: &BTreeSet<u64>| sizes.first().copied())
        } else {
            Some(entry.size)
        };
        let code: Option<Arc<[u8]>> = bounded_size.and_then(|size: u64| {
            let key: (usize, u64, u64) = (entry.section.0, entry.section_offset, size);
            match bodies.entry(key) {
                Entry::Occupied(body_entry) => Some(body_entry.get().clone()),
                Entry::Vacant(body_entry) => {
                    let body: Option<Arc<[u8]>> =
                        bounded_function_body(file, entry.section, entry.section_offset, size);
                    if let Some(body_ref) = body.as_ref() {
                        body_entry.insert(body_ref.clone());
                    }
                    body
                }
            }
        });
        functions.push(FunctionSymbol {
            index: entry.index,
            name: entry.name.clone(),
            address: entry.address,
            section: entry.section,
            section_offset: entry.section_offset,
            code,
        });
    }
    functions.sort_by(|left: &FunctionSymbol, right: &FunctionSymbol| {
        left.section
            .0
            .cmp(&right.section.0)
            .then(left.section_offset.cmp(&right.section_offset))
            .then(left.name.cmp(&right.name))
    });
    functions
}

fn bounded_function_body(
    file: &object::File<'_>,
    section_index: SectionIndex,
    section_offset: u64,
    size_u64: u64,
) -> Option<Arc<[u8]>> {
    let section: object::Section<'_, '_> = file.section_by_index(section_index).ok()?;
    let data: &[u8] = section.data().ok()?;
    let start: usize = usize::try_from(section_offset).ok()?;
    let size: usize = usize::try_from(size_u64).ok()?;
    let end: usize = start.checked_add(size)?;
    let bytes: &[u8] = data.get(start..end)?;
    Some(Arc::<[u8]>::from(bytes))
}

fn attribute_call_sites(
    file: &object::File<'_>,
    functions: &[FunctionSymbol],
) -> BTreeMap<usize, Vec<AttributedSite>> {
    let function_indices: BTreeSet<usize> = functions
        .iter()
        .map(|function: &FunctionSymbol| function.index)
        .collect();
    let relocations: BTreeMap<usize, BTreeMap<u64, Vec<object::Relocation>>> =
        index_relocations(file, functions);
    let direct_targets: BTreeMap<(usize, u64), Vec<usize>> = index_direct_targets(functions);
    let mut attributed: BTreeMap<usize, Vec<AttributedSite>> = BTreeMap::new();
    for caller in functions {
        let Some(code): Option<&Arc<[u8]>> = caller.code.as_ref() else {
            continue;
        };
        if !aarch64_call_site_body_is_bounded(code) {
            continue;
        }
        let instructions: Arc<[DisasmInsn]> =
            match disassemble(Arch::Aarch64, caller.section_offset, code.as_ref()) {
                Ok(instructions) => instructions,
                Err(_) => continue,
            }
            .into();
        let caller_relocations: Option<&BTreeMap<u64, Vec<object::Relocation>>> =
            relocations.get(&caller.section.0);
        let relocated_branches: Arc<BTreeSet<usize>> = Arc::new(
            instructions
                .iter()
                .enumerate()
                .filter_map(|(index, instruction): (usize, &DisasmInsn)| {
                    let has_relocation: bool = caller_relocations.is_some_and(
                        |entries: &BTreeMap<u64, Vec<object::Relocation>>| {
                            entries.contains_key(&instruction.address)
                        },
                    );
                    (has_relocation
                        && (instruction.mnemonic == "b" || is_conditional_branch(instruction)))
                    .then_some(index)
                })
                .collect(),
        );
        for (instruction_index, instruction) in instructions.iter().enumerate() {
            let word: u32 = match instruction_word(instruction) {
                Some(word) => word,
                None => continue,
            };
            let section_offset: u64 = instruction.address;
            let relocation_entries: Option<&Vec<object::Relocation>> = caller_relocations.and_then(
                |section_relocations: &BTreeMap<u64, Vec<object::Relocation>>| {
                    section_relocations.get(&section_offset)
                },
            );
            let target: Option<(usize, bool)> = relocation_entries.map_or_else(
                || direct_target(caller.section, section_offset, word, &direct_targets),
                |entries: &Vec<object::Relocation>| {
                    relocated_target(entries, word, &function_indices)
                },
            );
            let Some((target_index, tail)): Option<(usize, bool)> = target else {
                continue;
            };
            attributed
                .entry(target_index)
                .or_default()
                .push(AttributedSite {
                    instructions: instructions.clone(),
                    relocated_branches: relocated_branches.clone(),
                    call_index: instruction_index,
                    tail,
                });
        }
    }
    attributed
}

fn index_relocations(
    file: &object::File<'_>,
    functions: &[FunctionSymbol],
) -> BTreeMap<usize, BTreeMap<u64, Vec<object::Relocation>>> {
    let mut sections: BTreeMap<usize, SectionIndex> = BTreeMap::new();
    for function in functions {
        sections
            .entry(function.section.0)
            .or_insert(function.section);
    }
    let mut indexed: BTreeMap<usize, BTreeMap<u64, Vec<object::Relocation>>> = BTreeMap::new();
    for (section_key, section_index) in sections {
        let section: object::Section<'_, '_> = match file.section_by_index(section_index) {
            Ok(section) => section,
            Err(_) => continue,
        };
        let mut by_offset: BTreeMap<u64, Vec<object::Relocation>> = BTreeMap::new();
        for (offset, relocation) in section.relocations() {
            by_offset.entry(offset).or_default().push(relocation);
        }
        indexed.insert(section_key, by_offset);
    }
    indexed
}

fn index_direct_targets(functions: &[FunctionSymbol]) -> BTreeMap<(usize, u64), Vec<usize>> {
    let mut indexed: BTreeMap<(usize, u64), Vec<usize>> = BTreeMap::new();
    for function in functions {
        indexed
            .entry((function.section.0, function.section_offset))
            .or_default()
            .push(function.index);
    }
    indexed
}

fn relocated_target(
    entries: &[object::Relocation],
    word: u32,
    function_indices: &BTreeSet<usize>,
) -> Option<(usize, bool)> {
    if entries.len() != 1 {
        return None;
    }
    let relocation: &object::Relocation = entries.first()?;
    if relocation.addend() != 0 || relocation.has_implicit_addend() {
        return None;
    }
    let r_type: u32 = match relocation.flags() {
        RelocationFlags::Elf { r_type } => r_type,
        _ => return None,
    };
    let tail: bool = if r_type == AARCH64_CALL26 && word & BRANCH_OPCODE_MASK == BL_OPCODE {
        false
    } else if r_type == AARCH64_JUMP26 && word & BRANCH_OPCODE_MASK == B_OPCODE {
        true
    } else {
        return None;
    };
    let RelocationTarget::Symbol(target_index) = relocation.target() else {
        return None;
    };
    let target: usize = target_index.0;
    function_indices.contains(&target).then_some((target, tail))
}

fn direct_target(
    caller_section: SectionIndex,
    instruction_offset: u64,
    word: u32,
    direct_targets: &BTreeMap<(usize, u64), Vec<usize>>,
) -> Option<(usize, bool)> {
    let opcode: u32 = word & BRANCH_OPCODE_MASK;
    let tail: bool = match opcode {
        BL_OPCODE => false,
        B_OPCODE => true,
        _ => return None,
    };
    let displacement: i64 = sign_extend(u64::from(word & 0x03ff_ffff), 26)?.checked_mul(4)?;
    let instruction_offset_i64: i64 = i64::try_from(instruction_offset).ok()?;
    let target_offset_i64: i64 = instruction_offset_i64.checked_add(displacement)?;
    let target_offset: u64 = u64::try_from(target_offset_i64).ok()?;
    let matches: &Vec<usize> = direct_targets.get(&(caller_section.0, target_offset))?;
    if matches.len() != 1 {
        return None;
    }
    matches
        .first()
        .copied()
        .map(|target_index: usize| (target_index, tail))
}

fn instruction_word(instruction: &DisasmInsn) -> Option<u32> {
    let bytes: [u8; 4] = instruction.bytes.as_slice().try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn sign_extend(value: u64, bits: u32) -> Option<i64> {
    if bits == 0 || bits > 63 {
        return None;
    }
    let shift: u32 = 64_u32.checked_sub(bits)?;
    let shifted: i64 = i64::from_ne_bytes(value.wrapping_shl(shift).to_ne_bytes());
    Some(shifted.wrapping_shr(shift))
}

fn is_result_free_return_body(code: &[u8], address: u64) -> bool {
    if !aarch64_call_site_body_is_bounded(code) {
        return false;
    }
    let instructions: Vec<DisasmInsn> = match disassemble(Arch::Aarch64, address, code) {
        Ok(instructions) => instructions,
        Err(_) => return false,
    };
    !instructions.is_empty()
        && instructions
            .iter()
            .all(|instruction: &DisasmInsn| instruction.mnemonic == "ret")
}

fn recover_ambiguous_identity(
    function: &FunctionSymbol,
    sites: Option<&Vec<AttributedSite>>,
    isolated_reason: &str,
) -> core::result::Result<LeafRecovery, String> {
    let Some(sites): Option<&Vec<AttributedSite>> = sites else {
        return Err(isolated_reason.to_owned());
    };
    if sites.is_empty() {
        return Err(isolated_reason.to_owned());
    }
    let mut evidence: Vec<SiteEvidence> = Vec::with_capacity(sites.len());
    for site in sites {
        evidence.push(analyze_site(site));
    }
    let fatal: Option<String> = evidence
        .iter()
        .find_map(|site: &SiteEvidence| match &site.issue {
            Some(SiteIssue::Fatal(reason)) => Some(reason.clone()),
            Some(SiteIssue::Discarded(_)) | None => None,
        });
    if let Some(reason) = fatal {
        return Err(reason);
    }
    let arguments: Option<ArgumentSignature> = unify_arguments(&evidence)?;
    let return_proof: Option<(CallSiteScalar, CallSiteReturnProof)> = unify_returns(&evidence)?;
    if evidence
        .iter()
        .any(|site: &SiteEvidence| site.indirect_composite)
    {
        return Err(
            "call-site evidence proves an indirect composite return but not its layout".to_owned(),
        );
    }
    let discarded: Option<String> =
        evidence
            .iter()
            .find_map(|site: &SiteEvidence| match &site.issue {
                Some(SiteIssue::Discarded(reason)) => Some(reason.clone()),
                Some(SiteIssue::Fatal(_)) | None => None,
            });
    let Some((return_type, return_rule)): Option<(CallSiteScalar, CallSiteReturnProof)> =
        return_proof
    else {
        if let Some(discarded_reason) = discarded.as_ref() {
            return Err(discarded_reason.clone());
        }
        return Err(
            "every attributed caller ignores the result; return type remains underdetermined"
                .to_owned(),
        );
    };
    let Some(arguments): Option<ArgumentSignature> = arguments else {
        if let Some(discarded_reason) = discarded.as_ref() {
            return Err(discarded_reason.clone());
        }
        return Err(
            "call-site return evidence lacks a matching proven argument for the result-free body"
                .to_owned(),
        );
    };
    validate_identity_return(return_type, &arguments)?;
    let fp_params: Vec<FpWidth> = arguments
        .fp
        .iter()
        .map(|width: &EvidenceWidth| match width {
            EvidenceWidth::FloatingPoint32 => Ok(FpWidth::F32),
            EvidenceWidth::FloatingPoint64 => Ok(FpWidth::F64),
            EvidenceWidth::Integer32 | EvidenceWidth::Integer64 => {
                Err("floating-point argument evidence contains an integer width".to_owned())
            }
        })
        .collect::<core::result::Result<Vec<FpWidth>, String>>()?;
    let int_params: Vec<Width> = arguments
        .int
        .iter()
        .map(|width: &EvidenceWidth| match width {
            EvidenceWidth::Integer32 => Ok(Width::W32),
            EvidenceWidth::Integer64 => Ok(Width::W64),
            EvidenceWidth::FloatingPoint32 | EvidenceWidth::FloatingPoint64 => {
                Err("integer argument evidence contains a floating-point width".to_owned())
            }
        })
        .collect::<core::result::Result<Vec<Width>, String>>()?;
    let recovered_signature: CallSiteIdentitySignature = CallSiteIdentitySignature {
        fp_params,
        int_params,
        return_type,
        proof: CallSiteSignatureProof {
            return_proof: return_rule,
            attributed_sites: sites.len(),
        },
    };
    let Some(code): Option<&Arc<[u8]>> = function.code.as_ref() else {
        return Err("function symbol has no bounded body".to_owned());
    };
    recover_call_site_identity(code.as_ref(), function.address, &recovered_signature)
        .map_err(|error: Error| error.to_string())
}

fn analyze_site(site: &AttributedSite) -> SiteEvidence {
    let successors: Vec<Vec<usize>> =
        control_flow_successors(&site.instructions, &site.relocated_branches);
    let predecessors: Vec<Vec<usize>> = control_flow_predecessors(&successors);
    let has_unresolved_noncall_edge: bool = has_unresolved_noncall_edge(site, &successors);
    let arguments: core::result::Result<Option<ArgumentSignature>, String> =
        if has_unresolved_noncall_edge {
            Ok(None)
        } else {
            prove_arguments(site, &successors, &predecessors)
        };
    let return_read: core::result::Result<Option<EvidenceWidth>, String> =
        prove_scalar_return(site, &successors);
    let indirect_composite: bool =
        !has_unresolved_noncall_edge && prove_indirect_composite(site, &successors, &predecessors);
    match (arguments, return_read) {
        (Ok(arguments), Ok(return_read)) => SiteEvidence {
            arguments,
            return_read,
            indirect_composite,
            issue: None,
        },
        (Err(reason), _) => SiteEvidence {
            arguments: None,
            return_read: None,
            indirect_composite: false,
            issue: Some(SiteIssue::Discarded(reason)),
        },
        (Ok(_), Err(reason)) => SiteEvidence {
            arguments: None,
            return_read: None,
            indirect_composite: false,
            issue: Some(SiteIssue::Fatal(reason)),
        },
    }
}

fn has_unresolved_noncall_edge(site: &AttributedSite, successors: &[Vec<usize>]) -> bool {
    let unresolved_target: usize = site.instructions.len();
    successors
        .iter()
        .enumerate()
        .any(|(source, targets): (usize, &Vec<usize>)| {
            source != site.call_index && targets.contains(&unresolved_target)
        })
}

fn prove_arguments(
    site: &AttributedSite,
    successors: &[Vec<usize>],
    predecessors: &[Vec<usize>],
) -> core::result::Result<Option<ArgumentSignature>, String> {
    let mut fp: Vec<Option<EvidenceWidth>> = vec![None; REGISTER_ARGUMENT_LIMIT];
    let mut int: Vec<Option<EvidenceWidth>> = vec![None; REGISTER_ARGUMENT_LIMIT];
    for index in 0..REGISTER_ARGUMENT_LIMIT {
        let fp_register: TrackedRegister = TrackedRegister {
            file: RegisterFile::FloatingPoint,
            index: u8::try_from(index).map_err(|_| "register index overflow".to_owned())?,
        };
        fp[index] = proven_argument(
            &site.instructions,
            site.call_index,
            fp_register,
            successors,
            predecessors,
        );
        let int_register: TrackedRegister = TrackedRegister {
            file: RegisterFile::Integer,
            index: u8::try_from(index).map_err(|_| "register index overflow".to_owned())?,
        };
        int[index] = proven_argument(
            &site.instructions,
            site.call_index,
            int_register,
            successors,
            predecessors,
        );
    }
    let fp_prefix: Vec<EvidenceWidth> = evidence_prefix(
        &fp,
        "call-site argument evidence is not a floating-point register prefix",
    )?;
    let int_prefix: Vec<EvidenceWidth> = evidence_prefix(
        &int,
        "call-site argument evidence is not an integer register prefix",
    )?;
    if fp_prefix.is_empty() && int_prefix.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ArgumentSignature {
            fp: fp_prefix,
            int: int_prefix,
        }))
    }
}

fn evidence_prefix(
    evidence: &[Option<EvidenceWidth>],
    reason: &str,
) -> core::result::Result<Vec<EvidenceWidth>, String> {
    let last: Option<usize> = evidence.iter().rposition(Option::is_some);
    let Some(last): Option<usize> = last else {
        return Ok(Vec::new());
    };
    let mut prefix: Vec<EvidenceWidth> = Vec::with_capacity(last + 1);
    for entry in evidence.iter().take(last + 1) {
        let Some(width): Option<EvidenceWidth> = *entry else {
            return Err(reason.to_owned());
        };
        prefix.push(width);
    }
    Ok(prefix)
}

fn proven_argument(
    instructions: &[DisasmInsn],
    call_index: usize,
    register: TrackedRegister,
    successors: &[Vec<usize>],
    predecessors: &[Vec<usize>],
) -> Option<EvidenceWidth> {
    let definition: ReachingDefinition =
        reaching_definition(instructions, call_index, register, predecessors)?;
    exclusive_call_consumer(
        instructions,
        definition.index,
        call_index,
        register,
        successors,
    )
    .then_some(definition.width)
}

fn reaching_definition(
    instructions: &[DisasmInsn],
    call_index: usize,
    register: TrackedRegister,
    predecessors: &[Vec<usize>],
) -> Option<ReachingDefinition> {
    let initial: &Vec<usize> = predecessors.get(call_index)?;
    if initial.is_empty() {
        return None;
    }
    let mut pending: Vec<usize> = initial.clone();
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut unified: Option<ReachingDefinition> = None;
    while let Some(index) = pending.pop() {
        if !visited.insert(index) {
            continue;
        }
        let instruction: &DisasmInsn = instructions.get(index)?;
        if is_call_instruction(instruction) {
            return None;
        }
        let access: RegisterAccess = register_access(instruction, register);
        if access.unknown {
            return None;
        }
        if !access.writes.is_empty() {
            if definition_reads_old_destination(instruction, register) {
                return None;
            }
            if access.writes.len() != 1 {
                return None;
            }
            let width: EvidenceWidth = *access.writes.first()?;
            let candidate: ReachingDefinition = ReachingDefinition { index, width };
            match unified {
                Some(existing) if existing != candidate => return None,
                Some(_) => {}
                None => unified = Some(candidate),
            }
            continue;
        }
        if !access.reads.is_empty() {
            return None;
        }
        let incoming: &Vec<usize> = predecessors.get(index)?;
        if incoming.is_empty() {
            return None;
        }
        pending.extend(incoming.iter().copied());
    }
    unified
}

fn exclusive_call_consumer(
    instructions: &[DisasmInsn],
    definition_index: usize,
    call_index: usize,
    register: TrackedRegister,
    successors: &[Vec<usize>],
) -> bool {
    let Some(initial): Option<&Vec<usize>> = successors.get(definition_index) else {
        return false;
    };
    let mut pending: Vec<usize> = initial.clone();
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut reaches_call: bool = false;
    while let Some(index) = pending.pop() {
        if !visited.insert(index) {
            continue;
        }
        if index == call_index {
            reaches_call = true;
            continue;
        }
        let Some(instruction): Option<&DisasmInsn> = instructions.get(index) else {
            return false;
        };
        if is_call_instruction(instruction) {
            return false;
        }
        let access: RegisterAccess = register_access(instruction, register);
        if access.unknown || !access.reads.is_empty() {
            return false;
        }
        if !access.writes.is_empty() {
            continue;
        }
        let Some(outgoing): Option<&Vec<usize>> = successors.get(index) else {
            return false;
        };
        pending.extend(outgoing.iter().copied());
    }
    reaches_call
}

fn prove_scalar_return(
    site: &AttributedSite,
    successors: &[Vec<usize>],
) -> core::result::Result<Option<EvidenceWidth>, String> {
    if site.tail {
        return Ok(None);
    }
    let fp_register: TrackedRegister = TrackedRegister {
        file: RegisterFile::FloatingPoint,
        index: 0,
    };
    let int_register: TrackedRegister = TrackedRegister {
        file: RegisterFile::Integer,
        index: 0,
    };
    let fp_reads: BTreeSet<EvidenceWidth> = first_post_call_reads(site, fp_register, successors)?;
    let int_reads: BTreeSet<EvidenceWidth> = first_post_call_reads(site, int_register, successors)?;
    if !fp_reads.is_empty() && !int_reads.is_empty() {
        return Err(
            "one attributed site reads both floating-point and integer result registers".to_owned(),
        );
    }
    if fp_reads.len() > 1 {
        return Err("one attributed site reads incompatible result widths".to_owned());
    }
    if let Some(width) = fp_reads.first() {
        return Ok(Some(*width));
    }
    if int_reads.contains(&EvidenceWidth::Integer64) {
        return Ok(Some(EvidenceWidth::Integer64));
    }
    Ok(int_reads.first().copied())
}

fn first_post_call_reads(
    site: &AttributedSite,
    register: TrackedRegister,
    successors: &[Vec<usize>],
) -> core::result::Result<BTreeSet<EvidenceWidth>, String> {
    let mut reads: BTreeSet<EvidenceWidth> = BTreeSet::new();
    let Some(initial): Option<&Vec<usize>> = successors.get(site.call_index) else {
        return Ok(reads);
    };
    let mut pending: Vec<usize> = initial.clone();
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    while let Some(index) = pending.pop() {
        if !visited.insert(index) {
            continue;
        }
        let Some(instruction): Option<&DisasmInsn> = site.instructions.get(index) else {
            return Err(
                "one attributed site has an unresolved post-call control-flow edge".to_owned(),
            );
        };
        if is_call_instruction(instruction) {
            continue;
        }
        let access: RegisterAccess = register_access(instruction, register);
        if access.unknown {
            return Err("one attributed site has an unsupported result-register access".to_owned());
        }
        if !access.reads.is_empty() {
            reads.extend(access.reads);
            continue;
        }
        if !access.writes.is_empty() {
            continue;
        }
        let Some(outgoing): Option<&Vec<usize>> = successors.get(index) else {
            continue;
        };
        pending.extend(outgoing.iter().copied());
    }
    Ok(reads)
}

fn prove_indirect_composite(
    site: &AttributedSite,
    successors: &[Vec<usize>],
    predecessors: &[Vec<usize>],
) -> bool {
    if site.tail {
        return false;
    }
    let register: TrackedRegister = TrackedRegister {
        file: RegisterFile::Integer,
        index: 8,
    };
    let Some(definition): Option<ReachingDefinition> =
        reaching_definition(&site.instructions, site.call_index, register, predecessors)
    else {
        return false;
    };
    if !exclusive_call_consumer(
        &site.instructions,
        definition.index,
        site.call_index,
        register,
        successors,
    ) {
        return false;
    }
    let Some(instruction): Option<&DisasmInsn> = site.instructions.get(definition.index) else {
        return false;
    };
    let Some(buffer): Option<BufferLocation> = x8_buffer_location(instruction) else {
        return false;
    };
    let Some(base_register): Option<TrackedRegister> = buffer_register(&buffer) else {
        return false;
    };
    if !base_unchanged_between(
        &site.instructions,
        definition.index,
        site.call_index,
        base_register,
        predecessors,
    ) {
        return false;
    }
    post_call_reads_buffer(site, &buffer, successors)
}

fn x8_buffer_location(instruction: &DisasmInsn) -> Option<BufferLocation> {
    let operands: Vec<&str> = split_operands(&instruction.operands);
    if operands.len() < 2 || operands.first()?.trim() != "x8" {
        return None;
    }
    let mnemonic: &str = instruction.mnemonic.as_str();
    if mnemonic == "mov" && operands.get(1)?.trim() == "sp" {
        return Some(BufferLocation {
            base: "sp".to_owned(),
            displacement: 0,
        });
    }
    if !matches!(mnemonic, "add" | "sub") || operands.len() != 3 {
        return None;
    }
    let base: &str = operands.get(1)?.trim();
    if !matches!(base, "sp" | "x29") {
        return None;
    }
    let magnitude: i64 = parse_immediate(operands.get(2)?.trim())?;
    let displacement: i64 = if mnemonic == "sub" {
        magnitude.checked_neg()?
    } else {
        magnitude
    };
    Some(BufferLocation {
        base: base.to_owned(),
        displacement,
    })
}

fn buffer_register(buffer: &BufferLocation) -> Option<TrackedRegister> {
    let index: u8 = match buffer.base.as_str() {
        "x29" => 29,
        "sp" => 31,
        _ => return None,
    };
    Some(TrackedRegister {
        file: RegisterFile::Integer,
        index,
    })
}

fn base_unchanged_between(
    instructions: &[DisasmInsn],
    definition_index: usize,
    call_index: usize,
    register: TrackedRegister,
    predecessors: &[Vec<usize>],
) -> bool {
    let Some(initial): Option<&Vec<usize>> = predecessors.get(call_index) else {
        return false;
    };
    if initial.is_empty() {
        return false;
    }
    let mut pending: Vec<usize> = initial.clone();
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    while let Some(index) = pending.pop() {
        if !visited.insert(index) || index == definition_index {
            continue;
        }
        let Some(instruction): Option<&DisasmInsn> = instructions.get(index) else {
            return false;
        };
        let access: RegisterAccess = register_access(instruction, register);
        if access.unknown || !access.writes.is_empty() {
            return false;
        }
        let Some(incoming): Option<&Vec<usize>> = predecessors.get(index) else {
            return false;
        };
        if incoming.is_empty() {
            return false;
        }
        pending.extend(incoming.iter().copied());
    }
    true
}

fn post_call_reads_buffer(
    site: &AttributedSite,
    buffer: &BufferLocation,
    successors: &[Vec<usize>],
) -> bool {
    let Some(base_register): Option<TrackedRegister> = buffer_register(buffer) else {
        return false;
    };
    let Some(initial): Option<&Vec<usize>> = successors.get(site.call_index) else {
        return false;
    };
    let mut pending: Vec<usize> = initial.clone();
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    while let Some(index) = pending.pop() {
        if !visited.insert(index) {
            continue;
        }
        let Some(instruction): Option<&DisasmInsn> = site.instructions.get(index) else {
            continue;
        };
        if is_call_instruction(instruction) {
            continue;
        }
        let base_access: RegisterAccess = register_access(instruction, base_register);
        if base_access.unknown || !base_access.writes.is_empty() {
            continue;
        }
        if may_write_memory(instruction) {
            continue;
        }
        let location: Option<BufferLocation> = memory_location(&instruction.operands);
        if instruction.mnemonic.starts_with("ld") && location.as_ref() == Some(buffer) {
            return true;
        }
        let Some(outgoing): Option<&Vec<usize>> = successors.get(index) else {
            continue;
        };
        pending.extend(outgoing.iter().copied());
    }
    false
}

fn may_write_memory(instruction: &DisasmInsn) -> bool {
    let mnemonic: &str = instruction.mnemonic.as_str();
    if mnemonic.starts_with("st")
        || mnemonic.starts_with("cas")
        || mnemonic.starts_with("swp")
        || mnemonic.starts_with("ldadd")
        || mnemonic.starts_with("ldclr")
        || mnemonic.starts_with("ldeor")
        || mnemonic.starts_with("ldset")
        || mnemonic.starts_with("ldsmax")
        || mnemonic.starts_with("ldsmin")
        || mnemonic.starts_with("ldumax")
        || mnemonic.starts_with("ldumin")
        || mnemonic.starts_with("cpy")
        || mnemonic.starts_with("setp")
        || mnemonic.starts_with("setm")
        || mnemonic.starts_with("sete")
    {
        return true;
    }
    if mnemonic == "dc" && instruction.operands.trim_start().starts_with("zva") {
        return true;
    }
    if mnemonic.starts_with("ld") || mnemonic == "prfm" {
        return false;
    }
    if instruction.operands.contains('[') {
        return true;
    }
    if destination_operand_count(mnemonic).is_some()
        || matches!(
            mnemonic,
            "nop"
                | "hint"
                | "yield"
                | "wfe"
                | "wfi"
                | "sev"
                | "sevl"
                | "dmb"
                | "dsb"
                | "isb"
                | "sb"
                | "clrex"
        )
    {
        return false;
    }
    true
}

fn memory_location(operands: &str) -> Option<BufferLocation> {
    let open: usize = operands.find('[')?;
    let close_relative: usize = operands.get(open + 1..)?.find(']')?;
    let close: usize = open.checked_add(1)?.checked_add(close_relative)?;
    let inside: &str = operands.get(open + 1..close)?;
    let parts: Vec<&str> = split_operands(inside);
    let base: &str = parts.first()?.trim();
    if !matches!(base, "sp" | "x29") {
        return None;
    }
    let displacement: i64 = match parts.get(1) {
        Some(value) => parse_immediate(value.trim())?,
        None => 0,
    };
    Some(BufferLocation {
        base: base.to_owned(),
        displacement,
    })
}

fn parse_immediate(token: &str) -> Option<i64> {
    let value: &str = token.strip_prefix('#')?;
    let positive_hex: Option<&str> = value.strip_prefix("0x");
    let negative_hex: Option<&str> = value.strip_prefix("-0x");
    if let Some(hex) = positive_hex {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(hex) = negative_hex {
        i64::from_str_radix(hex, 16).ok()?.checked_neg()
    } else {
        value.parse::<i64>().ok()
    }
}

fn unify_arguments(
    evidence: &[SiteEvidence],
) -> core::result::Result<Option<ArgumentSignature>, String> {
    let mut unified: Option<ArgumentSignature> = None;
    for site in evidence {
        let Some(candidate): Option<&ArgumentSignature> = site.arguments.as_ref() else {
            continue;
        };
        match &unified {
            Some(existing) if existing != candidate => {
                return Err(
                    "proof-grade attributed sites disagree on argument class, width, or arity"
                        .to_owned(),
                );
            }
            Some(_) => {}
            None => unified = Some(candidate.clone()),
        }
    }
    Ok(unified)
}

fn unify_returns(
    evidence: &[SiteEvidence],
) -> core::result::Result<Option<(CallSiteScalar, CallSiteReturnProof)>, String> {
    let reads: Vec<EvidenceWidth> = evidence
        .iter()
        .filter_map(|site: &SiteEvidence| site.return_read)
        .collect();
    if reads.is_empty() {
        return Ok(None);
    }
    let classes: BTreeSet<RegisterFile> = reads
        .iter()
        .map(|width: &EvidenceWidth| match width {
            EvidenceWidth::Integer32 | EvidenceWidth::Integer64 => RegisterFile::Integer,
            EvidenceWidth::FloatingPoint32 | EvidenceWidth::FloatingPoint64 => {
                RegisterFile::FloatingPoint
            }
        })
        .collect();
    if classes.len() != 1 {
        return Err("proof-grade attributed sites disagree on return class or width".to_owned());
    }
    match classes.first() {
        Some(RegisterFile::FloatingPoint) => {
            let widths: BTreeSet<EvidenceWidth> = reads.iter().copied().collect();
            if widths.len() != 1 {
                return Err(
                    "proof-grade attributed sites disagree on return class or width".to_owned(),
                );
            }
            match widths.first() {
                Some(EvidenceWidth::FloatingPoint32) => Ok(Some((
                    CallSiteScalar::FloatingPoint(FpWidth::F32),
                    CallSiteReturnProof::FloatingPoint32,
                ))),
                Some(EvidenceWidth::FloatingPoint64) => Ok(Some((
                    CallSiteScalar::FloatingPoint(FpWidth::F64),
                    CallSiteReturnProof::FloatingPoint64,
                ))),
                Some(EvidenceWidth::Integer32 | EvidenceWidth::Integer64) | None => {
                    Err("floating-point return evidence has an invalid width".to_owned())
                }
            }
        }
        Some(RegisterFile::Integer) => {
            if reads.contains(&EvidenceWidth::Integer64) {
                Ok(Some((
                    CallSiteScalar::Integer(Width::W64),
                    CallSiteReturnProof::Integer64,
                )))
            } else if reads
                .iter()
                .all(|width: &EvidenceWidth| *width == EvidenceWidth::Integer32)
            {
                Ok(Some((
                    CallSiteScalar::Integer(Width::W32),
                    CallSiteReturnProof::UnanimousInteger32,
                )))
            } else {
                Err("proof-grade attributed sites disagree on return class or width".to_owned())
            }
        }
        None => Ok(None),
    }
}

fn validate_identity_return(
    return_type: CallSiteScalar,
    arguments: &ArgumentSignature,
) -> core::result::Result<(), String> {
    match return_type {
        CallSiteScalar::FloatingPoint(width) => {
            let expected: EvidenceWidth = match width {
                FpWidth::F32 => EvidenceWidth::FloatingPoint32,
                FpWidth::F64 => EvidenceWidth::FloatingPoint64,
            };
            if arguments.fp.first() == Some(&expected) {
                Ok(())
            } else {
                Err(
                    "call-site return evidence lacks a matching proven argument for the result-free body"
                        .to_owned(),
                )
            }
        }
        CallSiteScalar::Integer(_) => {
            if arguments.int.is_empty() {
                Err(
                    "call-site return evidence lacks a matching proven argument for the result-free body"
                        .to_owned(),
                )
            } else {
                Ok(())
            }
        }
    }
}

fn recovered_function(function: &FunctionSymbol, recovery: LeafRecovery) -> RecoveredFunction {
    let source: String = rename_recovered_c_symbol(&recovery.source, &function.name);
    let rust_source: Option<String> = recovery
        .rust_source
        .as_deref()
        .map(|body: &str| rename_recovered_rust_symbol(body, &function.name, &[]));
    RecoveredFunction {
        name: function.name.clone(),
        address: function.address,
        source,
        rust_source,
        return_width_bits: recovery.return_width_bits,
        param_width_bits: recovery.param_width_bits,
        params: recovery.params,
        fp_params: recovery.fp_params,
        returns_fp: recovery.returns_fp,
        resolved_calls: recovery.call_targets,
        call_site_signature: recovery.call_site_signature,
    }
}

fn control_flow_successors(
    instructions: &[DisasmInsn],
    relocated_branches: &BTreeSet<usize>,
) -> Vec<Vec<usize>> {
    let by_address: BTreeMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(index, instruction): (usize, &DisasmInsn)| (instruction.address, index))
        .collect();
    let mut successors: Vec<Vec<usize>> = vec![Vec::new(); instructions.len()];
    let unresolved_target: usize = instructions.len();
    for (index, instruction) in instructions.iter().enumerate() {
        let next: Option<usize> = index
            .checked_add(1)
            .filter(|next_index: &usize| *next_index < instructions.len());
        let word: Option<u32> = instruction_word(instruction);
        if is_indirect_terminator(instruction) {
            continue;
        }
        if instruction.mnemonic == "b" {
            let target: Option<usize> = if relocated_branches.contains(&index) {
                None
            } else {
                word.and_then(|value: u32| branch_target_index(value, instruction.address, 26, 0))
                    .and_then(|address: u64| by_address.get(&address).copied())
            };
            successors[index].push(target.unwrap_or(unresolved_target));
            continue;
        }
        if is_conditional_branch(instruction) {
            let target: Option<usize> = if relocated_branches.contains(&index) {
                None
            } else {
                word.and_then(|value: u32| conditional_target(value, instruction.address))
                    .and_then(|address: u64| by_address.get(&address).copied())
            };
            successors[index].push(target.unwrap_or(unresolved_target));
            if let Some(next_index) = next {
                successors[index].push(next_index);
            } else {
                successors[index].push(unresolved_target);
            }
            successors[index].sort_unstable();
            successors[index].dedup();
            continue;
        }
        if let Some(next_index) = next {
            successors[index].push(next_index);
        } else {
            successors[index].push(unresolved_target);
        }
    }
    successors
}

fn control_flow_predecessors(successors: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); successors.len()];
    for (source, targets) in successors.iter().enumerate() {
        for target in targets {
            let incoming: Option<&mut Vec<usize>> = predecessors.get_mut(*target);
            if let Some(incoming) = incoming {
                incoming.push(source);
            }
        }
    }
    predecessors
}

fn is_conditional_branch(instruction: &DisasmInsn) -> bool {
    instruction.mnemonic.starts_with("b.")
        || matches!(
            instruction.mnemonic.as_str(),
            "cbz" | "cbnz" | "tbz" | "tbnz"
        )
}

fn conditional_target(word: u32, address: u64) -> Option<u64> {
    if word & 0xff00_0010 == 0x5400_0000 || word & 0x7e00_0000 == 0x3400_0000 {
        branch_target_index(word, address, 19, 5)
    } else if word & 0x7e00_0000 == 0x3600_0000 {
        branch_target_index(word, address, 14, 5)
    } else {
        None
    }
}

fn branch_target_index(word: u32, address: u64, bits: u32, shift: u32) -> Option<u64> {
    let mask: u64 = 1_u64.checked_shl(bits)?.checked_sub(1)?;
    let immediate: u64 = u64::from(word.wrapping_shr(shift)) & mask;
    let displacement: i64 = sign_extend(immediate, bits)?.checked_mul(4)?;
    let address_i64: i64 = i64::try_from(address).ok()?;
    u64::try_from(address_i64.checked_add(displacement)?).ok()
}

fn is_call_instruction(instruction: &DisasmInsn) -> bool {
    matches!(
        instruction.mnemonic.as_str(),
        "bl" | "blr" | "blraa" | "blraaz" | "blrab" | "blrabz" | "hvc" | "smc" | "svc"
    )
}

fn is_indirect_terminator(instruction: &DisasmInsn) -> bool {
    matches!(
        instruction.mnemonic.as_str(),
        "br" | "braa"
            | "braaz"
            | "brab"
            | "brabz"
            | "drps"
            | "eret"
            | "eretaa"
            | "eretab"
            | "ret"
            | "retaa"
            | "retab"
    )
}

fn register_access(instruction: &DisasmInsn, register: TrackedRegister) -> RegisterAccess {
    let operands: Vec<&str> = split_operands(&instruction.operands);
    let mut access: RegisterAccess = RegisterAccess::default();
    if operands.is_empty() {
        return access;
    }
    let destination_count: Option<usize> = destination_operand_count(instruction.mnemonic.as_str());
    let mentioned: bool = operands
        .iter()
        .any(|operand: &&str| operand_mentions_register(operand, register));
    let Some(destination_count): Option<usize> = destination_count else {
        access.unknown = mentioned;
        return access;
    };
    for (index, operand) in operands.iter().enumerate() {
        let widths: BTreeSet<EvidenceWidth> = operand_widths(operand, register);
        if widths.is_empty() {
            if operand_mentions_unsupported_width(operand, register) {
                access.unknown = true;
            }
            continue;
        }
        if index < destination_count {
            access.writes.extend(widths.iter().copied());
            if destination_reads_old_value(instruction.mnemonic.as_str()) {
                access.reads.extend(widths);
            }
        } else {
            access.reads.extend(widths.iter().copied());
            if operand_is_writeback(operand, &operands, index) {
                access.writes.extend(widths);
            }
        }
    }
    access
}

fn destination_operand_count(mnemonic: &str) -> Option<usize> {
    if mnemonic.starts_with("ldp") || mnemonic.starts_with("ldnp") {
        return Some(2);
    }
    if mnemonic.starts_with("ldr")
        || mnemonic.starts_with("ldur")
        || mnemonic.starts_with("ldar")
        || mnemonic.starts_with("ldax")
        || mnemonic.starts_with("ldxr")
        || mnemonic.starts_with("ldtr")
    {
        return Some(1);
    }
    if mnemonic.starts_with("stxr")
        || mnemonic.starts_with("stlxr")
        || mnemonic.starts_with("stxp")
        || mnemonic.starts_with("stlxp")
    {
        return Some(1);
    }
    if mnemonic.starts_with("str")
        || mnemonic.starts_with("stur")
        || mnemonic.starts_with("stp")
        || mnemonic.starts_with("stnp")
        || mnemonic.starts_with("stlr")
        || mnemonic.starts_with("stlx")
        || mnemonic.starts_with("stxr")
        || matches!(
            mnemonic,
            "b" | "bl"
                | "blr"
                | "br"
                | "ret"
                | "cbz"
                | "cbnz"
                | "tbz"
                | "tbnz"
                | "cmp"
                | "cmn"
                | "tst"
                | "ccmp"
                | "ccmn"
                | "fcmp"
                | "fcmpe"
                | "fccmp"
                | "fccmpe"
                | "prfm"
        )
        || mnemonic.starts_with("b.")
    {
        return Some(0);
    }
    if has_standard_destination(mnemonic) {
        Some(1)
    } else {
        None
    }
}

fn has_standard_destination(mnemonic: &str) -> bool {
    [
        "adc", "adcs", "add", "adds", "adr", "adrp", "and", "ands", "asr", "bfi", "bfxil", "bic",
        "bics", "cls", "clz", "csel", "cset", "csetm", "csinc", "csinv", "csneg", "eon", "eor",
        "extr", "fabs", "fadd", "fcsel", "fcvt", "fcvtas", "fcvtau", "fcvtms", "fcvtmu", "fcvtns",
        "fcvtnu", "fcvtps", "fcvtpu", "fcvtzs", "fcvtzu", "fdiv", "fmadd", "fmax", "fmaxnm",
        "fmin", "fminnm", "fmov", "fmsub", "fmul", "fneg", "fnmadd", "fnmsub", "fnmul", "frinta",
        "frinti", "frintm", "frintn", "frintp", "frintx", "frintz", "fsqrt", "fsub", "lsl", "lsr",
        "madd", "mneg", "mov", "movk", "movn", "movz", "msub", "mul", "mvn", "neg", "negs", "orn",
        "orr", "rbit", "rev", "rev16", "rev32", "ror", "sbc", "sbcs", "sbfiz", "sbfx", "scvtf",
        "sdiv", "smaddl", "smnegl", "smsubl", "smulh", "smull", "sub", "subs", "sxtb", "sxth",
        "sxtw", "ubfiz", "ubfx", "ucvtf", "udiv", "umaddl", "umnegl", "umsubl", "umulh", "umull",
        "uxtb", "uxth",
    ]
    .contains(&mnemonic)
}

fn destination_reads_old_value(mnemonic: &str) -> bool {
    matches!(mnemonic, "bfi" | "bfxil" | "movk")
}

fn definition_reads_old_destination(instruction: &DisasmInsn, register: TrackedRegister) -> bool {
    if !destination_reads_old_value(instruction.mnemonic.as_str()) {
        return false;
    }
    let operands: Vec<&str> = split_operands(&instruction.operands);
    operands
        .first()
        .is_some_and(|operand: &&str| operand_mentions_register(operand, register))
}

fn operand_is_writeback(operand: &str, operands: &[&str], index: usize) -> bool {
    operand.contains('[')
        && (operand.contains('!')
            || (index + 1 == operands.len().saturating_sub(1)
                && operands
                    .last()
                    .is_some_and(|last: &&str| last.trim().starts_with('#'))))
}

fn split_operands(operands: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    let mut depth: usize = 0;
    let mut start: usize = 0;
    for (index, byte) in operands.bytes().enumerate() {
        match byte {
            b'[' | b'{' => depth = depth.saturating_add(1),
            b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                let part: Option<&str> = operands.get(start..index);
                if let Some(part) = part {
                    out.push(part.trim());
                }
                start = index.saturating_add(1);
            }
            _ => {}
        }
    }
    let part: Option<&str> = operands.get(start..);
    if let Some(part) = part
        && !part.trim().is_empty()
    {
        out.push(part.trim());
    }
    out
}

fn operand_widths(operand: &str, register: TrackedRegister) -> BTreeSet<EvidenceWidth> {
    operand
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter_map(|token: &str| token_width(token, register))
        .collect()
}

fn operand_mentions_register(operand: &str, register: TrackedRegister) -> bool {
    operand
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|token: &str| token_register_index(token, register.file) == Some(register.index))
}

fn operand_mentions_unsupported_width(operand: &str, register: TrackedRegister) -> bool {
    operand
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|token: &str| {
            token_register_index(token, register.file) == Some(register.index)
                && token_width(token, register).is_none()
        })
}

fn token_width(token: &str, register: TrackedRegister) -> Option<EvidenceWidth> {
    if token_register_index(token, register.file) != Some(register.index) {
        return None;
    }
    if register.file == RegisterFile::Integer && matches!(token, "sp" | "wsp") {
        return if token == "sp" {
            Some(EvidenceWidth::Integer64)
        } else {
            Some(EvidenceWidth::Integer32)
        };
    }
    match (register.file, token.as_bytes().first().copied()) {
        (RegisterFile::Integer, Some(b'w')) => Some(EvidenceWidth::Integer32),
        (RegisterFile::Integer, Some(b'x')) => Some(EvidenceWidth::Integer64),
        (RegisterFile::FloatingPoint, Some(b's')) => Some(EvidenceWidth::FloatingPoint32),
        (RegisterFile::FloatingPoint, Some(b'd')) => Some(EvidenceWidth::FloatingPoint64),
        _ => None,
    }
}

fn token_register_index(token: &str, file: RegisterFile) -> Option<u8> {
    if file == RegisterFile::Integer && matches!(token, "sp" | "wsp") {
        return Some(31);
    }
    let first: u8 = *token.as_bytes().first()?;
    let permitted: bool = match file {
        RegisterFile::Integer => matches!(first, b'w' | b'x'),
        RegisterFile::FloatingPoint => matches!(first, b'b' | b'h' | b's' | b'd' | b'q' | b'v'),
    };
    if !permitted {
        return None;
    }
    token.get(1..)?.parse::<u8>().ok()
}
