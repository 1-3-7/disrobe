use std::collections::{BTreeMap, BTreeSet, VecDeque};

use disrobe_ir::payload::DisasmInstruction;
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Formatter as _, Instruction, Mnemonic,
    NasmFormatter, OpKind, Register,
};
use serde::{Deserialize, Serialize};

use crate::arch::decode_one_x86;
use crate::error::{Error, Result};
use crate::pseudo_c::aarch64::{
    AARCH64_INSTRUCTION_BYTES, Aarch64DirectTransfer, aarch64_direct_transfer,
    aarch64_stops_traversal,
};

const VMWARE_BACKDOOR_MAGIC: u32 = 0x564D_5868;
const VMWARE_BACKDOOR_PORT: u16 = 0x5658;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmwareBackdoorHit {
    pub mov_address: u64,
    pub io_address: u64,
}

#[must_use]
pub fn scan_vmware_backdoor(bitness: Bitness, base: u64, bytes: &[u8]) -> Vec<VmwareBackdoorHit> {
    let mut hits: Vec<VmwareBackdoorHit> = Vec::new();
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bitness.value(), bytes, base, DecoderOptions::NONE);
    let mut prev_magic: Option<u64> = None;
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            prev_magic = None;
            continue;
        }
        if is_vmware_magic_load(&insn) {
            prev_magic = Some(insn.ip());
            continue;
        }
        if let Some(mov_address) = prev_magic
            && is_vmware_port_in(&insn)
        {
            hits.push(VmwareBackdoorHit {
                mov_address,
                io_address: insn.ip(),
            });
        }
        prev_magic = None;
    }
    hits
}

fn is_vmware_magic_load(insn: &Instruction) -> bool {
    if insn.mnemonic() != Mnemonic::Mov {
        return false;
    }
    if insn.op0_kind() != OpKind::Register || insn.op0_register() != Register::EAX {
        return false;
    }
    if !matches!(insn.op1_kind(), OpKind::Immediate32) {
        return false;
    }
    insn.immediate32() == VMWARE_BACKDOOR_MAGIC
}

fn is_vmware_port_in(insn: &Instruction) -> bool {
    if !matches!(insn.code(), Code::In_EAX_DX | Code::In_AX_DX) {
        return false;
    }
    matches!(insn.op1_kind(), OpKind::Register) && insn.op1_register() == Register::DX
}

#[must_use]
pub const fn vmware_backdoor_port() -> u16 {
    VMWARE_BACKDOOR_PORT
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bitness {
    Bits32,
    Bits64,
}

impl Bitness {
    const fn value(self) -> u32 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredInsn {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnresolvedKind {
    IndirectBranch,
    IndirectCall,
    Return,
    Interrupt,
    DecodeError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnresolvedTarget {
    pub address: u64,
    pub kind: UnresolvedKind,
    pub mnemonic: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesyncReport {
    pub recovered: Vec<RecoveredInsn>,
    pub unresolved: Vec<UnresolvedTarget>,
    pub junk_ranges: Vec<ByteRange>,
    pub overlap_addresses: Vec<u64>,
    pub linear_sweep_count: usize,
    pub recursive_count: usize,
}

impl DesyncReport {
    #[must_use]
    pub fn desync_detected(&self) -> bool {
        !self.junk_ranges.is_empty() || !self.overlap_addresses.is_empty()
    }

    #[must_use]
    pub fn fully_resolved(&self) -> bool {
        !self
            .unresolved
            .iter()
            .any(|t: &UnresolvedTarget| matches!(t.kind, UnresolvedKind::DecodeError))
    }

    #[must_use]
    pub fn cleaned_listing(&self) -> String {
        use std::fmt::Write as _;
        let mut out: String = String::new();
        let _ = writeln!(
            out,
            "; recovered linear listing ({} real instructions, {} junk range(s))",
            self.recovered.len(),
            self.junk_ranges.len()
        );
        for insn in &self.recovered {
            if insn.operands.is_empty() {
                let _ = writeln!(out, "  0x{:x}: {}", insn.address, insn.mnemonic);
            } else {
                let _ = writeln!(
                    out,
                    "  0x{:x}: {} {}",
                    insn.address, insn.mnemonic, insn.operands
                );
            }
        }
        for range in &self.junk_ranges {
            let _ = writeln!(
                out,
                "; junk bytes elided: 0x{:x}..0x{:x}",
                range.start, range.end
            );
        }
        out
    }
}

#[must_use]
pub fn cleaned_listing(
    bitness: Bitness,
    base: u64,
    bytes: &[u8],
    entries: &[u64],
) -> Option<String> {
    resolve(bitness, base, bytes, entries)
        .ok()
        .map(|report: DesyncReport| report.cleaned_listing())
}

pub fn resolve(bitness: Bitness, base: u64, bytes: &[u8], entries: &[u64]) -> Result<DesyncReport> {
    resolve_with_noreturn(bitness, base, bytes, entries, &BTreeSet::new())
}

pub fn resolve_with_noreturn(
    bitness: Bitness,
    base: u64,
    bytes: &[u8],
    entries: &[u64],
    noreturn_seeds: &BTreeSet<u64>,
) -> Result<DesyncReport> {
    Ok(resolve_with_noreturn_status(bitness, base, bytes, entries, noreturn_seeds)?.into_value())
}

pub fn resolve_with_noreturn_status(
    bitness: Bitness,
    base: u64,
    bytes: &[u8],
    entries: &[u64],
    noreturn_seeds: &BTreeSet<u64>,
) -> Result<NoreturnInferenceOutcome<DesyncReport>> {
    if bytes.is_empty() {
        return Err(Error::Truncated { needed: 1, had: 0 });
    }
    let end_addr: u64 = base.saturating_add(bytes.len() as u64);
    let starts: Vec<u64> = if entries.is_empty() {
        vec![base]
    } else {
        entries.to_vec()
    };
    for entry in &starts {
        if *entry < base || *entry >= end_addr {
            return Err(Error::Disasm {
                engine: "desync",
                message: format!("entry {entry:#x} outside [{base:#x}, {end_addr:#x})"),
            });
        }
    }

    let single: [CodeWindow<'_>; 1] = [CodeWindow {
        address: base,
        bytes,
    }];
    let candidates: BTreeSet<u64> = starts.iter().copied().collect();
    let inference_input: DiscoveryInput<'_> = DiscoveryInput {
        bitness,
        code: single.to_vec(),
        rodata: Vec::new(),
        seeds: starts.clone(),
        noreturn: noreturn_seeds.clone(),
    };
    let inference: NoreturnInference =
        noreturn_closure(&inference_input, &candidates, noreturn_seeds.clone());
    let termination: NoreturnInferenceTermination = inference.termination();
    let noreturn: BTreeSet<u64> = inference.into_known();

    let recursive: TraversalResult = recursive_traversal(bitness, base, bytes, &starts, &noreturn);
    let linear: usize = linear_sweep_count(bitness, base, bytes);

    let mut recovered: Vec<RecoveredInsn> = recursive
        .instructions
        .into_values()
        .collect::<Vec<RecoveredInsn>>();
    recovered.sort_by_key(|insn: &RecoveredInsn| insn.address);

    let junk_ranges: Vec<ByteRange> = uncovered_ranges(base, bytes.len(), &recursive.covered);
    let mut overlap_addresses: Vec<u64> = recursive.overlaps.into_iter().collect();
    overlap_addresses.sort_unstable();
    let mut unresolved: Vec<UnresolvedTarget> = recursive.unresolved;
    unresolved.sort_by_key(|target: &UnresolvedTarget| target.address);

    Ok(NoreturnInferenceOutcome::new(
        DesyncReport {
            recursive_count: recovered.len(),
            recovered,
            unresolved,
            junk_ranges,
            overlap_addresses,
            linear_sweep_count: linear,
        },
        termination,
    ))
}

struct TraversalResult {
    instructions: BTreeMap<u64, RecoveredInsn>,
    covered: BTreeSet<u64>,
    overlaps: BTreeSet<u64>,
    unresolved: Vec<UnresolvedTarget>,
}

fn recursive_traversal(
    bitness: Bitness,
    base: u64,
    bytes: &[u8],
    entries: &[u64],
    noreturn: &BTreeSet<u64>,
) -> TraversalResult {
    let end_addr: u64 = base.saturating_add(bytes.len() as u64);
    let mut instructions: BTreeMap<u64, RecoveredInsn> = BTreeMap::new();
    let mut covered: BTreeSet<u64> = BTreeSet::new();
    let mut overlaps: BTreeSet<u64> = BTreeSet::new();
    let mut unresolved: Vec<UnresolvedTarget> = Vec::new();
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut instruction_starts: BTreeSet<u64> = BTreeSet::new();

    let mut formatter: NasmFormatter = NasmFormatter::new();
    let mut queue: VecDeque<u64> = entries.iter().copied().collect::<VecDeque<u64>>();

    while let Some(address) = queue.pop_front() {
        if address < base || address >= end_addr {
            continue;
        }
        if !visited.insert(address) {
            continue;
        }
        let offset: usize = (address - base) as usize;
        let window: &[u8] = &bytes[offset..];
        let mut decoder: Decoder<'_> =
            Decoder::with_ip(bitness.value(), window, address, DecoderOptions::NONE);
        if !decoder.can_decode() {
            continue;
        }
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            unresolved.push(UnresolvedTarget {
                address,
                kind: UnresolvedKind::DecodeError,
                mnemonic: "(bad)".to_owned(),
            });
            continue;
        }

        let len: usize = insn.len();
        let insn_end: u64 = address.saturating_add(len as u64);
        if insn_end > end_addr {
            continue;
        }

        instruction_starts.insert(address);
        for covered_addr in address..insn_end {
            covered.insert(covered_addr);
        }

        let mut text: String = String::new();
        formatter.format(&insn, &mut text);
        let (mnemonic, operands): (String, String) = split_text(&text);
        let raw: Vec<u8> = window.get(..len).map(<[u8]>::to_vec).unwrap_or_default();
        instructions.insert(
            address,
            RecoveredInsn {
                address,
                bytes: raw,
                mnemonic: mnemonic.clone(),
                operands,
            },
        );

        enqueue_successors(
            &insn,
            insn_end,
            base,
            end_addr,
            noreturn,
            &mut queue,
            &mut unresolved,
            &mnemonic,
        );
    }

    mark_overlaps(&instruction_starts, &instructions, &mut overlaps);

    TraversalResult {
        instructions,
        covered,
        overlaps,
        unresolved,
    }
}

fn mark_overlaps(
    starts: &BTreeSet<u64>,
    instructions: &BTreeMap<u64, RecoveredInsn>,
    overlaps: &mut BTreeSet<u64>,
) {
    for (address, insn) in instructions {
        let insn_end: u64 = address.saturating_add(insn.bytes.len() as u64);
        for inner in (address + 1)..insn_end {
            if starts.contains(&inner) {
                overlaps.insert(inner);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn enqueue_successors(
    insn: &Instruction,
    fallthrough: u64,
    base: u64,
    end_addr: u64,
    noreturn: &BTreeSet<u64>,
    queue: &mut VecDeque<u64>,
    unresolved: &mut Vec<UnresolvedTarget>,
    mnemonic: &str,
) {
    let in_range = |target: u64| target >= base && target < end_addr;
    match insn.flow_control() {
        FlowControl::Next => {
            if in_range(fallthrough) {
                queue.push_back(fallthrough);
            }
        }
        FlowControl::XbeginXabortXend => {
            let target: u64 = insn.near_branch_target();
            if in_range(target) {
                queue.push_back(target);
            }
            if in_range(fallthrough) {
                queue.push_back(fallthrough);
            }
        }
        FlowControl::Call => {
            let target: u64 = insn.near_branch_target();
            let direct: bool = matches!(
                insn.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            );
            if in_range(target) {
                queue.push_back(target);
            }
            if !(direct && noreturn.contains(&target)) && in_range(fallthrough) {
                queue.push_back(fallthrough);
            }
        }
        FlowControl::ConditionalBranch => {
            let target: u64 = insn.near_branch_target();
            if in_range(target) {
                queue.push_back(target);
            }
            if in_range(fallthrough) {
                queue.push_back(fallthrough);
            }
        }
        FlowControl::UnconditionalBranch => {
            let target: u64 = insn.near_branch_target();
            if in_range(target) {
                queue.push_back(target);
            }
        }
        FlowControl::IndirectBranch => unresolved.push(UnresolvedTarget {
            address: insn.ip(),
            kind: UnresolvedKind::IndirectBranch,
            mnemonic: mnemonic.to_owned(),
        }),
        FlowControl::IndirectCall => {
            unresolved.push(UnresolvedTarget {
                address: insn.ip(),
                kind: UnresolvedKind::IndirectCall,
                mnemonic: mnemonic.to_owned(),
            });
            if in_range(fallthrough) {
                queue.push_back(fallthrough);
            }
        }
        FlowControl::Return => unresolved.push(UnresolvedTarget {
            address: insn.ip(),
            kind: UnresolvedKind::Return,
            mnemonic: mnemonic.to_owned(),
        }),
        FlowControl::Interrupt => {
            unresolved.push(UnresolvedTarget {
                address: insn.ip(),
                kind: UnresolvedKind::Interrupt,
                mnemonic: mnemonic.to_owned(),
            });
            if in_range(fallthrough) {
                queue.push_back(fallthrough);
            }
        }
        FlowControl::Exception => {}
    }
}

fn linear_sweep_count(bitness: Bitness, base: u64, bytes: &[u8]) -> usize {
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bitness.value(), bytes, base, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut count: usize = 0;
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        count += 1;
    }
    count
}

fn uncovered_ranges(base: u64, len: usize, covered: &BTreeSet<u64>) -> Vec<ByteRange> {
    let mut ranges: Vec<ByteRange> = Vec::new();
    let mut run_start: Option<u64> = None;
    for index in 0..len {
        let addr: u64 = base + index as u64;
        if covered.contains(&addr) {
            if let Some(start) = run_start.take() {
                ranges.push(ByteRange { start, end: addr });
            }
        } else if run_start.is_none() {
            run_start = Some(addr);
        }
    }
    if let Some(start) = run_start {
        ranges.push(ByteRange {
            start,
            end: base + len as u64,
        });
    }
    ranges
}

fn split_text(text: &str) -> (String, String) {
    match text.split_once(' ') {
        Some((mnemonic, operands)) => (mnemonic.to_owned(), operands.trim().to_owned()),
        None => (text.to_owned(), String::new()),
    }
}

#[derive(Debug, Clone)]
pub struct CodeWindow<'a> {
    pub address: u64,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct ReadOnlyWindow<'a> {
    pub address: u64,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct DiscoveryInput<'a> {
    pub bitness: Bitness,
    pub code: Vec<CodeWindow<'a>>,
    pub rodata: Vec<ReadOnlyWindow<'a>>,
    pub seeds: Vec<u64>,
    pub noreturn: BTreeSet<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NoreturnInferenceTermination {
    Complete,
    DecodedInstructionBudget,
    IterationLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoreturnInferenceOutcome<T> {
    value: T,
    termination: NoreturnInferenceTermination,
}

impl<T> NoreturnInferenceOutcome<T> {
    fn new(value: T, termination: NoreturnInferenceTermination) -> Self {
        Self { value, termination }
    }

    #[must_use]
    pub const fn termination(&self) -> NoreturnInferenceTermination {
        self.termination
    }

    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }

    #[must_use]
    pub fn into_parts(self) -> (T, NoreturnInferenceTermination) {
        (self.value, self.termination)
    }
}

const NORETURN_IMPORT_NAMES: &[&str] = &[
    "ExitProcess",
    "ExitThread",
    "TerminateProcess",
    "RtlExitUserProcess",
    "RtlExitUserThread",
    "_invoke_watson",
    "_invalid_parameter_noinfo_noreturn",
    "__fastfail",
    "abort",
    "_abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "_o_exit",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__stack_chk_fail",
    "__assert_fail",
    "__cxa_throw",
    "_Unwind_Resume",
    "pthread_exit",
    "ExitProcessImplementation",
    "_invalid_parameter",
];

#[must_use]
pub fn is_noreturn_import_name(name: &str) -> bool {
    let trimmed: &str = name.strip_prefix("__imp_").unwrap_or(name);
    let trimmed: &str = trimmed.strip_prefix('_').unwrap_or(trimmed);
    NORETURN_IMPORT_NAMES.iter().any(|known: &&str| {
        let canon: &str = known.strip_prefix('_').unwrap_or(known);
        trimmed == *known || trimmed == canon
    })
}

#[must_use]
pub fn noreturn_import_seeds<'a, I>(named_targets: I) -> BTreeSet<u64>
where
    I: IntoIterator<Item = (&'a str, u64)>,
{
    named_targets
        .into_iter()
        .filter_map(|(name, address): (&'a str, u64)| {
            is_noreturn_import_name(name).then_some(address)
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JumpTableHit {
    pub instruction: u64,
    pub table_base: u64,
    pub entry_size: u32,
    pub targets: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredFunctions {
    pub starts: Vec<u64>,
    pub jump_tables: Vec<JumpTableHit>,
    pub unresolved: Vec<UnresolvedTarget>,
    pub from_seed: usize,
    pub from_prologue: usize,
    pub from_call_target: usize,
    pub from_jump_table: usize,
}

const MAX_DISCOVERY_FUNCTIONS: usize = 1 << 18;
const MAX_JUMP_TABLE_ENTRIES: usize = 1 << 12;
const MAX_DIRECT_CALL_SWEEP_OFFSETS: usize = 32 * 1024 * 1024;
const MAX_REL32_FORWARD_DISTANCE: u64 = (1_u64 << 31) - 1;
const MAX_REL32_BACKWARD_DISTANCE: u64 = 1_u64 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectCallTargetEvidence {
    pub(crate) decoded: usize,
    pub(crate) independent: usize,
    pub(crate) linear: usize,
    target_boundary: bool,
}

impl DirectCallTargetEvidence {
    #[must_use]
    pub(crate) const fn accepted(self) -> bool {
        self.independent > 1 && self.linear > 1 && self.target_boundary
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct DirectCallTargetAccumulator {
    decoded_calls: usize,
    independent_calls: usize,
    linear_calls: usize,
    target_boundary: bool,
    last_independent_end: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartOrigin {
    Seed,
    Prologue,
    CallTarget,
    JumpTable,
}

#[must_use]
pub fn discover_functions(input: &DiscoveryInput<'_>) -> DiscoveredFunctions {
    discover_functions_with_status(input).into_value()
}

#[must_use]
pub fn discover_functions_with_status(
    input: &DiscoveryInput<'_>,
) -> NoreturnInferenceOutcome<DiscoveredFunctions> {
    discover_functions_impl(input, false)
}

pub(crate) fn discover_functions_with_direct_call_sweep_status(
    input: &DiscoveryInput<'_>,
) -> NoreturnInferenceOutcome<DiscoveredFunctions> {
    discover_functions_impl(input, true)
}

fn discover_functions_impl(
    input: &DiscoveryInput<'_>,
    enable_direct_call_sweep: bool,
) -> NoreturnInferenceOutcome<DiscoveredFunctions> {
    let mut starts: BTreeMap<u64, StartOrigin> = BTreeMap::new();
    for seed in &input.seeds {
        if window_for(&input.code, *seed).is_some() {
            starts.entry(*seed).or_insert(StartOrigin::Seed);
        }
    }
    for window in &input.code {
        for candidate in scan_prologues(input.bitness, window) {
            starts.entry(candidate).or_insert(StartOrigin::Prologue);
        }
    }
    if enable_direct_call_sweep && matches!(input.bitness, Bitness::Bits64) {
        let swept_targets: BTreeMap<u64, usize> = direct_call_target_counts(input);
        for target in swept_targets.keys().copied() {
            if starts.len() >= MAX_DISCOVERY_FUNCTIONS {
                break;
            }
            starts.entry(target).or_insert(StartOrigin::CallTarget);
        }
    }

    let candidate_entries: BTreeSet<u64> = starts.keys().copied().collect();
    let inference: NoreturnInference =
        noreturn_closure(input, &candidate_entries, input.noreturn.clone());
    let termination: NoreturnInferenceTermination = inference.termination();
    let noreturn: BTreeSet<u64> = inference.into_known();

    let mut jump_tables: Vec<JumpTableHit> = Vec::new();
    let mut unresolved: Vec<UnresolvedTarget> = Vec::new();
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut queue: VecDeque<u64> = starts.keys().copied().collect::<VecDeque<u64>>();

    while let Some(address) = queue.pop_front() {
        if !visited.insert(address) {
            continue;
        }
        let Some(window): Option<&CodeWindow<'_>> = window_for(&input.code, address) else {
            continue;
        };
        traverse_function(
            input,
            window,
            address,
            &noreturn,
            &mut starts,
            &mut jump_tables,
            &mut unresolved,
            &mut queue,
        );
        if starts.len() >= MAX_DISCOVERY_FUNCTIONS {
            break;
        }
    }

    unresolved.sort_by(|a: &UnresolvedTarget, b: &UnresolvedTarget| {
        a.address.cmp(&b.address).then(a.mnemonic.cmp(&b.mnemonic))
    });
    unresolved.dedup();
    jump_tables.sort_by_key(|t: &JumpTableHit| t.instruction);
    jump_tables.dedup();

    let from_seed: usize = count_origin(&starts, StartOrigin::Seed);
    let from_prologue: usize = count_origin(&starts, StartOrigin::Prologue);
    let from_call_target: usize = count_origin(&starts, StartOrigin::CallTarget);
    let from_jump_table: usize = count_origin(&starts, StartOrigin::JumpTable);

    NoreturnInferenceOutcome::new(
        DiscoveredFunctions {
            starts: starts.keys().copied().collect(),
            jump_tables,
            unresolved,
            from_seed,
            from_prologue,
            from_call_target,
            from_jump_table,
        },
        termination,
    )
}

pub(crate) fn discover_aarch64_functions(
    code: &[CodeWindow<'_>],
    instructions: &[DisasmInstruction],
    seeds: &[u64],
) -> Option<DiscoveredFunctions> {
    let mut previous_end: Option<u64> = None;
    for window in code {
        if window.address % AARCH64_INSTRUCTION_BYTES as u64 != 0
            || window.bytes.len() % AARCH64_INSTRUCTION_BYTES != 0
        {
            return None;
        }
        let length: u64 = u64::try_from(window.bytes.len()).ok()?;
        let end: u64 = window.address.checked_add(length)?;
        if previous_end.is_some_and(|prior: u64| window.address < prior) {
            return None;
        }
        previous_end = Some(end);
    }

    let mut previous_address: Option<u64> = None;
    let mut window_index: usize = 0;
    for instruction in instructions {
        if instruction.offset % AARCH64_INSTRUCTION_BYTES as u64 != 0
            || instruction.bytes.len() != AARCH64_INSTRUCTION_BYTES
            || previous_address.is_some_and(|prior: u64| instruction.offset <= prior)
        {
            return None;
        }
        let instruction_end: u64 = instruction
            .offset
            .checked_add(AARCH64_INSTRUCTION_BYTES as u64)?;
        let window: &CodeWindow<'_> = loop {
            let candidate: &CodeWindow<'_> = code.get(window_index)?;
            let candidate_length: u64 = u64::try_from(candidate.bytes.len()).ok()?;
            let candidate_end: u64 = candidate.address.checked_add(candidate_length)?;
            if instruction.offset < candidate.address {
                return None;
            }
            if instruction.offset < candidate_end {
                break candidate;
            }
            window_index = window_index.checked_add(1)?;
        };
        let window_length: u64 = u64::try_from(window.bytes.len()).ok()?;
        let window_end: u64 = window.address.checked_add(window_length)?;
        if instruction_end > window_end {
            return None;
        }
        let relative_address: u64 = instruction.offset.checked_sub(window.address)?;
        let relative_offset: usize = usize::try_from(relative_address).ok()?;
        let relative_end: usize = relative_offset.checked_add(AARCH64_INSTRUCTION_BYTES)?;
        let expected: &[u8] = window.bytes.get(relative_offset..relative_end)?;
        if instruction.bytes.as_slice() != expected {
            return None;
        }
        previous_address = Some(instruction.offset);
    }

    let mut starts: BTreeMap<u64, StartOrigin> = BTreeMap::new();
    let mut pending: VecDeque<usize> = VecDeque::new();
    for seed in seeds {
        if starts.len() >= MAX_DISCOVERY_FUNCTIONS {
            break;
        }
        if seed % AARCH64_INSTRUCTION_BYTES as u64 != 0 {
            continue;
        }
        let Some(seed_index): Option<usize> = aarch64_instruction_index(instructions, *seed) else {
            continue;
        };
        if starts.insert(*seed, StartOrigin::Seed).is_none() {
            pending.push_back(seed_index);
        }
    }

    let mut visited: Vec<u8> = vec![0; instructions.len()];
    while !pending.is_empty() {
        let index: usize = pending.pop_front()?;
        let visited_entry: &mut u8 = visited.get_mut(index)?;
        if *visited_entry != 0 {
            continue;
        }
        *visited_entry = 1;
        let instruction: &DisasmInstruction = instructions.get(index)?;
        let address: u64 = instruction.offset;
        let raw: [u8; AARCH64_INSTRUCTION_BYTES] = instruction.bytes.as_slice().try_into().ok()?;
        let word: u32 = u32::from_le_bytes(raw);
        let next_address: Option<u64> = address.checked_add(AARCH64_INSTRUCTION_BYTES as u64);
        let fallthrough: Option<usize> = index.checked_add(1).filter(|next_index: &usize| {
            instructions
                .get(*next_index)
                .is_some_and(|next: &DisasmInstruction| Some(next.offset) == next_address)
        });
        match aarch64_direct_transfer(address, word) {
            Some(Aarch64DirectTransfer::BranchLink { target }) => {
                if target == address {
                    continue;
                }
                let target_index: Option<usize> = aarch64_instruction_index(instructions, target);
                if target_index.is_some()
                    && !starts.contains_key(&target)
                    && starts.len() < MAX_DISCOVERY_FUNCTIONS
                {
                    starts.insert(target, StartOrigin::CallTarget);
                    pending.extend(target_index);
                }
                pending.extend(fallthrough);
            }
            Some(Aarch64DirectTransfer::UnconditionalBranch { target }) => {
                let target_index: Option<usize> = aarch64_instruction_index(instructions, target);
                pending.extend(target_index);
            }
            Some(
                Aarch64DirectTransfer::ConditionalBranch { target, .. }
                | Aarch64DirectTransfer::CompareBranch { target }
                | Aarch64DirectTransfer::TestBranch { target },
            ) => {
                let target_index: Option<usize> = aarch64_instruction_index(instructions, target);
                pending.extend(target_index);
                pending.extend(fallthrough);
            }
            None => {
                if !aarch64_stops_traversal(&instruction.mnemonic) {
                    pending.extend(fallthrough);
                }
            }
        }
    }

    let from_seed: usize = count_origin(&starts, StartOrigin::Seed);
    let from_call_target: usize = count_origin(&starts, StartOrigin::CallTarget);
    Some(DiscoveredFunctions {
        starts: starts.keys().copied().collect(),
        jump_tables: Vec::new(),
        unresolved: Vec::new(),
        from_seed,
        from_prologue: 0,
        from_call_target,
        from_jump_table: 0,
    })
}

fn aarch64_instruction_index(instructions: &[DisasmInstruction], address: u64) -> Option<usize> {
    instructions
        .binary_search_by_key(&address, |instruction: &DisasmInstruction| {
            instruction.offset
        })
        .ok()
}

fn count_origin(starts: &BTreeMap<u64, StartOrigin>, origin: StartOrigin) -> usize {
    starts
        .values()
        .filter(|o: &&StartOrigin| **o == origin)
        .count()
}

fn window_for<'a, 'b>(code: &'b [CodeWindow<'a>], address: u64) -> Option<&'b CodeWindow<'a>> {
    code.iter().find(|w: &&CodeWindow<'a>| {
        let end: u64 = w.address.saturating_add(w.bytes.len() as u64);
        address >= w.address && address < end
    })
}

fn decode_input_instruction(input: &DiscoveryInput<'_>, address: u64) -> Option<Instruction> {
    let window: &CodeWindow<'_> = window_for(&input.code, address)?;
    let relative: u64 = address.checked_sub(window.address)?;
    let offset: usize = usize::try_from(relative).ok()?;
    let bytes: &[u8] = window.bytes.get(offset..)?;
    decode_one_x86(input.bitness.value(), address, bytes)
}

fn valid_code_windows(code: &[CodeWindow<'_>]) -> bool {
    let mut previous_end: Option<u64> = None;
    for window in code {
        let Ok(window_len): core::result::Result<u64, std::num::TryFromIntError> =
            u64::try_from(window.bytes.len())
        else {
            return false;
        };
        let Some(window_end): Option<u64> = window.address.checked_add(window_len) else {
            return false;
        };
        if previous_end.is_some_and(|end: u64| window.address < end) {
            return false;
        }
        previous_end = Some(window_end);
    }
    true
}

#[must_use]
fn direct_call_target_counts(input: &DiscoveryInput<'_>) -> BTreeMap<u64, usize> {
    direct_call_target_evidence(input)
        .into_iter()
        .filter_map(|(target, evidence): (u64, DirectCallTargetEvidence)| {
            evidence.accepted().then_some((target, evidence.decoded))
        })
        .collect()
}

#[must_use]
pub(crate) fn direct_call_target_evidence(
    input: &DiscoveryInput<'_>,
) -> BTreeMap<u64, DirectCallTargetEvidence> {
    sweep_direct_call_target_evidence(input, MAX_DIRECT_CALL_SWEEP_OFFSETS)
}

fn direct_call_target(
    input: &DiscoveryInput<'_>,
    address: u64,
    instruction: &Instruction,
) -> Option<(u64, u64)> {
    if instruction.code() != Code::Call_rel32_64
        || instruction.flow_control() != FlowControl::Call
        || !matches!(instruction.op0_kind(), OpKind::NearBranch64)
    {
        return None;
    }
    let instruction_len: u64 = u64::try_from(instruction.len()).ok()?;
    let instruction_end: u64 = address.checked_add(instruction_len)?;
    let target: u64 = instruction.near_branch_target();
    let rel32_in_range: bool = if target >= instruction_end {
        target
            .checked_sub(instruction_end)
            .is_some_and(|distance: u64| distance <= MAX_REL32_FORWARD_DISTANCE)
    } else {
        instruction_end
            .checked_sub(target)
            .is_some_and(|distance: u64| distance <= MAX_REL32_BACKWARD_DISTANCE)
    };
    if !rel32_in_range {
        return None;
    }
    if target >= address && target <= instruction_end {
        return None;
    }
    decode_input_instruction(input, target)?;
    Some((target, instruction_end))
}

fn sweep_direct_call_target_evidence(
    input: &DiscoveryInput<'_>,
    offset_limit: usize,
) -> BTreeMap<u64, DirectCallTargetEvidence> {
    if !matches!(input.bitness, Bitness::Bits64) || !valid_code_windows(&input.code) {
        return BTreeMap::new();
    }
    let mut targets: BTreeMap<u64, DirectCallTargetAccumulator> = BTreeMap::new();
    let mut remaining_offsets: usize = offset_limit;
    for window in &input.code {
        let scan_len: usize = window.bytes.len().min(remaining_offsets);
        for offset in 0..scan_len {
            let Ok(offset_address): core::result::Result<u64, std::num::TryFromIntError> =
                u64::try_from(offset)
            else {
                continue;
            };
            let Some(address): Option<u64> = window.address.checked_add(offset_address) else {
                continue;
            };
            let Some(bytes): Option<&[u8]> = window.bytes.get(offset..) else {
                continue;
            };
            let Some(instruction): Option<Instruction> =
                decode_one_x86(input.bitness.value(), address, bytes)
            else {
                continue;
            };
            let Some((target, instruction_end)): Option<(u64, u64)> =
                direct_call_target(input, address, &instruction)
            else {
                continue;
            };
            let accumulator: &mut DirectCallTargetAccumulator = targets.entry(target).or_default();
            accumulator.decoded_calls = accumulator.decoded_calls.saturating_add(1);
            if accumulator
                .last_independent_end
                .is_none_or(|end: u64| address >= end)
            {
                accumulator.independent_calls = accumulator.independent_calls.saturating_add(1);
                accumulator.last_independent_end = Some(instruction_end);
            }
            if targets.len() > MAX_DISCOVERY_FUNCTIONS {
                return BTreeMap::new();
            }
        }
        remaining_offsets = remaining_offsets.saturating_sub(scan_len);
        if remaining_offsets == 0 {
            break;
        }
    }
    add_linear_call_evidence(input, offset_limit, &mut targets);
    targets
        .into_iter()
        .map(
            |(target, accumulator): (u64, DirectCallTargetAccumulator)| {
                (
                    target,
                    DirectCallTargetEvidence {
                        decoded: accumulator.decoded_calls,
                        independent: accumulator.independent_calls,
                        linear: accumulator.linear_calls,
                        target_boundary: accumulator.target_boundary,
                    },
                )
            },
        )
        .collect()
}

fn add_linear_call_evidence(
    input: &DiscoveryInput<'_>,
    offset_limit: usize,
    targets: &mut BTreeMap<u64, DirectCallTargetAccumulator>,
) {
    let mut remaining_offsets: usize = offset_limit;
    for window in &input.code {
        let scan_len: usize = window.bytes.len().min(remaining_offsets);
        let mut offset: usize = 0;
        while offset < scan_len {
            let Ok(offset_address): core::result::Result<u64, std::num::TryFromIntError> =
                u64::try_from(offset)
            else {
                break;
            };
            let Some(address): Option<u64> = window.address.checked_add(offset_address) else {
                break;
            };
            let Some(bytes): Option<&[u8]> = window.bytes.get(offset..) else {
                break;
            };
            let Some(instruction): Option<Instruction> =
                decode_one_x86(input.bitness.value(), address, bytes)
            else {
                break;
            };
            record_linear_target(address, targets);
            record_linear_call(input, address, &instruction, targets);
            offset = offset.saturating_add(instruction.len());
        }
        remaining_offsets = remaining_offsets.saturating_sub(scan_len);
        if remaining_offsets == 0 {
            break;
        }
    }
}

fn record_linear_target(address: u64, targets: &mut BTreeMap<u64, DirectCallTargetAccumulator>) {
    let Some(accumulator): Option<&mut DirectCallTargetAccumulator> = targets.get_mut(&address)
    else {
        return;
    };
    accumulator.target_boundary = true;
}

fn record_linear_call(
    input: &DiscoveryInput<'_>,
    address: u64,
    instruction: &Instruction,
    targets: &mut BTreeMap<u64, DirectCallTargetAccumulator>,
) {
    let Some((target, _)): Option<(u64, u64)> = direct_call_target(input, address, instruction)
    else {
        return;
    };
    let Some(accumulator): Option<&mut DirectCallTargetAccumulator> = targets.get_mut(&target)
    else {
        return;
    };
    accumulator.linear_calls = accumulator.linear_calls.saturating_add(1);
}

fn rodata_slice<'a>(rodata: &[ReadOnlyWindow<'a>], address: u64, len: usize) -> Option<&'a [u8]> {
    for window in rodata {
        let end: u64 = window.address.saturating_add(window.bytes.len() as u64);
        if address >= window.address && address.saturating_add(len as u64) <= end {
            let offset: usize = (address - window.address) as usize;
            return window.bytes.get(offset..offset + len);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn traverse_function(
    input: &DiscoveryInput<'_>,
    window: &CodeWindow<'_>,
    entry: u64,
    noreturn: &BTreeSet<u64>,
    starts: &mut BTreeMap<u64, StartOrigin>,
    jump_tables: &mut Vec<JumpTableHit>,
    unresolved: &mut Vec<UnresolvedTarget>,
    queue: &mut VecDeque<u64>,
) {
    let base: u64 = window.address;
    let end_addr: u64 = base.saturating_add(window.bytes.len() as u64);
    let mut local: VecDeque<u64> = VecDeque::new();
    local.push_back(entry);
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut formatter: NasmFormatter = NasmFormatter::new();

    while let Some(address) = local.pop_front() {
        if address < base || address >= end_addr {
            continue;
        }
        if !seen.insert(address) {
            continue;
        }
        let offset: usize = (address - base) as usize;
        let mut decoder: Decoder<'_> = Decoder::with_ip(
            input.bitness.value(),
            &window.bytes[offset..],
            address,
            DecoderOptions::NONE,
        );
        if !decoder.can_decode() {
            continue;
        }
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            continue;
        }
        let insn_end: u64 = address.saturating_add(insn.len() as u64);
        if insn_end > end_addr {
            continue;
        }

        match insn.flow_control() {
            FlowControl::Next => {
                local.push_back(insn_end);
            }
            FlowControl::XbeginXabortXend => {
                let target: u64 = insn.near_branch_target();
                if target >= base && target < end_addr {
                    local.push_back(target);
                }
                local.push_back(insn_end);
            }
            FlowControl::Call => {
                let target: u64 = insn.near_branch_target();
                let direct: bool = matches!(
                    insn.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                );
                if direct {
                    record_call_target(input, target, starts, queue);
                }
                if !(direct && noreturn.contains(&target)) {
                    local.push_back(insn_end);
                }
            }
            FlowControl::ConditionalBranch => {
                let target: u64 = insn.near_branch_target();
                if target >= base && target < end_addr {
                    local.push_back(target);
                }
                local.push_back(insn_end);
            }
            FlowControl::UnconditionalBranch => {
                let target: u64 = insn.near_branch_target();
                if target >= base && target < end_addr {
                    local.push_back(target);
                }
            }
            FlowControl::IndirectBranch => {
                if let Some(hit) = resolve_jump_table(input, &insn, base, end_addr) {
                    for target in &hit.targets {
                        local.push_back(*target);
                    }
                    jump_tables.push(hit);
                } else {
                    unresolved.push(UnresolvedTarget {
                        address: insn.ip(),
                        kind: UnresolvedKind::IndirectBranch,
                        mnemonic: mnemonic_of(&mut formatter, &insn),
                    });
                }
            }
            FlowControl::IndirectCall => {
                unresolved.push(UnresolvedTarget {
                    address: insn.ip(),
                    kind: UnresolvedKind::IndirectCall,
                    mnemonic: mnemonic_of(&mut formatter, &insn),
                });
                local.push_back(insn_end);
            }
            FlowControl::Return => {}
            FlowControl::Interrupt => {
                local.push_back(insn_end);
            }
            FlowControl::Exception => {}
        }
    }
}

const MAX_NORETURN_ITERATIONS: usize = 64;
const MAX_NORETURN_DECODED_INSTRUCTIONS: usize = 262_144;

#[derive(Debug, Clone, PartialEq, Eq)]
enum NoreturnInference {
    Complete(BTreeSet<u64>),
    Exhausted {
        known: BTreeSet<u64>,
        termination: NoreturnInferenceTermination,
    },
}

impl NoreturnInference {
    const fn termination(&self) -> NoreturnInferenceTermination {
        match self {
            Self::Complete(_) => NoreturnInferenceTermination::Complete,
            Self::Exhausted { termination, .. } => *termination,
        }
    }

    fn into_known(self) -> BTreeSet<u64> {
        match self {
            Self::Complete(known) | Self::Exhausted { known, .. } => known,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NoreturnCandidates {
    Complete(BTreeSet<u64>),
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoreturnFunctionOutcome {
    Proven,
    Unproven,
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NoreturnInstructionBudget {
    remaining: usize,
}

impl NoreturnInstructionBudget {
    const fn new(limit: usize) -> Self {
        Self { remaining: limit }
    }

    fn consume(&mut self) -> bool {
        let Some(remaining): Option<usize> = self.remaining.checked_sub(1) else {
            return false;
        };
        self.remaining = remaining;
        true
    }
}

fn noreturn_closure(
    input: &DiscoveryInput<'_>,
    seed_candidates: &BTreeSet<u64>,
    seeds: BTreeSet<u64>,
) -> NoreturnInference {
    let mut budget: NoreturnInstructionBudget =
        NoreturnInstructionBudget::new(MAX_NORETURN_DECODED_INSTRUCTIONS);
    let mut candidates: BTreeSet<u64> = seed_candidates.clone();
    for window in &input.code {
        match direct_call_targets(input.bitness, window, &mut budget) {
            NoreturnCandidates::Complete(targets) => candidates.extend(targets),
            NoreturnCandidates::Exhausted => {
                return NoreturnInference::Exhausted {
                    known: seeds,
                    termination: NoreturnInferenceTermination::DecodedInstructionBudget,
                };
            }
        }
    }
    let mut known: BTreeSet<u64> = seeds;
    for _ in 0..MAX_NORETURN_ITERATIONS {
        let mut changed: bool = false;
        for entry in &candidates {
            if known.contains(entry) {
                continue;
            }
            if let Some(window) = window_for(&input.code, *entry) {
                match function_is_noreturn(input.bitness, window, *entry, &known, &mut budget) {
                    NoreturnFunctionOutcome::Proven => {
                        known.insert(*entry);
                        changed = true;
                    }
                    NoreturnFunctionOutcome::Unproven => {}
                    NoreturnFunctionOutcome::Exhausted => {
                        return NoreturnInference::Exhausted {
                            known,
                            termination: NoreturnInferenceTermination::DecodedInstructionBudget,
                        };
                    }
                }
            }
        }
        if !changed {
            return NoreturnInference::Complete(known);
        }
    }
    if candidates
        .iter()
        .any(|entry: &u64| !known.contains(entry) && window_for(&input.code, *entry).is_some())
    {
        NoreturnInference::Exhausted {
            known,
            termination: NoreturnInferenceTermination::IterationLimit,
        }
    } else {
        NoreturnInference::Complete(known)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepKind {
    Continue,
    Sink,
    Escape,
}

fn function_is_noreturn(
    bitness: Bitness,
    window: &CodeWindow<'_>,
    entry: u64,
    known: &BTreeSet<u64>,
    budget: &mut NoreturnInstructionBudget,
) -> NoreturnFunctionOutcome {
    let base: u64 = window.address;
    let end_addr: u64 = base.saturating_add(window.bytes.len() as u64);
    if entry < base || entry >= end_addr {
        return NoreturnFunctionOutcome::Unproven;
    }
    let mut local: VecDeque<u64> = VecDeque::new();
    local.push_back(entry);
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut saw_sink: bool = false;

    while let Some(address) = local.pop_front() {
        if address < base || address >= end_addr {
            return NoreturnFunctionOutcome::Unproven;
        }
        if !seen.insert(address) {
            continue;
        }
        if !budget.consume() {
            return NoreturnFunctionOutcome::Exhausted;
        }
        let offset: usize = (address - base) as usize;
        let mut decoder: Decoder<'_> = Decoder::with_ip(
            bitness.value(),
            &window.bytes[offset..],
            address,
            DecoderOptions::NONE,
        );
        if !decoder.can_decode() {
            return NoreturnFunctionOutcome::Unproven;
        }
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            return NoreturnFunctionOutcome::Unproven;
        }
        let insn_end: u64 = address.saturating_add(insn.len() as u64);
        if insn_end > end_addr {
            return NoreturnFunctionOutcome::Unproven;
        }
        match step_kind(&insn, insn_end, base, end_addr, known, &mut local) {
            StepKind::Continue => {}
            StepKind::Sink => saw_sink = true,
            StepKind::Escape => return NoreturnFunctionOutcome::Unproven,
        }
    }
    if saw_sink {
        NoreturnFunctionOutcome::Proven
    } else {
        NoreturnFunctionOutcome::Unproven
    }
}

fn step_kind(
    insn: &Instruction,
    insn_end: u64,
    base: u64,
    end_addr: u64,
    known: &BTreeSet<u64>,
    local: &mut VecDeque<u64>,
) -> StepKind {
    let in_range = |target: u64| target >= base && target < end_addr;
    if insn.code() == Code::Hlt {
        return StepKind::Escape;
    }
    match insn.flow_control() {
        FlowControl::Next => {
            local.push_back(insn_end);
            StepKind::Continue
        }
        FlowControl::Call => {
            let target: u64 = insn.near_branch_target();
            let direct: bool = matches!(
                insn.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            );
            if direct && known.contains(&target) {
                return StepKind::Sink;
            }
            local.push_back(insn_end);
            StepKind::Continue
        }
        FlowControl::ConditionalBranch => {
            let target: u64 = insn.near_branch_target();
            if !in_range(target) {
                return StepKind::Escape;
            }
            local.push_back(target);
            local.push_back(insn_end);
            StepKind::Continue
        }
        FlowControl::UnconditionalBranch => {
            let target: u64 = insn.near_branch_target();
            if !in_range(target) {
                return StepKind::Escape;
            }
            if target == insn.ip() {
                return StepKind::Sink;
            }
            local.push_back(target);
            StepKind::Continue
        }
        FlowControl::Return
        | FlowControl::IndirectBranch
        | FlowControl::IndirectCall
        | FlowControl::Interrupt
        | FlowControl::Exception
        | FlowControl::XbeginXabortXend => StepKind::Escape,
    }
}

fn direct_call_targets(
    bitness: Bitness,
    window: &CodeWindow<'_>,
    budget: &mut NoreturnInstructionBudget,
) -> NoreturnCandidates {
    let base: u64 = window.address;
    let end_addr: u64 = base.saturating_add(window.bytes.len() as u64);
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bitness.value(), window.bytes, base, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    while decoder.can_decode() {
        if !budget.consume() {
            return NoreturnCandidates::Exhausted;
        }
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            continue;
        }
        if insn.flow_control() == FlowControl::Call
            && matches!(
                insn.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        {
            let target: u64 = insn.near_branch_target();
            if target >= base && target < end_addr {
                targets.insert(target);
            }
        }
    }
    NoreturnCandidates::Complete(targets)
}

fn record_call_target(
    input: &DiscoveryInput<'_>,
    target: u64,
    starts: &mut BTreeMap<u64, StartOrigin>,
    queue: &mut VecDeque<u64>,
) {
    if window_for(&input.code, target).is_none() {
        return;
    }
    if starts.len() >= MAX_DISCOVERY_FUNCTIONS {
        return;
    }
    if let std::collections::btree_map::Entry::Vacant(slot) = starts.entry(target) {
        slot.insert(StartOrigin::CallTarget);
        queue.push_back(target);
    }
}

fn resolve_jump_table(
    input: &DiscoveryInput<'_>,
    insn: &Instruction,
    base: u64,
    end_addr: u64,
) -> Option<JumpTableHit> {
    if insn.op0_kind() != OpKind::Memory {
        return None;
    }
    if insn.memory_index() == Register::None {
        return None;
    }
    let scale: u32 = insn.memory_index_scale();
    if scale != 4 && scale != 8 {
        return None;
    }
    if insn.memory_base() != Register::None && !insn.is_ip_rel_memory_operand() {
        return None;
    }
    let table_base: u64 = insn.memory_displacement64();
    let mut targets: Vec<u64> = Vec::new();
    let mut index: usize = 0;
    while index < MAX_JUMP_TABLE_ENTRIES {
        let entry_addr: u64 = table_base.saturating_add((index as u64).wrapping_mul(scale as u64));
        let target: Option<u64> = match scale {
            8 => rodata_slice(&input.rodata, entry_addr, 8)
                .and_then(|raw: &[u8]| raw.try_into().ok())
                .map(u64::from_le_bytes),
            _ => rodata_slice(&input.rodata, entry_addr, 4)
                .and_then(|raw: &[u8]| raw.try_into().ok())
                .map(|b: [u8; 4]| u64::from(u32::from_le_bytes(b))),
        };
        let Some(target): Option<u64> = target else {
            break;
        };
        if target < base || target >= end_addr {
            break;
        }
        targets.push(target);
        index += 1;
    }
    if targets.is_empty() {
        return None;
    }
    targets.sort_unstable();
    targets.dedup();
    Some(JumpTableHit {
        instruction: insn.ip(),
        table_base,
        entry_size: scale,
        targets,
    })
}

fn mnemonic_of(formatter: &mut NasmFormatter, insn: &Instruction) -> String {
    let mut text: String = String::new();
    formatter.format(insn, &mut text);
    split_text(&text).0
}

fn scan_prologues(bitness: Bitness, window: &CodeWindow<'_>) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    let bytes: &[u8] = window.bytes;
    let len: usize = bytes.len();
    let mut i: usize = 0;
    while i < len {
        let addr: u64 = window.address.saturating_add(i as u64);
        if is_prologue_at(bitness, &bytes[i..]) {
            out.push(addr);
        }
        i += 1;
    }
    out
}

fn is_prologue_at(bitness: Bitness, bytes: &[u8]) -> bool {
    if starts_with_endbr64(bytes) {
        return true;
    }
    match bitness {
        Bitness::Bits64 => starts_with_push_rbp_mov_rbp_rsp64(bytes),
        Bitness::Bits32 => starts_with_push_ebp_mov_ebp_esp32(bytes),
    }
}

fn starts_with_endbr64(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0] == 0xF3 && bytes[1] == 0x0F && bytes[2] == 0x1E && bytes[3] == 0xFA
}

fn starts_with_push_rbp_mov_rbp_rsp64(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0] == 0x55 && bytes[1] == 0x48 && bytes[2] == 0x89 && bytes[3] == 0xE5
}

fn starts_with_push_ebp_mov_ebp_esp32(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x55 && bytes[1] == 0x89 && bytes[2] == 0xE5
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn aarch64_discovery_instruction(address: u64, mnemonic: &str, word: u32) -> DisasmInstruction {
        DisasmInstruction {
            offset: address,
            bytes: word.to_le_bytes().to_vec(),
            mnemonic: mnemonic.to_owned(),
            ..DisasmInstruction::default()
        }
    }

    #[test]
    fn jump_over_junk_byte_recovers_real_stream() {
        let bytes: [u8; 6] = [0xEB, 0x01, 0xE8, 0x90, 0xC3, 0xCC];
        let report: DesyncReport =
            resolve(Bitness::Bits64, 0x1000, &bytes, &[0x1000]).expect("resolve");
        let addresses: Vec<u64> = report
            .recovered
            .iter()
            .map(|insn: &RecoveredInsn| insn.address)
            .collect();
        assert!(addresses.contains(&0x1000), "jmp not recovered");
        assert!(addresses.contains(&0x1003), "nop after jump not recovered");
        assert!(addresses.contains(&0x1004), "ret not recovered");
        assert!(
            !addresses.contains(&0x1002),
            "junk byte 0xE8 was wrongly decoded as a real instruction start"
        );
        assert!(report.desync_detected());
        assert!(
            report
                .junk_ranges
                .iter()
                .any(|r: &ByteRange| r.start == 0x1002 && r.end == 0x1003),
            "junk byte at 0x1002 not flagged; ranges = {:?}",
            report.junk_ranges
        );
    }

    #[test]
    fn jump_over_junk_differs_from_linear_sweep() {
        let bytes: [u8; 6] = [0xEB, 0x01, 0xE8, 0x90, 0xC3, 0xCC];
        let report: DesyncReport = resolve(Bitness::Bits64, 0x0, &bytes, &[0x0]).expect("resolve");
        assert_ne!(
            report.linear_sweep_count, report.recursive_count,
            "linear sweep and recursive traversal should disagree on the desynced stream"
        );
    }

    #[test]
    fn clean_linear_code_has_no_desync() {
        let bytes: [u8; 4] = [0x90, 0x90, 0x90, 0xC3];
        let report: DesyncReport =
            resolve(Bitness::Bits64, 0x2000, &bytes, &[0x2000]).expect("resolve");
        assert_eq!(report.recovered.len(), 4);
        assert!(
            !report.desync_detected(),
            "clean code flagged as desync: {report:?}"
        );
        assert_eq!(report.recovered[0].mnemonic, "nop");
        assert_eq!(report.recovered[3].mnemonic, "ret");
    }

    #[test]
    fn overlapping_instruction_is_flagged() {
        let bytes: [u8; 4] = [0xEB, 0xFF, 0xC0, 0xC3];
        let report: DesyncReport =
            resolve(Bitness::Bits64, 0x3000, &bytes, &[0x3000]).expect("resolve");
        assert!(
            report.overlap_addresses.contains(&0x3001),
            "expected overlap at 0x3001 (jmp lands mid-instruction), got {:?}",
            report.overlap_addresses
        );
        assert!(report.desync_detected());
    }

    #[test]
    fn indirect_branch_is_flagged_not_guessed() {
        let bytes: [u8; 2] = [0xFF, 0xE0];
        let report: DesyncReport =
            resolve(Bitness::Bits64, 0x4000, &bytes, &[0x4000]).expect("resolve");
        assert!(
            report
                .unresolved
                .iter()
                .any(|t: &UnresolvedTarget| t.kind == UnresolvedKind::IndirectBranch),
            "jmp rax should be flagged as an indirect branch, got {:?}",
            report.unresolved
        );
    }

    #[test]
    fn entry_outside_range_is_rejected() {
        let bytes: [u8; 2] = [0x90, 0xC3];
        let err: Error =
            resolve(Bitness::Bits64, 0x1000, &bytes, &[0x9000]).expect_err("oob entry");
        assert!(matches!(err, Error::Disasm { .. }));
    }

    #[test]
    fn empty_input_is_rejected() {
        let err: Error = resolve(Bitness::Bits64, 0, &[], &[]).expect_err("empty");
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn discovery_recovers_call_targets_from_entry() {
        let code: [u8; 12] = [
            0xE8, 0x06, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0x55, 0x48, 0x89, 0xE5,
        ];
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: 0x1000,
                bytes: &code,
            }],
            rodata: Vec::new(),
            seeds: vec![0x1000],
            noreturn: BTreeSet::new(),
        };
        let out: DiscoveredFunctions = discover_functions(&input);
        assert!(out.starts.contains(&0x1000), "entry seed: {:?}", out.starts);
        assert!(
            out.starts.contains(&0x100B),
            "callee 0x100b not surfaced: {:?}",
            out.starts
        );
        assert!(out.from_call_target >= 1);
    }

    #[test]
    fn discovery_recovers_call_targets_from_unreachable_code() {
        let code: [u8; 27] = [
            0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0xC3,
            0xCC, 0xCC, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0x31, 0xC0, 0xC3,
        ];
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: 0x1000,
                bytes: &code,
            }],
            rodata: Vec::new(),
            seeds: vec![0x1000],
            noreturn: BTreeSet::new(),
        };
        let out: DiscoveredFunctions =
            discover_functions_with_direct_call_sweep_status(&input).into_value();
        assert_eq!(out.starts, vec![0x1000, 0x1018]);
        assert_eq!(out.from_seed, 1);
        assert_eq!(out.from_call_target, 1);
        assert_eq!(out.from_prologue, 0);
    }

    #[test]
    fn embedded_e8_is_not_accepted_as_an_independent_call() {
        let code: [u8; 9] = [0xC7, 0x45, 0xE8, 0x01, 0x00, 0x00, 0x00, 0x90, 0xC3];
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: 0x1000,
                bytes: &code,
            }],
            rodata: Vec::new(),
            seeds: vec![0x1000],
            noreturn: BTreeSet::new(),
        };
        let counts: BTreeMap<u64, usize> = direct_call_target_counts(&input);
        assert!(
            !counts.contains_key(&0x1008),
            "overlapping decodes of an embedded E8 are not independent call evidence: {counts:x?}"
        );
    }

    #[test]
    fn separate_embedded_e8_values_do_not_corroborate() {
        let code: [u8; 33] = [
            0xB8, 0xE8, 0x1A, 0x00, 0x00, 0x00, 0xC0, 0xB8, 0xE8, 0x13, 0x00, 0x00, 0x00, 0xC0,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0xC3,
        ];
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: 0x1000,
                bytes: &code,
            }],
            rodata: Vec::new(),
            seeds: Vec::new(),
            noreturn: BTreeSet::new(),
        };
        let counts: BTreeMap<u64, usize> = direct_call_target_counts(&input);
        assert!(
            !counts.contains_key(&0x1020),
            "separate immediates are not independent call evidence: {counts:x?}"
        );
    }

    #[test]
    fn calls_to_an_interior_decodable_byte_do_not_corroborate() {
        let code: [u8; 36] = [
            0xE8, 0x1B, 0x00, 0x00, 0x00, 0xE8, 0x16, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0xB8, 0xC3, 0x00, 0x00, 0x00,
        ];
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: 0x1000,
                bytes: &code,
            }],
            rodata: Vec::new(),
            seeds: Vec::new(),
            noreturn: BTreeSet::new(),
        };
        let counts: BTreeMap<u64, usize> = direct_call_target_counts(&input);
        assert!(
            !counts.contains_key(&0x1020),
            "an interior target byte is not a function boundary: {counts:x?}"
        );
    }

    #[test]
    fn call_sweep_accepts_a_cross_window_target() {
        let caller: [u8; 22] = [
            0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xE8, 0xF3, 0x0F, 0x00, 0x00, 0xC3,
            0xCC, 0xCC, 0xE8, 0xEB, 0x0F, 0x00, 0x00, 0xC3,
        ];
        let callee: [u8; 3] = [0x31, 0xC0, 0xC3];
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![
                CodeWindow {
                    address: 0x1000,
                    bytes: &caller,
                },
                CodeWindow {
                    address: 0x2000,
                    bytes: &callee,
                },
            ],
            rodata: Vec::new(),
            seeds: vec![0x1000],
            noreturn: BTreeSet::new(),
        };
        let discovered: DiscoveredFunctions =
            discover_functions_with_direct_call_sweep_status(&input).into_value();
        assert_eq!(discovered.starts, vec![0x1000, 0x2000]);
        assert_eq!(discovered.from_call_target, 1);
    }

    #[test]
    fn call_sweep_rejects_truncated_and_outside_targets() {
        let truncated_call: [u8; 5] = [0xC3, 0xCC, 0xE8, 0x00, 0x00];
        let truncated_target: [u8; 8] = [0xE8, 0x02, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0x0F];
        let outside_target: [u8; 6] = [0xE8, 0xFB, 0x0F, 0x00, 0x00, 0xC3];
        let cases: [&[u8]; 3] = [&truncated_call, &truncated_target, &outside_target];
        for code in cases {
            let input: DiscoveryInput<'_> = DiscoveryInput {
                bitness: Bitness::Bits64,
                code: vec![CodeWindow {
                    address: 0x1000,
                    bytes: code,
                }],
                rodata: Vec::new(),
                seeds: Vec::new(),
                noreturn: BTreeSet::new(),
            };
            let counts: BTreeMap<u64, DirectCallTargetEvidence> =
                direct_call_target_evidence(&input);
            assert!(
                counts.is_empty(),
                "invalid call evidence accepted: {counts:x?}"
            );
        }
    }

    #[test]
    fn call_sweep_rejects_invalid_window_layouts() {
        let first: [u8; 8] = [0xE8, 0x03, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC];
        let second: [u8; 2] = [0x90, 0xC3];
        let overlapping: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![
                CodeWindow {
                    address: 0x1000,
                    bytes: &first,
                },
                CodeWindow {
                    address: 0x1004,
                    bytes: &second,
                },
            ],
            rodata: Vec::new(),
            seeds: Vec::new(),
            noreturn: BTreeSet::new(),
        };
        let overflowing: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: u64::MAX - 1,
                bytes: &first,
            }],
            rodata: Vec::new(),
            seeds: Vec::new(),
            noreturn: BTreeSet::new(),
        };
        assert!(direct_call_target_counts(&overlapping).is_empty());
        assert!(direct_call_target_counts(&overflowing).is_empty());
    }

    #[test]
    fn call_sweep_obeys_the_offset_limit() {
        let code: [u8; 27] = [
            0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0xC3,
            0xCC, 0xCC, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0x31, 0xC0, 0xC3,
        ];
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: 0x1000,
                bytes: &code,
            }],
            rodata: Vec::new(),
            seeds: Vec::new(),
            noreturn: BTreeSet::new(),
        };
        let before_second_call: BTreeMap<u64, DirectCallTargetEvidence> =
            sweep_direct_call_target_evidence(&input, 16);
        let through_second_call: BTreeMap<u64, DirectCallTargetEvidence> =
            sweep_direct_call_target_evidence(&input, 17);
        let through_target: BTreeMap<u64, DirectCallTargetEvidence> =
            sweep_direct_call_target_evidence(&input, 25);
        assert!(
            before_second_call
                .get(&0x1018)
                .is_some_and(|evidence: &DirectCallTargetEvidence| !evidence.accepted())
        );
        assert!(through_second_call.get(&0x1018).is_some_and(
            |evidence: &DirectCallTargetEvidence| {
                evidence.independent > 1
                    && evidence.linear > 1
                    && !evidence.target_boundary
                    && !evidence.accepted()
            }
        ));
        assert!(
            through_target
                .get(&0x1018)
                .is_some_and(|evidence: &DirectCallTargetEvidence| evidence.accepted())
        );
    }

    #[test]
    fn call_sweep_rejects_wrapped_rel32_targets() {
        let low_target: [u8; 1] = [0xC3];
        let positive_wrap: [u8; 5] = [0xE8, 0x08, 0x00, 0x00, 0x00];
        let negative_wrap: [u8; 5] = [0xE8, 0xF8, 0xFF, 0xFF, 0xFF];
        let positive_input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![
                CodeWindow {
                    address: 0x4,
                    bytes: &low_target,
                },
                CodeWindow {
                    address: u64::MAX - 8,
                    bytes: &positive_wrap,
                },
            ],
            rodata: Vec::new(),
            seeds: Vec::new(),
            noreturn: BTreeSet::new(),
        };
        let negative_input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![
                CodeWindow {
                    address: 0,
                    bytes: &negative_wrap,
                },
                CodeWindow {
                    address: u64::MAX - 2,
                    bytes: &low_target,
                },
            ],
            rodata: Vec::new(),
            seeds: Vec::new(),
            noreturn: BTreeSet::new(),
        };
        assert!(direct_call_target_evidence(&positive_input).is_empty());
        assert!(direct_call_target_evidence(&negative_input).is_empty());
    }

    #[test]
    fn discovery_scans_prologues_without_seeds() {
        let code: [u8; 8] = [0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3, 0xCC, 0xCC];
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: 0x2000,
                bytes: &code,
            }],
            rodata: Vec::new(),
            seeds: Vec::new(),
            noreturn: BTreeSet::new(),
        };
        let out: DiscoveredFunctions = discover_functions(&input);
        assert!(
            out.starts.contains(&0x2000),
            "push rbp; mov rbp,rsp prologue not detected: {:?}",
            out.starts
        );
        assert!(out.from_prologue >= 1);
    }

    #[test]
    fn aarch64_discovery_accepts_forward_and_backward_bl_targets() {
        let words: [u32; 5] = [
            0x9400_0004,
            0xd65f_03c0,
            0xd65f_03c0,
            0xd503_201f,
            0x97ff_fffe,
        ];
        let code: Vec<u8> = words
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect();
        let windows: [CodeWindow<'_>; 1] = [CodeWindow {
            address: 0x1000,
            bytes: &code,
        }];
        let instructions: Vec<DisasmInstruction> = vec![
            aarch64_discovery_instruction(0x1000, "bl", words[0]),
            aarch64_discovery_instruction(0x1004, "ret", words[1]),
            aarch64_discovery_instruction(0x1008, "ret", words[2]),
            aarch64_discovery_instruction(0x100c, "nop", words[3]),
            aarch64_discovery_instruction(0x1010, "bl", words[4]),
        ];
        let discovered: DiscoveredFunctions =
            discover_aarch64_functions(&windows, &instructions, &[0x1000])
                .expect("aligned complete code");
        assert_eq!(discovered.starts, vec![0x1000, 0x1008, 0x1010]);
        assert_eq!(discovered.from_seed, 1);
        assert_eq!(discovered.from_call_target, 2);
        assert_eq!(discovered.from_prologue, 0);
        assert_eq!(discovered.from_jump_table, 0);
    }

    #[test]
    fn aarch64_discovery_requires_a_decoded_target_instruction() {
        let code: [u8; 8] = [0x01, 0x00, 0x00, 0x94, 0x1f, 0x20, 0x03, 0xd5];
        let windows: [CodeWindow<'_>; 1] = [CodeWindow {
            address: 0x2000,
            bytes: &code,
        }];
        let instructions: [DisasmInstruction; 1] =
            [aarch64_discovery_instruction(0x2000, "bl", 0x9400_0001)];
        let discovered: DiscoveredFunctions =
            discover_aarch64_functions(&windows, &instructions, &[0x2000])
                .expect("aligned complete code");
        assert_eq!(discovered.starts, vec![0x2000]);
        assert_eq!(discovered.from_call_target, 0);
    }

    #[test]
    fn aarch64_discovery_rejects_a_self_targeting_bl() {
        let code: [u8; 8] = [0x00, 0x00, 0x00, 0x94, 0x1f, 0x20, 0x03, 0xd5];
        let windows: [CodeWindow<'_>; 1] = [CodeWindow {
            address: 0x2800,
            bytes: &code,
        }];
        let instructions: [DisasmInstruction; 2] = [
            aarch64_discovery_instruction(0x2800, "bl", 0x9400_0000),
            aarch64_discovery_instruction(0x2804, "nop", 0xd503_201f),
        ];
        let discovered: DiscoveredFunctions =
            discover_aarch64_functions(&windows, &instructions, &[0x2800])
                .expect("aligned complete code");
        assert_eq!(discovered.starts, vec![0x2800]);
        assert_eq!(discovered.from_call_target, 0);
    }

    #[test]
    fn aarch64_discovery_refuses_misaligned_or_truncated_windows() {
        let complete: [u8; 4] = [0x00, 0x00, 0x00, 0x94];
        let misaligned: [CodeWindow<'_>; 1] = [CodeWindow {
            address: 0x3001,
            bytes: &complete,
        }];
        let truncated: [CodeWindow<'_>; 1] = [CodeWindow {
            address: 0x3000,
            bytes: &complete[..3],
        }];
        let instructions: [DisasmInstruction; 1] =
            [aarch64_discovery_instruction(0x3000, "bl", 0x9400_0000)];
        assert!(discover_aarch64_functions(&misaligned, &instructions, &[]).is_none());
        assert!(discover_aarch64_functions(&truncated, &instructions, &[]).is_none());
    }

    #[test]
    fn aarch64_discovery_refuses_overlapping_overflowing_or_duplicate_input() {
        let complete: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];
        let overlapping: [CodeWindow<'_>; 2] = [
            CodeWindow {
                address: 0x4000,
                bytes: &complete,
            },
            CodeWindow {
                address: 0x4000,
                bytes: &complete,
            },
        ];
        let overflowing: [CodeWindow<'_>; 1] = [CodeWindow {
            address: u64::MAX - 3,
            bytes: &complete,
        }];
        let ordinary: [CodeWindow<'_>; 1] = [CodeWindow {
            address: 0x4000,
            bytes: &complete,
        }];
        let ordinary_instruction: DisasmInstruction =
            aarch64_discovery_instruction(0x4000, "nop", 0xd503_201f);
        let overflowing_instruction: DisasmInstruction =
            aarch64_discovery_instruction(u64::MAX - 3, "nop", 0xd503_201f);
        let duplicate_instructions: [DisasmInstruction; 2] =
            [ordinary_instruction.clone(), ordinary_instruction.clone()];
        assert!(
            discover_aarch64_functions(
                &overlapping,
                std::slice::from_ref(&ordinary_instruction),
                &[]
            )
            .is_none()
        );
        assert!(
            discover_aarch64_functions(
                &overflowing,
                std::slice::from_ref(&overflowing_instruction),
                &[]
            )
            .is_none()
        );
        assert!(discover_aarch64_functions(&ordinary, &duplicate_instructions, &[]).is_none());
    }

    #[test]
    fn aarch64_discovery_accepts_cross_window_calls_and_valid_seeds() {
        let caller: [u8; 4] = 0x9400_0400_u32.to_le_bytes();
        let callee: [u8; 4] = 0xd65f_03c0_u32.to_le_bytes();
        let windows: [CodeWindow<'_>; 2] = [
            CodeWindow {
                address: 0x1000,
                bytes: &caller,
            },
            CodeWindow {
                address: 0x2000,
                bytes: &callee,
            },
        ];
        let instructions: [DisasmInstruction; 2] = [
            aarch64_discovery_instruction(0x1000, "bl", 0x9400_0400),
            aarch64_discovery_instruction(0x2000, "ret", 0xd65f_03c0),
        ];
        let discovered: DiscoveredFunctions =
            discover_aarch64_functions(&windows, &instructions, &[0x1000])
                .expect("aligned complete windows");
        assert_eq!(discovered.starts, vec![0x1000, 0x2000]);
        assert_eq!(discovered.from_seed, 1);
        assert_eq!(discovered.from_call_target, 1);
    }

    #[test]
    fn aarch64_discovery_ignores_unreachable_branch_link_words() {
        let words: [u32; 5] = [
            0x1400_0003,
            0x9400_0003,
            0xd503_201f,
            0xd65f_03c0,
            0xd65f_03c0,
        ];
        let code: Vec<u8> = words
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect();
        let windows: [CodeWindow<'_>; 1] = [CodeWindow {
            address: 0x1000,
            bytes: &code,
        }];
        let instructions: Vec<DisasmInstruction> = vec![
            aarch64_discovery_instruction(0x1000, "b", words[0]),
            aarch64_discovery_instruction(0x1004, "bl", words[1]),
            aarch64_discovery_instruction(0x1008, "nop", words[2]),
            aarch64_discovery_instruction(0x100c, "ret", words[3]),
            aarch64_discovery_instruction(0x1010, "ret", words[4]),
        ];
        let discovered: DiscoveredFunctions =
            discover_aarch64_functions(&windows, &instructions, &[0x1000])
                .expect("aligned complete code");

        assert_eq!(discovered.starts, vec![0x1000]);
        assert_eq!(discovered.from_seed, 1);
        assert_eq!(discovered.from_call_target, 0);
    }

    #[test]
    fn aarch64_discovery_reaches_calls_on_both_conditional_paths() {
        let words: [u32; 6] = [
            0x5400_0040,
            0x9400_0003,
            0x9400_0003,
            0xd65f_03c0,
            0xd65f_03c0,
            0xd65f_03c0,
        ];
        let code: Vec<u8> = words
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect();
        let windows: [CodeWindow<'_>; 1] = [CodeWindow {
            address: 0x1000,
            bytes: &code,
        }];
        let instructions: Vec<DisasmInstruction> = vec![
            aarch64_discovery_instruction(0x1000, "b.eq", words[0]),
            aarch64_discovery_instruction(0x1004, "bl", words[1]),
            aarch64_discovery_instruction(0x1008, "bl", words[2]),
            aarch64_discovery_instruction(0x100c, "ret", words[3]),
            aarch64_discovery_instruction(0x1010, "ret", words[4]),
            aarch64_discovery_instruction(0x1014, "ret", words[5]),
        ];
        let discovered: DiscoveredFunctions =
            discover_aarch64_functions(&windows, &instructions, &[0x1000])
                .expect("aligned complete code");

        assert_eq!(discovered.starts, vec![0x1000, 0x1010, 0x1014]);
        assert_eq!(discovered.from_seed, 1);
        assert_eq!(discovered.from_call_target, 2);
    }

    #[test]
    fn aarch64_discovery_stops_at_debug_returns() {
        let words: [u32; 4] = [0xd6bf_03e0, 0x9400_0002, 0xd503_201f, 0xd65f_03c0];
        let code: Vec<u8> = words
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect();
        let windows: [CodeWindow<'_>; 1] = [CodeWindow {
            address: 0x5000,
            bytes: &code,
        }];
        let instructions: Vec<DisasmInstruction> = vec![
            aarch64_discovery_instruction(0x5000, "drps", words[0]),
            aarch64_discovery_instruction(0x5004, "bl", words[1]),
            aarch64_discovery_instruction(0x5008, "nop", words[2]),
            aarch64_discovery_instruction(0x500c, "ret", words[3]),
        ];
        let discovered: DiscoveredFunctions =
            discover_aarch64_functions(&windows, &instructions, &[0x5000])
                .expect("aligned complete code");

        assert_eq!(discovered.starts, vec![0x5000]);
        assert_eq!(discovered.from_call_target, 0);
    }

    #[test]
    fn discovery_resolves_indexed_jump_table_from_rodata() {
        let mut code: Vec<u8> = vec![0xCC; 0x20];
        code[0x00] = 0x89;
        code[0x01] = 0xF8;
        code[0x02] = 0xFF;
        code[0x03] = 0x24;
        code[0x04] = 0xC5;
        code[0x05..0x09].copy_from_slice(&0x4000u32.to_le_bytes());
        code[0x10] = 0xC3;
        code[0x11] = 0xC3;
        let mut table: Vec<u8> = Vec::new();
        table.extend_from_slice(&0x3010u64.to_le_bytes());
        table.extend_from_slice(&0x3011u64.to_le_bytes());
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: 0x3000,
                bytes: &code,
            }],
            rodata: vec![ReadOnlyWindow {
                address: 0x4000,
                bytes: &table,
            }],
            seeds: vec![0x3000],
            noreturn: BTreeSet::new(),
        };
        let out: DiscoveredFunctions = discover_functions(&input);
        assert_eq!(out.jump_tables.len(), 1, "one jump table: {out:?}");
        let hit: &JumpTableHit = &out.jump_tables[0];
        assert_eq!(hit.table_base, 0x4000);
        assert_eq!(hit.entry_size, 8);
        assert_eq!(hit.targets, vec![0x3010, 0x3011]);
    }

    #[test]
    fn vmware_backdoor_handshake_is_detected() {
        let probe: [u8; 6] = [0xB8, 0x68, 0x58, 0x4D, 0x56, 0xED];
        let hits: Vec<VmwareBackdoorHit> = scan_vmware_backdoor(Bitness::Bits32, 0x1000, &probe);
        assert_eq!(
            hits.len(),
            1,
            "exact VMXh magic + in eax,dx must match once: {hits:?}"
        );
        assert_eq!(hits[0].mov_address, 0x1000);
        assert_eq!(hits[0].io_address, 0x1005);
    }

    #[test]
    fn vmware_magic_constant_without_port_in_is_not_a_hit() {
        let bytes: [u8; 6] = [0xB8, 0x68, 0x58, 0x4D, 0x56, 0x90];
        let hits: Vec<VmwareBackdoorHit> = scan_vmware_backdoor(Bitness::Bits32, 0x2000, &bytes);
        assert!(
            hits.is_empty(),
            "a bare VMXh magic load with a trailing nop (no in eax,dx) must not be a backdoor hit: {hits:?}"
        );
    }

    #[test]
    fn unrelated_immediate_with_port_in_is_not_a_hit() {
        let bytes: [u8; 6] = [0xB8, 0x78, 0x56, 0x34, 0x12, 0xED];
        let hits: Vec<VmwareBackdoorHit> = scan_vmware_backdoor(Bitness::Bits32, 0x3000, &bytes);
        assert!(
            hits.is_empty(),
            "mov eax, 0x12345678 ; in eax,dx must not be misread as the VMware backdoor: {hits:?}"
        );
    }

    #[test]
    fn discovery_flags_unresolved_indirect_call() {
        let code: [u8; 3] = [0xFF, 0xD0, 0xC3];
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: 0x5000,
                bytes: &code,
            }],
            rodata: Vec::new(),
            seeds: vec![0x5000],
            noreturn: BTreeSet::new(),
        };
        let out: DiscoveredFunctions = discover_functions(&input);
        assert!(
            out.unresolved
                .iter()
                .any(|t: &UnresolvedTarget| t.kind == UnresolvedKind::IndirectCall),
            "call rax must be flagged indirect: {:?}",
            out.unresolved
        );
    }

    const NORETURN_BASE: u64 = 0x1000;

    fn noreturn_fixture(callee: &[u8]) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0xE8, 0x04, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90];
        bytes.extend_from_slice(callee);
        bytes
    }

    fn noreturn_budget_fixture() -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0x90; 262_153];
        bytes[..5].copy_from_slice(&[0xE8, 0x0B, 0x00, 0x00, 0x00]);
        bytes[5] = 0xC3;
        bytes[6..11].copy_from_slice(&[0xE8, 0x0A, 0x00, 0x00, 0x00]);
        bytes[11] = 0xCC;
        bytes[16] = 0xCC;
        bytes[21] = 0xCC;
        bytes
    }

    fn noreturn_iteration_limit_fixture(count: usize) -> (Vec<u8>, Vec<u64>) {
        const FUNCTION_WIDTH: usize = 6;
        let mut bytes: Vec<u8> = Vec::with_capacity((count - 1) * FUNCTION_WIDTH + 1);
        let mut entries: Vec<u64> = Vec::with_capacity(count);
        for index in 0..count {
            entries.push(NORETURN_BASE + (index * FUNCTION_WIDTH) as u64);
            if index + 1 == count {
                bytes.extend_from_slice(&[0xEB, 0xFE]);
            } else {
                bytes.extend_from_slice(&[0xE8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
            }
        }
        (bytes, entries)
    }

    fn recovered_addresses(report: &DesyncReport) -> Vec<u64> {
        report
            .recovered
            .iter()
            .map(|insn: &RecoveredInsn| insn.address)
            .collect()
    }

    #[test]
    fn dead_bytes_after_self_loop_call_are_not_decoded() {
        let bytes: Vec<u8> = noreturn_fixture(&[0xEB, 0xFE]);
        let report: DesyncReport =
            resolve(Bitness::Bits64, NORETURN_BASE, &bytes, &[NORETURN_BASE]).expect("resolve");
        let addresses: Vec<u64> = recovered_addresses(&report);
        assert!(
            addresses.contains(&0x1000),
            "the call itself must be recovered: {addresses:x?}"
        );
        assert!(
            addresses.contains(&0x1009),
            "the self-looping noreturn callee must be recovered: {addresses:x?}"
        );
        for dead in 0x1005u64..0x1009 {
            assert!(
                !addresses.contains(&dead),
                "dead byte {dead:#x} after a proven-noreturn call must not be decoded as an instruction: {addresses:x?}"
            );
        }
        assert!(
            report
                .junk_ranges
                .iter()
                .any(|r: &ByteRange| r.start == 0x1005 && r.end == 0x1009),
            "the dead fallthrough region must be flagged junk: {:?}",
            report.junk_ranges
        );
    }

    #[test]
    fn resolve_status_reports_a_complete_noreturn_inference() {
        let bytes: Vec<u8> = noreturn_fixture(&[0xEB, 0xFE]);
        let outcome: NoreturnInferenceOutcome<DesyncReport> = resolve_with_noreturn_status(
            Bitness::Bits64,
            NORETURN_BASE,
            &bytes,
            &[NORETURN_BASE],
            &BTreeSet::new(),
        )
        .expect("resolve");
        assert_eq!(
            outcome.termination(),
            NoreturnInferenceTermination::Complete,
            "a converged no-return inference must report completion"
        );
    }

    #[test]
    fn returning_call_keeps_its_fallthrough() {
        let bytes: Vec<u8> = noreturn_fixture(&[0xC3]);
        let report: DesyncReport =
            resolve(Bitness::Bits64, NORETURN_BASE, &bytes, &[NORETURN_BASE]).expect("resolve");
        let addresses: Vec<u64> = recovered_addresses(&report);
        for live in 0x1005u64..0x1009 {
            assert!(
                addresses.contains(&live),
                "byte {live:#x} after a returning call is real fallthrough and must be decoded: {addresses:x?}"
            );
        }
        assert!(
            report.junk_ranges.is_empty(),
            "a returning callee leaves no dead fallthrough: {:?}",
            report.junk_ranges
        );
    }

    #[test]
    fn exception_and_interrupt_traps_keep_call_fallthrough() {
        let traps: [(&str, &[u8]); 4] = [
            ("int3", &[0xCC]),
            ("int1", &[0xF1]),
            ("ud2", &[0x0F, 0x0B]),
            ("hlt", &[0xF4]),
        ];
        for (name, trap) in traps {
            let bytes: Vec<u8> = noreturn_fixture(trap);
            let report: DesyncReport =
                resolve(Bitness::Bits64, NORETURN_BASE, &bytes, &[NORETURN_BASE]).expect("resolve");
            let addresses: Vec<u64> = recovered_addresses(&report);
            for live in 0x1005u64..0x1009 {
                assert!(
                    addresses.contains(&live),
                    "{name} may resume execution, so byte {live:#x} must remain fallthrough: {addresses:x?}"
                );
            }
            assert!(
                report.junk_ranges.is_empty(),
                "{name} must not turn call fallthrough into junk: {:?}",
                report.junk_ranges
            );
        }
    }

    #[test]
    fn traps_do_not_make_a_reachable_self_loop_noreturn() {
        let traps: [(&str, &[u8]); 4] = [
            ("int3", &[0xCC]),
            ("int1", &[0xF1]),
            ("ud2", &[0x0F, 0x0B]),
            ("hlt", &[0xF4]),
        ];
        let known: BTreeSet<u64> = BTreeSet::new();
        for (name, trap) in traps {
            let mut bytes: Vec<u8> = trap.to_vec();
            bytes.extend_from_slice(&[0xEB, 0xFE]);
            let window: CodeWindow<'_> = CodeWindow {
                address: NORETURN_BASE,
                bytes: &bytes,
            };
            let mut budget: NoreturnInstructionBudget = NoreturnInstructionBudget::new(8);
            let outcome: NoreturnFunctionOutcome =
                function_is_noreturn(Bitness::Bits64, &window, NORETURN_BASE, &known, &mut budget);
            assert_eq!(
                outcome,
                NoreturnFunctionOutcome::Unproven,
                "{name} may resume before the self-loop"
            );
        }
    }

    #[test]
    fn transactional_abort_fallback_prevents_noreturn_inference() {
        let bytes: [u8; 9] = [0xC7, 0xF8, 0x02, 0x00, 0x00, 0x00, 0xEB, 0xFE, 0xC3];
        let window: CodeWindow<'_> = CodeWindow {
            address: NORETURN_BASE,
            bytes: &bytes,
        };
        let known: BTreeSet<u64> = BTreeSet::new();
        let mut budget: NoreturnInstructionBudget = NoreturnInstructionBudget::new(8);
        let outcome: NoreturnFunctionOutcome =
            function_is_noreturn(Bitness::Bits64, &window, NORETURN_BASE, &known, &mut budget);
        assert_eq!(outcome, NoreturnFunctionOutcome::Unproven);
    }

    #[test]
    fn transactional_abort_fallback_is_recovered() {
        let bytes: [u8; 9] = [0xC7, 0xF8, 0x02, 0x00, 0x00, 0x00, 0xEB, 0xFE, 0xC3];
        let report: DesyncReport =
            resolve(Bitness::Bits64, NORETURN_BASE, &bytes, &[NORETURN_BASE]).expect("resolve");
        let addresses: Vec<u64> = recovered_addresses(&report);
        assert!(
            addresses.contains(&(NORETURN_BASE + 8)),
            "the XBEGIN abort fallback must remain reachable: {addresses:x?}"
        );
    }

    #[test]
    fn transactional_abort_handler_call_target_is_discovered() {
        let bytes: [u8; 17] = [
            0xC7, 0xF8, 0x02, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xC3,
            0xCC, 0xCC, 0xC3,
        ];
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: NORETURN_BASE,
                bytes: &bytes,
            }],
            rodata: Vec::new(),
            seeds: vec![NORETURN_BASE],
            noreturn: BTreeSet::new(),
        };
        let discovered: DiscoveredFunctions = discover_functions(&input);
        assert_eq!(discovered.starts, vec![NORETURN_BASE, NORETURN_BASE + 16]);
        assert_eq!(discovered.from_seed, 1);
        assert_eq!(discovered.from_call_target, 1);
        assert_eq!(discovered.from_prologue, 0);
        assert_eq!(discovered.from_jump_table, 0);
    }

    #[test]
    fn exhausted_noreturn_inference_preserves_unproven_fallthrough() {
        let bytes: Vec<u8> = noreturn_budget_fixture();
        let seeded_target: u64 = NORETURN_BASE + 21;
        let mut seeds: BTreeSet<u64> = BTreeSet::new();
        seeds.insert(seeded_target);
        let outcome: NoreturnInferenceOutcome<DesyncReport> = resolve_with_noreturn_status(
            Bitness::Bits64,
            NORETURN_BASE,
            &bytes,
            &[NORETURN_BASE, NORETURN_BASE + 6],
            &seeds,
        )
        .expect("resolve");
        assert_eq!(
            outcome.termination(),
            NoreturnInferenceTermination::DecodedInstructionBudget,
            "the status API must expose a bounded direct-call scan"
        );
        let report: DesyncReport = outcome.into_value();
        let addresses: Vec<u64> = recovered_addresses(&report);
        assert!(
            addresses.contains(&(NORETURN_BASE + 5)),
            "an unproven callee must retain its fallthrough when noreturn inference exhausts; recovered {} instruction starts",
            addresses.len()
        );
        assert!(
            !addresses.contains(&(NORETURN_BASE + 11)),
            "an explicitly seeded noreturn callee must still suppress its fallthrough; recovered {} instruction starts",
            addresses.len()
        );
    }

    #[test]
    fn function_is_noreturn_stops_when_its_budget_is_depleted() {
        let bytes: [u8; 2] = [0x90, 0xCC];
        let window: CodeWindow<'_> = CodeWindow {
            address: NORETURN_BASE,
            bytes: &bytes,
        };
        let known: BTreeSet<u64> = BTreeSet::new();
        let mut budget: NoreturnInstructionBudget = NoreturnInstructionBudget::new(0);
        let outcome: NoreturnFunctionOutcome =
            function_is_noreturn(Bitness::Bits64, &window, NORETURN_BASE, &known, &mut budget);
        assert_eq!(outcome, NoreturnFunctionOutcome::Exhausted);
    }

    #[test]
    fn function_walk_exhausts_just_below_the_default_budget() {
        assert!(
            MAX_NORETURN_DECODED_INSTRUCTIONS >= 262_144,
            "the default no-return inference budget must not fall below 262144 decoded instructions"
        );
        let bytes: Vec<u8> = vec![0x90; MAX_NORETURN_DECODED_INSTRUCTIONS - 1];
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: NORETURN_BASE,
                bytes: &bytes,
            }],
            rodata: Vec::new(),
            seeds: vec![NORETURN_BASE],
            noreturn: BTreeSet::new(),
        };
        let candidates: BTreeSet<u64> = BTreeSet::from([NORETURN_BASE]);
        let result: NoreturnInference = noreturn_closure(&input, &candidates, BTreeSet::new());
        assert!(
            matches!(result, NoreturnInference::Exhausted { ref known, termination: NoreturnInferenceTermination::DecodedInstructionBudget } if known.is_empty()),
            "the function walk must report exhaustion after the direct-call scan consumes all but one default-budget slot: {result:?}"
        );
    }

    #[test]
    fn noreturn_iteration_limit_reports_exhaustion_after_a_changed_final_pass() {
        let (bytes, entries): (Vec<u8>, Vec<u64>) = noreturn_iteration_limit_fixture(65);
        assert_eq!(
            MAX_NORETURN_ITERATIONS, 64,
            "the iteration-limit regression pins the 64/65 propagation boundary"
        );
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: NORETURN_BASE,
                bytes: &bytes,
            }],
            rodata: Vec::new(),
            seeds: Vec::new(),
            noreturn: BTreeSet::new(),
        };
        let candidates: BTreeSet<u64> = entries.iter().copied().collect();
        let result: NoreturnInference = noreturn_closure(&input, &candidates, BTreeSet::new());
        assert!(
            matches!(result, NoreturnInference::Exhausted { ref known, termination: NoreturnInferenceTermination::IterationLimit } if known.len() == MAX_NORETURN_ITERATIONS && !known.contains(&NORETURN_BASE)),
            "a changed final pass must report incomplete no-return inference: {result:?}"
        );
    }

    #[test]
    fn discovery_status_reports_the_noreturn_iteration_limit() {
        let (bytes, entries): (Vec<u8>, Vec<u64>) = noreturn_iteration_limit_fixture(65);
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: NORETURN_BASE,
                bytes: &bytes,
            }],
            rodata: Vec::new(),
            seeds: entries,
            noreturn: BTreeSet::new(),
        };
        let outcome: NoreturnInferenceOutcome<DiscoveredFunctions> =
            discover_functions_with_status(&input);
        assert_eq!(
            outcome.termination(),
            NoreturnInferenceTermination::IterationLimit,
            "function discovery must expose an incomplete no-return inference"
        );
    }

    #[test]
    fn direct_call_sweep_status_distinguishes_completed_and_bounded_inference() {
        let cases: [(usize, NoreturnInferenceTermination); 2] = [
            (64, NoreturnInferenceTermination::Complete),
            (65, NoreturnInferenceTermination::IterationLimit),
        ];
        for (count, expected) in cases {
            let (bytes, entries): (Vec<u8>, Vec<u64>) = noreturn_iteration_limit_fixture(count);
            let input: DiscoveryInput<'_> = DiscoveryInput {
                bitness: Bitness::Bits64,
                code: vec![CodeWindow {
                    address: NORETURN_BASE,
                    bytes: &bytes,
                }],
                rodata: Vec::new(),
                seeds: entries,
                noreturn: BTreeSet::new(),
            };
            let outcome: NoreturnInferenceOutcome<DiscoveredFunctions> =
                discover_functions_with_direct_call_sweep_status(&input);
            assert_eq!(
                outcome.termination(),
                expected,
                "direct call sweep status must preserve the {count}-node boundary"
            );
        }
    }

    #[test]
    fn resolve_status_reports_the_noreturn_iteration_limit() {
        let (bytes, entries): (Vec<u8>, Vec<u64>) = noreturn_iteration_limit_fixture(65);
        let outcome: NoreturnInferenceOutcome<DesyncReport> = resolve_with_noreturn_status(
            Bitness::Bits64,
            NORETURN_BASE,
            &bytes,
            &entries,
            &BTreeSet::new(),
        )
        .expect("resolve");
        assert_eq!(
            outcome.termination(),
            NoreturnInferenceTermination::IterationLimit,
            "resolution must expose an incomplete no-return inference"
        );
    }

    #[test]
    fn noreturn_iteration_limit_completes_when_the_final_pass_proves_every_candidate() {
        let (bytes, entries): (Vec<u8>, Vec<u64>) = noreturn_iteration_limit_fixture(64);
        assert_eq!(
            MAX_NORETURN_ITERATIONS, 64,
            "the iteration-limit regression pins the 64/65 propagation boundary"
        );
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code: vec![CodeWindow {
                address: NORETURN_BASE,
                bytes: &bytes,
            }],
            rodata: Vec::new(),
            seeds: Vec::new(),
            noreturn: BTreeSet::new(),
        };
        let candidates: BTreeSet<u64> = entries.iter().copied().collect();
        let result: NoreturnInference = noreturn_closure(&input, &candidates, BTreeSet::new());
        assert!(
            matches!(result, NoreturnInference::Complete(ref known) if known.len() == MAX_NORETURN_ITERATIONS && known.contains(&NORETURN_BASE)),
            "a final changed pass that proves every candidate must complete: {result:?}"
        );
    }

    #[test]
    fn import_seeded_noreturn_suppresses_fallthrough() {
        let bytes: [u8; 5] = [0xE8, 0x00, 0x00, 0x00, 0x00];
        let call_target: u64 = NORETURN_BASE + 5;
        let mut seeds: BTreeSet<u64> = BTreeSet::new();
        seeds.insert(call_target);
        let report: DesyncReport = resolve_with_noreturn(
            Bitness::Bits64,
            NORETURN_BASE,
            &bytes,
            &[NORETURN_BASE],
            &seeds,
        )
        .expect("resolve");
        let addresses: Vec<u64> = recovered_addresses(&report);
        assert_eq!(
            addresses,
            vec![NORETURN_BASE],
            "only the call to the import-seeded noreturn target is real; nothing falls through: {addresses:x?}"
        );
    }

    #[test]
    fn noreturn_import_name_recognition() {
        assert!(is_noreturn_import_name("ExitProcess"));
        assert!(is_noreturn_import_name("abort"));
        assert!(is_noreturn_import_name("_exit"));
        assert!(is_noreturn_import_name("__imp_ExitProcess"));
        assert!(is_noreturn_import_name("__stack_chk_fail"));
        assert!(!is_noreturn_import_name("printf"));
        assert!(!is_noreturn_import_name("CreateFileW"));
        let seeds: BTreeSet<u64> =
            noreturn_import_seeds([("printf", 0x10u64), ("ExitProcess", 0x20u64)]);
        assert_eq!(seeds, BTreeSet::from([0x20]));
    }

    #[test]
    fn self_loop_call_reaches_the_execution_cap_under_emulation() {
        use crate::stub_emu::cpu::{ExitReason, NoopHost};
        use crate::stub_emu::{Cpu, CpuMode, Perm, Reg};

        let bytes: Vec<u8> = noreturn_fixture(&[0xEB, 0xFE]);
        let mut image: Vec<u8> = vec![0x00; 0x1000];
        image.extend_from_slice(&bytes);
        let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
        cpu.mem.map(0, 0x2000, Perm::RWX).expect("map image");
        cpu.mem.write_unchecked(0, &image);
        cpu.regs.rip = NORETURN_BASE;
        cpu.regs.set(Reg::Rsp, 0x800);
        let mut host: NoopHost = NoopHost;
        let reason: ExitReason = cpu.run(&mut host, 4096).expect("emulate");
        assert!(
            matches!(reason, ExitReason::StepCap(_)),
            "a direct self-loop must consume the execution cap rather than return: {reason:?}"
        );
    }
}
