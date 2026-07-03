use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Formatter as _, Instruction, Mnemonic,
    NasmFormatter, OpKind, Register,
};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const VMWARE_BACKDOOR_MAGIC: u32 = 0x564D_5868;
const VMWARE_BACKDOOR_PORT: u16 = 0x5658;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmwareBackdoorHit {
    pub mov_address: u64,
    pub io_address: u64,
}

/// Scan a decoded x86 code window for the hypervisor backdoor handshake.
///
/// The signal is `mov eax, 0x564D5868` (the `VMXh` magic) directly followed by `in (e)ax, dx`
/// against the `0x5658` backdoor port. The two-instruction pair is a near-zero-false-positive
/// anti-analysis signal: the magic constant never appears as an immediate in normal code, and
/// pairing it with the privileged port-in guards against an incidental constant match.
///
/// The pair is matched on the linear instruction stream (decoder over `bytes` at `base`) so a
/// junk byte cannot wedge a false `in` between the magic load and the port read.
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
    let noreturn: BTreeSet<u64> =
        noreturn_closure(&inference_input, &candidates, noreturn_seeds.clone());

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

    Ok(DesyncReport {
        recursive_count: recovered.len(),
        recovered,
        unresolved,
        junk_ranges,
        overlap_addresses,
        linear_sweep_count: linear,
    })
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
        FlowControl::Next | FlowControl::XbeginXabortXend => {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartOrigin {
    Seed,
    Prologue,
    CallTarget,
    JumpTable,
}

#[must_use]
pub fn discover_functions(input: &DiscoveryInput<'_>) -> DiscoveredFunctions {
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

    let candidate_entries: BTreeSet<u64> = starts.keys().copied().collect();
    let noreturn: BTreeSet<u64> =
        noreturn_closure(input, &candidate_entries, input.noreturn.clone());

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

    DiscoveredFunctions {
        starts: starts.keys().copied().collect(),
        jump_tables,
        unresolved,
        from_seed,
        from_prologue,
        from_call_target,
        from_jump_table,
    }
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
            FlowControl::Next | FlowControl::XbeginXabortXend => {
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

fn noreturn_closure(
    input: &DiscoveryInput<'_>,
    seed_candidates: &BTreeSet<u64>,
    seeds: BTreeSet<u64>,
) -> BTreeSet<u64> {
    let mut candidates: BTreeSet<u64> = seed_candidates.clone();
    for window in &input.code {
        candidates.extend(direct_call_targets(input.bitness, window));
    }
    let mut known: BTreeSet<u64> = seeds;
    for _ in 0..MAX_NORETURN_ITERATIONS {
        let mut changed: bool = false;
        for entry in &candidates {
            if known.contains(entry) {
                continue;
            }
            if let Some(window) = window_for(&input.code, *entry)
                && function_is_noreturn(input.bitness, window, *entry, &known)
            {
                known.insert(*entry);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    known
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
) -> bool {
    let base: u64 = window.address;
    let end_addr: u64 = base.saturating_add(window.bytes.len() as u64);
    if entry < base || entry >= end_addr {
        return false;
    }
    let mut local: VecDeque<u64> = VecDeque::new();
    local.push_back(entry);
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut saw_sink: bool = false;

    while let Some(address) = local.pop_front() {
        if address < base || address >= end_addr {
            return false;
        }
        if !seen.insert(address) {
            continue;
        }
        let offset: usize = (address - base) as usize;
        let mut decoder: Decoder<'_> = Decoder::with_ip(
            bitness.value(),
            &window.bytes[offset..],
            address,
            DecoderOptions::NONE,
        );
        if !decoder.can_decode() {
            return false;
        }
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            return false;
        }
        let insn_end: u64 = address.saturating_add(insn.len() as u64);
        if insn_end > end_addr {
            return false;
        }
        match step_kind(&insn, insn_end, base, end_addr, known, &mut local) {
            StepKind::Continue => {}
            StepKind::Sink => saw_sink = true,
            StepKind::Escape => return false,
        }
    }
    saw_sink
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
    if is_noreturn_trap(insn) {
        return StepKind::Sink;
    }
    match insn.flow_control() {
        FlowControl::Next | FlowControl::XbeginXabortXend => {
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
            local.push_back(target);
            StepKind::Continue
        }
        FlowControl::Return
        | FlowControl::IndirectBranch
        | FlowControl::IndirectCall
        | FlowControl::Interrupt
        | FlowControl::Exception => StepKind::Escape,
    }
}

fn is_noreturn_trap(insn: &Instruction) -> bool {
    matches!(insn.code(), Code::Int3 | Code::Ud2 | Code::Hlt | Code::Int1)
}

fn direct_call_targets(bitness: Bitness, window: &CodeWindow<'_>) -> BTreeSet<u64> {
    let base: u64 = window.address;
    let end_addr: u64 = base.saturating_add(window.bytes.len() as u64);
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bitness.value(), window.bytes, base, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    while decoder.can_decode() {
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
    targets
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

    fn noreturn_fixture(callee_terminator: u8) -> [u8; 10] {
        [
            0xE8,
            0x04,
            0x00,
            0x00,
            0x00,
            0x90,
            0x90,
            0x90,
            0x90,
            callee_terminator,
        ]
    }

    fn recovered_addresses(report: &DesyncReport) -> Vec<u64> {
        report
            .recovered
            .iter()
            .map(|insn: &RecoveredInsn| insn.address)
            .collect()
    }

    #[test]
    fn dead_bytes_after_noreturn_call_are_not_decoded() {
        let bytes: [u8; 10] = noreturn_fixture(0xCC);
        let report: DesyncReport =
            resolve(Bitness::Bits64, NORETURN_BASE, &bytes, &[NORETURN_BASE]).expect("resolve");
        let addresses: Vec<u64> = recovered_addresses(&report);
        assert!(
            addresses.contains(&0x1000),
            "the call itself must be recovered: {addresses:x?}"
        );
        assert!(
            addresses.contains(&0x1009),
            "the int3-terminated noreturn callee must be recovered: {addresses:x?}"
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
    fn returning_call_keeps_its_fallthrough() {
        let bytes: [u8; 10] = noreturn_fixture(0xC3);
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
    fn noreturn_call_halts_under_emulation() {
        use crate::stub_emu::cpu::{ExitReason, NoopHost};
        use crate::stub_emu::{Cpu, CpuMode, Perm, Reg};

        let bytes: [u8; 10] = noreturn_fixture(0xCC);
        let mut image: Vec<u8> = vec![0x00; 0x1000];
        image.extend_from_slice(&bytes);
        let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
        cpu.mem.map(0, 0x2000, Perm::RWX).expect("map image");
        cpu.mem.write_unchecked(0, &image);
        cpu.regs.rip = NORETURN_BASE;
        cpu.regs.set(Reg::Rsp, 0x800);
        let mut host: NoopHost = NoopHost;
        let reason: ExitReason = cpu.run(&mut host, 4096).expect("emulate");
        let trapped_at_callee: bool = match reason {
            ExitReason::HostHalt(_)
            | ExitReason::JumpedOutOfRange { .. }
            | ExitReason::GuestFault(_) => true,
            ExitReason::UnsupportedInstr { ip, .. } => ip == 0x1009,
            _ => false,
        };
        assert!(
            trapped_at_callee,
            "emulation must reach the int3 at the noreturn callee (0x1009) and never fall through to 0x1005: {reason:?}"
        );
    }
}
