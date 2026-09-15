use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;

use disrobe_mba::cff::{
    BlockRole, CanaryViolation, CffAbstain, DegradeReason, DevirtEdge, DevirtNote, EdgeGuard,
    RecoveredCfg,
};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter as _, Instruction, Mnemonic, NasmFormatter,
    OpKind, Register,
};
use serde::{Deserialize, Serialize};

const MAX_INSNS: usize = 200_000;
const MAX_BLOCKS: usize = 8192;
const MIN_DISPATCH_PREDS: usize = 3;
const MAX_DISPATCH_TREE_STEPS: usize = 4096;
const MAX_REGION_STEPS: u32 = 4096;
const MAX_REGION_DEPTH: u32 = 128;
const MAX_RESOLVE_DEPTH: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StateLoc {
    Reg(u16),
    Mem { base: u16, disp: i64 },
}

impl StateLoc {
    fn from_dest(insn: &Instruction) -> Option<Self> {
        match insn.op0_kind() {
            OpKind::Register => Some(Self::Reg(insn.op0_register() as u16)),
            OpKind::Memory => Some(Self::Mem {
                base: insn.memory_base() as u16,
                disp: insn.memory_displacement64().cast_signed(),
            }),
            _ => None,
        }
    }

    fn from_src(insn: &Instruction) -> Option<Self> {
        match insn.op1_kind() {
            OpKind::Register => Some(Self::Reg(insn.op1_register() as u16)),
            OpKind::Memory => Some(Self::Mem {
                base: insn.memory_base() as u16,
                disp: insn.memory_displacement64().cast_signed(),
            }),
            _ => None,
        }
    }

    #[must_use]
    pub fn render(self) -> String {
        match self {
            Self::Reg(r) => format!("{:?}", register_from_u16(r)),
            Self::Mem { base, disp } => {
                format!("[{:?}{disp:+}]", register_from_u16(base))
            }
        }
    }
}

fn register_from_u16(value: u16) -> Register {
    Register::values()
        .find(|r: &Register| *r as u16 == value)
        .unwrap_or(Register::None)
}

#[derive(Debug, Clone)]
struct DecodedInsn {
    insn: Instruction,
    text: String,
}

#[derive(Debug, Clone)]
struct Block {
    start: u64,
    end: u64,
    insns: Vec<usize>,
}

#[derive(Debug)]
struct Program<'a> {
    decoded: Vec<DecodedInsn>,
    blocks: Vec<Block>,
    block_of_addr: BTreeMap<u64, usize>,
    base: u64,
    entry: u64,
    bytes: &'a [u8],
}

impl Program<'_> {
    fn read_u32(&self, addr: u64) -> Option<u32> {
        let offset: usize = addr.checked_sub(self.base)? as usize;
        let slice: &[u8] = self.bytes.get(offset..offset.checked_add(4)?)?;
        Some(u32::from_le_bytes(slice.try_into().ok()?))
    }

    fn read_u64(&self, addr: u64) -> Option<u64> {
        let offset: usize = addr.checked_sub(self.base)? as usize;
        let slice: &[u8] = self.bytes.get(offset..offset.checked_add(8)?)?;
        Some(u64::from_le_bytes(slice.try_into().ok()?))
    }

    fn end_addr(&self) -> u64 {
        self.base.saturating_add(self.bytes.len() as u64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockSpan {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRegion {
    pub state: u64,
    pub case_target: u64,
    pub blocks: Vec<BlockSpan>,
    pub successors: Vec<u64>,
    pub terminal: bool,
    pub degrade: Option<DegradeReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "gap")]
pub enum StateCoverGap {
    CaseTargetNotDecoded,
    UnreachedBehindUnresolvedTransition {
        at_state: u64,
        reason: DegradeReason,
    },
    UnreachedUnderResolvedTransitions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UncoveredState {
    pub state: u64,
    pub case_target: u64,
    pub gap: StateCoverGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateEdge {
    pub from: u64,
    pub to: u64,
    pub guard: EdgeGuard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatcherCover {
    pub dispatcher_states: u32,
    pub covered_states: u32,
    pub entry_states: Vec<u64>,
    pub covered: Vec<u64>,
    pub uncovered: Vec<UncoveredState>,
    pub edges: Vec<StateEdge>,
    pub regions: Vec<StateRegion>,
    pub prologue: Vec<BlockSpan>,
    pub canary: Option<CanaryViolation>,
}

impl DispatcherCover {
    #[must_use]
    pub fn covers_every_state(&self) -> bool {
        self.dispatcher_states > 0 && self.covered_states == self.dispatcher_states
    }

    #[must_use]
    pub fn unresolved_transitions(&self) -> Vec<&StateRegion> {
        self.regions
            .iter()
            .filter(|region: &&StateRegion| {
                region.degrade.is_some() && self.covered.contains(&region.state)
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CffRecovery {
    pub dispatcher_address: u64,
    pub state_loc: StateLoc,
    pub original_block_count: u32,
    pub recovered_block_count: u32,
    pub state_case_count: u32,
    pub linear_order: Vec<u64>,
    pub unresolved_blocks: Vec<u64>,
    pub fully_recovered: bool,
    pub cover: DispatcherCover,
    pub listing: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CffOutcome {
    NotFlattened,
    Abstained(CffAbstain),
    Recovered(Box<CffRecovery>),
}

#[must_use]
pub fn unflatten(bitness: u32, base: u64, bytes: &[u8], entry: u64) -> CffOutcome {
    let Some(program): Option<Program<'_>> = build_program(bitness, base, bytes, entry) else {
        return CffOutcome::NotFlattened;
    };
    let Some(dispatcher): Option<DispatcherModel> = find_dispatcher(&program) else {
        return CffOutcome::NotFlattened;
    };
    recover(&program, &dispatcher)
}

#[must_use]
pub fn detect_flattening(bytes: &[u8]) -> bool {
    const BASE: u64 = 0x1000;
    for bitness in [64u32, 32u32] {
        if let Some(program) = build_program(bitness, BASE, bytes, BASE)
            && find_dispatcher(&program).is_some()
        {
            return true;
        }
    }
    false
}

fn build_program(bitness: u32, base: u64, bytes: &[u8], entry: u64) -> Option<Program<'_>> {
    if bytes.is_empty() || entry < base {
        return None;
    }
    let end_addr: u64 = base.saturating_add(bytes.len() as u64);
    if entry >= end_addr {
        return None;
    }
    let decoded: Vec<DecodedInsn> = recursive_decode(bitness, base, bytes, entry, end_addr)?;
    if decoded.is_empty() || decoded.len() > MAX_INSNS {
        return None;
    }
    let leaders: BTreeSet<u64> = collect_leaders(&decoded, base, bytes, end_addr, entry);
    let (blocks, block_of_addr): (Vec<Block>, BTreeMap<u64, usize>) =
        carve_blocks(&decoded, &leaders)?;
    Some(Program {
        decoded,
        blocks,
        block_of_addr,
        base,
        entry,
        bytes,
    })
}

fn recursive_decode(
    bitness: u32,
    base: u64,
    bytes: &[u8],
    entry: u64,
    end_addr: u64,
) -> Option<Vec<DecodedInsn>> {
    let mut found: BTreeMap<u64, DecodedInsn> = BTreeMap::new();
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut queue: VecDeque<u64> = VecDeque::new();
    let mut formatter: NasmFormatter = NasmFormatter::new();
    queue.push_back(entry);
    while let Some(addr) = queue.pop_front() {
        if addr < base || addr >= end_addr || !visited.insert(addr) {
            continue;
        }
        if found.len() > MAX_INSNS {
            return None;
        }
        let offset: usize = (addr - base) as usize;
        let mut decoder: Decoder<'_> =
            Decoder::with_ip(bitness, &bytes[offset..], addr, DecoderOptions::NONE);
        if !decoder.can_decode() {
            continue;
        }
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            continue;
        }
        let insn_end: u64 = addr.saturating_add(insn.len() as u64);
        if insn_end > end_addr {
            continue;
        }
        let mut text: String = String::new();
        formatter.format(&insn, &mut text);
        enqueue_targets(&insn, insn_end, base, end_addr, &mut queue);
        enqueue_jump_table_targets(&insn, base, bytes, end_addr, &mut queue);
        found.insert(addr, DecodedInsn { insn, text });
    }
    Some(found.into_values().collect())
}

fn enqueue_jump_table_targets(
    insn: &Instruction,
    base: u64,
    bytes: &[u8],
    end_addr: u64,
    queue: &mut VecDeque<u64>,
) {
    if insn.flow_control() != FlowControl::IndirectBranch || insn.op0_kind() != OpKind::Memory {
        return;
    }
    if insn.memory_index() == Register::None {
        return;
    }
    let scale: u32 = insn.memory_index_scale();
    if scale != 4 && scale != 8 {
        return;
    }
    if insn.memory_base() != Register::None && !insn.is_ip_rel_memory_operand() {
        return;
    }
    let table_base: u64 = insn.memory_displacement64();
    let mut index: u64 = 0;
    while index < MAX_DISPATCH_TREE_STEPS as u64 {
        let entry_addr: u64 = table_base.saturating_add(index.wrapping_mul(u64::from(scale)));
        let Some(offset): Option<u64> = entry_addr.checked_sub(base) else {
            break;
        };
        let offset: usize = offset as usize;
        let target: Option<u64> = match scale {
            8 => bytes
                .get(offset..offset.saturating_add(8))
                .and_then(|raw: &[u8]| raw.try_into().ok())
                .map(u64::from_le_bytes),
            _ => bytes
                .get(offset..offset.saturating_add(4))
                .and_then(|raw: &[u8]| raw.try_into().ok())
                .map(|b: [u8; 4]| u64::from(u32::from_le_bytes(b))),
        };
        let Some(target): Option<u64> = target else {
            break;
        };
        if target < base || target >= end_addr {
            break;
        }
        queue.push_back(target);
        index += 1;
    }
}

fn enqueue_targets(
    insn: &Instruction,
    fallthrough: u64,
    base: u64,
    end_addr: u64,
    queue: &mut VecDeque<u64>,
) {
    let in_range = |t: u64| t >= base && t < end_addr;
    match insn.flow_control() {
        FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
            if in_range(fallthrough) {
                queue.push_back(fallthrough);
            }
            if matches!(insn.flow_control(), FlowControl::Call) {
                let target: u64 = insn.near_branch_target();
                if in_range(target) {
                    queue.push_back(target);
                }
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
        FlowControl::IndirectBranch
        | FlowControl::Return
        | FlowControl::Interrupt
        | FlowControl::Exception
        | FlowControl::XbeginXabortXend => {}
    }
}

fn collect_leaders(
    decoded: &[DecodedInsn],
    base: u64,
    bytes: &[u8],
    end_addr: u64,
    entry: u64,
) -> BTreeSet<u64> {
    let in_range = |t: u64| t >= base && t < end_addr;
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    if let Some(first) = decoded.first() {
        leaders.insert(first.insn.ip());
    }
    if in_range(entry) {
        leaders.insert(entry);
    }
    for d in decoded {
        let insn: &Instruction = &d.insn;
        let insn_end: u64 = insn.ip().saturating_add(insn.len() as u64);
        match insn.flow_control() {
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                let target: u64 = insn.near_branch_target();
                if in_range(target) {
                    leaders.insert(target);
                }
                if in_range(insn_end) {
                    leaders.insert(insn_end);
                }
            }
            FlowControl::Return if in_range(insn_end) => {
                leaders.insert(insn_end);
            }
            FlowControl::IndirectBranch => {
                if in_range(insn_end) {
                    leaders.insert(insn_end);
                }
                let mut table_targets: VecDeque<u64> = VecDeque::new();
                enqueue_jump_table_targets(insn, base, bytes, end_addr, &mut table_targets);
                for target in table_targets {
                    leaders.insert(target);
                }
            }
            _ => {}
        }
    }
    leaders
}

fn carve_blocks(
    decoded: &[DecodedInsn],
    leaders: &BTreeSet<u64>,
) -> Option<(Vec<Block>, BTreeMap<u64, usize>)> {
    let mut blocks: Vec<Block> = Vec::new();
    let mut block_of_addr: BTreeMap<u64, usize> = BTreeMap::new();
    let mut current: Option<Block> = None;
    for (idx, d) in decoded.iter().enumerate() {
        let addr: u64 = d.insn.ip();
        let insn_end: u64 = addr.saturating_add(d.insn.len() as u64);
        if leaders.contains(&addr) || current.is_none() {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            if blocks.len() >= MAX_BLOCKS {
                return None;
            }
            block_of_addr.insert(addr, blocks.len());
            current = Some(Block {
                start: addr,
                end: insn_end,
                insns: Vec::new(),
            });
        }
        if let Some(block) = current.as_mut() {
            block.insns.push(idx);
            block.end = insn_end;
        }
        if ends_block(&d.insn)
            && let Some(block) = current.take()
        {
            blocks.push(block);
        }
    }
    if let Some(block) = current.take() {
        blocks.push(block);
    }
    Some((blocks, block_of_addr))
}

fn ends_block(insn: &Instruction) -> bool {
    matches!(
        insn.flow_control(),
        FlowControl::ConditionalBranch
            | FlowControl::UnconditionalBranch
            | FlowControl::Return
            | FlowControl::IndirectBranch
    )
}

#[derive(Debug)]
struct DispatcherModel {
    block_index: usize,
    address: u64,
    state_loc: StateLoc,
    case_targets: BTreeMap<u64, u64>,
}

fn find_dispatcher(program: &Program<'_>) -> Option<DispatcherModel> {
    let predecessors: BTreeMap<usize, usize> = count_predecessors(program);
    let mut best: Option<DispatcherModel> = None;
    let mut best_cases: usize = 0;
    for (block_index, block) in program.blocks.iter().enumerate() {
        let preds: usize = predecessors.get(&block_index).copied().unwrap_or(0);
        if preds < MIN_DISPATCH_PREDS {
            continue;
        }
        let model: Option<DispatcherModel> = model_compare_tree(program, block_index, block)
            .or_else(|| model_jump_table(program, block_index, block));
        let Some(model): Option<DispatcherModel> = model else {
            continue;
        };
        if model.case_targets.len() > best_cases {
            best_cases = model.case_targets.len();
            best = Some(model);
        }
    }
    best.filter(|m: &DispatcherModel| m.case_targets.len() >= 2)
}

fn model_compare_tree(
    program: &Program<'_>,
    block_index: usize,
    block: &Block,
) -> Option<DispatcherModel> {
    let mut case_targets: BTreeMap<u64, u64> = BTreeMap::new();
    let mut state_loc: Option<StateLoc> = None;
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut stack: Vec<usize> = vec![block_index];
    let mut steps: usize = 0;
    while let Some(current_index) = stack.pop() {
        steps += 1;
        if steps > MAX_DISPATCH_TREE_STEPS {
            return None;
        }
        if !visited.insert(current_index) {
            continue;
        }
        let Some(current): Option<&Block> = program.blocks.get(current_index) else {
            continue;
        };
        let Some(step): Option<CompareStep> = match_tree_compare_step(program, current) else {
            continue;
        };
        match state_loc {
            Some(existing) if existing != step.loc => return None,
            _ => state_loc = Some(step.loc),
        }
        match step.kind {
            CompareKind::Equality {
                value,
                case,
                continue_block,
            } => {
                case_targets.entry(value).or_insert(case);
                if let Some(&next) = program.block_of_addr.get(&continue_block) {
                    stack.push(next);
                }
            }
            CompareKind::Ordering { taken, fallthrough } => {
                if let Some(&t) = program.block_of_addr.get(&taken) {
                    stack.push(t);
                }
                if let Some(&f) = program.block_of_addr.get(&fallthrough) {
                    stack.push(f);
                }
            }
        }
    }
    let loc: StateLoc = state_loc?;
    if case_targets.len() < 2 {
        return None;
    }
    Some(DispatcherModel {
        block_index,
        address: block.start,
        state_loc: loc,
        case_targets,
    })
}

fn model_jump_table(
    program: &Program<'_>,
    block_index: usize,
    block: &Block,
) -> Option<DispatcherModel> {
    let last_idx: usize = *block.insns.last()?;
    let insn: &Instruction = &program.decoded.get(last_idx)?.insn;
    if insn.flow_control() != FlowControl::IndirectBranch {
        return None;
    }
    if insn.op0_kind() != OpKind::Memory {
        return None;
    }
    let index_reg: Register = insn.memory_index();
    if index_reg == Register::None {
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
    let end_addr: u64 = program.end_addr();
    let mut case_targets: BTreeMap<u64, u64> = BTreeMap::new();
    let mut value: u64 = 0;
    while value < MAX_DISPATCH_TREE_STEPS as u64 {
        let entry_addr: u64 = table_base.saturating_add(value.wrapping_mul(u64::from(scale)));
        let target: Option<u64> = match scale {
            8 => program.read_u64(entry_addr),
            _ => program.read_u32(entry_addr).map(u64::from),
        };
        let Some(target): Option<u64> = target else {
            break;
        };
        if target < program.base || target >= end_addr {
            break;
        }
        if !program.block_of_addr.contains_key(&target) {
            break;
        }
        case_targets.insert(value, target);
        value += 1;
    }
    if case_targets.len() < 2 {
        return None;
    }
    Some(DispatcherModel {
        block_index,
        address: block.start,
        state_loc: StateLoc::Reg(index_reg.full_register() as u16),
        case_targets,
    })
}

struct CompareStep {
    loc: StateLoc,
    kind: CompareKind,
}

enum CompareKind {
    Equality {
        value: u64,
        case: u64,
        continue_block: u64,
    },
    Ordering {
        taken: u64,
        fallthrough: u64,
    },
}

fn match_tree_compare_step(program: &Program<'_>, block: &Block) -> Option<CompareStep> {
    let insns: &[usize] = &block.insns;
    if insns.len() < 2 {
        return None;
    }
    let last: &Instruction = &program.decoded.get(*insns.last()?)?.insn;
    if last.flow_control() != FlowControl::ConditionalBranch {
        return None;
    }
    let cmp: &Instruction = &program.decoded.get(*insns.get(insns.len() - 2)?)?.insn;
    if cmp.mnemonic() != Mnemonic::Cmp {
        return None;
    }
    let loc: StateLoc = StateLoc::from_dest(cmp)?;
    let value: u64 = immediate_value(cmp, 1)?;
    let taken: u64 = last.near_branch_target();
    let fallthrough: u64 = block.end;
    let kind: CompareKind = match last.mnemonic() {
        Mnemonic::Je => CompareKind::Equality {
            value,
            case: taken,
            continue_block: fallthrough,
        },
        Mnemonic::Jne => CompareKind::Equality {
            value,
            case: fallthrough,
            continue_block: taken,
        },
        m if is_ordering_branch(m) => CompareKind::Ordering { taken, fallthrough },
        _ => return None,
    };
    Some(CompareStep { loc, kind })
}

const fn is_ordering_branch(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
    )
}

fn count_predecessors(program: &Program<'_>) -> BTreeMap<usize, usize> {
    let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
    for block in &program.blocks {
        for succ in block_successors(program, block) {
            if let Some(target_block) = program.block_of_addr.get(&succ) {
                *counts.entry(*target_block).or_insert(0) += 1;
            }
        }
    }
    counts
}

fn block_successors(program: &Program<'_>, block: &Block) -> Vec<u64> {
    let Some(last_idx): Option<&usize> = block.insns.last() else {
        return Vec::new();
    };
    let Some(decoded): Option<&DecodedInsn> = program.decoded.get(*last_idx) else {
        return Vec::new();
    };
    let insn: &Instruction = &decoded.insn;
    let insn_end: u64 = block.end;
    match insn.flow_control() {
        FlowControl::UnconditionalBranch => vec![insn.near_branch_target()],
        FlowControl::ConditionalBranch => vec![insn.near_branch_target(), insn_end],
        FlowControl::Return | FlowControl::IndirectBranch => Vec::new(),
        _ => {
            if program.block_of_addr.contains_key(&insn_end) {
                vec![insn_end]
            } else {
                Vec::new()
            }
        }
    }
}

fn immediate_value(insn: &Instruction, operand: u32) -> Option<u64> {
    match insn.op_kind(operand) {
        OpKind::Immediate8 => Some(u64::from(insn.immediate8())),
        OpKind::Immediate16 => Some(u64::from(insn.immediate16())),
        OpKind::Immediate32 => Some(u64::from(insn.immediate32())),
        OpKind::Immediate64 => Some(insn.immediate64()),
        OpKind::Immediate8to16 => Some(insn.immediate8to16().cast_unsigned().into()),
        OpKind::Immediate8to32 => Some(insn.immediate8to32().cast_unsigned().into()),
        OpKind::Immediate8to64 => Some(insn.immediate8to64().cast_unsigned()),
        OpKind::Immediate32to64 => Some(insn.immediate32to64().cast_unsigned()),
        _ => None,
    }
}

const fn reads_without_writing_first_operand(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Push
            | Mnemonic::Bt
            | Mnemonic::Jmp
            | Mnemonic::Call
            | Mnemonic::Nop
    )
}

fn definition_target(insn: &Instruction) -> Option<StateLoc> {
    if reads_without_writing_first_operand(insn.mnemonic()) {
        return None;
    }
    StateLoc::from_dest(insn)
}

fn defines(insn: &Instruction, loc: StateLoc) -> bool {
    definition_target(insn) == Some(loc)
}

const fn is_cmov(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Cmove
            | Mnemonic::Cmovne
            | Mnemonic::Cmovl
            | Mnemonic::Cmovle
            | Mnemonic::Cmovg
            | Mnemonic::Cmovge
            | Mnemonic::Cmovb
            | Mnemonic::Cmovbe
            | Mnemonic::Cmova
            | Mnemonic::Cmovae
            | Mnemonic::Cmovs
            | Mnemonic::Cmovns
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateValue {
    Unknown,
    Const(u64),
    Select { taken: u64, fallthrough: u64 },
}

fn unique_constants(program: &Program<'_>) -> BTreeMap<StateLoc, u64> {
    let mut sightings: BTreeMap<StateLoc, (u32, Option<u64>)> = BTreeMap::new();
    for decoded in &program.decoded {
        let Some(loc): Option<StateLoc> = definition_target(&decoded.insn) else {
            continue;
        };
        let slot: &mut (u32, Option<u64>) = sightings.entry(loc).or_insert((0, None));
        slot.0 = slot.0.saturating_add(1);
        slot.1 = if decoded.insn.mnemonic() == Mnemonic::Mov {
            immediate_value(&decoded.insn, 1)
        } else {
            None
        };
    }
    sightings
        .into_iter()
        .filter_map(
            |(loc, (count, value)): (StateLoc, (u32, Option<u64>))| match (count, value) {
                (1, Some(constant)) => Some((loc, constant)),
                _ => None,
            },
        )
        .collect()
}

fn definitions_of<'p>(program: &'p Program<'p>, loc: StateLoc) -> Vec<&'p Instruction> {
    program
        .decoded
        .iter()
        .map(|decoded: &DecodedInsn| &decoded.insn)
        .filter(|insn: &&Instruction| defines(insn, loc))
        .collect()
}

fn resolve_loc(
    program: &Program<'_>,
    loc: StateLoc,
    consts: &BTreeMap<StateLoc, u64>,
    depth: u32,
) -> StateValue {
    if depth > MAX_RESOLVE_DEPTH {
        return StateValue::Unknown;
    }
    if let Some(constant) = consts.get(&loc) {
        return StateValue::Const(*constant);
    }
    let defs: Vec<&Instruction> = definitions_of(program, loc);
    let [first, second]: [&Instruction; 2] = match defs.as_slice() {
        [a, b] => [a, b],
        _ => return StateValue::Unknown,
    };
    if first.mnemonic() != Mnemonic::Mov || !is_cmov(second.mnemonic()) {
        return StateValue::Unknown;
    }
    let Some(base): Option<u64> = immediate_value(first, 1) else {
        return StateValue::Unknown;
    };
    let Some(source): Option<StateLoc> = StateLoc::from_src(second) else {
        return StateValue::Unknown;
    };
    match resolve_loc(program, source, consts, depth + 1) {
        StateValue::Const(alternative) => StateValue::Select {
            taken: alternative,
            fallthrough: base,
        },
        StateValue::Select { .. } | StateValue::Unknown => StateValue::Unknown,
    }
}

fn apply_block(
    program: &Program<'_>,
    block: &Block,
    state_loc: StateLoc,
    incoming: StateValue,
    consts: &BTreeMap<StateLoc, u64>,
) -> (StateValue, bool) {
    let mut value: StateValue = incoming;
    let mut wrote: bool = false;
    for idx in &block.insns {
        let Some(decoded): Option<&DecodedInsn> = program.decoded.get(*idx) else {
            continue;
        };
        let insn: &Instruction = &decoded.insn;
        if !defines(insn, state_loc) {
            continue;
        }
        wrote = true;
        value = match insn.mnemonic() {
            Mnemonic::Mov => immediate_value(insn, 1).map_or_else(
                || {
                    StateLoc::from_src(insn).map_or(StateValue::Unknown, |src: StateLoc| {
                        resolve_loc(program, src, consts, 0)
                    })
                },
                StateValue::Const,
            ),
            m if is_cmov(m) => cmov_value(program, insn, value, consts),
            _ => StateValue::Unknown,
        };
    }
    (value, wrote)
}

fn cmov_value(
    program: &Program<'_>,
    insn: &Instruction,
    current: StateValue,
    consts: &BTreeMap<StateLoc, u64>,
) -> StateValue {
    let alternative: StateValue = StateLoc::from_src(insn)
        .map_or(StateValue::Unknown, |src: StateLoc| {
            resolve_loc(program, src, consts, 0)
        });
    match (current, alternative) {
        (StateValue::Const(base), StateValue::Const(alt)) => StateValue::Select {
            taken: alt,
            fallthrough: base,
        },
        _ => StateValue::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegionExit {
    Dispatch(StateValue),
    Return,
    Unresolved(DegradeReason),
}

struct RegionWalk<'p> {
    program: &'p Program<'p>,
    state_loc: StateLoc,
    dispatcher_blocks: &'p BTreeSet<usize>,
    case_blocks: &'p BTreeSet<usize>,
    consts: &'p BTreeMap<StateLoc, u64>,
    order: Vec<usize>,
    seen: BTreeSet<usize>,
    exits: Vec<RegionExit>,
    steps: u32,
}

impl<'p> RegionWalk<'p> {
    fn new(
        program: &'p Program<'p>,
        state_loc: StateLoc,
        dispatcher_blocks: &'p BTreeSet<usize>,
        case_blocks: &'p BTreeSet<usize>,
        consts: &'p BTreeMap<StateLoc, u64>,
    ) -> Self {
        Self {
            program,
            state_loc,
            dispatcher_blocks,
            case_blocks,
            consts,
            order: Vec::new(),
            seen: BTreeSet::new(),
            exits: Vec::new(),
            steps: 0,
        }
    }

    fn walk(
        &mut self,
        block_index: usize,
        incoming: StateValue,
        wrote: bool,
        path: &mut Vec<usize>,
        depth: u32,
    ) {
        self.steps = self.steps.saturating_add(1);
        if self.steps > MAX_REGION_STEPS || depth > MAX_REGION_DEPTH {
            self.exits
                .push(RegionExit::Unresolved(DegradeReason::RegionUnbounded));
            return;
        }
        if path.contains(&block_index) {
            self.exits
                .push(RegionExit::Unresolved(DegradeReason::RegionUnbounded));
            return;
        }
        let Some(block): Option<&Block> = self.program.blocks.get(block_index) else {
            self.exits
                .push(RegionExit::Unresolved(DegradeReason::NextStateNotConstant));
            return;
        };
        if self.seen.insert(block_index) {
            self.order.push(block_index);
        }
        let (value, block_wrote): (StateValue, bool) =
            apply_block(self.program, block, self.state_loc, incoming, self.consts);
        let wrote: bool = wrote || block_wrote;
        if returns(self.program, block) {
            self.exits.push(RegionExit::Return);
            return;
        }
        let successors: Vec<u64> = block_successors(self.program, block);
        if successors.is_empty() {
            self.exits
                .push(RegionExit::Unresolved(DegradeReason::NextStateNotConstant));
            return;
        }
        path.push(block_index);
        for address in successors {
            let Some(next): Option<&usize> = self.program.block_of_addr.get(&address) else {
                self.exits
                    .push(RegionExit::Unresolved(DegradeReason::NextStateNotConstant));
                continue;
            };
            let next: usize = *next;
            if self.dispatcher_blocks.contains(&next) {
                self.exits.push(if wrote {
                    RegionExit::Dispatch(value)
                } else {
                    RegionExit::Unresolved(DegradeReason::StateVarNotAssigned)
                });
            } else if self.case_blocks.contains(&next) {
                self.exits
                    .push(RegionExit::Unresolved(DegradeReason::FellIntoCase));
            } else {
                self.walk(next, value, wrote, path, depth + 1);
            }
        }
        path.pop();
    }
}

fn returns(program: &Program<'_>, block: &Block) -> bool {
    block
        .insns
        .last()
        .and_then(|idx: &usize| program.decoded.get(*idx))
        .is_some_and(|decoded: &DecodedInsn| decoded.insn.flow_control() == FlowControl::Return)
}

fn summarize_exits(
    exits: &[RegionExit],
    case_states: &BTreeSet<u64>,
) -> (Vec<u64>, bool, Option<DegradeReason>) {
    let mut successors: Vec<u64> = Vec::new();
    let mut terminal: bool = false;
    let mut degrade: Option<DegradeReason> = None;
    let mut record = |state: u64, degrade: &mut Option<DegradeReason>| {
        if !case_states.contains(&state) {
            degrade.get_or_insert(DegradeReason::NextStateOutsideCaseMap);
            return;
        }
        if !successors.contains(&state) {
            successors.push(state);
        }
    };
    for exit in exits {
        match *exit {
            RegionExit::Return => terminal = true,
            RegionExit::Unresolved(reason) => {
                degrade.get_or_insert(reason);
            }
            RegionExit::Dispatch(StateValue::Const(state)) => record(state, &mut degrade),
            RegionExit::Dispatch(StateValue::Select { taken, fallthrough }) => {
                record(taken, &mut degrade);
                record(fallthrough, &mut degrade);
            }
            RegionExit::Dispatch(StateValue::Unknown) => {
                degrade.get_or_insert(DegradeReason::NextStateNotConstant);
            }
        }
    }
    if successors.is_empty() && !terminal {
        degrade.get_or_insert(DegradeReason::StateVarNotAssigned);
    }
    (successors, terminal, degrade)
}

fn block_spans(program: &Program<'_>, order: &[usize]) -> Vec<BlockSpan> {
    order
        .iter()
        .filter_map(|index: &usize| program.blocks.get(*index))
        .map(|block: &Block| BlockSpan {
            start: block.start,
            end: block.end,
        })
        .collect()
}

fn recover(program: &Program<'_>, dispatcher: &DispatcherModel) -> CffOutcome {
    let case_entry: BTreeMap<u64, usize> = dispatcher
        .case_targets
        .iter()
        .filter_map(|(state, address): (&u64, &u64)| {
            program
                .block_of_addr
                .get(address)
                .map(|block: &usize| (*state, *block))
        })
        .collect();
    if case_entry.is_empty() {
        return CffOutcome::Abstained(CffAbstain::CaseMapTooSmall);
    }
    let case_blocks: BTreeSet<usize> = case_entry.values().copied().collect();
    let case_states: BTreeSet<u64> = case_entry.keys().copied().collect();
    let dispatcher_blocks: BTreeSet<usize> = compare_chain_blocks(program, dispatcher);
    let consts: BTreeMap<StateLoc, u64> = unique_constants(program);

    let Some(entry_block): Option<&usize> = program.block_of_addr.get(&program.entry) else {
        return CffOutcome::Abstained(CffAbstain::InitialStateUnknown);
    };
    let mut prologue: RegionWalk<'_> = RegionWalk::new(
        program,
        dispatcher.state_loc,
        &dispatcher_blocks,
        &case_blocks,
        &consts,
    );
    prologue.walk(*entry_block, StateValue::Unknown, false, &mut Vec::new(), 0);
    let (entry_states, _, _): (Vec<u64>, bool, Option<DegradeReason>) =
        summarize_exits(&prologue.exits, &case_states);
    if entry_states.is_empty() {
        return CffOutcome::Abstained(CffAbstain::InitialStateUnknown);
    }
    let prologue_spans: Vec<BlockSpan> = block_spans(program, &prologue.order);

    let mut regions: Vec<StateRegion> = Vec::with_capacity(case_entry.len());
    let mut region_blocks: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (state, block_index) in &case_entry {
        let mut walk: RegionWalk<'_> = RegionWalk::new(
            program,
            dispatcher.state_loc,
            &dispatcher_blocks,
            &case_blocks,
            &consts,
        );
        walk.walk(
            *block_index,
            StateValue::Const(*state),
            false,
            &mut Vec::new(),
            0,
        );
        let (successors, terminal, degrade): (Vec<u64>, bool, Option<DegradeReason>) =
            summarize_exits(&walk.exits, &case_states);
        regions.push(StateRegion {
            state: *state,
            case_target: program
                .blocks
                .get(*block_index)
                .map_or(0, |block: &Block| block.start),
            blocks: block_spans(program, &walk.order),
            successors,
            terminal,
            degrade,
        });
        region_blocks.insert(*state, walk.order);
    }

    let cover: DispatcherCover = build_cover(
        dispatcher,
        &case_entry,
        entry_states,
        regions,
        prologue_spans,
        dispatcher.state_loc,
    );
    let (linear_order, listing): (Vec<u64>, String) =
        render_recovery(program, dispatcher, &cover, &region_blocks);
    let unresolved_blocks: Vec<u64> = unresolved_addresses(&cover);
    let fully_recovered: bool = cover.covers_every_state()
        && cover.unresolved_transitions().is_empty()
        && cover.canary.is_none();

    CffOutcome::Recovered(Box::new(CffRecovery {
        dispatcher_address: dispatcher.address,
        state_loc: dispatcher.state_loc,
        original_block_count: u32::try_from(program.blocks.len()).unwrap_or(u32::MAX),
        recovered_block_count: u32::try_from(linear_order.len()).unwrap_or(u32::MAX),
        state_case_count: u32::try_from(dispatcher.case_targets.len()).unwrap_or(u32::MAX),
        linear_order,
        unresolved_blocks,
        fully_recovered,
        cover,
        listing,
    }))
}

fn build_cover(
    dispatcher: &DispatcherModel,
    case_entry: &BTreeMap<u64, usize>,
    entry_states: Vec<u64>,
    regions: Vec<StateRegion>,
    prologue: Vec<BlockSpan>,
    state_loc: StateLoc,
) -> DispatcherCover {
    let by_state: BTreeMap<u64, &StateRegion> = regions
        .iter()
        .map(|region: &StateRegion| (region.state, region))
        .collect();
    let mut covered: Vec<u64> = Vec::new();
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut queue: VecDeque<u64> = entry_states.iter().copied().collect();
    let mut edges: Vec<StateEdge> = Vec::new();
    while let Some(state) = queue.pop_front() {
        if !visited.insert(state) {
            continue;
        }
        covered.push(state);
        let Some(region): Option<&&StateRegion> = by_state.get(&state) else {
            continue;
        };
        let guard: EdgeGuard = if region.successors.len() > 1 {
            EdgeGuard::Branch
        } else {
            EdgeGuard::Direct
        };
        for next in &region.successors {
            edges.push(StateEdge {
                from: state,
                to: *next,
                guard,
            });
            queue.push_back(*next);
        }
    }

    let blocking: Option<(u64, DegradeReason)> = covered
        .iter()
        .filter_map(|state: &u64| {
            by_state.get(state).and_then(|region: &&StateRegion| {
                region.degrade.map(|r: DegradeReason| (*state, r))
            })
        })
        .min();
    let uncovered: Vec<UncoveredState> = dispatcher
        .case_targets
        .iter()
        .filter(|(state, _): &(&u64, &u64)| !visited.contains(state))
        .map(|(state, target): (&u64, &u64)| UncoveredState {
            state: *state,
            case_target: *target,
            gap: if case_entry.contains_key(state) {
                blocking.map_or(
                    StateCoverGap::UnreachedUnderResolvedTransitions,
                    |(at_state, reason): (u64, DegradeReason)| {
                        StateCoverGap::UnreachedBehindUnresolvedTransition { at_state, reason }
                    },
                )
            } else {
                StateCoverGap::CaseTargetNotDecoded
            },
        })
        .collect();

    let canary: Option<CanaryViolation> = state_canary(
        &entry_states,
        &covered,
        &edges,
        &by_state,
        dispatcher,
        state_loc,
    );
    DispatcherCover {
        dispatcher_states: u32::try_from(dispatcher.case_targets.len()).unwrap_or(u32::MAX),
        covered_states: u32::try_from(covered.len()).unwrap_or(u32::MAX),
        entry_states,
        covered,
        uncovered,
        edges,
        regions,
        prologue,
        canary,
    }
}

fn state_canary(
    entry_states: &[u64],
    covered: &[u64],
    edges: &[StateEdge],
    by_state: &BTreeMap<u64, &StateRegion>,
    dispatcher: &DispatcherModel,
    state_loc: StateLoc,
) -> Option<CanaryViolation> {
    let roles: BTreeMap<u64, BlockRole> = dispatcher
        .case_targets
        .keys()
        .map(|state: &u64| {
            let role: BlockRole = match by_state.get(state) {
                Some(region) if covered.contains(state) && region.degrade.is_none() => {
                    if region.successors.is_empty() {
                        BlockRole::Terminal
                    } else {
                        BlockRole::Resolved
                    }
                }
                _ => BlockRole::Unresolved,
            };
            (*state, role)
        })
        .collect();
    let cfg: RecoveredCfg = RecoveredCfg {
        entry: *entry_states.first()?,
        state_var: state_loc.render(),
        cases: dispatcher.case_targets.keys().copied().collect(),
        edges: edges
            .iter()
            .map(|edge: &StateEdge| DevirtEdge {
                from: edge.from,
                to: edge.to,
                guard: edge.guard,
            })
            .collect(),
        scaffolding: Vec::new(),
        roles,
        notes: by_state
            .values()
            .filter_map(|region: &&StateRegion| {
                region.degrade.map(|reason: DegradeReason| DevirtNote {
                    block: region.state,
                    reason,
                })
            })
            .collect(),
    };
    cfg.canary().err()
}

fn unresolved_addresses(cover: &DispatcherCover) -> Vec<u64> {
    let mut out: Vec<u64> = cover
        .uncovered
        .iter()
        .map(|state: &UncoveredState| state.case_target)
        .collect();
    out.extend(
        cover
            .unresolved_transitions()
            .iter()
            .map(|region: &&StateRegion| region.case_target),
    );
    out.sort_unstable();
    out.dedup();
    out
}

fn render_recovery(
    program: &Program<'_>,
    dispatcher: &DispatcherModel,
    cover: &DispatcherCover,
    region_blocks: &BTreeMap<u64, Vec<usize>>,
) -> (Vec<u64>, String) {
    let mut listing: String = String::new();
    let _ = writeln!(
        listing,
        "; dispatcher cover {} of {} states, state variable {}",
        cover.covered_states,
        cover.dispatcher_states,
        dispatcher.state_loc.render()
    );
    let by_state: BTreeMap<u64, &StateRegion> = cover
        .regions
        .iter()
        .map(|region: &StateRegion| (region.state, region))
        .collect();
    let mut order: Vec<u64> = Vec::new();
    let mut emitted: BTreeSet<usize> = BTreeSet::new();
    for state in &cover.covered {
        let Some(blocks): Option<&Vec<usize>> = region_blocks.get(state) else {
            continue;
        };
        for index in blocks {
            if !emitted.insert(*index) {
                continue;
            }
            let Some(block): Option<&Block> = program.blocks.get(*index) else {
                continue;
            };
            order.push(block.start);
            emit_block(program, block, dispatcher, &mut listing);
        }
        if let Some(region) = by_state.get(state) {
            annotate_transition(region, &mut listing);
        }
    }
    for uncovered in &cover.uncovered {
        let _ = writeln!(
            listing,
            "; state {:#x} at block_{:x} is not covered: {}",
            uncovered.state,
            uncovered.case_target,
            describe_gap(uncovered.gap)
        );
    }
    (order, listing)
}

fn annotate_transition(region: &StateRegion, listing: &mut String) {
    match region.successors.as_slice() {
        [taken, fallthrough] => {
            let _ = writeln!(
                listing,
                "  ; conditional: taken state {taken}, fallthrough state {fallthrough}"
            );
        }
        _ => {
            if let Some(reason) = region.degrade {
                let _ = writeln!(
                    listing,
                    "  ; transition out of state {:#x} is unresolved: {}",
                    region.state,
                    describe_degrade(reason)
                );
            }
        }
    }
}

fn describe_gap(gap: StateCoverGap) -> String {
    match gap {
        StateCoverGap::CaseTargetNotDecoded => {
            "the dispatcher names a case target that never decoded into a block".to_owned()
        }
        StateCoverGap::UnreachedUnderResolvedTransitions => {
            "every covered transition resolved and none of them names this state".to_owned()
        }
        StateCoverGap::UnreachedBehindUnresolvedTransition { at_state, reason } => {
            format!(
                "state {at_state:#x} has an unresolved transition ({}), so the reachable set stops short of it",
                describe_degrade(reason)
            )
        }
    }
}

const fn describe_degrade(reason: DegradeReason) -> &'static str {
    match reason {
        DegradeReason::NextStateNotConstant => "the next state is not a constant",
        DegradeReason::NextStateOutsideCaseMap => {
            "the next state is not one the dispatcher selects"
        }
        DegradeReason::StateVarNotAssigned => {
            "the region reaches the dispatcher without writing the state variable"
        }
        DegradeReason::RegionUnbounded => "the region exceeds its traversal budget",
        DegradeReason::SolverUnknown => "the solver returned no verdict",
        DegradeReason::FellIntoCase => {
            "the region falls into another case block instead of returning to the dispatcher"
        }
        DegradeReason::RequiresSolver => "resolving this transition needs the solver tier",
    }
}

fn compare_chain_blocks(program: &Program<'_>, dispatcher: &DispatcherModel) -> BTreeSet<usize> {
    let mut blocks: BTreeSet<usize> = BTreeSet::from([dispatcher.block_index]);
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut stack: Vec<usize> = vec![dispatcher.block_index];
    let mut steps: usize = 0;
    while let Some(walker) = stack.pop() {
        steps += 1;
        if steps > MAX_DISPATCH_TREE_STEPS {
            break;
        }
        if !visited.insert(walker) {
            continue;
        }
        let Some(current): Option<&Block> = program.blocks.get(walker) else {
            continue;
        };
        let Some(step): Option<CompareStep> = match_tree_compare_step(program, current) else {
            continue;
        };
        if step.loc != dispatcher.state_loc {
            continue;
        }
        blocks.insert(walker);
        match step.kind {
            CompareKind::Equality { continue_block, .. } => {
                if let Some(&next) = program.block_of_addr.get(&continue_block) {
                    stack.push(next);
                }
            }
            CompareKind::Ordering { taken, fallthrough } => {
                if let Some(&t) = program.block_of_addr.get(&taken) {
                    stack.push(t);
                }
                if let Some(&f) = program.block_of_addr.get(&fallthrough) {
                    stack.push(f);
                }
            }
        }
    }
    blocks
}

fn emit_block(
    program: &Program<'_>,
    block: &Block,
    dispatcher: &DispatcherModel,
    listing: &mut String,
) {
    let _ = writeln!(listing, "block_{:x}:", block.start);
    for idx in &block.insns {
        let Some(decoded): Option<&DecodedInsn> = program.decoded.get(*idx) else {
            continue;
        };
        if is_state_machinery(&decoded.insn, dispatcher.state_loc) {
            continue;
        }
        let _ = writeln!(listing, "  {}", decoded.text);
    }
}

fn is_state_machinery(insn: &Instruction, state_loc: StateLoc) -> bool {
    let mnemonic: Mnemonic = insn.mnemonic();
    if mnemonic == Mnemonic::Mov
        && StateLoc::from_dest(insn) == Some(state_loc)
        && immediate_value(insn, 1).is_some()
    {
        return true;
    }
    if is_cmov(mnemonic) && StateLoc::from_dest(insn) == Some(state_loc) {
        return true;
    }
    if matches!(insn.flow_control(), FlowControl::UnconditionalBranch) {
        return true;
    }
    false
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
