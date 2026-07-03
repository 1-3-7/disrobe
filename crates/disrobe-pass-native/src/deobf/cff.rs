use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter as _, Instruction, Mnemonic, NasmFormatter,
    OpKind, Register,
};
use serde::{Deserialize, Serialize};

const MAX_INSNS: usize = 200_000;
const MAX_BLOCKS: usize = 8192;
const MIN_DISPATCH_PREDS: usize = 3;
const MAX_DISPATCH_TREE_STEPS: usize = 4096;

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
    insns: Vec<usize>,
}

#[derive(Debug)]
struct Program<'a> {
    decoded: Vec<DecodedInsn>,
    blocks: Vec<Block>,
    block_of_addr: BTreeMap<u64, usize>,
    base: u64,
    bytes: &'a [u8],
}

impl Program<'_> {
    fn read_u32(&self, addr: u64) -> Option<u32> {
        let offset: usize = addr.checked_sub(self.base)? as usize;
        let slice: &[u8] = self.bytes.get(offset..offset + 4)?;
        Some(u32::from_le_bytes(slice.try_into().ok()?))
    }

    fn read_u64(&self, addr: u64) -> Option<u64> {
        let offset: usize = addr.checked_sub(self.base)? as usize;
        let slice: &[u8] = self.bytes.get(offset..offset + 8)?;
        Some(u64::from_le_bytes(slice.try_into().ok()?))
    }

    fn end_addr(&self) -> u64 {
        self.base.saturating_add(self.bytes.len() as u64)
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
    pub listing: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CffOutcome {
    NotFlattened,
    Recovered(CffRecovery),
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
    let leaders: BTreeSet<u64> = collect_leaders(&decoded, base, bytes, end_addr);
    let (blocks, block_of_addr): (Vec<Block>, BTreeMap<u64, usize>) =
        carve_blocks(&decoded, &leaders)?;
    Some(Program {
        decoded,
        blocks,
        block_of_addr,
        base,
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
                .get(offset..offset + 8)
                .and_then(|raw: &[u8]| raw.try_into().ok())
                .map(u64::from_le_bytes),
            _ => bytes
                .get(offset..offset + 4)
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
) -> BTreeSet<u64> {
    let in_range = |t: u64| t >= base && t < end_addr;
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    if let Some(first) = decoded.first() {
        leaders.insert(first.insn.ip());
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
                insns: Vec::new(),
            });
        }
        if let Some(block) = current.as_mut() {
            block.insns.push(idx);
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
        let model: Option<DispatcherModel> = model_compare_chain(program, block_index, block)
            .or_else(|| model_compare_tree(program, block_index, block))
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
    let insn: &Instruction = &program.decoded[last_idx].insn;
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
    let last: &Instruction = &program.decoded[*insns.last()?].insn;
    if last.flow_control() != FlowControl::ConditionalBranch {
        return None;
    }
    let cmp: &Instruction = &program.decoded[insns[insns.len() - 2]].insn;
    if cmp.mnemonic() != Mnemonic::Cmp {
        return None;
    }
    let loc: StateLoc = StateLoc::from_dest(cmp)?;
    let value: u64 = immediate_value(cmp, 1)?;
    let taken: u64 = last.near_branch_target();
    let fallthrough: u64 = block_terminator_fallthrough(program, block)?;
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
    for (idx, block) in program.blocks.iter().enumerate() {
        for succ in block_successors(program, block) {
            if let Some(target_block) = program.block_of_addr.get(&succ) {
                *counts.entry(*target_block).or_insert(0) += 1;
            }
        }
        let _ = idx;
    }
    counts
}

fn block_successors(program: &Program<'_>, block: &Block) -> Vec<u64> {
    let Some(last_idx): Option<&usize> = block.insns.last() else {
        return Vec::new();
    };
    let insn: &Instruction = &program.decoded[*last_idx].insn;
    let insn_end: u64 = insn.ip().saturating_add(insn.len() as u64);
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

fn model_compare_chain(
    program: &Program<'_>,
    block_index: usize,
    block: &Block,
) -> Option<DispatcherModel> {
    let mut walker: usize = block_index;
    let mut case_targets: BTreeMap<u64, u64> = BTreeMap::new();
    let mut state_loc: Option<StateLoc> = None;
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    loop {
        if !visited.insert(walker) {
            break;
        }
        let Some(current): Option<&Block> = program.blocks.get(walker) else {
            break;
        };
        let Some((loc, value, taken)): Option<(StateLoc, u64, u64)> =
            match_compare_step(program, current)
        else {
            break;
        };
        match state_loc {
            Some(existing) if existing != loc => break,
            _ => state_loc = Some(loc),
        }
        case_targets.entry(value).or_insert(taken);
        let insn_end: u64 = block_terminator_fallthrough(program, current)?;
        let Some(next_block): Option<&usize> = program.block_of_addr.get(&insn_end) else {
            break;
        };
        walker = *next_block;
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

fn match_compare_step(program: &Program<'_>, block: &Block) -> Option<(StateLoc, u64, u64)> {
    let insns: &[usize] = &block.insns;
    if insns.len() < 2 {
        return None;
    }
    let last: &Instruction = &program.decoded[*insns.last()?].insn;
    if last.flow_control() != FlowControl::ConditionalBranch {
        return None;
    }
    if !is_equality_branch(last.mnemonic()) {
        return None;
    }
    let taken: u64 = last.near_branch_target();
    let cmp: &Instruction = &program.decoded[insns[insns.len() - 2]].insn;
    if cmp.mnemonic() != Mnemonic::Cmp {
        return None;
    }
    let loc: StateLoc = StateLoc::from_dest(cmp)?;
    let value: u64 = immediate_value(cmp, 1)?;
    Some((loc, value, taken))
}

const fn is_equality_branch(mnemonic: Mnemonic) -> bool {
    matches!(mnemonic, Mnemonic::Je | Mnemonic::Jne)
}

fn block_terminator_fallthrough(program: &Program<'_>, block: &Block) -> Option<u64> {
    let last_idx: usize = *block.insns.last()?;
    let insn: &Instruction = &program.decoded[last_idx].insn;
    Some(insn.ip().saturating_add(insn.len() as u64))
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

fn recover(program: &Program<'_>, dispatcher: &DispatcherModel) -> CffOutcome {
    let value_to_block: BTreeMap<u64, usize> = dispatcher
        .case_targets
        .iter()
        .filter_map(|(value, addr): (&u64, &u64)| {
            program
                .block_of_addr
                .get(addr)
                .map(|b: &usize| (*value, *b))
        })
        .collect();
    if value_to_block.is_empty() {
        return CffOutcome::NotFlattened;
    }

    let dispatcher_blocks: BTreeSet<usize> = compare_chain_blocks(program, dispatcher);
    let entry_state: Option<u64> = find_entry_state(program, dispatcher);
    let Some(entry_state): Option<u64> = entry_state else {
        return partial(program, dispatcher, &value_to_block);
    };

    let mut order: Vec<u64> = Vec::new();
    let mut unresolved: Vec<u64> = Vec::new();
    let mut seen_states: BTreeSet<u64> = BTreeSet::new();
    let mut state: u64 = entry_state;
    let mut listing: String = String::new();
    let _ = writeln!(
        listing,
        "; recovered linear control flow (state @ {}, {} cases)",
        dispatcher.state_loc.render(),
        value_to_block.len()
    );

    while seen_states.insert(state) {
        let Some(block_index): Option<&usize> = value_to_block.get(&state) else {
            unresolved.push(state);
            break;
        };
        let Some(block): Option<&Block> = program.blocks.get(*block_index) else {
            break;
        };
        order.push(block.start);
        emit_block(program, block, dispatcher, &mut listing);
        match next_state(program, *block_index, dispatcher, &dispatcher_blocks) {
            NextState::Linear(value) => state = value,
            NextState::Branch { taken, fallthrough } => {
                let _ = writeln!(
                    listing,
                    "  ; conditional: taken state {taken}, fallthrough state {fallthrough}"
                );
                if !walk_branch(
                    program,
                    dispatcher,
                    &value_to_block,
                    &dispatcher_blocks,
                    taken,
                    fallthrough,
                    &mut order,
                    &mut seen_states,
                    &mut unresolved,
                    &mut listing,
                ) {
                    unresolved.push(state);
                }
                break;
            }
            NextState::Terminal => break,
            NextState::Unknown => {
                unresolved.push(block.start);
                break;
            }
        }
    }

    let recovered_block_count: u32 = u32::try_from(order.len()).unwrap_or(u32::MAX);
    let fully_recovered: bool = unresolved.is_empty() && recovered_block_count >= 2;
    CffOutcome::Recovered(CffRecovery {
        dispatcher_address: dispatcher.address,
        state_loc: dispatcher.state_loc,
        original_block_count: u32::try_from(program.blocks.len()).unwrap_or(u32::MAX),
        recovered_block_count,
        state_case_count: u32::try_from(value_to_block.len()).unwrap_or(u32::MAX),
        linear_order: order,
        unresolved_blocks: unresolved,
        fully_recovered,
        listing,
    })
}

#[allow(clippy::too_many_arguments)]
fn walk_branch(
    program: &Program<'_>,
    dispatcher: &DispatcherModel,
    value_to_block: &BTreeMap<u64, usize>,
    dispatcher_blocks: &BTreeSet<usize>,
    taken: u64,
    fallthrough: u64,
    order: &mut Vec<u64>,
    seen_states: &mut BTreeSet<u64>,
    unresolved: &mut Vec<u64>,
    listing: &mut String,
) -> bool {
    let mut ok: bool = true;
    for branch_state in [taken, fallthrough] {
        let mut state: u64 = branch_state;
        while seen_states.insert(state) {
            let Some(block_index): Option<&usize> = value_to_block.get(&state) else {
                unresolved.push(state);
                ok = false;
                break;
            };
            let Some(block): Option<&Block> = program.blocks.get(*block_index) else {
                ok = false;
                break;
            };
            order.push(block.start);
            emit_block(program, block, dispatcher, listing);
            match next_state(program, *block_index, dispatcher, dispatcher_blocks) {
                NextState::Linear(value) => state = value,
                NextState::Terminal => break,
                NextState::Branch { .. } | NextState::Unknown => {
                    break;
                }
            }
        }
    }
    ok
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NextState {
    Linear(u64),
    Branch { taken: u64, fallthrough: u64 },
    Terminal,
    Unknown,
}

fn next_state(
    program: &Program<'_>,
    block_index: usize,
    dispatcher: &DispatcherModel,
    dispatcher_blocks: &BTreeSet<usize>,
) -> NextState {
    let Some(block): Option<&Block> = program.blocks.get(block_index) else {
        return NextState::Unknown;
    };
    if returns(program, block) {
        return NextState::Terminal;
    }
    if let Some(value) = cmov_select(program, block, dispatcher.state_loc) {
        return NextState::Branch {
            taken: value.0,
            fallthrough: value.1,
        };
    }
    if ends_conditional(program, block)
        && let Some((taken, fallthrough)) =
            branch_successor_states(program, block, dispatcher, dispatcher_blocks)
    {
        return NextState::Branch { taken, fallthrough };
    }
    if let Some(value) = state_constant_stores(program, block, dispatcher.state_loc).last() {
        return NextState::Linear(*value);
    }
    if let Some(src_reg) = state_register_copy(program, block, dispatcher.state_loc) {
        return resolve_register_state(program, src_reg, 0);
    }
    NextState::Unknown
}

fn state_register_copy(
    program: &Program<'_>,
    block: &Block,
    state_loc: StateLoc,
) -> Option<StateLoc> {
    let mut copied_from: Option<StateLoc> = None;
    for idx in &block.insns {
        let insn: &Instruction = &program.decoded[*idx].insn;
        if insn.mnemonic() == Mnemonic::Mov
            && StateLoc::from_dest(insn) == Some(state_loc)
            && immediate_value(insn, 1).is_none()
            && let Some(src) = StateLoc::from_src(insn)
            && matches!(src, StateLoc::Reg(_))
        {
            copied_from = Some(src);
        }
    }
    copied_from
}

fn resolve_register_state(program: &Program<'_>, reg: StateLoc, depth: u32) -> NextState {
    if depth > 8 {
        return NextState::Unknown;
    }
    let mut base_value: Option<u64> = None;
    let mut alt_reg: Option<StateLoc> = None;
    for block in &program.blocks {
        for idx in &block.insns {
            let insn: &Instruction = &program.decoded[*idx].insn;
            if StateLoc::from_dest(insn) != Some(reg) {
                continue;
            }
            if insn.mnemonic() == Mnemonic::Mov
                && let Some(value) = immediate_value(insn, 1)
            {
                base_value = Some(value);
                alt_reg = None;
            } else if is_cmov(insn.mnemonic())
                && let Some(src) = StateLoc::from_src(insn)
            {
                alt_reg = Some(src);
            }
        }
    }
    match (base_value, alt_reg) {
        (Some(base), Some(alt)) => match resolve_register_state(program, alt, depth + 1) {
            NextState::Linear(alt_value) => NextState::Branch {
                taken: alt_value,
                fallthrough: base,
            },
            _ => NextState::Linear(base),
        },
        (Some(base), None) => NextState::Linear(base),
        _ => NextState::Unknown,
    }
}

fn ends_conditional(program: &Program<'_>, block: &Block) -> bool {
    block
        .insns
        .last()
        .map(|idx: &usize| &program.decoded[*idx].insn)
        .is_some_and(|insn: &Instruction| insn.flow_control() == FlowControl::ConditionalBranch)
}

fn branch_successor_states(
    program: &Program<'_>,
    block: &Block,
    dispatcher: &DispatcherModel,
    dispatcher_blocks: &BTreeSet<usize>,
) -> Option<(u64, u64)> {
    let last_idx: usize = *block.insns.last()?;
    let insn: &Instruction = &program.decoded[last_idx].insn;
    let taken_addr: u64 = insn.near_branch_target();
    let fallthrough_addr: u64 = insn.ip().saturating_add(insn.len() as u64);
    let taken_state: u64 = tail_state(program, taken_addr, dispatcher, dispatcher_blocks)?;
    let fall_state: u64 = tail_state(program, fallthrough_addr, dispatcher, dispatcher_blocks)?;
    Some((taken_state, fall_state))
}

fn tail_state(
    program: &Program<'_>,
    addr: u64,
    dispatcher: &DispatcherModel,
    dispatcher_blocks: &BTreeSet<usize>,
) -> Option<u64> {
    let block_index: usize = *program.block_of_addr.get(&addr)?;
    if dispatcher_blocks.contains(&block_index) {
        return None;
    }
    let block: &Block = program.blocks.get(block_index)?;
    state_constant_stores(program, block, dispatcher.state_loc)
        .last()
        .copied()
}

fn returns(program: &Program<'_>, block: &Block) -> bool {
    block
        .insns
        .last()
        .map(|idx: &usize| &program.decoded[*idx].insn)
        .is_some_and(|insn: &Instruction| insn.flow_control() == FlowControl::Return)
}

fn state_constant_stores(program: &Program<'_>, block: &Block, state_loc: StateLoc) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    for idx in &block.insns {
        let insn: &Instruction = &program.decoded[*idx].insn;
        if insn.mnemonic() != Mnemonic::Mov {
            continue;
        }
        if StateLoc::from_dest(insn) != Some(state_loc) {
            continue;
        }
        if let Some(value) = immediate_value(insn, 1) {
            out.push(value);
        }
    }
    out
}

fn cmov_select(program: &Program<'_>, block: &Block, state_loc: StateLoc) -> Option<(u64, u64)> {
    let mut base_value: Option<u64> = None;
    let mut alt_value: Option<u64> = None;
    let mut alt_source: Option<StateLoc> = None;
    for idx in &block.insns {
        let insn: &Instruction = &program.decoded[*idx].insn;
        let mnemonic: Mnemonic = insn.mnemonic();
        if mnemonic == Mnemonic::Mov
            && StateLoc::from_dest(insn) == Some(state_loc)
            && let Some(value) = immediate_value(insn, 1)
        {
            base_value = Some(value);
        }
        if is_cmov(mnemonic)
            && let (Some(dest), Some(src)) = (StateLoc::from_dest(insn), StateLoc::from_src(insn))
            && dest == state_loc
        {
            alt_source = Some(src);
        }
    }
    let alt_src: StateLoc = alt_source?;
    for idx in &block.insns {
        let insn: &Instruction = &program.decoded[*idx].insn;
        if insn.mnemonic() == Mnemonic::Mov
            && StateLoc::from_dest(insn) == Some(alt_src)
            && let Some(value) = immediate_value(insn, 1)
        {
            alt_value = Some(value);
        }
    }
    match (base_value, alt_value) {
        (Some(base), Some(alt)) => Some((alt, base)),
        _ => None,
    }
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

fn compare_chain_blocks(program: &Program<'_>, dispatcher: &DispatcherModel) -> BTreeSet<usize> {
    let mut blocks: BTreeSet<usize> = BTreeSet::new();
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

fn find_entry_state(program: &Program<'_>, dispatcher: &DispatcherModel) -> Option<u64> {
    let first: &Block = program.blocks.first()?;
    let stores: Vec<u64> = state_constant_stores(program, first, dispatcher.state_loc);
    stores.first().copied()
}

fn emit_block(
    program: &Program<'_>,
    block: &Block,
    dispatcher: &DispatcherModel,
    listing: &mut String,
) {
    let _ = writeln!(listing, "block_{:x}:", block.start);
    for idx in &block.insns {
        let decoded: &DecodedInsn = &program.decoded[*idx];
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
    if matches!(insn.flow_control(), FlowControl::UnconditionalBranch) {
        return true;
    }
    false
}

fn partial(
    program: &Program<'_>,
    dispatcher: &DispatcherModel,
    value_to_block: &BTreeMap<u64, usize>,
) -> CffOutcome {
    CffOutcome::Recovered(CffRecovery {
        dispatcher_address: dispatcher.address,
        state_loc: dispatcher.state_loc,
        original_block_count: u32::try_from(program.blocks.len()).unwrap_or(u32::MAX),
        recovered_block_count: 0,
        state_case_count: u32::try_from(value_to_block.len()).unwrap_or(u32::MAX),
        linear_order: Vec::new(),
        unresolved_blocks: vec![dispatcher.address],
        fully_recovered: false,
        listing: String::from("; dispatcher found but entry state not resolved"),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
