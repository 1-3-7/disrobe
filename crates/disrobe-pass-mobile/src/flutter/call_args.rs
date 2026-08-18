use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::NirBlock;

use super::aot_lift::{
    add_imm, blr_target_reg, fmov_double_immediate, ldr_imm_unsigned, movk, movz, subs_imm,
};
use super::disasm::{Arm64FlowKind, Arm64Function, Arm64Instruction};
use super::pool_table::{DartPoolTable, UNRESOLVED_TOKEN, render_double};

pub(super) const DART_ARGUMENT_REGISTERS: [u8; 6] = [1, 2, 3, 5, 6, 7];

const DART_RESULT_REGISTER: u8 = 0;

const DART_POOL_REGISTER: u8 = 27;

const DART_NULL_REGISTER: u8 = 22;

const DART_STACK_REGISTER: u8 = 15;

const DART_FRAME_REGISTER: u8 = 29;

const DART_IC_DATA_REGISTER: u8 = 5;

const DART_TRUE_OFFSET_FROM_NULL: u64 = 0x20;

const DART_FALSE_OFFSET_FROM_NULL: u64 = 0x30;

const ARM64_ZERO_REGISTER: u8 = 31;

const STACK_SLOT_BYTES: u64 = 8;

const MAX_STACK_ARGUMENTS: usize = 32;

const MAX_FRAME_SLOTS: usize = 128;

const MAX_VALUE_DEPTH: usize = 6;

const MAX_TRACKED_CALLS: usize = 1 << 14;

const MAX_BOOLEAN_RETURN_INSTRUCTIONS: usize = 64;

const ARM64_IMMEDIATE_SHIFT_BIT: u32 = 1 << 22;

struct DartComparison {
    left: DartValue,
    right: DartValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionalSelectKind {
    Select,
    Increment,
    Invert,
    Negate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DartCondition {
    Equal,
    NotEqual,
    GreaterOrEqual,
    LessThan,
    GreaterThan,
    LessOrEqual,
}

impl DartCondition {
    const fn from_arm64(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Equal),
            1 => Some(Self::NotEqual),
            10 => Some(Self::GreaterOrEqual),
            11 => Some(Self::LessThan),
            12 => Some(Self::GreaterThan),
            13 => Some(Self::LessOrEqual),
            _ => None,
        }
    }

    const fn inverse(self) -> Self {
        match self {
            Self::Equal => Self::NotEqual,
            Self::NotEqual => Self::Equal,
            Self::GreaterOrEqual => Self::LessThan,
            Self::LessThan => Self::GreaterOrEqual,
            Self::GreaterThan => Self::LessOrEqual,
            Self::LessOrEqual => Self::GreaterThan,
        }
    }

    const fn operator(self) -> &'static str {
        match self {
            Self::Equal => "==",
            Self::NotEqual => "!=",
            Self::GreaterOrEqual => ">=",
            Self::LessThan => "<",
            Self::GreaterThan => ">",
            Self::LessOrEqual => "<=",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DartValue {
    Null,
    Bool(bool),
    Int(i64),
    Double(u64),
    Pool { byte_offset: u64, float: bool },
    Param(usize),
    CallResult(u64),
    Field { base: Box<Self>, offset: i64 },
    Offset { base: Box<Self>, delta: i64 },
    PcRelative(u64),
}

#[derive(Debug, Default, Clone)]
pub(super) struct DartCallArguments {
    rendered: BTreeMap<u64, Vec<String>>,
    results: BTreeMap<u64, usize>,
    pub(super) recovered_sites: usize,
    pub(super) opaque_sites: usize,
    pub(super) max_parameter: Option<usize>,
}

impl DartCallArguments {
    pub(super) fn arguments(&self, address: u64) -> Option<&[String]> {
        self.rendered
            .get(&address)
            .map(|values: &Vec<String>| values.as_slice())
    }

    pub(super) fn result_binding(&self, address: u64) -> Option<usize> {
        self.results.get(&address).copied()
    }
}

#[derive(Debug, Default, Clone)]
struct TrackState {
    integers: BTreeMap<u8, DartValue>,
    floats: BTreeMap<u8, DartValue>,
    written: BTreeSet<u8>,
    stack: BTreeMap<u64, Option<DartValue>>,
    frame: BTreeMap<i64, DartValue>,
    selector_registers: BTreeSet<u8>,
}

impl TrackState {
    fn entry(parameter_count: Option<u8>) -> Self {
        let mut state: Self = Self::default();
        let register_count: usize = parameter_count
            .map_or(DART_ARGUMENT_REGISTERS.len(), |count: u8| {
                usize::from(count).min(DART_ARGUMENT_REGISTERS.len())
            });
        for (position, register) in DART_ARGUMENT_REGISTERS
            .iter()
            .take(register_count)
            .enumerate()
        {
            state.integers.insert(*register, DartValue::Param(position));
        }
        state
    }

    fn define(&mut self, register: u8, value: Option<DartValue>) {
        if register == ARM64_ZERO_REGISTER {
            return;
        }
        if register == DART_STACK_REGISTER {
            self.stack.clear();
        }
        if register == DART_FRAME_REGISTER {
            self.frame.clear();
        }
        self.written.insert(register);
        self.selector_registers.remove(&register);
        match value {
            Some(value) => {
                self.integers.insert(register, value);
            }
            None => {
                self.integers.remove(&register);
            }
        }
    }

    fn forget(&mut self, register: u8) {
        self.integers.remove(&register);
        self.selector_registers.remove(&register);
    }

    fn mark_read(&mut self, register: u8) {
        self.written.remove(&register);
    }

    fn define_float(&mut self, register: u8, value: Option<DartValue>) {
        match value {
            Some(value) => {
                self.floats.insert(register, value);
            }
            None => {
                self.floats.remove(&register);
            }
        }
    }

    fn consume_call(&mut self, address: u64) {
        self.integers.clear();
        self.floats.clear();
        self.written.clear();
        self.stack.clear();
        self.selector_registers.clear();
        self.integers
            .insert(DART_RESULT_REGISTER, DartValue::CallResult(address));
        self.floats
            .insert(DART_RESULT_REGISTER, DartValue::CallResult(address));
    }
}

pub(super) fn recover_boolean_return(
    func: &Arm64Function,
    pool: Option<&DartPoolTable>,
) -> Option<(String, u8)> {
    if func.instructions.is_empty() || func.instructions.len() > MAX_BOOLEAN_RETURN_INSTRUCTIONS {
        return None;
    }
    let mut state: TrackState = TrackState::entry(None);
    let mut comparison: Option<(usize, DartComparison)> = None;
    let mut selected: Option<(DartComparison, DartCondition)> = None;
    let mut producers: BTreeMap<u8, usize> = BTreeMap::new();
    let mut consumed_effects: Vec<bool> = Vec::with_capacity(func.instructions.len());
    for (index, instruction) in func.instructions.iter().enumerate() {
        match instruction.flow {
            Arm64FlowKind::Sequential => {
                if !is_boolean_return_step(instruction.bytes) {
                    return None;
                }
                consumed_effects.push(false);
                if let Some((destination, base, _)) = ldr_imm_unsigned(instruction.bytes) {
                    consume_register_effect(&producers, &mut consumed_effects, base);
                    producers.insert(destination, index);
                } else if let Some((destination, base, _)) = ldur_signed(instruction.bytes) {
                    consume_register_effect(&producers, &mut consumed_effects, base);
                    producers.insert(destination, index);
                } else if let Some((destination, base, _)) = add_imm(instruction.bytes) {
                    consume_register_effect(&producers, &mut consumed_effects, base);
                    producers.insert(destination, index);
                }
                if let Some((31, register, immediate)) = subs_imm(instruction.bytes) {
                    if instruction.bytes & ARM64_IMMEDIATE_SHIFT_BIT != 0 {
                        return None;
                    }
                    consume_register_effect(&producers, &mut consumed_effects, register);
                    comparison = state
                        .integers
                        .get(&register)
                        .cloned()
                        .map(|left: DartValue| DartComparison {
                            left,
                            right: DartValue::Int(immediate as i64),
                        })
                        .map(|comparison: DartComparison| (index, comparison));
                }
                if let Some((kind, 0, true_register, false_register, condition)) =
                    conditional_select(instruction.bytes)
                {
                    if kind != ConditionalSelectKind::Select || index + 2 != func.instructions.len()
                    {
                        return None;
                    }
                    let condition: DartCondition = DartCondition::from_arm64(condition)?;
                    let when_true: &DartValue = state.integers.get(&true_register)?;
                    let when_false: &DartValue = state.integers.get(&false_register)?;
                    let selected_condition: DartCondition = match (when_true, when_false) {
                        (DartValue::Bool(true), DartValue::Bool(false)) => condition,
                        (DartValue::Bool(false), DartValue::Bool(true)) => condition.inverse(),
                        _ => return None,
                    };
                    let (comparison_index, comparison): (usize, DartComparison) =
                        comparison.take()?;
                    if index.saturating_sub(comparison_index) > 3 {
                        return None;
                    }
                    consume_register_effect(&producers, &mut consumed_effects, true_register);
                    consume_register_effect(&producers, &mut consumed_effects, false_register);
                    let comparison_consumed: &mut bool =
                        consumed_effects.get_mut(comparison_index)?;
                    *comparison_consumed = true;
                    let selection_consumed: &mut bool = consumed_effects.get_mut(index)?;
                    *selection_consumed = true;
                    selected = Some((comparison, selected_condition));
                }
                apply_sequential(&mut state, instruction, instruction.bytes);
            }
            Arm64FlowKind::Return if index + 1 == func.instructions.len() => {
                if consumed_effects.iter().any(|consumed: &bool| !consumed) {
                    return None;
                }
                let (comparison, condition): (DartComparison, DartCondition) = selected?;
                let mut consumed: BTreeSet<u64> = BTreeSet::new();
                let mut max_parameter: Option<usize> = None;
                collect_dependencies(&comparison.left, &mut consumed, &mut max_parameter);
                collect_dependencies(&comparison.right, &mut consumed, &mut max_parameter);
                let parameter_count: u8 = max_parameter
                    .and_then(|position: usize| position.checked_add(1))
                    .and_then(|count: usize| u8::try_from(count).ok())
                    .unwrap_or(0);
                return Some((
                    format!(
                        "{} {} {}",
                        render_value(&comparison.left, pool, &BTreeMap::new(), 0),
                        condition.operator(),
                        render_value(&comparison.right, pool, &BTreeMap::new(), 0)
                    ),
                    parameter_count,
                ));
            }
            _ => return None,
        }
    }
    None
}

fn consume_register_effect(
    producers: &BTreeMap<u8, usize>,
    consumed_effects: &mut [bool],
    register: u8,
) {
    if let Some(index) = producers.get(&register)
        && let Some(consumed) = consumed_effects.get_mut(*index)
    {
        *consumed = true;
    }
}

fn is_boolean_return_step(raw: u32) -> bool {
    ldr_imm_unsigned(raw).is_some()
        || ldur_signed(raw).is_some()
        || matches!(subs_imm(raw), Some((31, _, _)))
        || matches!(
            add_imm(raw),
            Some((
                _,
                DART_NULL_REGISTER,
                DART_TRUE_OFFSET_FROM_NULL | DART_FALSE_OFFSET_FROM_NULL
            ))
        )
        || conditional_select(raw).is_some()
}

pub(super) fn recover_call_arguments(
    func: &Arm64Function,
    blocks: &[NirBlock],
    reachable: &BTreeSet<u64>,
    tail_calls: &BTreeSet<u64>,
    pool: Option<&DartPoolTable>,
    parameter_count: Option<u8>,
) -> DartCallArguments {
    let live: Vec<&NirBlock> = blocks
        .iter()
        .filter(|block: &&NirBlock| reachable.contains(&block.start))
        .collect::<Vec<&NirBlock>>();
    let sites: BTreeMap<u64, Vec<Option<DartValue>>> =
        track_call_sites(func, &live, tail_calls, parameter_count);
    let mut consumed: BTreeSet<u64> = BTreeSet::new();
    let mut max_parameter: Option<usize> = None;
    for values in sites.values() {
        for value in values.iter().flatten() {
            collect_dependencies(value, &mut consumed, &mut max_parameter);
        }
    }
    let results: BTreeMap<u64, usize> = consumed
        .iter()
        .enumerate()
        .map(|(index, address): (usize, &u64)| (*address, index))
        .collect::<BTreeMap<u64, usize>>();

    let mut rendered: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut recovered_sites: usize = 0;
    for (address, values) in &sites {
        if values.is_empty() {
            continue;
        }
        let texts: Vec<String> = values
            .iter()
            .map(|value: &Option<DartValue>| match value {
                Some(value) => render_value(value, pool, &results, 0),
                None => UNRESOLVED_TOKEN.to_owned(),
            })
            .collect::<Vec<String>>();
        recovered_sites += 1;
        rendered.insert(*address, texts);
    }
    let opaque_sites: usize = sites.len().saturating_sub(recovered_sites);

    DartCallArguments {
        rendered,
        results,
        recovered_sites,
        opaque_sites,
        max_parameter,
    }
}

fn collect_dependencies(
    value: &DartValue,
    consumed: &mut BTreeSet<u64>,
    max_parameter: &mut Option<usize>,
) {
    match value {
        DartValue::CallResult(address) => {
            consumed.insert(*address);
        }
        DartValue::Param(position) => {
            *max_parameter =
                Some(max_parameter.map_or(*position, |seen: usize| seen.max(*position)));
        }
        DartValue::Field { base, .. } | DartValue::Offset { base, .. } => {
            collect_dependencies(base, consumed, max_parameter);
        }
        DartValue::Null
        | DartValue::Bool(_)
        | DartValue::Int(_)
        | DartValue::Double(_)
        | DartValue::Pool { .. }
        | DartValue::PcRelative(_) => {}
    }
}

fn track_call_sites(
    func: &Arm64Function,
    blocks: &[&NirBlock],
    tail_calls: &BTreeSet<u64>,
    parameter_count: Option<u8>,
) -> BTreeMap<u64, Vec<Option<DartValue>>> {
    let insns: &[Arm64Instruction] = &func.instructions;
    let predecessors: BTreeMap<u64, usize> = predecessor_counts(blocks);
    let single: BTreeMap<u64, u64> = single_predecessor(blocks);
    let mut exits: BTreeMap<u64, TrackState> = BTreeMap::new();
    let mut sites: BTreeMap<u64, Vec<Option<DartValue>>> = BTreeMap::new();
    let entry: Option<u64> = blocks.first().map(|block: &&NirBlock| block.start);

    for block in blocks {
        if sites.len() > MAX_TRACKED_CALLS {
            break;
        }
        let mut state: TrackState = if Some(block.start) == entry {
            TrackState::entry(parameter_count)
        } else if predecessors.get(&block.start).copied().unwrap_or(0) == 1
            && let Some(source) = single.get(&block.start)
            && let Some(inherited) = exits.get(source)
        {
            inherited.clone()
        } else {
            TrackState::default()
        };
        for insn in insns.iter().filter(|insn: &&Arm64Instruction| {
            insn.address >= block.start && insn.address < block.end
        }) {
            step(&mut state, insn, tail_calls, &mut sites);
        }
        exits.insert(block.start, state);
    }
    sites
}

fn predecessor_counts(blocks: &[&NirBlock]) -> BTreeMap<u64, usize> {
    let starts: BTreeSet<u64> = blocks.iter().map(|block: &&NirBlock| block.start).collect();
    let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
    for block in blocks {
        for successor in &block.successors {
            if starts.contains(successor) {
                *counts.entry(*successor).or_default() += 1;
            }
        }
    }
    counts
}

fn single_predecessor(blocks: &[&NirBlock]) -> BTreeMap<u64, u64> {
    let starts: BTreeSet<u64> = blocks.iter().map(|block: &&NirBlock| block.start).collect();
    let mut sources: BTreeMap<u64, u64> = BTreeMap::new();
    for block in blocks {
        for successor in &block.successors {
            if starts.contains(successor) {
                sources.entry(*successor).or_insert(block.start);
            }
        }
    }
    sources
}

fn step(
    state: &mut TrackState,
    insn: &Arm64Instruction,
    tail_calls: &BTreeSet<u64>,
    sites: &mut BTreeMap<u64, Vec<Option<DartValue>>>,
) {
    let raw: u32 = insn.bytes;
    match insn.flow {
        Arm64FlowKind::DirectCall | Arm64FlowKind::IndirectCall => {
            let indirect: bool = insn.flow == Arm64FlowKind::IndirectCall;
            let arguments: Vec<Option<DartValue>> = collect_arguments(state, indirect, raw);
            sites.insert(insn.address, arguments);
            state.consume_call(insn.address);
            return;
        }
        Arm64FlowKind::DirectBranch => {
            if tail_calls.contains(&insn.address) {
                let arguments: Vec<Option<DartValue>> = collect_arguments(state, false, raw);
                sites.insert(insn.address, arguments);
            }
            return;
        }
        Arm64FlowKind::Return
        | Arm64FlowKind::ConditionalBranch
        | Arm64FlowKind::IndirectBranch
        | Arm64FlowKind::DecodeError => return,
        Arm64FlowKind::Sequential => {}
    }
    apply_sequential(state, insn, raw);
}

fn apply_sequential(state: &mut TrackState, insn: &Arm64Instruction, raw: u32) {
    let group: u32 = (raw >> 25) & 0xF;
    if group & 0b0101 == 0b0100 {
        apply_memory(state, raw);
        return;
    }
    if group & 0b0111 == 0b0111 {
        apply_floating_point(state, raw);
        return;
    }
    if group & 0b1110 == 0b1000 {
        apply_immediate(state, insn, raw);
        return;
    }
    if group & 0b0111 == 0b0101 {
        apply_register(state, raw);
    }
}

fn apply_memory(state: &mut TrackState, raw: u32) {
    let pair: bool = raw & 0x3E00_0000 == 0x2800_0000;
    let load: bool = raw & 0x0040_0000 != 0;
    let simd: bool = raw & 0x0400_0000 != 0;
    let rt: u8 = (raw & 0x1F) as u8;
    let rt2: u8 = ((raw >> 10) & 0x1F) as u8;
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let unsigned_offset: bool = !pair && raw & 0x0100_0000 != 0;
    let writeback: bool = if pair {
        matches!((raw >> 23) & 0x3, 1 | 3)
    } else if unsigned_offset {
        false
    } else {
        matches!((raw >> 10) & 0x3, 1 | 3)
    };

    if !load && !simd {
        state.mark_read(rt);
        if pair {
            state.mark_read(rt2);
        }
    }

    if !load {
        if rn == DART_STACK_REGISTER && !writeback && !simd {
            if let Some((source, _, offset)) = store_to_stack(raw) {
                let value: Option<DartValue> = state.integers.get(&source).cloned();
                record_stack(state, offset, value);
            } else if let Some((first, second, _, offset)) = stp_offset(raw) {
                let low: Option<DartValue> = state.integers.get(&first).cloned();
                let high: Option<DartValue> = state.integers.get(&second).cloned();
                record_stack(state, offset, low);
                record_stack(state, offset.saturating_add(STACK_SLOT_BYTES), high);
            }
        }
        if rn == DART_FRAME_REGISTER && !writeback && !simd {
            record_frame(state, raw, rt, rt2, pair);
        }
        if writeback {
            state.define(rn, None);
        }
        return;
    }

    if simd {
        let value: Option<DartValue> = match ldr_float_pool(raw) {
            Some((_, base, byte_offset)) if base == DART_POOL_REGISTER => Some(DartValue::Pool {
                byte_offset,
                float: true,
            }),
            _ => None,
        };
        state.define_float(rt, value);
        if pair {
            state.define_float(rt2, None);
        }
    } else {
        let value: Option<DartValue> = load_value(state, raw, rn);
        state.define(rt, value);
        if rt == DART_IC_DATA_REGISTER && rn == DART_POOL_REGISTER {
            state.selector_registers.insert(rt);
        }
        if pair {
            state.define(rt2, None);
        }
    }
    if writeback {
        state.define(rn, None);
    }
}

fn load_value(state: &TrackState, raw: u32, rn: u8) -> Option<DartValue> {
    if let Some((_, base, byte_offset)) = ldr_imm_unsigned(raw) {
        if base == DART_POOL_REGISTER {
            return Some(DartValue::Pool {
                byte_offset,
                float: false,
            });
        }
        if base == DART_FRAME_REGISTER {
            return i64::try_from(byte_offset)
                .ok()
                .and_then(|offset: i64| state.frame.get(&offset).cloned());
        }
        if base == DART_STACK_REGISTER && byte_offset == 0 {
            return Some(DartValue::Param(0));
        }
        return field_of(state, base, i64::try_from(byte_offset).ok());
    }
    if let Some((_, base, offset)) = ldur_signed(raw) {
        if base == DART_STACK_REGISTER {
            return None;
        }
        if base == DART_FRAME_REGISTER {
            return state.frame.get(&offset).cloned();
        }
        return field_of(state, base, Some(offset));
    }
    let _ = rn;
    None
}

fn record_frame(state: &mut TrackState, raw: u32, rt: u8, rt2: u8, pair: bool) {
    if state.frame.len() >= MAX_FRAME_SLOTS {
        return;
    }
    let offset: i64 = frame_store_offset(raw, pair);
    let first: Option<DartValue> = state.integers.get(&rt).cloned();
    write_frame(state, offset, first);
    if pair {
        let second: Option<DartValue> = state.integers.get(&rt2).cloned();
        write_frame(
            state,
            offset.saturating_add(STACK_SLOT_BYTES as i64),
            second,
        );
    }
}

fn write_frame(state: &mut TrackState, offset: i64, value: Option<DartValue>) {
    match value {
        Some(value) => {
            state.frame.insert(offset, value);
        }
        None => {
            state.frame.remove(&offset);
        }
    }
}

fn frame_store_offset(raw: u32, pair: bool) -> i64 {
    if pair {
        let imm7: i64 = i64::from((raw >> 15) & 0x7F);
        let signed: i64 = if imm7 & 0x40 != 0 { imm7 - 128 } else { imm7 };
        return signed.saturating_mul(STACK_SLOT_BYTES as i64);
    }
    if raw & 0x3B00_0000 == 0x3900_0000 {
        return i64::from((raw >> 10) & 0xFFF).saturating_mul(STACK_SLOT_BYTES as i64);
    }
    let imm9: u32 = (raw >> 12) & 0x1FF;
    if imm9 & 0x100 != 0 {
        i64::from(imm9) - 512
    } else {
        i64::from(imm9)
    }
}

fn apply_floating_point(state: &mut TrackState, raw: u32) {
    let rd: u8 = (raw & 0x1F) as u8;
    state.forget(rd);
    match fmov_double(raw) {
        Some((register, bits)) => state.define_float(register, Some(DartValue::Double(bits))),
        None => state.define_float(rd, None),
    }
}

fn apply_immediate(state: &mut TrackState, insn: &Arm64Instruction, raw: u32) {
    if let Some((rd, page)) = adrp(raw, insn.address) {
        state.define(rd, Some(DartValue::PcRelative(page)));
        return;
    }
    if let Some((rd, imm)) = movz(raw) {
        state.define(rd, Some(DartValue::Int(imm as i64)));
        return;
    }
    if let Some((rd, imm, shift)) = movk(raw) {
        let updated: Option<DartValue> = match state.integers.get(&rd) {
            Some(DartValue::Int(prior)) => {
                let cleared: u64 = (*prior as u64) & !(0xFFFF_u64 << shift);
                Some(DartValue::Int((cleared | (imm << shift)) as i64))
            }
            _ => None,
        };
        state.define(rd, updated);
        return;
    }
    if let Some((rd, base, applied)) = add_imm(raw) {
        state.define(
            rd,
            offset_of(state, base, i64::try_from(applied).unwrap_or(0)),
        );
        return;
    }
    if let Some((rd, base, imm)) = sub_imm(raw) {
        state.define(
            rd,
            offset_of(
                state,
                base,
                i64::try_from(imm).unwrap_or(0).saturating_neg(),
            ),
        );
        return;
    }
    if let Some((rd, _, _)) = subs_imm(raw) {
        state.define(rd, None);
        return;
    }
    state.define((raw & 0x1F) as u8, None);
}

fn apply_register(state: &mut TrackState, raw: u32) {
    if let Some(register) = compressed_pointer_decompression(raw) {
        let value: Option<DartValue> = state.integers.get(&register).cloned();
        state.define(register, value);
        return;
    }
    if let Some((rd, source)) = mov_register(raw) {
        let value: Option<DartValue> = if source == DART_NULL_REGISTER {
            Some(DartValue::Null)
        } else {
            state.integers.get(&source).cloned()
        };
        let selector: bool = state.selector_registers.contains(&source);
        state.define(rd, value);
        if selector {
            state.selector_registers.insert(rd);
        }
        return;
    }
    state.define((raw & 0x1F) as u8, None);
}

fn compressed_pointer_decompression(raw: u32) -> Option<u8> {
    if raw & 0xFFFF_FC00 != 0x8B1C_8000 {
        return None;
    }
    let destination: u8 = (raw & 0x1F) as u8;
    let source: u8 = ((raw >> 5) & 0x1F) as u8;
    (destination == source).then_some(destination)
}

fn record_stack(state: &mut TrackState, offset: u64, value: Option<DartValue>) {
    if state.stack.len() >= MAX_STACK_ARGUMENTS {
        return;
    }
    state.stack.insert(offset, value);
}

fn field_of(state: &TrackState, base: u8, offset: Option<i64>) -> Option<DartValue> {
    let offset: i64 = offset?;
    let value: DartValue = state.integers.get(&base).cloned()?;
    Some(DartValue::Field {
        base: Box::new(value),
        offset,
    })
}

fn offset_of(state: &TrackState, base: u8, delta: i64) -> Option<DartValue> {
    if base == DART_NULL_REGISTER {
        return match u64::try_from(delta).ok() {
            Some(DART_TRUE_OFFSET_FROM_NULL) => Some(DartValue::Bool(true)),
            Some(DART_FALSE_OFFSET_FROM_NULL) => Some(DartValue::Bool(false)),
            _ => None,
        };
    }
    match state.integers.get(&base) {
        Some(DartValue::Int(value)) => Some(DartValue::Int(value.saturating_add(delta))),
        Some(value) => Some(DartValue::Offset {
            base: Box::new(value.clone()),
            delta,
        }),
        None => None,
    }
}

fn collect_arguments(state: &TrackState, indirect: bool, raw: u32) -> Vec<Option<DartValue>> {
    let dispatch: Option<u8> = indirect.then(|| blr_target_reg(raw)).flatten();
    let mut register_arguments: Vec<Option<DartValue>> = Vec::new();
    let mut last_written: Option<usize> = None;
    for (position, register) in DART_ARGUMENT_REGISTERS.iter().enumerate() {
        let excluded: bool = Some(*register) == dispatch
            || (indirect && state.selector_registers.contains(register));
        if excluded {
            register_arguments.push(None);
            continue;
        }
        if state.written.contains(register) {
            last_written = Some(position);
        }
        register_arguments.push(state.integers.get(register).cloned());
    }
    let mut arguments: Vec<Option<DartValue>> = match last_written {
        Some(position) => register_arguments.get(..=position).unwrap_or(&[]).to_vec(),
        None => Vec::new(),
    };
    arguments.extend(stack_arguments(state));
    arguments
}

fn stack_arguments(state: &TrackState) -> Vec<Option<DartValue>> {
    let mut arguments: Vec<Option<DartValue>> = Vec::with_capacity(state.stack.len());
    for (position, (offset, value)) in state.stack.iter().enumerate() {
        if *offset != position as u64 * STACK_SLOT_BYTES {
            return Vec::new();
        }
        if position >= MAX_STACK_ARGUMENTS {
            return Vec::new();
        }
        arguments.push(value.clone());
    }
    arguments
}

fn render_value(
    value: &DartValue,
    pool: Option<&DartPoolTable>,
    results: &BTreeMap<u64, usize>,
    depth: usize,
) -> String {
    if depth > MAX_VALUE_DEPTH {
        return UNRESOLVED_TOKEN.to_owned();
    }
    match value {
        DartValue::Null => "null".to_owned(),
        DartValue::Bool(true) => "true".to_owned(),
        DartValue::Bool(false) => "false".to_owned(),
        DartValue::Int(number) => number.to_string(),
        DartValue::Double(bits) => render_double(f64::from_bits(*bits)),
        DartValue::Pool { byte_offset, float } => render_pool(pool, *byte_offset, *float),
        DartValue::Param(position) => format!("arg{position}"),
        DartValue::CallResult(address) => match results.get(address) {
            Some(index) => format!("v{index}"),
            None => UNRESOLVED_TOKEN.to_owned(),
        },
        DartValue::Field { base, offset } => format!(
            "{}.field@{offset:#x}",
            render_value(base, pool, results, depth + 1)
        ),
        DartValue::Offset { base, delta } => {
            let rendered: String = render_value(base, pool, results, depth + 1);
            if *delta < 0 {
                format!("{rendered} - {}", delta.unsigned_abs())
            } else {
                format!("{rendered} + {delta}")
            }
        }
        DartValue::PcRelative(address) => format!("pc@{address:#x}"),
    }
}

fn conditional_select(raw: u32) -> Option<(ConditionalSelectKind, u8, u8, u8, u8)> {
    if raw & 0x3FE0_0800 != 0x1A80_0000 {
        return None;
    }
    let kind: ConditionalSelectKind = match ((raw >> 30) & 1, (raw >> 10) & 1) {
        (0, 0) => ConditionalSelectKind::Select,
        (0, 1) => ConditionalSelectKind::Increment,
        (1, 0) => ConditionalSelectKind::Invert,
        (1, 1) => ConditionalSelectKind::Negate,
        _ => return None,
    };
    let rm: u8 = ((raw >> 16) & 0x1F) as u8;
    let condition: u8 = ((raw >> 12) & 0xF) as u8;
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rd: u8 = (raw & 0x1F) as u8;
    Some((kind, rd, rn, rm, condition))
}

fn render_pool(pool: Option<&DartPoolTable>, byte_offset: u64, float: bool) -> String {
    let Some(table): Option<&DartPoolTable> = pool else {
        return UNRESOLVED_TOKEN.to_owned();
    };
    if let Some(rendered) = table.render_at_offset(byte_offset, float) {
        return rendered;
    }
    match table.slot_index(byte_offset) {
        Some(index) => format!("pool[{index}]"),
        None => UNRESOLVED_TOKEN.to_owned(),
    }
}

fn mov_register(raw: u32) -> Option<(u8, u8)> {
    if raw & 0xFFE0_FFE0 != 0xAA00_03E0 {
        return None;
    }
    let rm: u8 = ((raw >> 16) & 0x1F) as u8;
    let rd: u8 = (raw & 0x1F) as u8;
    Some((rd, rm))
}

fn sub_imm(raw: u32) -> Option<(u8, u8, u64)> {
    if raw & 0xFF00_0000 != 0xD100_0000 {
        return None;
    }
    let shift: u32 = (raw >> 22) & 0x3;
    if shift > 1 {
        return None;
    }
    let imm12: u64 = u64::from((raw >> 10) & 0xFFF);
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rd: u8 = (raw & 0x1F) as u8;
    Some((rd, rn, imm12 << (shift * 12)))
}

fn ldur_signed(raw: u32) -> Option<(u8, u8, i64)> {
    let sized: bool = raw & 0xFFE0_0C00 == 0xF840_0000 || raw & 0xFFE0_0C00 == 0xB840_0000;
    if !sized {
        return None;
    }
    let imm9: u32 = (raw >> 12) & 0x1FF;
    let signed: i64 = if imm9 & 0x100 != 0 {
        i64::from(imm9) - 512
    } else {
        i64::from(imm9)
    };
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rt: u8 = (raw & 0x1F) as u8;
    Some((rt, rn, signed))
}

fn ldr_float_pool(raw: u32) -> Option<(u8, u8, u64)> {
    if raw & 0xFFC0_0000 != 0xFD40_0000 {
        return None;
    }
    let imm12: u64 = u64::from((raw >> 10) & 0xFFF);
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rt: u8 = (raw & 0x1F) as u8;
    Some((rt, rn, imm12 * STACK_SLOT_BYTES))
}

fn fmov_double(raw: u32) -> Option<(u8, u64)> {
    let bits: u64 = fmov_double_immediate(raw)?;
    Some(((raw & 0x1F) as u8, bits))
}

fn store_to_stack(raw: u32) -> Option<(u8, u8, u64)> {
    if raw & 0xFFC0_0000 == 0xF900_0000 {
        let imm12: u64 = u64::from((raw >> 10) & 0xFFF);
        let rn: u8 = ((raw >> 5) & 0x1F) as u8;
        let rt: u8 = (raw & 0x1F) as u8;
        return Some((rt, rn, imm12 * STACK_SLOT_BYTES));
    }
    if raw & 0xFFE0_0C00 == 0xF800_0000 {
        let imm9: u32 = (raw >> 12) & 0x1FF;
        if imm9 & 0x100 != 0 {
            return None;
        }
        let rn: u8 = ((raw >> 5) & 0x1F) as u8;
        let rt: u8 = (raw & 0x1F) as u8;
        return Some((rt, rn, u64::from(imm9)));
    }
    None
}

fn stp_offset(raw: u32) -> Option<(u8, u8, u8, u64)> {
    if raw & 0xFFC0_0000 != 0xA900_0000 {
        return None;
    }
    let imm7: u32 = (raw >> 15) & 0x7F;
    if imm7 & 0x40 != 0 {
        return None;
    }
    let rt2: u8 = ((raw >> 10) & 0x1F) as u8;
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rt: u8 = (raw & 0x1F) as u8;
    Some((rt, rt2, rn, u64::from(imm7) * STACK_SLOT_BYTES))
}

fn adrp(raw: u32, address: u64) -> Option<(u8, u64)> {
    if raw & 0x9F00_0000 != 0x9000_0000 {
        return None;
    }
    let immlo: u64 = u64::from((raw >> 29) & 0x3);
    let immhi: u64 = u64::from((raw >> 5) & 0x7FFFF);
    let combined: u64 = (immhi << 2) | immlo;
    let signed: i64 = if combined & (1 << 20) != 0 {
        (combined as i64) - (1 << 21)
    } else {
        combined as i64
    };
    let page: u64 = (address & !0xFFF).wrapping_add_signed(signed.saturating_mul(0x1000));
    Some(((raw & 0x1F) as u8, page))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use crate::flutter::disasm::disassemble_range;

    use super::*;

    #[test]
    fn decodes_a_real_register_move() {
        assert_eq!(mov_register(0xaa0f03fd), Some((29, 15)));
        assert_eq!(mov_register(0xaa1603e1), Some((1, 22)));
        assert_eq!(mov_register(0xd503201f), None);
    }

    #[test]
    fn decodes_only_exact_dart_compressed_pointer_decompression() {
        assert_eq!(compressed_pointer_decompression(0x8b1c_8000), Some(0));
        assert_eq!(compressed_pointer_decompression(0x8b1c_8021), Some(1));
        assert_eq!(compressed_pointer_decompression(0x8b1b_8000), None);
        assert_eq!(compressed_pointer_decompression(0x8b1c_7c00), None);
        assert_eq!(compressed_pointer_decompression(0x8b1c_8001), None);
        assert_eq!(compressed_pointer_decompression(0xab1c_8000), None);
        assert_eq!(compressed_pointer_decompression(0x0b1c_8000), None);
    }

    #[test]
    fn decodes_a_real_subtract_immediate() {
        assert_eq!(sub_imm(0xd1000401), Some((1, 0, 1)));
        assert_eq!(sub_imm(0xd1000801), Some((1, 0, 2)));
    }

    #[test]
    fn decodes_a_real_unscaled_field_load() {
        assert_eq!(ldur_signed(0xb8407020), Some((0, 1, 7)));
        assert_eq!(ldur_signed(0xf85f83a1), Some((1, 29, -8)));
    }

    #[test]
    fn decodes_a_real_float_pool_load() {
        assert_eq!(ldr_float_pool(0xfd6b9b60), Some((0, 27, 0x5730)));
    }

    #[test]
    fn decodes_a_real_stack_store_and_pair() {
        assert_eq!(store_to_stack(0xf90001e0), Some((0, 15, 0)));
        assert_eq!(stp_offset(0xa90041fe), Some((30, 16, 15, 0)));
        assert_eq!(
            stp_offset(0xa9bf79fd),
            None,
            "the pre-index prologue push is not an argument store"
        );
    }

    #[test]
    fn true_and_false_come_from_the_null_register_offsets() {
        let state: TrackState = TrackState::default();
        assert_eq!(
            offset_of(&state, DART_NULL_REGISTER, 0x20),
            Some(DartValue::Bool(true))
        );
        assert_eq!(
            offset_of(&state, DART_NULL_REGISTER, 0x30),
            Some(DartValue::Bool(false))
        );
        assert_eq!(offset_of(&state, DART_NULL_REGISTER, 0x40), None);
    }

    #[test]
    fn declared_parameter_count_bounds_entry_registers() {
        let one: TrackState = TrackState::entry(Some(1));
        assert_eq!(
            one.integers.get(&DART_ARGUMENT_REGISTERS[0]),
            Some(&DartValue::Param(0))
        );
        assert_eq!(one.integers.get(&DART_ARGUMENT_REGISTERS[1]), None);

        let many: TrackState = TrackState::entry(Some(u8::MAX));
        assert_eq!(many.integers.len(), DART_ARGUMENT_REGISTERS.len());
    }

    #[test]
    fn decodes_every_conditional_select_variant() {
        assert_eq!(
            conditional_select(0x9a82_0020),
            Some((ConditionalSelectKind::Select, 0, 1, 2, 0))
        );
        assert_eq!(
            conditional_select(0x9a82_0420),
            Some((ConditionalSelectKind::Increment, 0, 1, 2, 0))
        );
        assert_eq!(
            conditional_select(0xda82_0020),
            Some((ConditionalSelectKind::Invert, 0, 1, 2, 0))
        );
        assert_eq!(
            conditional_select(0xda82_0420),
            Some((ConditionalSelectKind::Negate, 0, 1, 2, 0))
        );
        assert_eq!(conditional_select(0xd65f_03c0), None);
    }

    #[test]
    fn shifted_compare_immediate_abstains_from_boolean_recovery() {
        let words: [u32; 7] = [
            0xf940_01e1,
            0xf840_b022,
            0xf140_045f,
            0x9100_82d0,
            0x9100_c2d1,
            0x9a91_d200,
            0xd65f_03c0,
        ];
        let bytes: Vec<u8> = words
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect::<Vec<u8>>();
        let function: Arm64Function =
            disassemble_range(&bytes, 0x1000, 0, bytes.len(), Some("shifted".to_owned()));

        assert_eq!(recover_boolean_return(&function, None), None);
    }

    #[test]
    fn unrelated_faulting_load_abstains_from_boolean_recovery() {
        let words: [u32; 8] = [
            0xf940_01e1,
            0x9100_82d0,
            0x9100_c2d1,
            0xf840_b022,
            0xf100_005f,
            0xf940_0083,
            0x9a91_d200,
            0xd65f_03c0,
        ];
        let bytes: Vec<u8> = words
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect::<Vec<u8>>();
        let function: Arm64Function = disassemble_range(
            &bytes,
            0x1000,
            0,
            bytes.len(),
            Some("faulting-load".to_owned()),
        );

        assert_eq!(recover_boolean_return(&function, None), None);
    }
}
