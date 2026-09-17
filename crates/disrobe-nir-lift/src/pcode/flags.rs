use std::collections::{BTreeMap, BTreeSet, VecDeque};

use disrobe_nir::{
    CallOtherEffect, DefUse, NirBlock, NirClass, NirFunction, NirInstr, NirOp, SourceRef, ValueId,
    ValueOp, basic_blocks, def_use,
};

use super::varnode::RegisterCell;

type DefinitionRecord = (usize, usize);

const MAX_REACHING_ANALYSIS_ELEMENTS: usize = 8_388_608;

#[derive(Debug)]
struct ReachingDefinitions {
    block_instructions: Vec<Vec<usize>>,
    predecessors: Vec<Vec<usize>>,
    successors: Vec<Vec<usize>>,
    locations: Vec<Option<(usize, usize)>>,
    definitions: Vec<BTreeMap<String, Vec<DefinitionRecord>>>,
    wildcard_definitions: Vec<Vec<DefinitionRecord>>,
    all_definitions: BTreeMap<String, BTreeSet<usize>>,
    all_wildcard_definitions: BTreeSet<usize>,
    entry_cache: BTreeMap<String, Vec<BTreeSet<usize>>>,
    conservative_names: BTreeSet<String>,
    remaining_analysis_elements: usize,
    register_names: BTreeSet<String>,
}

impl ReachingDefinitions {
    fn new(
        instructions: &[NirInstr],
        flows: &[DefUse],
        register_names: &BTreeSet<String>,
    ) -> Option<Self> {
        let first: &NirInstr = instructions.first()?;
        let function_end: u64 = instructions
            .iter()
            .map(|instruction: &NirInstr| instruction.address.saturating_add(1))
            .max()
            .unwrap_or(first.address);
        let function: NirFunction = NirFunction {
            name: String::new(),
            address: first.address,
            end: function_end,
            is_export: false,
            instructions: instructions.to_vec(),
            source: first.source.clone(),
        };
        let blocks: Vec<disrobe_nir::NirBlock> = basic_blocks(&function);
        let mut sorted_indices: Vec<usize> = (0..instructions.len()).collect();
        sorted_indices.sort_by_key(|index: &usize| instructions[*index].address);
        let mut block_instructions: Vec<Vec<usize>> = Vec::with_capacity(blocks.len());
        let mut locations: Vec<Option<(usize, usize)>> = vec![None; instructions.len()];
        let mut cursor: usize = 0;
        for (block_index, block) in blocks.iter().enumerate() {
            let next_cursor: usize = cursor.checked_add(block.instructions.len())?;
            let indices: Vec<usize> = sorted_indices.get(cursor..next_cursor)?.to_vec();
            for (position, instruction_index) in indices.iter().copied().enumerate() {
                let location: &mut Option<(usize, usize)> = locations.get_mut(instruction_index)?;
                *location = Some((block_index, position));
            }
            block_instructions.push(indices);
            cursor = next_cursor;
        }
        if cursor != sorted_indices.len() || locations.iter().any(Option::is_none) {
            return None;
        }
        let block_by_start: BTreeMap<u64, usize> = blocks
            .iter()
            .enumerate()
            .map(|(index, block): (usize, &disrobe_nir::NirBlock)| (block.start, index))
            .collect();
        let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
        let mut successors: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
        for (block_index, block) in blocks.iter().enumerate() {
            for successor in &block.successors {
                let Some(successor_index): Option<&usize> = block_by_start.get(successor) else {
                    continue;
                };
                predecessors.get_mut(*successor_index)?.push(block_index);
                successors.get_mut(block_index)?.push(*successor_index);
            }
        }
        for block_predecessors in &mut predecessors {
            block_predecessors.sort_unstable();
            block_predecessors.dedup();
        }
        for block_successors in &mut successors {
            block_successors.sort_unstable();
            block_successors.dedup();
        }
        let mut definitions: Vec<BTreeMap<String, Vec<DefinitionRecord>>> =
            vec![BTreeMap::new(); blocks.len()];
        let mut wildcard_definitions: Vec<Vec<DefinitionRecord>> = vec![Vec::new(); blocks.len()];
        let mut all_definitions: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
        let mut all_wildcard_definitions: BTreeSet<usize> = BTreeSet::new();
        for (block_index, indices) in block_instructions.iter().enumerate() {
            for (position, instruction_index) in indices.iter().copied().enumerate() {
                let flow: &DefUse = flows.get(instruction_index)?;
                for definition in &flow.defs {
                    let ValueId::Register(name) = definition else {
                        continue;
                    };
                    let record: DefinitionRecord = (position, instruction_index);
                    if name == "*" {
                        wildcard_definitions.get_mut(block_index)?.push(record);
                        all_wildcard_definitions.insert(instruction_index);
                    } else {
                        definitions
                            .get_mut(block_index)?
                            .entry(name.clone())
                            .or_default()
                            .push(record);
                        all_definitions
                            .entry(name.clone())
                            .or_default()
                            .insert(instruction_index);
                    }
                }
            }
        }
        Some(Self {
            block_instructions,
            predecessors,
            successors,
            locations,
            definitions,
            wildcard_definitions,
            all_definitions,
            all_wildcard_definitions,
            entry_cache: BTreeMap::new(),
            conservative_names: BTreeSet::new(),
            remaining_analysis_elements: MAX_REACHING_ANALYSIS_ELEMENTS,
            register_names: register_names.clone(),
        })
    }

    fn producers(&mut self, instruction_index: usize, name: &str) -> BTreeSet<usize> {
        let Some((block_index, position)): Option<(usize, usize)> =
            self.locations.get(instruction_index).copied().flatten()
        else {
            return BTreeSet::new();
        };
        let producer: Option<usize> = self.latest_before(block_index, name, position);
        if let Some(producer) = producer {
            return BTreeSet::from([producer]);
        }
        self.entry_producers(block_index, name)
    }

    fn entry_producers(&mut self, block_index: usize, name: &str) -> BTreeSet<usize> {
        let cached: Option<BTreeSet<usize>> = self
            .entry_cache
            .get(name)
            .and_then(|entries: &Vec<BTreeSet<usize>>| entries.get(block_index))
            .cloned();
        if let Some(cached) = cached {
            return cached;
        }
        let possible: BTreeSet<usize> = self.possible_producers(name);
        if possible.len() <= 1 || self.conservative_names.contains(name) {
            return possible;
        }
        if !self.entry_cache.contains_key(name) {
            let entries: Option<Vec<BTreeSet<usize>>> = self.compute_entries(name);
            let Some(entries): Option<Vec<BTreeSet<usize>>> = entries else {
                self.conservative_names.insert(name.to_owned());
                return possible;
            };
            self.entry_cache.insert(name.to_owned(), entries);
        }
        self.entry_cache
            .get(name)
            .and_then(|entries: &Vec<BTreeSet<usize>>| entries.get(block_index))
            .cloned()
            .unwrap_or(possible)
    }

    fn compute_entries(&mut self, name: &str) -> Option<Vec<BTreeSet<usize>>> {
        let block_count: usize = self.block_instructions.len();
        let mut entries: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); block_count];
        let mut exits: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); block_count];
        let mut pending: VecDeque<usize> = (0..block_count).collect();
        let mut queued: Vec<bool> = vec![true; block_count];
        while let Some(block_index) = pending.pop_front() {
            let queued_entry: &mut bool = queued.get_mut(block_index)?;
            *queued_entry = false;
            let predecessors: &Vec<usize> = self.predecessors.get(block_index)?;
            let merge_cost: usize =
                predecessors
                    .iter()
                    .try_fold(1_usize, |cost: usize, predecessor: &usize| {
                        let definitions: &BTreeSet<usize> = exits.get(*predecessor)?;
                        cost.checked_add(definitions.len())
                    })?;
            if merge_cost > self.remaining_analysis_elements {
                return None;
            }
            self.remaining_analysis_elements =
                self.remaining_analysis_elements.saturating_sub(merge_cost);
            let mut next_entry: BTreeSet<usize> = BTreeSet::new();
            for predecessor in predecessors {
                let definitions: &BTreeSet<usize> = exits.get(*predecessor)?;
                next_entry.extend(definitions.iter().copied());
            }
            let block_length: usize = self.block_instructions.get(block_index).map_or(0, Vec::len);
            let next_exit: BTreeSet<usize> = self
                .latest_before(block_index, name, block_length)
                .map_or_else(
                    || next_entry.clone(),
                    |producer: usize| BTreeSet::from([producer]),
                );
            let exit_changed: bool = exits.get(block_index) != Some(&next_exit);
            let entry: &mut BTreeSet<usize> = entries.get_mut(block_index)?;
            *entry = next_entry;
            if !exit_changed {
                continue;
            }
            let exit: &mut BTreeSet<usize> = exits.get_mut(block_index)?;
            *exit = next_exit;
            for successor in self.successors.get(block_index)? {
                let successor_queued: &mut bool = queued.get_mut(*successor)?;
                if !*successor_queued {
                    pending.push_back(*successor);
                    *successor_queued = true;
                }
            }
        }
        Some(entries)
    }

    fn possible_producers(&self, name: &str) -> BTreeSet<usize> {
        let mut producers: BTreeSet<usize> =
            self.all_definitions.get(name).cloned().unwrap_or_default();
        if self.register_names.contains(name) {
            producers.extend(self.all_wildcard_definitions.iter().copied());
        }
        producers
    }

    fn latest_before(&self, block_index: usize, name: &str, position: usize) -> Option<usize> {
        let normal: Option<DefinitionRecord> = self
            .definitions
            .get(block_index)
            .and_then(|by_name: &BTreeMap<String, Vec<DefinitionRecord>>| by_name.get(name))
            .and_then(|records: &Vec<DefinitionRecord>| last_before(records, position));
        let wildcard: Option<DefinitionRecord> = if self.register_names.contains(name) {
            self.wildcard_definitions
                .get(block_index)
                .and_then(|records: &Vec<DefinitionRecord>| last_before(records, position))
        } else {
            None
        };
        match (normal, wildcard) {
            (Some(left), Some(right)) => Some(if left.0 >= right.0 { left.1 } else { right.1 }),
            (Some(record), None) | (None, Some(record)) => Some(record.1),
            (None, None) => None,
        }
    }
}

fn last_before(records: &[DefinitionRecord], position: usize) -> Option<DefinitionRecord> {
    let split: usize = records.partition_point(|record: &DefinitionRecord| record.0 < position);
    split
        .checked_sub(1)
        .and_then(|index: usize| records.get(index).copied())
}

pub(super) fn callother_effect(
    name: &str,
    reads: Vec<String>,
    writes: Vec<String>,
    x86_contracts: bool,
) -> CallOtherEffect {
    if !x86_contracts || !name.starts_with("x86_") {
        return CallOtherEffect {
            name: name.to_owned(),
            reads,
            writes,
            reads_memory: true,
            writes_memory: true,
            unknown_registers: true,
        };
    }
    let pure: bool = name.contains("_pure_");
    let side_effecting: bool = name.contains("_side_effecting_");
    let reads_writes_memory: bool = name.contains("_reads_writes_mem_");
    let reads_memory: bool = reads_writes_memory || name.contains("_reads_mem_");
    let writes_memory: bool = reads_writes_memory || name.contains("_writes_mem_");
    let classified: bool =
        pure || reads_memory || writes_memory || name.starts_with("x86_undefined_flag_");
    CallOtherEffect {
        name: name.to_owned(),
        reads,
        writes,
        reads_memory: reads_memory || side_effecting || !classified,
        writes_memory: writes_memory || side_effecting || !classified,
        unknown_registers: side_effecting || !classified,
    }
}

pub(super) fn eliminate_dead_values(
    instructions: Vec<NirInstr>,
    registers: &[RegisterCell],
    discarded_registers: &BTreeSet<String>,
) -> Vec<NirInstr> {
    if discarded_registers.is_empty() {
        return instructions;
    }
    let anchors: BTreeMap<u64, NirInstr> = control_flow_anchors(&instructions);
    let register_names: BTreeSet<String> = registers
        .iter()
        .map(|cell: &RegisterCell| cell.name.to_ascii_lowercase())
        .collect();
    if instructions
        .iter()
        .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::Branch { target: None }))
    {
        return instructions;
    }
    let flows: Vec<DefUse> = instructions.iter().map(def_use).collect();
    let Some(mut reaching): Option<ReachingDefinitions> =
        ReachingDefinitions::new(&instructions, &flows, &register_names)
    else {
        return instructions;
    };
    let mut retained: BTreeSet<usize> = BTreeSet::new();
    let mut pending: VecDeque<usize> = VecDeque::new();
    let mut remaining_dependency_edges: usize = MAX_REACHING_ANALYSIS_ELEMENTS;
    for (index, instruction) in instructions.iter().enumerate() {
        if instruction_has_effect(instruction)
            || defines_observable_register(instruction, &register_names, discarded_registers)
        {
            retained.insert(index);
            pending.push_back(index);
        }
    }
    while let Some(index) = pending.pop_front() {
        let Some(flow): Option<&DefUse> = flows.get(index) else {
            continue;
        };
        for usage in &flow.uses {
            let ValueId::Register(name) = usage else {
                continue;
            };
            let producers: BTreeSet<usize> = if name == "*" {
                let mut wildcard_producers: BTreeSet<usize> = BTreeSet::new();
                for register_name in &register_names {
                    wildcard_producers.extend(reaching.producers(index, register_name));
                }
                wildcard_producers
            } else {
                reaching.producers(index, name)
            };
            if producers.len() > remaining_dependency_edges {
                return instructions;
            }
            remaining_dependency_edges = remaining_dependency_edges.saturating_sub(producers.len());
            for producer in producers {
                if retained.insert(producer) {
                    pending.push_back(producer);
                }
            }
        }
    }
    let eliminated: Vec<NirInstr> = instructions
        .into_iter()
        .enumerate()
        .filter_map(|(index, instruction): (usize, NirInstr)| {
            retained.contains(&index).then_some(instruction)
        })
        .collect();
    preserve_control_flow_anchors(eliminated, anchors)
}

fn control_flow_anchors(instructions: &[NirInstr]) -> BTreeMap<u64, NirInstr> {
    let available_addresses: BTreeSet<u64> = instructions
        .iter()
        .map(|instruction: &NirInstr| instruction.address)
        .collect();
    let mut required_addresses: BTreeSet<u64> = BTreeSet::new();
    let first: Option<&NirInstr> = instructions.first();
    if let Some(first) = first {
        required_addresses.insert(first.address);
    }
    for instruction in instructions {
        if !matches!(
            instruction.class(),
            NirClass::ConditionalJump | NirClass::UnconditionalJump
        ) {
            continue;
        }
        let Some(target): Option<u64> = instruction.direct_target() else {
            continue;
        };
        if available_addresses.contains(&target) {
            required_addresses.insert(target);
        }
    }
    let mut anchors: BTreeMap<u64, NirInstr> = BTreeMap::new();
    for instruction in instructions {
        if required_addresses.contains(&instruction.address) {
            anchors
                .entry(instruction.address)
                .or_insert_with(|| instruction.clone());
        }
    }
    anchors
}

fn preserve_control_flow_anchors(
    mut instructions: Vec<NirInstr>,
    anchors: BTreeMap<u64, NirInstr>,
) -> Vec<NirInstr> {
    let retained_addresses: BTreeSet<u64> = instructions
        .iter()
        .map(|instruction: &NirInstr| instruction.address)
        .collect();
    for (address, mut anchor) in anchors {
        if retained_addresses.contains(&address) {
            continue;
        }
        anchor.op = NirOp::Nop;
        "NOP".clone_into(&mut anchor.mnemonic);
        anchor.operands.clear();
        anchor.reads_memory = false;
        anchor.writes_memory = false;
        anchor.byte_width = false;
        instructions.push(anchor);
    }
    instructions.sort_by_key(|instruction: &NirInstr| instruction.address);
    instructions
}

fn defines_observable_register(
    instruction: &NirInstr,
    register_names: &BTreeSet<String>,
    discarded_registers: &BTreeSet<String>,
) -> bool {
    def_use(instruction)
        .defs
        .iter()
        .any(|definition: &ValueId| {
            let ValueId::Register(name) = definition else {
                return false;
            };
            register_names.contains(name) && !discarded_registers.contains(name)
        })
}

const fn instruction_has_effect(instruction: &NirInstr) -> bool {
    match &instruction.op {
        NirOp::Copy { .. }
        | NirOp::Subpiece { .. }
        | NirOp::Deposit { .. }
        | NirOp::Piece { .. } => false,
        NirOp::Value { op, .. } => value_may_trap(*op),
        NirOp::CallOther { effect } => {
            effect.reads_memory || effect.writes_memory || effect.unknown_registers
        }
        NirOp::RawLoad { .. }
        | NirOp::RawStore { .. }
        | NirOp::Nop
        | NirOp::Const
        | NirOp::BinOp { .. }
        | NirOp::Load
        | NirOp::Store
        | NirOp::Call { .. }
        | NirOp::NoReturnCall { .. }
        | NirOp::TailCall { .. }
        | NirOp::IndirectCall
        | NirOp::ExternCall { .. }
        | NirOp::Branch { .. }
        | NirOp::CondBranch { .. }
        | NirOp::Phi
        | NirOp::Return
        | NirOp::Interrupt
        | NirOp::Unmodeled { .. } => true,
    }
}

const fn value_may_trap(op: ValueOp) -> bool {
    matches!(
        op,
        ValueOp::FloatAdd
            | ValueOp::FloatDiv
            | ValueOp::FloatEqual
            | ValueOp::FloatLess
            | ValueOp::FloatLessEqual
            | ValueOp::FloatMult
            | ValueOp::FloatSqrt
            | ValueOp::FloatSub
            | ValueOp::FloatToFloat
            | ValueOp::FloatTrunc
            | ValueOp::IntToFloat
            | ValueOp::IntDiv
            | ValueOp::IntRem
            | ValueOp::IntSignedDiv
            | ValueOp::IntSignedRem
    )
}

const MAX_FOLD_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CmpTerm {
    Eq,
    Ne,
    UnsignedLess,
    UnsignedLessEqual,
    UnsignedGreater,
    UnsignedGreaterEqual,
    SignedLess,
    SignedLessEqual,
    SignedGreater,
    SignedGreaterEqual,
    SignBit,
    OverflowBit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompareKey {
    left: String,
    right: String,
    width: u32,
}

#[derive(Clone, Debug)]
struct ResolvedCondition {
    term: CmpTerm,
    compare: CompareKey,
    earliest_read: usize,
}

pub(super) fn fold_condition_codes(
    instructions: Vec<NirInstr>,
    registers: &[RegisterCell],
) -> Vec<NirInstr> {
    if instructions.is_empty() {
        return instructions;
    }
    let function: NirFunction = fold_scratch_function(&instructions);
    let blocks: Vec<NirBlock> = basic_blocks(&function);
    let mut sorted: Vec<NirInstr> = instructions.clone();
    sorted.sort_by_key(|instruction: &NirInstr| instruction.address);
    let block_addresses: Vec<u64> = blocks
        .iter()
        .flat_map(|block: &NirBlock| {
            block
                .instructions
                .iter()
                .map(|item: &NirInstr| item.address)
        })
        .collect();
    let sorted_addresses: Vec<u64> = sorted
        .iter()
        .map(|instruction: &NirInstr| instruction.address)
        .collect();
    if block_addresses != sorted_addresses {
        return instructions;
    }
    let mut next_temp: u64 = fresh_temp_base(&sorted, registers);
    let mut out: Vec<NirInstr> = Vec::with_capacity(sorted.len().saturating_add(blocks.len()));
    for block in &blocks {
        match fold_conditional_block(&block.instructions, &mut next_temp) {
            Some(folded) => out.extend(folded),
            None => out.extend(block.instructions.iter().cloned()),
        }
    }
    out
}

fn fold_scratch_function(instructions: &[NirInstr]) -> NirFunction {
    let first: Option<&NirInstr> = instructions.first();
    let address: u64 = first.map_or(0, |instruction: &NirInstr| instruction.address);
    let end: u64 = instructions
        .iter()
        .map(|instruction: &NirInstr| instruction.address.saturating_add(1))
        .max()
        .unwrap_or(address);
    NirFunction {
        name: String::new(),
        address,
        end,
        is_export: false,
        instructions: instructions.to_vec(),
        source: first.map_or_else(SourceRef::default, |instruction: &NirInstr| {
            instruction.source.clone()
        }),
    }
}

fn fold_conditional_block(block: &[NirInstr], next_temp: &mut u64) -> Option<Vec<NirInstr>> {
    let cbranch_index: usize = block.len().checked_sub(1)?;
    let cbranch: &NirInstr = block.get(cbranch_index)?;
    if !matches!(cbranch.op, NirOp::CondBranch { .. }) {
        return None;
    }
    let condition: &String = cbranch.operands.first()?;
    let context: BlockContext = BlockContext::build(block);
    let resolved: ResolvedCondition = context.resolve(condition, 0)?;
    let (op, swap): (ValueOp, bool) = comparison_for(resolved.term)?;
    let (left, right): (String, String) = if swap {
        (resolved.compare.right, resolved.compare.left)
    } else {
        (resolved.compare.left, resolved.compare.right)
    };
    if redefines_operand(block, resolved.earliest_read, cbranch_index, &left, &right) {
        return None;
    }
    let fresh: String = format!("t{next_temp}");
    *next_temp = next_temp.saturating_add(1);
    let comparison: NirInstr = NirInstr {
        address: cbranch.address,
        op: NirOp::Value {
            op,
            inputs: vec![left.clone(), right.clone()],
            input_sizes: vec![resolved.compare.width, resolved.compare.width],
            size: 1,
        },
        mnemonic: op.mnemonic().to_owned(),
        operands: vec![fresh.clone(), left, right],
        reads_memory: false,
        writes_memory: false,
        byte_width: false,
        source: cbranch.source.clone(),
    };
    let mut folded: Vec<NirInstr> = Vec::with_capacity(block.len().saturating_add(1));
    folded.extend(block.get(..cbranch_index)?.iter().cloned());
    folded.push(comparison);
    let mut rewritten: NirInstr = cbranch.clone();
    rewritten.operands = vec![fresh];
    folded.push(rewritten);
    Some(folded)
}

#[derive(Debug)]
struct BlockContext<'a> {
    block: &'a [NirInstr],
    definition_counts: BTreeMap<String, usize>,
    value_definitions: BTreeMap<String, usize>,
}

impl<'a> BlockContext<'a> {
    fn build(block: &'a [NirInstr]) -> Self {
        let mut definition_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut value_definitions: BTreeMap<String, usize> = BTreeMap::new();
        for (index, instruction) in block.iter().enumerate() {
            for name in defined_names(instruction) {
                let key: String = name.to_ascii_lowercase();
                *definition_counts.entry(key.clone()).or_insert(0) += 1;
                if matches!(instruction.op, NirOp::Value { .. }) {
                    value_definitions.insert(key, index);
                }
            }
        }
        Self {
            block,
            definition_counts,
            value_definitions,
        }
    }

    fn value_definition(&self, name: &str) -> Option<(usize, ValueOp, &'a [String], &'a [u32])> {
        let key: String = name.to_ascii_lowercase();
        if self.definition_counts.get(&key).copied() != Some(1) {
            return None;
        }
        let index: usize = *self.value_definitions.get(&key)?;
        match &self.block.get(index)?.op {
            NirOp::Value {
                op,
                inputs,
                input_sizes,
                ..
            } => Some((index, *op, inputs.as_slice(), input_sizes.as_slice())),
            _ => None,
        }
    }

    fn resolve(&self, name: &str, depth: usize) -> Option<ResolvedCondition> {
        if depth > MAX_FOLD_DEPTH {
            return None;
        }
        let (index, op, inputs, sizes): (usize, ValueOp, &[String], &[u32]) =
            self.value_definition(name)?;
        match op {
            ValueOp::IntEqual => {
                if is_zero_operand(inputs.get(1)?) {
                    let (read_index, compare): (usize, CompareKey) =
                        self.resolve_subtraction(inputs.first()?)?;
                    return Some(ResolvedCondition {
                        term: CmpTerm::Eq,
                        compare,
                        earliest_read: read_index,
                    });
                }
                let equality: ResolvedCondition = self.combine(inputs, depth, combine_xor)?;
                Some(ResolvedCondition {
                    term: negate_term(equality.term)?,
                    compare: equality.compare,
                    earliest_read: equality.earliest_read,
                })
            }
            ValueOp::IntNotEqual => {
                if is_zero_operand(inputs.get(1)?) {
                    let (read_index, compare): (usize, CompareKey) =
                        self.resolve_subtraction(inputs.first()?)?;
                    return Some(ResolvedCondition {
                        term: CmpTerm::Ne,
                        compare,
                        earliest_read: read_index,
                    });
                }
                self.combine(inputs, depth, combine_xor)
            }
            ValueOp::IntSignedLess => {
                if !is_zero_operand(inputs.get(1)?) {
                    return None;
                }
                let (read_index, compare): (usize, CompareKey) =
                    self.resolve_subtraction(inputs.first()?)?;
                Some(ResolvedCondition {
                    term: CmpTerm::SignBit,
                    compare,
                    earliest_read: read_index,
                })
            }
            ValueOp::IntSignedBorrow => Some(ResolvedCondition {
                term: CmpTerm::OverflowBit,
                compare: CompareKey {
                    left: inputs.first()?.clone(),
                    right: inputs.get(1)?.clone(),
                    width: *sizes.first()?,
                },
                earliest_read: index,
            }),
            ValueOp::IntLess => Some(ResolvedCondition {
                term: CmpTerm::UnsignedLess,
                compare: CompareKey {
                    left: inputs.first()?.clone(),
                    right: inputs.get(1)?.clone(),
                    width: *sizes.first()?,
                },
                earliest_read: index,
            }),
            ValueOp::BoolNegate => {
                let inner: ResolvedCondition = self.resolve(inputs.first()?, depth + 1)?;
                Some(ResolvedCondition {
                    term: negate_term(inner.term)?,
                    compare: inner.compare,
                    earliest_read: inner.earliest_read,
                })
            }
            ValueOp::BoolXor => self.combine(inputs, depth, combine_xor),
            ValueOp::BoolOr => self.combine(inputs, depth, combine_or),
            ValueOp::BoolAnd => self.combine(inputs, depth, combine_and),
            _ => None,
        }
    }

    fn resolve_subtraction(&self, name: &str) -> Option<(usize, CompareKey)> {
        let (index, op, inputs, sizes): (usize, ValueOp, &[String], &[u32]) =
            self.value_definition(name)?;
        if op != ValueOp::IntSub {
            return None;
        }
        Some((
            index,
            CompareKey {
                left: inputs.first()?.clone(),
                right: inputs.get(1)?.clone(),
                width: *sizes.first()?,
            },
        ))
    }

    fn combine(
        &self,
        inputs: &[String],
        depth: usize,
        rule: fn(CmpTerm, CmpTerm) -> Option<CmpTerm>,
    ) -> Option<ResolvedCondition> {
        let left: ResolvedCondition = self.resolve(inputs.first()?, depth + 1)?;
        let right: ResolvedCondition = self.resolve(inputs.get(1)?, depth + 1)?;
        if left.compare != right.compare {
            return None;
        }
        let term: CmpTerm = rule(left.term, right.term)?;
        Some(ResolvedCondition {
            term,
            compare: left.compare,
            earliest_read: left.earliest_read.min(right.earliest_read),
        })
    }
}

fn defined_names(instruction: &NirInstr) -> Vec<String> {
    match &instruction.op {
        NirOp::Value { .. }
        | NirOp::Copy { .. }
        | NirOp::Subpiece { .. }
        | NirOp::RawLoad { .. }
        | NirOp::Piece { .. } => instruction.operands.first().cloned().into_iter().collect(),
        NirOp::Deposit { cell, .. } => vec![cell.clone()],
        NirOp::CallOther { effect } => effect.writes.clone(),
        NirOp::Nop
        | NirOp::Const
        | NirOp::BinOp { .. }
        | NirOp::Load
        | NirOp::Store
        | NirOp::Call { .. }
        | NirOp::NoReturnCall { .. }
        | NirOp::TailCall { .. }
        | NirOp::IndirectCall
        | NirOp::ExternCall { .. }
        | NirOp::Branch { .. }
        | NirOp::CondBranch { .. }
        | NirOp::Phi
        | NirOp::Return
        | NirOp::Interrupt
        | NirOp::RawStore { .. }
        | NirOp::Unmodeled { .. } => Vec::new(),
    }
}

fn redefines_operand(
    block: &[NirInstr],
    earliest_read: usize,
    cbranch_index: usize,
    left: &str,
    right: &str,
) -> bool {
    let targets: Vec<ValueId> = [left, right]
        .into_iter()
        .filter(|name: &&str| !is_operand_constant(name))
        .map(ValueId::register)
        .collect();
    if targets.is_empty() {
        return false;
    }
    let start: usize = earliest_read.saturating_add(1);
    for index in start..cbranch_index {
        let Some(instruction): Option<&NirInstr> = block.get(index) else {
            continue;
        };
        let flow: DefUse = def_use(instruction);
        if flow
            .defs
            .iter()
            .any(|definition: &ValueId| targets.contains(definition))
        {
            return true;
        }
    }
    false
}

const fn negate_term(term: CmpTerm) -> Option<CmpTerm> {
    Some(match term {
        CmpTerm::Eq => CmpTerm::Ne,
        CmpTerm::Ne => CmpTerm::Eq,
        CmpTerm::UnsignedLess => CmpTerm::UnsignedGreaterEqual,
        CmpTerm::UnsignedGreaterEqual => CmpTerm::UnsignedLess,
        CmpTerm::UnsignedLessEqual => CmpTerm::UnsignedGreater,
        CmpTerm::UnsignedGreater => CmpTerm::UnsignedLessEqual,
        CmpTerm::SignedLess => CmpTerm::SignedGreaterEqual,
        CmpTerm::SignedGreaterEqual => CmpTerm::SignedLess,
        CmpTerm::SignedLessEqual => CmpTerm::SignedGreater,
        CmpTerm::SignedGreater => CmpTerm::SignedLessEqual,
        CmpTerm::SignBit | CmpTerm::OverflowBit => return None,
    })
}

const fn combine_xor(left: CmpTerm, right: CmpTerm) -> Option<CmpTerm> {
    match (left, right) {
        (CmpTerm::SignBit, CmpTerm::OverflowBit) | (CmpTerm::OverflowBit, CmpTerm::SignBit) => {
            Some(CmpTerm::SignedLess)
        }
        _ => None,
    }
}

const fn combine_or(left: CmpTerm, right: CmpTerm) -> Option<CmpTerm> {
    match (left, right) {
        (CmpTerm::Eq, CmpTerm::SignedLess) | (CmpTerm::SignedLess, CmpTerm::Eq) => {
            Some(CmpTerm::SignedLessEqual)
        }
        (CmpTerm::Eq, CmpTerm::SignedGreater) | (CmpTerm::SignedGreater, CmpTerm::Eq) => {
            Some(CmpTerm::SignedGreaterEqual)
        }
        (CmpTerm::Eq, CmpTerm::UnsignedLess) | (CmpTerm::UnsignedLess, CmpTerm::Eq) => {
            Some(CmpTerm::UnsignedLessEqual)
        }
        (CmpTerm::Eq, CmpTerm::UnsignedGreater) | (CmpTerm::UnsignedGreater, CmpTerm::Eq) => {
            Some(CmpTerm::UnsignedGreaterEqual)
        }
        _ => None,
    }
}

const fn combine_and(left: CmpTerm, right: CmpTerm) -> Option<CmpTerm> {
    match (left, right) {
        (CmpTerm::UnsignedGreaterEqual, CmpTerm::Ne)
        | (CmpTerm::Ne, CmpTerm::UnsignedGreaterEqual) => Some(CmpTerm::UnsignedGreater),
        (CmpTerm::SignedGreaterEqual, CmpTerm::Ne) | (CmpTerm::Ne, CmpTerm::SignedGreaterEqual) => {
            Some(CmpTerm::SignedGreater)
        }
        (CmpTerm::UnsignedLessEqual, CmpTerm::Ne) | (CmpTerm::Ne, CmpTerm::UnsignedLessEqual) => {
            Some(CmpTerm::UnsignedLess)
        }
        (CmpTerm::SignedLessEqual, CmpTerm::Ne) | (CmpTerm::Ne, CmpTerm::SignedLessEqual) => {
            Some(CmpTerm::SignedLess)
        }
        _ => None,
    }
}

const fn comparison_for(term: CmpTerm) -> Option<(ValueOp, bool)> {
    Some(match term {
        CmpTerm::Eq => (ValueOp::IntEqual, false),
        CmpTerm::Ne => (ValueOp::IntNotEqual, false),
        CmpTerm::UnsignedLess => (ValueOp::IntLess, false),
        CmpTerm::UnsignedLessEqual => (ValueOp::IntLessEqual, false),
        CmpTerm::UnsignedGreater => (ValueOp::IntLess, true),
        CmpTerm::UnsignedGreaterEqual => (ValueOp::IntLessEqual, true),
        CmpTerm::SignedLess => (ValueOp::IntSignedLess, false),
        CmpTerm::SignedLessEqual => (ValueOp::IntSignedLessEqual, false),
        CmpTerm::SignedGreater => (ValueOp::IntSignedLess, true),
        CmpTerm::SignedGreaterEqual => (ValueOp::IntSignedLessEqual, true),
        CmpTerm::SignBit | CmpTerm::OverflowBit => return None,
    })
}

fn is_zero_operand(operand: &str) -> bool {
    let body: &str = operand.strip_prefix('-').unwrap_or(operand);
    if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        return !hex.is_empty() && hex.bytes().all(|byte: u8| byte == b'0');
    }
    !body.is_empty() && body.bytes().all(|byte: u8| byte == b'0')
}

fn is_operand_constant(operand: &str) -> bool {
    let body: &str = operand.strip_prefix('-').unwrap_or(operand);
    if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        return !hex.is_empty() && hex.bytes().all(|byte: u8| byte.is_ascii_hexdigit());
    }
    !body.is_empty() && body.bytes().all(|byte: u8| byte.is_ascii_digit())
}

fn fresh_temp_base(instructions: &[NirInstr], registers: &[RegisterCell]) -> u64 {
    let mut highest: Option<u64> = None;
    let mut consider = |name: &str| {
        if let Some(rest) = name.strip_prefix('t')
            && !rest.is_empty()
            && rest.bytes().all(|byte: u8| byte.is_ascii_digit())
            && let Ok(value) = rest.parse::<u64>()
        {
            highest = Some(highest.map_or(value, |current: u64| current.max(value)));
        }
    };
    for instruction in instructions {
        for operand in &instruction.operands {
            consider(operand);
        }
        for name in embedded_names(instruction) {
            consider(&name);
        }
    }
    for cell in registers {
        consider(&cell.name);
    }
    highest.map_or(0, |value: u64| value.saturating_add(1))
}

fn embedded_names(instruction: &NirInstr) -> Vec<String> {
    match &instruction.op {
        NirOp::Value { inputs, .. } => inputs.clone(),
        NirOp::Copy { src, .. } | NirOp::Subpiece { src, .. } => vec![src.clone()],
        NirOp::RawLoad { addr, .. } => vec![addr.clone()],
        NirOp::RawStore { addr, value, .. } => vec![addr.clone(), value.clone()],
        NirOp::Deposit { cell, value, .. } => vec![cell.clone(), value.clone()],
        NirOp::Piece { high, low, .. } => vec![high.clone(), low.clone()],
        NirOp::CallOther { effect } => effect
            .reads
            .iter()
            .chain(effect.writes.iter())
            .cloned()
            .collect(),
        NirOp::Nop
        | NirOp::Const
        | NirOp::BinOp { .. }
        | NirOp::Load
        | NirOp::Store
        | NirOp::Call { .. }
        | NirOp::NoReturnCall { .. }
        | NirOp::TailCall { .. }
        | NirOp::IndirectCall
        | NirOp::ExternCall { .. }
        | NirOp::Branch { .. }
        | NirOp::CondBranch { .. }
        | NirOp::Phi
        | NirOp::Return
        | NirOp::Interrupt
        | NirOp::Unmodeled { .. } => Vec::new(),
    }
}
