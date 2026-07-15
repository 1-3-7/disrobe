use std::collections::{BTreeMap, BTreeSet, VecDeque};

use disrobe_nir::{
    CallOtherEffect, DefUse, NirClass, NirFunction, NirInstr, NirOp, ValueId, ValueOp,
    basic_blocks, def_use,
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
