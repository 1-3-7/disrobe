use std::collections::{BTreeMap, BTreeSet};

use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue, SlotOp, slot_index_of};

pub type BlockId = usize;

#[derive(Debug, Clone)]
pub struct Block {
    pub start: u32,
    pub first: usize,
    pub last: usize,
}

#[derive(Debug, Clone)]
pub struct Dispatcher {
    pub state_local: u32,
    pub case_count: u32,
    pub switch_index: usize,
    pub switch_targets: Vec<u32>,
    pub header_entry: u32,
}

#[derive(Debug, Clone)]
pub struct BlockGraph {
    pub blocks: Vec<Block>,
    pub start_to_block: BTreeMap<u32, BlockId>,
    pub dispatcher: Dispatcher,
}

const MAX_BLOCKS: usize = 4096;

#[must_use]
pub fn absolute_target(ins: &Instruction, rel: i32, next_off: u32) -> u32 {
    let _ = ins;
    u32::try_from(i64::from(next_off) + i64::from(rel)).unwrap_or(next_off)
}

fn next_offset(body: &MethodBody, idx: usize) -> u32 {
    body.instructions
        .get(idx + 1)
        .map_or_else(|| body.code_size, |n: &Instruction| n.offset)
}

#[must_use]
pub fn find_dispatcher(body: &MethodBody) -> Option<Dispatcher> {
    let instrs: &[Instruction] = &body.instructions;
    for (idx, ins) in instrs.iter().enumerate() {
        if ins.name != "switch" {
            continue;
        }
        let OperandValue::Switch(ref rels) = ins.operand else {
            continue;
        };
        let Some((state_local, case_count)): Option<(u32, u32)> = match_header(instrs, idx) else {
            continue;
        };
        if case_count == 0 || rels.len() != case_count as usize {
            continue;
        }
        let next_off: u32 = next_offset(body, idx);
        let switch_targets: Vec<u32> = rels
            .iter()
            .map(|r: &i32| absolute_target(ins, *r, next_off))
            .collect();
        let header_entry: u32 = header_entry_offset(body, idx);
        return Some(Dispatcher {
            state_local,
            case_count,
            switch_index: idx,
            switch_targets,
            header_entry,
        });
    }
    None
}

fn header_entry_offset(body: &MethodBody, switch_idx: usize) -> u32 {
    let instrs: &[Instruction] = &body.instructions;
    let switch_off: u32 = instrs[switch_idx].offset;
    let dup_off: u32 =
        dup_before_state_store(instrs, switch_idx).map_or(switch_off, |i: usize| instrs[i].offset);
    let mut indegree: BTreeMap<u32, u32> = BTreeMap::new();
    for (idx, ins) in instrs.iter().enumerate() {
        if !matches!(ins.name.as_str(), "br" | "br.s") {
            continue;
        }
        let OperandValue::BrTarget(rel) = ins.operand else {
            continue;
        };
        let target: u32 = absolute_target(ins, rel, next_offset(body, idx));
        if target <= dup_off && target < switch_off {
            *indegree.entry(target).or_insert(0) += 1;
        }
    }
    indegree
        .into_iter()
        .max_by(|a: &(u32, u32), b: &(u32, u32)| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
        .map_or(dup_off, |(off, _count): (u32, u32)| off)
}

fn dup_before_state_store(instrs: &[Instruction], switch_idx: usize) -> Option<usize> {
    let mut store_idx: usize = switch_idx.checked_sub(3)?;
    if instrs.get(store_idx)?.name == "dup" {
        store_idx = store_idx.checked_sub(1)?;
    }
    let dup_idx: usize = store_idx.checked_sub(1)?;
    (instrs.get(dup_idx)?.name == "dup").then_some(dup_idx)
}

fn match_header(instrs: &[Instruction], switch_idx: usize) -> Option<(u32, u32)> {
    let rem: &Instruction = instrs.get(switch_idx.checked_sub(1)?)?;
    if !matches!(rem.name.as_str(), "rem.un") {
        return None;
    }
    let count_ins: &Instruction = instrs.get(switch_idx.checked_sub(2)?)?;
    let case_count: u32 = u32::try_from(int_literal(count_ins)?).ok()?;
    let mut store_idx: usize = switch_idx.checked_sub(3)?;
    let mut store: &Instruction = instrs.get(store_idx)?;
    if store.name == "dup" {
        store_idx = store_idx.checked_sub(1)?;
        store = instrs.get(store_idx)?;
    }
    let state_local: u32 = store_local(store)?;
    let dup_idx: usize = store_idx.checked_sub(1)?;
    if instrs.get(dup_idx)?.name != "dup" {
        return None;
    }
    Some((state_local, case_count))
}

fn store_local(ins: &Instruction) -> Option<u32> {
    slot_index_of(ins, SlotOp::StoreLocal).map(u32::from)
}

#[must_use]
pub fn int_literal(ins: &Instruction) -> Option<i64> {
    match ins.name.as_str() {
        "ldc.i4.0" => Some(0),
        "ldc.i4.1" => Some(1),
        "ldc.i4.2" => Some(2),
        "ldc.i4.3" => Some(3),
        "ldc.i4.4" => Some(4),
        "ldc.i4.5" => Some(5),
        "ldc.i4.6" => Some(6),
        "ldc.i4.7" => Some(7),
        "ldc.i4.8" => Some(8),
        "ldc.i4.m1" => Some(-1),
        "ldc.i4.s" => match ins.operand {
            OperandValue::U8(b) => Some(i64::from(b.cast_signed())),
            _ => None,
        },
        "ldc.i4" => match ins.operand {
            OperandValue::I32(v) => Some(i64::from(v)),
            _ => None,
        },
        _ => None,
    }
}

const KEY_PATH_STEP_CAP: usize = 4096;

fn instr_index(instrs: &[Instruction], offset: u32) -> Option<usize> {
    instrs
        .binary_search_by_key(&offset, |i: &Instruction| i.offset)
        .ok()
}

fn local_of(ins: &Instruction, prefix: &str) -> Option<u32> {
    let rest: &str = ins.name.as_str().strip_prefix(prefix)?;
    if !(rest.is_empty() || rest.starts_with('.')) {
        return None;
    }
    if let Some(tail) = rest.rsplit('.').next()
        && let Ok(n) = tail.parse::<u32>()
    {
        return Some(n);
    }
    match ins.operand {
        OperandValue::U8(b) => Some(u32::from(b)),
        OperandValue::U16(v) => Some(u32::from(v)),
        _ => None,
    }
}

fn is_pure_key_step(ins: &Instruction, state_local: u32) -> bool {
    let name: &str = ins.name.as_str();
    if name.starts_with("ldc.i4") || name.starts_with("conv.") {
        return true;
    }
    match name {
        "nop" | "break" | "dup" | "pop" | "add" | "add.ovf" | "add.ovf.un" | "sub" | "sub.ovf"
        | "sub.ovf.un" | "mul" | "mul.ovf" | "mul.ovf.un" | "div" | "div.un" | "rem" | "rem.un"
        | "and" | "or" | "xor" | "shl" | "shr" | "shr.un" | "neg" | "not" => true,
        _ => {
            local_of(ins, "ldloc") == Some(state_local)
                || local_of(ins, "stloc") == Some(state_local)
        }
    }
}

fn reaches_dispatcher_switch(body: &MethodBody, dispatcher: &Dispatcher, start_off: u32) -> bool {
    let instrs: &[Instruction] = &body.instructions;
    let header_idx: Option<usize> = instr_index(instrs, dispatcher.header_entry);
    let Some(mut idx): Option<usize> = instr_index(instrs, start_off) else {
        return false;
    };
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut steps: usize = 0;
    loop {
        steps += 1;
        if steps > KEY_PATH_STEP_CAP || !visited.insert(idx) {
            return false;
        }
        if idx == dispatcher.switch_index || Some(idx) == header_idx {
            return true;
        }
        let Some(ins): Option<&Instruction> = instrs.get(idx) else {
            return false;
        };
        match ins.flow {
            FlowControl::Branch => {
                let OperandValue::BrTarget(rel) = ins.operand else {
                    return false;
                };
                let target: u32 = absolute_target(ins, rel, next_offset(body, idx));
                let Some(next_idx): Option<usize> = instr_index(instrs, target) else {
                    return false;
                };
                idx = next_idx;
            }
            FlowControl::CondBranch | FlowControl::Return | FlowControl::Throw => return false,
            _ if !is_pure_key_step(ins, dispatcher.state_local) => return false,
            _ => idx += 1,
        }
    }
}

fn collect_leaders(body: &MethodBody, dispatcher: &Dispatcher) -> BTreeSet<u32> {
    let instrs: &[Instruction] = &body.instructions;
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    if let Some(first) = instrs.first() {
        leaders.insert(first.offset);
    }
    leaders.insert(dispatcher.header_entry);
    for t in &dispatcher.switch_targets {
        leaders.insert(*t);
    }
    for (idx, ins) in instrs.iter().enumerate() {
        let next_off: u32 = next_offset(body, idx);
        if matches!(ins.flow, FlowControl::Return | FlowControl::Throw) && next_off < body.code_size
        {
            leaders.insert(next_off);
        }
        if idx == dispatcher.switch_index {
            continue;
        }
        let (FlowControl::Branch | FlowControl::CondBranch, &OperandValue::BrTarget(rel)) =
            (ins.flow, &ins.operand)
        else {
            continue;
        };
        let target: u32 = absolute_target(ins, rel, next_off);
        if target < body.code_size && !reaches_dispatcher_switch(body, dispatcher, target) {
            leaders.insert(target);
        }
        if ins.flow == FlowControl::CondBranch
            && next_off < body.code_size
            && !reaches_dispatcher_switch(body, dispatcher, next_off)
        {
            leaders.insert(next_off);
        }
    }
    leaders
}

#[must_use]
pub fn build(body: &MethodBody) -> Option<BlockGraph> {
    let dispatcher: Dispatcher = find_dispatcher(body)?;
    let leaders: BTreeSet<u32> = collect_leaders(body, &dispatcher);
    let instrs: &[Instruction] = &body.instructions;
    if instrs.is_empty() {
        return None;
    }
    let mut blocks: Vec<Block> = Vec::new();
    let mut start_to_block: BTreeMap<u32, BlockId> = BTreeMap::new();
    let mut i: usize = 0;
    while i < instrs.len() {
        if blocks.len() >= MAX_BLOCKS {
            return None;
        }
        let start: u32 = instrs[i].offset;
        let first: usize = i;
        let mut last: usize = i;
        i += 1;
        while i < instrs.len() && !leaders.contains(&instrs[i].offset) {
            last = i;
            i += 1;
        }
        start_to_block.insert(start, blocks.len());
        blocks.push(Block { start, first, last });
    }
    Some(BlockGraph {
        blocks,
        start_to_block,
        dispatcher,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cil::disassemble;

    fn body_from(code: &[u8]) -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: code.len() as u32,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions: disassemble(code).expect("disasm"),
            exception_clauses: Vec::new(),
        }
    }

    #[test]
    fn rejects_unflattened_method() {
        let body: MethodBody = body_from(&[0x02, 0x03, 0x58, 0x2A]);
        assert!(find_dispatcher(&body).is_none());
    }

    #[test]
    fn detects_switch_dispatcher_header() {
        let mut code: Vec<u8> = Vec::new();
        code.push(0x20);
        code.extend_from_slice(&7i32.to_le_bytes());
        code.push(0x25);
        code.push(0x0B);
        code.push(0x18);
        code.push(0x5E);
        code.push(0x45);
        code.extend_from_slice(&2u32.to_le_bytes());
        code.extend_from_slice(&0i32.to_le_bytes());
        code.extend_from_slice(&0i32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let d: Dispatcher = find_dispatcher(&body).expect("dispatcher");
        assert_eq!(d.state_local, 1);
        assert_eq!(d.case_count, 2);
    }
}
