use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::cil::{Instruction, MethodBody, OperandValue};

use super::blocks::{BlockGraph, BlockId};
use super::interp::{
    KeyOracle, Predicate, ResolveError, Successors, is_unconditional_branch, resolve_block,
    resolve_header_key,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edge {
    Goto(BlockId),
    Cond {
        taken: BlockId,
        fallthrough: BlockId,
        predicate: Predicate,
    },
    Return,
}

#[derive(Debug, Clone)]
pub struct RecoveredBlock {
    pub id: BlockId,
    pub payload: Vec<String>,
    pub edge: Edge,
}

#[derive(Debug, Clone)]
pub struct Recovered {
    pub entry: BlockId,
    pub blocks: Vec<RecoveredBlock>,
    pub reachable_order: Vec<BlockId>,
    pub unresolved: Vec<BlockId>,
}

#[derive(Debug, Clone)]
pub struct RecoveredInstructionBlock {
    pub id: BlockId,
    pub instructions: Vec<Instruction>,
}

#[must_use]
pub fn recover_payload_instructions(
    graph: &BlockGraph,
    body: &MethodBody,
    recovered: &Recovered,
) -> Option<Vec<RecoveredInstructionBlock>> {
    let mut block_ids: BTreeSet<BlockId> = BTreeSet::new();
    let mut instruction_offsets: BTreeSet<u32> = BTreeSet::new();
    let mut retained: usize = 0;
    let mut payloads: Vec<RecoveredInstructionBlock> = Vec::with_capacity(recovered.blocks.len());
    for block in &recovered.blocks {
        if !block_ids.insert(block.id) {
            return None;
        }
        let instructions: Vec<Instruction> = block_payload(graph, &body.instructions, block.id)?;
        let projected: Vec<String> = instructions
            .iter()
            .map(|instruction: &Instruction| instruction.name.clone())
            .collect();
        if projected != block.payload {
            return None;
        }
        retained = retained.checked_add(instructions.len())?;
        if retained > body.instructions.len()
            || instructions
                .iter()
                .any(|instruction: &Instruction| !instruction_offsets.insert(instruction.offset))
        {
            return None;
        }
        payloads.push(RecoveredInstructionBlock {
            id: block.id,
            instructions,
        });
    }
    Some(payloads)
}

const MAX_VISIT: usize = 8192;

#[must_use]
pub fn deflatten(graph: &BlockGraph, body: &crate::cil::MethodBody) -> Recovered {
    deflatten_with_oracle(graph, body, &super::interp::NoOracle)
}

#[must_use]
pub fn deflatten_with_oracle(
    graph: &BlockGraph,
    body: &crate::cil::MethodBody,
    oracle: &dyn KeyOracle,
) -> Recovered {
    let instrs: &[Instruction] = &body.instructions;
    let code_size: u32 = body.code_size;
    let entry: BlockId = 0;
    let mut edges: BTreeMap<BlockId, Edge> = BTreeMap::new();
    let mut unresolved: Vec<BlockId> = Vec::new();
    let mut reachable_order: Vec<BlockId> = Vec::new();
    let mut visited: BTreeSet<BlockId> = BTreeSet::new();
    let mut work: VecDeque<(BlockId, i64)> = VecDeque::new();
    let header_key: i64 = resolve_header_key(graph, oracle, instrs, code_size).unwrap_or(0);
    work.push_back((entry, header_key));
    let mut guard: usize = 0;
    while let Some((bid, key)) = work.pop_front() {
        guard += 1;
        if guard > MAX_VISIT {
            break;
        }
        if !visited.insert(bid) {
            continue;
        }
        reachable_order.push(bid);
        let Some(block) = graph.blocks.get(bid) else {
            continue;
        };
        if is_dispatcher_block(graph, bid) {
            continue;
        }
        let outcome: Result<Successors, ResolveError> = resolve_block(
            graph,
            oracle,
            instrs,
            code_size,
            block.first,
            block.last,
            key,
        );
        match outcome {
            Ok(Successors::Terminal) => {
                edges.insert(bid, Edge::Return);
            }
            Ok(Successors::One(t)) => {
                let succ: BlockId = block_of(graph, t.offset);
                edges.insert(bid, Edge::Goto(succ));
                work.push_back((succ, t.key));
            }
            Ok(Successors::Two {
                taken,
                fallthrough,
                predicate,
            }) => {
                let taken_b: BlockId = block_of(graph, taken.offset);
                let fall_b: BlockId = block_of(graph, fallthrough.offset);
                edges.insert(
                    bid,
                    Edge::Cond {
                        taken: taken_b,
                        fallthrough: fall_b,
                        predicate,
                    },
                );
                work.push_back((taken_b, taken.key));
                work.push_back((fall_b, fallthrough.key));
            }
            Err(_) => {
                unresolved.push(bid);
            }
        }
    }

    let blocks: Vec<RecoveredBlock> = reachable_order
        .iter()
        .filter_map(|&bid: &BlockId| {
            if is_dispatcher_block(graph, bid) {
                return None;
            }
            let edge: Edge = edges.get(&bid).cloned()?;
            let payload_instructions: Vec<Instruction> = block_payload(graph, instrs, bid)?;
            let payload: Vec<String> = payload_instructions
                .iter()
                .map(|instruction: &Instruction| instruction.name.clone())
                .collect();
            Some(RecoveredBlock {
                id: bid,
                payload,
                edge,
            })
        })
        .collect();

    unresolved.sort_unstable();
    unresolved.dedup();
    Recovered {
        entry,
        blocks,
        reachable_order,
        unresolved,
    }
}

fn is_dispatcher_block(graph: &BlockGraph, bid: BlockId) -> bool {
    graph
        .blocks
        .get(bid)
        .is_some_and(|b| b.start == graph.dispatcher.header_entry)
}

fn block_of(graph: &BlockGraph, offset: u32) -> BlockId {
    graph.start_to_block.get(&offset).copied().unwrap_or(0)
}

fn block_payload(
    graph: &BlockGraph,
    instrs: &[Instruction],
    bid: BlockId,
) -> Option<Vec<Instruction>> {
    let block = graph.blocks.get(bid)?;
    let slice: &[Instruction] = instrs.get(block.first..=block.last)?;
    Some(
        strip_key_tail(slice, graph.dispatcher.state_local)
            .iter()
            .map(|instruction: &&Instruction| (*instruction).clone())
            .collect(),
    )
}

#[must_use]
pub fn strip_key_tail(slice: &[Instruction], state_local: u32) -> Vec<&Instruction> {
    let mut end: usize = slice.len();
    while end > 0 {
        let index: usize = end - 1;
        let ins: &Instruction = &slice[index];
        if ins.name == "pop" && !is_key_selector_pop(slice, index) {
            break;
        }
        if is_key_machinery(ins, state_local) {
            end -= 1;
        } else {
            break;
        }
    }
    slice[..end].iter().collect()
}

fn is_key_selector_pop(slice: &[Instruction], index: usize) -> bool {
    let Some(pop): Option<&Instruction> = slice.get(index) else {
        return false;
    };
    if pop.name != "pop" {
        return false;
    }
    let mut cursor: usize = index;
    let Some(right_dup_index): Option<usize> = previous_non_padding_index(slice, &mut cursor)
    else {
        return false;
    };
    let Some(right_value_index): Option<usize> = previous_non_padding_index(slice, &mut cursor)
    else {
        return false;
    };
    let Some(join_branch_index): Option<usize> = previous_non_padding_index(slice, &mut cursor)
    else {
        return false;
    };
    let Some(left_dup_index): Option<usize> = previous_non_padding_index(slice, &mut cursor) else {
        return false;
    };
    let Some(left_value_index): Option<usize> = previous_non_padding_index(slice, &mut cursor)
    else {
        return false;
    };
    let Some(condition_index): Option<usize> = previous_non_padding_index(slice, &mut cursor)
    else {
        return false;
    };
    let Some(right_dup): Option<&Instruction> = slice.get(right_dup_index) else {
        return false;
    };
    let Some(right_value): Option<&Instruction> = slice.get(right_value_index) else {
        return false;
    };
    let Some(join_branch): Option<&Instruction> = slice.get(join_branch_index) else {
        return false;
    };
    let Some(left_dup): Option<&Instruction> = slice.get(left_dup_index) else {
        return false;
    };
    let Some(left_value): Option<&Instruction> = slice.get(left_value_index) else {
        return false;
    };
    let Some(condition): Option<&Instruction> = slice.get(condition_index) else {
        return false;
    };
    right_dup.name == "dup"
        && left_dup.name == "dup"
        && super::blocks::int_literal(right_value).is_some()
        && super::blocks::int_literal(left_value).is_some()
        && matches!(join_branch.name.as_str(), "br" | "br.s")
        && super::interp::is_conditional_branch(&condition.name)
        && relative_branch_target(slice, join_branch_index) == Some(pop.offset)
        && relative_branch_target(slice, condition_index) == Some(right_value.offset)
}

fn previous_non_padding_index(slice: &[Instruction], cursor: &mut usize) -> Option<usize> {
    while let Some(index) = cursor.checked_sub(1) {
        let index: usize = index;
        *cursor = index;
        let ins: &Instruction = slice.get(index)?;
        if !matches!(ins.name.as_str(), "nop" | "break") {
            return Some(index);
        }
    }
    None
}

fn relative_branch_target(slice: &[Instruction], index: usize) -> Option<u32> {
    let branch: &Instruction = slice.get(index)?;
    let OperandValue::BrTarget(relative): &OperandValue = &branch.operand else {
        return None;
    };
    let next_offset: u32 = slice.get(index.checked_add(1)?)?.offset;
    let target: i64 = i64::from(next_offset).checked_add(i64::from(*relative))?;
    u32::try_from(target).ok()
}

fn is_key_machinery(ins: &Instruction, state_local: u32) -> bool {
    let name: &str = ins.name.as_str();
    if is_unconditional_branch(name) || name == "dup" || name == "pop" || name == "switch" {
        return true;
    }
    if name.starts_with("ldc.i4") {
        return true;
    }
    if matches!(name, "mul" | "xor" | "mul.ovf" | "mul.ovf.un" | "rem.un") {
        return true;
    }
    is_state_local_load(ins, state_local) || is_state_local_store(ins, state_local)
}

fn is_state_local_load(ins: &Instruction, state_local: u32) -> bool {
    local_index(ins, "ldloc").is_some_and(|i: u32| i == state_local)
}

fn is_state_local_store(ins: &Instruction, state_local: u32) -> bool {
    local_index(ins, "stloc").is_some_and(|i: u32| i == state_local)
}

fn local_index(ins: &Instruction, prefix: &str) -> Option<u32> {
    let name: &str = ins.name.as_str();
    if !name.starts_with(prefix) {
        return None;
    }
    if let Some(rest) = name.rsplit('.').next()
        && let Ok(n) = rest.parse::<u32>()
    {
        return Some(n);
    }
    match ins.operand {
        crate::cil::OperandValue::U8(b) => Some(u32::from(b)),
        crate::cil::OperandValue::U16(v) => Some(u32::from(v)),
        _ => None,
    }
}

#[must_use]
pub fn edge_targets(edge: &Edge) -> Vec<BlockId> {
    match edge {
        Edge::Goto(b) => vec![*b],
        Edge::Cond {
            taken, fallthrough, ..
        } => vec![*taken, *fallthrough],
        Edge::Return => Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::super::blocks::{Block, Dispatcher};
    use super::*;
    use crate::cil::disassemble;

    #[test]
    fn strips_xor_key_tail_to_payload() {
        let mut code: Vec<u8> = vec![0x02, 0x58, 0x07, 0x20];
        code.extend_from_slice(&5i32.to_le_bytes());
        code.push(0x5A);
        code.push(0x20);
        code.extend_from_slice(&9i32.to_le_bytes());
        code.push(0x61);
        code.push(0x2B);
        code.push(0x00);
        let instrs: Vec<Instruction> = disassemble(&code).expect("disasm");
        let full_len: usize = instrs.len();
        let payload: Vec<&Instruction> = strip_key_tail(&instrs, 1);
        assert!(payload.len() < full_len, "tail must be stripped");
        assert_eq!(payload.first().map(|i| i.name.as_str()), Some("ldarg.0"));
    }

    #[test]
    fn preserves_distinct_operands_for_repeated_opcodes_in_order() {
        let mut code: Vec<u8> = vec![0x20];
        code.extend_from_slice(&7i32.to_le_bytes());
        code.push(0x20);
        code.extend_from_slice(&11i32.to_le_bytes());
        code.push(0x2A);
        let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
        let graph: BlockGraph = BlockGraph {
            blocks: vec![Block {
                start: 0,
                first: 0,
                last: instructions.len() - 1,
            }],
            start_to_block: std::collections::BTreeMap::from([(0, 0)]),
            dispatcher: Dispatcher {
                state_local: 3,
                case_count: 1,
                switch_index: usize::MAX,
                switch_targets: Vec::new(),
                header_entry: u32::MAX,
            },
        };
        let payload: Vec<Instruction> = block_payload(&graph, &instructions, 0).expect("payload");
        let operands: Vec<OperandValue> = payload
            .iter()
            .filter(|instruction: &&Instruction| instruction.name == "ldc.i4")
            .map(|instruction: &Instruction| instruction.operand.clone())
            .collect();
        assert_eq!(operands, [OperandValue::I32(7), OperandValue::I32(11)]);
    }

    #[test]
    fn preserves_discarded_call_results_before_direct_key_tails() {
        let call_opcodes: [(u8, &str); 4] = [
            (0x28, "call"),
            (0x29, "calli"),
            (0x6F, "callvirt"),
            (0x73, "newobj"),
        ];
        for call_opcode in call_opcodes {
            let opcode: u8 = call_opcode.0;
            let expected: &str = call_opcode.1;
            let mut code: Vec<u8> = vec![opcode];
            code.extend_from_slice(&0x0600_0001u32.to_le_bytes());
            code.extend_from_slice(&[0x26, 0x20]);
            code.extend_from_slice(&7i32.to_le_bytes());
            code.extend_from_slice(&[0x2B, 0x00]);
            let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
            let payload: Vec<&Instruction> = strip_key_tail(&instructions, 1);
            let names: Vec<&str> = payload
                .iter()
                .map(|instruction: &&Instruction| instruction.name.as_str())
                .collect();
            assert_eq!(names, [expected, "pop"]);
        }
    }

    #[test]
    fn preserves_payload_pop_after_stack_neutral_instructions() {
        let mut code: Vec<u8> = vec![0x28];
        code.extend_from_slice(&0x0600_0001u32.to_le_bytes());
        code.extend_from_slice(&[0x00, 0x01, 0x26, 0x20]);
        code.extend_from_slice(&7i32.to_le_bytes());
        code.extend_from_slice(&[0x2B, 0x00]);
        let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
        let payload: Vec<&Instruction> = strip_key_tail(&instructions, 1);
        let names: Vec<&str> = payload
            .iter()
            .map(|instruction: &&Instruction| instruction.name.as_str())
            .collect();
        assert_eq!(names, ["call", "nop", "break", "pop"]);
    }

    #[test]
    fn preserves_non_selector_pop_before_direct_key_tail() {
        let code: Vec<u8> = vec![0x17, 0x26, 0x20, 7, 0, 0, 0, 0x2B, 0x00];
        let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
        let payload: Vec<&Instruction> = strip_key_tail(&instructions, 1);
        let names: Vec<&str> = payload
            .iter()
            .map(|instruction: &&Instruction| instruction.name.as_str())
            .collect();
        assert_eq!(names, ["ldc.i4.1", "pop"]);
    }

    #[test]
    fn preserves_non_selector_dup_branch_dup_pop_sequence() {
        let mut code: Vec<u8> = vec![0x02, 0x25, 0x2B, 0x01, 0x00, 0x25, 0x26, 0x20];
        code.extend_from_slice(&7i32.to_le_bytes());
        code.extend_from_slice(&[0x2B, 0x00]);
        let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
        let payload: Vec<&Instruction> = strip_key_tail(&instructions, 1);
        let names: Vec<&str> = payload
            .iter()
            .map(|instruction: &&Instruction| instruction.name.as_str())
            .collect();
        assert_eq!(names, ["ldarg.0", "dup", "br.s", "nop", "dup", "pop"]);
    }

    #[test]
    fn preserves_selector_like_pops_with_mismatched_branch_targets() {
        let cases: [[u8; 17]; 2] = [
            [
                0x02, 0x2D, 0x00, 0x17, 0x25, 0x2B, 0x02, 0x18, 0x25, 0x26, 0x07, 0x19, 0x5A, 0x1A,
                0x61, 0x2B, 0x00,
            ],
            [
                0x02, 0x2D, 0x04, 0x17, 0x25, 0x2B, 0x00, 0x18, 0x25, 0x26, 0x07, 0x19, 0x5A, 0x1A,
                0x61, 0x2B, 0x00,
            ],
        ];
        for code in cases {
            let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
            let payload: Vec<&Instruction> = strip_key_tail(&instructions, 1);
            let names: Vec<&str> = payload
                .iter()
                .map(|instruction: &&Instruction| instruction.name.as_str())
                .collect();
            assert_eq!(
                names,
                [
                    "ldarg.0", "brtrue.s", "ldc.i4.1", "dup", "br.s", "ldc.i4.2", "dup", "pop",
                ]
            );
        }
    }

    #[test]
    fn preserves_selector_like_pops_with_stack_clearing_joins() {
        let cases: [(Vec<u8>, &str); 2] = [
            (
                vec![
                    0x02, 0x2D, 0x04, 0x17, 0x25, 0xDE, 0x02, 0x18, 0x25, 0x26, 0x07, 0x19, 0x5A,
                    0x1A, 0x61, 0x2B, 0x00,
                ],
                "leave.s",
            ),
            (
                vec![
                    0x02, 0x2D, 0x07, 0x17, 0x25, 0xDD, 0x02, 0x00, 0x00, 0x00, 0x18, 0x25, 0x26,
                    0x07, 0x19, 0x5A, 0x1A, 0x61, 0x2B, 0x00,
                ],
                "leave",
            ),
        ];
        for (code, join) in cases {
            let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
            let payload: Vec<&Instruction> = strip_key_tail(&instructions, 1);
            let names: Vec<&str> = payload
                .iter()
                .map(|instruction: &&Instruction| instruction.name.as_str())
                .collect();
            assert_eq!(
                names,
                [
                    "ldarg.0", "brtrue.s", "ldc.i4.1", "dup", join, "ldc.i4.2", "dup", "pop",
                ]
            );
        }
    }

    #[test]
    fn strips_selector_pop_after_duplicate_key_arms() {
        let code: Vec<u8> = vec![
            0x02, 0x2D, 0x04, 0x17, 0x25, 0x2B, 0x02, 0x18, 0x25, 0x26, 0x07, 0x19, 0x5A, 0x1A,
            0x61, 0x2B, 0x00,
        ];
        let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
        let payload: Vec<&Instruction> = strip_key_tail(&instructions, 1);
        let names: Vec<&str> = payload
            .iter()
            .map(|instruction: &&Instruction| instruction.name.as_str())
            .collect();
        assert_eq!(names, ["ldarg.0", "brtrue.s"]);
    }
}
