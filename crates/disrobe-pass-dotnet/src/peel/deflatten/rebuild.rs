use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::cil::Instruction;

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
            let payload: Vec<String> = block_payload(graph, instrs, bid);
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

fn block_payload(graph: &BlockGraph, instrs: &[Instruction], bid: BlockId) -> Vec<String> {
    let Some(block) = graph.blocks.get(bid) else {
        return Vec::new();
    };
    let slice: &[Instruction] = &instrs[block.first..=block.last];
    strip_key_tail(slice, graph.dispatcher.state_local)
        .iter()
        .map(|i: &&Instruction| i.name.clone())
        .collect()
}

#[must_use]
pub fn strip_key_tail(slice: &[Instruction], state_local: u32) -> Vec<&Instruction> {
    let mut end: usize = slice.len();
    while end > 0 {
        let ins: &Instruction = &slice[end - 1];
        if is_key_machinery(ins, state_local) {
            end -= 1;
        } else {
            break;
        }
    }
    slice[..end].iter().collect()
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
}
