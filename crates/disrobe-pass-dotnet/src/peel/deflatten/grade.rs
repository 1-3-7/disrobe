use std::collections::BTreeMap;

use crate::cfg::{Cfg, Terminator};
use crate::cil::{Instruction, MethodBody};
use crate::structurize::normalize_branches_pub;

use super::blocks::{BlockGraph, BlockId};
use super::rebuild::{
    Edge, Recovered, RecoveredBlock, RecoveredInstructionBlock, recover_payload_instructions,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum NormEdge {
    Goto(usize),
    Branch {
        taken: usize,
        fallthrough: usize,
        predicate: String,
    },
    Return,
}

#[derive(Debug, Clone)]
struct NormBlock {
    payload: Vec<String>,
    instructions: Vec<Instruction>,
    edge: NormEdge,
}

#[derive(Debug, Clone)]
struct NormGraph {
    entry: usize,
    blocks: Vec<NormBlock>,
    payload_edges_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgFingerprint {
    pub block_signatures: Vec<String>,
    pub return_blocks: usize,
    pub branch_blocks: usize,
    pub edge_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuralScore {
    pub matched_signatures: usize,
    pub expected_signatures: usize,
    pub branch_blocks_match: bool,
    pub return_blocks_match: bool,
    pub edge_count_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadEdge {
    Goto(usize),
    Branch {
        taken: usize,
        fallthrough: usize,
        predicate: String,
    },
    Return,
}

#[derive(Debug, Clone)]
pub struct PayloadBlock {
    pub instructions: Vec<Instruction>,
    pub edge: PayloadEdge,
}

#[derive(Debug, Clone)]
pub struct PayloadGraph {
    pub entry: usize,
    pub blocks: Vec<PayloadBlock>,
}

impl StructuralScore {
    #[must_use]
    pub const fn is_full(self) -> bool {
        self.matched_signatures >= self.expected_signatures
            && self.branch_blocks_match
            && self.return_blocks_match
            && self.edge_count_match
    }

    #[must_use]
    pub fn percent(self) -> f64 {
        if self.expected_signatures == 0 {
            return 100.0;
        }
        (self.matched_signatures as f64 / self.expected_signatures as f64 * 100.0).min(100.0)
    }
}

fn is_structural(name: &str) -> bool {
    super::interp::is_conditional_branch(name)
        || super::interp::is_unconditional_branch(name)
        || super::interp::is_terminal(name)
        || name == "switch"
}

fn payload_of(names: &[&str]) -> Vec<String> {
    names
        .iter()
        .filter(|n: &&&str| !is_structural(n))
        .map(|n: &&str| (*n).to_owned())
        .collect()
}

fn norm_from_recovered(recovered: &Recovered) -> NormGraph {
    norm_from_recovered_with_instructions(recovered, &BTreeMap::new())
}

fn norm_from_recovered_with_instructions(
    recovered: &Recovered,
    instruction_blocks: &BTreeMap<BlockId, Vec<Instruction>>,
) -> NormGraph {
    let mut id_to_index: BTreeMap<BlockId, usize> = BTreeMap::new();
    for (i, b) in recovered.blocks.iter().enumerate() {
        id_to_index.insert(b.id, i);
    }
    let resolve = |bid: BlockId| -> usize { id_to_index.get(&bid).copied().unwrap_or(usize::MAX) };
    let blocks: Vec<NormBlock> = recovered
        .blocks
        .iter()
        .map(|b: &RecoveredBlock| {
            let payload: Vec<String> = b
                .payload
                .iter()
                .filter(|n: &&String| !is_structural(n))
                .cloned()
                .collect();
            let instructions: Vec<Instruction> = instruction_blocks
                .get(&b.id)
                .into_iter()
                .flatten()
                .filter(|instruction: &&Instruction| !is_structural(instruction.name.as_str()))
                .cloned()
                .collect();
            let edge: NormEdge = match &b.edge {
                Edge::Goto(t) => NormEdge::Goto(resolve(*t)),
                Edge::Cond {
                    taken,
                    fallthrough,
                    predicate,
                } => NormEdge::Branch {
                    taken: resolve(*taken),
                    fallthrough: resolve(*fallthrough),
                    predicate: predicate.opcode.clone(),
                },
                Edge::Return => NormEdge::Return,
            };
            NormBlock {
                payload,
                instructions,
                edge,
            }
        })
        .collect();
    NormGraph {
        entry: resolve(recovered.entry),
        blocks,
        payload_edges_complete: true,
    }
}

fn norm_from_clean(body: &MethodBody) -> NormGraph {
    let normalized: MethodBody = normalize_branches_pub(body);
    let cfg: Cfg = Cfg::build(&normalized);
    let mut index_map: BTreeMap<usize, usize> = BTreeMap::new();
    let mut order: Vec<usize> = Vec::new();
    for (bid, _block) in cfg.blocks.iter().enumerate() {
        if cfg.is_reachable(bid) {
            index_map.insert(bid, order.len());
            order.push(bid);
        }
    }
    let payload_edges_complete: bool = order
        .iter()
        .all(|bid: &usize| !matches!(&cfg.terminators[*bid], Terminator::Switch { .. }));
    let resolve = |bid: usize| -> usize { index_map.get(&bid).copied().unwrap_or(usize::MAX) };
    let blocks: Vec<NormBlock> = order
        .iter()
        .map(|&bid: &usize| {
            let block: &crate::cfg::BasicBlock = &cfg.blocks[bid];
            let names: Vec<&str> = normalized.instructions[block.first..=block.last]
                .iter()
                .map(|i: &Instruction| i.name.as_str())
                .collect();
            let payload: Vec<String> = payload_of(&names);
            let instructions: Vec<Instruction> = normalized.instructions[block.first..=block.last]
                .iter()
                .filter(|instruction: &&Instruction| !is_structural(instruction.name.as_str()))
                .cloned()
                .collect();
            let edge: NormEdge = match &cfg.terminators[bid] {
                Terminator::Return | Terminator::Throw | Terminator::EndFinally => NormEdge::Return,
                Terminator::Cond { taken, fallthrough } => NormEdge::Branch {
                    taken: resolve(*taken),
                    fallthrough: resolve(*fallthrough),
                    predicate: normalized.instructions[block.last].name.clone(),
                },
                Terminator::FallThrough(t) | Terminator::Goto(t) => NormEdge::Goto(resolve(*t)),
                Terminator::Switch { cases, fallthrough } => {
                    let first: usize = cases.first().copied().unwrap_or(*fallthrough);
                    NormEdge::Goto(resolve(first))
                }
            };
            NormBlock {
                payload,
                instructions,
                edge,
            }
        })
        .collect();
    let entry: usize = if blocks.is_empty() { usize::MAX } else { 0 };
    NormGraph {
        entry,
        blocks,
        payload_edges_complete,
    }
}

fn predecessors(graph: &NormGraph) -> Vec<Vec<usize>> {
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); graph.blocks.len()];
    for (i, b) in graph.blocks.iter().enumerate() {
        for s in successors(&b.edge) {
            if let Some(list) = preds.get_mut(s) {
                list.push(i);
            }
        }
    }
    preds
}

fn successors(edge: &NormEdge) -> Vec<usize> {
    match edge {
        NormEdge::Goto(t) => vec![*t],
        NormEdge::Branch {
            taken, fallthrough, ..
        } => vec![*taken, *fallthrough],
        NormEdge::Return => Vec::new(),
    }
}

fn coalesce(graph: &NormGraph) -> NormGraph {
    let mut blocks: Vec<NormBlock> = graph.blocks.clone();
    let entry: usize = graph.entry;
    let mut changed: bool = true;
    let mut guard: usize = 0;
    while changed && guard < 4096 {
        changed = false;
        guard += 1;
        let preds: Vec<Vec<usize>> = preds_of(&blocks);
        for i in 0..blocks.len() {
            let NormEdge::Goto(succ) = blocks[i].edge.clone() else {
                continue;
            };
            if succ >= blocks.len() || succ == i || succ == entry {
                continue;
            }
            if preds.get(succ).map_or(0, Vec::len) != 1 {
                continue;
            }
            let mut merged_payload: Vec<String> = blocks[i].payload.clone();
            let succ_payload: Vec<String> = blocks[succ].payload.clone();
            merged_payload.extend(succ_payload);
            let mut merged_instructions: Vec<Instruction> = blocks[i].instructions.clone();
            let succ_instructions: Vec<Instruction> = blocks[succ].instructions.clone();
            merged_instructions.extend(succ_instructions);
            let succ_edge: NormEdge = blocks[succ].edge.clone();
            blocks[i].payload = merged_payload;
            blocks[i].instructions = merged_instructions;
            blocks[i].edge = redirect_self(succ_edge, succ, i);
            blocks[succ].edge = NormEdge::Return;
            blocks[succ].payload = vec!["__merged__".to_owned()];
            blocks[succ].instructions.clear();
            redirect_all(&mut blocks, succ, i);
            changed = true;
            break;
        }
    }
    prune_merged(&blocks, entry, graph.payload_edges_complete)
}

fn preds_of(blocks: &[NormBlock]) -> Vec<Vec<usize>> {
    let g: NormGraph = NormGraph {
        entry: usize::MAX,
        blocks: blocks.to_vec(),
        payload_edges_complete: true,
    };
    predecessors(&g)
}

fn redirect_self(edge: NormEdge, from: usize, to: usize) -> NormEdge {
    let map = |x: usize| -> usize { if x == from { to } else { x } };
    match edge {
        NormEdge::Goto(t) => NormEdge::Goto(map(t)),
        NormEdge::Branch {
            taken,
            fallthrough,
            predicate,
        } => NormEdge::Branch {
            taken: map(taken),
            fallthrough: map(fallthrough),
            predicate,
        },
        NormEdge::Return => NormEdge::Return,
    }
}

fn redirect_all(blocks: &mut [NormBlock], from: usize, to: usize) {
    for b in blocks.iter_mut() {
        b.edge = redirect_self(b.edge.clone(), from, to);
    }
}

fn prune_merged(blocks: &[NormBlock], entry: usize, payload_edges_complete: bool) -> NormGraph {
    let mut remap: Vec<Option<usize>> = vec![None; blocks.len()];
    let mut kept: Vec<NormBlock> = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        if block.payload.first().map(String::as_str) == Some("__merged__") {
            continue;
        }
        remap[index] = Some(kept.len());
        kept.push(block.clone());
    }
    for block in &mut kept {
        let map =
            |target: usize| -> usize { remap.get(target).copied().flatten().unwrap_or(usize::MAX) };
        block.edge = match block.edge {
            NormEdge::Goto(target) => NormEdge::Goto(map(target)),
            NormEdge::Branch {
                taken,
                fallthrough,
                ref predicate,
            } => NormEdge::Branch {
                taken: map(taken),
                fallthrough: map(fallthrough),
                predicate: predicate.clone(),
            },
            NormEdge::Return => NormEdge::Return,
        };
    }
    NormGraph {
        entry: remap.get(entry).copied().flatten().unwrap_or(usize::MAX),
        blocks: kept,
        payload_edges_complete,
    }
}

fn signature_of(payload: &[String]) -> String {
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for op in payload {
        *counts.entry(op.as_str()).or_insert(0) += 1;
    }
    counts
        .iter()
        .map(|(op, n): (&&str, &u32)| format!("{op}*{n}"))
        .collect::<Vec<String>>()
        .join(";")
}

fn fingerprint(graph: &NormGraph) -> CfgFingerprint {
    let coalesced: NormGraph = coalesce(graph);
    let mut signatures: Vec<String> = Vec::new();
    let mut return_blocks: usize = 0;
    let mut branch_blocks: usize = 0;
    let mut edge_count: usize = 0;
    for b in &coalesced.blocks {
        signatures.push(signature_of(&b.payload));
        match &b.edge {
            NormEdge::Return => return_blocks += 1,
            NormEdge::Goto(_) => edge_count += 1,
            NormEdge::Branch { .. } => {
                branch_blocks += 1;
                edge_count += 2;
            }
        }
    }
    signatures.sort();
    CfgFingerprint {
        block_signatures: signatures,
        return_blocks,
        branch_blocks,
        edge_count,
    }
}

#[must_use]
pub fn clean_fingerprint(body: &MethodBody) -> CfgFingerprint {
    fingerprint(&norm_from_clean(body))
}

#[must_use]
pub fn recovered_fingerprint(recovered: &Recovered) -> CfgFingerprint {
    fingerprint(&norm_from_recovered(recovered))
}

fn payload_graph(graph: &NormGraph) -> Option<PayloadGraph> {
    let coalesced: NormGraph = coalesce(graph);
    if !coalesced.payload_edges_complete || coalesced.entry >= coalesced.blocks.len() {
        return None;
    }
    let block_count: usize = coalesced.blocks.len();
    let mut blocks: Vec<PayloadBlock> = Vec::with_capacity(block_count);
    for block in coalesced.blocks {
        let edge: PayloadEdge = match block.edge {
            NormEdge::Goto(target) if target < block_count => PayloadEdge::Goto(target),
            NormEdge::Branch {
                taken,
                fallthrough,
                predicate,
            } if taken < block_count && fallthrough < block_count => PayloadEdge::Branch {
                taken,
                fallthrough,
                predicate,
            },
            NormEdge::Return => PayloadEdge::Return,
            NormEdge::Goto(_) | NormEdge::Branch { .. } => return None,
        };
        blocks.push(PayloadBlock {
            instructions: block.instructions,
            edge,
        });
    }
    Some(PayloadGraph {
        entry: coalesced.entry,
        blocks,
    })
}

#[must_use]
pub fn clean_payload_graph(body: &MethodBody) -> Option<PayloadGraph> {
    payload_graph(&norm_from_clean(body))
}

#[must_use]
pub fn recovered_payload_graph(
    graph: &BlockGraph,
    body: &MethodBody,
    recovered: &Recovered,
) -> Option<PayloadGraph> {
    let instruction_blocks: Vec<RecoveredInstructionBlock> =
        recover_payload_instructions(graph, body, recovered)?;
    let instructions_by_id: BTreeMap<BlockId, Vec<Instruction>> = instruction_blocks
        .into_iter()
        .map(|block: RecoveredInstructionBlock| (block.id, block.instructions))
        .collect();
    payload_graph(&norm_from_recovered_with_instructions(
        recovered,
        &instructions_by_id,
    ))
}

#[must_use]
pub fn grade(clean_body: &MethodBody, recovered: &Recovered) -> StructuralScore {
    let clean: CfgFingerprint = clean_fingerprint(clean_body);
    let rec: CfgFingerprint = recovered_fingerprint(recovered);
    let matched: usize = multiset_overlap(&clean.block_signatures, &rec.block_signatures);
    StructuralScore {
        matched_signatures: matched,
        expected_signatures: clean.block_signatures.len(),
        branch_blocks_match: clean.branch_blocks == rec.branch_blocks,
        return_blocks_match: clean.return_blocks == rec.return_blocks,
        edge_count_match: clean.edge_count == rec.edge_count,
    }
}

fn multiset_overlap(a: &[String], b: &[String]) -> usize {
    let mut counts: BTreeMap<&str, i64> = BTreeMap::new();
    for s in a {
        *counts.entry(s.as_str()).or_insert(0) += 1;
    }
    let mut matched: usize = 0;
    for s in b {
        let entry: &mut i64 = counts.entry(s.as_str()).or_insert(0);
        if *entry > 0 {
            *entry -= 1;
            matched += 1;
        }
    }
    matched
}

#[must_use]
pub fn predicate_kinds(recovered: &Recovered) -> Vec<String> {
    let mut kinds: Vec<String> = recovered
        .blocks
        .iter()
        .filter_map(|b: &RecoveredBlock| match &b.edge {
            Edge::Cond { predicate, .. } => Some(predicate.opcode.clone()),
            _ => None,
        })
        .collect();
    kinds.sort();
    kinds
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
    fn signature_counts_opcode_multiset() {
        let sig: String = signature_of(&["ldarg.0".into(), "ldarg.0".into(), "add".into()]);
        assert!(sig.contains("ldarg.0*2"));
        assert!(sig.contains("add*1"));
    }

    #[test]
    fn clean_fingerprint_collapses_goto_chain() {
        let body: MethodBody = body_from(&[0x02, 0x03, 0x58, 0x2A]);
        let fp: CfgFingerprint = clean_fingerprint(&body);
        assert_eq!(fp.return_blocks, 1);
        assert_eq!(fp.branch_blocks, 0);
    }

    #[test]
    fn exact_payload_graph_rejects_multiway_switch() {
        let body: MethodBody = body_from(&[
            0x16, 0x45, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2A, 0x2A,
        ]);
        assert!(clean_payload_graph(&body).is_none());
    }
}
