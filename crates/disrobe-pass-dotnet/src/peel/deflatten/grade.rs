use std::collections::BTreeMap;

use crate::cfg::{Cfg, Terminator};
use crate::cil::{Instruction, MethodBody};
use crate::structurize::normalize_branches_pub;

use super::blocks::BlockId;
use super::rebuild::{Edge, Recovered, RecoveredBlock};

#[derive(Debug, Clone, PartialEq, Eq)]
enum NormEdge {
    Goto(usize),
    Branch(usize, usize),
    Return,
}

#[derive(Debug, Clone)]
struct NormBlock {
    payload: Vec<String>,
    edge: NormEdge,
}

#[derive(Debug, Clone)]
struct NormGraph {
    blocks: Vec<NormBlock>,
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
            let edge: NormEdge = match &b.edge {
                Edge::Goto(t) => NormEdge::Goto(resolve(*t)),
                Edge::Cond {
                    taken, fallthrough, ..
                } => NormEdge::Branch(resolve(*taken), resolve(*fallthrough)),
                Edge::Return => NormEdge::Return,
            };
            NormBlock { payload, edge }
        })
        .collect();
    NormGraph { blocks }
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
            let edge: NormEdge = match &cfg.terminators[bid] {
                Terminator::Return | Terminator::Throw | Terminator::EndFinally => NormEdge::Return,
                Terminator::Cond { taken, fallthrough } => {
                    NormEdge::Branch(resolve(*taken), resolve(*fallthrough))
                }
                Terminator::FallThrough(t) | Terminator::Goto(t) => NormEdge::Goto(resolve(*t)),
                Terminator::Switch { cases, fallthrough } => {
                    let first: usize = cases.first().copied().unwrap_or(*fallthrough);
                    NormEdge::Goto(resolve(first))
                }
            };
            NormBlock { payload, edge }
        })
        .collect();
    NormGraph { blocks }
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
        NormEdge::Branch(a, b) => vec![*a, *b],
        NormEdge::Return => Vec::new(),
    }
}

fn coalesce(graph: &NormGraph) -> NormGraph {
    let mut blocks: Vec<NormBlock> = graph.blocks.clone();
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
            if succ >= blocks.len() || succ == i {
                continue;
            }
            if preds.get(succ).map_or(0, Vec::len) != 1 {
                continue;
            }
            let mut merged_payload: Vec<String> = blocks[i].payload.clone();
            let succ_payload: Vec<String> = blocks[succ].payload.clone();
            merged_payload.extend(succ_payload);
            let succ_edge: NormEdge = blocks[succ].edge.clone();
            blocks[i].payload = merged_payload;
            blocks[i].edge = redirect_self(succ_edge, succ, i);
            blocks[succ].edge = NormEdge::Return;
            blocks[succ].payload = vec!["__merged__".to_owned()];
            redirect_all(&mut blocks, succ, i);
            changed = true;
            break;
        }
    }
    prune_merged(&blocks)
}

fn preds_of(blocks: &[NormBlock]) -> Vec<Vec<usize>> {
    let g: NormGraph = NormGraph {
        blocks: blocks.to_vec(),
    };
    predecessors(&g)
}

fn redirect_self(edge: NormEdge, from: usize, to: usize) -> NormEdge {
    let map = |x: usize| -> usize { if x == from { to } else { x } };
    match edge {
        NormEdge::Goto(t) => NormEdge::Goto(map(t)),
        NormEdge::Branch(a, b) => NormEdge::Branch(map(a), map(b)),
        NormEdge::Return => NormEdge::Return,
    }
}

fn redirect_all(blocks: &mut [NormBlock], from: usize, to: usize) {
    for b in blocks.iter_mut() {
        b.edge = redirect_self(b.edge.clone(), from, to);
    }
}

fn prune_merged(blocks: &[NormBlock]) -> NormGraph {
    let kept: Vec<NormBlock> = blocks
        .iter()
        .filter(|b: &&NormBlock| b.payload.first().map(String::as_str) != Some("__merged__"))
        .cloned()
        .collect();
    NormGraph { blocks: kept }
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
            NormEdge::Branch(_, _) => {
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
}
