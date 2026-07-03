use std::collections::{BTreeMap, BTreeSet, VecDeque};

use disrobe_nir::{NirBlock, NirFunction, NirInstr, NirModule, basic_blocks};
use serde::Serialize;
use serde_json::Value as Json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DataEdge {
    pub from: u64,
    pub to: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DfgFunction {
    pub name: String,
    pub address: u64,
    pub write_sites: Vec<u64>,
    pub read_sites: Vec<u64>,
    pub edges: Vec<DataEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct DfgSummary {
    pub lang: String,
    pub functions: Vec<DfgFunction>,
}

impl DfgSummary {
    #[must_use]
    pub fn function(&self, name: &str) -> Option<&DfgFunction> {
        self.functions
            .iter()
            .find(|f: &&DfgFunction| f.name == name)
    }

    #[must_use]
    pub fn total_edges(&self) -> usize {
        self.functions
            .iter()
            .map(|f: &DfgFunction| f.edges.len())
            .sum()
    }

    #[must_use]
    pub fn reaches(&self, function: &str, from: u64, to: u64) -> bool {
        self.function(function)
            .is_some_and(|f: &DfgFunction| f.edges.contains(&DataEdge { from, to }))
    }

    #[must_use]
    pub fn to_json(&self) -> Json {
        serde_json::to_value(self).unwrap_or(Json::Null)
    }
}

#[must_use]
pub fn dfg_summary(module: &NirModule) -> DfgSummary {
    let functions: Vec<DfgFunction> = module.functions.iter().map(function_dfg).collect();
    DfgSummary {
        lang: module.lang.label().to_owned(),
        functions,
    }
}

fn function_dfg(function: &NirFunction) -> DfgFunction {
    let blocks: Vec<NirBlock> = basic_blocks(function);
    let write_sites: Vec<u64> = function
        .instructions
        .iter()
        .filter(|i: &&NirInstr| i.writes_memory)
        .map(|i: &NirInstr| i.address)
        .collect();
    let read_sites: Vec<u64> = function
        .instructions
        .iter()
        .filter(|i: &&NirInstr| i.reads_memory)
        .map(|i: &NirInstr| i.address)
        .collect();

    let index_of: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(idx, b): (usize, &NirBlock)| (b.start, idx))
        .collect();

    let mut edges: BTreeSet<DataEdge> = BTreeSet::new();
    for write in &write_sites {
        for read in reachable_reads(&blocks, &index_of, *write) {
            edges.insert(DataEdge {
                from: *write,
                to: read,
            });
        }
    }

    DfgFunction {
        name: function.name.clone(),
        address: function.address,
        write_sites,
        read_sites,
        edges: edges.into_iter().collect(),
    }
}

fn reachable_reads(
    blocks: &[NirBlock],
    index_of: &BTreeMap<u64, usize>,
    write_site: u64,
) -> Vec<u64> {
    let Some(origin_idx): Option<usize> = block_index_containing(blocks, write_site) else {
        return Vec::new();
    };
    let mut reads: Vec<u64> = Vec::new();
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut queue: VecDeque<(usize, bool)> = VecDeque::new();
    queue.push_back((origin_idx, true));
    visited.insert(origin_idx);

    while let Some((block_idx, is_origin)) = queue.pop_front() {
        let Some(block): Option<&NirBlock> = blocks.get(block_idx) else {
            continue;
        };
        for insn in &block.instructions {
            if is_origin && insn.address <= write_site {
                continue;
            }
            if insn.reads_memory {
                reads.push(insn.address);
            }
        }
        for succ in &block.successors {
            let Some(succ_idx): Option<&usize> = index_of.get(succ) else {
                continue;
            };
            if visited.insert(*succ_idx) {
                queue.push_back((*succ_idx, false));
            }
        }
    }
    reads
}

fn block_index_containing(blocks: &[NirBlock], address: u64) -> Option<usize> {
    blocks
        .iter()
        .position(|b: &NirBlock| address >= b.start && address < b.end)
}
