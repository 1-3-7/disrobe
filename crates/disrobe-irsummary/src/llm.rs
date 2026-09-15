use std::collections::BTreeSet;

use disrobe_llm_metadata::{Category, LlmMetadataEmitter, MetadataCapability};
use disrobe_nir::{BlockKind, NirModule};
use serde::Serialize;
use serde_json::Value as Json;

use crate::capability::{CapabilitySummary, capability_summary};
use crate::cfg::{CfgBlock, CfgFunction, CfgSummary, cfg_summary};
use crate::dfg::{DataEdge, DfgFunction, DfgSummary, dfg_summary};

const PASS: &str = "disrobe-irsummary";

const MODULE_UNIT: &str = "<module>";

const MAX_CFG_BLOCKS: usize = 200_000;
const MAX_CFG_EDGES: usize = 400_000;
const MAX_DFG_SITES: usize = 400_000;

pub const METADATA_CAPABILITY: MetadataCapability =
    MetadataCapability::new(PASS, crate::VERSION, &[Category::Cfg, Category::Dfg]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EdgeKind {
    Fallthrough,
    BranchTrue,
    BranchFalse,
    Jump,
}

#[derive(Debug, Clone, Serialize)]
struct BundleBlock {
    id: usize,
    label: String,
    pc_range: [u64; 2],
    kind: BlockKind,
    instruction_count: usize,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct BundleEdge {
    from: usize,
    to: usize,
    kind: EdgeKind,
}

#[derive(Debug, Clone, Serialize)]
struct BundleCfgFunction {
    name: String,
    address: u64,
    is_export: bool,
    cyclomatic_complexity: u32,
    edge_count: usize,
    block_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_block: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct BundleCfg {
    function: &'static str,
    lang: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_block: Option<usize>,
    blocks: Vec<BundleBlock>,
    edges: Vec<BundleEdge>,
    functions: Vec<BundleCfgFunction>,
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
struct BundleSite {
    var: String,
    pc: u64,
}

#[derive(Debug, Clone, Serialize)]
struct BundleUse {
    var: String,
    pc: u64,
    def_pc: u64,
}

#[derive(Debug, Clone, Serialize)]
struct BundleDfg {
    function: &'static str,
    lang: String,
    ssa: bool,
    defs: Vec<BundleSite>,
    uses: Vec<BundleUse>,
    unreached_reads: Vec<BundleSite>,
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    truncated: bool,
}

#[derive(Debug, Clone)]
pub struct IrSummaryEmitter<'a> {
    module: &'a NirModule,
}

impl<'a> IrSummaryEmitter<'a> {
    #[must_use]
    pub const fn new(module: &'a NirModule) -> Self {
        Self { module }
    }

    #[must_use]
    pub fn capabilities(&self) -> CapabilitySummary {
        capability_summary(self.module)
    }
}

impl LlmMetadataEmitter for IrSummaryEmitter<'_> {
    fn metadata_capability(&self) -> MetadataCapability {
        METADATA_CAPABILITY
    }

    fn emit_cfg(&self) -> Option<Json> {
        let summary: CfgSummary = cfg_summary(self.module);
        serde_json::to_value(bundle_cfg(&summary)).ok()
    }

    fn emit_dfg(&self) -> Option<Json> {
        let summary: DfgSummary = dfg_summary(self.module);
        serde_json::to_value(bundle_dfg(&summary)).ok()
    }
}

fn bundle_cfg(summary: &CfgSummary) -> BundleCfg {
    let mut blocks: Vec<BundleBlock> = Vec::new();
    let mut edges: Vec<BundleEdge> = Vec::new();
    let mut functions: Vec<BundleCfgFunction> = Vec::with_capacity(summary.functions.len());
    let mut truncated: bool = false;

    for function in &summary.functions {
        let entry_block: Option<usize> = (!function.blocks.is_empty()).then_some(blocks.len());
        let first_id: usize = blocks.len();
        if blocks.len().saturating_add(function.blocks.len()) > MAX_CFG_BLOCKS {
            truncated = true;
            functions.push(function_row(function, 0, None));
            continue;
        }
        for (offset, block) in function.blocks.iter().enumerate() {
            blocks.push(BundleBlock {
                id: first_id.saturating_add(offset),
                label: function.name.clone(),
                pc_range: [block.start, block.end],
                kind: block.kind,
                instruction_count: block.instruction_count,
            });
        }
        truncated |= extend_edges(&mut edges, &function.blocks, first_id);
        functions.push(function_row(function, function.blocks.len(), entry_block));
    }

    BundleCfg {
        function: MODULE_UNIT,
        lang: summary.lang.clone(),
        entry_block: (!blocks.is_empty()).then_some(0),
        blocks,
        edges,
        functions,
        truncated,
    }
}

fn function_row(
    function: &CfgFunction,
    block_count: usize,
    entry_block: Option<usize>,
) -> BundleCfgFunction {
    BundleCfgFunction {
        name: function.name.clone(),
        address: function.address,
        is_export: function.is_export,
        cyclomatic_complexity: function.cyclomatic_complexity,
        edge_count: function.edge_count,
        block_count,
        entry_block,
    }
}

fn extend_edges(edges: &mut Vec<BundleEdge>, blocks: &[CfgBlock], first_id: usize) -> bool {
    let starts: Vec<u64> = blocks.iter().map(|block: &CfgBlock| block.start).collect();
    let mut truncated: bool = false;
    for (offset, block) in blocks.iter().enumerate() {
        for successor in &block.successors {
            let Ok(target): Result<usize, usize> = starts.binary_search(successor) else {
                continue;
            };
            if edges.len() >= MAX_CFG_EDGES {
                truncated = true;
                break;
            }
            edges.push(BundleEdge {
                from: first_id.saturating_add(offset),
                to: first_id.saturating_add(target),
                kind: edge_kind(block, *successor),
            });
        }
    }
    truncated
}

const fn edge_kind(block: &CfgBlock, successor: u64) -> EdgeKind {
    match block.kind {
        BlockKind::Conditional if successor == block.end => EdgeKind::BranchFalse,
        BlockKind::Conditional => EdgeKind::BranchTrue,
        BlockKind::FallThrough => EdgeKind::Fallthrough,
        BlockKind::Jump | BlockKind::Return | BlockKind::Indirect => EdgeKind::Jump,
    }
}

fn bundle_dfg(summary: &DfgSummary) -> BundleDfg {
    let mut defs: Vec<BundleSite> = Vec::new();
    let mut uses: Vec<BundleUse> = Vec::new();
    let mut unreached_reads: Vec<BundleSite> = Vec::new();
    let mut truncated: bool = false;

    for function in &summary.functions {
        let var: String = memory_var(function);
        for write in &function.write_sites {
            if defs.len() >= MAX_DFG_SITES {
                truncated = true;
                break;
            }
            defs.push(BundleSite {
                var: var.clone(),
                pc: *write,
            });
        }
        for edge in &function.edges {
            if uses.len() >= MAX_DFG_SITES {
                truncated = true;
                break;
            }
            uses.push(BundleUse {
                var: var.clone(),
                pc: edge.to,
                def_pc: edge.from,
            });
        }
        let reached: BTreeSet<u64> = function
            .edges
            .iter()
            .map(|edge: &DataEdge| edge.to)
            .collect();
        for read in &function.read_sites {
            if reached.contains(read) {
                continue;
            }
            if unreached_reads.len() >= MAX_DFG_SITES {
                truncated = true;
                break;
            }
            unreached_reads.push(BundleSite {
                var: var.clone(),
                pc: *read,
            });
        }
    }

    BundleDfg {
        function: MODULE_UNIT,
        lang: summary.lang.clone(),
        ssa: false,
        defs,
        uses,
        unreached_reads,
        truncated,
    }
}

fn memory_var(function: &DfgFunction) -> String {
    format!("{}::memory", function.name)
}
