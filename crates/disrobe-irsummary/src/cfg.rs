use disrobe_nir::{BlockKind, NirBlock, NirFunction, NirModule, basic_blocks, complexity};
use serde::Serialize;
use serde_json::Value as Json;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CfgBlock {
    pub start: u64,
    pub end: u64,
    pub kind: BlockKind,
    pub instruction_count: usize,
    pub successors: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CfgFunction {
    pub name: String,
    pub address: u64,
    pub is_export: bool,
    pub cyclomatic_complexity: u32,
    pub edge_count: usize,
    pub blocks: Vec<CfgBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct CfgSummary {
    pub lang: String,
    pub functions: Vec<CfgFunction>,
}

impl CfgSummary {
    #[must_use]
    pub fn function(&self, name: &str) -> Option<&CfgFunction> {
        self.functions
            .iter()
            .find(|f: &&CfgFunction| f.name == name)
    }

    #[must_use]
    pub fn total_edges(&self) -> usize {
        self.functions
            .iter()
            .map(|f: &CfgFunction| f.edge_count)
            .sum()
    }

    #[must_use]
    pub fn total_blocks(&self) -> usize {
        self.functions
            .iter()
            .map(|f: &CfgFunction| f.blocks.len())
            .sum()
    }

    #[must_use]
    pub fn to_json(&self) -> Json {
        serde_json::to_value(self).unwrap_or(Json::Null)
    }
}

#[must_use]
pub fn cfg_summary(module: &NirModule) -> CfgSummary {
    let functions: Vec<CfgFunction> = module.functions.iter().map(function_summary).collect();
    CfgSummary {
        lang: module.lang.label().to_owned(),
        functions,
    }
}

fn function_summary(function: &NirFunction) -> CfgFunction {
    let blocks: Vec<NirBlock> = basic_blocks(function);
    let starts: Vec<u64> = blocks.iter().map(|b: &NirBlock| b.start).collect();
    let mut edge_count: usize = 0;
    let summary_blocks: Vec<CfgBlock> = blocks
        .iter()
        .map(|b: &NirBlock| {
            let successors: Vec<u64> = b
                .successors
                .iter()
                .copied()
                .filter(|s: &u64| starts.binary_search(s).is_ok())
                .collect();
            edge_count += successors.len();
            CfgBlock {
                start: b.start,
                end: b.end,
                kind: b.kind,
                instruction_count: b.instructions.len(),
                successors,
            }
        })
        .collect();
    CfgFunction {
        name: function.name.clone(),
        address: function.address,
        is_export: function.is_export,
        cyclomatic_complexity: complexity(function),
        edge_count,
        blocks: summary_blocks,
    }
}
