use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{NirFunction, NirInstr, NirModule, NirOp, NirSymbol};
use disrobe_query::Capability;
use serde::Serialize;
use serde_json::Value as Json;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityTag {
    pub capability: Capability,
    pub site_count: usize,
    pub symbols: Vec<String>,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct CapabilitySummary {
    pub lang: String,
    pub tags: Vec<CapabilityTag>,
}

impl CapabilitySummary {
    #[must_use]
    pub fn has(&self, capability: Capability) -> bool {
        self.tags
            .iter()
            .any(|t: &CapabilityTag| t.capability == capability)
    }

    #[must_use]
    pub fn tag(&self, capability: Capability) -> Option<&CapabilityTag> {
        self.tags
            .iter()
            .find(|t: &&CapabilityTag| t.capability == capability)
    }

    #[must_use]
    pub fn labels(&self) -> Vec<&'static str> {
        self.tags
            .iter()
            .map(|t: &CapabilityTag| t.capability.label())
            .collect()
    }

    #[must_use]
    pub fn to_json(&self) -> Json {
        serde_json::to_value(self).unwrap_or(Json::Null)
    }
}

struct Accumulator {
    site_count: usize,
    symbols: BTreeSet<String>,
    functions: BTreeSet<String>,
}

impl Accumulator {
    const fn new() -> Self {
        Self {
            site_count: 0,
            symbols: BTreeSet::new(),
            functions: BTreeSet::new(),
        }
    }
}

#[must_use]
pub fn capability_summary(module: &NirModule) -> CapabilitySummary {
    let symbol_by_addr: BTreeMap<u64, &NirSymbol> = module
        .symbols
        .iter()
        .map(|s: &NirSymbol| (s.address, s))
        .collect();
    let defined: BTreeSet<u64> = module
        .functions
        .iter()
        .map(|f: &NirFunction| f.address)
        .collect();

    let mut by_capability: BTreeMap<u8, (Capability, Accumulator)> = BTreeMap::new();
    for function in &module.functions {
        for insn in &function.instructions {
            let Some(symbol): Option<String> = external_callee(insn, &symbol_by_addr, &defined)
            else {
                continue;
            };
            let Some(capability): Option<Capability> = Capability::classify(&symbol) else {
                continue;
            };
            let entry: &mut (Capability, Accumulator) = by_capability
                .entry(capability_rank(capability))
                .or_insert_with(|| (capability, Accumulator::new()));
            entry.1.site_count += 1;
            entry.1.symbols.insert(symbol);
            entry.1.functions.insert(function.name.clone());
        }
    }

    let tags: Vec<CapabilityTag> = by_capability
        .into_values()
        .map(
            |(capability, acc): (Capability, Accumulator)| CapabilityTag {
                capability,
                site_count: acc.site_count,
                symbols: acc.symbols.into_iter().collect(),
                functions: acc.functions.into_iter().collect(),
            },
        )
        .collect();

    CapabilitySummary {
        lang: module.lang.label().to_owned(),
        tags,
    }
}

fn external_callee(
    insn: &NirInstr,
    symbol_by_addr: &BTreeMap<u64, &NirSymbol>,
    defined: &BTreeSet<u64>,
) -> Option<String> {
    match &insn.op {
        NirOp::ExternCall { symbol } => Some(symbol.clone()),
        NirOp::Call { target: Some(addr) } if !defined.contains(addr) => symbol_by_addr
            .get(addr)
            .map(|s: &&NirSymbol| s.name.clone()),
        _ => None,
    }
}

const fn capability_rank(capability: Capability) -> u8 {
    match capability {
        Capability::Network => 0,
        Capability::Crypto => 1,
        Capability::Filesystem => 2,
        Capability::Process => 3,
    }
}
