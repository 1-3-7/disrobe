use std::collections::{BTreeMap, BTreeSet, VecDeque};

use disrobe_nir::{
    DefUse, NirBlock, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, ValueId,
    basic_blocks, def_use,
};

use crate::config::TaintConfig;
use crate::report::{TaintFinding, TaintReport, TaintStep};

type OriginMap = BTreeMap<u64, LiveTaint>;
type ValueMap = BTreeMap<ValueId, OriginMap>;

struct ResolvedModule<'a> {
    module: &'a NirModule,
    symbol_by_addr: BTreeMap<u64, &'a NirSymbol>,
    function_at: BTreeMap<u64, usize>,
}

impl<'a> ResolvedModule<'a> {
    fn new(module: &'a NirModule) -> Self {
        let symbol_by_addr: BTreeMap<u64, &'a NirSymbol> = module
            .symbols
            .iter()
            .map(|s: &'a NirSymbol| (s.address, s))
            .collect();
        let function_at: BTreeMap<u64, usize> = module
            .functions
            .iter()
            .enumerate()
            .map(|(idx, f): (usize, &'a NirFunction)| (f.address, idx))
            .collect();
        Self {
            module,
            symbol_by_addr,
            function_at,
        }
    }

    fn callee_symbol(&self, instr: &NirInstr) -> Option<String> {
        match &instr.op {
            NirOp::ExternCall { symbol } => Some(symbol.clone()),
            NirOp::Call { target: Some(addr) } => self
                .symbol_by_addr
                .get(addr)
                .map(|s: &&'a NirSymbol| s.name.clone()),
            _ => None,
        }
    }

    fn callee_internal(&self, instr: &NirInstr) -> Option<u64> {
        match &instr.op {
            NirOp::Call { target: Some(addr) } if self.function_at.contains_key(addr) => {
                Some(*addr)
            }
            _ => None,
        }
    }

    fn external_callee(&self, instr: &NirInstr) -> Option<String> {
        match &instr.op {
            NirOp::ExternCall { .. } | NirOp::Call { target: Some(_) }
                if self.callee_internal(instr).is_none() =>
            {
                self.callee_symbol(instr)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Interproc {
    source_returning: BTreeSet<u64>,
    sink_reaching: BTreeSet<u64>,
}

#[must_use]
pub fn analyze(module: &NirModule, config: &TaintConfig) -> TaintReport {
    if config.is_empty() {
        return TaintReport::empty();
    }
    let resolved: ResolvedModule<'_> = ResolvedModule::new(module);
    let mut interproc: Interproc = Interproc::default();
    for _iteration in 0..interproc_iteration_cap(resolved.module.functions.len()) {
        let next: Interproc = propagate_interproc(&resolved, config, &interproc);
        if next.source_returning == interproc.source_returning
            && next.sink_reaching == interproc.sink_reaching
        {
            return collect_findings(&resolved, config, &interproc);
        }
        interproc = next;
    }
    collect_findings(&resolved, config, &interproc)
}

const fn interproc_iteration_cap(functions: usize) -> usize {
    functions.saturating_mul(2).saturating_add(1)
}

fn propagate_interproc(
    resolved: &ResolvedModule<'_>,
    config: &TaintConfig,
    current: &Interproc,
) -> Interproc {
    let mut next: Interproc = current.clone();
    for function in &resolved.module.functions {
        let intrinsic: FunctionTaint =
            analyze_function(resolved, config, current, function, false, false);
        if intrinsic.taint_returns {
            next.source_returning.insert(function.address);
        }
        if intrinsic.reaches_sink {
            next.sink_reaching.insert(function.address);
        }
        let forwarded: FunctionTaint =
            analyze_function(resolved, config, current, function, true, false);
        if forwarded.reaches_sink {
            next.sink_reaching.insert(function.address);
        }
    }
    next
}

fn collect_findings(
    resolved: &ResolvedModule<'_>,
    config: &TaintConfig,
    interproc: &Interproc,
) -> TaintReport {
    let mut findings: Vec<TaintFinding> = Vec::new();
    let mut truncated: bool = false;
    for function in &resolved.module.functions {
        let summary: FunctionTaint =
            analyze_function(resolved, config, interproc, function, false, true);
        findings.extend(summary.findings);
        truncated = truncated || summary.truncated;
    }
    findings.sort_by(|a: &TaintFinding, b: &TaintFinding| {
        a.function
            .cmp(&b.function)
            .then(a.source_site.cmp(&b.source_site))
            .then(a.sink_site.cmp(&b.sink_site))
    });
    findings.dedup();
    TaintReport::new_with_truncated(findings, truncated)
}

#[derive(Debug, Default)]
struct FunctionTaint {
    taint_returns: bool,
    reaches_sink: bool,
    truncated: bool,
    findings: Vec<TaintFinding>,
}

#[derive(Debug, Clone)]
struct LiveTaint {
    origin_site: u64,
    origin_symbol: String,
    path: Vec<TaintStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StateKey {
    flag: Vec<u64>,
    values: Vec<(ValueId, Vec<u64>)>,
}

fn analyze_function(
    resolved: &ResolvedModule<'_>,
    config: &TaintConfig,
    interproc: &Interproc,
    function: &NirFunction,
    entry_tainted: bool,
    record: bool,
) -> FunctionTaint {
    let blocks: Vec<NirBlock> = basic_blocks(function);
    if blocks.is_empty() {
        return FunctionTaint::default();
    }
    let index_of: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(idx, b): (usize, &NirBlock)| (b.start, idx))
        .collect();

    let mut entry_state: Vec<BlockState> = vec![BlockState::default(); blocks.len()];
    if entry_tainted {
        let seed: LiveTaint = LiveTaint {
            origin_site: function.address,
            origin_symbol: function.name.clone(),
            path: vec![TaintStep {
                address: function.address,
                symbol: function.name.clone(),
                kind: "parameter".to_owned(),
            }],
        };
        entry_state[0].insert_flag(seed.clone());
        entry_state[0].insert_value(ValueId::register(PARAMETER_REGISTER), seed);
    }
    let mut summary: FunctionTaint = FunctionTaint::default();
    let mut worklist: VecDeque<usize> = VecDeque::new();
    worklist.push_back(0);
    let mut visited_with: BTreeSet<(usize, StateKey)> = BTreeSet::new();
    let max_states: usize = config.max_states_per_function();

    while let Some(block_idx) = worklist.pop_front() {
        let block: &NirBlock = &blocks[block_idx];
        let incoming: BlockState = entry_state[block_idx].clone();
        if visited_with.len() >= max_states {
            summary.truncated = true;
            break;
        }
        if !visited_with.insert(incoming.visit_key(block_idx)) {
            continue;
        }
        let outcome: BlockOutcome = walk_block(
            resolved,
            config,
            interproc,
            function,
            block,
            incoming,
            record,
            &mut summary,
        );
        if outcome.taint_returns {
            summary.taint_returns = true;
        }
        let exit: BlockState = outcome.exit;
        for succ in &block.successors {
            let Some(succ_idx): Option<&usize> = index_of.get(succ) else {
                summary.truncated = true;
                continue;
            };
            let before: StateKey = entry_state[*succ_idx].key();
            entry_state[*succ_idx].merge(&exit);
            let after: StateKey = entry_state[*succ_idx].key();
            let unseen: bool = !visited_with.contains(&(*succ_idx, after.clone()));
            if after != before || unseen {
                worklist.push_back(*succ_idx);
            }
        }
    }
    summary
}

const PARAMETER_REGISTER: &str = "rdi";
const RETURN_REGISTER: &str = "rax";

#[derive(Debug, Clone, Default)]
struct BlockState {
    flag: OriginMap,
    values: ValueMap,
}

impl BlockState {
    fn key(&self) -> StateKey {
        StateKey {
            flag: self.flag.keys().copied().collect(),
            values: self
                .values
                .iter()
                .map(|(value, taints): (&ValueId, &OriginMap)| {
                    (value.clone(), taints.keys().copied().collect())
                })
                .collect(),
        }
    }

    fn visit_key(&self, block_idx: usize) -> (usize, StateKey) {
        (block_idx, self.key())
    }

    fn merge(&mut self, incoming: &Self) {
        for (origin_site, taint) in &incoming.flag {
            self.flag
                .entry(*origin_site)
                .or_insert_with(|| taint.clone());
        }
        for (value, taints) in &incoming.values {
            let merged: &mut OriginMap = self.values.entry(value.clone()).or_default();
            for (origin_site, taint) in taints {
                merged.entry(*origin_site).or_insert_with(|| taint.clone());
            }
        }
    }

    fn insert_flag(&mut self, taint: LiveTaint) {
        self.flag.insert(taint.origin_site, taint);
    }

    fn insert_value(&mut self, value: ValueId, taint: LiveTaint) {
        self.values
            .entry(value)
            .or_default()
            .insert(taint.origin_site, taint);
    }
}

struct BlockOutcome {
    exit: BlockState,
    taint_returns: bool,
}

#[allow(clippy::too_many_arguments)]
fn walk_block(
    resolved: &ResolvedModule<'_>,
    config: &TaintConfig,
    interproc: &Interproc,
    function: &NirFunction,
    block: &NirBlock,
    incoming: BlockState,
    record: bool,
    summary: &mut FunctionTaint,
) -> BlockOutcome {
    let mut state: BlockState = incoming;
    let mut taint_returns: bool = false;
    for instr in &block.instructions {
        let is_source: bool = call_is_source(resolved, config, interproc, instr);
        let is_sink: bool = call_is_sink(resolved, config, interproc, instr);
        let symbol: Option<String> = resolved.callee_symbol(instr);
        let defuse: DefUse = def_use(instr);

        if is_sink {
            let mut reached: BTreeMap<u64, &LiveTaint> = BTreeMap::new();
            for value in &defuse.uses {
                if let Some(taints) = state.values.get(value) {
                    for (origin_site, taint) in taints {
                        reached.entry(*origin_site).or_insert(taint);
                    }
                }
            }
            if reached.is_empty() && defuse.uses.is_empty() {
                for (origin_site, taint) in &state.flag {
                    reached.entry(*origin_site).or_insert(taint);
                }
            }
            if !reached.is_empty() {
                summary.reaches_sink = true;
                if record {
                    let sink_symbol: String = symbol.clone().unwrap_or_else(|| "<sink>".to_owned());
                    for current in reached.values() {
                        let mut path: Vec<TaintStep> = current.path.clone();
                        path.push(TaintStep {
                            address: instr.address,
                            symbol: sink_symbol.clone(),
                            kind: "sink".to_owned(),
                        });
                        summary.findings.push(TaintFinding {
                            function: function.name.clone(),
                            function_address: function.address,
                            source_site: current.origin_site,
                            source_symbol: current.origin_symbol.clone(),
                            sink_site: instr.address,
                            sink_symbol: sink_symbol.clone(),
                            path,
                        });
                    }
                }
            }
        }

        if is_source {
            let origin_symbol: String = symbol.unwrap_or_else(|| "<source>".to_owned());
            let origin: LiveTaint = LiveTaint {
                origin_site: instr.address,
                origin_symbol: origin_symbol.clone(),
                path: vec![TaintStep {
                    address: instr.address,
                    symbol: origin_symbol,
                    kind: "source".to_owned(),
                }],
            };
            state.insert_flag(origin.clone());
            for def in &defuse.defs {
                state.insert_value(def.clone(), origin.clone());
            }
        } else {
            propagate_values(&mut state, instr, &defuse, record);
            if propagates(instr) && record {
                for current in state.flag.values_mut() {
                    current.path.push(TaintStep {
                        address: instr.address,
                        symbol: instr.mnemonic.clone(),
                        kind: "propagate".to_owned(),
                    });
                }
            }
        }

        if matches!(instr.op, NirOp::Return)
            && (!state.flag.is_empty()
                || defuse.uses.iter().any(|value: &ValueId| {
                    state
                        .values
                        .get(value)
                        .is_some_and(|taints: &OriginMap| !taints.is_empty())
                }))
        {
            taint_returns = true;
        }
        if severs_wasm_stack_value(instr) {
            state.flag.clear();
            state.values.remove(&ValueId::register(RETURN_REGISTER));
        }
    }
    BlockOutcome {
        exit: state,
        taint_returns,
    }
}

fn propagate_values(state: &mut BlockState, instr: &NirInstr, defuse: &DefUse, record: bool) {
    if defuse.defs.is_empty() {
        return;
    }
    let mut tainting_uses: OriginMap = OriginMap::new();
    for value in &defuse.uses {
        if let Some(taints) = state.values.get(value) {
            for (origin_site, taint) in taints {
                tainting_uses
                    .entry(*origin_site)
                    .or_insert_with(|| taint.clone());
            }
        }
    }
    if tainting_uses.is_empty() {
        for def in &defuse.defs {
            state.values.remove(def);
        }
        return;
    }
    if record {
        for taint in tainting_uses.values_mut() {
            taint.path.push(TaintStep {
                address: instr.address,
                symbol: instr.mnemonic.clone(),
                kind: "propagate".to_owned(),
            });
        }
    }
    for def in &defuse.defs {
        state.values.insert(def.clone(), tainting_uses.clone());
    }
}

fn severs_wasm_stack_value(instr: &NirInstr) -> bool {
    instr.source.lang == SourceLang::Wasm
        && matches!(
            instr.mnemonic.as_str(),
            "drop" | "else" | "i32.const" | "i64.const" | "f32.const" | "f64.const"
        )
}

fn call_is_source(
    resolved: &ResolvedModule<'_>,
    config: &TaintConfig,
    interproc: &Interproc,
    instr: &NirInstr,
) -> bool {
    if let Some(symbol) = resolved.external_callee(instr)
        && config.is_source(&symbol)
    {
        return true;
    }
    resolved
        .callee_internal(instr)
        .is_some_and(|addr: u64| interproc.source_returning.contains(&addr))
}

fn call_is_sink(
    resolved: &ResolvedModule<'_>,
    config: &TaintConfig,
    interproc: &Interproc,
    instr: &NirInstr,
) -> bool {
    if let Some(symbol) = resolved.external_callee(instr)
        && config.is_sink(&symbol)
    {
        return true;
    }
    resolved
        .callee_internal(instr)
        .is_some_and(|addr: u64| interproc.sink_reaching.contains(&addr))
}

const fn propagates(instr: &NirInstr) -> bool {
    matches!(
        instr.op,
        NirOp::BinOp { .. } | NirOp::Load | NirOp::Store | NirOp::Phi
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn taint(origin_site: u64) -> LiveTaint {
        LiveTaint {
            origin_site,
            origin_symbol: format!("source_{origin_site}"),
            path: Vec::new(),
        }
    }

    #[test]
    fn state_key_preserves_distinct_origin_sets() {
        let mut left: BlockState = BlockState::default();
        left.insert_value(ValueId::register("a"), taint(1));
        left.insert_value(ValueId::register("b"), taint(2));

        let mut right: BlockState = BlockState::default();
        right.insert_value(ValueId::register("a"), taint(3));
        right.insert_value(ValueId::register("b"), taint(0));

        assert_ne!(left.key(), right.key());
        assert_ne!(left.visit_key(4), right.visit_key(4));
    }
}
