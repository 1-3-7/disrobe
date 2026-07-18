use std::collections::{BTreeMap, BTreeSet, VecDeque};

use disrobe_nir::{
    DefUse, NirBlock, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, ValueId,
    basic_blocks, def_use,
};

use crate::callgraph::scc_bottom_up;
use crate::config::{ResolvedSinkPolicy, TaintConfig};
use crate::report::{TaintFinding, TaintReport, TaintStep};
use crate::summary::{
    Arena, FeatureSet, FunctionSummary, KindSet, OutPort, PathId, SinkFrame, SummaryKey,
};

const ARG_REGISTERS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
const RETURN_REGISTER: &str = "rax";
const MAX_PATH_STEPS: usize = 128;

type Summaries = BTreeMap<u64, FunctionSummary>;
type FactMap = BTreeMap<FactKey, Fact>;
type FactSig = Vec<(FactKey, u64, u64)>;
type ValueSig = Vec<(PathId, FactSig)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum FactKey {
    Formal(u16),
    Source(u64),
}

#[derive(Debug, Clone)]
struct Fact {
    key: FactKey,
    kinds: KindSet,
    features: FeatureSet,
    origin_symbol: String,
    origin_site: u64,
    path: Vec<TaintStep>,
}

impl Fact {
    const fn is_concrete(&self) -> bool {
        matches!(self.key, FactKey::Source(_))
    }

    const fn formal_index(&self) -> Option<u16> {
        match self.key {
            FactKey::Formal(index) => Some(index),
            FactKey::Source(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkMode {
    Summarize,
    Collect,
}

#[derive(Debug, Default)]
struct Outputs {
    summary: FunctionSummary,
    findings: Vec<TaintFinding>,
    truncated: bool,
}

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

    fn external_symbol(&self, instr: &NirInstr) -> Option<String> {
        if self.callee_internal(instr).is_some() {
            return None;
        }
        self.callee_symbol(instr)
    }

    fn function_name(&self, addr: u64) -> Option<&str> {
        self.function_at
            .get(&addr)
            .and_then(|idx: &usize| self.module.functions.get(*idx))
            .map(|f: &NirFunction| f.name.as_str())
    }
}

struct Ctx<'a> {
    resolved: &'a ResolvedModule<'a>,
    config: &'a TaintConfig,
    summaries: &'a Summaries,
    function: &'a NirFunction,
}

#[must_use]
pub fn analyze(module: &NirModule, config: &TaintConfig) -> TaintReport {
    if config.is_empty() {
        return TaintReport::empty();
    }
    let resolved: ResolvedModule<'_> = ResolvedModule::new(module);
    let mut arena: Arena = Arena::default();
    let mut summaries: Summaries = Summaries::new();

    let order: Vec<Vec<usize>> = scc_bottom_up(&call_adjacency(&resolved));
    for component in &order {
        solve_component(&resolved, config, &mut arena, &mut summaries, component);
    }

    let mut findings: Vec<TaintFinding> = Vec::new();
    let mut truncated: bool = false;
    for function in &resolved.module.functions {
        let ctx: Ctx<'_> = Ctx {
            resolved: &resolved,
            config,
            summaries: &summaries,
            function,
        };
        let out: Outputs = walk_function(&ctx, &mut arena, WalkMode::Collect);
        findings.extend(out.findings);
        truncated = truncated || out.truncated;
    }

    findings.sort_by(|a: &TaintFinding, b: &TaintFinding| {
        a.function
            .cmp(&b.function)
            .then(a.source_symbol.cmp(&b.source_symbol))
            .then(a.source_site.cmp(&b.source_site))
            .then(a.sink_symbol.cmp(&b.sink_symbol))
            .then(a.sink_site.cmp(&b.sink_site))
    });
    findings.dedup_by(|a: &mut TaintFinding, b: &mut TaintFinding| {
        a.function == b.function
            && a.source_symbol == b.source_symbol
            && a.source_site == b.source_site
            && a.sink_symbol == b.sink_symbol
            && a.sink_site == b.sink_site
    });
    TaintReport::new_with_truncated(findings, truncated)
}

fn call_adjacency(resolved: &ResolvedModule<'_>) -> Vec<Vec<usize>> {
    resolved
        .module
        .functions
        .iter()
        .map(|function: &NirFunction| {
            let mut callees: BTreeSet<usize> = BTreeSet::new();
            for instr in &function.instructions {
                if let Some(addr) = resolved.callee_internal(instr)
                    && let Some(idx) = resolved.function_at.get(&addr)
                {
                    callees.insert(*idx);
                }
            }
            callees.into_iter().collect()
        })
        .collect()
}

fn solve_component(
    resolved: &ResolvedModule<'_>,
    config: &TaintConfig,
    arena: &mut Arena,
    summaries: &mut Summaries,
    component: &[usize],
) {
    let mut members: Vec<usize> = component.to_vec();
    members.sort_by_key(|idx: &usize| {
        resolved
            .module
            .functions
            .get(*idx)
            .map_or(u64::MAX, |f: &NirFunction| f.address)
    });
    loop {
        let mut changed: bool = false;
        for idx in &members {
            let Some(function): Option<&NirFunction> = resolved.module.functions.get(*idx) else {
                continue;
            };
            let ctx: Ctx<'_> = Ctx {
                resolved,
                config,
                summaries,
                function,
            };
            let out: Outputs = walk_function(&ctx, arena, WalkMode::Summarize);
            let key: SummaryKey = out.summary.semantic_key();
            let differs: bool = summaries
                .get(&function.address)
                .is_none_or(|existing: &FunctionSummary| existing.semantic_key() != key);
            if differs {
                summaries.insert(function.address, out.summary);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

#[derive(Debug, Clone, Default)]
struct BlockState {
    values: BTreeMap<PathId, FactMap>,
    flag: FactMap,
}

impl BlockState {
    fn visit_key(&self) -> StateKey {
        let values: ValueSig = self
            .values
            .iter()
            .map(|(loc, facts): (&PathId, &FactMap)| (*loc, fact_signature(facts)))
            .collect();
        StateKey {
            values,
            flag: fact_signature(&self.flag),
        }
    }

    fn merge(&mut self, incoming: &Self) {
        for (loc, facts) in &incoming.values {
            let target: &mut FactMap = self.values.entry(*loc).or_default();
            for fact in facts.values() {
                merge_fact(target, fact.clone());
            }
        }
        for fact in incoming.flag.values() {
            merge_fact(&mut self.flag, fact.clone());
        }
    }
}

fn fact_signature(facts: &FactMap) -> FactSig {
    facts
        .values()
        .map(|fact: &Fact| (fact.key, fact.kinds.bits(), fact.features.bits()))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StateKey {
    values: ValueSig,
    flag: FactSig,
}

fn merge_fact(map: &mut FactMap, fact: Fact) {
    match map.get_mut(&fact.key) {
        Some(existing) => {
            existing.kinds.insert(fact.kinds);
            existing.features = existing.features.intersect(fact.features);
        }
        None => {
            map.insert(fact.key, fact);
        }
    }
}

fn walk_function(ctx: &Ctx<'_>, arena: &mut Arena, mode: WalkMode) -> Outputs {
    let mut out: Outputs = Outputs::default();
    let blocks: Vec<NirBlock> = basic_blocks(ctx.function);
    if blocks.is_empty() {
        return out;
    }
    let index_of: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(idx, b): (usize, &NirBlock)| (b.start, idx))
        .collect();

    let mut entry_state: Vec<BlockState> = vec![BlockState::default(); blocks.len()];
    seed_formals(ctx, arena, &mut entry_state[0]);

    let mut worklist: VecDeque<usize> = VecDeque::from([0usize]);
    let mut visited: BTreeSet<(usize, StateKey)> = BTreeSet::new();
    let max_states: usize = ctx.config.max_states_per_function();

    while let Some(block_idx) = worklist.pop_front() {
        if visited.len() >= max_states {
            out.truncated = true;
            break;
        }
        let incoming: BlockState = entry_state[block_idx].clone();
        if !visited.insert((block_idx, incoming.visit_key())) {
            continue;
        }
        let exit: BlockState = walk_block(ctx, arena, mode, &blocks[block_idx], incoming, &mut out);
        if terminator_target_outside_blocks(&blocks[block_idx], &index_of) {
            out.truncated = true;
        }
        for succ in &blocks[block_idx].successors {
            let Some(succ_idx): Option<&usize> = index_of.get(succ) else {
                out.truncated = true;
                continue;
            };
            let before: StateKey = entry_state[*succ_idx].visit_key();
            entry_state[*succ_idx].merge(&exit);
            let after: StateKey = entry_state[*succ_idx].visit_key();
            if after != before || !visited.contains(&(*succ_idx, after)) {
                worklist.push_back(*succ_idx);
            }
        }
    }
    out
}

fn terminator_target_outside_blocks(block: &NirBlock, index_of: &BTreeMap<u64, usize>) -> bool {
    let Some(last): Option<&NirInstr> = block.instructions.last() else {
        return false;
    };
    if !matches!(last.op, NirOp::Branch { .. } | NirOp::CondBranch { .. }) {
        return false;
    }
    last.direct_target()
        .is_some_and(|target: u64| !index_of.contains_key(&target))
}

fn seed_formals(ctx: &Ctx<'_>, arena: &mut Arena, state: &mut BlockState) {
    for (index, register) in ARG_REGISTERS.iter().enumerate() {
        let arg: u16 = index as u16;
        let fact: Fact = formal_fact(ctx.function, arg);
        let loc: PathId = reg_loc(arena, register);
        state.values.entry(loc).or_default().insert(fact.key, fact);
    }
    let flag_fact: Fact = formal_fact(ctx.function, 0);
    state.flag.insert(flag_fact.key, flag_fact);
}

fn formal_fact(function: &NirFunction, arg: u16) -> Fact {
    Fact {
        key: FactKey::Formal(arg),
        kinds: KindSet::EMPTY,
        features: FeatureSet::EMPTY,
        origin_symbol: function.name.clone(),
        origin_site: function.address,
        path: vec![step(function.address, &function.name, "parameter")],
    }
}

fn walk_block(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    mode: WalkMode,
    block: &NirBlock,
    incoming: BlockState,
    out: &mut Outputs,
) -> BlockState {
    let mut state: BlockState = incoming;
    for instr in &block.instructions {
        let defuse: DefUse = def_use(instr);
        if let Some(callee) = ctx.resolved.callee_internal(instr) {
            instantiate_callee(ctx, arena, mode, instr, callee, &mut state, out);
        } else if let Some(symbol) = ctx.resolved.external_symbol(instr) {
            dispatch_external(ctx, arena, mode, instr, &symbol, &defuse, &mut state, out);
        } else {
            propagate(arena, instr, &defuse, &mut state);
        }
        if mode == WalkMode::Summarize && matches!(instr.op, NirOp::Return) {
            extract_outputs(arena, instr, &state, &mut out.summary);
        }
        if severs_wasm_stack_value(instr) {
            state.flag.clear();
            let rax: PathId = reg_loc(arena, RETURN_REGISTER);
            state.values.remove(&rax);
        }
    }
    state
}

#[allow(clippy::too_many_arguments)]
fn dispatch_external(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    mode: WalkMode,
    instr: &NirInstr,
    symbol: &str,
    defuse: &DefUse,
    state: &mut BlockState,
    out: &mut Outputs,
) {
    if let Some(kind) = ctx.config.source_kind(symbol) {
        apply_source(arena, instr, symbol, kind, defuse, state);
    } else if let Some(policy) = ctx.config.sink_policy(symbol) {
        apply_sink(ctx, arena, mode, instr, symbol, &policy, defuse, state, out);
    } else if let Some(feature) = ctx.config.sanitizer_feature(symbol) {
        apply_sanitizer(arena, instr, symbol, feature, defuse, state);
    } else {
        propagate(arena, instr, defuse, state);
    }
}

fn apply_source(
    arena: &mut Arena,
    instr: &NirInstr,
    symbol: &str,
    kind: KindSet,
    defuse: &DefUse,
    state: &mut BlockState,
) {
    let fact: Fact = Fact {
        key: FactKey::Source(instr.address),
        kinds: kind,
        features: FeatureSet::EMPTY,
        origin_symbol: symbol.to_owned(),
        origin_site: instr.address,
        path: vec![step(instr.address, symbol, "source")],
    };
    for def in &defuse.defs {
        let loc: PathId = arena.location(def);
        let mut map: FactMap = FactMap::new();
        map.insert(fact.key, fact.clone());
        state.values.insert(loc, map);
    }
    state.flag.insert(fact.key, fact);
}

#[allow(clippy::too_many_arguments)]
fn apply_sink(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    mode: WalkMode,
    instr: &NirInstr,
    symbol: &str,
    policy: &ResolvedSinkPolicy,
    defuse: &DefUse,
    state: &mut BlockState,
    out: &mut Outputs,
) {
    for (fact, via_flag) in gather_reaching(arena, defuse, state) {
        if fact.is_concrete() {
            if mode == WalkMode::Collect
                && fact.kinds.intersects(policy.sensitive)
                && !fact.features.intersects(policy.suppress)
            {
                let mut path: Vec<TaintStep> = fact.path.clone();
                append_step(&mut path, step(instr.address, symbol, "sink"));
                push_finding(out, ctx.function, &fact, symbol, instr.address, path);
            }
        } else if let (WalkMode::Summarize, Some(arg)) = (mode, fact.formal_index()) {
            let mut path: Vec<TaintStep> = fact.path.clone();
            append_step(&mut path, step(instr.address, symbol, "sink"));
            out.summary.add_frame(SinkFrame {
                in_arg: arg,
                via_flag,
                sink_symbol: symbol.to_owned(),
                sink_site: instr.address,
                sink_kinds: policy.sensitive,
                suppress: policy.suppress,
                accumulated: fact.features,
                path,
            });
        }
    }
    for def in &defuse.defs {
        let loc: PathId = arena.location(def);
        state.values.remove(&loc);
    }
}

fn apply_sanitizer(
    arena: &mut Arena,
    instr: &NirInstr,
    symbol: &str,
    feature: FeatureSet,
    defuse: &DefUse,
    state: &mut BlockState,
) {
    let incoming: Vec<(Fact, bool)> = gather_reaching(arena, defuse, state);
    let mut produced: FactMap = FactMap::new();
    for (mut fact, _via_flag) in incoming {
        fact.features.insert(feature);
        append_step(&mut fact.path, step(instr.address, symbol, "sanitize"));
        produced.insert(fact.key, fact);
    }
    for def in &defuse.defs {
        let loc: PathId = arena.location(def);
        if produced.is_empty() {
            state.values.remove(&loc);
        } else {
            state.values.insert(loc, produced.clone());
        }
    }
    for fact in produced.into_values() {
        state.flag.insert(fact.key, fact);
    }
}

fn gather_reaching(arena: &mut Arena, defuse: &DefUse, state: &BlockState) -> Vec<(Fact, bool)> {
    let mut reached: Vec<(Fact, bool)> = Vec::new();
    for value in &defuse.uses {
        let loc: PathId = arena.location(value);
        if let Some(map) = state.values.get(&loc) {
            for fact in map.values() {
                reached.push((fact.clone(), false));
            }
        }
    }
    if reached.is_empty() && defuse.uses.is_empty() {
        for fact in state.flag.values() {
            reached.push((fact.clone(), true));
        }
    }
    reached
}

fn instantiate_callee(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    mode: WalkMode,
    instr: &NirInstr,
    callee: u64,
    state: &mut BlockState,
    out: &mut Outputs,
) {
    let callee_name: String = ctx
        .resolved
        .function_name(callee)
        .unwrap_or("<callee>")
        .to_owned();
    let arg_locs: Vec<PathId> = ARG_REGISTERS
        .iter()
        .map(|register: &&str| reg_loc(arena, register))
        .collect();
    let arg_facts: Vec<FactMap> = arg_locs
        .iter()
        .map(|loc: &PathId| state.values.get(loc).cloned().unwrap_or_default())
        .collect();
    let flag_facts: FactMap = state.flag.clone();
    let rax: PathId = reg_loc(arena, RETURN_REGISTER);
    state.values.remove(&rax);

    let Some(summary): Option<&FunctionSummary> = ctx.summaries.get(&callee) else {
        return;
    };
    let summary: FunctionSummary = summary.clone();

    for (port, generation) in &summary.generations {
        let Some(loc): Option<PathId> = out_port_location(&arg_locs, rax, *port) else {
            continue;
        };
        let fact: Fact = Fact {
            key: FactKey::Source(instr.address),
            kinds: generation.kinds,
            features: generation.features,
            origin_symbol: callee_name.clone(),
            origin_site: instr.address,
            path: vec![step(instr.address, &callee_name, "source")],
        };
        let mut map: FactMap = FactMap::new();
        map.insert(fact.key, fact.clone());
        state.values.insert(loc, map);
        if matches!(port, OutPort::Return) {
            state.flag.insert(fact.key, fact);
        }
    }

    for (in_arg, outs) in &summary.propagations {
        let Some(sources): Option<&FactMap> = arg_facts.get(*in_arg as usize) else {
            continue;
        };
        for (port, propagation) in outs {
            let Some(loc): Option<PathId> = out_port_location(&arg_locs, rax, *port) else {
                continue;
            };
            for source_fact in sources.values() {
                let mut fact: Fact = source_fact.clone();
                fact.kinds.insert(propagation.kinds);
                fact.features.insert(propagation.features);
                append_step(
                    &mut fact.path,
                    step(instr.address, &callee_name, "propagate"),
                );
                let carrier: Fact = fact.clone();
                merge_fact(state.values.entry(loc).or_default(), fact);
                if matches!(port, OutPort::Return) {
                    merge_fact(&mut state.flag, carrier);
                }
            }
        }
    }

    for frame in &summary.frames {
        instantiate_frame(
            ctx,
            mode,
            instr,
            &callee_name,
            frame,
            &arg_facts,
            &flag_facts,
            out,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn instantiate_frame(
    ctx: &Ctx<'_>,
    mode: WalkMode,
    instr: &NirInstr,
    callee_name: &str,
    frame: &SinkFrame,
    arg_facts: &[FactMap],
    flag_facts: &FactMap,
    out: &mut Outputs,
) {
    let empty: FactMap = FactMap::new();
    let candidates: &FactMap = if frame.via_flag {
        flag_facts
    } else {
        arg_facts.get(frame.in_arg as usize).unwrap_or(&empty)
    };
    for cf in candidates.values() {
        let effective: FeatureSet = cf.features.union(frame.accumulated);
        if cf.is_concrete() {
            if mode == WalkMode::Collect
                && cf.kinds.intersects(frame.sink_kinds)
                && !effective.intersects(frame.suppress)
            {
                let mut path: Vec<TaintStep> = cf.path.clone();
                append_step(&mut path, step(instr.address, callee_name, "sink"));
                for hop in &frame.path {
                    append_step(&mut path, hop.clone());
                }
                push_finding(out, ctx.function, cf, callee_name, instr.address, path);
            }
        } else if let (WalkMode::Summarize, Some(arg)) = (mode, cf.formal_index()) {
            let mut path: Vec<TaintStep> = cf.path.clone();
            append_step(&mut path, step(instr.address, callee_name, "sink"));
            for hop in &frame.path {
                append_step(&mut path, hop.clone());
            }
            out.summary.add_frame(SinkFrame {
                in_arg: arg,
                via_flag: frame.via_flag,
                sink_symbol: callee_name.to_owned(),
                sink_site: instr.address,
                sink_kinds: frame.sink_kinds,
                suppress: frame.suppress,
                accumulated: effective,
                path,
            });
        }
    }
}

fn out_port_location(arg_locs: &[PathId], rax: PathId, port: OutPort) -> Option<PathId> {
    match port {
        OutPort::Return => Some(rax),
        OutPort::Argument(index) => arg_locs.get(index as usize).copied(),
    }
}

fn extract_outputs(
    arena: &mut Arena,
    instr: &NirInstr,
    state: &BlockState,
    summary: &mut FunctionSummary,
) {
    let rax: PathId = reg_loc(arena, RETURN_REGISTER);
    if let Some(map) = state.values.get(&rax) {
        for fact in map.values() {
            record_output(summary, OutPort::Return, fact, instr);
        }
    }
    for fact in state.flag.values() {
        if fact.is_concrete() {
            record_output(summary, OutPort::Return, fact, instr);
        }
    }
    for (index, register) in ARG_REGISTERS.iter().enumerate() {
        let loc: PathId = reg_loc(arena, register);
        let Some(map): Option<&FactMap> = state.values.get(&loc) else {
            continue;
        };
        for fact in map.values() {
            if fact.formal_index() == Some(index as u16) {
                continue;
            }
            record_output(summary, OutPort::Argument(index as u16), fact, instr);
        }
    }
}

fn record_output(summary: &mut FunctionSummary, port: OutPort, fact: &Fact, instr: &NirInstr) {
    let mut path: Vec<TaintStep> = fact.path.clone();
    append_step(&mut path, step(instr.address, &instr.mnemonic, "return"));
    if fact.is_concrete() {
        summary.add_generation(port, fact.kinds, fact.features, &path);
    } else if let Some(arg) = fact.formal_index() {
        summary.add_propagation(arg, port, fact.kinds, fact.features, &path);
    }
}

fn propagate(arena: &mut Arena, instr: &NirInstr, defuse: &DefUse, state: &mut BlockState) {
    if !defuse.defs.is_empty() {
        let mut tainting: FactMap = FactMap::new();
        for value in &defuse.uses {
            let loc: PathId = arena.location(value);
            if let Some(map) = state.values.get(&loc) {
                for fact in map.values() {
                    merge_fact(&mut tainting, fact.clone());
                }
            }
        }
        if tainting.is_empty() {
            for def in &defuse.defs {
                let loc: PathId = arena.location(def);
                state.values.remove(&loc);
            }
        } else {
            for fact in tainting.values_mut() {
                append_step(
                    &mut fact.path,
                    step(instr.address, &instr.mnemonic, "propagate"),
                );
            }
            for def in &defuse.defs {
                let loc: PathId = arena.location(def);
                state.values.insert(loc, tainting.clone());
            }
        }
    }
    if propagates(instr) {
        for fact in state.flag.values_mut() {
            append_step(
                &mut fact.path,
                step(instr.address, &instr.mnemonic, "propagate"),
            );
        }
    }
}

fn push_finding(
    out: &mut Outputs,
    function: &NirFunction,
    source: &Fact,
    sink_symbol: &str,
    sink_site: u64,
    path: Vec<TaintStep>,
) {
    out.findings.push(TaintFinding {
        function: function.name.clone(),
        function_address: function.address,
        source_site: source.origin_site,
        source_symbol: source.origin_symbol.clone(),
        sink_site,
        sink_symbol: sink_symbol.to_owned(),
        path,
    });
}

fn reg_loc(arena: &mut Arena, register: &str) -> PathId {
    arena.location(&ValueId::register(register))
}

fn step(address: u64, symbol: &str, kind: &str) -> TaintStep {
    TaintStep {
        address,
        symbol: symbol.to_owned(),
        kind: kind.to_owned(),
    }
}

fn append_step(path: &mut Vec<TaintStep>, entry: TaintStep) {
    if path.len() < MAX_PATH_STEPS {
        path.push(entry);
    }
}

fn severs_wasm_stack_value(instr: &NirInstr) -> bool {
    instr.source.lang == SourceLang::Wasm
        && matches!(
            instr.mnemonic.as_str(),
            "drop" | "else" | "i32.const" | "i64.const" | "f32.const" | "f64.const"
        )
}

const fn propagates(instr: &NirInstr) -> bool {
    matches!(
        instr.op,
        NirOp::BinOp { .. } | NirOp::Load | NirOp::Store | NirOp::Phi
    )
}
