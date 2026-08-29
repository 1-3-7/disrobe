use std::collections::{BTreeMap, BTreeSet, VecDeque};

use disrobe_nir::{
    DefUse, NirBlock, NirClass, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang,
    ValueId, basic_blocks, def_use,
};

use crate::abi::CallAbi;
use crate::callgraph::{
    CallEdge, CallEdgeEvidence, CallEdgeLabel, normalize_call_edges, scc_bottom_up,
    unresolved_non_internal_edge,
};
use crate::config::{OutArgument, ResolvedSinkPolicy, TaintConfig};
use crate::report::{TaintFinding, TaintReport, TaintStep, UnresolvedCall, UnresolvedCallKind};
use crate::summary::{
    Arena, FeatureSet, FunctionSummary, KindSet, OutPort, PathId, SinkFrame, SummaryKey,
};
use crate::thunks::ImportThunks;

const MAX_PATH_STEPS: usize = 128;
const MAX_RECORDED_UNRESOLVED_CALLS: usize = 4096;

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
    thunks: &'a ImportThunks,
    abi: CallAbi,
    call_targets_by_site: BTreeMap<u64, Vec<u64>>,
    call_kind_by_site: BTreeMap<u64, &'static str>,
    uncertain_call_sites: BTreeSet<u64>,
    call_edges: Vec<CallEdge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectCall {
    ToAddress(u64),
    ToUnknown,
}

const fn direct_call(instr: &NirInstr) -> Option<DirectCall> {
    match instr.op {
        NirOp::Call { target } | NirOp::TailCall { target } | NirOp::NoReturnCall { target } => {
            Some(match target {
                Some(address) => DirectCall::ToAddress(address),
                None => DirectCall::ToUnknown,
            })
        }
        _ => None,
    }
}

fn call_kind_rank(kind: &str) -> u8 {
    match kind {
        "call-definite" => 0,
        "call-finite-set" => 1,
        "call-symbolic" => 2,
        "call-unresolved" => 3,
        _ => 4,
    }
}

impl<'a> ResolvedModule<'a> {
    fn new(module: &'a NirModule, thunks: &'a ImportThunks, call_edges: &[CallEdge]) -> Self {
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
        let abi: CallAbi = CallAbi::detect(module);
        let supplied_sites: BTreeSet<u64> =
            call_edges.iter().map(|edge: &CallEdge| edge.site).collect();
        let mut collected: Vec<CallEdge> = call_edges.to_vec();
        for function in &module.functions {
            for instr in &function.instructions {
                if instr.op.class() != NirClass::Call {
                    continue;
                }
                if !supplied_sites.contains(&instr.address) {
                    collected.push(match &instr.op {
                        NirOp::ExternCall { symbol } => CallEdge::symbolic(
                            instr.address,
                            CallEdgeEvidence::NamedExternal {
                                symbol: symbol.clone(),
                            },
                        ),
                        _ => match direct_call(instr) {
                            Some(DirectCall::ToAddress(target)) => CallEdge::definite(
                                instr.address,
                                target,
                                CallEdgeEvidence::DirectCall,
                            ),
                            Some(DirectCall::ToUnknown) | None => CallEdge::unresolved(
                                instr.address,
                                CallEdgeEvidence::NavigationIndirect,
                            ),
                        },
                    });
                }
            }
        }
        let mut call_edges: Vec<CallEdge> = normalize_call_edges(collected);
        let mut non_internal_edges: Vec<CallEdge> = Vec::new();
        for edge in &call_edges {
            if !matches!(edge.label, CallEdgeLabel::FiniteSet { .. }) {
                continue;
            }
            let non_internal: BTreeSet<u64> = edge
                .label
                .targets()
                .iter()
                .copied()
                .filter(|target: &u64| {
                    !function_at.contains_key(target) || thunks.name_at(*target).is_some()
                })
                .collect();
            if let Some(unresolved) = unresolved_non_internal_edge(edge.site, non_internal) {
                non_internal_edges.push(unresolved);
            }
        }
        call_edges.extend(non_internal_edges);
        call_edges = normalize_call_edges(call_edges);
        let mut call_targets_by_site: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        let mut call_kind_by_site: BTreeMap<u64, &'static str> = BTreeMap::new();
        let mut uncertain_call_sites: BTreeSet<u64> = BTreeSet::new();
        for edge in &call_edges {
            call_targets_by_site
                .entry(edge.site)
                .or_default()
                .extend(edge.label.targets());
            let kind: &'static str = edge.label.path_kind();
            call_kind_by_site
                .entry(edge.site)
                .and_modify(|current: &mut &'static str| {
                    if call_kind_rank(kind) > call_kind_rank(*current) {
                        *current = kind;
                    }
                })
                .or_insert(kind);
            if matches!(
                &edge.label,
                CallEdgeLabel::Symbolic | CallEdgeLabel::Unresolved
            ) {
                uncertain_call_sites.insert(edge.site);
            }
        }
        for targets in call_targets_by_site.values_mut() {
            targets.sort_unstable();
            targets.dedup();
        }
        Self {
            module,
            symbol_by_addr,
            function_at,
            thunks,
            abi,
            call_targets_by_site,
            call_kind_by_site,
            uncertain_call_sites,
            call_edges,
        }
    }

    fn named_at(&self, addr: u64) -> Option<String> {
        self.symbol_by_addr
            .get(&addr)
            .map(|s: &&'a NirSymbol| s.name.clone())
            .or_else(|| self.thunks.name_at(addr).map(str::to_owned))
    }

    fn callee_symbol(&self, instr: &NirInstr) -> Option<String> {
        if let NirOp::ExternCall { symbol } = &instr.op {
            return Some(symbol.clone());
        }
        let DirectCall::ToAddress(addr) = direct_call(instr)? else {
            return None;
        };
        self.named_at(addr)
    }

    fn callee_internal(&self, instr: &NirInstr) -> Option<u64> {
        self.callee_internals(instr)
            .into_iter()
            .next()
            .map(|(address, _kind): (u64, &'static str)| address)
    }

    fn callee_internals(&self, instr: &NirInstr) -> Vec<(u64, &'static str)> {
        let Some(targets): Option<&Vec<u64>> = self.call_targets_by_site.get(&instr.address) else {
            return Vec::new();
        };
        let kind: &'static str = self
            .call_kind_by_site
            .get(&instr.address)
            .copied()
            .unwrap_or("call-unresolved");
        targets
            .iter()
            .copied()
            .filter(|address: &u64| {
                self.thunks.name_at(*address).is_none() && self.function_at.contains_key(address)
            })
            .map(|address: u64| (address, kind))
            .collect()
    }

    fn external_symbol(&self, instr: &NirInstr) -> Option<String> {
        if self.callee_internal(instr).is_some() {
            return None;
        }
        self.callee_symbol(instr)
    }

    fn call_kind(&self, instr: &NirInstr) -> &'static str {
        self.call_kind_by_site
            .get(&instr.address)
            .copied()
            .unwrap_or("call-unresolved")
    }

    fn unresolved_call(&self, function: &NirFunction, instr: &NirInstr) -> Option<UnresolvedCall> {
        if matches!(instr.op, NirOp::ExternCall { .. }) {
            return None;
        }
        if self.uncertain_call_sites.contains(&instr.address) && instr.op.class() == NirClass::Call
        {
            return Some(UnresolvedCall {
                function: function.name.clone(),
                function_address: function.address,
                site: instr.address,
                kind: UnresolvedCallKind::IndirectTarget,
                target: None,
            });
        }
        if matches!(instr.op, NirOp::IndirectCall)
            && self
                .call_targets_by_site
                .get(&instr.address)
                .is_some_and(|targets: &Vec<u64>| !targets.is_empty())
        {
            return None;
        }
        let (kind, target): (UnresolvedCallKind, Option<u64>) = match &instr.op {
            NirOp::ExternCall { .. } => return None,
            NirOp::IndirectCall => (UnresolvedCallKind::IndirectTarget, None),
            _ => match direct_call(instr)? {
                DirectCall::ToUnknown => (UnresolvedCallKind::IndirectTarget, None),
                DirectCall::ToAddress(addr) => {
                    if self.function_at.contains_key(&addr) || self.named_at(addr).is_some() {
                        return None;
                    }
                    (UnresolvedCallKind::UnnamedTarget, Some(addr))
                }
            },
        };
        Some(UnresolvedCall {
            function: function.name.clone(),
            function_address: function.address,
            site: instr.address,
            kind,
            target,
        })
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
    analyze_with_call_edges_and_import_thunks(module, config, &[], &ImportThunks::new())
}

#[must_use]
pub fn analyze_with_call_edges(
    module: &NirModule,
    config: &TaintConfig,
    call_edges: &[CallEdge],
) -> TaintReport {
    analyze_with_call_edges_and_import_thunks(module, config, call_edges, &ImportThunks::new())
}

#[must_use]
pub fn analyze_with_import_thunks(
    module: &NirModule,
    config: &TaintConfig,
    thunks: &ImportThunks,
) -> TaintReport {
    analyze_with_call_edges_and_import_thunks(module, config, &[], thunks)
}

fn analyze_with_call_edges_and_import_thunks(
    module: &NirModule,
    config: &TaintConfig,
    call_edges: &[CallEdge],
    thunks: &ImportThunks,
) -> TaintReport {
    let resolved: ResolvedModule<'_> = ResolvedModule::new(module, thunks, call_edges);
    if config.is_empty() {
        return TaintReport::empty().with_call_edges(resolved.call_edges);
    }
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
    let (unresolved_calls, unresolved_call_count): (Vec<UnresolvedCall>, usize) =
        collect_unresolved_calls(&resolved);
    TaintReport::new_with_truncated(findings, truncated)
        .with_unresolved_calls(unresolved_calls, unresolved_call_count)
        .with_call_edges(resolved.call_edges)
}

fn collect_unresolved_calls(resolved: &ResolvedModule<'_>) -> (Vec<UnresolvedCall>, usize) {
    let mut recorded: Vec<UnresolvedCall> = Vec::new();
    let mut total: usize = 0;
    for function in &resolved.module.functions {
        for instr in &function.instructions {
            let Some(call): Option<UnresolvedCall> = resolved.unresolved_call(function, instr)
            else {
                continue;
            };
            total = total.saturating_add(1);
            if recorded.len() < MAX_RECORDED_UNRESOLVED_CALLS {
                recorded.push(call);
            }
        }
    }
    recorded.sort_by(|a: &UnresolvedCall, b: &UnresolvedCall| {
        a.function_address
            .cmp(&b.function_address)
            .then(a.site.cmp(&b.site))
            .then(a.function.cmp(&b.function))
    });
    (recorded, total)
}

fn call_adjacency(resolved: &ResolvedModule<'_>) -> Vec<Vec<usize>> {
    resolved
        .module
        .functions
        .iter()
        .map(|function: &NirFunction| {
            let mut callees: BTreeSet<usize> = BTreeSet::new();
            for instr in &function.instructions {
                for (address, _edge) in resolved.callee_internals(instr) {
                    if let Some(index) = resolved.function_at.get(&address) {
                        callees.insert(*index);
                    }
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
    established: BTreeMap<PathId, Option<String>>,
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
            established: self.established.clone(),
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
        for (loc, expr) in &incoming.established {
            self.established.entry(*loc).or_insert_with(|| expr.clone());
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
    established: BTreeMap<PathId, Option<String>>,
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
    for (index, register) in ctx.resolved.abi.argument_registers().iter().enumerate() {
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
        let defuse: DefUse = taint_def_use(ctx.resolved.abi, instr);
        let is_call: bool = instr.op.class() == NirClass::Call;
        let callees: Vec<(u64, &'static str)> = ctx.resolved.callee_internals(instr);
        if !callees.is_empty() {
            let incoming: BlockState = state.clone();
            let mut merged: Option<BlockState> = None;
            for (callee, call_kind) in callees {
                let mut candidate: BlockState = incoming.clone();
                instantiate_callee(
                    ctx,
                    arena,
                    mode,
                    instr,
                    callee,
                    call_kind,
                    &mut candidate,
                    out,
                );
                match &mut merged {
                    Some(existing) => existing.merge(&candidate),
                    None => merged = Some(candidate),
                }
            }
            if let Some(candidate) = merged {
                state = candidate;
            }
        } else if let Some(symbol) = ctx.resolved.external_symbol(instr) {
            let external_defuse: DefUse = external_taint_def_use(ctx, instr, &symbol, defuse);
            let call_kind: &'static str = ctx.resolved.call_kind(instr);
            dispatch_external(
                ctx,
                arena,
                mode,
                instr,
                &symbol,
                call_kind,
                &external_defuse,
                &mut state,
                out,
            );
        } else {
            if !is_call {
                track_established_registers(ctx.resolved.abi, arena, &defuse, &mut state);
            }
            propagate(arena, instr, &defuse, &mut state);
        }
        if is_call {
            clear_established_argument_registers(ctx, arena, &mut state);
        }
        if mode == WalkMode::Summarize && matches!(instr.op, NirOp::Return) {
            extract_outputs(ctx.resolved.abi, arena, instr, &state, &mut out.summary);
        }
        if severs_wasm_stack_value(instr) {
            state.flag.clear();
            let returned: PathId = reg_loc(arena, ctx.resolved.abi.return_register());
            state.values.remove(&returned);
        }
    }
    state
}

fn taint_def_use(abi: CallAbi, instr: &NirInstr) -> DefUse {
    if matches!(instr.op, NirOp::Nop)
        && let Some(moved) = abi.register_move(instr)
    {
        return moved;
    }
    let defuse: DefUse = abi.normalize_def_use(def_use(instr));
    if instr.op.class() == NirClass::Call {
        return DefUse {
            defs: vec![ValueId::register(abi.return_register())],
            uses: defuse.uses,
        };
    }
    defuse
}

fn external_taint_def_use(ctx: &Ctx<'_>, instr: &NirInstr, symbol: &str, defuse: DefUse) -> DefUse {
    let configured: bool = ctx.config.source_kind(symbol).is_some()
        || ctx.config.sink_policy(symbol).is_some()
        || ctx.config.sanitizer_feature(symbol).is_some();
    if !crate::abi::is_native(instr.source.lang)
        || !matches!(direct_call(instr), Some(DirectCall::ToAddress(_)))
        || !configured
    {
        return defuse;
    }
    DefUse {
        defs: defuse.defs,
        uses: ctx
            .resolved
            .abi
            .argument_registers()
            .iter()
            .map(|register: &&str| ValueId::register(register))
            .collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_external(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    mode: WalkMode,
    instr: &NirInstr,
    symbol: &str,
    call_kind: &str,
    defuse: &DefUse,
    state: &mut BlockState,
    out: &mut Outputs,
) {
    if let Some(kind) = ctx.config.source_kind(symbol) {
        apply_source(ctx, arena, instr, symbol, call_kind, kind, defuse, state);
    } else if let Some(policy) = ctx.config.sink_policy(symbol) {
        apply_sink(
            ctx, arena, mode, instr, symbol, call_kind, &policy, defuse, state, out,
        );
    } else if let Some(feature) = ctx.config.sanitizer_feature(symbol) {
        apply_sanitizer(arena, instr, symbol, call_kind, feature, defuse, state);
    } else {
        propagate(arena, instr, defuse, state);
    }
}

fn apply_source(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    instr: &NirInstr,
    symbol: &str,
    call_kind: &str,
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
        path: vec![
            step(instr.address, symbol, call_kind),
            step(instr.address, symbol, "source"),
        ],
    };
    let out_argument_defs: Vec<ValueId> =
        established_out_argument_defs(ctx, arena, instr, symbol, state);
    for def in defuse.defs.iter().chain(out_argument_defs.iter()) {
        let loc: PathId = arena.location(def);
        let mut map: FactMap = FactMap::new();
        map.insert(fact.key, fact.clone());
        state.values.insert(loc, map);
    }
    state.flag.insert(fact.key, fact);
}

fn established_out_argument_defs(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    instr: &NirInstr,
    symbol: &str,
    state: &BlockState,
) -> Vec<ValueId> {
    if !crate::abi::is_native(instr.source.lang) {
        return Vec::new();
    }
    let abi: CallAbi = ctx.resolved.abi;
    let register_count: usize = abi.argument_registers().len();
    let mut defs: Vec<ValueId> = Vec::new();
    let out_arguments: &[OutArgument] = ctx.config.source_out_arguments(symbol);
    for out_argument in out_arguments {
        for index in out_argument.indices(register_count) {
            let Ok(index): Result<u16, _> = u16::try_from(index) else {
                continue;
            };
            for register in abi.out_argument_candidates(index) {
                let value: ValueId = ValueId::register(register);
                let loc: PathId = arena.location(&value);
                let Some(established_via) = state.established.get(&loc) else {
                    continue;
                };
                defs.push(value);
                if let Some(reduced) = established_via {
                    defs.push(ValueId::memory(reduced));
                }
            }
        }
    }
    defs
}

fn clear_established_argument_registers(ctx: &Ctx<'_>, arena: &mut Arena, state: &mut BlockState) {
    for register in ctx.resolved.abi.argument_registers() {
        let loc: PathId = reg_loc(arena, register);
        state.established.remove(&loc);
    }
}

fn track_established_registers(
    abi: CallAbi,
    arena: &mut Arena,
    defuse: &DefUse,
    state: &mut BlockState,
) {
    let established_via: Option<String> =
        defuse.uses.iter().find_map(|value: &ValueId| match value {
            ValueId::Memory(expr) => reduce_indexed_memory_expr(abi, expr),
            ValueId::Register(_) | ValueId::Stack(_) => None,
        });
    for def in &defuse.defs {
        if matches!(def, ValueId::Register(_)) {
            let loc: PathId = arena.location(def);
            state.established.insert(loc, established_via.clone());
        }
    }
}

fn reduce_indexed_memory_expr(abi: CallAbi, expr: &str) -> Option<String> {
    let inner: &str = expr.strip_prefix('[')?.strip_suffix(']')?;
    let mut base: Option<&str> = None;
    let mut displacement_terms: Vec<&str> = Vec::new();
    let mut dropped_index: bool = false;
    for (offset, term) in signed_terms(inner) {
        let register_part: &str = term
            .trim_start_matches(['+', '-'])
            .split('*')
            .next()
            .unwrap_or_default();
        if abi.canonical_register(register_part).is_some() {
            if offset == 0 && base.is_none() {
                base = Some(term);
            } else {
                dropped_index = true;
            }
        } else {
            displacement_terms.push(term);
        }
    }
    if !dropped_index {
        return None;
    }
    let base: &str = base?;
    let mut reduced: String = String::from("[");
    reduced.push_str(base);
    for term in displacement_terms {
        reduced.push_str(term);
    }
    reduced.push(']');
    Some(reduced)
}

fn signed_terms(inner: &str) -> Vec<(usize, &str)> {
    let mut terms: Vec<(usize, &str)> = Vec::new();
    let mut start: usize = 0;
    for (offset, ch) in inner.char_indices() {
        if offset > start && matches!(ch, '+' | '-') {
            terms.push((start, &inner[start..offset]));
            start = offset;
        }
    }
    if start < inner.len() {
        terms.push((start, &inner[start..]));
    }
    terms
}

#[allow(clippy::too_many_arguments)]
fn apply_sink(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    mode: WalkMode,
    instr: &NirInstr,
    symbol: &str,
    call_kind: &str,
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
                append_step(&mut path, step(instr.address, symbol, call_kind));
                append_step(&mut path, step(instr.address, symbol, "sink"));
                push_finding(out, ctx.function, &fact, symbol, instr.address, path);
            }
        } else if let (WalkMode::Summarize, Some(arg)) = (mode, fact.formal_index()) {
            let mut path: Vec<TaintStep> = fact.path.clone();
            append_step(&mut path, step(instr.address, symbol, call_kind));
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
    call_kind: &str,
    feature: FeatureSet,
    defuse: &DefUse,
    state: &mut BlockState,
) {
    let incoming: Vec<(Fact, bool)> = gather_reaching(arena, defuse, state);
    let mut produced: FactMap = FactMap::new();
    for (mut fact, _via_flag) in incoming {
        fact.features.insert(feature);
        append_step(&mut fact.path, step(instr.address, symbol, call_kind));
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
    call_kind: &str,
    state: &mut BlockState,
    out: &mut Outputs,
) {
    let callee_name: String = ctx
        .resolved
        .function_name(callee)
        .unwrap_or("<callee>")
        .to_owned();
    let arg_locs: Vec<PathId> = ctx
        .resolved
        .abi
        .argument_registers()
        .iter()
        .map(|register: &&str| reg_loc(arena, register))
        .collect();
    let arg_facts: Vec<FactMap> = arg_locs
        .iter()
        .map(|loc: &PathId| state.values.get(loc).cloned().unwrap_or_default())
        .collect();
    let flag_facts: FactMap = state.flag.clone();
    let returned: PathId = reg_loc(arena, ctx.resolved.abi.return_register());
    state.values.remove(&returned);

    let Some(summary): Option<&FunctionSummary> = ctx.summaries.get(&callee) else {
        return;
    };
    let summary: FunctionSummary = summary.clone();

    for (port, generation) in &summary.generations {
        let Some(loc): Option<PathId> = out_port_location(&arg_locs, returned, *port) else {
            continue;
        };
        let fact: Fact = Fact {
            key: FactKey::Source(instr.address),
            kinds: generation.kinds,
            features: generation.features,
            origin_symbol: callee_name.clone(),
            origin_site: instr.address,
            path: vec![
                step(instr.address, &callee_name, call_kind),
                step(instr.address, &callee_name, "source"),
            ],
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
            let Some(loc): Option<PathId> = out_port_location(&arg_locs, returned, *port) else {
                continue;
            };
            for source_fact in sources.values() {
                let mut fact: Fact = source_fact.clone();
                fact.kinds.insert(propagation.kinds);
                fact.features.insert(propagation.features);
                append_step(&mut fact.path, step(instr.address, &callee_name, call_kind));
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
            call_kind,
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
    call_kind: &str,
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
                append_step(&mut path, step(instr.address, callee_name, call_kind));
                append_step(&mut path, step(instr.address, callee_name, "sink"));
                for hop in &frame.path {
                    append_step(&mut path, hop.clone());
                }
                push_finding(out, ctx.function, cf, callee_name, instr.address, path);
            }
        } else if let (WalkMode::Summarize, Some(arg)) = (mode, cf.formal_index()) {
            let mut path: Vec<TaintStep> = cf.path.clone();
            append_step(&mut path, step(instr.address, callee_name, call_kind));
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

fn out_port_location(arg_locs: &[PathId], returned: PathId, port: OutPort) -> Option<PathId> {
    match port {
        OutPort::Return => Some(returned),
        OutPort::Argument(index) => arg_locs.get(index as usize).copied(),
    }
}

fn extract_outputs(
    abi: CallAbi,
    arena: &mut Arena,
    instr: &NirInstr,
    state: &BlockState,
    summary: &mut FunctionSummary,
) {
    let returned: PathId = reg_loc(arena, abi.return_register());
    if let Some(map) = state.values.get(&returned) {
        for fact in map.values() {
            record_output(summary, OutPort::Return, fact, instr);
        }
    }
    for fact in state.flag.values() {
        if fact.is_concrete() {
            record_output(summary, OutPort::Return, fact, instr);
        }
    }
    for (index, register) in abi.argument_registers().iter().enumerate() {
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod reduction_tests {
    use super::{CallAbi, reduce_indexed_memory_expr};

    #[test]
    fn a_base_plus_index_plus_displacement_reduces_by_dropping_the_index() {
        assert_eq!(
            reduce_indexed_memory_expr(CallAbi::X86, "[rsp+r9+30h]").as_deref(),
            Some("[rsp+30h]")
        );
    }

    #[test]
    fn a_base_plus_index_with_no_displacement_reduces_to_the_bare_base() {
        assert_eq!(
            reduce_indexed_memory_expr(CallAbi::X86, "[rsp+r9]").as_deref(),
            Some("[rsp]")
        );
    }

    #[test]
    fn a_base_with_no_index_has_nothing_to_reduce() {
        assert_eq!(reduce_indexed_memory_expr(CallAbi::X86, "[rax-63h]"), None);
        assert_eq!(reduce_indexed_memory_expr(CallAbi::X86, "[rsp+30h]"), None);
        assert_eq!(reduce_indexed_memory_expr(CallAbi::X86, "[rax]"), None);
    }

    #[test]
    fn a_rip_relative_expression_has_no_recognizable_base_and_is_not_reduced() {
        assert_eq!(
            reduce_indexed_memory_expr(CallAbi::X86, "[rel 140005050h]"),
            None
        );
    }

    #[test]
    fn a_scaled_index_still_reduces_to_the_base_and_displacement() {
        assert_eq!(
            reduce_indexed_memory_expr(CallAbi::X86, "[rsp+r9*4+30h]").as_deref(),
            Some("[rsp+30h]")
        );
    }

    #[test]
    fn a_malformed_expression_without_brackets_is_not_reduced() {
        assert_eq!(reduce_indexed_memory_expr(CallAbi::X86, "rsp+r9+30h"), None);
        assert_eq!(reduce_indexed_memory_expr(CallAbi::X86, ""), None);
    }

    #[test]
    fn a_base_that_is_not_the_first_term_is_not_reduced() {
        assert_eq!(
            reduce_indexed_memory_expr(CallAbi::X86, "[30h+r9+rsp]"),
            None
        );
    }
}
