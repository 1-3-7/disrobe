use std::collections::{BTreeMap, BTreeSet, VecDeque};

use disrobe_nir::{
    BinaryOp, DefUse, NirBlock, NirClass, NirFunction, NirInstr, NirModule, NirOp, NirSymbol,
    SourceLang, ValueId, basic_blocks, def_use,
};

use crate::abi::CallAbi;
use crate::callgraph::{
    CallEdge, CallEdgeEvidence, CallEdgeLabel, normalize_call_edges, scc_bottom_up,
    unresolved_non_internal_edge,
};
use crate::config::{
    CopyTransfer, OutArgument, ResolvedSinkPolicy, TaintConfig, allocates, copy_transfer,
};
use crate::pointers::ConstantPointers;
use crate::report::{TaintFinding, TaintReport, TaintStep, UnresolvedCall, UnresolvedCallKind};
use crate::summary::{
    Arena, FeatureSet, FunctionSummary, InPort, KindSet, OutPort, PathId, PointerTarget, SinkFrame,
    SummaryKey, relative_address,
};
use crate::thunks::ImportThunks;

const MAX_PATH_STEPS: usize = 128;
const MAX_RECORDED_UNRESOLVED_CALLS: usize = 4096;
const PATH_TRUNCATED_KIND: &str = "path-truncated";
const TRACKED_CALL_KIND: &str = "call-finite-set";

type Summaries = BTreeMap<u64, FunctionSummary>;
type FactMap = BTreeMap<FactKey, Fact>;
type FactSig = Vec<(FactKey, u64, u64)>;
type ValueSig = Vec<(PathId, FactSig)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum FactKey {
    Formal(InPort),
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

    const fn formal_input(&self) -> Option<InPort> {
        match self.key {
            FactKey::Formal(input) => Some(input),
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
    constant_pointers: &'a ConstantPointers,
    abi: CallAbi,
    call_targets_by_site: BTreeMap<u64, Vec<u64>>,
    call_kind_by_site: BTreeMap<u64, &'static str>,
    call_symbols_by_site: BTreeMap<u64, BTreeSet<String>>,
    uncertain_call_sites: BTreeSet<u64>,
    external_tail_calls: BTreeSet<u64>,
    call_edges: Vec<CallEdge>,
    win64: bool,
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
    fn new(
        module: &'a NirModule,
        thunks: &'a ImportThunks,
        constant_pointers: &'a ConstantPointers,
        call_edges: &[CallEdge],
    ) -> Self {
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
        let mut external_tail_calls: BTreeSet<u64> = BTreeSet::new();
        for function in &module.functions {
            for instr in &function.instructions {
                if let NirOp::Branch {
                    target: Some(target),
                } = instr.op
                    && !(function.address..function.end).contains(&target)
                    && !supplied_sites.contains(&instr.address)
                    && let Some(symbol) = thunks.name_at(target).map(str::to_owned).or_else(|| {
                        symbol_by_addr
                            .get(&target)
                            .filter(|symbol: &&&'a NirSymbol| symbol.kind.is_external())
                            .map(|symbol: &&'a NirSymbol| symbol.name.clone())
                    })
                {
                    external_tail_calls.insert(instr.address);
                    collected.push(CallEdge::definite(
                        instr.address,
                        target,
                        CallEdgeEvidence::NamedExternal { symbol },
                    ));
                    continue;
                }
                if let NirOp::Branch {
                    target: Some(target),
                } = instr.op
                    && target != function.address
                    && !(function.address..function.end).contains(&target)
                    && function.instructions.iter().all(|candidate: &NirInstr| {
                        candidate.address == instr.address
                            || candidate.mnemonic.eq_ignore_ascii_case("nop")
                    })
                    && function_at.contains_key(&target)
                    && !supplied_sites.contains(&instr.address)
                {
                    collected.push(CallEdge::definite(
                        instr.address,
                        target,
                        CallEdgeEvidence::DirectTailTransfer,
                    ));
                    continue;
                }
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
        let mut call_symbols_by_site: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
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
                    if call_kind_rank(kind) > call_kind_rank(current) {
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
            for evidence in edge.evidence() {
                if let CallEdgeEvidence::NamedExternal { symbol } = evidence {
                    call_symbols_by_site
                        .entry(edge.site)
                        .or_default()
                        .insert(symbol.clone());
                }
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
            constant_pointers,
            abi,
            call_targets_by_site,
            call_kind_by_site,
            call_symbols_by_site,
            uncertain_call_sites,
            external_tail_calls,
            call_edges,
            win64: abi.detects_win64(module),
        }
    }

    fn argument_candidates(&self, index: u16) -> Vec<&'static str> {
        let mut candidates: Vec<&'static str> = self.abi.out_argument_candidates(index);
        candidates.retain(|register: &&str| self.passes_arguments_in(register));
        candidates
    }

    fn passes_arguments_in(&self, register: &str) -> bool {
        !(self.win64 && matches!(register, "rdi" | "rsi"))
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
        if let Some(symbols) = self.call_symbols_by_site.get(&instr.address)
            && symbols.len() == 1
        {
            return symbols.iter().next().cloned();
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
    analyze_with_inputs(
        module,
        config,
        &[],
        &ImportThunks::new(),
        &ConstantPointers::new(),
    )
}

#[must_use]
pub fn analyze_with_call_edges(
    module: &NirModule,
    config: &TaintConfig,
    call_edges: &[CallEdge],
) -> TaintReport {
    analyze_with_inputs(
        module,
        config,
        call_edges,
        &ImportThunks::new(),
        &ConstantPointers::new(),
    )
}

#[must_use]
pub fn analyze_with_import_thunks(
    module: &NirModule,
    config: &TaintConfig,
    thunks: &ImportThunks,
) -> TaintReport {
    analyze_with_inputs(module, config, &[], thunks, &ConstantPointers::new())
}

#[must_use]
pub fn analyze_with_constant_pointers(
    module: &NirModule,
    config: &TaintConfig,
    call_edges: &[CallEdge],
    constant_pointers: &ConstantPointers,
) -> TaintReport {
    analyze_with_inputs(
        module,
        config,
        call_edges,
        &ImportThunks::new(),
        constant_pointers,
    )
}

fn analyze_with_inputs(
    module: &NirModule,
    config: &TaintConfig,
    call_edges: &[CallEdge],
    thunks: &ImportThunks,
    constant_pointers: &ConstantPointers,
) -> TaintReport {
    let resolved: ResolvedModule<'_> =
        ResolvedModule::new(module, thunks, constant_pointers, call_edges);
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
    inherited: BTreeMap<PathId, String>,
    cells: BTreeMap<PathId, String>,
}

impl BlockState {
    fn alias_of(&self, loc: PathId) -> Option<&str> {
        self.established.get(&loc).map_or_else(
            || self.inherited.get(&loc).map(String::as_str),
            |alias: &Option<String>| alias.as_deref(),
        )
    }

    fn holds_argument(&self, loc: PathId) -> bool {
        self.established.contains_key(&loc) || self.inherited.contains_key(&loc)
    }

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
            inherited: self.inherited.clone(),
            cells: self.cells.clone(),
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
        for (loc, expr) in &incoming.inherited {
            self.inherited.entry(*loc).or_insert_with(|| expr.clone());
        }
        for (loc, expr) in &incoming.cells {
            self.cells.entry(*loc).or_insert_with(|| expr.clone());
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
    inherited: BTreeMap<PathId, String>,
    cells: BTreeMap<PathId, String>,
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
    match &last.op {
        NirOp::Branch { .. } | NirOp::CondBranch { .. } => last
            .direct_target()
            .is_some_and(|target: u64| !index_of.contains_key(&target)),
        NirOp::Switch { targets } => targets
            .iter()
            .any(|target: &u64| !index_of.contains_key(target)),
        _ => false,
    }
}

fn seed_formals(ctx: &Ctx<'_>, arena: &mut Arena, state: &mut BlockState) {
    for (index, register) in ctx.resolved.abi.argument_registers().iter().enumerate() {
        if !ctx.resolved.passes_arguments_in(register) {
            continue;
        }
        let arg: u16 = index as u16;
        let fact: Fact = formal_fact(ctx.function, arg);
        let loc: PathId = reg_loc(arena, register);
        state.values.entry(loc).or_default().insert(fact.key, fact);
        state.inherited.insert(loc, formal_pointee_expr(register));
    }
    let flag_fact: Fact = formal_fact(ctx.function, 0);
    state.flag.insert(flag_fact.key, flag_fact);
    for instr in &ctx.function.instructions {
        let defuse: DefUse = taint_def_use(ctx.resolved.abi, instr);
        for value in &defuse.uses {
            let ValueId::Memory(expr) = value else {
                continue;
            };
            if let Some(target) = constant_pointer_target(ctx, expr) {
                let global: ValueId = ValueId::memory(&global_expr(target));
                let loc: PathId = arena.location(&global);
                let fact: Fact = formal_input_fact(ctx.function, InPort::Global(loc));
                state.values.entry(loc).or_default().insert(fact.key, fact);
            }
            let input: Option<InPort> = memory_argument_projection(ctx.resolved.abi, expr)
                .filter(|(argument, _offset): &(u16, i64)| {
                    ctx.resolved
                        .abi
                        .argument_registers()
                        .get(*argument as usize)
                        .is_some_and(|register: &&str| ctx.resolved.passes_arguments_in(register))
                })
                .map(|(argument, offset): (u16, i64)| InPort::ArgumentMemory { argument, offset })
                .or_else(|| {
                    is_relative_memory(expr).then(|| InPort::Global(arena.location(value)))
                });
            let Some(input) = input else {
                continue;
            };
            let fact: Fact = formal_input_fact(ctx.function, input);
            let loc: PathId = arena.location(value);
            state.values.entry(loc).or_default().insert(fact.key, fact);
        }
    }
}

fn formal_pointee_expr(register: &str) -> String {
    format!("[@{register}]")
}

fn nested_pointee_expr(register: &str) -> String {
    format!("[@@{register}]")
}

fn formal_pointee(abi: CallAbi, arena: &Arena, loc: PathId) -> Option<InPort> {
    let (base, offset): (&str, i64) = arena.memory_projection(loc)?;
    let (nested, register): (bool, &str) = match base.strip_prefix("@@") {
        Some(register) => (true, register),
        None => (false, base.strip_prefix('@')?),
    };
    let argument: u16 = u16::try_from(
        abi.argument_registers()
            .iter()
            .position(|candidate: &&str| *candidate == register)?,
    )
    .ok()?;
    Some(if nested {
        InPort::ArgumentDeref { argument, offset }
    } else {
        InPort::ArgumentMemory { argument, offset }
    })
}

fn pointer_stored_at(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    state: &BlockState,
    expr: &str,
) -> Option<String> {
    let loc: PathId = arena.location(&ValueId::memory(expr));
    if let Some(pointee) = state.cells.get(&loc) {
        return Some(pointee.clone());
    }
    let InPort::ArgumentMemory {
        argument,
        offset: 0,
    } = formal_pointee(ctx.resolved.abi, arena, loc)?
    else {
        return None;
    };
    let register: &str = ctx
        .resolved
        .abi
        .argument_registers()
        .get(argument as usize)?;
    Some(nested_pointee_expr(register))
}

fn pointee_of_argument_pointer(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    state: &BlockState,
    argument_loc: PathId,
    offset: i64,
) -> Option<String> {
    let cell: String = offset_memory_expr(state.alias_of(argument_loc)?, 0)?;
    let pointee: String = pointer_stored_at(ctx, arena, state, &cell)?;
    offset_memory_expr(&pointee, offset)
}

fn global_expr(address: u64) -> String {
    format!("[rel {address:X}h]")
}

fn constant_pointer_target(ctx: &Ctx<'_>, expr: &str) -> Option<u64> {
    let slot: u64 = relative_address(memory_inner(expr)?)?;
    ctx.resolved.constant_pointers.target_at(slot)
}

fn read_location(ctx: &Ctx<'_>, arena: &mut Arena, state: &BlockState, expr: &str) -> FactMap {
    let loc: PathId = arena.location(&ValueId::memory(expr));
    if let Some(facts) = state.values.get(&loc) {
        return facts.clone();
    }
    let mut facts: FactMap = FactMap::new();
    if let Some(input) = formal_pointee(ctx.resolved.abi, arena, loc) {
        let fact: Fact = formal_input_fact(ctx.function, input);
        facts.insert(fact.key, fact);
    }
    facts
}

fn materialize_formal_pointee(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    state: &mut BlockState,
    expr: &str,
) {
    let loc: PathId = arena.location(&ValueId::memory(expr));
    if state.values.contains_key(&loc) {
        return;
    }
    let Some(input): Option<InPort> = formal_pointee(ctx.resolved.abi, arena, loc) else {
        return;
    };
    let fact: Fact = formal_input_fact(ctx.function, input);
    state.values.entry(loc).or_default().insert(fact.key, fact);
}

fn memory_base_and_displacement(abi: CallAbi, expr: &str) -> Option<(String, i64)> {
    let inner: &str = memory_inner(expr)?;
    let mut base: Option<String> = None;
    let mut displacement: i64 = 0;
    for (position, term) in signed_terms(inner) {
        let negative: bool = term.starts_with('-');
        let core: &str = term.trim_start_matches(['+', '-']).trim();
        let register_part: &str = core.split('*').next().unwrap_or_default();
        if let Some(register) = abi.canonical_register(register_part) {
            if position == 0 && !negative && !core.contains('*') {
                base = Some(register);
            }
        } else {
            let value: i64 = parse_native_integer(core)?;
            displacement = displacement.checked_add(if negative {
                value.checked_neg()?
            } else {
                value
            })?;
        }
    }
    Some((base?, displacement))
}

fn alias_reads(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    defuse: &DefUse,
    state: &mut BlockState,
) -> Vec<ValueId> {
    let abi: CallAbi = ctx.resolved.abi;
    let mut reads: Vec<ValueId> = Vec::new();
    for value in &defuse.uses {
        let ValueId::Memory(expr) = value else {
            continue;
        };
        let Some(redirected): Option<String> = pointee_through_base(abi, arena, state, expr) else {
            continue;
        };
        materialize_formal_pointee(ctx, arena, state, &redirected);
        reads.push(ValueId::memory(&redirected));
    }
    reads
}

fn formal_fact(function: &NirFunction, arg: u16) -> Fact {
    formal_input_fact(function, InPort::Argument(arg))
}

fn formal_input_fact(function: &NirFunction, input: InPort) -> Fact {
    Fact {
        key: FactKey::Formal(input),
        kinds: KindSet::EMPTY,
        features: FeatureSet::EMPTY,
        origin_symbol: function.name.clone(),
        origin_site: function.address,
        path: vec![step(function.address, &function.name, "parameter")],
    }
}

fn memory_argument_projection(abi: CallAbi, expr: &str) -> Option<(u16, i64)> {
    let inner: &str = memory_inner(expr)?;
    let mut base: Option<String> = None;
    let mut offset: i64 = 0;
    for (_position, term) in signed_terms(inner) {
        let sign: i64 = if term.starts_with('-') { -1 } else { 1 };
        let core: &str = term.trim_start_matches(['+', '-']);
        if core.contains('*') {
            return None;
        }
        if let Some(register) = abi.canonical_register(core) {
            if base.replace(register).is_some() {
                return None;
            }
        } else {
            offset = offset.checked_add(sign * parse_native_integer(core)?)?;
        }
    }
    let base: String = base?;
    let argument: usize = abi
        .argument_registers()
        .iter()
        .position(|register: &&str| **register == base)?;
    Some((u16::try_from(argument).ok()?, offset))
}

fn memory_inner(expr: &str) -> Option<&str> {
    let trimmed: &str = expr.trim();
    let without_size: &str = ["byte ", "word ", "dword ", "qword "]
        .iter()
        .find_map(|prefix: &&str| trimmed.strip_prefix(prefix))
        .unwrap_or(trimmed);
    without_size.strip_prefix('[')?.strip_suffix(']')
}

fn parse_native_integer(value: &str) -> Option<i64> {
    let value: &str = value.trim();
    if let Some(hex) = value.strip_suffix('h') {
        return i64::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = value.strip_prefix("0x") {
        return i64::from_str_radix(hex, 16).ok();
    }
    value.parse::<i64>().ok()
}

fn is_relative_memory(expr: &str) -> bool {
    memory_inner(expr).is_some_and(|inner: &str| inner.trim_start().starts_with("rel "))
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
        let tail_call: bool = ctx.resolved.external_tail_calls.contains(&instr.address);
        let mut defuse: DefUse = taint_def_use(ctx.resolved.abi, instr);
        if tail_call {
            defuse.defs = vec![ValueId::register(ctx.resolved.abi.return_register())];
        }
        let is_call: bool = tail_call || instr.op.class() == NirClass::Call;
        let mut returned_pointee: Option<String> = None;
        let mut callees: Vec<(u64, &'static str)> = ctx.resolved.callee_internals(instr);
        if callees.is_empty()
            && let Some(target) = tracked_call_target(ctx, arena, instr, &state)
        {
            callees.push((target, TRACKED_CALL_KIND));
        }
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
            if ctx.resolved.uncertain_call_sites.contains(&instr.address) {
                let mut candidate: BlockState = incoming;
                propagate(arena, instr, &defuse, &mut candidate);
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
            returned_pointee = dispatch_external(
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
        } else if is_call {
            propagate(arena, instr, &defuse, &mut state);
        } else {
            let reads: Vec<ValueId> = alias_reads(ctx, arena, &defuse, &mut state);
            defuse.uses.extend(reads);
            track_established_locations(ctx, arena, instr, &defuse, &mut state);
            propagate(arena, instr, &defuse, &mut state);
        }
        if is_call {
            clear_call_clobbered_aliases(ctx, arena, &mut state);
            if let Some(pointee) = returned_pointee {
                let returned: PathId = reg_loc(arena, ctx.resolved.abi.return_register());
                state.established.insert(returned, Some(pointee));
            }
        }
        if mode == WalkMode::Summarize && (tail_call || matches!(instr.op, NirOp::Return)) {
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

fn tracked_call_target(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    instr: &NirInstr,
    state: &BlockState,
) -> Option<u64> {
    let indirect: bool = matches!(instr.op, NirOp::IndirectCall)
        || matches!(direct_call(instr), Some(DirectCall::ToUnknown));
    if !indirect || instr.operands.len() != 1 {
        return None;
    }
    let operand: &str = instr.operands.first()?;
    let pointee: String = if let Some(register) = ctx.resolved.abi.register_value(operand) {
        state.alias_of(arena.location(&register))?.to_owned()
    } else if memory_inner(operand).is_some() {
        state
            .cells
            .get(&arena.location(&ValueId::memory(operand)))?
            .clone()
    } else {
        return None;
    };
    let target: u64 = relative_address(memory_inner(&pointee)?)?;
    (ctx.resolved.function_at.contains_key(&target)
        && ctx.resolved.thunks.name_at(target).is_none())
    .then_some(target)
}

fn taint_def_use(abi: CallAbi, instr: &NirInstr) -> DefUse {
    if is_flag_comparison(instr) {
        return DefUse {
            defs: Vec::new(),
            uses: abi.normalize_def_use(def_use(instr)).uses,
        };
    }
    if zeroes_register(abi, instr) {
        return DefUse {
            defs: abi.normalize_def_use(def_use(instr)).defs,
            uses: Vec::new(),
        };
    }
    if let Some(address) = abi.address_calculation(instr) {
        return address;
    }
    if let Some(transfer) = abi.memory_transfer(instr) {
        return transfer;
    }
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

fn zeroes_register(abi: CallAbi, instr: &NirInstr) -> bool {
    let [destination, source]: &[String] = instr.operands.as_slice() else {
        return false;
    };
    matches!(
        instr.op,
        NirOp::BinOp {
            op: BinaryOp::Xor | BinaryOp::Sub
        }
    ) && abi
        .register_value(destination)
        .is_some_and(|register: ValueId| abi.register_value(source) == Some(register))
}

fn is_flag_comparison(instr: &NirInstr) -> bool {
    crate::abi::is_native(instr.source.lang)
        && (instr.mnemonic.eq_ignore_ascii_case("cmp")
            || instr.mnemonic.eq_ignore_ascii_case("test"))
}

fn external_taint_def_use(ctx: &Ctx<'_>, instr: &NirInstr, symbol: &str, defuse: DefUse) -> DefUse {
    let configured: bool = ctx.config.source_kind(symbol).is_some()
        || ctx.config.sink_policy(symbol).is_some()
        || ctx.config.sanitizer_feature(symbol).is_some();
    let addressed: bool = matches!(direct_call(instr), Some(DirectCall::ToAddress(_)))
        || ctx.resolved.external_tail_calls.contains(&instr.address);
    if !crate::abi::is_native(instr.source.lang) || !addressed || !configured {
        return defuse;
    }
    DefUse {
        defs: defuse.defs,
        uses: ctx
            .resolved
            .abi
            .argument_registers()
            .iter()
            .filter(|register: &&&str| ctx.resolved.passes_arguments_in(register))
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
) -> Option<String> {
    if let Some(kind) = ctx.config.source_kind(symbol) {
        apply_source(ctx, arena, instr, symbol, call_kind, kind, defuse, state);
    } else if let Some(policy) = ctx.config.sink_policy(symbol) {
        apply_sink(
            ctx, arena, mode, instr, symbol, call_kind, &policy, defuse, state, out,
        );
    } else if let Some(feature) = ctx.config.sanitizer_feature(symbol) {
        apply_sanitizer(ctx, arena, instr, symbol, call_kind, feature, defuse, state);
    } else if let Some(transfer) = copy_transfer(symbol) {
        return apply_copy(
            ctx, arena, instr, symbol, call_kind, transfer, defuse, state,
        );
    } else if allocates(symbol) {
        propagate(arena, instr, defuse, state);
        return Some(heap_object_expr(instr.address));
    } else {
        propagate(arena, instr, defuse, state);
    }
    None
}

fn heap_object_expr(site: u64) -> String {
    format!("[#{site:X}]")
}

#[allow(clippy::too_many_arguments)]
fn apply_copy(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    instr: &NirInstr,
    symbol: &str,
    call_kind: &str,
    transfer: CopyTransfer,
    defuse: &DefUse,
    state: &mut BlockState,
) -> Option<String> {
    let mut copied: FactMap = FactMap::new();
    if crate::abi::is_native(instr.source.lang) {
        for register in ctx.resolved.argument_candidates(transfer.source) {
            let loc: PathId = reg_loc(arena, register);
            if !state.holds_argument(loc) {
                continue;
            }
            let alias: Option<String> = state.alias_of(loc).map(str::to_owned);
            if let Some(facts) = state.values.get(&loc) {
                for fact in facts.values() {
                    merge_fact(&mut copied, fact.clone());
                }
            }
            if let Some(alias) = alias {
                for fact in read_location(ctx, arena, state, &alias).into_values() {
                    merge_fact(&mut copied, fact);
                }
            }
        }
    }
    for fact in copied.values_mut() {
        append_step(&mut fact.path, step(instr.address, symbol, call_kind));
        append_step(&mut fact.path, step(instr.address, symbol, "propagate"));
    }
    if !copied.is_empty() {
        for target in buffer_targets(ctx, arena, state, transfer.destination) {
            if let ValueId::Memory(expr) = &target {
                materialize_formal_pointee(ctx, arena, state, expr);
            }
            let loc: PathId = arena.location(&target);
            let entry: &mut FactMap = state.values.entry(loc).or_default();
            for fact in copied.values() {
                merge_fact(entry, fact.clone());
            }
        }
    }
    for def in &defuse.defs {
        let loc: PathId = arena.location(def);
        if copied.is_empty() {
            state.values.remove(&loc);
        } else {
            state.values.insert(loc, copied.clone());
        }
    }
    ctx.resolved
        .argument_candidates(transfer.destination)
        .into_iter()
        .find_map(|register: &str| {
            state
                .established
                .get(&reg_loc(arena, register))
                .cloned()
                .flatten()
        })
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
    let register_count: usize = ctx.resolved.abi.argument_registers().len();
    let mut defs: Vec<ValueId> = Vec::new();
    let out_arguments: &[OutArgument] = ctx.config.source_out_arguments(symbol);
    for out_argument in out_arguments {
        for index in out_argument.indices(register_count) {
            let Ok(index): Result<u16, _> = u16::try_from(index) else {
                continue;
            };
            defs.extend(buffer_targets(ctx, arena, state, index));
        }
    }
    defs
}

fn buffer_targets(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    state: &BlockState,
    index: u16,
) -> Vec<ValueId> {
    let abi: CallAbi = ctx.resolved.abi;
    let mut targets: Vec<ValueId> = Vec::new();
    for register in ctx.resolved.argument_candidates(index) {
        let value: ValueId = ValueId::register(register);
        let loc: PathId = arena.location(&value);
        let Some(established_via) = state.established.get(&loc) else {
            continue;
        };
        targets.push(value);
        let Some(reduced) = established_via else {
            continue;
        };
        targets.push(ValueId::memory(reduced));
        let Some(base) = memory_base_register(abi, reduced) else {
            continue;
        };
        if abi.is_stack_pointer(&base) {
            continue;
        }
        targets.push(ValueId::register(&base));
    }
    targets
}

fn memory_base_register(abi: CallAbi, expr: &str) -> Option<String> {
    let inner: &str = memory_inner(expr)?;
    signed_terms(inner)
        .into_iter()
        .find_map(|(_position, term): (usize, &str)| {
            let core: &str = term
                .trim_start_matches(['+', '-'])
                .split('*')
                .next()
                .unwrap_or_default();
            abi.canonical_register(core)
        })
}

fn clear_call_clobbered_aliases(ctx: &Ctx<'_>, arena: &mut Arena, state: &mut BlockState) {
    for register in ctx
        .resolved
        .abi
        .call_clobbered_registers(ctx.resolved.win64)
    {
        let loc: PathId = reg_loc(arena, register);
        state.established.remove(&loc);
        state.inherited.remove(&loc);
    }
}

fn track_established_locations(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    instr: &NirInstr,
    defuse: &DefUse,
    state: &mut BlockState,
) {
    let abi: CallAbi = ctx.resolved.abi;
    let is_lea: bool = instr.mnemonic.eq_ignore_ascii_case("lea");
    let register_alias: Option<String> = if is_lea {
        instr
            .operands
            .get(1)
            .filter(|expr: &&String| !sets_frame_base(abi, instr, expr))
            .and_then(|expr: &String| {
                pointee_through_base(abi, arena, state, expr).or_else(|| {
                    reduce_indexed_memory_expr(abi, expr)
                        .or_else(|| memory_inner(expr).map(|inner: &str| format!("[{inner}]")))
                })
            })
    } else if keeps_pointer(instr) {
        defuse
            .uses
            .iter()
            .find_map(|value: &ValueId| {
                let ValueId::Register(_) = value else {
                    return None;
                };
                state.alias_of(arena.location(value)).map(str::to_owned)
            })
            .and_then(|alias: String| match immediate_displacement(instr) {
                Some(displacement) => offset_memory_expr(&alias, displacement),
                None => Some(alias),
            })
    } else {
        None
    };
    let loads_pointer: bool = !is_lea
        && instr
            .operands
            .first()
            .is_some_and(|operand: &String| abi.is_pointer_width_register(operand));
    let loaded_alias: Option<String> = if loads_pointer {
        defuse.uses.iter().find_map(|value: &ValueId| {
            let ValueId::Memory(expr) = value else {
                return None;
            };
            constant_pointer_target(ctx, expr)
                .map(global_expr)
                .or_else(|| pointer_stored_at(ctx, arena, state, expr))
        })
    } else {
        None
    };
    let stores_pointer: bool = instr
        .operands
        .get(1)
        .is_some_and(|operand: &String| abi.is_pointer_width_register(operand));
    let stored: Option<&String> = register_alias.as_ref().filter(|_| stores_pointer);
    for def in &defuse.defs {
        match def {
            ValueId::Register(_) => {
                let loc: PathId = arena.location(def);
                state.inherited.remove(&loc);
                state
                    .established
                    .insert(loc, register_alias.clone().or_else(|| loaded_alias.clone()));
            }
            ValueId::Memory(expr) => {
                let resolved: Option<ValueId> = pointee_through_base(abi, arena, state, expr)
                    .map(|pointee: String| ValueId::memory(&pointee));
                for cell in core::iter::once(def).chain(resolved.as_ref()) {
                    let loc: PathId = arena.location(cell);
                    match stored {
                        Some(alias) => {
                            state.cells.insert(loc, alias.clone());
                        }
                        None => {
                            state.cells.remove(&loc);
                        }
                    }
                }
            }
            ValueId::Stack(_) => {}
        }
    }
}

const fn keeps_pointer(instr: &NirInstr) -> bool {
    !matches!(
        instr.op,
        NirOp::BinOp {
            op: BinaryOp::Mul
                | BinaryOp::Div
                | BinaryOp::Rem
                | BinaryOp::And
                | BinaryOp::Or
                | BinaryOp::Xor
                | BinaryOp::Shl
                | BinaryOp::Shr
                | BinaryOp::Rol
                | BinaryOp::Ror
                | BinaryOp::Not
                | BinaryOp::Neg
        }
    )
}

fn immediate_displacement(instr: &NirInstr) -> Option<i64> {
    let negative: bool = match instr.mnemonic.to_ascii_lowercase().as_str() {
        "add" => false,
        "sub" => true,
        _ => return None,
    };
    let [_destination, operand]: &[String] = instr.operands.as_slice() else {
        return None;
    };
    let value: i64 = parse_native_integer(operand)?;
    Some(if negative {
        value.checked_neg()?
    } else {
        value
    })
}

fn sets_frame_base(abi: CallAbi, instr: &NirInstr, expr: &str) -> bool {
    instr
        .operands
        .first()
        .and_then(|operand: &String| abi.register_value(operand))
        == Some(ValueId::register(abi.frame_pointer()))
        && memory_base_and_displacement(abi, expr)
            .is_some_and(|(base, _displacement): (String, i64)| abi.is_stack_pointer(&base))
}

fn pointee_through_base(
    abi: CallAbi,
    arena: &mut Arena,
    state: &BlockState,
    expr: &str,
) -> Option<String> {
    let (base, displacement): (String, i64) = memory_base_and_displacement(abi, expr)?;
    if abi.is_stack_pointer(&base) {
        return None;
    }
    let base_loc: PathId = arena.location(&ValueId::register(&base));
    let alias: &str = state.alias_of(base_loc)?;
    offset_memory_expr(alias, displacement)
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
    for (fact, via_flag) in gather_reaching(ctx, arena, defuse, state) {
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
        } else if let (WalkMode::Summarize, Some(input)) = (mode, fact.formal_input()) {
            let mut path: Vec<TaintStep> = fact.path.clone();
            append_step(&mut path, step(instr.address, symbol, call_kind));
            append_step(&mut path, step(instr.address, symbol, "sink"));
            out.summary.add_frame(SinkFrame {
                input,
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

#[allow(clippy::too_many_arguments)]
fn apply_sanitizer(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    instr: &NirInstr,
    symbol: &str,
    call_kind: &str,
    feature: FeatureSet,
    defuse: &DefUse,
    state: &mut BlockState,
) {
    let incoming: Vec<(Fact, bool)> = gather_reaching(ctx, arena, defuse, state);
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

fn gather_reaching(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    defuse: &DefUse,
    state: &BlockState,
) -> Vec<(Fact, bool)> {
    let mut reached: Vec<(Fact, bool)> = Vec::new();
    for value in &defuse.uses {
        let loc: PathId = arena.location(value);
        if let Some(map) = state.values.get(&loc) {
            for fact in map.values() {
                reached.push((fact.clone(), false));
            }
        }
        if matches!(value, ValueId::Register(_))
            && let Some(alias) = state.alias_of(loc)
        {
            for fact in read_location(ctx, arena, state, alias).into_values() {
                reached.push((fact, false));
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
    let flag_facts: FactMap = state.flag.clone();
    let returned: PathId = reg_loc(arena, ctx.resolved.abi.return_register());
    state.values.remove(&returned);

    let Some(summary): Option<&FunctionSummary> = ctx.summaries.get(&callee) else {
        return;
    };
    let summary: FunctionSummary = summary.clone();

    for (port, generation) in &summary.generations {
        let Some(loc): Option<PathId> =
            out_port_location(ctx, arena, state, &arg_locs, returned, *port)
        else {
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
        if matches!(
            port,
            OutPort::ArgumentMemory { .. } | OutPort::ArgumentDeref { .. }
        ) {
            merge_fact(state.values.entry(loc).or_default(), fact);
            continue;
        }
        let mut map: FactMap = FactMap::new();
        map.insert(fact.key, fact.clone());
        state.values.insert(loc, map);
        if matches!(port, OutPort::Return) {
            state.flag.insert(fact.key, fact);
        }
    }

    for (input, outs) in &summary.propagations {
        let sources: FactMap = resolve_input_facts(ctx, arena, state, &arg_locs, *input);
        for (port, propagation) in outs {
            let Some(loc): Option<PathId> =
                out_port_location(ctx, arena, state, &arg_locs, returned, *port)
            else {
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

    instantiate_pointer_stores(arena, state, &arg_locs, &summary.pointer_stores);

    for frame in &summary.frames {
        instantiate_frame(
            ctx,
            mode,
            instr,
            &callee_name,
            call_kind,
            frame,
            arena,
            state,
            &arg_locs,
            &flag_facts,
            out,
        );
    }
}

fn resolve_input_facts(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    state: &BlockState,
    arg_locs: &[PathId],
    input: InPort,
) -> FactMap {
    match input {
        InPort::Argument(argument) => {
            let Some(argument_loc): Option<&PathId> = arg_locs.get(argument as usize) else {
                return FactMap::new();
            };
            let mut facts: FactMap = state.values.get(argument_loc).cloned().unwrap_or_default();
            if let Some(alias) = state.alias_of(*argument_loc) {
                for fact in read_location(ctx, arena, state, alias).into_values() {
                    merge_fact(&mut facts, fact);
                }
            }
            facts
        }
        InPort::Global(loc) => {
            let mut facts: FactMap = state.values.get(&loc).cloned().unwrap_or_default();
            if let Some(pointee) = state.cells.get(&loc) {
                for fact in read_location(ctx, arena, state, pointee).into_values() {
                    merge_fact(&mut facts, fact);
                }
            }
            facts
        }
        InPort::ArgumentDeref { argument, offset } => {
            let Some(argument_loc): Option<&PathId> = arg_locs.get(argument as usize) else {
                return FactMap::new();
            };
            pointee_of_argument_pointer(ctx, arena, state, *argument_loc, offset)
                .map(|pointee: String| read_location(ctx, arena, state, &pointee))
                .unwrap_or_default()
        }
        InPort::ArgumentMemory { argument, offset } => {
            let Some(argument_loc): Option<&PathId> = arg_locs.get(argument as usize) else {
                return FactMap::new();
            };
            let mut facts: FactMap = state.values.get(argument_loc).cloned().unwrap_or_default();
            let Some(alias): Option<&str> = state.alias_of(*argument_loc) else {
                return facts;
            };
            let Some(projected): Option<String> = offset_memory_expr(alias, offset) else {
                return facts;
            };
            for fact in read_location(ctx, arena, state, &projected).into_values() {
                merge_fact(&mut facts, fact);
            }
            let loc: PathId = arena.location(&ValueId::memory(&projected));
            if let Some(pointee) = state.cells.get(&loc) {
                for fact in read_location(ctx, arena, state, pointee).into_values() {
                    merge_fact(&mut facts, fact);
                }
            }
            facts
        }
    }
}

fn offset_memory_expr(expr: &str, added: i64) -> Option<String> {
    let inner: &str = memory_inner(expr)?;
    if let Some(address) = relative_address(inner) {
        return Some(global_expr(address.checked_add_signed(added)?));
    }
    let mut base: Option<&str> = None;
    let mut offset: i64 = added;
    for (_position, term) in signed_terms(inner) {
        let negative: bool = term.starts_with('-');
        let core: &str = term.trim_start_matches(['+', '-']);
        if core.contains('*') {
            return None;
        }
        match parse_native_integer(core) {
            Some(value) => {
                offset = offset.checked_add(if negative {
                    value.checked_neg()?
                } else {
                    value
                })?;
            }
            None => {
                if negative || base.replace(core).is_some() {
                    return None;
                }
            }
        }
    }
    let base: &str = base?;
    if offset == 0 {
        return Some(format!("[{base}]"));
    }
    if offset > 0 {
        Some(format!("[{base}+{offset:x}h]"))
    } else {
        Some(format!("[{base}-{:x}h]", offset.unsigned_abs()))
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
    arena: &mut Arena,
    state: &BlockState,
    arg_locs: &[PathId],
    flag_facts: &FactMap,
    out: &mut Outputs,
) {
    let candidates: FactMap = if frame.via_flag {
        flag_facts.clone()
    } else {
        resolve_input_facts(ctx, arena, state, arg_locs, frame.input)
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
        } else if let (WalkMode::Summarize, Some(input)) = (mode, cf.formal_input()) {
            let mut path: Vec<TaintStep> = cf.path.clone();
            append_step(&mut path, step(instr.address, callee_name, call_kind));
            append_step(&mut path, step(instr.address, callee_name, "sink"));
            for hop in &frame.path {
                append_step(&mut path, hop.clone());
            }
            out.summary.add_frame(SinkFrame {
                input,
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

fn out_port_location(
    ctx: &Ctx<'_>,
    arena: &mut Arena,
    state: &mut BlockState,
    arg_locs: &[PathId],
    returned: PathId,
    port: OutPort,
) -> Option<PathId> {
    match port {
        OutPort::Return => Some(returned),
        OutPort::Argument(index) => arg_locs.get(index as usize).copied(),
        OutPort::ArgumentMemory { argument, offset } => {
            let argument_loc: PathId = *arg_locs.get(argument as usize)?;
            let projected: String = offset_memory_expr(state.alias_of(argument_loc)?, offset)?;
            materialize_formal_pointee(ctx, arena, state, &projected);
            Some(arena.location(&ValueId::memory(&projected)))
        }
        OutPort::ArgumentDeref { argument, offset } => {
            let argument_loc: PathId = *arg_locs.get(argument as usize)?;
            let pointee: String =
                pointee_of_argument_pointer(ctx, arena, state, argument_loc, offset)?;
            materialize_formal_pointee(ctx, arena, state, &pointee);
            Some(arena.location(&ValueId::memory(&pointee)))
        }
    }
}

fn instantiate_pointer_stores(
    arena: &mut Arena,
    state: &mut BlockState,
    arg_locs: &[PathId],
    stores: &BTreeMap<(u16, i64), PointerTarget>,
) {
    for ((argument, offset), target) in stores {
        let Some(argument_loc): Option<&PathId> = arg_locs.get(*argument as usize) else {
            continue;
        };
        let Some(cell): Option<String> = state
            .alias_of(*argument_loc)
            .and_then(|alias: &str| offset_memory_expr(alias, *offset))
        else {
            continue;
        };
        let pointee: Option<String> = match target {
            PointerTarget::ArgumentMemory { argument, offset } => arg_locs
                .get(*argument as usize)
                .and_then(|loc: &PathId| state.alias_of(*loc))
                .and_then(|alias: &str| offset_memory_expr(alias, *offset)),
            PointerTarget::Global(address) => Some(global_expr(*address)),
        };
        let Some(pointee) = pointee else {
            continue;
        };
        let loc: PathId = arena.location(&ValueId::memory(&cell));
        state.cells.insert(loc, pointee);
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
    if let Some(pointee) = state.alias_of(returned) {
        let pointee: PathId = arena.location(&ValueId::memory(pointee));
        if let Some(map) = state.values.get(&pointee) {
            for fact in map.values() {
                record_output(summary, OutPort::Return, fact, instr);
            }
        }
    }
    for (index, register) in abi.argument_registers().iter().enumerate() {
        let loc: PathId = reg_loc(arena, register);
        let Some(map): Option<&FactMap> = state.values.get(&loc) else {
            continue;
        };
        for fact in map.values() {
            if fact.formal_input() == Some(InPort::Argument(index as u16)) {
                continue;
            }
            if fact.is_concrete() {
                continue;
            }
            record_output(summary, OutPort::Argument(index as u16), fact, instr);
        }
    }
    for (loc, map) in &state.values {
        let (own, port): (InPort, OutPort) = match formal_pointee(abi, arena, *loc) {
            Some(own @ InPort::ArgumentMemory { argument, offset }) => {
                (own, OutPort::ArgumentMemory { argument, offset })
            }
            Some(own @ InPort::ArgumentDeref { argument, offset }) => {
                (own, OutPort::ArgumentDeref { argument, offset })
            }
            Some(InPort::Argument(_) | InPort::Global(_)) | None => continue,
        };
        for fact in map.values() {
            if fact.formal_input() != Some(own) {
                record_output(summary, port, fact, instr);
            }
        }
    }
    for (loc, pointee) in &state.cells {
        let Some(InPort::ArgumentMemory { argument, offset }) = formal_pointee(abi, arena, *loc)
        else {
            continue;
        };
        let pointee_loc: PathId = arena.location(&ValueId::memory(pointee));
        let target: Option<PointerTarget> = match formal_pointee(abi, arena, pointee_loc) {
            Some(InPort::ArgumentMemory { argument, offset }) => {
                Some(PointerTarget::ArgumentMemory { argument, offset })
            }
            _ => memory_inner(pointee)
                .and_then(relative_address)
                .map(PointerTarget::Global),
        };
        if let Some(target) = target {
            summary.add_pointer_store(argument, offset, target);
        }
    }
}

fn record_output(summary: &mut FunctionSummary, port: OutPort, fact: &Fact, instr: &NirInstr) {
    let mut path: Vec<TaintStep> = fact.path.clone();
    append_step(&mut path, step(instr.address, &instr.mnemonic, "return"));
    if fact.is_concrete() {
        summary.add_generation(port, fact.kinds, fact.features, &path);
    } else if let Some(input) = fact.formal_input() {
        summary.add_propagation(input, port, fact.kinds, fact.features, &path);
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
    if path
        .iter()
        .any(|step: &TaintStep| step.kind == PATH_TRUNCATED_KIND)
    {
        out.truncated = true;
    }
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
    if let Some(marker_index) = path
        .iter()
        .position(|step: &TaintStep| step.kind == PATH_TRUNCATED_KIND)
    {
        let Some(entry_rank): Option<u8> = call_path_kind_rank(&entry.kind) else {
            return;
        };
        let witness_index: usize = marker_index + 1;
        if let Some(witness) = path.get_mut(witness_index) {
            match call_path_kind_rank(&witness.kind) {
                Some(witness_rank) if entry_rank > witness_rank => *witness = entry,
                None => *witness = entry,
                Some(_) => {}
            }
        } else {
            path.push(entry);
        }
        return;
    }
    if path.len() < MAX_PATH_STEPS {
        path.push(entry);
        return;
    }

    let weakest_call: Option<TaintStep> = path
        .iter()
        .chain(core::iter::once(&entry))
        .filter_map(|step: &TaintStep| call_path_kind_rank(&step.kind).map(|rank: u8| (rank, step)))
        .max_by(|(left_rank, left), (right_rank, right)| {
            left_rank
                .cmp(right_rank)
                .then_with(|| right.address.cmp(&left.address))
                .then_with(|| right.symbol.cmp(&left.symbol))
        })
        .map(|(_rank, step): (u8, &TaintStep)| step.clone());
    path.truncate(MAX_PATH_STEPS - 2);
    path.push(TaintStep {
        address: entry.address,
        symbol: entry.symbol,
        kind: PATH_TRUNCATED_KIND.to_owned(),
    });
    if let Some(weakest_call) = weakest_call {
        path.push(weakest_call);
    }
}

fn call_path_kind_rank(kind: &str) -> Option<u8> {
    match kind {
        "call-definite" => Some(0),
        "call-finite-set" => Some(1),
        "call-symbolic" => Some(2),
        "call-unresolved" => Some(3),
        _ => None,
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
