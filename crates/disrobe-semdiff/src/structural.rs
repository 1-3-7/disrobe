use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use disrobe_nir::{NirBlock, NirFunction, NirInstr, NirModule, NirOp, basic_blocks};

pub const MAX_FUNCTIONS_PER_MODULE: usize = 50_000;
pub const MAX_PROPAGATION_ROUNDS: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchTier {
    LeafExact,
    Propagated { round: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indeterminate {
    NoCandidate,
    Ambiguous { base_side: usize, other_side: usize },
    RoundBudgetExhausted,
    FunctionCountCapExceeded,
    DuplicateAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuralPair {
    pub base_address: u64,
    pub other_address: u64,
    pub tier: MatchTier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralMatchReport {
    pub matches: Vec<StructuralPair>,
    pub unmatched_base: Vec<(u64, Indeterminate)>,
    pub unmatched_other: Vec<(u64, Indeterminate)>,
    pub rounds_run: u32,
}

impl StructuralMatchReport {
    #[must_use]
    pub fn matched_partner(&self, base_address: u64) -> Option<u64> {
        self.matches
            .iter()
            .find(|pair: &&StructuralPair| pair.base_address == base_address)
            .map(|pair: &StructuralPair| pair.other_address)
    }

    #[must_use]
    pub const fn match_count(&self) -> usize {
        self.matches.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LeafSignature {
    instr_tokens: Vec<String>,
    edges: Vec<(usize, usize)>,
    external_edges: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CfgShapeKey {
    block_count: usize,
    edge_count: usize,
    block_invariants: Vec<(u8, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CalleeToken {
    Matched(u32),
    Extern(String),
    Indirect,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RoundSignature {
    cfg: CfgShapeKey,
    callees: Vec<CalleeToken>,
    histogram: Vec<(String, usize)>,
}

fn shape_token(op: &NirOp, reads_memory: bool, writes_memory: bool, byte_width: bool) -> String {
    let base: String = match op {
        NirOp::Nop => "nop".to_owned(),
        NirOp::Const => "const".to_owned(),
        NirOp::BinOp { op } => format!("bin.{}", op.mnemonic()),
        NirOp::Load => "load".to_owned(),
        NirOp::Store => "store".to_owned(),
        NirOp::Call { .. } => "call.internal".to_owned(),
        NirOp::IndirectCall => "call.indirect".to_owned(),
        NirOp::ExternCall { symbol } => format!("call.extern:{symbol}"),
        NirOp::Branch { .. } => "jmp".to_owned(),
        NirOp::CondBranch { .. } => "jcc".to_owned(),
        NirOp::Phi => "phi".to_owned(),
        NirOp::Return => "ret".to_owned(),
        NirOp::Interrupt => "int".to_owned(),
        NirOp::Unmodeled { opcode, .. } => format!("unmodeled.{opcode:#04x}"),
        NirOp::RawLoad { .. } => "rawload".to_owned(),
        NirOp::RawStore { .. } => "rawstore".to_owned(),
        NirOp::Subpiece { .. } => "subpiece".to_owned(),
        NirOp::Deposit { .. } => "deposit".to_owned(),
        NirOp::CallOther { .. } => "callother".to_owned(),
        NirOp::Copy { .. } => "copy".to_owned(),
        NirOp::Value { op, .. } => format!("value.{}", op.mnemonic()),
        NirOp::Piece { .. } => "piece".to_owned(),
        NirOp::NoReturnCall { .. } => "call.noreturn".to_owned(),
        NirOp::TailCall { .. } => "call.tail".to_owned(),
    };
    let mem_shape: &'static str = match (reads_memory, writes_memory) {
        (true, true) => ".rw",
        (true, false) => ".r",
        (false, true) => ".w",
        (false, false) => "",
    };
    let width_shape: &'static str = if byte_width { ".b" } else { "" };
    format!("{base}{mem_shape}{width_shape}")
}

fn is_leaf(function: &NirFunction) -> bool {
    !function.instructions.iter().any(|insn: &NirInstr| {
        matches!(
            insn.op,
            NirOp::Call { .. } | NirOp::IndirectCall | NirOp::ExternCall { .. }
        )
    })
}

fn block_edges(function: &NirFunction) -> (Vec<(usize, usize)>, usize) {
    let blocks: Vec<NirBlock> = basic_blocks(function);
    let start_index: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(idx, block): (usize, &NirBlock)| (block.start, idx))
        .collect();
    let mut edges: Vec<(usize, usize)> = Vec::new();
    let mut external_edges: usize = 0;
    for (idx, block) in blocks.iter().enumerate() {
        for succ in &block.successors {
            match start_index.get(succ) {
                Some(&successor_idx) => edges.push((idx, successor_idx)),
                None => external_edges += 1,
            }
        }
    }
    edges.sort_unstable();
    edges.dedup();
    (edges, external_edges)
}

fn leaf_signature(function: &NirFunction) -> LeafSignature {
    let instr_tokens: Vec<String> = function
        .instructions
        .iter()
        .map(|insn: &NirInstr| {
            shape_token(
                &insn.op,
                insn.reads_memory,
                insn.writes_memory,
                insn.byte_width,
            )
        })
        .collect();
    let (edges, external_edges): (Vec<(usize, usize)>, usize) = block_edges(function);
    LeafSignature {
        instr_tokens,
        edges,
        external_edges,
    }
}

fn block_content_hash(block: &NirBlock) -> u64 {
    let mut hasher: DefaultHasher = DefaultHasher::new();
    for insn in &block.instructions {
        shape_token(
            &insn.op,
            insn.reads_memory,
            insn.writes_memory,
            insn.byte_width,
        )
        .hash(&mut hasher);
    }
    hasher.finish()
}

fn degree_nibble(in_degree: usize, out_degree: usize) -> u8 {
    (in_degree.min(15) as u8) * 16 + (out_degree.min(15) as u8)
}

fn cfg_shape_key(function: &NirFunction) -> CfgShapeKey {
    let blocks: Vec<NirBlock> = basic_blocks(function);
    if blocks.is_empty() {
        return CfgShapeKey {
            block_count: 0,
            edge_count: 0,
            block_invariants: Vec::new(),
        };
    }
    let start_index: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(idx, block): (usize, &NirBlock)| (block.start, idx))
        .collect();
    let mut in_degree: Vec<usize> = vec![0; blocks.len()];
    let mut out_degree: Vec<usize> = vec![0; blocks.len()];
    let mut edge_count: usize = 0;
    for (idx, block) in blocks.iter().enumerate() {
        for succ in &block.successors {
            if let Some(&successor_idx) = start_index.get(succ) {
                out_degree[idx] += 1;
                in_degree[successor_idx] += 1;
                edge_count += 1;
            }
        }
    }
    let mut block_invariants: Vec<(u8, u64)> = blocks
        .iter()
        .enumerate()
        .map(|(idx, block): (usize, &NirBlock)| {
            (
                degree_nibble(in_degree[idx], out_degree[idx]),
                block_content_hash(block),
            )
        })
        .collect();
    block_invariants.sort_unstable();
    CfgShapeKey {
        block_count: blocks.len(),
        edge_count,
        block_invariants,
    }
}

fn instr_class_histogram(function: &NirFunction) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for insn in &function.instructions {
        let token: String = shape_token(
            &insn.op,
            insn.reads_memory,
            insn.writes_memory,
            insn.byte_width,
        );
        *counts.entry(token).or_default() += 1;
    }
    counts.into_iter().collect()
}

fn callee_tokens(
    function: &NirFunction,
    own_functions: &BTreeMap<u64, &NirFunction>,
    own_match_ids: &BTreeMap<u64, u32>,
) -> Vec<CalleeToken> {
    let mut tokens: Vec<CalleeToken> = function
        .instructions
        .iter()
        .filter_map(|insn: &NirInstr| match &insn.op {
            NirOp::Call {
                target: Some(target),
            } => Some(
                own_functions
                    .get(target)
                    .map_or(CalleeToken::Unresolved, |_| {
                        own_match_ids
                            .get(target)
                            .map_or(CalleeToken::Unresolved, |id: &u32| {
                                CalleeToken::Matched(*id)
                            })
                    }),
            ),
            NirOp::Call { target: None } => Some(CalleeToken::Unresolved),
            NirOp::IndirectCall => Some(CalleeToken::Indirect),
            NirOp::ExternCall { symbol } => Some(CalleeToken::Extern(symbol.clone())),
            _ => None,
        })
        .collect();
    tokens.sort_unstable();
    tokens
}

fn index_functions(module: &NirModule) -> (BTreeMap<u64, &NirFunction>, Vec<u64>) {
    let mut index: BTreeMap<u64, &NirFunction> = BTreeMap::new();
    let mut collided_addresses: Vec<u64> = Vec::new();
    for function in &module.functions {
        if index.insert(function.address, function).is_some() {
            collided_addresses.push(function.address);
        }
    }
    (index, collided_addresses)
}

struct MatchState {
    confirmed_base_to_other: BTreeMap<u64, (u64, MatchTier)>,
    confirmed_other_to_base: BTreeMap<u64, u64>,
    match_id_of_base: BTreeMap<u64, u32>,
    match_id_of_other: BTreeMap<u64, u32>,
    ambiguous_base: BTreeMap<u64, (usize, usize)>,
    ambiguous_other: BTreeMap<u64, (usize, usize)>,
    next_match_id: u32,
}

impl MatchState {
    const fn new() -> Self {
        Self {
            confirmed_base_to_other: BTreeMap::new(),
            confirmed_other_to_base: BTreeMap::new(),
            match_id_of_base: BTreeMap::new(),
            match_id_of_other: BTreeMap::new(),
            ambiguous_base: BTreeMap::new(),
            ambiguous_other: BTreeMap::new(),
            next_match_id: 0,
        }
    }

    fn promote_unique_buckets<K: Ord + Clone>(
        &mut self,
        base_sigs: &BTreeMap<u64, K>,
        other_sigs: &BTreeMap<u64, K>,
        tier: MatchTier,
    ) -> usize {
        let mut bucket_base: BTreeMap<K, Vec<u64>> = BTreeMap::new();
        for (&addr, sig) in base_sigs {
            bucket_base.entry(sig.clone()).or_default().push(addr);
        }
        let mut bucket_other: BTreeMap<K, Vec<u64>> = BTreeMap::new();
        for (&addr, sig) in other_sigs {
            bucket_other.entry(sig.clone()).or_default().push(addr);
        }

        let mut promoted: usize = 0;
        for (key, base_addrs) in &bucket_base {
            let Some(other_addrs): Option<&Vec<u64>> = bucket_other.get(key) else {
                continue;
            };
            if base_addrs.len() == 1 && other_addrs.len() == 1 {
                let base_addr: u64 = base_addrs[0];
                let other_addr: u64 = other_addrs[0];
                let id: u32 = self.next_match_id;
                self.next_match_id += 1;
                self.confirmed_base_to_other
                    .insert(base_addr, (other_addr, tier));
                self.confirmed_other_to_base.insert(other_addr, base_addr);
                self.match_id_of_base.insert(base_addr, id);
                self.match_id_of_other.insert(other_addr, id);
                promoted += 1;
            } else {
                for &base_addr in base_addrs {
                    self.ambiguous_base
                        .insert(base_addr, (base_addrs.len(), other_addrs.len()));
                }
                for &other_addr in other_addrs {
                    self.ambiguous_other
                        .insert(other_addr, (other_addrs.len(), base_addrs.len()));
                }
            }
        }
        promoted
    }
}

fn capped_report(base: &NirModule, other: &NirModule) -> StructuralMatchReport {
    let unmatched_base: Vec<(u64, Indeterminate)> = base
        .functions
        .iter()
        .map(|function: &NirFunction| (function.address, Indeterminate::FunctionCountCapExceeded))
        .collect();
    let unmatched_other: Vec<(u64, Indeterminate)> = other
        .functions
        .iter()
        .map(|function: &NirFunction| (function.address, Indeterminate::FunctionCountCapExceeded))
        .collect();
    StructuralMatchReport {
        matches: Vec::new(),
        unmatched_base,
        unmatched_other,
        rounds_run: 0,
    }
}

fn classify_unmatched(
    address: u64,
    ambiguous: &BTreeMap<u64, (usize, usize)>,
    exhausted_by_cap: bool,
    has_pending_callee: bool,
) -> Indeterminate {
    if let Some(&(own_side, other_side)) = ambiguous.get(&address) {
        Indeterminate::Ambiguous {
            base_side: own_side,
            other_side,
        }
    } else if exhausted_by_cap && has_pending_callee {
        Indeterminate::RoundBudgetExhausted
    } else {
        Indeterminate::NoCandidate
    }
}

fn has_unresolved_internal_call(tokens: &[CalleeToken]) -> bool {
    tokens
        .iter()
        .any(|token: &CalleeToken| matches!(token, CalleeToken::Unresolved))
}

#[must_use]
pub fn structural_match(base: &NirModule, other: &NirModule) -> StructuralMatchReport {
    if base.functions.len() > MAX_FUNCTIONS_PER_MODULE
        || other.functions.len() > MAX_FUNCTIONS_PER_MODULE
    {
        return capped_report(base, other);
    }

    let (base_functions, base_collided_addresses): (BTreeMap<u64, &NirFunction>, Vec<u64>) =
        index_functions(base);
    let (other_functions, other_collided_addresses): (BTreeMap<u64, &NirFunction>, Vec<u64>) =
        index_functions(other);

    let mut state: MatchState = MatchState::new();

    let leaf_sig_base: BTreeMap<u64, LeafSignature> = base_functions
        .iter()
        .filter(|(_, function): &(&u64, &&NirFunction)| is_leaf(function))
        .map(|(&addr, function): (&u64, &&NirFunction)| (addr, leaf_signature(function)))
        .collect();
    let leaf_sig_other: BTreeMap<u64, LeafSignature> = other_functions
        .iter()
        .filter(|(_, function): &(&u64, &&NirFunction)| is_leaf(function))
        .map(|(&addr, function): (&u64, &&NirFunction)| (addr, leaf_signature(function)))
        .collect();
    state.promote_unique_buckets(&leaf_sig_base, &leaf_sig_other, MatchTier::LeafExact);

    let cfg_key_base: BTreeMap<u64, CfgShapeKey> = base_functions
        .iter()
        .map(|(&addr, function): (&u64, &&NirFunction)| (addr, cfg_shape_key(function)))
        .collect();
    let cfg_key_other: BTreeMap<u64, CfgShapeKey> = other_functions
        .iter()
        .map(|(&addr, function): (&u64, &&NirFunction)| (addr, cfg_shape_key(function)))
        .collect();
    let histogram_base: BTreeMap<u64, Vec<(String, usize)>> = base_functions
        .iter()
        .map(|(&addr, function): (&u64, &&NirFunction)| (addr, instr_class_histogram(function)))
        .collect();
    let histogram_other: BTreeMap<u64, Vec<(String, usize)>> = other_functions
        .iter()
        .map(|(&addr, function): (&u64, &&NirFunction)| (addr, instr_class_histogram(function)))
        .collect();

    let mut rounds_run: u32 = 0;
    let mut last_round_promoted: usize = 0;
    while rounds_run < MAX_PROPAGATION_ROUNDS {
        rounds_run += 1;
        state.ambiguous_base.clear();
        state.ambiguous_other.clear();

        let round_base: BTreeMap<u64, RoundSignature> = base_functions
            .iter()
            .filter(|(addr, _): &(&u64, &&NirFunction)| {
                !state.confirmed_base_to_other.contains_key(addr)
            })
            .map(|(&addr, function): (&u64, &&NirFunction)| {
                let signature: RoundSignature = RoundSignature {
                    cfg: cfg_key_base[&addr].clone(),
                    callees: callee_tokens(function, &base_functions, &state.match_id_of_base),
                    histogram: histogram_base[&addr].clone(),
                };
                (addr, signature)
            })
            .collect();
        let round_other: BTreeMap<u64, RoundSignature> = other_functions
            .iter()
            .filter(|(addr, _): &(&u64, &&NirFunction)| {
                !state.confirmed_other_to_base.contains_key(addr)
            })
            .map(|(&addr, function): (&u64, &&NirFunction)| {
                let signature: RoundSignature = RoundSignature {
                    cfg: cfg_key_other[&addr].clone(),
                    callees: callee_tokens(function, &other_functions, &state.match_id_of_other),
                    histogram: histogram_other[&addr].clone(),
                };
                (addr, signature)
            })
            .collect();

        last_round_promoted = state.promote_unique_buckets(
            &round_base,
            &round_other,
            MatchTier::Propagated { round: rounds_run },
        );
        if last_round_promoted == 0 {
            break;
        }
    }
    let exhausted_by_cap: bool = rounds_run == MAX_PROPAGATION_ROUNDS && last_round_promoted > 0;

    let matches: Vec<StructuralPair> = state
        .confirmed_base_to_other
        .iter()
        .map(|(&base_address, &(other_address, tier))| StructuralPair {
            base_address,
            other_address,
            tier,
        })
        .collect();
    let mut unmatched_base: Vec<(u64, Indeterminate)> = base_functions
        .iter()
        .filter(|(addr, _): &(&u64, &&NirFunction)| {
            !state.confirmed_base_to_other.contains_key(addr)
        })
        .map(|(&addr, function): (&u64, &&NirFunction)| {
            let has_pending_callee: bool = has_unresolved_internal_call(&callee_tokens(
                function,
                &base_functions,
                &state.match_id_of_base,
            ));
            (
                addr,
                classify_unmatched(
                    addr,
                    &state.ambiguous_base,
                    exhausted_by_cap,
                    has_pending_callee,
                ),
            )
        })
        .collect();
    let mut unmatched_other: Vec<(u64, Indeterminate)> = other_functions
        .iter()
        .filter(|(addr, _): &(&u64, &&NirFunction)| {
            !state.confirmed_other_to_base.contains_key(addr)
        })
        .map(|(&addr, function): (&u64, &&NirFunction)| {
            let has_pending_callee: bool = has_unresolved_internal_call(&callee_tokens(
                function,
                &other_functions,
                &state.match_id_of_other,
            ));
            (
                addr,
                classify_unmatched(
                    addr,
                    &state.ambiguous_other,
                    exhausted_by_cap,
                    has_pending_callee,
                ),
            )
        })
        .collect();
    unmatched_base.extend(
        base_collided_addresses
            .into_iter()
            .map(|addr: u64| (addr, Indeterminate::DuplicateAddress)),
    );
    unmatched_other.extend(
        other_collided_addresses
            .into_iter()
            .map(|addr: u64| (addr, Indeterminate::DuplicateAddress)),
    );

    StructuralMatchReport {
        matches,
        unmatched_base,
        unmatched_other,
        rounds_run,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_nir::{BinaryOp, SourceLang, SourceRef};

    fn instr(address: u64, op: NirOp) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: String::new(),
            operands: Vec::new(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    fn leaf_function(name: &str, address: u64, op: BinaryOp) -> NirFunction {
        NirFunction {
            name: name.to_owned(),
            address,
            end: address + 3,
            is_export: false,
            instructions: vec![
                instr(address, NirOp::BinOp { op }),
                instr(address + 1, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    fn module_of(functions: Vec<NirFunction>) -> NirModule {
        NirModule {
            source_hash: [0u8; 32],
            lang: SourceLang::NativeX86,
            functions,
            symbols: Vec::new(),
        }
    }

    #[test]
    fn identical_leaf_bodies_match_regardless_of_name_or_address() {
        let base: NirModule = module_of(vec![leaf_function("named_add", 0x1000, BinaryOp::Add)]);
        let other: NirModule = module_of(vec![leaf_function("sub_2000", 0x2000, BinaryOp::Add)]);
        let report: StructuralMatchReport = structural_match(&base, &other);
        assert_eq!(report.match_count(), 1);
        assert_eq!(report.matched_partner(0x1000), Some(0x2000));
    }

    #[test]
    fn structurally_different_leaves_do_not_match() {
        let base: NirModule = module_of(vec![leaf_function("a", 0x1000, BinaryOp::Add)]);
        let other: NirModule = module_of(vec![leaf_function("b", 0x2000, BinaryOp::Xor)]);
        let report: StructuralMatchReport = structural_match(&base, &other);
        assert_eq!(report.match_count(), 0);
        assert_eq!(
            report.unmatched_base.first().map(|(_, reason)| *reason),
            Some(Indeterminate::NoCandidate)
        );
    }

    #[test]
    fn duplicate_identical_leaves_are_ambiguous_not_guessed() {
        let base: NirModule = module_of(vec![
            leaf_function("a1", 0x1000, BinaryOp::Add),
            leaf_function("a2", 0x1010, BinaryOp::Add),
        ]);
        let other: NirModule = module_of(vec![
            leaf_function("b1", 0x2000, BinaryOp::Add),
            leaf_function("b2", 0x2010, BinaryOp::Add),
        ]);
        let report: StructuralMatchReport = structural_match(&base, &other);
        assert_eq!(report.match_count(), 0);
        for (_, reason) in &report.unmatched_base {
            assert!(matches!(
                reason,
                Indeterminate::Ambiguous {
                    base_side: 2,
                    other_side: 2
                }
            ));
        }
    }

    #[test]
    fn caller_of_two_matched_leaves_propagates_across_rounds() {
        let leaf_add_base: NirFunction = leaf_function("leaf_add", 0x1000, BinaryOp::Add);
        let leaf_xor_base: NirFunction = leaf_function("leaf_xor", 0x1010, BinaryOp::Xor);
        let caller_base: NirFunction = NirFunction {
            name: "caller".to_owned(),
            address: 0x1020,
            end: 0x1030,
            is_export: false,
            instructions: vec![
                instr(
                    0x1020,
                    NirOp::Call {
                        target: Some(0x1000),
                    },
                ),
                instr(
                    0x1022,
                    NirOp::Call {
                        target: Some(0x1010),
                    },
                ),
                instr(0x1024, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x1020),
        };

        let leaf_add_other: NirFunction = leaf_function("sub_a", 0x9000, BinaryOp::Add);
        let leaf_xor_other: NirFunction = leaf_function("sub_b", 0x9010, BinaryOp::Xor);
        let caller_other: NirFunction = NirFunction {
            name: "sub_caller".to_owned(),
            address: 0x9020,
            end: 0x9030,
            is_export: false,
            instructions: vec![
                instr(
                    0x9020,
                    NirOp::Call {
                        target: Some(0x9000),
                    },
                ),
                instr(
                    0x9022,
                    NirOp::Call {
                        target: Some(0x9010),
                    },
                ),
                instr(0x9024, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x9020),
        };

        let base: NirModule = module_of(vec![leaf_add_base, leaf_xor_base, caller_base]);
        let other: NirModule = module_of(vec![leaf_add_other, leaf_xor_other, caller_other]);
        let report: StructuralMatchReport = structural_match(&base, &other);
        assert_eq!(report.match_count(), 3);
        assert_eq!(report.matched_partner(0x1020), Some(0x9020));
        let caller_pair: &StructuralPair = report
            .matches
            .iter()
            .find(|pair: &&StructuralPair| pair.base_address == 0x1020)
            .expect("caller matched");
        assert!(matches!(
            caller_pair.tier,
            MatchTier::Propagated { round: 1 }
        ));
    }

    #[test]
    fn oversized_module_is_capped_not_guessed() {
        let mut functions: Vec<NirFunction> = Vec::new();
        for i in 0..=MAX_FUNCTIONS_PER_MODULE {
            functions.push(leaf_function("x", i as u64 * 4, BinaryOp::Add));
        }
        let base: NirModule = module_of(functions);
        let other: NirModule = module_of(vec![leaf_function("y", 0x1000, BinaryOp::Add)]);
        let report: StructuralMatchReport = structural_match(&base, &other);
        assert_eq!(report.match_count(), 0);
        assert!(
            report
                .unmatched_base
                .iter()
                .all(|(_, reason)| matches!(reason, Indeterminate::FunctionCountCapExceeded))
        );
    }

    #[test]
    fn cfg_shape_key_distinguishes_blocks_that_collided_under_the_retired_prime_bucket() {
        const RETIRED_PRIME_BUCKET_COUNT: u64 = 64;

        fn single_block_function(address: u64, ops: &[NirOp]) -> NirFunction {
            let mut instructions: Vec<NirInstr> = ops
                .iter()
                .enumerate()
                .map(|(offset, op): (usize, &NirOp)| instr(address + offset as u64, op.clone()))
                .collect();
            instructions.push(instr(address + ops.len() as u64, NirOp::Return));
            NirFunction {
                name: String::new(),
                address,
                end: address + ops.len() as u64 + 1,
                is_export: false,
                instructions,
                source: SourceRef::new(SourceLang::NativeX86, address),
            }
        }

        fn retired_bucket_index(content_hash: u64) -> u64 {
            content_hash % RETIRED_PRIME_BUCKET_COUNT
        }

        let binary_ops: [BinaryOp; 14] = [
            BinaryOp::Add,
            BinaryOp::Sub,
            BinaryOp::Mul,
            BinaryOp::Div,
            BinaryOp::Rem,
            BinaryOp::And,
            BinaryOp::Or,
            BinaryOp::Xor,
            BinaryOp::Shl,
            BinaryOp::Shr,
            BinaryOp::Rol,
            BinaryOp::Ror,
            BinaryOp::Not,
            BinaryOp::Neg,
        ];
        let mut candidate_bodies: Vec<Vec<NirOp>> = Vec::new();
        for padding in 0..10usize {
            for op in binary_ops {
                let mut body: Vec<NirOp> = vec![NirOp::Nop; padding];
                body.push(NirOp::BinOp { op });
                candidate_bodies.push(body);
            }
        }

        let mut collision: Option<(NirFunction, NirFunction)> = None;
        'search: for (index, body_a) in candidate_bodies.iter().enumerate() {
            for body_b in candidate_bodies.iter().skip(index + 1) {
                let function_a: NirFunction = single_block_function(0x1000, body_a);
                let function_b: NirFunction = single_block_function(0x2000, body_b);
                let block_a: NirBlock = basic_blocks(&function_a)
                    .into_iter()
                    .next()
                    .expect("single block a");
                let block_b: NirBlock = basic_blocks(&function_b)
                    .into_iter()
                    .next()
                    .expect("single block b");
                let hash_a: u64 = block_content_hash(&block_a);
                let hash_b: u64 = block_content_hash(&block_b);
                if hash_a != hash_b && retired_bucket_index(hash_a) == retired_bucket_index(hash_b)
                {
                    collision = Some((function_a, function_b));
                    break 'search;
                }
            }
        }

        let (function_a, function_b): (NirFunction, NirFunction) = collision.expect(
            "the candidate block bodies must contain a pair that collided under the retired 64-bucket prime index",
        );
        assert_ne!(
            cfg_shape_key(&function_a),
            cfg_shape_key(&function_b),
            "the strengthened key must not collapse two distinct block contents that shared a retired 64-bucket prime index"
        );
    }

    #[test]
    fn stale_round_ambiguity_is_cleared_once_the_true_final_state_has_no_candidate() {
        let helper_add_base: NirFunction = leaf_function("helper_add", 0x1000, BinaryOp::Add);
        let helper_sub_base: NirFunction = leaf_function("helper_sub", 0x1010, BinaryOp::Sub);
        let p_base: NirFunction = NirFunction {
            name: "p".to_owned(),
            address: 0x1020,
            end: 0x1024,
            is_export: false,
            instructions: vec![
                instr(
                    0x1020,
                    NirOp::Call {
                        target: Some(0x1000),
                    },
                ),
                instr(0x1022, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x1020),
        };
        let q_base: NirFunction = NirFunction {
            name: "q".to_owned(),
            address: 0x1030,
            end: 0x1034,
            is_export: false,
            instructions: vec![
                instr(
                    0x1030,
                    NirOp::Call {
                        target: Some(0x1010),
                    },
                ),
                instr(0x1032, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x1030),
        };
        let twin_a_base: NirFunction = NirFunction {
            name: "twin_a".to_owned(),
            address: 0x1040,
            end: 0x1044,
            is_export: false,
            instructions: vec![
                instr(
                    0x1040,
                    NirOp::Call {
                        target: Some(0xFFFF_0000),
                    },
                ),
                instr(0x1042, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x1040),
        };

        let helper_add_other: NirFunction = leaf_function("helper_add", 0x9000, BinaryOp::Add);
        let helper_sub_other: NirFunction = leaf_function("helper_sub", 0x9010, BinaryOp::Sub);
        let p_other: NirFunction = NirFunction {
            name: "p".to_owned(),
            address: 0x9020,
            end: 0x9024,
            is_export: false,
            instructions: vec![
                instr(
                    0x9020,
                    NirOp::Call {
                        target: Some(0x9000),
                    },
                ),
                instr(0x9022, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x9020),
        };
        let q_other: NirFunction = NirFunction {
            name: "q".to_owned(),
            address: 0x9030,
            end: 0x9034,
            is_export: false,
            instructions: vec![
                instr(
                    0x9030,
                    NirOp::Call {
                        target: Some(0x9010),
                    },
                ),
                instr(0x9032, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x9030),
        };
        let candidate_x_other: NirFunction = NirFunction {
            name: "candidate_x".to_owned(),
            address: 0x9040,
            end: 0x9044,
            is_export: false,
            instructions: vec![
                instr(
                    0x9040,
                    NirOp::Call {
                        target: Some(0x9020),
                    },
                ),
                instr(0x9042, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x9040),
        };
        let candidate_y_other: NirFunction = NirFunction {
            name: "candidate_y".to_owned(),
            address: 0x9050,
            end: 0x9054,
            is_export: false,
            instructions: vec![
                instr(
                    0x9050,
                    NirOp::Call {
                        target: Some(0x9030),
                    },
                ),
                instr(0x9052, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x9050),
        };

        let base: NirModule = module_of(vec![
            helper_add_base,
            helper_sub_base,
            p_base,
            q_base,
            twin_a_base,
        ]);
        let other: NirModule = module_of(vec![
            helper_add_other,
            helper_sub_other,
            p_other,
            q_other,
            candidate_x_other,
            candidate_y_other,
        ]);
        let report: StructuralMatchReport = structural_match(&base, &other);

        assert_eq!(report.matched_partner(0x1020), Some(0x9020));
        assert_eq!(report.matched_partner(0x1030), Some(0x9030));

        let twin_a_reason: Indeterminate = report
            .unmatched_base
            .iter()
            .find(|&&(addr, _): &&(u64, Indeterminate)| addr == 0x1040)
            .map(|&(_, reason): &(u64, Indeterminate)| reason)
            .expect("twin_a must appear in unmatched_base");
        assert_eq!(
            twin_a_reason,
            Indeterminate::NoCandidate,
            "twin_a had zero real candidates by the final round and must not report a stale early-round ambiguity"
        );

        for target in [0x9040, 0x9050] {
            let reason: Indeterminate = report
                .unmatched_other
                .iter()
                .find(|&&(addr, _): &&(u64, Indeterminate)| addr == target)
                .map_or_else(
                    || panic!("{target:#x} must appear in unmatched_other"),
                    |&(_, reason): &(u64, Indeterminate)| reason,
                );
            assert_eq!(
                reason,
                Indeterminate::NoCandidate,
                "candidate at {target:#x} diverged away from the ambiguous group by the final round"
            );
        }
    }

    #[test]
    fn classify_unmatched_only_blames_the_round_budget_when_a_callee_could_still_resolve() {
        assert_eq!(
            classify_unmatched(0x1000, &BTreeMap::new(), true, true),
            Indeterminate::RoundBudgetExhausted
        );
        assert_eq!(
            classify_unmatched(0x1000, &BTreeMap::new(), true, false),
            Indeterminate::NoCandidate
        );
        assert_eq!(
            classify_unmatched(0x1000, &BTreeMap::new(), false, true),
            Indeterminate::NoCandidate
        );
        let mut ambiguous: BTreeMap<u64, (usize, usize)> = BTreeMap::new();
        ambiguous.insert(0x1000, (2, 3));
        assert_eq!(
            classify_unmatched(0x1000, &ambiguous, true, true),
            Indeterminate::Ambiguous {
                base_side: 2,
                other_side: 3
            }
        );
    }

    #[test]
    fn duplicate_function_address_is_reported_not_dropped() {
        let base: NirModule = module_of(vec![
            leaf_function("first_at_addr", 0x1000, BinaryOp::Add),
            leaf_function("second_at_addr", 0x1000, BinaryOp::Xor),
        ]);
        let other: NirModule = module_of(vec![leaf_function("only", 0x2000, BinaryOp::Add)]);
        let report: StructuralMatchReport = structural_match(&base, &other);
        assert!(
            report
                .unmatched_base
                .iter()
                .any(|&(addr, reason): &(u64, Indeterminate)| addr == 0x1000
                    && reason == Indeterminate::DuplicateAddress),
            "the address collision loser must surface in the unmatched report instead of vanishing: {:?}",
            report.unmatched_base
        );
    }
}
