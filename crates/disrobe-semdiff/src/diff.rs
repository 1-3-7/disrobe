use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{
    NirBlock, NirClass, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, basic_blocks,
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionFingerprint {
    opcodes: Vec<String>,
    edges: Vec<(usize, usize)>,
    dangling_edges: Vec<(usize, i128)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EdgeFingerprint {
    edges: Vec<(usize, usize)>,
    dangling_edges: Vec<(usize, i128)>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FunctionKey {
    name: String,
    name_index: Option<usize>,
}

impl FunctionKey {
    fn display_name(&self) -> String {
        match (self.name.as_str(), self.name_index) {
            ("", None) => "<unnamed>".to_owned(),
            (_, None) => self.name.clone(),
            ("", Some(index)) => format!("<unnamed>#{}", index + 1),
            (name, Some(index)) => format!("{name}#{}", index + 1),
        }
    }
}

fn fingerprint(function: &NirFunction, labels: &BTreeMap<u64, String>) -> FunctionFingerprint {
    let opcodes: Vec<String> = function
        .instructions
        .iter()
        .map(|insn: &NirInstr| op_token(insn, labels))
        .collect();
    let edge_fingerprint: EdgeFingerprint = relative_edges(function);
    FunctionFingerprint {
        opcodes,
        edges: edge_fingerprint.edges,
        dangling_edges: edge_fingerprint.dangling_edges,
    }
}

fn op_token(insn: &NirInstr, labels: &BTreeMap<u64, String>) -> String {
    match &insn.op {
        NirOp::Nop => "nop".to_owned(),
        NirOp::Const => format!("const[{}]", insn.operands.join(",")),
        NirOp::BinOp { op } => format!("binop.{}", op.mnemonic()),
        NirOp::Load => "load".to_owned(),
        NirOp::Store => "store".to_owned(),
        NirOp::Call { target } => format!("call->{}", call_label(*target, labels)),
        NirOp::IndirectCall => "call->*".to_owned(),
        NirOp::ExternCall { symbol } => format!("call->{symbol}"),
        NirOp::Branch { .. } => "branch".to_owned(),
        NirOp::CondBranch { .. } => "condbranch".to_owned(),
        NirOp::Phi => "phi".to_owned(),
        NirOp::Return => "return".to_owned(),
        NirOp::Interrupt => "interrupt".to_owned(),
        NirOp::Unmodeled { opcode, .. } => format!("unmodeled.{opcode:#04x}"),
    }
}

fn call_label(target: Option<u64>, labels: &BTreeMap<u64, String>) -> String {
    target.map_or_else(
        || "?".to_owned(),
        |addr: u64| {
            labels
                .get(&addr)
                .cloned()
                .unwrap_or_else(|| format!("0x{addr:x}"))
        },
    )
}

fn relative_edges(function: &NirFunction) -> EdgeFingerprint {
    let blocks: Vec<NirBlock> = basic_blocks(function);
    let index_of: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(idx, b): (usize, &NirBlock)| (b.start, idx))
        .collect();
    let mut edges: Vec<(usize, usize)> = Vec::new();
    let mut dangling_edges: Vec<(usize, i128)> = Vec::new();
    for (idx, block) in blocks.iter().enumerate() {
        for succ in &block.successors {
            let Some(succ_idx): Option<&usize> = index_of.get(succ) else {
                dangling_edges.push((idx, relative_addr_delta(*succ, function.address)));
                continue;
            };
            edges.push((idx, *succ_idx));
        }
        let direct_cfg_target: Option<u64> =
            block
                .instructions
                .last()
                .and_then(|last: &NirInstr| match last.class() {
                    NirClass::ConditionalJump | NirClass::UnconditionalJump => last.direct_target(),
                    NirClass::Call | NirClass::Return | NirClass::Other => None,
                });
        let Some(target): Option<u64> = direct_cfg_target else {
            continue;
        };
        if !index_of.contains_key(&target) {
            dangling_edges.push((idx, relative_addr_delta(target, function.address)));
        }
    }
    edges.sort_unstable();
    edges.dedup();
    dangling_edges.sort_unstable();
    dangling_edges.dedup();
    EdgeFingerprint {
        edges,
        dangling_edges,
    }
}

fn relative_addr_delta(address: u64, base: u64) -> i128 {
    i128::from(address) - i128::from(base)
}

fn label_index(module: &NirModule) -> BTreeMap<u64, String> {
    let mut labels: BTreeMap<u64, String> = module
        .symbols
        .iter()
        .map(|s: &NirSymbol| (s.address, s.name.clone()))
        .collect();
    for function in &module.functions {
        labels.entry(function.address).or_insert_with(|| {
            if function.name.is_empty() {
                format!("0x{:x}", function.address)
            } else {
                function.name.clone()
            }
        });
    }
    labels
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionChange {
    pub function: String,
    pub kind: ChangeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct SemanticDiff {
    changes: Vec<FunctionChange>,
}

impl SemanticDiff {
    #[must_use]
    pub fn changes(&self) -> &[FunctionChange] {
        &self.changes
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.changes.len()
    }

    pub fn changed(&self) -> impl Iterator<Item = &str> {
        self.changes
            .iter()
            .filter(|c: &&FunctionChange| c.kind == ChangeKind::Changed)
            .map(|c: &FunctionChange| c.function.as_str())
    }

    #[must_use]
    pub fn is_changed(&self, function: &str) -> bool {
        self.changes
            .iter()
            .any(|c: &FunctionChange| c.function == function && c.kind == ChangeKind::Changed)
    }

    #[must_use]
    pub fn affects(&self, function: &str) -> bool {
        self.changes
            .iter()
            .any(|c: &FunctionChange| c.function == function)
    }
}

#[must_use]
pub fn diff(base: &NirModule, other: &NirModule) -> SemanticDiff {
    let base_labels: BTreeMap<u64, String> = label_index(base);
    let other_labels: BTreeMap<u64, String> = label_index(other);
    let duplicate_function_names: BTreeSet<String> = duplicate_names(base, other);

    let base_fp: BTreeMap<FunctionKey, FunctionFingerprint> =
        fingerprints_by_key(base, &base_labels, &duplicate_function_names);
    let other_fp: BTreeMap<FunctionKey, FunctionFingerprint> =
        fingerprints_by_key(other, &other_labels, &duplicate_function_names);

    let keys: BTreeSet<FunctionKey> = base_fp.keys().chain(other_fp.keys()).cloned().collect();
    let mut changes: Vec<FunctionChange> = Vec::new();
    for key in keys {
        let base_fingerprint: Option<&FunctionFingerprint> = base_fp.get(&key);
        let other_fingerprint: Option<&FunctionFingerprint> = other_fp.get(&key);
        let kind: Option<ChangeKind> = match (base_fingerprint, other_fingerprint) {
            (Some(base_item), Some(other_item)) if base_item == other_item => None,
            (Some(_), Some(_)) => Some(ChangeKind::Changed),
            (Some(_), None) => Some(ChangeKind::Removed),
            (None, Some(_)) => Some(ChangeKind::Added),
            (None, None) => None,
        };
        let Some(kind): Option<ChangeKind> = kind else {
            continue;
        };
        changes.push(FunctionChange {
            function: key.display_name(),
            kind,
        });
    }
    changes.sort_by(|a: &FunctionChange, b: &FunctionChange| a.function.cmp(&b.function));
    SemanticDiff { changes }
}

fn name_counts(module: &NirModule) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for function in &module.functions {
        let count: &mut usize = counts.entry(function.name.clone()).or_default();
        *count += 1;
    }
    counts
}

fn duplicate_names(base: &NirModule, other: &NirModule) -> BTreeSet<String> {
    let base_counts: BTreeMap<String, usize> = name_counts(base);
    let other_counts: BTreeMap<String, usize> = name_counts(other);
    base_counts
        .iter()
        .chain(other_counts.iter())
        .filter_map(|(name, count): (&String, &usize)| (*count > 1).then_some(name.clone()))
        .collect()
}

fn fingerprints_by_key(
    module: &NirModule,
    labels: &BTreeMap<u64, String>,
    duplicate_names: &BTreeSet<String>,
) -> BTreeMap<FunctionKey, FunctionFingerprint> {
    let mut map: BTreeMap<FunctionKey, FunctionFingerprint> = BTreeMap::new();
    let mut name_indices: BTreeMap<String, usize> = BTreeMap::new();
    for function in &module.functions {
        let name_index: Option<usize> = if duplicate_names.contains(&function.name) {
            let index: &mut usize = name_indices.entry(function.name.clone()).or_default();
            let current: usize = *index;
            *index += 1;
            Some(current)
        } else {
            None
        };
        let key: FunctionKey = FunctionKey {
            name: function.name.clone(),
            name_index,
        };
        map.insert(key, fingerprint(function, labels));
    }
    map
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_nir::{SourceLang, SourceRef};

    const fn instr(address: u64, op: NirOp) -> NirInstr {
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

    fn dangling_edge_module_with_target(base: u64, target: u64) -> NirModule {
        NirModule {
            source_hash: [0u8; 32],
            lang: SourceLang::NativeX86,
            functions: vec![NirFunction {
                name: "branchy".to_owned(),
                address: base,
                end: base + 0x40,
                is_export: true,
                instructions: vec![
                    instr(
                        base,
                        NirOp::CondBranch {
                            target: Some(target),
                        },
                    ),
                    instr(base + 1, NirOp::Return),
                ],
                source: SourceRef::new(SourceLang::NativeX86, base),
            }],
            symbols: Vec::new(),
        }
    }

    fn dangling_edge_module(base: u64, target_offset: u64) -> NirModule {
        dangling_edge_module_with_target(base, base + target_offset)
    }

    #[test]
    fn dangling_cfg_targets_are_part_of_the_fingerprint() {
        let base: NirModule = dangling_edge_module(0x1000, 0x20);
        let other: NirModule = dangling_edge_module(0x1000, 0x28);
        let report: SemanticDiff = diff(&base, &other);
        let changed: Vec<&str> = report.changed().collect();
        assert_eq!(changed, vec!["branchy"]);
    }

    #[test]
    fn dangling_cfg_targets_stay_relocation_invariant() {
        let base: NirModule = dangling_edge_module(0x1000, 0x20);
        let other: NirModule = dangling_edge_module(0x4000, 0x20);
        let report: SemanticDiff = diff(&base, &other);
        assert!(report.is_empty());
    }

    #[test]
    fn dangling_cfg_targets_below_function_base_are_distinct() {
        let base: NirModule = dangling_edge_module_with_target(0x1000, 0x0ff0);
        let other: NirModule = dangling_edge_module_with_target(0x1000, 0x0fc0);
        let report: SemanticDiff = diff(&base, &other);
        let changed: Vec<&str> = report.changed().collect();
        assert_eq!(changed, vec!["branchy"]);
    }
}
