use std::collections::BTreeMap;

use disrobe_cfg::{
    Atom, Cfg, CfgNode, CloneMap, NodeId, Terminator, make_reducible, multi_entry_irreducible_sccs,
    reconvergent_joins, relowered_matches_original_modulo_clones, split_reconvergence,
};
use serde::Serialize;

use crate::cfg::{BlockKind, NirBlock};
use crate::types::{NirInstr, NirOp};

pub use disrobe_cfg::CnsBudget;

const MAX_SPLIT_NODES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructureFailure {
    RegionDepthExceeded,
    MissingBlock,
    BlockReachedTwice,
    LoopHasManyExits,
    IndirectTransfer,
    MissingTerminator,
    JumpWithoutTarget,
    IncompleteCover,
}

impl StructureFailure {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegionDepthExceeded => "region-depth-exceeded",
            Self::MissingBlock => "missing-block",
            Self::BlockReachedTwice => "block-reached-twice",
            Self::LoopHasManyExits => "loop-has-many-exits",
            Self::IndirectTransfer => "indirect-transfer",
            Self::MissingTerminator => "missing-terminator",
            Self::JumpWithoutTarget => "jump-without-target",
            Self::IncompleteCover => "incomplete-cover",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SplitRefusal {
    Disabled,
    NotIrreducible,
    GraphTooLarge,
    GraphRejected,
    BudgetExhausted,
    CloneCheckFailed,
    AddressSpaceExhausted,
    StillUnstructured,
}

impl SplitRefusal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "splitting-disabled",
            Self::NotIrreducible => "not-irreducible",
            Self::GraphTooLarge => "graph-too-large",
            Self::GraphRejected => "graph-rejected",
            Self::BudgetExhausted => "budget-exhausted",
            Self::CloneCheckFailed => "clone-check-failed",
            Self::AddressSpaceExhausted => "address-space-exhausted",
            Self::StillUnstructured => "still-unstructured",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct HirDecline {
    pub failure: StructureFailure,
    pub refusal: SplitRefusal,
    pub after_split: Option<StructureFailure>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SplitBudget {
    #[default]
    TightForGraph,
    Explicit(CnsBudget),
    Disabled,
}

pub(crate) fn split_irreducible(
    blocks: &[NirBlock],
    entry: u64,
    budget: SplitBudget,
) -> Result<Vec<NirBlock>, SplitRefusal> {
    if budget == SplitBudget::Disabled {
        return Err(SplitRefusal::Disabled);
    }
    if blocks.len() > MAX_SPLIT_NODES {
        return Err(SplitRefusal::GraphTooLarge);
    }
    let ordered: Vec<&NirBlock> = ordered_blocks(blocks);
    let node_of: BTreeMap<u64, NodeId> = ordered
        .iter()
        .enumerate()
        .filter_map(|(position, block): (usize, &&NirBlock)| {
            NodeId::try_from(position)
                .ok()
                .map(|node: NodeId| (block.start, node))
        })
        .collect();
    if node_of.len() != ordered.len() {
        return Err(SplitRefusal::GraphRejected);
    }
    let mut nodes: Vec<CfgNode> = Vec::with_capacity(ordered.len());
    for (position, block) in ordered.iter().enumerate() {
        let atom: Atom = Atom::try_from(position).map_err(|_error| SplitRefusal::GraphTooLarge)?;
        let term: Terminator =
            terminator_for(block, &node_of, atom).ok_or(SplitRefusal::GraphRejected)?;
        nodes.push(CfgNode {
            term,
            pure: block_is_pure(block),
        });
    }
    let entry_node: NodeId = node_of
        .get(&entry)
        .copied()
        .ok_or(SplitRefusal::GraphRejected)?;
    let original: Cfg =
        Cfg::new(entry_node, nodes).map_err(|_error| SplitRefusal::GraphRejected)?;
    let irreducible: bool = !multi_entry_irreducible_sccs(&original).is_empty();
    let (transformed, clone_map): (Cfg, CloneMap) = if irreducible {
        let limit: CnsBudget = match budget {
            SplitBudget::Explicit(explicit) => explicit,
            SplitBudget::TightForGraph | SplitBudget::Disabled => CnsBudget::tight_for(&original),
        };
        make_reducible(&original, limit).ok_or(SplitRefusal::BudgetExhausted)?
    } else {
        if reconvergent_joins(&original).is_empty() {
            return Err(SplitRefusal::NotIrreducible);
        }
        let limit: CnsBudget = match budget {
            SplitBudget::Explicit(explicit) => explicit,
            SplitBudget::TightForGraph | SplitBudget::Disabled => {
                CnsBudget::tight_for_reconvergence(&original)
            }
        };
        split_reconvergence(&original, limit).ok_or(SplitRefusal::BudgetExhausted)?
    };
    if !relowered_matches_original_modulo_clones(
        &original,
        &transformed,
        &clone_map,
        &BTreeMap::new(),
    ) {
        return Err(SplitRefusal::CloneCheckFailed);
    }
    materialize(&ordered, &transformed, &clone_map)
}

fn ordered_blocks(blocks: &[NirBlock]) -> Vec<&NirBlock> {
    let mut ordered: Vec<&NirBlock> = blocks.iter().collect();
    ordered.sort_unstable_by_key(|block: &&NirBlock| block.start);
    ordered
}

fn block_is_pure(block: &NirBlock) -> bool {
    !block.instructions.iter().any(|instruction: &NirInstr| {
        instruction.touches_memory()
            || matches!(
                instruction.op,
                NirOp::Call { .. }
                    | NirOp::IndirectCall
                    | NirOp::NoReturnCall { .. }
                    | NirOp::TailCall { .. }
                    | NirOp::CallOther { .. }
            )
    })
}

fn terminator_for(
    block: &NirBlock,
    node_of: &BTreeMap<u64, NodeId>,
    atom: Atom,
) -> Option<Terminator> {
    let successor = |address: u64| -> Option<NodeId> { node_of.get(&address).copied() };
    match block.kind {
        BlockKind::Return => Some(Terminator::Return),
        BlockKind::Indirect => Some(Terminator::Unreachable),
        BlockKind::Jump | BlockKind::FallThrough => block
            .successors
            .first()
            .copied()
            .map_or(Some(Terminator::Return), |target: u64| {
                successor(target).map(Terminator::Goto)
            }),
        BlockKind::Conditional => {
            let taken: Option<u64> = block
                .instructions
                .last()
                .and_then(NirInstr::direct_target)
                .filter(|target: &u64| node_of.contains_key(target));
            let not_taken: Option<u64> = block
                .successors
                .iter()
                .copied()
                .find(|candidate: &u64| Some(*candidate) != taken);
            match (taken, not_taken) {
                (Some(taken_target), Some(not_taken_target)) => Some(Terminator::Branch {
                    atom,
                    taken: successor(taken_target)?,
                    not_taken: successor(not_taken_target)?,
                }),
                (Some(only), None) | (None, Some(only)) => successor(only).map(Terminator::Goto),
                (None, None) => Some(Terminator::Return),
            }
        }
    }
}

fn materialize(
    ordered: &[&NirBlock],
    transformed: &Cfg,
    clone_map: &CloneMap,
) -> Result<Vec<NirBlock>, SplitRefusal> {
    let original_len: usize = ordered.len();
    let highest_start: u64 = ordered
        .last()
        .map(|block: &&NirBlock| block.start)
        .ok_or(SplitRefusal::GraphRejected)?;
    let mut address_of: Vec<u64> = Vec::with_capacity(transformed.len());
    for node in 0..transformed.len() {
        if node < original_len {
            let block: &&NirBlock = ordered.get(node).ok_or(SplitRefusal::GraphRejected)?;
            address_of.push(block.start);
            continue;
        }
        let offset: u64 = u64::try_from(node.saturating_sub(original_len).saturating_add(1))
            .map_err(|_error| SplitRefusal::AddressSpaceExhausted)?;
        let address: u64 = highest_start
            .checked_add(offset)
            .ok_or(SplitRefusal::AddressSpaceExhausted)?;
        address_of.push(address);
    }
    let mut split: Vec<NirBlock> = Vec::with_capacity(transformed.len());
    for node in 0..transformed.len() {
        let node_id: NodeId =
            NodeId::try_from(node).map_err(|_error| SplitRefusal::AddressSpaceExhausted)?;
        let origin: usize = if node < original_len {
            node
        } else {
            let mapped: NodeId = clone_map
                .get(&node_id)
                .copied()
                .ok_or(SplitRefusal::CloneCheckFailed)?;
            usize::try_from(mapped).map_err(|_error| SplitRefusal::CloneCheckFailed)?
        };
        let source: &NirBlock = ordered.get(origin).ok_or(SplitRefusal::CloneCheckFailed)?;
        let start: u64 = address_of
            .get(node)
            .copied()
            .ok_or(SplitRefusal::GraphRejected)?;
        let node_term: &CfgNode = transformed
            .node(node_id)
            .ok_or(SplitRefusal::GraphRejected)?;
        split.push(rewired_block(source, start, &node_term.term, &address_of)?);
    }
    Ok(split)
}

fn rewired_block(
    source: &NirBlock,
    start: u64,
    term: &Terminator,
    address_of: &[u64],
) -> Result<NirBlock, SplitRefusal> {
    let address = |node: NodeId| -> Result<u64, SplitRefusal> {
        usize::try_from(node)
            .ok()
            .and_then(|index: usize| address_of.get(index).copied())
            .ok_or(SplitRefusal::GraphRejected)
    };
    let (mut successors, retarget): (Vec<u64>, Option<u64>) = match term {
        Terminator::Return | Terminator::Unreachable => (Vec::new(), None),
        Terminator::Goto(target) => {
            let resolved: u64 = address(*target)?;
            (vec![resolved], Some(resolved))
        }
        Terminator::Branch {
            taken, not_taken, ..
        } => {
            let taken_address: u64 = address(*taken)?;
            let not_taken_address: u64 = address(*not_taken)?;
            (vec![taken_address, not_taken_address], Some(taken_address))
        }
        Terminator::Switch { cases, default, .. } => {
            let mut targets: Vec<u64> = Vec::with_capacity(cases.len().saturating_add(1));
            for (_value, target) in cases {
                targets.push(address(*target)?);
            }
            if let Some(fallback) = default {
                targets.push(address(*fallback)?);
            }
            (targets, None)
        }
    };
    successors.sort_unstable();
    successors.dedup();
    let mut instructions: Vec<NirInstr> = source.instructions.clone();
    if let Some(target) = retarget
        && matches!(
            source.kind,
            BlockKind::Conditional | BlockKind::Jump | BlockKind::Indirect
        )
        && let Some(last) = instructions.last_mut()
    {
        retarget_instruction(last, target);
    }
    Ok(NirBlock {
        start,
        end: source.end,
        instructions,
        successors,
        kind: source.kind,
    })
}

const fn retarget_instruction(instruction: &mut NirInstr, target: u64) {
    match &mut instruction.op {
        NirOp::Branch { target: slot } | NirOp::CondBranch { target: slot } => {
            *slot = Some(target);
        }
        _ => {}
    }
}
