use std::collections::{BTreeMap, BTreeSet};

use crate::flow::FlowGraph;
use crate::{
    Cfg, CfgNode, CloneMap, CnsBudget, NodeId, PostDominators, flow_of, predecessors, reachable,
    retarget_terminator, term_successors,
};

type Dominance = FlowGraph<NodeId>;

fn dominance_of(cfg: &Cfg) -> Option<Dominance> {
    flow_of(cfg).ok()
}

fn post_dominance_of(cfg: &Cfg) -> Option<PostDominators> {
    PostDominators::compute(cfg).ok()
}

const MAX_RECONVERGENCE_CLONES: usize = 64;
const RECONVERGENCE_ITERATION_SLACK: usize = 4;
const RECONVERGENCE_CASCADE_HEADROOM: usize = 2;

impl CnsBudget {
    #[must_use]
    pub fn tight_for_reconvergence(cfg: &Cfg) -> Self {
        let joins: Vec<NodeId> = reconvergent_joins(cfg);
        let preds: Vec<Vec<NodeId>> = predecessors(cfg);
        let live: Vec<bool> = reachable(cfg);
        let Some(doms): Option<Dominance> = dominance_of(cfg) else {
            return Self {
                max_cloned_blocks: 0,
                max_iterations: 0,
            };
        };
        let Some(post): Option<PostDominators> = post_dominance_of(cfg) else {
            return Self {
                max_cloned_blocks: 0,
                max_iterations: 0,
            };
        };
        let mut clones: usize = 0;
        for join in &joins {
            let extra_edges: usize =
                preds
                    .get(*join as usize)
                    .map_or(0, |incoming: &Vec<NodeId>| {
                        incoming
                            .iter()
                            .filter(|pred: &&NodeId| {
                                live.get(**pred as usize).copied().unwrap_or(false)
                            })
                            .count()
                            .saturating_sub(1)
                    });
            let region: usize = region_between(cfg, *join, &doms, &post).len();
            clones = clones.saturating_add(extra_edges.saturating_mul(region));
        }
        Self {
            max_cloned_blocks: clones
                .saturating_mul(RECONVERGENCE_CASCADE_HEADROOM)
                .min(MAX_RECONVERGENCE_CLONES),
            max_iterations: joins
                .len()
                .saturating_mul(RECONVERGENCE_CASCADE_HEADROOM)
                .saturating_add(RECONVERGENCE_ITERATION_SLACK),
        }
    }
}

#[must_use]
pub fn reconvergent_joins(cfg: &Cfg) -> Vec<NodeId> {
    let live: Vec<bool> = reachable(cfg);
    let preds: Vec<Vec<NodeId>> = predecessors(cfg);
    let Some(doms): Option<Dominance> = dominance_of(cfg) else {
        return Vec::new();
    };
    let Some(post): Option<PostDominators> = post_dominance_of(cfg) else {
        return Vec::new();
    };
    let mut found: Vec<NodeId> = Vec::new();
    let Ok(count): Result<NodeId, _> = NodeId::try_from(cfg.len()) else {
        return found;
    };
    for node in 0..count {
        if !live.get(node as usize).copied().unwrap_or(false) {
            continue;
        }
        let Some(incoming): Option<&Vec<NodeId>> = preds.get(node as usize) else {
            continue;
        };
        let live_incoming: Vec<NodeId> = incoming
            .iter()
            .copied()
            .filter(|pred: &NodeId| live.get(*pred as usize).copied().unwrap_or(false))
            .collect();
        if live_incoming.len() < 2 {
            continue;
        }
        if live_incoming
            .iter()
            .any(|pred: &NodeId| doms.dominates(node, *pred))
        {
            continue;
        }
        let Some(idom): Option<NodeId> = doms.immediate_dominator(node) else {
            continue;
        };
        if post.immediate_post_dominator(idom) == Some(node) {
            continue;
        }
        found.push(node);
    }
    found
}

pub fn split_reconvergence(cfg: &Cfg, budget: CnsBudget) -> Option<(Cfg, CloneMap)> {
    let original_len: usize = cfg.len();
    let mut transformed: Cfg = cfg.clone();
    let mut clone_map: CloneMap = BTreeMap::new();
    let mut cloned_blocks: usize = 0;
    let mut iterations: usize = 0;
    while iterations < budget.max_iterations {
        let joins: Vec<NodeId> = reconvergent_joins(&transformed);
        let Some(join): Option<NodeId> = joins.first().copied() else {
            return Some((transformed, clone_map));
        };
        if !peel_join(
            &mut transformed,
            join,
            original_len,
            &mut clone_map,
            &mut cloned_blocks,
            budget,
        ) {
            return None;
        }
        iterations = iterations.saturating_add(1);
    }
    reconvergent_joins(&transformed)
        .is_empty()
        .then_some((transformed, clone_map))
}

fn region_between(
    cfg: &Cfg,
    join: NodeId,
    doms: &Dominance,
    post: &PostDominators,
) -> BTreeSet<NodeId> {
    let mut region: BTreeSet<NodeId> = BTreeSet::new();
    let follow: Option<NodeId> = doms
        .immediate_dominator(join)
        .and_then(|idom: NodeId| post.immediate_post_dominator(idom))
        .or_else(|| post.immediate_post_dominator(join));
    let mut stack: Vec<NodeId> = vec![join];
    while let Some(node) = stack.pop() {
        if Some(node) == follow || !doms.dominates(join, node) || !region.insert(node) {
            continue;
        }
        let Some(entry): Option<&CfgNode> = cfg.nodes.get(node as usize) else {
            continue;
        };
        for successor in term_successors(&entry.term) {
            stack.push(successor);
        }
    }
    region
}

fn peel_join(
    cfg: &mut Cfg,
    join: NodeId,
    original_len: usize,
    clone_map: &mut CloneMap,
    cloned_blocks: &mut usize,
    budget: CnsBudget,
) -> bool {
    let live: Vec<bool> = reachable(cfg);
    let preds: Vec<Vec<NodeId>> = predecessors(cfg);
    let Some(doms): Option<Dominance> = dominance_of(cfg) else {
        return false;
    };
    let Some(post): Option<PostDominators> = post_dominance_of(cfg) else {
        return false;
    };
    let Some(incoming): Option<&Vec<NodeId>> = preds.get(join as usize) else {
        return false;
    };
    let live_incoming: Vec<NodeId> = incoming
        .iter()
        .copied()
        .filter(|pred: &NodeId| live.get(*pred as usize).copied().unwrap_or(false))
        .collect();
    if live_incoming.len() < 2 {
        return false;
    }
    let region: BTreeSet<NodeId> = region_between(cfg, join, &doms, &post);
    if region.is_empty() {
        return false;
    }
    for pred in live_incoming.iter().copied().skip(1) {
        let remaining: usize = budget.max_cloned_blocks.saturating_sub(*cloned_blocks);
        if region.len() > remaining {
            return false;
        }
        if !duplicate_region(cfg, &region, join, pred, original_len, clone_map) {
            return false;
        }
        *cloned_blocks = cloned_blocks.saturating_add(region.len());
    }
    true
}

fn duplicate_region(
    cfg: &mut Cfg,
    region: &BTreeSet<NodeId>,
    join: NodeId,
    predecessor: NodeId,
    original_len: usize,
    clone_map: &mut CloneMap,
) -> bool {
    let Ok(base): Result<NodeId, _> = NodeId::try_from(cfg.nodes.len()) else {
        return false;
    };
    let mut remap: BTreeMap<NodeId, NodeId> = BTreeMap::new();
    for (offset, node) in region.iter().copied().enumerate() {
        let Ok(step): Result<NodeId, _> = NodeId::try_from(offset) else {
            return false;
        };
        let Some(clone): Option<NodeId> = base.checked_add(step) else {
            return false;
        };
        remap.insert(node, clone);
    }
    let mut duplicates: Vec<CfgNode> = Vec::with_capacity(region.len());
    for node in region.iter().copied() {
        let Some(source): Option<&CfgNode> = cfg.nodes.get(node as usize) else {
            return false;
        };
        let mut duplicate: CfgNode = source.clone();
        for (&from, &to) in &remap {
            retarget_terminator(&mut duplicate.term, from, to);
        }
        let origin: NodeId = clone_map.get(&node).copied().unwrap_or(node);
        if usize::try_from(origin).map_or(true, |value: usize| value >= original_len) {
            return false;
        }
        let Some(&clone): Option<&NodeId> = remap.get(&node) else {
            return false;
        };
        clone_map.insert(clone, origin);
        duplicates.push(duplicate);
    }
    let Some(&clone_entry): Option<&NodeId> = remap.get(&join) else {
        return false;
    };
    cfg.nodes.extend(duplicates);
    let Some(source): Option<&mut CfgNode> = cfg.nodes.get_mut(predecessor as usize) else {
        return false;
    };
    retarget_terminator(&mut source.term, join, clone_entry);
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{Terminator, relowered_matches_original_modulo_clones};

    fn node(term: Terminator) -> CfgNode {
        CfgNode { term, pure: true }
    }

    fn build(entry: NodeId, terms: Vec<Terminator>) -> Cfg {
        Cfg::new(entry, terms.into_iter().map(node).collect()).expect("cfg builds")
    }

    fn short_circuit() -> Cfg {
        build(
            0,
            vec![
                Terminator::Branch {
                    atom: 0,
                    taken: 3,
                    not_taken: 1,
                },
                Terminator::Goto(2),
                Terminator::Branch {
                    atom: 2,
                    taken: 3,
                    not_taken: 4,
                },
                Terminator::Goto(5),
                Terminator::Goto(5),
                Terminator::Return,
            ],
        )
    }

    #[test]
    fn a_plain_diamond_has_nothing_to_peel() {
        let diamond: Cfg = build(
            0,
            vec![
                Terminator::Branch {
                    atom: 0,
                    taken: 1,
                    not_taken: 2,
                },
                Terminator::Goto(3),
                Terminator::Goto(3),
                Terminator::Return,
            ],
        );
        assert!(
            reconvergent_joins(&diamond).is_empty(),
            "an if/else merge is the follow node and must never be duplicated"
        );
    }

    #[test]
    fn a_loop_header_is_never_treated_as_a_reconvergent_join() {
        let loop_cfg: Cfg = build(
            0,
            vec![
                Terminator::Goto(1),
                Terminator::Branch {
                    atom: 1,
                    taken: 2,
                    not_taken: 3,
                },
                Terminator::Goto(1),
                Terminator::Return,
            ],
        );
        assert!(
            reconvergent_joins(&loop_cfg).is_empty(),
            "a header reached by its own back edge is a loop, not a reconvergence"
        );
    }

    #[test]
    fn a_short_circuit_join_is_found_and_peeled_into_a_verified_graph() {
        let original: Cfg = short_circuit();
        assert_eq!(
            reconvergent_joins(&original),
            vec![3],
            "the block both conditions jump to is the reconvergence"
        );
        let budget: CnsBudget = CnsBudget::tight_for_reconvergence(&original);
        let (transformed, clone_map): (Cfg, CloneMap) =
            split_reconvergence(&original, budget).expect("the peel fits its budget");
        assert_eq!(transformed.len(), original.len() + 1);
        assert_eq!(clone_map.get(&6).copied(), Some(3));
        assert!(
            reconvergent_joins(&transformed).is_empty(),
            "peeling must remove the reconvergence it found"
        );
        assert!(
            relowered_matches_original_modulo_clones(
                &original,
                &transformed,
                &clone_map,
                &BTreeMap::new(),
            ),
            "the peeled graph must stay edge-equivalent to the original modulo clones"
        );
    }

    #[test]
    fn a_zero_clone_budget_refuses_rather_than_degrading() {
        let original: Cfg = short_circuit();
        assert!(
            split_reconvergence(
                &original,
                CnsBudget {
                    max_cloned_blocks: 0,
                    max_iterations: 8,
                },
            )
            .is_none(),
            "a budget that cannot pay for the peel must refuse"
        );
    }

    #[test]
    fn peeling_the_same_graph_twice_produces_the_same_graph() {
        let original: Cfg = short_circuit();
        let budget: CnsBudget = CnsBudget::tight_for_reconvergence(&original);
        let (first, first_map): (Cfg, CloneMap) =
            split_reconvergence(&original, budget).expect("first peel");
        let (second, second_map): (Cfg, CloneMap) =
            split_reconvergence(&original, budget).expect("second peel");
        assert_eq!(first_map, second_map);
        assert_eq!(first.len(), second.len());
        for index in 0..first.len() as NodeId {
            assert_eq!(first.node(index), second.node(index));
        }
    }
}
