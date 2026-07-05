use std::collections::BTreeSet;

/// Directed graph over dense `u32` nodes `0..node_count` with a single entry.
pub trait DiGraph {
    /// Number of nodes; valid ids are `0..node_count()`.
    fn node_count(&self) -> usize;
    /// The unique entry node id.
    fn entry(&self) -> u32;
    /// Report each direct successor of `node` to `visit`, in a deterministic order.
    fn for_each_successor(&self, node: u32, visit: &mut dyn FnMut(u32));
}

/// Owned adjacency-list graph, useful for reversed graphs, tests, and ad-hoc callers.
#[derive(Debug, Clone)]
pub struct AdjGraph {
    entry: u32,
    succ: Vec<Vec<u32>>,
}

impl AdjGraph {
    /// Build a graph with `entry` and per-node successor lists (`succ[n]` for node `n`).
    #[must_use]
    pub const fn new(entry: u32, succ: Vec<Vec<u32>>) -> Self {
        Self { entry, succ }
    }
}

impl DiGraph for AdjGraph {
    fn node_count(&self) -> usize {
        self.succ.len()
    }

    fn entry(&self) -> u32 {
        self.entry
    }

    fn for_each_successor(&self, node: u32, visit: &mut dyn FnMut(u32)) {
        if let Some(list) = self.succ.get(node as usize) {
            for &s in list {
                visit(s);
            }
        }
    }
}

const UNVISITED: u32 = u32::MAX;

fn reverse_postorder<G: DiGraph>(graph: &G) -> (Vec<u32>, Vec<u32>) {
    let count: usize = graph.node_count();
    let mut visited: Vec<bool> = vec![false; count];
    let mut postorder: Vec<u32> = Vec::with_capacity(count);
    let entry: u32 = graph.entry();
    if (entry as usize) >= count {
        return (Vec::new(), vec![UNVISITED; count]);
    }
    let mut stack: Vec<(u32, Vec<u32>, usize)> = Vec::new();
    let mut initial: Vec<u32> = Vec::new();
    graph.for_each_successor(entry, &mut |s: u32| initial.push(s));
    visited[entry as usize] = true;
    stack.push((entry, initial, 0));
    while let Some((node, succs, idx)) = stack.last_mut() {
        if *idx < succs.len() {
            let child: u32 = succs[*idx];
            *idx += 1;
            let ci: usize = child as usize;
            if ci < count && !visited[ci] {
                visited[ci] = true;
                let mut child_succs: Vec<u32> = Vec::new();
                graph.for_each_successor(child, &mut |s: u32| child_succs.push(s));
                stack.push((child, child_succs, 0));
            }
        } else {
            postorder.push(*node);
            stack.pop();
        }
    }
    let mut rpo: Vec<u32> = postorder;
    rpo.reverse();
    let mut rpo_num: Vec<u32> = vec![UNVISITED; count];
    for (i, &node) in rpo.iter().enumerate() {
        rpo_num[node as usize] = i as u32;
    }
    (rpo, rpo_num)
}

fn predecessors<G: DiGraph>(graph: &G) -> Vec<Vec<u32>> {
    let count: usize = graph.node_count();
    let mut preds: Vec<Vec<u32>> = vec![Vec::new(); count];
    for from in 0..count {
        graph.for_each_successor(from as u32, &mut |s: u32| {
            if (s as usize) < count {
                preds[s as usize].push(from as u32);
            }
        });
    }
    preds
}

/// Dominator tree of a [`DiGraph`], via the Cooper-Harvey-Kennedy iterative algorithm.
#[derive(Debug, Clone)]
pub struct Dominators {
    entry: u32,
    idom: Vec<Option<u32>>,
    rpo: Vec<u32>,
}

impl Dominators {
    /// Compute the unique dominator tree (Cooper-Harvey-Kennedy iterative dominance).
    #[must_use]
    pub fn compute<G: DiGraph>(graph: &G) -> Self {
        let count: usize = graph.node_count();
        let entry: u32 = graph.entry();
        let (rpo, rpo_num): (Vec<u32>, Vec<u32>) = reverse_postorder(graph);
        let preds: Vec<Vec<u32>> = predecessors(graph);
        let mut idom: Vec<Option<u32>> = vec![None; count];
        if (entry as usize) < count {
            idom[entry as usize] = Some(entry);
        }
        let mut changed: bool = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == entry {
                    continue;
                }
                let mut new_idom: Option<u32> = None;
                for &p in &preds[b as usize] {
                    if idom[p as usize].is_some() {
                        new_idom =
                            Some(new_idom.map_or(p, |cur: u32| intersect(cur, p, &idom, &rpo_num)));
                    }
                }
                if new_idom.is_some() && new_idom != idom[b as usize] {
                    idom[b as usize] = new_idom;
                    changed = true;
                }
            }
        }
        Self { entry, idom, rpo }
    }

    /// Reverse-postorder of the reachable nodes, entry first.
    #[must_use]
    pub fn reverse_postorder(&self) -> &[u32] {
        &self.rpo
    }

    /// Whether `node` is reachable from the entry.
    #[must_use]
    pub fn is_reachable(&self, node: u32) -> bool {
        node == self.entry || self.idom.get(node as usize).copied().flatten().is_some()
    }

    /// Immediate dominator of `node`: `None` for the entry and unreachable nodes.
    #[must_use]
    pub fn immediate_dominator(&self, node: u32) -> Option<u32> {
        if node == self.entry {
            return None;
        }
        self.idom.get(node as usize).copied().flatten()
    }

    /// Whether `a` dominates `b` (every path from entry to `b` passes through `a`).
    #[must_use]
    pub fn dominates(&self, a: u32, b: u32) -> bool {
        let mut cur: u32 = b;
        loop {
            if cur == a {
                return true;
            }
            match self.idom.get(cur as usize).copied().flatten() {
                Some(parent) if parent == cur => return false,
                Some(parent) => cur = parent,
                None => return false,
            }
        }
    }

    /// Full dominator set of `node` (itself plus every strict dominator), for reachable nodes.
    #[must_use]
    pub fn dominator_set(&self, node: u32) -> BTreeSet<u32> {
        let mut set: BTreeSet<u32> = BTreeSet::new();
        let mut cur: u32 = node;
        loop {
            if !set.insert(cur) {
                break;
            }
            match self.idom.get(cur as usize).copied().flatten() {
                Some(parent) if parent == cur => break,
                Some(parent) => cur = parent,
                None => break,
            }
        }
        set
    }

    /// Children of `node` in the dominator tree, in ascending id order.
    #[must_use]
    pub fn children(&self, node: u32) -> Vec<u32> {
        let mut kids: Vec<u32> = Vec::new();
        for (child, parent) in self.idom.iter().enumerate() {
            if child as u32 != self.entry && *parent == Some(node) {
                kids.push(child as u32);
            }
        }
        kids
    }
}

fn intersect(mut a: u32, mut b: u32, idom: &[Option<u32>], rpo_num: &[u32]) -> u32 {
    while a != b {
        while rpo_num[a as usize] > rpo_num[b as usize] {
            match idom[a as usize] {
                Some(next) if next != a => a = next,
                _ => return a,
            }
        }
        while rpo_num[b as usize] > rpo_num[a as usize] {
            match idom[b as usize] {
                Some(next) if next != b => b = next,
                _ => return b,
            }
        }
    }
    a
}

/// Classic maximum-fixed-point dominator sets (`set[n]` is `{n}` plus every dominator of `n`).
#[must_use]
pub fn dominator_sets<G: DiGraph>(graph: &G) -> Vec<BTreeSet<u32>> {
    let count: usize = graph.node_count();
    let entry: u32 = graph.entry();
    let preds: Vec<Vec<u32>> = predecessors(graph);
    let all: BTreeSet<u32> = (0..count as u32).collect();
    let mut dom: Vec<BTreeSet<u32>> = vec![all; count];
    if (entry as usize) < count {
        dom[entry as usize] = BTreeSet::from([entry]);
    }
    let mut changed: bool = true;
    while changed {
        changed = false;
        for node in 0..count as u32 {
            if node == entry {
                continue;
            }
            let mut new_dom: Option<BTreeSet<u32>> = None;
            for &pred in &preds[node as usize] {
                new_dom = Some(new_dom.map_or_else(
                    || dom[pred as usize].clone(),
                    |acc: BTreeSet<u32>| acc.intersection(&dom[pred as usize]).copied().collect(),
                ));
            }
            let mut new_dom: BTreeSet<u32> = new_dom.unwrap_or_default();
            new_dom.insert(node);
            if new_dom != dom[node as usize] {
                dom[node as usize] = new_dom;
                changed = true;
            }
        }
    }
    dom
}

/// Immediate post-dominators via dominance on the reversed graph rooted at a synthetic exit (`node_count`); `None` when a node cannot reach exit.
pub fn immediate_post_dominators(
    node_count: usize,
    mut successors_with_exit: impl FnMut(u32, &mut dyn FnMut(u32)),
) -> Vec<Option<u32>> {
    let exit: u32 = node_count as u32;
    let total: usize = node_count + 1;
    let mut reverse: Vec<Vec<u32>> = vec![Vec::new(); total];
    for from in 0..node_count as u32 {
        successors_with_exit(from, &mut |s: u32| {
            if (s as usize) < total {
                reverse[s as usize].push(from);
            }
        });
    }
    let graph: AdjGraph = AdjGraph::new(exit, reverse);
    let doms: Dominators = Dominators::compute(&graph);
    (0..node_count as u32)
        .map(|n: u32| doms.immediate_dominator(n))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::needless_range_loop)]
mod tests {
    use super::*;
    use crate::rng::{SeededRng, seeded};
    use rand::RngExt;
    use std::collections::BTreeMap;

    fn naive_dominators(entry: u32, succ: &[Vec<u32>]) -> Vec<Option<BTreeSet<u32>>> {
        let count: usize = succ.len();
        let reachable: Vec<bool> = reachable_set(entry, succ);
        let mut out: Vec<Option<BTreeSet<u32>>> = vec![None; count];
        for target in 0..count as u32 {
            if !reachable[target as usize] {
                continue;
            }
            let mut doms: BTreeSet<u32> = BTreeSet::new();
            for candidate in 0..count as u32 {
                if !reachable[candidate as usize] {
                    continue;
                }
                if candidate == target || !reaches_avoiding(entry, target, candidate, succ) {
                    doms.insert(candidate);
                }
            }
            out[target as usize] = Some(doms);
        }
        out
    }

    fn reachable_set(entry: u32, succ: &[Vec<u32>]) -> Vec<bool> {
        let count: usize = succ.len();
        let mut seen: Vec<bool> = vec![false; count];
        if (entry as usize) >= count {
            return seen;
        }
        let mut stack: Vec<u32> = vec![entry];
        seen[entry as usize] = true;
        while let Some(node) = stack.pop() {
            for &s in &succ[node as usize] {
                if (s as usize) < count && !seen[s as usize] {
                    seen[s as usize] = true;
                    stack.push(s);
                }
            }
        }
        seen
    }

    fn reaches_avoiding(entry: u32, target: u32, blocked: u32, succ: &[Vec<u32>]) -> bool {
        let count: usize = succ.len();
        if entry == blocked {
            return false;
        }
        let mut seen: Vec<bool> = vec![false; count];
        let mut stack: Vec<u32> = vec![entry];
        seen[entry as usize] = true;
        while let Some(node) = stack.pop() {
            if node == target {
                return true;
            }
            for &s in &succ[node as usize] {
                let si: usize = s as usize;
                if si < count && s != blocked && !seen[si] {
                    seen[si] = true;
                    stack.push(s);
                }
            }
        }
        false
    }

    fn idom_from_sets(entry: u32, sets: &[Option<BTreeSet<u32>>]) -> Vec<Option<u32>> {
        sets.iter()
            .enumerate()
            .map(|(node, maybe): (usize, &Option<BTreeSet<u32>>)| {
                let node: u32 = node as u32;
                let Some(doms) = maybe else {
                    return None;
                };
                if node == entry {
                    return None;
                }
                let strict: Vec<u32> = doms.iter().copied().filter(|&d: &u32| d != node).collect();
                strict.iter().copied().find(|&cand: &u32| {
                    strict.iter().all(|&other: &u32| {
                        other == cand
                            || sets[cand as usize]
                                .as_ref()
                                .is_some_and(|s: &BTreeSet<u32>| s.contains(&other))
                    })
                })
            })
            .collect()
    }

    fn random_graph(rng: &mut SeededRng, count: usize, allow_irreducible: bool) -> Vec<Vec<u32>> {
        let mut succ: Vec<Vec<u32>> = vec![Vec::new(); count];
        for node in 0..count {
            let fanout: usize = (rng.random::<u32>() % 3) as usize;
            for _ in 0..fanout {
                let target: u32 = if allow_irreducible {
                    rng.random::<u32>() % count as u32
                } else {
                    let span: u32 = (count - node) as u32;
                    node as u32 + 1 + (rng.random::<u32>() % span.max(1))
                };
                if (target as usize) < count && !succ[node].contains(&target) {
                    succ[node].push(target);
                }
            }
            succ[node].sort_unstable();
        }
        succ
    }

    fn connected_graph(rng: &mut SeededRng, count: usize) -> Vec<Vec<u32>> {
        let mut succ: Vec<Vec<u32>> = random_graph(rng, count, true);
        for node in 1..count as u32 {
            let parent: usize = (rng.random::<u32>() % node) as usize;
            if !succ[parent].contains(&node) {
                succ[parent].push(node);
                succ[parent].sort_unstable();
            }
        }
        succ
    }

    #[test]
    fn chk_idom_matches_naive_oracle_reducible_and_irreducible() {
        for irreducible in [false, true] {
            let mut rng: SeededRng = seeded(if irreducible {
                0xC0FF_EE01
            } else {
                0x1234_5678
            });
            for _ in 0..400 {
                let count: usize = 1 + (rng.random::<u32>() % 12) as usize;
                let succ: Vec<Vec<u32>> = random_graph(&mut rng, count, irreducible);
                let graph: AdjGraph = AdjGraph::new(0, succ.clone());
                let doms: Dominators = Dominators::compute(&graph);
                let oracle_sets: Vec<Option<BTreeSet<u32>>> = naive_dominators(0, &succ);
                let oracle_idom: Vec<Option<u32>> = idom_from_sets(0, &oracle_sets);
                for node in 0..count as u32 {
                    assert_eq!(
                        doms.immediate_dominator(node),
                        oracle_idom[node as usize],
                        "idom mismatch node {node} irreducible={irreducible} succ={succ:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn dominator_sets_match_naive_on_connected_graphs() {
        let mut rng: SeededRng = seeded(0xABCD_1234);
        for _ in 0..400 {
            let count: usize = 1 + (rng.random::<u32>() % 12) as usize;
            let succ: Vec<Vec<u32>> = connected_graph(&mut rng, count);
            let graph: AdjGraph = AdjGraph::new(0, succ.clone());
            let sets: Vec<BTreeSet<u32>> = dominator_sets(&graph);
            let oracle: Vec<Option<BTreeSet<u32>>> = naive_dominators(0, &succ);
            for node in 0..count {
                assert_eq!(
                    Some(&sets[node]),
                    oracle[node].as_ref(),
                    "dom-set mismatch node {node} succ={succ:?}"
                );
            }
        }
    }

    #[test]
    fn dominates_agrees_with_dominator_set() {
        let mut rng: SeededRng = seeded(0x5555_AAAA);
        for _ in 0..300 {
            let count: usize = 1 + (rng.random::<u32>() % 10) as usize;
            let succ: Vec<Vec<u32>> = random_graph(&mut rng, count, true);
            let graph: AdjGraph = AdjGraph::new(0, succ);
            let doms: Dominators = Dominators::compute(&graph);
            for b in 0..count as u32 {
                if !doms.is_reachable(b) {
                    continue;
                }
                let set: BTreeSet<u32> = doms.dominator_set(b);
                for a in 0..count as u32 {
                    assert_eq!(doms.dominates(a, b), set.contains(&a), "dominates({a},{b})");
                }
            }
        }
    }

    #[test]
    fn postdominators_well_defined_multi_return_noreturn_infinite() {
        let mut rng: SeededRng = seeded(0xFEED_BEEF);
        for _ in 0..400 {
            let count: usize = 1 + (rng.random::<u32>() % 12) as usize;
            let succ: Vec<Vec<u32>> = random_graph(&mut rng, count, true);
            let mut sinks: BTreeSet<u32> = BTreeSet::new();
            for (node, list) in succ.iter().enumerate() {
                if list.is_empty() || rng.random::<u32>() % 4 == 0 {
                    sinks.insert(node as u32);
                }
            }
            let succ_ref: &Vec<Vec<u32>> = &succ;
            let sinks_ref: &BTreeSet<u32> = &sinks;
            let report = |node: u32, visit: &mut dyn FnMut(u32)| {
                for &s in &succ_ref[node as usize] {
                    visit(s);
                }
                if sinks_ref.contains(&node) {
                    visit(count as u32);
                }
            };
            let first: Vec<Option<u32>> = immediate_post_dominators(count, report);
            let report2 = |node: u32, visit: &mut dyn FnMut(u32)| {
                for &s in &succ_ref[node as usize] {
                    visit(s);
                }
                if sinks_ref.contains(&node) {
                    visit(count as u32);
                }
            };
            let second: Vec<Option<u32>> = immediate_post_dominators(count, report2);
            assert_eq!(first, second, "postdom nondeterministic succ={succ:?}");

            let mut reverse: Vec<Vec<u32>> = vec![Vec::new(); count + 1];
            for node in 0..count as u32 {
                for &s in &succ[node as usize] {
                    reverse[s as usize].push(node);
                }
                if sinks.contains(&node) {
                    reverse[count].push(node);
                }
            }
            let oracle_sets: Vec<Option<BTreeSet<u32>>> = naive_dominators(count as u32, &reverse);
            let oracle_idom: Vec<Option<u32>> = idom_from_sets(count as u32, &oracle_sets);
            for node in 0..count {
                assert_eq!(
                    first[node], oracle_idom[node],
                    "postdom mismatch node {node} succ={succ:?} sinks={sinks:?}"
                );
            }
        }
    }

    #[test]
    fn dominator_sets_order_independent_with_dead_block_into_live() {
        let succ: Vec<Vec<u32>> = vec![vec![1], vec![], vec![1]];
        let graph: AdjGraph = AdjGraph::new(0, succ);
        let sets: Vec<BTreeSet<u32>> = dominator_sets(&graph);
        assert_eq!(sets[1], BTreeSet::from([1]));
        let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
        for set in &sets {
            *counts.entry(set.len() as u32).or_default() += 1;
        }
        assert!(counts.contains_key(&1));
    }
}
