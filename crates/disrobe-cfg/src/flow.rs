use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use disrobe_core::{
    AdjGraph, Dominators, dominators::natural_loop_body, immediate_post_dominators,
};

pub const MAX_FLOW_NODES: usize = (u32::MAX - 1) as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flow<T> {
    To(T),
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum FlowError {
    NoNodes,
    DuplicateNode,
    EntryNotDeclared,
    SuccessorNotDeclared,
    NodeCountExceedsCapacity { count: usize, capacity: usize },
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoNodes => f.write_str("control-flow graph declares no nodes"),
            Self::DuplicateNode => f.write_str("control-flow graph declares one node twice"),
            Self::EntryNotDeclared => {
                f.write_str("control-flow graph entry is not one of its declared nodes")
            }
            Self::SuccessorNotDeclared => {
                f.write_str("control-flow edge targets a node the graph did not declare")
            }
            Self::NodeCountExceedsCapacity { count, capacity } => write!(
                f,
                "control-flow graph declares {count} nodes and the limit is {capacity}"
            ),
        }
    }
}

impl std::error::Error for FlowError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PostDominator<T> {
    Node(T),
    FunctionExit,
    Undefined,
}

impl<T> PostDominator<T> {
    pub fn node(self) -> Option<T> {
        match self {
            Self::Node(node) => Some(node),
            Self::FunctionExit | Self::Undefined => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowGraph<T: Copy + Ord> {
    ids: Vec<T>,
    dense: BTreeMap<T, u32>,
    entry: T,
    successors: Vec<Vec<u32>>,
    predecessors: Vec<Vec<u32>>,
    exiting: Vec<bool>,
    dominance: Dominators,
    ipdom: Vec<Option<u32>>,
}

impl<T: Copy + Ord> FlowGraph<T> {
    pub fn build<F>(
        nodes: impl IntoIterator<Item = T>,
        entry: T,
        flow: F,
    ) -> Result<Self, FlowError>
    where
        F: FnMut(T, &mut dyn FnMut(Flow<T>)),
    {
        assemble(nodes, entry, MAX_FLOW_NODES, flow)
    }

    pub const fn node_count(&self) -> usize {
        self.ids.len()
    }

    pub fn nodes(&self) -> &[T] {
        &self.ids
    }

    pub const fn entry(&self) -> T {
        self.entry
    }

    pub fn contains(&self, node: T) -> bool {
        self.dense.contains_key(&node)
    }

    fn index(&self, node: T) -> Option<u32> {
        self.dense.get(&node).copied()
    }

    fn id(&self, dense: u32) -> Option<T> {
        self.ids.get(dense as usize).copied()
    }

    fn adjacent<'a>(&'a self, table: &'a [Vec<u32>], node: T) -> impl Iterator<Item = T> + 'a {
        self.index(node)
            .and_then(|dense: u32| table.get(dense as usize))
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .filter_map(|dense: &u32| self.id(*dense))
    }

    pub fn successors(&self, node: T) -> impl Iterator<Item = T> + '_ {
        self.adjacent(&self.successors, node)
    }

    pub fn predecessors(&self, node: T) -> impl Iterator<Item = T> + '_ {
        self.adjacent(&self.predecessors, node)
    }

    pub fn is_reachable(&self, node: T) -> bool {
        self.index(node)
            .is_some_and(|dense: u32| self.dominance.is_reachable(dense))
    }

    pub fn reverse_postorder(&self) -> impl Iterator<Item = T> + '_ {
        self.dominance
            .reverse_postorder()
            .iter()
            .filter_map(|dense: &u32| self.id(*dense))
    }

    pub fn immediate_dominator(&self, node: T) -> Option<T> {
        let dense: u32 = self.index(node)?;
        self.id(self.dominance.immediate_dominator(dense)?)
    }

    pub fn dominates(&self, dominator: T, node: T) -> bool {
        let (Some(a), Some(b)): (Option<u32>, Option<u32>) =
            (self.index(dominator), self.index(node))
        else {
            return false;
        };
        self.dominance.is_reachable(b) && self.dominance.dominates(a, b)
    }

    pub fn dominator_set(&self, node: T) -> BTreeSet<T> {
        let Some(dense): Option<u32> = self.index(node) else {
            return BTreeSet::new();
        };
        if !self.dominance.is_reachable(dense) {
            return BTreeSet::new();
        }
        self.dominance
            .dominator_set(dense)
            .into_iter()
            .filter_map(|member: u32| self.id(member))
            .collect()
    }

    pub fn dominator_tree_children(&self, node: T) -> Vec<T> {
        let Some(dense): Option<u32> = self.index(node) else {
            return Vec::new();
        };
        self.dominance
            .children(dense)
            .into_iter()
            .filter_map(|child: u32| self.id(child))
            .collect()
    }

    pub fn dominance_frontiers(&self) -> BTreeMap<T, BTreeSet<T>> {
        let mut frontiers: BTreeMap<T, BTreeSet<T>> = BTreeMap::new();
        for (dense, entering) in self.predecessors.iter().enumerate() {
            let joined: u32 = dense as u32;
            if entering.is_empty() || !self.dominance.is_reachable(joined) {
                continue;
            }
            let Some(joined_id): Option<T> = self.id(joined) else {
                continue;
            };
            let stop: Option<u32> = self.dominance.immediate_dominator(joined);
            for &from in entering {
                if !self.dominance.is_reachable(from) {
                    continue;
                }
                let mut runner: u32 = from;
                let mut steps: usize = 0;
                while Some(runner) != stop {
                    let Some(runner_id): Option<T> = self.id(runner) else {
                        break;
                    };
                    frontiers.entry(runner_id).or_default().insert(joined_id);
                    let Some(next): Option<u32> = self.dominance.immediate_dominator(runner) else {
                        break;
                    };
                    if next == runner {
                        break;
                    }
                    runner = next;
                    steps += 1;
                    if steps > self.ids.len() {
                        break;
                    }
                }
            }
        }
        frontiers
    }

    pub fn immediate_post_dominator(&self, node: T) -> PostDominator<T> {
        let Some(dense): Option<u32> = self.index(node) else {
            return PostDominator::Undefined;
        };
        match self.ipdom.get(dense as usize).copied().flatten() {
            None => PostDominator::Undefined,
            Some(target) if target as usize >= self.ids.len() => PostDominator::FunctionExit,
            Some(target) => self
                .id(target)
                .map_or(PostDominator::Undefined, PostDominator::Node),
        }
    }

    pub fn post_dominates(&self, post_dominator: T, node: T) -> bool {
        if post_dominator == node {
            return self.contains(node);
        }
        let mut current: T = node;
        let mut steps: usize = 0;
        loop {
            match self.immediate_post_dominator(current) {
                PostDominator::Node(next) if next == post_dominator => return true,
                PostDominator::Node(next) if next == current => return false,
                PostDominator::Node(next) => current = next,
                PostDominator::FunctionExit | PostDominator::Undefined => return false,
            }
            steps += 1;
            if steps > self.ids.len() {
                return false;
            }
        }
    }

    pub fn exit_post_dominates(&self, node: T) -> bool {
        let mut current: T = node;
        let mut steps: usize = 0;
        loop {
            match self.immediate_post_dominator(current) {
                PostDominator::FunctionExit => return true,
                PostDominator::Undefined => return false,
                PostDominator::Node(next) if next == current => return false,
                PostDominator::Node(next) => current = next,
            }
            steps += 1;
            if steps > self.ids.len() {
                return false;
            }
        }
    }

    pub fn natural_loop_body(&self, header: T, latches: &[T]) -> BTreeSet<T> {
        natural_loop_body(header, latches, |node: T, emit: &mut dyn FnMut(T)| {
            for predecessor in self.predecessors(node) {
                if self.is_reachable(predecessor) {
                    emit(predecessor);
                }
            }
        })
    }

    pub fn back_edges(&self) -> Vec<(T, T)> {
        let mut edges: Vec<(T, T)> = Vec::new();
        for (dense, targets) in self.successors.iter().enumerate() {
            let latch: u32 = dense as u32;
            if !self.dominance.is_reachable(latch) {
                continue;
            }
            let Some(latch_id): Option<T> = self.id(latch) else {
                continue;
            };
            for &target in targets {
                let Some(header_id): Option<T> = self.id(target) else {
                    continue;
                };
                if self.dominance.dominates(target, latch) {
                    edges.push((latch_id, header_id));
                }
            }
        }
        edges
    }
}

fn assemble<T: Copy + Ord, F>(
    nodes: impl IntoIterator<Item = T>,
    entry: T,
    capacity: usize,
    mut flow: F,
) -> Result<FlowGraph<T>, FlowError>
where
    F: FnMut(T, &mut dyn FnMut(Flow<T>)),
{
    let mut ids: Vec<T> = Vec::new();
    let mut dense: BTreeMap<T, u32> = BTreeMap::new();
    for node in nodes {
        if ids.len() >= capacity {
            return Err(FlowError::NodeCountExceedsCapacity {
                count: ids.len() + 1,
                capacity,
            });
        }
        if dense.insert(node, ids.len() as u32).is_some() {
            return Err(FlowError::DuplicateNode);
        }
        ids.push(node);
    }
    if ids.is_empty() {
        return Err(FlowError::NoNodes);
    }
    let Some(entry_dense): Option<u32> = dense.get(&entry).copied() else {
        return Err(FlowError::EntryNotDeclared);
    };

    let count: usize = ids.len();
    let mut successors: Vec<Vec<u32>> = vec![Vec::new(); count];
    let mut predecessors: Vec<Vec<u32>> = vec![Vec::new(); count];
    let mut exiting: Vec<bool> = vec![false; count];
    for (index, node) in ids.iter().copied().enumerate() {
        let mut targets: Vec<u32> = Vec::new();
        let mut leaves: bool = false;
        let mut undeclared: bool = false;
        flow(node, &mut |edge: Flow<T>| match edge {
            Flow::To(target) => match dense.get(&target).copied() {
                Some(target_dense) => {
                    if !targets.contains(&target_dense) {
                        targets.push(target_dense);
                    }
                }
                None => undeclared = true,
            },
            Flow::Exit => leaves = true,
        });
        if undeclared {
            return Err(FlowError::SuccessorNotDeclared);
        }
        for &target in &targets {
            predecessors[target as usize].push(index as u32);
        }
        successors[index] = targets;
        exiting[index] = leaves;
    }

    let forward: AdjGraph = AdjGraph::new(entry_dense, successors.clone());
    let dominance: Dominators = Dominators::compute(&forward);
    let exit: u32 = count as u32;
    let ipdom: Vec<Option<u32>> =
        immediate_post_dominators(count, |node: u32, visit: &mut dyn FnMut(u32)| {
            let Some(targets): Option<&Vec<u32>> = successors.get(node as usize) else {
                return;
            };
            for &target in targets {
                visit(target);
            }
            if exiting.get(node as usize).copied().unwrap_or(false) {
                visit(exit);
            }
        });

    Ok(FlowGraph {
        ids,
        dense,
        entry,
        successors,
        predecessors,
        exiting,
        dominance,
        ipdom,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_range_loop,
    clippy::manual_memcpy
)]
mod tests {
    use super::*;
    use disrobe_core::rng::{SeededRng, seeded};
    use rand::RngExt;

    struct Shape {
        successors: Vec<Vec<u32>>,
        exiting: Vec<bool>,
    }

    fn graph_of(shape: &Shape) -> FlowGraph<u32> {
        FlowGraph::build(
            0..shape.successors.len() as u32,
            0,
            |node: u32, emit: &mut dyn FnMut(Flow<u32>)| {
                for &target in &shape.successors[node as usize] {
                    emit(Flow::To(target));
                }
                if shape.exiting[node as usize] {
                    emit(Flow::Exit);
                }
            },
        )
        .expect("shape builds")
    }

    fn reachable_from(entry: u32, successors: &[Vec<u32>]) -> Vec<bool> {
        let mut seen: Vec<bool> = vec![false; successors.len()];
        let mut stack: Vec<u32> = vec![entry];
        seen[entry as usize] = true;
        while let Some(node) = stack.pop() {
            for &target in &successors[node as usize] {
                if !seen[target as usize] {
                    seen[target as usize] = true;
                    stack.push(target);
                }
            }
        }
        seen
    }

    fn naive_dominator_sets(entry: u32, successors: &[Vec<u32>]) -> Vec<Option<BTreeSet<u32>>> {
        let count: usize = successors.len();
        let live: Vec<bool> = reachable_from(entry, successors);
        let mut out: Vec<Option<BTreeSet<u32>>> = vec![None; count];
        for target in 0..count as u32 {
            if !live[target as usize] {
                continue;
            }
            let mut doms: BTreeSet<u32> = BTreeSet::new();
            for candidate in 0..count as u32 {
                if !live[candidate as usize] {
                    continue;
                }
                if candidate == target || !reaches_avoiding(entry, target, candidate, successors) {
                    doms.insert(candidate);
                }
            }
            out[target as usize] = Some(doms);
        }
        out
    }

    fn reaches_avoiding(entry: u32, target: u32, blocked: u32, successors: &[Vec<u32>]) -> bool {
        if entry == blocked {
            return false;
        }
        let mut seen: Vec<bool> = vec![false; successors.len()];
        let mut stack: Vec<u32> = vec![entry];
        seen[entry as usize] = true;
        while let Some(node) = stack.pop() {
            if node == target {
                return true;
            }
            for &next in &successors[node as usize] {
                if next != blocked && !seen[next as usize] {
                    seen[next as usize] = true;
                    stack.push(next);
                }
            }
        }
        false
    }

    fn reversed_with_exit(shape: &Shape) -> Vec<Vec<u32>> {
        let count: usize = shape.successors.len();
        let mut reverse: Vec<Vec<u32>> = vec![Vec::new(); count + 1];
        for node in 0..count as u32 {
            for &target in &shape.successors[node as usize] {
                reverse[target as usize].push(node);
            }
            if shape.exiting[node as usize] {
                reverse[count].push(node);
            }
        }
        reverse
    }

    fn idom_from_sets(entry: u32, sets: &[Option<BTreeSet<u32>>]) -> Vec<Option<u32>> {
        sets.iter()
            .enumerate()
            .map(|(node, maybe): (usize, &Option<BTreeSet<u32>>)| {
                let node: u32 = node as u32;
                let doms: &BTreeSet<u32> = maybe.as_ref()?;
                if node == entry {
                    return None;
                }
                let strict: Vec<u32> = doms.iter().copied().filter(|&d: &u32| d != node).collect();
                strict.iter().copied().find(|&candidate: &u32| {
                    strict.iter().all(|&other: &u32| {
                        other == candidate
                            || sets[candidate as usize]
                                .as_ref()
                                .is_some_and(|s: &BTreeSet<u32>| s.contains(&other))
                    })
                })
            })
            .collect()
    }

    fn naive_frontiers(entry: u32, successors: &[Vec<u32>]) -> BTreeMap<u32, BTreeSet<u32>> {
        let sets: Vec<Option<BTreeSet<u32>>> = naive_dominator_sets(entry, successors);
        let mut out: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
        for (from, targets) in successors.iter().enumerate() {
            let from: u32 = from as u32;
            let Some(from_doms) = sets[from as usize].as_ref() else {
                continue;
            };
            for &joined in targets {
                let Some(joined_doms) = sets[joined as usize].as_ref() else {
                    continue;
                };
                for &candidate in from_doms {
                    let strictly_dominates: bool =
                        joined_doms.contains(&candidate) && candidate != joined;
                    if !strictly_dominates {
                        out.entry(candidate).or_default().insert(joined);
                    }
                }
            }
        }
        out.retain(|_, members: &mut BTreeSet<u32>| !members.is_empty());
        out
    }

    fn random_shape(rng: &mut SeededRng, count: usize) -> Shape {
        let mut successors: Vec<Vec<u32>> = vec![Vec::new(); count];
        for node in 0..count {
            let fanout: usize = (rng.random::<u32>() % 4) as usize;
            for _ in 0..fanout {
                let target: u32 = rng.random::<u32>() % count as u32;
                successors[node].push(target);
            }
        }
        let exiting: Vec<bool> = (0..count)
            .map(|node: usize| successors[node].is_empty() || rng.random::<u32>() % 4 == 0)
            .collect();
        Shape {
            successors,
            exiting,
        }
    }

    #[test]
    fn dominance_matches_the_naive_fixpoint_on_random_graphs() {
        let mut rng: SeededRng = seeded(0x0BAD_F00D);
        for _ in 0..600 {
            let count: usize = 1 + (rng.random::<u32>() % 14) as usize;
            let shape: Shape = random_shape(&mut rng, count);
            let graph: FlowGraph<u32> = graph_of(&shape);
            let oracle: Vec<Option<BTreeSet<u32>>> = naive_dominator_sets(0, &shape.successors);
            for node in 0..count as u32 {
                let expected: BTreeSet<u32> = oracle[node as usize].clone().unwrap_or_default();
                assert_eq!(
                    graph.dominator_set(node),
                    expected,
                    "dominator set for {node} in {:?}",
                    shape.successors
                );
                for candidate in 0..count as u32 {
                    assert_eq!(
                        graph.dominates(candidate, node),
                        expected.contains(&candidate),
                        "dominates({candidate},{node}) in {:?}",
                        shape.successors
                    );
                }
            }
        }
    }

    #[test]
    fn post_dominance_matches_the_naive_fixpoint_over_a_synthesised_exit() {
        let mut rng: SeededRng = seeded(0x1DEA_5EED);
        for _ in 0..600 {
            let count: usize = 1 + (rng.random::<u32>() % 14) as usize;
            let shape: Shape = random_shape(&mut rng, count);
            let graph: FlowGraph<u32> = graph_of(&shape);
            let reverse: Vec<Vec<u32>> = reversed_with_exit(&shape);
            let oracle_sets: Vec<Option<BTreeSet<u32>>> =
                naive_dominator_sets(count as u32, &reverse);
            let oracle: Vec<Option<u32>> = idom_from_sets(count as u32, &oracle_sets);
            for node in 0..count as u32 {
                let expected: PostDominator<u32> = match oracle[node as usize] {
                    None => PostDominator::Undefined,
                    Some(target) if target as usize == count => PostDominator::FunctionExit,
                    Some(target) => PostDominator::Node(target),
                };
                assert_eq!(
                    graph.immediate_post_dominator(node),
                    expected,
                    "ipdom for {node} in {:?} exiting={:?}",
                    shape.successors,
                    shape.exiting
                );
            }
        }
    }

    #[test]
    fn frontiers_match_the_definition_on_random_graphs() {
        let mut rng: SeededRng = seeded(0xFACE_B00C);
        for _ in 0..400 {
            let count: usize = 1 + (rng.random::<u32>() % 12) as usize;
            let shape: Shape = random_shape(&mut rng, count);
            let graph: FlowGraph<u32> = graph_of(&shape);
            assert_eq!(
                graph.dominance_frontiers(),
                naive_frontiers(0, &shape.successors),
                "frontiers for {:?}",
                shape.successors
            );
        }
    }

    #[test]
    fn duplicate_edges_do_not_change_the_answer() {
        let plain: Shape = Shape {
            successors: vec![vec![1, 2], vec![3], vec![3], vec![]],
            exiting: vec![false, false, false, true],
        };
        let doubled: Shape = Shape {
            successors: vec![vec![1, 2, 1, 2], vec![3, 3], vec![3], vec![]],
            exiting: vec![false, false, false, true],
        };
        let a: FlowGraph<u32> = graph_of(&plain);
        let b: FlowGraph<u32> = graph_of(&doubled);
        for node in 0..4u32 {
            assert_eq!(a.dominator_set(node), b.dominator_set(node));
            assert_eq!(
                a.immediate_post_dominator(node),
                b.immediate_post_dominator(node)
            );
        }
        assert_eq!(a.successors(0).collect::<Vec<u32>>(), vec![1, 2]);
    }

    #[test]
    fn a_self_loop_does_not_dominate_itself_through_its_own_back_edge() {
        let shape: Shape = Shape {
            successors: vec![vec![1], vec![1, 2], vec![]],
            exiting: vec![false, false, true],
        };
        let graph: FlowGraph<u32> = graph_of(&shape);
        assert_eq!(graph.immediate_dominator(1), Some(0));
        assert_eq!(graph.back_edges(), vec![(1, 1)]);
        assert_eq!(graph.natural_loop_body(1, &[1]), BTreeSet::from([1]));
    }

    #[test]
    fn an_unreachable_block_has_no_dominators() {
        let shape: Shape = Shape {
            successors: vec![vec![1], vec![], vec![1]],
            exiting: vec![false, true, false],
        };
        let graph: FlowGraph<u32> = graph_of(&shape);
        assert!(!graph.is_reachable(2));
        assert_eq!(graph.dominator_set(2), BTreeSet::new());
        assert!(!graph.dominates(0, 2));
        assert!(!graph.dominates(2, 2));
        assert_eq!(graph.immediate_dominator(2), None);
    }

    #[test]
    fn a_graph_with_no_exit_leaves_post_dominance_undefined() {
        let shape: Shape = Shape {
            successors: vec![vec![1], vec![0]],
            exiting: vec![false, false],
        };
        let graph: FlowGraph<u32> = graph_of(&shape);
        assert_eq!(graph.immediate_post_dominator(0), PostDominator::Undefined);
        assert_eq!(graph.immediate_post_dominator(1), PostDominator::Undefined);
        assert!(!graph.exit_post_dominates(0));
    }

    #[test]
    fn many_exits_share_the_one_synthesised_exit() {
        let shape: Shape = Shape {
            successors: vec![vec![1, 2], vec![], vec![]],
            exiting: vec![false, true, true],
        };
        let graph: FlowGraph<u32> = graph_of(&shape);
        assert_eq!(
            graph.immediate_post_dominator(0),
            PostDominator::FunctionExit
        );
        assert_eq!(
            graph.immediate_post_dominator(1),
            PostDominator::FunctionExit
        );
        assert!(graph.exit_post_dominates(0));
        assert!(!graph.post_dominates(1, 0));
    }

    #[test]
    fn an_irreducible_pair_of_headers_keeps_the_entry_as_the_dominator() {
        let shape: Shape = Shape {
            successors: vec![vec![1, 2], vec![2], vec![1, 3], vec![]],
            exiting: vec![false, false, false, true],
        };
        let graph: FlowGraph<u32> = graph_of(&shape);
        assert_eq!(graph.immediate_dominator(1), Some(0));
        assert_eq!(graph.immediate_dominator(2), Some(0));
        assert_eq!(graph.immediate_dominator(3), Some(2));
        assert!(graph.back_edges().is_empty());
    }

    #[test]
    fn an_entry_with_predecessors_still_dominates_everything() {
        let shape: Shape = Shape {
            successors: vec![vec![1], vec![0, 2], vec![]],
            exiting: vec![false, false, true],
        };
        let graph: FlowGraph<u32> = graph_of(&shape);
        assert!(graph.dominates(0, 1));
        assert!(graph.dominates(0, 2));
        assert_eq!(graph.immediate_dominator(0), None);
        assert_eq!(graph.back_edges(), vec![(1, 0)]);
    }

    #[test]
    fn a_node_the_graph_never_declared_is_rejected() {
        let built: Result<FlowGraph<u32>, FlowError> =
            FlowGraph::build(0..2u32, 0, |node: u32, emit: &mut dyn FnMut(Flow<u32>)| {
                if node == 0 {
                    emit(Flow::To(9));
                }
            });
        assert_eq!(built.unwrap_err(), FlowError::SuccessorNotDeclared);
    }

    #[test]
    fn a_node_count_above_the_ceiling_is_rejected() {
        let built: Result<FlowGraph<u32>, FlowError> =
            assemble(0..4u32, 0, 3, |_: u32, _: &mut dyn FnMut(Flow<u32>)| {});
        assert_eq!(
            built.unwrap_err(),
            FlowError::NodeCountExceedsCapacity {
                count: 4,
                capacity: 3
            }
        );
    }

    #[test]
    fn an_entry_outside_the_declared_nodes_is_rejected() {
        let built: Result<FlowGraph<u32>, FlowError> =
            FlowGraph::build(0..2u32, 7, |_: u32, _: &mut dyn FnMut(Flow<u32>)| {});
        assert_eq!(built.unwrap_err(), FlowError::EntryNotDeclared);
    }

    #[test]
    fn an_empty_node_list_is_rejected() {
        let built: Result<FlowGraph<u32>, FlowError> = FlowGraph::build(
            Vec::<u32>::new(),
            0,
            |_: u32, _: &mut dyn FnMut(Flow<u32>)| {},
        );
        assert_eq!(built.unwrap_err(), FlowError::NoNodes);
    }

    #[test]
    fn a_node_declared_twice_is_rejected() {
        let built: Result<FlowGraph<u32>, FlowError> = FlowGraph::build(
            vec![0u32, 1, 0],
            0,
            |_: u32, _: &mut dyn FnMut(Flow<u32>)| {},
        );
        assert_eq!(built.unwrap_err(), FlowError::DuplicateNode);
    }

    #[test]
    fn a_sparse_id_space_maps_both_ways() {
        let ids: Vec<u64> = vec![0x4010, 0x40a0, 0x4200];
        let graph: FlowGraph<u64> = FlowGraph::build(
            ids.clone(),
            0x4010,
            |node: u64, emit: &mut dyn FnMut(Flow<u64>)| match node {
                0x4010 => {
                    emit(Flow::To(0x40a0));
                    emit(Flow::To(0x4200));
                }
                _ => emit(Flow::Exit),
            },
        )
        .expect("sparse graph builds");
        assert_eq!(graph.nodes(), ids.as_slice());
        assert_eq!(graph.immediate_dominator(0x40a0), Some(0x4010));
        assert_eq!(
            graph.immediate_post_dominator(0x4010),
            PostDominator::FunctionExit
        );
        assert_eq!(
            graph.successors(0x4010).collect::<Vec<u64>>(),
            vec![0x40a0, 0x4200]
        );
        assert_eq!(
            graph.predecessors(0x4200).collect::<Vec<u64>>(),
            vec![0x4010]
        );
    }
}
