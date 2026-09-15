use std::collections::VecDeque;

use crate::structure::{BasicBlock, ControlFlowGraph};

const REFINEMENT_ROUND_CAP: usize = 16;

const UNREACHABLE_DEPTH: u32 = u32::MAX;

const FINGERPRINT_SEED: u64 = 0x9e37_79b9_7f4a_7c15;

const MIX_MULTIPLIER_LOW: u64 = 0xbf58_476d_1ce4_e5b9;

const MIX_MULTIPLIER_HIGH: u64 = 0x94d0_49bb_1331_11eb;

const COMBINE_ROTATION: u32 = 27;

const ENTRY_TAG: u64 = 0x01;

const ORDINARY_TAG: u64 = 0x02;

const VERTEX_TAG: u64 = 0x03;

const PREDECESSOR_TAG: u64 = 0x04;

const EDGE_TAG: u64 = 0x05;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlFlowFingerprint(u64);

impl ControlFlowFingerprint {
    #[must_use]
    pub fn of(graph: &ControlFlowGraph) -> Self {
        let adjacency: Adjacency<'_> = adjacency_of(graph);
        let colors: Vec<u64> = refine(graph.entry(), &adjacency);
        let depths: Vec<u32> = depths_from_entry(graph.entry(), &adjacency.successors);
        let keys: Vec<BlockKey> = depths
            .iter()
            .copied()
            .zip(colors.iter().copied())
            .map(|(depth, color): (u32, u64)| BlockKey { depth, color })
            .collect();
        let ranks: Vec<u64> = dense_ranks(&keys);
        let total: u64 = accumulate(&adjacency, &ranks, &canonical_order(&keys));
        finalize(total, graph.block_count(), adjacency.edges)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

const fn scramble(value: u64) -> u64 {
    let stirred: u64 = (value ^ (value >> 30)).wrapping_mul(MIX_MULTIPLIER_LOW);
    let folded: u64 = (stirred ^ (stirred >> 27)).wrapping_mul(MIX_MULTIPLIER_HIGH);
    folded ^ (folded >> 31)
}

const fn combine(state: u64, value: u64) -> u64 {
    scramble(state.rotate_left(COMBINE_ROTATION) ^ scramble(value))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct BlockKey {
    depth: u32,
    color: u64,
}

#[derive(Debug)]
struct Adjacency<'a> {
    successors: Vec<&'a [usize]>,
    predecessors: Vec<Vec<usize>>,
    incoming: Vec<u32>,
    outgoing: Vec<u32>,
    edges: u64,
}

fn adjacency_of(graph: &ControlFlowGraph) -> Adjacency<'_> {
    let blocks: &[BasicBlock] = graph.blocks();
    let order: usize = blocks.len();
    let mut successors: Vec<&[usize]> = Vec::with_capacity(order);
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); order];
    let mut incoming: Vec<u32> = vec![0; order];
    let mut outgoing: Vec<u32> = Vec::with_capacity(order);
    let mut edges: u64 = 0;
    for (source, block) in blocks.iter().enumerate() {
        let targets: &[usize] = block.successors();
        successors.push(targets);
        outgoing.push(saturating_degree(targets.len()));
        edges = edges.saturating_add(targets.len() as u64);
        for target in targets.iter().copied() {
            if let Some(degree) = incoming.get_mut(target) {
                *degree = degree.saturating_add(1);
            }
            if let Some(sources) = predecessors.get_mut(target) {
                sources.push(source);
            }
        }
    }
    Adjacency {
        successors,
        predecessors,
        incoming,
        outgoing,
        edges,
    }
}

fn saturating_degree(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn refine(entry: usize, adjacency: &Adjacency<'_>) -> Vec<u64> {
    let order: usize = adjacency.successors.len();
    let mut colors: Vec<u64> = adjacency
        .incoming
        .iter()
        .copied()
        .zip(adjacency.outgoing.iter().copied())
        .enumerate()
        .map(|(index, (incoming, outgoing)): (usize, (u32, u32))| {
            seed_color(index == entry, incoming, outgoing)
        })
        .collect();
    let mut distinct: usize = distinct_count(&colors);
    let mut scratch: Vec<u64> = Vec::with_capacity(order);
    let mut next: Vec<u64> = Vec::with_capacity(order);
    for _ in 0..order.min(REFINEMENT_ROUND_CAP) {
        next.clear();
        for (own, (targets, sources)) in colors.iter().copied().zip(
            adjacency
                .successors
                .iter()
                .zip(adjacency.predecessors.iter()),
        ) {
            let mut state: u64 = combine(VERTEX_TAG, own);
            state = fold_neighbours(state, targets.iter().copied(), &colors, &mut scratch);
            state = combine(state, PREDECESSOR_TAG);
            state = fold_neighbours(state, sources.iter().copied(), &colors, &mut scratch);
            next.push(state);
        }
        let refined: usize = distinct_count(&next);
        std::mem::swap(&mut colors, &mut next);
        if refined == distinct {
            break;
        }
        distinct = refined;
    }
    colors
}

const fn seed_color(is_entry: bool, incoming: u32, outgoing: u32) -> u64 {
    let tag: u64 = if is_entry { ENTRY_TAG } else { ORDINARY_TAG };
    combine(combine(tag, incoming as u64), outgoing as u64)
}

fn fold_neighbours(
    state: u64,
    neighbours: impl Iterator<Item = usize>,
    colors: &[u64],
    scratch: &mut Vec<u64>,
) -> u64 {
    scratch.clear();
    scratch.extend(neighbours.filter_map(|index: usize| colors.get(index).copied()));
    scratch.sort_unstable();
    scratch
        .iter()
        .copied()
        .fold(state, |carried: u64, color: u64| combine(carried, color))
}

fn distinct_count(colors: &[u64]) -> usize {
    let mut sorted: Vec<u64> = colors.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    sorted.len()
}

fn depths_from_entry(entry: usize, successors: &[&[usize]]) -> Vec<u32> {
    let order: usize = successors.len();
    let mut depths: Vec<u32> = vec![UNREACHABLE_DEPTH; order];
    let mut pending: VecDeque<usize> = VecDeque::with_capacity(order);
    if let Some(slot) = depths.get_mut(entry) {
        *slot = 0;
        pending.push_back(entry);
    }
    while let Some(current) = pending.pop_front() {
        let (Some(reached), Some(targets)): (Option<u32>, Option<&&[usize]>) =
            (depths.get(current).copied(), successors.get(current))
        else {
            continue;
        };
        let Some(next_depth): Option<u32> = reached.checked_add(1) else {
            continue;
        };
        for target in targets.iter().copied() {
            if let Some(slot) = depths.get_mut(target)
                && *slot == UNREACHABLE_DEPTH
            {
                *slot = next_depth;
                pending.push_back(target);
            }
        }
    }
    depths
}

fn dense_ranks(keys: &[BlockKey]) -> Vec<u64> {
    let mut distinct: Vec<BlockKey> = keys.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    keys.iter()
        .map(|key: &BlockKey| {
            distinct
                .binary_search(key)
                .map_or(0, |position: usize| position as u64 + 1)
        })
        .collect()
}

fn canonical_order(keys: &[BlockKey]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..keys.len()).collect();
    order.sort_unstable_by_key(|index: &usize| (keys.get(*index).copied(), *index));
    order
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Endpoint {
    rank: u64,
    incoming: u32,
    outgoing: u32,
}

fn endpoint(adjacency: &Adjacency<'_>, ranks: &[u64], index: usize) -> Option<Endpoint> {
    Some(Endpoint {
        rank: ranks.get(index).copied()?,
        incoming: adjacency.incoming.get(index).copied()?,
        outgoing: adjacency.outgoing.get(index).copied()?,
    })
}

fn accumulate(adjacency: &Adjacency<'_>, ranks: &[u64], order: &[usize]) -> u64 {
    let mut total: u64 = 0;
    let mut terms: Vec<u64> = Vec::new();
    for source in order.iter().copied() {
        let (Some(targets), Some(head)): (Option<&&[usize]>, Option<Endpoint>) = (
            adjacency.successors.get(source),
            endpoint(adjacency, ranks, source),
        ) else {
            continue;
        };
        terms.clear();
        for target in targets.iter().copied() {
            let Some(tail): Option<Endpoint> = endpoint(adjacency, ranks, target) else {
                continue;
            };
            terms.push(edge_term(head, tail));
        }
        terms.sort_unstable();
        for term in terms.iter().copied() {
            total = total.wrapping_add(term);
        }
    }
    total
}

const fn edge_term(head: Endpoint, tail: Endpoint) -> u64 {
    let mut state: u64 = combine(EDGE_TAG, head.rank);
    state = combine(state, tail.rank);
    state = combine(state, head.incoming as u64);
    state = combine(state, head.outgoing as u64);
    state = combine(state, tail.incoming as u64);
    combine(state, tail.outgoing as u64)
}

fn finalize(total: u64, block_count: usize, edges: u64) -> ControlFlowFingerprint {
    let mut state: u64 = combine(
        FINGERPRINT_SEED,
        u64::try_from(block_count).unwrap_or(u64::MAX),
    );
    state = combine(state, edges);
    ControlFlowFingerprint(combine(state, total))
}
